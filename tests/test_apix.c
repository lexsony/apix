#include <sched.h>
#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>
#include <string.h>
#include <stdlib.h>
#include <pthread.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "apix.h"
#include "srrp.h"
#include "crc16.h"
#include "log.h"

#define UNIX_ADDR "test_apisink_unix"
#define TCP_ADDR "127.0.0.1:1224"

/**
 * broker
 */

static void broker_on_srrp_packet(
    struct apix *ctx, int fd, struct srrp_packet *pac, void *priv)
{
    apix_srrp_forward(ctx, pac);
    LOG_INFO("broker forward packet: %s", srrp_get_raw(pac));
}

static void broker_on_accept(struct apix *ctx, int fd, int newfd, void *priv)
{
    apix_on_srrp_packet(ctx, newfd, broker_on_srrp_packet, NULL);
}

/**
 * requester
 */

static int requester_finished = 0;

static void requester_on_srrp_packet(
    struct apix *ctx, int fd, struct srrp_packet *pac, void *priv)
{
    assert_true(srrp_get_leader(pac) == SRRP_RESPONSE_LEADER);
    LOG_INFO("requester on response: %s", srrp_get_raw(pac));
    requester_finished = 1;
}

static void *requester_thread(void *args)
{
    struct apix *ctx = apix_new();
    apix_enable_posix(ctx);
    int fd = apix_open_unix_client(ctx, UNIX_ADDR);
    apix_enable_srrp_mode(ctx, fd, 0x3333);
    apix_on_srrp_packet(ctx, fd, requester_on_srrp_packet, NULL);

    sleep(1);

    struct srrp_packet *pac = srrp_new_request(
        0x3333, 0x8888, "/hello", "j:{name:'yon',age:'18',equip:['hat','shoes']}");
    int rc = send(fd, srrp_get_raw(pac), srrp_get_packet_len(pac), 0);
    assert_true(rc != -1);
    srrp_free(pac);

    while (requester_finished != 1)
        apix_poll(ctx, 0);

    sleep(1);

    apix_close(ctx, fd);
    apix_disable_posix(ctx);
    apix_destroy(ctx);

    LOG_INFO("requester exit");
    return NULL;
}

/**
 * responser
 */

static int responser_finished = 0;

static void responser_on_srrp_packet(
    struct apix *ctx, int fd, struct srrp_packet *pac, void *priv)
{
    if (srrp_get_leader(pac) == SRRP_REQUEST_LEADER) {
        LOG_INFO("responser on request: %s", srrp_get_raw(pac));
        if (strstr(srrp_get_anchor(pac), "/hello") != 0) {
            struct srrp_packet *resp = srrp_new_response(
                srrp_get_dstid(pac), srrp_get_srcid(pac), srrp_get_anchor(pac),
                "j:{err:0,errmsg:'succ',data:{msg:'world'}}",
                srrp_get_crc16(pac));
            apix_send(ctx, fd, srrp_get_raw(resp), srrp_get_packet_len(resp));
            srrp_free(resp);
            responser_finished = 1;
        }
        return;
    }

    if (srrp_get_leader(pac) == SRRP_RESPONSE_LEADER) {
        LOG_INFO("responser on response: %s", srrp_get_raw(pac));
    }
}

static void *responser_thread(void *args)
{
    struct apix *ctx = apix_new();
    apix_enable_posix(ctx);
    int fd = apix_open_unix_client(ctx, UNIX_ADDR);
    apix_enable_srrp_mode(ctx, fd, 0x8888);
    apix_on_srrp_packet(ctx, fd, responser_on_srrp_packet, NULL);

    while (responser_finished != 1) {
        apix_poll(ctx, 0);
    }

    sleep(1);

    apix_close(ctx, fd);
    apix_disable_posix(ctx);
    apix_destroy(ctx);

    LOG_INFO("responser exit");
    return NULL;
}

/**
 * test_api_request_response
 */

static void test_api_request_response(void **status)
{
    log_set_level(LOG_LV_DEBUG);

    struct apix *ctx = apix_new();
    apix_enable_posix(ctx);
    int fd = apix_open_unix_server(ctx, UNIX_ADDR);
    apix_enable_srrp_mode(ctx, fd, 0x1);
    apix_on_fd_accept(ctx, fd, broker_on_accept, NULL);

    pthread_t responser_pid;
    pthread_create(&responser_pid, NULL, responser_thread, NULL);
    pthread_t requester_pid;
    pthread_create(&requester_pid, NULL, requester_thread, NULL);

    while (requester_finished == 0 || responser_finished == 0)
        apix_poll(ctx, 0);

    pthread_join(requester_pid, NULL);
    pthread_join(responser_pid, NULL);

    apix_close(ctx, fd);
    apix_disable_posix(ctx);
    apix_destroy(ctx);
}

/**
 * publish
 */

static int publish_finished = 0;

static void *publish_thread(void *args)
{
    int fd = socket(PF_INET, SOCK_STREAM, 0);
    if (fd == -1)
        return NULL;

    uint32_t host;
    uint16_t port;
    char *tmp = strdup(TCP_ADDR);
    char *colon = strchr(tmp, ':');
    *colon = 0;
    host = inet_addr(tmp);
    port = htons(atoi(colon + 1));
    free(tmp);

    int rc = 0;
    struct sockaddr_in sockaddr = {0};
    sockaddr.sin_family = PF_INET;
    sockaddr.sin_addr.s_addr = host;
    sockaddr.sin_port = port;

    rc = connect(fd, (struct sockaddr *)&sockaddr, sizeof(sockaddr));
    if (rc == -1) {
        close(fd);
        return NULL;
    }

    sleep(1);

    struct srrp_packet *pac_sync = srrp_new_ctrl(0x9999, SRRP_CTRL_SYNC, "");
    send(fd, srrp_get_raw(pac_sync), srrp_get_packet_len(pac_sync), 0);
    srrp_free(pac_sync);

    struct srrp_packet *pac = srrp_new_publish("/test-topic", "{msg:'ahaa'}");
    rc = send(fd, srrp_get_raw(pac), srrp_get_packet_len(pac), 0);
    srrp_free(pac);

    sleep(1);

    close(fd);
    publish_finished = 1;
    LOG_INFO("publish exit");
    return NULL;
}

/**
 * subscribe
 */

static int subscribe_finished = 0;

static void subscribe_on_srrp_packet(
    struct apix *ctx, int fd, struct srrp_packet *pac, void *priv)
{
    LOG_INFO("sub recv: %s", srrp_get_raw(pac));

    if (srrp_get_leader(pac) == SRRP_PUBLISH_LEADER) {
        subscribe_finished = 1;
    }
}

static void *subscribe_thread(void *args)
{
    struct apix *ctx = apix_new();
    apix_enable_posix(ctx);
    int fd = apix_open_tcp_client(ctx, TCP_ADDR);
    apix_enable_srrp_mode(ctx, fd, 0x6666);
    apix_on_srrp_packet(ctx, fd, subscribe_on_srrp_packet, NULL);

    int rc = 0;

    struct srrp_packet *pac_sub = srrp_new_subscribe("/test-topic", "{}");
    rc = send(fd, srrp_get_raw(pac_sub), srrp_get_packet_len(pac_sub), 0);
    assert_true(rc != -1);
    srrp_free(pac_sub);

    while (subscribe_finished != 1)
        apix_poll(ctx, 0);

    struct srrp_packet *pac_unsub = srrp_new_unsubscribe("/test-topic", "{}");
    rc = send(fd, srrp_get_raw(pac_unsub), srrp_get_packet_len(pac_unsub), 0);
    assert_true(rc != -1);
    srrp_free(pac_unsub);

    sleep(1);

    apix_close(ctx, fd);
    apix_disable_posix(ctx);
    apix_destroy(ctx);

    subscribe_finished = 1;
    LOG_INFO("subscribe exit");
    return NULL;
}

/**
 * test_api_subscribe_publish
 */

static void test_api_subscribe_publish(void **status)
{
    struct apix *ctx = apix_new();
    apix_enable_posix(ctx);
    int fd = apix_open_tcp_server(ctx, TCP_ADDR);
    assert_true(fd != -1);
    apix_enable_srrp_mode(ctx, fd, 0x1);
    apix_on_fd_accept(ctx, fd, broker_on_accept, NULL);

    pthread_t subscribe_pid;
    pthread_create(&subscribe_pid, NULL, subscribe_thread, NULL);
    pthread_t publish_pid;
    pthread_create(&publish_pid, NULL, publish_thread, NULL);

    while (publish_finished == 0 || subscribe_finished == 0)
        apix_poll(ctx, 0);

    pthread_join(publish_pid, NULL);
    pthread_join(subscribe_pid, NULL);

    apix_close(ctx, fd);
    apix_disable_posix(ctx);
    apix_destroy(ctx);
}

int main(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_api_request_response),
        cmocka_unit_test(test_api_subscribe_publish),
    };
    return cmocka_run_group_tests(tests, NULL, NULL);
}
