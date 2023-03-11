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

static int requester_finished = 0;
static int responser_finished = 0;

static void requester_on_srrp_response(
    struct apix *ctx, int fd, struct srrp_packet *req, void *priv)
{
    LOG_INFO("requester on response: %s", vraw(req->payload));
    requester_finished = 1;
}

static void *requester_thread(void *args)
{
    struct apix *ctx = apix_new();
    apix_enable_posix(ctx);
    int fd = apix_open_unix_client(ctx, UNIX_ADDR);
    apix_enable_srrp_mode(ctx, fd, 3333);
    apix_on_srrp_response(ctx, fd, requester_on_srrp_response, NULL);

    int rc = 0;

    assert_true(apix_srrp_online(ctx, fd) == 0);

    sleep(1);

    struct srrp_packet *pac = srrp_new_request(
        3333, 8888, "/hello", "j:{name:'yon',age:'18',equip:['hat','shoes']}");
    rc = send(fd, vraw(pac->payload), pac->len, 0);
    assert_true(rc != -1);
    srrp_free(pac);

    while (requester_finished != 1)
        apix_poll(ctx);

    apix_close(ctx, fd);
    apix_disable_posix(ctx);
    apix_destroy(ctx);

    return NULL;
}

static void responser_on_srrp_response(
    struct apix *ctx, int fd, struct srrp_packet *resp, void *priv)
{
    if (strstr(resp->header, SRRP_CTRL_ONLINE) != 0) {
        LOG_INFO("responser on response: %s", vraw(resp->payload));
    }
}

static void responser_on_srrp_request(
    struct apix *ctx, int fd, struct srrp_packet *req, struct srrp_packet *resp, void *priv)
{
    LOG_INFO("responser on request: %s", vraw(req->payload));
    if (strstr(req->header, "/hello") != 0) {
        struct srrp_packet *tmp = srrp_new_response(
            req->dstid, req->srcid, req->crc16, req->header,
            "j:{err:0,errmsg:'succ',data:{msg:'world'}}");
        srrp_move(tmp, resp);
        responser_finished = 1;
    }
}

static void *responser_thread(void *args)
{
    struct apix *ctx = apix_new();
    apix_enable_posix(ctx);
    int fd = apix_open_unix_client(ctx, UNIX_ADDR);
    apix_enable_srrp_mode(ctx, fd, 8888);
    apix_on_srrp_request(ctx, fd, responser_on_srrp_request, NULL);
    apix_on_srrp_response(ctx, fd, responser_on_srrp_response, NULL);

    assert_true(apix_srrp_online(ctx, fd) == 0);

    while (responser_finished != 1) {
        apix_poll(ctx);
    }

    apix_close(ctx, fd);
    apix_disable_posix(ctx);
    apix_destroy(ctx);

    return NULL;
}

static void test_api_request_response(void **status)
{
    struct apix *ctx = apix_new();
    apix_enable_posix(ctx);
    int fd = apix_open_unix_server(ctx, UNIX_ADDR);
    apix_enable_srrp_mode(ctx, fd, 0);

    pthread_t responser_pid;
    pthread_create(&responser_pid, NULL, responser_thread, NULL);
    pthread_t requester_pid;
    pthread_create(&requester_pid, NULL, requester_thread, NULL);

    while (requester_finished == 0 || responser_finished == 0)
        apix_poll(ctx);

    pthread_join(requester_pid, NULL);
    pthread_join(responser_pid, NULL);

    apix_close(ctx, fd);
    apix_disable_posix(ctx);
    apix_destroy(ctx);
}

static int publish_finished = 0;
static int subscribe_finished = 0;

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

    struct srrp_packet *pac = srrp_new_publish("/test-topic", "{msg:'ahaa'}");
    rc = send(fd, vraw(pac->payload), pac->len, 0);
    srrp_free(pac);

    close(fd);
    publish_finished = 1;
    return NULL;
}

static void *subscribe_thread(void *args)
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

    char buf[256] = {0};

    struct srrp_packet *pac_sub = srrp_new_subscribe("/test-topic", "{}");
    rc = send(fd, vraw(pac_sub->payload), pac_sub->len, 0);
    srrp_free(pac_sub);
    memset(buf, 0, sizeof(buf));
    rc = recv(fd, buf, sizeof(buf), 0);
    LOG_INFO("responser recv sub: %s", buf);

    rc = recv(fd, buf, sizeof(buf), 0);
    LOG_INFO("responser recv pub: %s", buf);

    struct srrp_packet *pac_unsub = srrp_new_unsubscribe("/test-topic", "{}");
    rc = send(fd, vraw(pac_unsub->payload), pac_unsub->len, 0);
    srrp_free(pac_unsub);
    memset(buf, 0, sizeof(buf));
    rc = recv(fd, buf, sizeof(buf), 0);
    LOG_INFO("responser recv unsub: %s", buf);

    close(fd);
    subscribe_finished = 1;
    return NULL;
}

static void test_api_subscribe_publish(void **status)
{
    struct apix *ctx = apix_new();
    apix_enable_posix(ctx);
    int fd = apix_open_tcp_server(ctx, TCP_ADDR);
    assert_true(fd != -1);
    apix_enable_srrp_mode(ctx, fd, 0);

    pthread_t subscribe_pid;
    pthread_create(&subscribe_pid, NULL, subscribe_thread, NULL);
    pthread_t publish_pid;
    pthread_create(&publish_pid, NULL, publish_thread, NULL);

    while (publish_finished == 0 || subscribe_finished == 0)
        apix_poll(ctx);

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
