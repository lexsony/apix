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
#include "apix-posix.h"
#include "apix.h"
#include "srrp.h"
#include "crc16.h"
#include "log.h"

#define UNIX_ADDR "test_apisink_unix"
#define TCP_ADDR "127.0.0.1:1224"

const char *PAYLOAD = "t:hello";
const char *PAYLOAD2 =
    "t:0xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
    "1xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
    "2xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
    "3xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
    "4xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
    "5xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
    "6xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
    "7xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
    "8xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
    "9xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
    "0xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
    "1xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
    "2xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
    "3xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
    "4xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
    "5xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
    "6xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
    "7xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
    "8xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
    "9xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
    "0xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
    "1xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
    "2xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
    "3xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
    "4xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
    "5xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
    "6xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
    "7xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
    "8xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
    "9xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
    "0xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
    "1xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
    "2xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
    "3xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
    "4xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
    "5xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
    "6xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
    "7xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
    "8xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
    "9xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
    "0xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
    "1xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
    "2xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
    "3xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxo";

/**
 * requester
 */

static int requester_finished = 0;

static void *requester_thread(void *args)
{
    struct apix *ctx = apix_new();
    LOG_INFO("requester ctx: %x", ctx);
    apix_enable_posix(ctx);
    struct stream *stream = apix_open_unix_client(ctx, UNIX_ADDR);
    assert_true(stream);
    apix_upgrade_to_srrp(stream, 0x3333);

    sleep(1);

    struct srrp_packet *pac = srrp_new_request(0x3333, 0x8888, "/hello", PAYLOAD);
    int rc = apix_srrp_send(stream, pac);
    assert_true(rc != -1);
    srrp_free(pac);

    for (;;) {
        if (requester_finished)
            break;

        struct stream *stream = apix_waiting(ctx, 100 * 1000);
        if (stream == NULL) continue;

        switch (apix_next_event(stream)) {
        case AEC_OPEN:
            LOG_INFO("#%d open", apix_raw_fd(stream));
            break;
        case AEC_CLOSE:
            LOG_INFO("#%d close", apix_raw_fd(stream));
            break;
        case AEC_SRRP_PACKET: {
            struct srrp_packet *pac = apix_next_srrp_packet(stream);
            assert_true(pac);
            assert_true(srrp_get_leader(pac) == SRRP_RESPONSE_LEADER);
            LOG_INFO("requester on response: %s", srrp_get_raw(pac));
            requester_finished = 1;
            break;
        }
        default:
            break;
        }
    }

    sleep(1);

    apix_close(stream);
    apix_drop(ctx);

    LOG_INFO("requester exit");
    return NULL;
}

/**
 * responser
 */

static int responser_finished = 0;

static void *responser_thread(void *args)
{
    struct apix *ctx = apix_new();
    LOG_INFO("responser ctx: %x", ctx);
    apix_enable_posix(ctx);
    struct stream *stream = apix_open_unix_client(ctx, UNIX_ADDR);
    assert_true(stream);
    apix_upgrade_to_srrp(stream, 0x8888);

    for (;;) {
        if (responser_finished)
            break;

        struct stream *stream = apix_waiting(ctx, 100 * 1000);
        if (stream == NULL) continue;

        switch (apix_next_event(stream)) {
        case AEC_OPEN:
            LOG_INFO("#%d open", apix_raw_fd(stream));
            break;
        case AEC_CLOSE:
            LOG_INFO("#%d close", apix_raw_fd(stream));
            break;
        case AEC_SRRP_PACKET: {
            struct srrp_packet *pac = apix_next_srrp_packet(stream);
            assert_true(pac);
            if (srrp_get_leader(pac) == SRRP_REQUEST_LEADER) {
                LOG_INFO("responser on request: %s", srrp_get_raw(pac));
                if (strstr(srrp_get_anchor(pac), "/hello") != 0) {
                    assert_true(strcmp((char *)srrp_get_payload(pac), PAYLOAD) == 0);
                    struct srrp_packet *resp = srrp_new_response(
                        srrp_get_dstid(pac), srrp_get_srcid(pac), srrp_get_anchor(pac),
                        "j:{err:0,errmsg:'succ',data:{msg:'world'}}");
                    apix_send(stream, srrp_get_raw(resp), srrp_get_packet_len(resp));
                    srrp_free(resp);
                    responser_finished = 1;
                }
            } else if (srrp_get_leader(pac) == SRRP_RESPONSE_LEADER) {
                LOG_INFO("responser on response: %s", srrp_get_raw(pac));
            }
            break;
        }
        default:
            break;
        }
    }

    sleep(1);

    apix_close(stream);
    apix_drop(ctx);

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
    LOG_INFO("broker ctx: %x", ctx);
    apix_enable_posix(ctx);
    struct stream *server = apix_open_unix_server(ctx, UNIX_ADDR);
    assert_true(server);
    apix_upgrade_to_srrp(server, 0x1);

    pthread_t responser_pid;
    pthread_create(&responser_pid, NULL, responser_thread, NULL);
    pthread_t requester_pid;
    pthread_create(&requester_pid, NULL, requester_thread, NULL);

    for (;;) {
        if (requester_finished && responser_finished)
            break;

        struct stream *stream = apix_waiting(ctx, 100 * 1000);
        if (stream == NULL) continue;

        switch (apix_next_event(stream)) {
        case AEC_OPEN:
            LOG_INFO("#%d open", apix_raw_fd(stream));
            break;
        case AEC_CLOSE:
            LOG_INFO("#%d close", apix_raw_fd(stream));
            break;
        case AEC_ACCEPT: {
            struct stream * new_stream = apix_accept(stream);
            LOG_INFO("#%d accept #%d", apix_raw_fd(stream), apix_raw_fd(new_stream));
            break;
        }
        case AEC_SRRP_PACKET: {
            struct srrp_packet *pac = apix_next_srrp_packet(stream);
            assert_true(pac);
            apix_srrp_forward(stream, pac);
            LOG_INFO("#%d forward packet: %s", apix_raw_fd(stream), srrp_get_raw(pac));
            break;
        }
        default:
            break;
        }
    }

    pthread_join(requester_pid, NULL);
    pthread_join(responser_pid, NULL);

    apix_close(server);
    apix_drop(ctx);
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

static void *subscribe_thread(void *args)
{
    struct apix *ctx = apix_new();
    LOG_INFO("sub ctx: %x", ctx);
    apix_enable_posix(ctx);
    struct stream *stream = apix_open_tcp_client(ctx, TCP_ADDR);
    assert_true(stream);
    apix_upgrade_to_srrp(stream, 0x6666);

    int rc = 0;

    struct srrp_packet *pac_sub = srrp_new_subscribe("/test-topic", "{}");
    rc = apix_srrp_send(stream, pac_sub);
    assert_true(rc != -1);
    srrp_free(pac_sub);

    for (;;) {
        if (subscribe_finished)
            break;

        struct stream *stream = apix_waiting(ctx, 100 * 1000);
        if (stream == NULL) continue;

        switch (apix_next_event(stream)) {
        case AEC_OPEN:
            LOG_INFO("#%d open", apix_raw_fd(stream));
            break;
        case AEC_CLOSE:
            LOG_INFO("#%d close", apix_raw_fd(stream));
            break;
        case AEC_SRRP_PACKET: {
            struct srrp_packet *pac = apix_next_srrp_packet(stream);
            assert_true(pac);
            if (srrp_get_leader(pac) == SRRP_PUBLISH_LEADER) {
                subscribe_finished = 1;
            }
            LOG_INFO("sub recv: %s", srrp_get_raw(pac));
            break;
        }
        default:
            break;
        }
    }

    struct srrp_packet *pac_unsub = srrp_new_unsubscribe("/test-topic", "{}");
    rc = apix_srrp_send(stream, pac_unsub);
    assert_true(rc != -1);
    srrp_free(pac_unsub);

    sleep(1);

    apix_close(stream);
    apix_drop(ctx);

    subscribe_finished = 1;
    LOG_INFO("subscribe exit");
    return NULL;
}

/**
 * test_api_subscribe_publish
 */

static void test_api_subscribe_publish(void **status)
{
    log_set_level(LOG_LV_DEBUG);

    struct apix *ctx = apix_new();
    LOG_INFO("broker ctx: %x", ctx);
    apix_enable_posix(ctx);
    struct stream *server = apix_open_tcp_server(ctx, TCP_ADDR);
    assert_true(server);
    apix_upgrade_to_srrp(server, 0x1);

    pthread_t subscribe_pid;
    pthread_create(&subscribe_pid, NULL, subscribe_thread, NULL);
    pthread_t publish_pid;
    pthread_create(&publish_pid, NULL, publish_thread, NULL);

    for (;;) {
        if (publish_finished && subscribe_finished)
            break;

        struct stream *stream = apix_waiting(ctx, 100 * 1000);
        if (stream == NULL) continue;

        switch (apix_next_event(stream)) {
        case AEC_OPEN:
            LOG_INFO("#%d open", apix_raw_fd(stream));
            break;
        case AEC_CLOSE:
            LOG_INFO("#%d close", apix_raw_fd(stream));
            break;
        case AEC_ACCEPT: {
            struct stream *new_stream = apix_accept(stream);
            LOG_INFO("#%d accept #%d", apix_raw_fd(stream), apix_raw_fd(new_stream));
            break;
        }
        case AEC_SRRP_PACKET: {
            struct srrp_packet *pac = apix_next_srrp_packet(stream);
            assert_true(pac);
            apix_srrp_forward(stream, pac);
            LOG_INFO("#%d forward packet: %s", apix_raw_fd(stream), srrp_get_raw(pac));
            break;
        }
        default:
            break;
        }
    }

    pthread_join(publish_pid, NULL);
    pthread_join(subscribe_pid, NULL);

    apix_close(server);
    apix_drop(ctx);
}

int main(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_api_request_response),
        cmocka_unit_test(test_api_subscribe_publish),
    };
    return cmocka_run_group_tests(tests, NULL, NULL);
}
