#include <assert.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <signal.h>
#include <pthread.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "apix-posix.h"
#include "apix.h"
#include "srrp.h"
#include "svcx.h"
#include "crc16.h"
#include "log.h"

static int exit_flag;

static void signal_handler(int sig)
{
    exit_flag = 1;
}

static int on_echo(struct srrp_packet *req, struct srrp_packet **resp)
{
    uint16_t crc = crc16(req->header, req->header_len);
    crc = crc16_crc(crc, req->data, req->data_len);
    *resp = srrp_write_response(req->srcid, crc, req->header, "{msg:'world'}");
    return 0;
}

static void demo(const char *addr)
{
    struct svchub *hub = svchub_new();
    svchub_add_service(hub, "/8888/echo", on_echo);

    struct apix *ctx = apix_new();
    apix_enable_posix(ctx);
    int fd = apix_open_tcp_client(ctx, addr);
    assert(fd != -1);

    struct srrp_packet *pac = srrp_write_request(
        8888, "/8888/alive", "{}");
    apix_send(ctx, fd, (uint8_t *)pac->raw, pac->len);
    srrp_free(pac);

    int nr = 0;
    char buf[4096];
    while (exit_flag == 0) {
        usleep(100 * 1000);
        bzero(buf, sizeof(buf));
        nr = apix_recv(ctx, fd, buf, sizeof(buf));
        if (nr <= 0) continue;

        uint32_t offset = srrp_next_packet_offset(buf, nr);
        struct srrp_packet *req = srrp_read_one_packet(buf + offset);
        if (req == NULL) continue;

        struct srrp_packet *resp = NULL;
        if (svchub_deal(hub, req, &resp) == 0) {
            assert(resp);
            int nr = apix_send(ctx, fd, (uint8_t *)resp->raw, resp->len);
            assert(nr != -1);
            assert(nr != 0);
            srrp_free(resp);
        }
        srrp_free(req);
    }

    apix_close(ctx, fd);
    apix_disable_posix(ctx);
    apix_destroy(ctx);

    svchub_del_service(hub, "/8888/echo");
    svchub_destroy(hub);
}

int main(int argc, char *argv[])
{
    log_set_level(LOG_LV_DEBUG);
    signal(SIGINT, signal_handler);
    signal(SIGQUIT, signal_handler);
    demo(argv[1]);
    return 0;
}
