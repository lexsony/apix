#include <assert.h>
#include <ctype.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <signal.h>
#include <pthread.h>
#include <unistd.h>

#include <apix/apix.h>
#include <apix/log.h>
#include "opt.h"

static int exit_flag;
static struct apix *ctx;

static void signal_handler(int sig)
{
    exit_flag = 1;
}

static struct opt opttab[] = {
    INIT_OPT_BOOL("-h", "help", false, "print this usage"),
    INIT_OPT_BOOL("-D", "debug", false, "enable debug [defaut: false]"),
    INIT_OPT_BOOL("-r", "srrp_mode", true, "enable srrp mode [defaut: true]"),
    INIT_OPT_STRING("-u:", "unix", "/tmp/apix", "unix socket addr"),
    INIT_OPT_STRING("-t:", "tcp", "127.0.0.1:3824", "tcp socket addr"),
    INIT_OPT_NONE(),
};

static void *apix_thread(void *arg)
{
    ctx = apix_new();
    apix_enable_posix(ctx);

    struct opt *opt;

    opt = find_opt("unix", opttab);
    struct stream *server_unix = apix_open_unix_server(ctx, opt_string(opt));
    if (server_unix == NULL) {
        LOG_ERROR("open unix socket at %s failed!", opt_string(opt));
        exit(-1);
    }
    apix_upgrade_to_srrp(server_unix, "1");
    LOG_INFO("open unix socket #%d at %s", apix_get_raw_fd(server_unix), opt_string(opt));

    opt = find_opt("tcp", opttab);
    struct stream *server_tcp = apix_open_tcp_server(ctx, opt_string(opt));
    if (server_tcp == NULL) {
        perror("");
        LOG_ERROR("open tcp socket at %s failed!", opt_string(opt));
        exit(-1);
    }
    apix_upgrade_to_srrp(server_tcp, "2");
    LOG_INFO("open tcp socket #%d at %s", apix_get_raw_fd(server_tcp), opt_string(opt));

    for (;;) {
        if (exit_flag == 1) break;

        struct stream *stream = apix_wait_stream(ctx);
        if (stream == NULL) continue;

        switch (apix_wait_event(stream)) {
        case AEC_OPEN:
            LOG_INFO("#%d open", apix_get_raw_fd(stream));
            break;
        case AEC_CLOSE:
            LOG_INFO("#%d close", apix_get_raw_fd(stream));
            break;
        case AEC_ACCEPT: {
            struct stream *new_stream = apix_accept(stream);
            LOG_INFO("#%d accept #%d", apix_get_raw_fd(stream), apix_get_raw_fd(new_stream));
            break;
        }
        case AEC_SRRP_PACKET: {
            struct srrp_packet *pac = apix_wait_srrp_packet(stream);
            if (stream == server_unix || stream == server_tcp) {
                struct srrp_packet *resp = srrp_new_response(
                    srrp_get_dstid(pac),
                    srrp_get_srcid(pac),
                    srrp_get_anchor(pac),
                    "j:{\"err\":404,\"msg\":\"Service not found\"}");
                apix_srrp_send(stream, resp);
                srrp_free(resp);
                LOG_INFO("#%d serv packet: %s", apix_get_raw_fd(stream), srrp_get_raw(pac));
            } else {
                apix_srrp_forward(stream, pac);
                LOG_INFO("#%d forward packet: %s", apix_get_raw_fd(stream), srrp_get_raw(pac));
            }
            break;
        }
        default:
            break;
        }
    }

    apix_drop(ctx); // auto close all fds
    return NULL;
}

int main(int argc, char *argv[])
{
    opt_init_from_arg(opttab, argc, argv);
    signal(SIGINT, signal_handler);
    signal(SIGQUIT, signal_handler);

    struct opt *opt;
    opt = find_opt("debug", opttab);
    if (opt_bool(opt))
        log_set_level(LOG_LV_DEBUG);

    apix_thread(NULL);

    return 0;
}
