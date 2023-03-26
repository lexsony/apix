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
#include "srrp.h"

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

static void
on_srrp_packet_listen(struct apix *ctx, int fd, struct srrp_packet *pac, void *priv)
{
    LOG_INFO("serv #%d: %s", fd, srrp_get_raw(pac));

    struct srrp_packet *resp = srrp_new_response(
        srrp_get_dstid(pac),
        srrp_get_srcid(pac),
        srrp_get_anchor(pac),
        "j:{\"err\":404,\"msg\":\"Service not found\"}");
    apix_srrp_send(ctx, fd, resp);
    srrp_free(resp);
}

static void
on_srrp_packet_accept(struct apix *ctx, int fd, struct srrp_packet *pac, void *priv)
{
    LOG_INFO("forward #%d: %s", fd, srrp_get_raw(pac));
    apix_srrp_forward(ctx, pac);
}

static void on_fd_close(struct apix *ctx, int fd, void *priv)
{
    LOG_INFO("close #%d", fd);
}

static void on_fd_accept(struct apix *ctx, int _fd, int newfd, void *priv)
{
    apix_on_fd_close(ctx, newfd, on_fd_close, NULL);
    apix_on_srrp_packet(ctx, newfd, on_srrp_packet_accept, NULL);
    LOG_INFO("accept #%d from %d", newfd, _fd);
}

static void *apix_thread(void *arg)
{
    ctx = apix_new();
    apix_enable_posix(ctx);

    struct opt *opt;

    opt = find_opt("unix", opttab);
    int fd_unix = apix_open_unix_server(ctx, opt_string(opt));
    if (fd_unix == -1) {
        LOG_ERROR("open unix socket at %s failed!", opt_string(opt));
        exit(-1);
    }
    apix_enable_srrp_mode(ctx, fd_unix, 0x1);
    apix_on_fd_close(ctx, fd_unix, on_fd_close, NULL);
    apix_on_fd_accept(ctx, fd_unix, on_fd_accept, NULL);
    apix_on_srrp_packet(ctx, fd_unix, on_srrp_packet_listen, NULL);
    LOG_INFO("open unix socket #%d at %s", fd_unix, opt_string(opt));

    opt = find_opt("tcp", opttab);
    int fd_tcp = apix_open_tcp_server(ctx, opt_string(opt));
    if (fd_tcp == -1) {
        perror("");
        LOG_ERROR("open tcp socket at %s failed!", opt_string(opt));
        exit(-1);
    }
    apix_enable_srrp_mode(ctx, fd_tcp, 0x2);
    apix_on_fd_close(ctx, fd_tcp, on_fd_close, NULL);
    apix_on_fd_accept(ctx, fd_tcp, on_fd_accept, NULL);
    apix_on_srrp_packet(ctx, fd_tcp, on_srrp_packet_listen, NULL);
    LOG_INFO("open tcp socket #%d at %s", fd_tcp, opt_string(opt));

    while (exit_flag == 0) {
        apix_poll(ctx, 0);
    }

    apix_destroy(ctx); // auto close all fds

    return NULL;
}

int main(int argc, char *argv[])
{
    log_set_level(LOG_LV_INFO);
    opt_init_from_arg(opttab, argc, argv);
    signal(SIGINT, signal_handler);
    signal(SIGQUIT, signal_handler);

    struct opt *opt;
    opt = find_opt("debug", opttab);
    if (opt_bool(opt))
        log_set_level(LOG_LV_DEBUG);

    while (exit_flag == 0) {
        apix_thread(NULL);
        sleep(1);
    }

    return 0;
}
