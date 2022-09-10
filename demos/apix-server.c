#include <assert.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <signal.h>
#include <pthread.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "apix.h"
#include "apix-posix.h"
#include "srrp.h"
#include "opt.h"
#include "log.h"

static int exit_flag;

static void signal_handler(int sig)
{
    exit_flag = 1;
}

static struct opt opttab[] = {
    INIT_OPT_BOOL("-h", "help", false, "print this usage"),
    INIT_OPT_BOOL("-D", "debug", false, "debug mode [defaut: false]"),
    INIT_OPT_STRING("-x:", "unix", "", "unix domain"),
    INIT_OPT_STRING("-t:", "tcp", "", "tcp socket"),
    INIT_OPT_STRING("-s:", "serial", "", "serial dev file"),
    INIT_OPT_NONE(),
};

static void run_apix()
{
    struct opt *ud = find_opt("unix", opttab);
    struct opt *tcp = find_opt("tcp", opttab);
    struct opt *serial = find_opt("serial", opttab);

    struct apix *ctx = apix_new();
    apix_enable_posix(ctx);

    int fd = 0;
    int rc = 0;

    if (strcmp(opt_string(ud), "") != 0) {
        fd = apix_open_unix_server(ctx, opt_string(ud));
        if (fd == -1) {
            perror("open_unix");
            exit(1);
        }
    }

    if (strcmp(opt_string(tcp), "") != 0) {
        fd = apix_open_tcp_server(ctx, opt_string(tcp));
        if (fd == -1) {
            perror("open_tcp");
            exit(1);
        }
    }

    if (strcmp(opt_string(serial), "") != 0) {
        fd = apix_open_serial(ctx, opt_string(serial));
        if (fd == -1) {
            perror("open_serial");
            exit(1);
        }
        struct ioctl_serial_param sp = {
            .baud = SERIAL_ARG_BAUD_115200,
            .bits = SERIAL_ARG_BITS_8,
            .parity = SERIAL_ARG_PARITY_N,
            .stop = SERIAL_ARG_STOP_1,
        };
        rc = apix_ioctl(ctx, fd, 0, (unsigned long)&sp);
        assert(rc != -1);
    }

    while (exit_flag == 0) {
        apix_poll(ctx);
    }

    apix_disable_posix(ctx);
    apix_destroy(ctx); // auto close all fds
}

int main(int argc, char *argv[])
{
    log_set_level(LOG_LV_DEBUG);
    opt_init_from_arg(opttab, argc, argv);
    signal(SIGINT, signal_handler);
    signal(SIGQUIT, signal_handler);
    run_apix();
    return 0;
}
