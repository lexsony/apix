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
    INIT_OPT_STRING("-u:", "unix", "./apix-unix-domain", "unix domain"),
    INIT_OPT_STRING("-t:", "tcp", "0.0.0.0:12248", "tcp socket"),
    INIT_OPT_STRING("-s:", "serial", "", "serial dev file"),
    INIT_OPT_NONE(),
};

static void run_apibus()
{
    struct opt *ud = find_opt("unix", opttab);
    struct opt *tcp = find_opt("tcp", opttab);
    struct opt *serial = find_opt("serial", opttab);

    struct apibus *bus = apibus_new();
    apibus_enable_posix(bus);

    int fd = 0;
    int rc = 0;

    fd = apibus_open_unix(bus, opt_string(ud));
    if (fd == -1) {
        perror("open_unix");
        exit(1);
    }
    fd = apibus_open_tcp(bus, opt_string(tcp));
    if (fd == -1) {
        perror("open_tcp");
        exit(1);
    }

    if (strcmp(opt_string(serial), "") != 0) {
        fd = apibus_open_serial(bus, opt_string(serial));
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
        rc = apibus_ioctl(bus, fd, 0, (unsigned long)&sp);
        assert(rc != -1);
    }

    while (exit_flag == 0) {
        apibus_poll(bus);
    }

    apibus_disable_posix(bus);
    apibus_destroy(bus); // auto close all fds
}

int main(int argc, char *argv[])
{
    log_set_level(LOG_LV_DEBUG);
    opt_init_from_arg(opttab, argc, argv);
    signal(SIGINT, signal_handler);
    signal(SIGQUIT, signal_handler);
    run_apibus();
    return 0;
}
