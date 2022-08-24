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
#include "srrp.h"
#include "log.h"

#define SERIAL_ADDR "/dev/ttyUSB0"

static int exit_flag;

static void signal_handler(int sig)
{
    exit_flag = 1;
}

static void demo()
{
    struct apibus *bus = apibus_new();
    apibus_enable_posix(bus);
    int fd = apibus_open_serial(bus, SERIAL_ADDR);
    assert(fd != -1);

    struct ioctl_serial_param sp = {
        .baud = SERIAL_ARG_BAUD_115200,
        .bits = SERIAL_ARG_BITS_8,
        .parity = SERIAL_ARG_PARITY_N,
        .stop = SERIAL_ARG_STOP_1,
    };
    int rc = apibus_ioctl(bus, fd, 0, (unsigned long)&sp);
    assert(rc != -1);

    while (exit_flag == 0) {
        int nr = 0;
        char buf[256];

        struct srrp_packet *pac = srrp_write_request(
            3333, "/8888/echo", "{msg:'hello'}");
        nr = apibus_send(bus, fd, pac->raw, pac->len);
        LOG_INFO("%d, %s", nr, pac->raw);
        srrp_free(pac);

        bzero(buf, sizeof(buf));
        sleep(1);
        nr = apibus_recv(bus, fd, buf, sizeof(buf));
        LOG_INFO("%d, %s", nr, buf);
    }

    apibus_close(bus, fd);
    apibus_disable_posix(bus);
    apibus_destroy(bus);
}

int main(void)
{
    log_set_level(LOG_LV_DEBUG);
    signal(SIGINT, signal_handler);
    signal(SIGQUIT, signal_handler);
    demo();
    return 0;
}
