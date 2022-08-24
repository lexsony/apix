#if defined __arm__ && !defined __unix__

#include <assert.h>
#include <errno.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <strings.h>
#include <time.h>

#include <unistd.h>
#include <sys/select.h>
#include <fcntl.h>

#include "apix-private.h"
#include "apix-stm32.h"
#include "atbuf.h"
#include "unused.h"
#include "list.h"
#include "log.h"

// serial

static struct apisink __serial_sink;

static int serial_open(struct apisink *sink, const char *addr)
{
    int fd = open(addr, O_RDWR | O_NOCTTY);
    if (fd == -1) return -1;

    struct sinkfd *sinkfd = sinkfd_new();
    sinkfd->fd = fd;
    snprintf(sinkfd->addr, sizeof(sinkfd->addr), "%s", addr);
    sinkfd->sink = sink;
    list_add(&sinkfd->node_sink, &sink->sinkfds);
    list_add(&sinkfd->node_bus, &sink->bus->sinkfds);

    return fd;
}

static int serial_close(struct apisink *sink, int fd)
{
    struct sinkfd *sinkfd = find_sinkfd_in_apisink(sink, fd);
    if (sinkfd == NULL)
        return -1;
    close(sinkfd->fd);
    sinkfd_destroy(sinkfd);
    return 0;
}

static int
serial_ioctl(struct apisink *sink, int fd, unsigned int cmd, unsigned long arg)
{
    UNUSED(sink);
    UNUSED(cmd);
    return 0;
}

static int serial_send(struct apisink *sink, int fd, const void *buf, size_t len)
{
    UNUSED(sink);
    return write(fd, buf, len);
}

static int serial_recv(struct apisink *sink, int fd, void *buf, size_t size)
{
    UNUSED(sink);
    return read(fd, buf, size);
}

static int serial_poll(struct apisink *sink)
{
    struct sinkfd *pos;
    list_for_each_entry(pos, &sink->sinkfds, node_sink) {
        int nr = read(pos->fd, atbuf_write_pos(pos->rxbuf), atbuf_spare(pos->rxbuf));
        if (nr == 0) continue;
        if (nr == -1) {
            LOG_ERROR("poll failed!");
            continue;
        }
        atbuf_write_advance(pos->rxbuf, nr);
    }
    return 0;
}

static apisink_ops_t serial_ops = {
    .open = serial_open,
    .close = serial_close,
    .ioctl = serial_ioctl,
    .send = serial_send,
    .recv = serial_recv,
    .poll = serial_poll,
};

int apibus_enable_stm32(struct apibus *bus)
{
    apisink_init(&__serial_sink, APISINK_STM32_SERIAL, serial_ops);
    apibus_add_sink(bus, &__serial_sink);

    return 0;
}

void apibus_disable_stm32(struct apibus *bus)
{
    apibus_del_sink(bus, &__serial_sink);
    apisink_fini(&__serial_sink);
}

#endif
