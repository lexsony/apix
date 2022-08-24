#if defined __unix__ || defined __linux__ || defined __APPLE__

#include <assert.h>
#include <errno.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <strings.h>
#include <time.h>

#include <unistd.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <termios.h>

#include "apix-private.h"
#include "apix-posix.h"
#include "atbuf.h"
#include "unused.h"
#include "list.h"
#include "log.h"

struct posix_sink {
    struct apisink sink;
    // for select
    fd_set fds;
    int nfds;
};

// unix domain socket

static struct posix_sink __unix_sink;

static int unix_open(struct apisink *sink, const char *addr)
{
    int fd = socket(PF_UNIX, SOCK_STREAM, 0);
    if (fd == -1)
        return -1;

    int rc = 0;
    struct sockaddr_un sockaddr = {0};
    sockaddr.sun_family = PF_UNIX;
    snprintf(sockaddr.sun_path, sizeof(sockaddr.sun_path), "%s", addr);

    unlink(addr);
    rc = bind(fd, (struct sockaddr *)&sockaddr, sizeof(sockaddr));
    if (rc == -1) {
        close(fd);
        return -1;
    }

    rc = listen(fd, 100);
    if (rc == -1) {
        close(fd);
        return -1;
    }

    struct sinkfd *sinkfd = sinkfd_new();
    sinkfd->fd = fd;
    sinkfd->listen = 1;
    snprintf(sinkfd->addr, sizeof(sinkfd->addr), "%s", addr);
    sinkfd->sink = sink;
    list_add(&sinkfd->node_sink, &sink->sinkfds);
    list_add(&sinkfd->node_bus, &sink->bus->sinkfds);

    struct posix_sink *unix_sink = container_of(sink, struct posix_sink, sink);
    FD_SET(fd, &unix_sink->fds);
    unix_sink->nfds = fd + 1;

    return fd;
}

static int unix_close(struct apisink *sink, int fd)
{
    struct sinkfd *sinkfd = find_sinkfd_in_apisink(sink, fd);
    if (sinkfd == NULL)
        return -1;
    close(sinkfd->fd);
    unlink(sinkfd->addr);
    sinkfd_destroy(sinkfd);
    return 0;
}

static int unix_send(struct apisink *sink, int fd, const void *buf, size_t len)
{
    UNUSED(sink);
    return send(fd, buf, len, 0);
}

static int unix_recv(struct apisink *sink, int fd, void *buf, size_t size)
{
    UNUSED(sink);
    return recv(fd, buf, size, 0);
}

static int unix_poll(struct apisink *sink)
{
    struct posix_sink *unix_sink = container_of(sink, struct posix_sink, sink);

    struct timeval tv = { 0, 0 };
    fd_set recvfds;
    memcpy(&recvfds, &unix_sink->fds, sizeof(recvfds));

    int nr_recv_fds = select(unix_sink->nfds, &recvfds, NULL, NULL, &tv);
    if (nr_recv_fds == -1) {
        if (errno == EINTR)
            return 0;
        LOG_ERROR("[select] (%d) %s", errno, strerror(errno));
        return -1;
    }

    struct sinkfd *pos, *n;
    list_for_each_entry_safe(pos, n, &sink->sinkfds, node_sink) {
        if (nr_recv_fds == 0) break;

        if (!FD_ISSET(pos->fd, &recvfds))
            continue;

        nr_recv_fds--;

        // accept
        if (pos->listen == 1) {
            int newfd = accept(pos->fd, NULL, NULL);
            if (newfd == -1) {
                LOG_ERROR("[accept] (%d) %s", errno, strerror(errno));
                continue;
            }

            struct sinkfd *sinkfd = sinkfd_new();
            sinkfd->fd = newfd;
            sinkfd->sink = sink;
            list_add(&sinkfd->node_sink, &sink->sinkfds);
            list_add(&sinkfd->node_bus, &sink->bus->sinkfds);

            if (unix_sink->nfds < newfd + 1)
                unix_sink->nfds = newfd + 1;
            FD_SET(newfd, &unix_sink->fds);
        } else /* recv */ {
            int nread = recv(pos->fd, atbuf_write_pos(pos->rxbuf),
                             atbuf_spare(pos->rxbuf), 0);
            if (nread == -1) {
                LOG_DEBUG("[recv] (%d) %s", errno, strerror(errno));
                sinkfd_destroy(pos);
            } else if (nread == 0) {
                LOG_DEBUG("[recv] (%d) finished");
                sinkfd_destroy(pos);
            } else {
                atbuf_write_advance(pos->rxbuf, nread);
                gettimeofday(&pos->ts_poll_recv, NULL);
            }
        }
    }

    return 0;
}

static apisink_ops_t unix_ops = {
    .open = unix_open,
    .close = unix_close,
    .ioctl = NULL,
    .send = unix_send,
    .recv = unix_recv,
    .poll = unix_poll,
};

// tcp

static struct posix_sink __tcp_sink;

static int tcp_open(struct apisink *sink, const char *addr)
{
    int fd = socket(PF_INET, SOCK_STREAM, 0);
    if (fd == -1)
        return -1;

    uint32_t host;
    uint16_t port;
    char *tmp = strdup(addr);
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

    rc = bind(fd, (struct sockaddr *)&sockaddr, sizeof(sockaddr));
    if (rc == -1) {
        close(fd);
        return -1;
    }

    rc = listen(fd, 100);
    if (rc == -1) {
        close(fd);
        return -1;
    }

    struct sinkfd *sinkfd = sinkfd_new();
    sinkfd->fd = fd;
    sinkfd->listen = 1;
    snprintf(sinkfd->addr, sizeof(sinkfd->addr), "%s", addr);
    sinkfd->sink = sink;
    list_add(&sinkfd->node_sink, &sink->sinkfds);
    list_add(&sinkfd->node_bus, &sink->bus->sinkfds);

    struct posix_sink *tcp_sink = container_of(sink, struct posix_sink, sink);
    FD_SET(fd, &tcp_sink->fds);
    tcp_sink->nfds = fd + 1;

    return fd;
}

static int tcp_close(struct apisink *sink, int fd)
{
    struct sinkfd *sinkfd = find_sinkfd_in_apisink(sink, fd);
    if (sinkfd == NULL)
        return -1;
    close(sinkfd->fd);
    sinkfd_destroy(sinkfd);
    return 0;
}

static apisink_ops_t tcp_ops = {
    .open = tcp_open,
    .close = tcp_close,
    .ioctl = NULL,
    .send = unix_send,
    .recv = unix_recv,
    .poll = unix_poll,
};

// serial

static struct posix_sink __serial_sink;

static int serial_open(struct apisink *sink, const char *addr)
{
    int fd = open(addr, O_RDWR | O_NOCTTY | O_NDELAY);
    if (fd == -1) return -1;

    struct sinkfd *sinkfd = sinkfd_new();
    sinkfd->fd = fd;
    snprintf(sinkfd->addr, sizeof(sinkfd->addr), "%s", addr);
    sinkfd->sink = sink;
    list_add(&sinkfd->node_sink, &sink->sinkfds);
    list_add(&sinkfd->node_bus, &sink->bus->sinkfds);

    struct posix_sink *serial_sink = container_of(sink, struct posix_sink, sink);
    FD_SET(fd, &serial_sink->fds);
    serial_sink->nfds = fd + 1;

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
    struct ioctl_serial_param *sp = (struct ioctl_serial_param *)arg;
    struct termios newtio, oldtio;

    if (tcgetattr(fd, &oldtio) != 0)
        return -1;

    bzero(&newtio, sizeof(newtio));
    newtio.c_cflag |= (CLOCAL | CREAD);
    newtio.c_cflag &= ~CSIZE;

    if (sp->baud == SERIAL_ARG_BAUD_9600) {
        cfsetispeed(&newtio, B9600);
    } else if (sp->baud == SERIAL_ARG_BAUD_115200) {
        cfsetispeed(&newtio, B115200);
    } else {
        return -1;
    }
    if (sp->bits == SERIAL_ARG_BITS_7) {
        newtio.c_cflag |= CS7;
    } else if (sp->bits == SERIAL_ARG_BITS_8) {
        newtio.c_cflag |= CS8;
    } else {
        return -1;
    }
    if (sp->parity == SERIAL_ARG_PARITY_O) {
        newtio.c_cflag |= PARENB;
        newtio.c_cflag |= PARODD;
        newtio.c_cflag |= (INPCK | ISTRIP);
    } else if (sp->parity == SERIAL_ARG_PARITY_E) {
        newtio.c_cflag |= PARENB;
        newtio.c_cflag &= ~PARODD;
        newtio.c_cflag |= (INPCK | ISTRIP);
    } else if (sp->parity == SERIAL_ARG_PARITY_N) {
        newtio.c_cflag &= ~PARENB;
    } else {
        return -1;
    }
    if (sp->stop == SERIAL_ARG_STOP_1) {
        newtio.c_cflag &= ~CSTOPB;
    } else if (sp->stop == SERIAL_ARG_STOP_2) {
        newtio.c_cflag |= CSTOPB;
    } else {
        return -1;
    }

    newtio.c_cc[VTIME] = 0;
    newtio.c_cc[VMIN] = 0;
    tcflush(fd, TCIFLUSH);

    if (tcsetattr(fd, TCSANOW, &newtio) != 0)
        return -1;

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
    struct posix_sink *unix_sink = container_of(sink, struct posix_sink, sink);

    struct timeval tv = { 0, 0 };
    fd_set recvfds;
    memcpy(&recvfds, &unix_sink->fds, sizeof(recvfds));

    int nr_recv_fds = select(unix_sink->nfds, &recvfds, NULL, NULL, &tv);
    if (nr_recv_fds == -1) {
        if (errno == EINTR)
            return 0;
        LOG_ERROR("[select] (%d) %s", errno, strerror(errno));
        return -1;
    }

    struct sinkfd *pos, *n;
    list_for_each_entry_safe(pos, n, &sink->sinkfds, node_sink) {
        if (nr_recv_fds == 0) break;

        if (!FD_ISSET(pos->fd, &recvfds))
            continue;

        nr_recv_fds--;

        int nread = read(pos->fd, atbuf_write_pos(pos->rxbuf),
                         atbuf_spare(pos->rxbuf));
        if (nread == -1) {
            LOG_DEBUG("[read] (%d) %s", errno, strerror(errno));
            sinkfd_destroy(pos);
        } else if (nread == 0) {
            LOG_DEBUG("[read] (%d) finished");
            sinkfd_destroy(pos);
        } else {
            atbuf_write_advance(pos->rxbuf, nread);
            gettimeofday(&pos->ts_poll_recv, NULL);
        }
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

int apibus_enable_posix(struct apibus *bus)
{
    apisink_init(&__unix_sink.sink, APISINK_UNIX, unix_ops);
    apibus_add_sink(bus, &__unix_sink.sink);

    apisink_init(&__tcp_sink.sink, APISINK_TCP, tcp_ops);
    apibus_add_sink(bus, &__tcp_sink.sink);

    apisink_init(&__serial_sink.sink, APISINK_SERIAL, serial_ops);
    apibus_add_sink(bus, &__serial_sink.sink);

    return 0;
}

void apibus_disable_posix(struct apibus *bus)
{
    apibus_del_sink(bus, &__unix_sink.sink);
    apisink_fini(&__unix_sink.sink);

    apibus_del_sink(bus, &__tcp_sink.sink);
    apisink_fini(&__tcp_sink.sink);

    apibus_del_sink(bus, &__serial_sink.sink);
    apisink_fini(&__serial_sink.sink);
}

#endif
