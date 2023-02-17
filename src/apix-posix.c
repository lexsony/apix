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
#include <linux/can.h>
#include <linux/can/raw.h>
#include <sys/ioctl.h>
#include <net/if.h>

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

static int __fd_close(struct apisink *sink, int fd)
{
    struct sinkfd *sinkfd = find_sinkfd_in_apisink(sink, fd);
    if (sinkfd == NULL)
        return -1;

    close(sinkfd->fd);
    sinkfd_destroy(sinkfd);

    struct posix_sink *unix_c_sink = container_of(sink, struct posix_sink, sink);
    FD_CLR(fd, &unix_c_sink->fds);

    return 0;
}

/**
 * unix domain socket server
 */

static int unix_s_open(struct apisink *sink, const char *addr)
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
    sinkfd->type = 'l';
    snprintf(sinkfd->addr, sizeof(sinkfd->addr), "%s", addr);
    sinkfd->sink = sink;
    list_add(&sinkfd->node_sink, &sink->sinkfds);
    list_add(&sinkfd->node_ctx, &sink->ctx->sinkfds);

    struct posix_sink *ps = container_of(sink, struct posix_sink, sink);
    FD_SET(fd, &ps->fds);
    ps->nfds = fd + 1;

    return fd;
}

static int unix_s_close(struct apisink *sink, int fd)
{
    struct sinkfd *sinkfd = find_sinkfd_in_apisink(sink, fd);
    if (sinkfd == NULL)
        return -1;

    if (strcmp(sink->id, APISINK_UNIX_S) == 0)
        unlink(sinkfd->addr);

    __fd_close(sink, fd);
    return 0;
}

static int unix_s_send(struct apisink *sink, int fd, const void *buf, size_t len)
{
    UNUSED(sink);
    return send(fd, buf, len, 0);
}

static int unix_s_recv(struct apisink *sink, int fd, void *buf, size_t size)
{
    UNUSED(sink);
    return recv(fd, buf, size, 0);
}

static int unix_s_poll(struct apisink *sink)
{
    struct posix_sink *ps = container_of(sink, struct posix_sink, sink);

    struct timeval tv = { 0, 0 };
    fd_set recvfds;
    memcpy(&recvfds, &ps->fds, sizeof(recvfds));

    int nr_recv_fds = select(ps->nfds, &recvfds, NULL, NULL, &tv);
    if (nr_recv_fds == -1) {
        if (errno == EINTR)
            return 0;
        LOG_ERROR("[select] %s", strerror(errno));
        return -1;
    }

    struct sinkfd *pos, *n;
    list_for_each_entry_safe(pos, n, &sink->sinkfds, node_sink) {
        if (nr_recv_fds == 0) break;

        if (!FD_ISSET(pos->fd, &recvfds))
            continue;

        nr_recv_fds--;

        // accept
        if (pos->type == 'l') {
            int newfd = accept(pos->fd, NULL, NULL);
            if (newfd == -1) {
                LOG_ERROR("[accept] fd:%d, %s", pos->fd, strerror(errno));
                continue;
            }
            LOG_DEBUG("[accept] fd:%d, newfd:%d", pos->fd, newfd);

            struct sinkfd *sinkfd = sinkfd_new();
            sinkfd->fd = newfd;
            sinkfd->type = 'a';
            sinkfd->sink = sink;
            list_add(&sinkfd->node_sink, &sink->sinkfds);
            list_add(&sinkfd->node_ctx, &sink->ctx->sinkfds);

            if (ps->nfds < newfd + 1)
                ps->nfds = newfd + 1;
            FD_SET(newfd, &ps->fds);

            if (pos->events.on_accept)
                pos->events.on_accept(pos->fd, newfd);
        } else /* recv */ {
            int nread = recv(pos->fd, atbuf_write_pos(pos->rxbuf),
                             atbuf_spare(pos->rxbuf), 0);
            if (nread == -1) {
                LOG_DEBUG("[recv] fd:%d, %s", pos->fd, strerror(errno));
                FD_CLR(pos->fd, &ps->fds);
                sink->ops.close(sink, pos->fd);
            } else if (nread == 0) {
                LOG_DEBUG("[recv] fd:%d, finished", pos->fd);
                FD_CLR(pos->fd, &ps->fds);
                sink->ops.close(sink, pos->fd);
            } else {
                atbuf_write_advance(pos->rxbuf, nread);
                gettimeofday(&pos->ts_poll_recv, NULL);
            }
        }
    }

    return 0;
}

static struct apisink_operations unix_s_ops = {
    .open = unix_s_open,
    .close = unix_s_close,
    .ioctl = NULL,
    .send = unix_s_send,
    .recv = unix_s_recv,
    .poll = unix_s_poll,
};

/**
 * unix domain socket client
 */

static int unix_c_open(struct apisink *sink, const char *addr)
{
    int fd = socket(PF_UNIX, SOCK_STREAM, 0);
    if (fd == -1)
        return -1;

    int rc = 0;
    struct sockaddr_un sockaddr = {0};
    sockaddr.sun_family = PF_UNIX;
    snprintf(sockaddr.sun_path, sizeof(sockaddr.sun_path), "%s", addr);

    rc = connect(fd, (struct sockaddr *)&sockaddr, sizeof(sockaddr));
    if (rc == -1) {
        close(fd);
        return -1;
    }

    struct sinkfd *sinkfd = sinkfd_new();
    sinkfd->fd = fd;
    snprintf(sinkfd->addr, sizeof(sinkfd->addr), "%s", addr);
    sinkfd->sink = sink;
    list_add(&sinkfd->node_sink, &sink->sinkfds);
    list_add(&sinkfd->node_ctx, &sink->ctx->sinkfds);

    struct posix_sink *ps = container_of(sink, struct posix_sink, sink);
    FD_SET(fd, &ps->fds);
    ps->nfds = fd + 1;

    return fd;
}

static int unix_c_send(struct apisink *sink, int fd, const void *buf, size_t len)
{
    UNUSED(sink);
    return send(fd, buf, len, 0);
}

static int unix_c_recv(struct apisink *sink, int fd, void *buf, size_t size)
{
    UNUSED(sink);
    return recv(fd, buf, size, 0);
}

static int unix_c_poll(struct apisink *sink)
{
    struct posix_sink *ps = container_of(sink, struct posix_sink, sink);

    struct timeval tv = { 0, 0 };
    fd_set recvfds;
    memcpy(&recvfds, &ps->fds, sizeof(recvfds));

    int nr_recv_fds = select(ps->nfds, &recvfds, NULL, NULL, &tv);
    if (nr_recv_fds == -1) {
        if (errno == EINTR)
            return 0;
        LOG_ERROR("[select] %s", strerror(errno));
        return -1;
    }

    struct sinkfd *pos, *n;
    list_for_each_entry_safe(pos, n, &sink->sinkfds, node_sink) {
        if (nr_recv_fds == 0) break;

        if (!FD_ISSET(pos->fd, &recvfds))
            continue;

        nr_recv_fds--;

        int nread = recv(pos->fd, atbuf_write_pos(pos->rxbuf),
                            atbuf_spare(pos->rxbuf), 0);
        if (nread == -1) {
            LOG_DEBUG("[recv] fd:%d, %s", pos->fd, strerror(errno));
            FD_CLR(pos->fd, &ps->fds);
            sink->ops.close(sink, pos->fd);
        } else if (nread == 0) {
            LOG_DEBUG("[recv] fd:%d, finished", pos->fd);
            FD_CLR(pos->fd, &ps->fds);
            sink->ops.close(sink, pos->fd);
        } else {
            atbuf_write_advance(pos->rxbuf, nread);
            gettimeofday(&pos->ts_poll_recv, NULL);
        }
    }

    return 0;
}

static struct apisink_operations unix_c_ops = {
    .open = unix_c_open,
    .close = __fd_close,
    .ioctl = NULL,
    .send = unix_c_send,
    .recv = unix_c_recv,
    .poll = unix_c_poll,
};

/**
 * tcp server
 */

static int tcp_s_open(struct apisink *sink, const char *addr)
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
    sinkfd->type = 'l';
    snprintf(sinkfd->addr, sizeof(sinkfd->addr), "%s", addr);
    sinkfd->sink = sink;
    list_add(&sinkfd->node_sink, &sink->sinkfds);
    list_add(&sinkfd->node_ctx, &sink->ctx->sinkfds);

    struct posix_sink *tcp_s_sink = container_of(sink, struct posix_sink, sink);
    FD_SET(fd, &tcp_s_sink->fds);
    tcp_s_sink->nfds = fd + 1;

    return fd;
}

static struct apisink_operations tcp_s_ops = {
    .open = tcp_s_open,
    .close = __fd_close,
    .ioctl = NULL,
    .send = unix_s_send,
    .recv = unix_s_recv,
    .poll = unix_s_poll,
};

/**
 * tcp client
 */

static int tcp_c_open(struct apisink *sink, const char *addr)
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

    rc = connect(fd, (struct sockaddr *)&sockaddr, sizeof(sockaddr));
    if (rc == -1) {
        close(fd);
        return -1;
    }

    struct sinkfd *sinkfd = sinkfd_new();
    sinkfd->fd = fd;
    sinkfd->type = 'c';
    snprintf(sinkfd->addr, sizeof(sinkfd->addr), "%s", addr);
    sinkfd->sink = sink;
    list_add(&sinkfd->node_sink, &sink->sinkfds);
    list_add(&sinkfd->node_ctx, &sink->ctx->sinkfds);

    struct posix_sink *tcp_c_sink = container_of(sink, struct posix_sink, sink);
    FD_SET(fd, &tcp_c_sink->fds);
    tcp_c_sink->nfds = fd + 1;

    return fd;
}

static struct apisink_operations tcp_c_ops = {
    .open = tcp_c_open,
    .close = __fd_close,
    .ioctl = NULL,
    .send = unix_c_send,
    .recv = unix_c_recv,
    .poll = unix_c_poll,
};

/**
 * serial
 */

static int serial_open(struct apisink *sink, const char *addr)
{
    int fd = open(addr, O_RDWR | O_NOCTTY | O_NDELAY);
    if (fd == -1) return -1;

    struct sinkfd *sinkfd = sinkfd_new();
    sinkfd->fd = fd;
    snprintf(sinkfd->addr, sizeof(sinkfd->addr), "%s", addr);
    sinkfd->sink = sink;
    list_add(&sinkfd->node_sink, &sink->sinkfds);
    list_add(&sinkfd->node_ctx, &sink->ctx->sinkfds);

    struct posix_sink *serial_sink = container_of(sink, struct posix_sink, sink);
    FD_SET(fd, &serial_sink->fds);
    serial_sink->nfds = fd + 1;

    return fd;
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
    struct posix_sink *ps = container_of(sink, struct posix_sink, sink);

    struct timeval tv = { 0, 0 };
    fd_set recvfds;
    memcpy(&recvfds, &ps->fds, sizeof(recvfds));

    int nr_recv_fds = select(ps->nfds, &recvfds, NULL, NULL, &tv);
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
            sink->ops.close(sink, pos->fd);
        } else if (nread == 0) {
            LOG_DEBUG("[read] (%d) finished");
            sink->ops.close(sink, pos->fd);
        } else {
            atbuf_write_advance(pos->rxbuf, nread);
            gettimeofday(&pos->ts_poll_recv, NULL);
        }
    }

    return 0;
}

static struct apisink_operations serial_ops = {
    .open = serial_open,
    .close = __fd_close,
    .ioctl = serial_ioctl,
    .send = serial_send,
    .recv = serial_recv,
    .poll = serial_poll,
};

/**
 * can
 */

static int can_open(struct apisink *sink, const char *addr)
{
    int fd = socket(PF_CAN, SOCK_RAW, CAN_RAW);
    if (fd == -1)
        return -1;

    int rc = 0;
    struct ifreq ifr;
    struct sockaddr_can sockaddr = {0};
    strcpy(ifr.ifr_name, addr);
    ioctl(fd, SIOCGIFINDEX, &ifr);
    sockaddr.can_family = AF_CAN;
    sockaddr.can_ifindex = ifr.ifr_ifindex;

    rc = bind(fd, (struct sockaddr *)&sockaddr, sizeof(sockaddr));
    if (rc == -1) {
        close(fd);
        return -1;
    }

    struct sinkfd *sinkfd = sinkfd_new();
    sinkfd->fd = fd;
    sinkfd->type = 'c';
    snprintf(sinkfd->addr, sizeof(sinkfd->addr), "%s", addr);
    sinkfd->sink = sink;
    list_add(&sinkfd->node_sink, &sink->sinkfds);
    list_add(&sinkfd->node_ctx, &sink->ctx->sinkfds);

    struct posix_sink *tcp_c_sink = container_of(sink, struct posix_sink, sink);
    FD_SET(fd, &tcp_c_sink->fds);
    tcp_c_sink->nfds = fd + 1;

    return fd;
}

static int can_send(struct apisink *sink, int fd, const void *buf, size_t len)
{
    UNUSED(sink);
    return write(fd, buf, len);
}

static int can_recv(struct apisink *sink, int fd, void *buf, size_t size)
{
    UNUSED(sink);
    return read(fd, buf, size);
}

static int can_poll(struct apisink *sink)
{
    struct posix_sink *ps = container_of(sink, struct posix_sink, sink);

    struct timeval tv = { 0, 0 };
    fd_set recvfds;
    memcpy(&recvfds, &ps->fds, sizeof(recvfds));

    int nr_recv_fds = select(ps->nfds, &recvfds, NULL, NULL, &tv);
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
                         sizeof(struct can_frame));
        if (nread == -1) {
            LOG_DEBUG("[read] (%d) %s", errno, strerror(errno));
            sink->ops.close(sink, pos->fd);
        } else if (nread == 0) {
            LOG_DEBUG("[read] (%d) finished");
            sink->ops.close(sink, pos->fd);
        } else {
            atbuf_write_advance(pos->rxbuf, nread);
            gettimeofday(&pos->ts_poll_recv, NULL);
        }
    }

    return 0;
}

static struct apisink_operations can_ops = {
    .open = can_open,
    .close = __fd_close,
    .ioctl = NULL,
    .send = can_send,
    .recv = can_recv,
    .poll = can_poll,
};

/**
 * posix_sink
 */

int apix_enable_posix(struct apix *ctx)
{
    // unix_s
    struct posix_sink *unix_s_sink = calloc(1, sizeof(struct posix_sink));
    apisink_init(&unix_s_sink->sink, APISINK_UNIX_S, &unix_s_ops);
    apix_sink_register(ctx, &unix_s_sink->sink);

    // unix_c
    struct posix_sink *unix_c_sink = calloc(1, sizeof(struct posix_sink));
    apisink_init(&unix_c_sink->sink, APISINK_UNIX_C, &unix_c_ops);
    apix_sink_register(ctx, &unix_c_sink->sink);

    // tcp_s
    struct posix_sink *tcp_s_sink = calloc(1, sizeof(struct posix_sink));
    apisink_init(&tcp_s_sink->sink, APISINK_TCP_S, &tcp_s_ops);
    apix_sink_register(ctx, &tcp_s_sink->sink);

    // tcp_c
    struct posix_sink *tcp_c_sink = calloc(1, sizeof(struct posix_sink));
    apisink_init(&tcp_c_sink->sink, APISINK_TCP_C, &tcp_c_ops);
    apix_sink_register(ctx, &tcp_c_sink->sink);

    // serial
    struct posix_sink *serial_sink = calloc(1, sizeof(struct posix_sink));
    apisink_init(&serial_sink->sink, APISINK_SERIAL, &serial_ops);
    apix_sink_register(ctx, &serial_sink->sink);

    // can
    struct posix_sink *can_sink = calloc(1, sizeof(struct posix_sink));
    apisink_init(&can_sink->sink, APISINK_CAN, &can_ops);
    apix_sink_register(ctx, &can_sink->sink);

    return 0;
}

void apix_disable_posix(struct apix *ctx)
{
    struct apisink *pos, *n;
    list_for_each_entry_safe(pos, n, &ctx->sinks, node) {
        // unix_s
        if (strcmp(pos->id, APISINK_UNIX_S) == 0) {
            struct posix_sink *unix_s_sink =
                container_of(pos, struct posix_sink, sink);
            apix_sink_unregister(ctx, &unix_s_sink->sink);
            apisink_fini(&unix_s_sink->sink);
            free(unix_s_sink);
        }

        // unix_c
        if (strcmp(pos->id, APISINK_UNIX_C) == 0) {
            struct posix_sink *unix_c_sink =
                container_of(pos, struct posix_sink, sink);
            apix_sink_unregister(ctx, &unix_c_sink->sink);
            apisink_fini(&unix_c_sink->sink);
            free(unix_c_sink);
        }

        // tcp_s
        if (strcmp(pos->id, APISINK_TCP_S) == 0) {
            struct posix_sink *tcp_s_sink =
                container_of(pos, struct posix_sink, sink);
            apix_sink_unregister(ctx, &tcp_s_sink->sink);
            apisink_fini(&tcp_s_sink->sink);
            free(tcp_s_sink);
        }

        // tcp_c
        if (strcmp(pos->id, APISINK_TCP_C) == 0) {
            struct posix_sink *tcp_c_sink =
                container_of(pos, struct posix_sink, sink);
            apix_sink_unregister(ctx, &tcp_c_sink->sink);
            apisink_fini(&tcp_c_sink->sink);
            free(tcp_c_sink);
        }

        // serial
        if (strcmp(pos->id, APISINK_SERIAL) == 0) {
            struct posix_sink *serial_sink =
                container_of(pos, struct posix_sink, sink);
            apix_sink_unregister(ctx, &serial_sink->sink);
            apisink_fini(&serial_sink->sink);
            free(serial_sink);
        }

        // can
        if (strcmp(pos->id, APISINK_CAN) == 0) {
            struct posix_sink *can_sink =
                container_of(pos, struct posix_sink, sink);
            apix_sink_unregister(ctx, &can_sink->sink);
            apisink_fini(&can_sink->sink);
            free(can_sink);
        }
    }
}

#endif
