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
#ifndef __APPLE__
#include <termios.h>
#include <linux/can.h>
#include <linux/can/raw.h>
#endif
#include <sys/ioctl.h>
#include <net/if.h>

#include "apix-private.h"
#include "apix-posix.h"
#include "unused.h"
#include "log.h"

struct posix_sink {
    struct sink sink;
    // for select
    fd_set fds;
    int nfds;
};

static int __fd_close(struct stream *stream)
{
    close(stream->fd);
    stream_free(stream);

    struct posix_sink *unix_c_sink =
        container_of(stream->sink, struct posix_sink, sink);
    FD_CLR(stream->fd, &unix_c_sink->fds);

    return 0;
}

/**
 * unix domain socket server
 */

static struct stream *unix_s_open(struct sink *sink, const char *addr)
{
    int fd = socket(PF_UNIX, SOCK_STREAM, 0);
    if (fd == -1)
        return NULL;

    int rc = 0;
    struct sockaddr_un sockaddr = {0};
    sockaddr.sun_family = PF_UNIX;
    snprintf(sockaddr.sun_path, sizeof(sockaddr.sun_path), "%s", addr);

    unlink(addr);
    rc = bind(fd, (struct sockaddr *)&sockaddr, sizeof(sockaddr));
    if (rc == -1) {
        close(fd);
        return NULL;
    }

    rc = listen(fd, 100);
    if (rc == -1) {
        close(fd);
        return NULL;
    }

    struct stream *stream = stream_new(sink);
    stream->fd = fd;
    stream->type = STREAM_T_LISTEN;
    snprintf(stream->addr, sizeof(stream->addr), "%s", addr);

    struct posix_sink *ps = container_of(sink, struct posix_sink, sink);
    FD_SET(fd, &ps->fds);
    ps->nfds = fd + 1;

    return stream;
}

static int unix_s_close(struct stream *stream)
{
    if (strcmp(stream->sink->id, SINK_UNIX_S) == 0)
        unlink(stream->addr);

    __fd_close(stream);
    return 0;
}

static struct stream *unix_s_accept(struct stream *stream)
{
    struct posix_sink *ps = container_of(stream->sink, struct posix_sink, sink);

    int newfd = accept(stream->fd, NULL, NULL);
    if (newfd == -1) {
        LOG_ERROR("[%p:accept] #%d %s(%d)",
                  stream->ctx, stream->fd, strerror(errno), errno);
        return NULL;
    }
    LOG_DEBUG("[%p:accept] #%d accept #%d", stream->ctx, stream->fd, newfd);

    struct stream *new_stream = stream_new(stream->sink);
    new_stream->fd = newfd;
    new_stream->father = stream;
    new_stream->type = STREAM_T_ACCEPT;
    new_stream->srrp_mode = stream->srrp_mode;

    if (ps->nfds < newfd + 1)
        ps->nfds = newfd + 1;
    FD_SET(newfd, &ps->fds);

    return new_stream;
}

static int unix_s_send(struct stream *stream, const u8 *buf, u32 len)
{
    return send(stream->fd, buf, len, MSG_NOSIGNAL);
}

static int unix_s_recv(struct stream *stream, u8 *buf, u32 len)
{
    return recv(stream->fd, buf, len, 0);
}

static int unix_s_poll(struct sink *sink)
{
    struct posix_sink *ps = container_of(sink, struct posix_sink, sink);

    struct timeval tv = { 0, 0 };
    fd_set recvfds;
    memcpy(&recvfds, &ps->fds, sizeof(recvfds));

    int nr_recv_fds = select(ps->nfds, &recvfds, NULL, NULL, &tv);
    if (nr_recv_fds == -1) {
        if (errno == EINTR)
            return 0;
        LOG_ERROR("[%p:select] %s(%d)", sink->ctx, strerror(errno), errno);
        return -1;
    }

    struct stream *pos, *n;
    list_for_each_entry_safe(pos, n, &sink->streams, ln_sink) {
        if (nr_recv_fds == 0) break;

        if (!FD_ISSET(pos->fd, &recvfds))
            continue;

        nr_recv_fds--;

        // accept
        if (pos->type == STREAM_T_LISTEN) {
            pos->ev.bits.accept = 1;
        } else /* recv */ {
            char buf[1024] = {0};
            int nread = recv(pos->fd, buf, sizeof(buf), 0);
            if (nread == -1) {
                LOG_DEBUG("[%p:recv] #%d %s(%d)", sink->ctx, pos->fd, strerror(errno), errno);
                sink->ops.close(pos);
            } else if (nread == 0) {
                LOG_DEBUG("[%p:recv] #%d finished", sink->ctx, pos->fd);
                sink->ops.close(pos);
            } else {
                LOG_TRACE("[%p:recv] #%d packet in", sink->ctx, pos->fd);
                vpack(pos->rxbuf, buf, nread);
                gettimeofday(&pos->ts_poll_recv, NULL);
                pos->ev.bits.pollin = 1;
            }
        }
    }

    return 0;
}

static struct sink_operations unix_s_ops = {
    .open = unix_s_open,
    .close = unix_s_close,
    .accept = unix_s_accept,
    .ioctl = NULL,
    .send = unix_s_send,
    .recv = unix_s_recv,
    .poll = unix_s_poll,
};

/**
 * unix domain socket client
 */

static struct stream *unix_c_open(struct sink *sink, const char *addr)
{
    int fd = socket(PF_UNIX, SOCK_STREAM, 0);
    if (fd == -1)
        return NULL;

    int rc = 0;
    struct sockaddr_un sockaddr = {0};
    sockaddr.sun_family = PF_UNIX;
    snprintf(sockaddr.sun_path, sizeof(sockaddr.sun_path), "%s", addr);

    rc = connect(fd, (struct sockaddr *)&sockaddr, sizeof(sockaddr));
    if (rc == -1) {
        close(fd);
        return NULL;
    }

    struct stream *stream = stream_new(sink);
    stream->fd = fd;
    snprintf(stream->addr, sizeof(stream->addr), "%s", addr);

    struct posix_sink *ps = container_of(sink, struct posix_sink, sink);
    FD_SET(fd, &ps->fds);
    ps->nfds = fd + 1;

    return stream;
}

static int unix_c_send(struct stream *stream, const u8 *buf, u32 len)
{
    return send(stream->fd, buf, len, MSG_NOSIGNAL);
}

static int unix_c_recv(struct stream *stream, u8 *buf, u32 len)
{
    return recv(stream->fd, buf, len, 0);
}

static int unix_c_poll(struct sink *sink)
{
    struct posix_sink *ps = container_of(sink, struct posix_sink, sink);

    struct timeval tv = { 0, 0 };
    fd_set recvfds;
    memcpy(&recvfds, &ps->fds, sizeof(recvfds));

    int nr_recv_fds = select(ps->nfds, &recvfds, NULL, NULL, &tv);
    if (nr_recv_fds == -1) {
        if (errno == EINTR)
            return 0;
        LOG_ERROR("[%p:select] %s(%d)", sink->ctx, strerror(errno), errno);
        return -1;
    }

    struct stream *pos, *n;
    list_for_each_entry_safe(pos, n, &sink->streams, ln_sink) {
        if (nr_recv_fds == 0) break;

        if (!FD_ISSET(pos->fd, &recvfds))
            continue;

        nr_recv_fds--;

        char buf[1024] = {0};
        int nread = recv(pos->fd, buf, sizeof(buf), 0);
        if (nread == -1) {
            LOG_DEBUG("[%p:recv] #%d %s(%d)", sink->ctx, pos->fd, strerror(errno), errno);
            sink->ops.close(pos);
        } else if (nread == 0) {
            LOG_DEBUG("[%p:recv] #%d finished", sink->ctx, pos->fd);
            sink->ops.close(pos);
        } else {
            LOG_TRACE("[%p:recv] #%d packet in", sink->ctx, pos->fd);
            vpack(pos->rxbuf, buf, nread);
            gettimeofday(&pos->ts_poll_recv, NULL);
            pos->ev.bits.pollin = 1;
        }
    }

    return 0;
}

static struct sink_operations unix_c_ops = {
    .open = unix_c_open,
    .close = __fd_close,
    .accept = NULL,
    .ioctl = NULL,
    .send = unix_c_send,
    .recv = unix_c_recv,
    .poll = unix_c_poll,
};

/**
 * tcp server
 */

static struct stream *tcp_s_open(struct sink *sink, const char *addr)
{
    int fd = socket(PF_INET, SOCK_STREAM, 0);
    if (fd == -1)
        return NULL;

    u32 host;
    u16 port;
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
        return NULL;
    }

    rc = listen(fd, 100);
    if (rc == -1) {
        close(fd);
        return NULL;
    }

    struct stream *stream = stream_new(sink);
    stream->fd = fd;
    stream->type = STREAM_T_LISTEN;
    snprintf(stream->addr, sizeof(stream->addr), "%s", addr);

    struct posix_sink *tcp_s_sink = container_of(sink, struct posix_sink, sink);
    FD_SET(fd, &tcp_s_sink->fds);
    tcp_s_sink->nfds = fd + 1;

    return stream;
}

static struct sink_operations tcp_s_ops = {
    .open = tcp_s_open,
    .close = __fd_close,
    .accept = unix_s_accept,
    .ioctl = NULL,
    .send = unix_s_send,
    .recv = unix_s_recv,
    .poll = unix_s_poll,
};

/**
 * tcp client
 */

static struct stream *tcp_c_open(struct sink *sink, const char *addr)
{
    int fd = socket(PF_INET, SOCK_STREAM, 0);
    if (fd == -1)
        return NULL;

    u32 host;
    u16 port;
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
        return NULL;
    }

    struct stream *stream = stream_new(sink);
    stream->fd = fd;
    stream->type = STREAM_T_CONNECT;
    snprintf(stream->addr, sizeof(stream->addr), "%s", addr);

    struct posix_sink *tcp_c_sink = container_of(sink, struct posix_sink, sink);
    FD_SET(fd, &tcp_c_sink->fds);
    tcp_c_sink->nfds = fd + 1;

    return stream;
}

static struct sink_operations tcp_c_ops = {
    .open = tcp_c_open,
    .close = __fd_close,
    .accept = NULL,
    .ioctl = NULL,
    .send = unix_c_send,
    .recv = unix_c_recv,
    .poll = unix_c_poll,
};

#ifndef __APPLE__

/**
 * com
 */

static struct stream *com_open(struct sink *sink, const char *addr)
{
    int fd = open(addr, O_RDWR | O_NOCTTY | O_NDELAY);
    if (fd == -1)
        return NULL;

    struct stream *stream = stream_new(sink);
    stream->fd = fd;
    snprintf(stream->addr, sizeof(stream->addr), "%s", addr);

    struct posix_sink *com_sink = container_of(sink, struct posix_sink, sink);
    FD_SET(fd, &com_sink->fds);
    com_sink->nfds = fd + 1;

    return stream;
}

static int
com_ioctl(struct stream *stream, unsigned int cmd, unsigned long arg)
{
    UNUSED(cmd);
    struct ioctl_com_param *sp = (struct ioctl_com_param *)arg;
    struct termios newtio, oldtio;

    if (tcgetattr(stream->fd, &oldtio) != 0)
        return -1;

    bzero(&newtio, sizeof(newtio));
    newtio.c_cflag |= (CLOCAL | CREAD);
    newtio.c_cflag &= ~CSIZE;

    if (sp->baud == COM_ARG_BAUD_9600) {
        cfsetispeed(&newtio, B9600);
    } else if (sp->baud == COM_ARG_BAUD_115200) {
        cfsetispeed(&newtio, B115200);
    } else {
        return -1;
    }
    if (sp->bits == COM_ARG_BITS_7) {
        newtio.c_cflag |= CS7;
    } else if (sp->bits == COM_ARG_BITS_8) {
        newtio.c_cflag |= CS8;
    } else {
        return -1;
    }
    if (sp->parity == COM_ARG_PARITY_O) {
        newtio.c_cflag |= PARENB;
        newtio.c_cflag |= PARODD;
        newtio.c_cflag |= (INPCK | ISTRIP);
    } else if (sp->parity == COM_ARG_PARITY_E) {
        newtio.c_cflag |= PARENB;
        newtio.c_cflag &= ~PARODD;
        newtio.c_cflag |= (INPCK | ISTRIP);
    } else if (sp->parity == COM_ARG_PARITY_N) {
        newtio.c_cflag &= ~PARENB;
    } else {
        return -1;
    }
    if (sp->stop == COM_ARG_STOP_1) {
        newtio.c_cflag &= ~CSTOPB;
    } else if (sp->stop == COM_ARG_STOP_2) {
        newtio.c_cflag |= CSTOPB;
    } else {
        return -1;
    }

    newtio.c_cc[VTIME] = 0;
    newtio.c_cc[VMIN] = 0;
    tcflush(stream->fd, TCIFLUSH);

    if (tcsetattr(stream->fd, TCSANOW, &newtio) != 0)
        return -1;

    return 0;
}

static int com_send(struct stream *stream, const u8 *buf, u32 len)
{
    return write(stream->fd, buf, len);
}

static int com_recv(struct stream *stream, u8 *buf, u32 len)
{
    return read(stream->fd, buf, len);
}

static int com_poll(struct sink *sink)
{
    struct posix_sink *ps = container_of(sink, struct posix_sink, sink);

    struct timeval tv = { 0, 0 };
    fd_set recvfds;
    memcpy(&recvfds, &ps->fds, sizeof(recvfds));

    int nr_recv_fds = select(ps->nfds, &recvfds, NULL, NULL, &tv);
    if (nr_recv_fds == -1) {
        if (errno == EINTR)
            return 0;
        LOG_ERROR("[%p:select] %s(%d)", sink->ctx, strerror(errno), errno);
        return -1;
    }

    struct stream *pos, *n;
    list_for_each_entry_safe(pos, n, &sink->streams, ln_sink) {
        if (nr_recv_fds == 0) break;

        if (!FD_ISSET(pos->fd, &recvfds))
            continue;

        nr_recv_fds--;

        char buf[1024] = {0};
        int nread = read(pos->fd, buf, sizeof(buf));
        if (nread == -1) {
            LOG_DEBUG("[%p:read] #%d %s(%d)", sink->ctx, pos->fd, strerror(errno), errno);
            sink->ops.close(pos);
        } else if (nread == 0) {
            LOG_DEBUG("[%p:read] #%d finished", sink->ctx, pos->fd);
            sink->ops.close(pos);
        } else {
            LOG_TRACE("[%p:read] #%d packet in", sink->ctx, pos->fd);
            vpack(pos->rxbuf, buf, nread);
            gettimeofday(&pos->ts_poll_recv, NULL);
            pos->ev.bits.pollin = 1;
        }
    }

    return 0;
}

static struct sink_operations com_ops = {
    .open = com_open,
    .close = __fd_close,
    .accept = NULL,
    .ioctl = com_ioctl,
    .send = com_send,
    .recv = com_recv,
    .poll = com_poll,
};

/**
 * can
 */

static struct stream *can_open(struct sink *sink, const char *addr)
{
    int fd = socket(PF_CAN, SOCK_RAW, CAN_RAW);
    if (fd == -1)
        return NULL;

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
        return NULL;
    }

    struct stream *stream = stream_new(sink);
    stream->fd = fd;
    stream->type = STREAM_T_CONNECT;
    snprintf(stream->addr, sizeof(stream->addr), "%s", addr);

    struct posix_sink *tcp_c_sink = container_of(sink, struct posix_sink, sink);
    FD_SET(fd, &tcp_c_sink->fds);
    tcp_c_sink->nfds = fd + 1;

    return stream;
}

static int can_send(struct stream *stream, const u8 *buf, u32 len)
{
    return write(stream->fd, buf, len);
}

static int can_recv(struct stream *stream, u8 *buf, u32 len)
{
    return read(stream->fd, buf, len);
}

static int can_poll(struct sink *sink)
{
    struct posix_sink *ps = container_of(sink, struct posix_sink, sink);

    struct timeval tv = { 0, 0 };
    fd_set recvfds;
    memcpy(&recvfds, &ps->fds, sizeof(recvfds));

    int nr_recv_fds = select(ps->nfds, &recvfds, NULL, NULL, &tv);
    if (nr_recv_fds == -1) {
        if (errno == EINTR)
            return 0;
        LOG_ERROR("[%p:select] %s(%d)", sink->ctx, strerror(errno), errno);
        return -1;
    }

    struct stream *pos, *n;
    list_for_each_entry_safe(pos, n, &sink->streams, ln_sink) {
        if (nr_recv_fds == 0) break;

        if (!FD_ISSET(pos->fd, &recvfds))
            continue;

        nr_recv_fds--;

        struct can_frame frame = {0};
        int nread = read(pos->fd, &frame, sizeof(struct can_frame));
        if (nread == -1) {
            LOG_DEBUG("[%p:read] #%d %s(%d)", sink->ctx, pos->fd, strerror(errno), errno);
            sink->ops.close(pos);
        } else if (nread == 0) {
            LOG_DEBUG("[%p:read] #%d finished", sink->ctx, pos->fd);
            sink->ops.close(pos);
        } else {
            LOG_TRACE("[%p:read] #%d packet in", sink->ctx, pos->fd);
            vpack(pos->rxbuf, &frame, sizeof(struct can_frame));
            gettimeofday(&pos->ts_poll_recv, NULL);
            pos->ev.bits.pollin = 1;
        }
    }

    return 0;
}

static struct sink_operations can_ops = {
    .open = can_open,
    .close = __fd_close,
    .accept = NULL,
    .ioctl = NULL,
    .send = can_send,
    .recv = can_recv,
    .poll = can_poll,
};

#endif

/**
 * posix_sink
 */

int apix_enable_posix(struct apix *ctx)
{
    // unix_s
    struct posix_sink *unix_s_sink = calloc(1, sizeof(struct posix_sink));
    FD_ZERO(&unix_s_sink->fds);
    sink_init(&unix_s_sink->sink, SINK_UNIX_S, &unix_s_ops);
    apix_sink_register(ctx, &unix_s_sink->sink);

    // unix_c
    struct posix_sink *unix_c_sink = calloc(1, sizeof(struct posix_sink));
    FD_ZERO(&unix_c_sink->fds);
    sink_init(&unix_c_sink->sink, SINK_UNIX_C, &unix_c_ops);
    apix_sink_register(ctx, &unix_c_sink->sink);

    // tcp_s
    struct posix_sink *tcp_s_sink = calloc(1, sizeof(struct posix_sink));
    FD_ZERO(&tcp_s_sink->fds);
    sink_init(&tcp_s_sink->sink, SINK_TCP_S, &tcp_s_ops);
    apix_sink_register(ctx, &tcp_s_sink->sink);

    // tcp_c
    struct posix_sink *tcp_c_sink = calloc(1, sizeof(struct posix_sink));
    FD_ZERO(&tcp_c_sink->fds);
    sink_init(&tcp_c_sink->sink, SINK_TCP_C, &tcp_c_ops);
    apix_sink_register(ctx, &tcp_c_sink->sink);

#ifndef __APPLE__
    // com
    struct posix_sink *com_sink = calloc(1, sizeof(struct posix_sink));
    FD_ZERO(&com_sink->fds);
    sink_init(&com_sink->sink, SINK_COM, &com_ops);
    apix_sink_register(ctx, &com_sink->sink);

    // can
    struct posix_sink *can_sink = calloc(1, sizeof(struct posix_sink));
    FD_ZERO(&can_sink->fds);
    sink_init(&can_sink->sink, SINK_CAN, &can_ops);
    apix_sink_register(ctx, &can_sink->sink);
#endif

    return 0;
}

void apix_disable_posix(struct apix *ctx)
{
    struct sink *pos, *n;
    list_for_each_entry_safe(pos, n, &ctx->sinks, ln) {
        // unix_s
        if (strcmp(pos->id, SINK_UNIX_S) == 0) {
            struct posix_sink *unix_s_sink =
                container_of(pos, struct posix_sink, sink);
            apix_sink_unregister(ctx, &unix_s_sink->sink);
            sink_fini(&unix_s_sink->sink);
            free(unix_s_sink);
        }

        // unix_c
        if (strcmp(pos->id, SINK_UNIX_C) == 0) {
            struct posix_sink *unix_c_sink =
                container_of(pos, struct posix_sink, sink);
            apix_sink_unregister(ctx, &unix_c_sink->sink);
            sink_fini(&unix_c_sink->sink);
            free(unix_c_sink);
        }

        // tcp_s
        if (strcmp(pos->id, SINK_TCP_S) == 0) {
            struct posix_sink *tcp_s_sink =
                container_of(pos, struct posix_sink, sink);
            apix_sink_unregister(ctx, &tcp_s_sink->sink);
            sink_fini(&tcp_s_sink->sink);
            free(tcp_s_sink);
        }

        // tcp_c
        if (strcmp(pos->id, SINK_TCP_C) == 0) {
            struct posix_sink *tcp_c_sink =
                container_of(pos, struct posix_sink, sink);
            apix_sink_unregister(ctx, &tcp_c_sink->sink);
            sink_fini(&tcp_c_sink->sink);
            free(tcp_c_sink);
        }

#ifndef __APPLE__
        // com
        if (strcmp(pos->id, SINK_COM) == 0) {
            struct posix_sink *com_sink =
                container_of(pos, struct posix_sink, sink);
            apix_sink_unregister(ctx, &com_sink->sink);
            sink_fini(&com_sink->sink);
            free(com_sink);
        }

        // can
        if (strcmp(pos->id, SINK_CAN) == 0) {
            struct posix_sink *can_sink =
                container_of(pos, struct posix_sink, sink);
            apix_sink_unregister(ctx, &can_sink->sink);
            sink_fini(&can_sink->sink);
            free(can_sink);
        }
#endif
    }
}

#endif
