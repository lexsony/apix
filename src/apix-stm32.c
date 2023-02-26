#if defined __arm__ && !defined __linux__

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
#include <fcntl.h>

#include "apix-private.h"
#include "apix-stm32.h"
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
    list_add(&sinkfd->ln_sink, &sink->sinkfds);
    list_add(&sinkfd->ln_ctx, &sink->ctx->sinkfds);

    struct posix_sink *tcp_s_sink = container_of(sink, struct posix_sink, sink);
    FD_SET(fd, &tcp_s_sink->fds);
    tcp_s_sink->nfds = fd + 1;

    return fd;
}

static int tcp_s_close(struct apisink *sink, int fd)
{
    struct sinkfd *sinkfd = find_sinkfd_in_apisink(sink, fd);
    if (sinkfd == NULL)
        return -1;
    close(sinkfd->fd);
    if (strcmp(sink->id, APISINK_STM32_TCP_S) == 0)
        unlink(sinkfd->addr);
    sinkfd_destroy(sinkfd);
    return 0;
}

static int tcp_s_send(struct apisink *sink, int fd, const void *buf, size_t len)
{
    UNUSED(sink);
    return send(fd, buf, len, 0);
}

static int tcp_s_recv(struct apisink *sink, int fd, void *buf, size_t size)
{
    UNUSED(sink);
    return recv(fd, buf, size, 0);
}

static int tcp_s_poll(struct apisink *sink)
{
    struct posix_sink *tcp_s_sink = container_of(sink, struct posix_sink, sink);
    if (tcp_s_sink->nfds == 0) return 0;

    struct timeval tv = { 0, 0 };
    fd_set recvfds;
    memcpy(&recvfds, &tcp_s_sink->fds, sizeof(recvfds));

    int nr_recv_fds = select(tcp_s_sink->nfds, &recvfds, NULL, NULL, &tv);
    if (nr_recv_fds == -1) {
        if (errno == EINTR)
            return 0;
        LOG_ERROR("[select] %s", strerror(errno));
        return -1;
    }

    struct sinkfd *pos, *n;
    list_for_each_entry_safe(pos, n, &sink->sinkfds, ln_sink) {
        if (nr_recv_fds == 0) break;

        if (!FD_ISSET(pos->fd, &recvfds))
            continue;

        nr_recv_fds--;

        // accept
        //if (pos->listen == 1) {
        //    int newfd = accept(pos->fd, NULL, NULL);
        //    if (newfd == -1) {
        //        LOG_ERROR("[accept] fd:%d, %s", pos->fd, strerror(errno));
        //        continue;
        //    }
        //    LOG_DEBUG("[accept] fd:%d, newfd:%d", pos->fd, newfd);

        //    struct sinkfd *sinkfd = sinkfd_new();
        //    sinkfd->fd = newfd;
        //    sinkfd->sink = sink;
        //    list_add(&sinkfd->ln_sink, &sink->sinkfds);
        //    list_add(&sinkfd->ln_ctx, &sink->ctx->sinkfds);

        //    if (tcp_s_sink->nfds < newfd + 1)
        //        tcp_s_sink->nfds = newfd + 1;
        //    FD_SET(newfd, &tcp_s_sink->fds);
        //} else /* recv */ {
            int nread = recv(pos->fd, atbuf_write_pos(pos->rxbuf),
                             atbuf_spare(pos->rxbuf), 0);
            if (nread == -1) {
                LOG_DEBUG("[recv] fd:%d, %s", pos->fd, strerror(errno));
                FD_CLR(pos->fd, &tcp_s_sink->fds);
                sink->ops.close(sink, pos->fd);
            } else if (nread == 0) {
                LOG_DEBUG("[recv] fd:%d, finished", pos->fd);
                FD_CLR(pos->fd, &tcp_s_sink->fds);
                sink->ops.close(sink, pos->fd);
            } else {
                atbuf_write_advance(pos->rxbuf, nread);
                gettimeofday(&pos->ts_poll_recv, NULL);
            }
        //}
    }

    return 0;
}

static const struct apisink_operations tcp_s_ops = {
    .open = tcp_s_open,
    .close = tcp_s_close,
    .ioctl = NULL,
    .send = tcp_s_send,
    .recv = tcp_s_recv,
    .poll = tcp_s_poll,
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
    sinkfd->type = 'l';
    snprintf(sinkfd->addr, sizeof(sinkfd->addr), "%s", addr);
    sinkfd->sink = sink;
    list_add(&sinkfd->ln_sink, &sink->sinkfds);
    list_add(&sinkfd->ln_ctx, &sink->ctx->sinkfds);

    struct posix_sink *tcp_c_sink = container_of(sink, struct posix_sink, sink);
    FD_SET(fd, &tcp_c_sink->fds);
    tcp_c_sink->nfds = fd + 1;

    return fd;
}

static int tcp_c_close(struct apisink *sink, int fd)
{
    struct sinkfd *sinkfd = find_sinkfd_in_apisink(sink, fd);
    if (sinkfd == NULL)
        return -1;

    close(sinkfd->fd);
    sinkfd_destroy(sinkfd);

    struct posix_sink *tcp_c_sink = container_of(sink, struct posix_sink, sink);
    FD_CLR(fd, &tcp_c_sink->fds);

    return 0;
}

static int tcp_c_send(struct apisink *sink, int fd, const void *buf, size_t len)
{
    UNUSED(sink);
    return send(fd, buf, len, 0);
}

static int tcp_c_recv(struct apisink *sink, int fd, void *buf, size_t size)
{
    UNUSED(sink);
    return recv(fd, buf, size, 0);
}

static int tcp_c_poll(struct apisink *sink)
{
    struct posix_sink *tcp_c_sink = container_of(sink, struct posix_sink, sink);
    if (tcp_c_sink->nfds == 0) return 0;

    struct timeval tv = { 0, 0 };
    fd_set recvfds;
    memcpy(&recvfds, &tcp_c_sink->fds, sizeof(recvfds));

    int nr_recv_fds = select(tcp_c_sink->nfds, &recvfds, NULL, NULL, &tv);
    if (nr_recv_fds == -1) {
        if (errno == EINTR)
            return 0;
        LOG_ERROR("[select] %s", strerror(errno));
        return -1;
    }

    struct sinkfd *pos, *n;
    list_for_each_entry_safe(pos, n, &sink->sinkfds, ln_sink) {
        if (nr_recv_fds == 0) break;

        if (!FD_ISSET(pos->fd, &recvfds))
            continue;

        nr_recv_fds--;

        int nread = recv(pos->fd, atbuf_write_pos(pos->rxbuf),
                         atbuf_spare(pos->rxbuf), 0);
        if (nread == -1) {
            LOG_DEBUG("[recv] fd:%d, %s", pos->fd, strerror(errno));
            FD_CLR(pos->fd, &tcp_c_sink->fds);
            sink->ops.close(sink, pos->fd);
        } else if (nread == 0) {
            LOG_DEBUG("[recv] fd:%d, finished", pos->fd);
            FD_CLR(pos->fd, &tcp_c_sink->fds);
            sink->ops.close(sink, pos->fd);
        } else {
            atbuf_write_advance(pos->rxbuf, nread);
            gettimeofday(&pos->ts_poll_recv, NULL);
        }
    }

    return 0;
}

static const struct apisink_operations tcp_c_ops = {
    .open = tcp_c_open,
    .close = tcp_c_close,
    .ioctl = NULL,
    .send = tcp_c_send,
    .recv = tcp_c_recv,
    .poll = tcp_c_poll,
};

/**
 * com
 */

static int com_open(struct apisink *sink, const char *addr)
{
    int fd = open(addr, O_RDWR | O_NOCTTY);
    if (fd == -1) return -1;

    struct sinkfd *sinkfd = sinkfd_new();
    sinkfd->fd = fd;
    snprintf(sinkfd->addr, sizeof(sinkfd->addr), "%s", addr);
    sinkfd->sink = sink;
    list_add(&sinkfd->ln_sink, &sink->sinkfds);
    list_add(&sinkfd->ln_ctx, &sink->ctx->sinkfds);

    return fd;
}

static int com_close(struct apisink *sink, int fd)
{
    struct sinkfd *sinkfd = find_sinkfd_in_apisink(sink, fd);
    if (sinkfd == NULL)
        return -1;
    close(sinkfd->fd);
    sinkfd_destroy(sinkfd);
    return 0;
}

static int
com_ioctl(struct apisink *sink, int fd, unsigned int cmd, unsigned long arg)
{
    UNUSED(sink);
    UNUSED(cmd);
    return 0;
}

static int com_send(struct apisink *sink, int fd, const void *buf, size_t len)
{
    UNUSED(sink);
    return write(fd, buf, len);
}

static int com_recv(struct apisink *sink, int fd, void *buf, size_t size)
{
    UNUSED(sink);
    return read(fd, buf, size);
}

static int com_poll(struct apisink *sink)
{
    struct sinkfd *pos;
    list_for_each_entry(pos, &sink->sinkfds, ln_sink) {
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

static const struct apisink_operations com_ops = {
    .open = com_open,
    .close = com_close,
    .ioctl = com_ioctl,
    .send = com_send,
    .recv = com_recv,
    .poll = com_poll,
};

int apix_enable_stm32(struct apix *ctx)
{
    // tcp_s
    struct posix_sink *tcp_s_sink = calloc(1, sizeof(struct posix_sink));
    apisink_init(&tcp_s_sink->sink, APISINK_STM32_TCP_S, &tcp_s_ops);
    apix_sink_register(ctx, &tcp_s_sink->sink);

    // tcp_c
    struct posix_sink *tcp_c_sink = calloc(1, sizeof(struct posix_sink));
    apisink_init(&tcp_c_sink->sink, APISINK_STM32_TCP_C, &tcp_c_ops);
    apix_sink_register(ctx, &tcp_c_sink->sink);

    // com
    struct posix_sink *com_sink = calloc(1, sizeof(struct posix_sink));
    apisink_init(&com_sink->sink, APISINK_STM32_COM, &com_ops);
    apix_sink_register(ctx, &com_sink->sink);

    return 0;
}

void apix_disable_stm32(struct apix *ctx)
{
    struct apisink *pos, *n;
    list_for_each_entry_safe(pos, n, &ctx->sinks, ln) {
        // tcp_s
        if (strcmp(pos->id, APISINK_STM32_TCP_S) == 0) {
            struct posix_sink *tcp_s_sink =
                container_of(pos, struct posix_sink, sink);
            apix_sink_unregister(ctx, &tcp_s_sink->sink);
            apisink_fini(&tcp_s_sink->sink);
            free(tcp_s_sink);
        }

        // tcp_c
        if (strcmp(pos->id, APISINK_STM32_TCP_C) == 0) {
            struct posix_sink *tcp_c_sink =
                container_of(pos, struct posix_sink, sink);
            apix_sink_unregister(ctx, &tcp_c_sink->sink);
            apisink_fini(&tcp_c_sink->sink);
            free(tcp_c_sink);
        }

        // com
        if (strcmp(pos->id, APISINK_STM32_COM) == 0) {
            struct posix_sink *com_sink =
                container_of(pos, struct posix_sink, sink);
            apix_sink_unregister(ctx, &com_sink->sink);
            apisink_fini(&com_sink->sink);
            free(com_sink);
        }
    }
}

#endif
