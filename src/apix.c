#include <assert.h>
#include <ctype.h>
#include <errno.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <sys/time.h>

#include "apix-private.h"
#include "unused.h"
#include "log.h"

/**
 * apix
 */

static void log_hex_string(const char *buf, uint32_t len)
{
    printf("len: %d, data: ", (int)len);
    for (int i = 0; i < (int)len; i++) {
        if (isprint(buf[i]))
            printf("%c", buf[i]);
        else
            printf("_0x%.2x", buf[i]);
    }
    printf("\n");
}

static void append_srrp_packet(
    struct apix *ctx, struct sinkfd *sinkfd, struct srrp_packet *pac)
{
    if (pac->leader == SRRP_CTRL_LEADER) {
        struct apimsg *msg = malloc(sizeof(*msg));
        memset(msg, 0, sizeof(*msg));
        msg->type = APIMSG_T_CTRL;
        msg->state = APIMSG_ST_NONE;
        msg->fd = sinkfd->fd;
        msg->pac = pac;
        INIT_LIST_HEAD(&msg->ln);
        list_add(&msg->ln, &ctx->msgs);
    } else if (pac->leader == SRRP_REQUEST_LEADER) {
        struct apimsg *msg = malloc(sizeof(*msg));
        memset(msg, 0, sizeof(*msg));
        msg->type = APIMSG_T_REQUEST;
        msg->state = APIMSG_ST_NONE;
        msg->fd = sinkfd->fd;
        msg->pac = pac;
        INIT_LIST_HEAD(&msg->ln);
        list_add(&msg->ln, &ctx->msgs);
    } else if (pac->leader == SRRP_RESPONSE_LEADER) {
        struct apimsg *msg = malloc(sizeof(*msg));
        memset(msg, 0, sizeof(*msg));
        msg->type = APIMSG_T_RESPONSE;
        msg->state = APIMSG_ST_NONE;
        msg->fd = sinkfd->fd;
        msg->pac = pac;
        INIT_LIST_HEAD(&msg->ln);
        list_add(&msg->ln, &ctx->msgs);
    } else if (pac->leader == SRRP_SUBSCRIBE_LEADER ||
                pac->leader == SRRP_UNSUBSCRIBE_LEADER ||
                pac->leader == SRRP_PUBLISH_LEADER) {
        struct apimsg *msg = malloc(sizeof(*msg));
        memset(msg, 0, sizeof(*msg));
        msg->type = APIMSG_T_TOPIC_MSG;
        msg->state = APIMSG_ST_NONE;
        msg->fd = sinkfd->fd;
        msg->pac = pac;
        INIT_LIST_HEAD(&msg->ln);
        list_add(&msg->ln, &ctx->msgs);
    } else {
        free(pac);
    }
}

static void parse_packet(struct apix *ctx, struct sinkfd *sinkfd)
{
    while (vsize(sinkfd->rxbuf)) {
        uint32_t offset = srrp_next_packet_offset(
            vraw(sinkfd->rxbuf), vsize(sinkfd->rxbuf));
        if (offset != 0) {
            LOG_WARN("broken packet:");
            log_hex_string(vraw(sinkfd->rxbuf), offset);
            vdrop(sinkfd->rxbuf, offset);
        }
        if (vsize(sinkfd->rxbuf) == 0)
            break;

        struct srrp_packet *pac = srrp_parse(
            vraw(sinkfd->rxbuf), vsize(sinkfd->rxbuf));
        if (pac == NULL) {
            if (time(0) < sinkfd->ts_poll_recv.tv_sec + PARSE_PACKET_TIMEOUT / 1000)
                break;

            LOG_WARN("parse packet failed: %s", vraw(sinkfd->rxbuf));
            uint32_t offset = srrp_next_packet_offset(
                vraw(sinkfd->rxbuf) + 1,
                vsize(sinkfd->rxbuf) - 1) + 1;
            vdrop(sinkfd->rxbuf, offset);
            break;
        }

        append_srrp_packet(ctx, sinkfd, pac);
        vdrop(sinkfd->rxbuf, pac->packet_len);
    }
}

static struct api_topic *
find_topic(struct list_head *topics, const char *topic)
{
    struct api_topic *pos;
    list_for_each_entry(pos, topics, ln) {
        if (strcmp(pos->topic, topic) == 0) {
            return pos;
        }
    }
    return NULL;
}

static void topic_sub_handler(struct apix *ctx, struct apimsg *tmsg)
{
    struct api_topic *topic = NULL;
    struct api_topic *pos;
    list_for_each_entry(pos, &ctx->topics, ln) {
        if (strcmp(pos->topic, sget(tmsg->pac->anchor)) == 0) {
            topic = pos;
            break;
        }
    }
    if (topic == NULL) {
        topic = malloc(sizeof(*topic));
        memset(topic, 0, sizeof(*topic));
        snprintf(topic->topic, sizeof(topic->topic), "%s", sget(tmsg->pac->anchor));
        INIT_LIST_HEAD(&topic->ln);
        list_add(&topic->ln, &ctx->topics);
    }
    assert(topic);
    topic->fds[topic->nfds] = tmsg->fd;
    topic->nfds++;

    apix_send(ctx, tmsg->fd, (uint8_t *)"Sub OK", 6);
}

static void topic_unsub_handler(struct apix *ctx, struct apimsg *tmsg)
{
    struct api_topic *topic = NULL;
    list_for_each_entry(topic, &ctx->topics, ln) {
        if (strcmp(topic->topic, sget(tmsg->pac->anchor)) == 0) {
            break;
        }
    }
    if (topic) {
        for (int i = 0; i < topic->nfds; i++) {
            if (topic->fds[i] == tmsg->fd) {
                topic->fds[i] = topic->fds[topic->nfds-1];
                topic->nfds--;
            }
        }
    }

    apix_send(ctx, tmsg->fd, (uint8_t *)"Unsub OK", 8);
}

static void topic_pub_handler(struct apix *ctx, struct apimsg *tmsg)
{
    struct api_topic *topic = find_topic(&ctx->topics, sget(tmsg->pac->anchor));
    if (topic) {
        for (int i = 0; i < topic->nfds; i++)
            apix_send(ctx, topic->fds[i], vraw(tmsg->pac->raw), tmsg->pac->packet_len);
    } else {
        // do nothing, just drop this msg
        LOG_DEBUG("drop @: %s%s", sget(tmsg->pac->anchor), tmsg->pac->payload);
    }
}

struct apix *apix_new()
{
    struct apix *ctx = malloc(sizeof(*ctx));
    bzero(ctx, sizeof(*ctx));
    INIT_LIST_HEAD(&ctx->msgs);
    INIT_LIST_HEAD(&ctx->topics);
    INIT_LIST_HEAD(&ctx->sinkfds);
    INIT_LIST_HEAD(&ctx->sinks);
    return ctx;
}

void apix_destroy(struct apix *ctx)
{
    {
        struct apimsg *pos, *n;
        list_for_each_entry_safe(pos, n, &ctx->msgs, ln)
            apimsg_delete(pos);
    }

    {
        struct api_topic *pos, *n;
        list_for_each_entry_safe(pos, n, &ctx->topics, ln) {
            list_del_init(&pos->ln);
            free(pos);
        }
    }

    {
        struct sinkfd *pos, *n;
        list_for_each_entry_safe(pos, n, &ctx->sinkfds, ln_ctx)
            sinkfd_destroy(pos);
    }

    {
        struct apisink *pos, *n;
        list_for_each_entry_safe(pos, n, &ctx->sinks, ln) {
            apix_sink_unregister(pos->ctx, pos);
            apisink_fini(pos);
        }
    }

    free(ctx);
}

int apix_open(struct apix *ctx, const char *sinkid, const char *addr)
{
    struct apisink *pos;
    list_for_each_entry(pos, &ctx->sinks, ln) {
        if (strcmp(pos->id, sinkid) == 0) {
            assert(pos->ops.open);
            return pos->ops.open(pos, addr);
        }
    }
    return -1;
}

int apix_close(struct apix *ctx, int fd)
{
    struct sinkfd *sinkfd = find_sinkfd_in_apix(ctx, fd);
    if (sinkfd == NULL)
        return -1;
    if (sinkfd->sink && sinkfd->sink->ops.close)
        sinkfd->sink->ops.close(sinkfd->sink, fd);
    return 0;
}

int apix_ioctl(struct apix *ctx, int fd, unsigned int cmd, unsigned long arg)
{
    struct sinkfd *sinkfd = find_sinkfd_in_apix(ctx, fd);
    if (sinkfd == NULL)
        return -1;
    if (sinkfd->sink == NULL || sinkfd->sink->ops.ioctl == NULL)
        return -1;
    return sinkfd->sink->ops.ioctl(sinkfd->sink, fd, cmd, arg);
}

int apix_send(struct apix *ctx, int fd, const uint8_t *buf, uint32_t len)
{
    struct sinkfd *sinkfd = find_sinkfd_in_apix(ctx, fd);
    if (sinkfd == NULL)
        return -1;
    if (sinkfd->type == 'l' || sinkfd->sink == NULL ||
        sinkfd->sink->ops.send == NULL)
        return -1;
    return sinkfd->sink->ops.send(sinkfd->sink, fd, buf, len);
}

int apix_recv(struct apix *ctx, int fd, uint8_t *buf, uint32_t len)
{
    struct sinkfd *sinkfd = find_sinkfd_in_apix(ctx, fd);
    if (sinkfd == NULL)
        return -1;
    if (sinkfd->sink == NULL || sinkfd->sink->ops.recv == NULL)
        return -1;
    return sinkfd->sink->ops.recv(sinkfd->sink, fd, buf, len);
}

int apix_read_from_buffer(struct apix *ctx, int fd, uint8_t *buf, uint32_t len)
{
    struct sinkfd *sinkfd = find_sinkfd_in_apix(ctx, fd);
    if (sinkfd == NULL)
        return -1;
    uint32_t less = len < vsize(sinkfd->rxbuf) ? len : vsize(sinkfd->rxbuf);
    if (less) vdump(sinkfd->rxbuf, buf, less);
    return less;
}

static int apix_response(struct apix *ctx, int fd, struct srrp_packet *req, const char *data)
{
    struct srrp_packet *resp = srrp_new_response(
        req->dstid, req->srcid, sget(req->anchor), data, req->crc16);
    int rc = apix_send(ctx, fd, vraw(resp->raw), resp->packet_len);
    srrp_free(resp);
    return rc;
}

static void handle_ctrl(struct apix *ctx)
{
    struct apimsg *pos;
    list_for_each_entry(pos, &ctx->msgs, ln) {
        if (apimsg_is_finished(pos) || !apimsg_is_ctrl(pos))
            continue;

        LOG_DEBUG("(%x) = %d:%s", ctx, pos->pac->srcid, sget(pos->pac->anchor));

        struct sinkfd *src = find_sinkfd_in_apix(ctx, pos->fd);
        if (src == NULL) {
            apimsg_finish(pos);
            continue;
        }

        if (pos->pac->srcid == 0) {
            apix_response(ctx, pos->fd, pos->pac, "t:NODEID SHOULD NOT BE ZERO");
            apimsg_finish(pos);
            continue;
        }

        struct sinkfd *tmp = find_sinkfd_by_nodeid(ctx, pos->pac->srcid);
        if (tmp != NULL && tmp != src) {
            apix_response(ctx, pos->fd, pos->pac, "t:NODEID HAVE BEEN USED");
            apimsg_finish(pos);
            continue;
        }

        if (strcmp(sget(pos->pac->anchor), SRRP_CTRL_ONLINE) == 0) {
            if (src->r_nodeid != 0 && src->r_nodeid != pos->pac->srcid) {
                apix_response(ctx, pos->fd, pos->pac, "t:NODEID SHOULD NOT CHANGE");
                apimsg_finish(pos);
                continue;
            }
            src->r_nodeid = pos->pac->srcid;
            apix_response(ctx, pos->fd, pos->pac, "t:OK");
        } else if (strcmp(sget(pos->pac->anchor), SRRP_CTRL_OFFLINE) == 0) {
            src->r_nodeid = 0;
            apix_response(ctx, pos->fd, pos->pac, "t:OK");
        }

        apimsg_finish(pos);
    }
}

static void handle_request(struct apix *ctx)
{
    struct apimsg *pos;
    list_for_each_entry(pos, &ctx->msgs, ln) {
        if (apimsg_is_finished(pos) || !apimsg_is_request(pos))
            continue;

        LOG_DEBUG("(%x) %s", ctx, vraw(pos->pac->raw));

        struct sinkfd *src = find_sinkfd_in_apix(ctx, pos->fd);
        if (src == NULL) {
            apimsg_finish(pos);
            continue;
        }

        if (pos->pac->srcid == 0) {
            apix_response(ctx, pos->fd, pos->pac, "NODEID SHOULD NOT BE ZERO");
            apimsg_finish(pos);
            continue;
        }

        struct sinkfd *tmp = find_sinkfd_by_nodeid(ctx, pos->pac->srcid);
        if (tmp != NULL && tmp != src) {
            apix_response(ctx, pos->fd, pos->pac, "NODEID HAVE BEEN USED");
            apimsg_finish(pos);
            continue;
        }

        struct sinkfd *dst = find_sinkfd_by_nodeid(ctx, pos->pac->dstid);
        if (dst == NULL) {
            apix_response(ctx, pos->fd, pos->pac, "DESTINATION NOT FOUND");
            apimsg_finish(pos);
            continue;
        }

        if (dst->l_nodeid == pos->pac->dstid && dst->events.on_request) {
            struct srrp_packet *resp = srrp_new_response(0, 0, "", "", 0);
            dst->events.on_request(
                ctx, pos->fd, pos->pac, resp, dst->events_priv.priv_on_request);
            if (resp) {
                append_srrp_packet(ctx, src, resp);
                // should not free resp
            }
        } else if (dst->r_nodeid == pos->pac->dstid) {
            apix_send(ctx, dst->fd, vraw(pos->pac->raw), pos->pac->packet_len);
        }

        pos->state = APIMSG_ST_FINISHED;
    }
}

static void handle_response(struct apix *ctx)
{
    struct apimsg *pos;
    list_for_each_entry(pos, &ctx->msgs, ln) {
        if (apimsg_is_finished(pos) || !apimsg_is_response(pos))
            continue;

        LOG_DEBUG("(%x) %s", ctx, vraw(pos->pac->raw));

        struct sinkfd *dst = find_sinkfd_by_nodeid(ctx, pos->pac->dstid);
        if (dst) {
            if (dst->l_nodeid == pos->pac->dstid && dst->events.on_response) {
                dst->events.on_response(
                    ctx, pos->fd, pos->pac, dst->events_priv.priv_on_response);
            } else if (dst->r_nodeid == pos->pac->dstid) {
                apix_send(ctx, dst->fd, vraw(pos->pac->raw), pos->pac->packet_len);
            } else {
                LOG_WARN("(%x) %s", ctx, vraw(pos->pac->raw));
            }
        } else {
            apix_send(ctx, pos->fd, vraw(pos->pac->raw), pos->pac->packet_len);
        }

        apimsg_finish(pos);
    }
}

static void handle_topic_msg(struct apix *ctx)
{
    struct apimsg *pos;
    list_for_each_entry(pos, &ctx->msgs, ln) {
        if (pos->type != APIMSG_T_TOPIC_MSG)
            continue;

        if (pos->pac->leader == SRRP_SUBSCRIBE_LEADER) {
            topic_sub_handler(ctx, pos);
        } else if (pos->pac->leader == SRRP_UNSUBSCRIBE_LEADER) {
            topic_unsub_handler(ctx, pos);
        } else {
            topic_pub_handler(ctx, pos);
        }
        LOG_DEBUG("(%x) %s", ctx, vraw(pos->pac->raw));
        apimsg_finish(pos);
    }
}

static void clear_finished_msg(struct apix *ctx)
{
    struct apimsg *pos, *n;
    list_for_each_entry_safe(pos, n, &ctx->msgs, ln) {
        if (apimsg_is_finished(pos))
            apimsg_delete(pos);
    }
}

int apix_poll(struct apix *ctx, uint64_t usec)
{
    ctx->poll_cnt = 0;
    gettimeofday(&ctx->poll_ts, NULL);

    // poll each sink
    struct apisink *pos_sink;
    list_for_each_entry(pos_sink, &ctx->sinks, ln) {
        if (pos_sink->ops.poll(pos_sink) != 0) {
            LOG_ERROR("%s", strerror(errno));
        }
    }

    // parse each sinkfds
    struct sinkfd *pos_fd;
    list_for_each_entry(pos_fd, &ctx->sinkfds, ln_ctx) {
        if (timercmp(&ctx->poll_ts, &pos_fd->ts_poll_recv, <)) {
            assert(vsize(pos_fd->rxbuf));
            ctx->poll_cnt++;

            // on_pollin prior to on_srrp_*
            if (pos_fd->events.on_pollin) {
                int nr = pos_fd->events.on_pollin(
                    ctx, pos_fd->fd, vraw(pos_fd->rxbuf),
                    vsize(pos_fd->rxbuf),
                    pos_fd->events_priv.priv_on_pollin);

                /*
                 * nr <= 0: unhandled
                 * nr > 0: handled, skip nr bytes
                 */
                if (nr > 0) {
                    if ((uint32_t)nr > vsize(pos_fd->rxbuf))
                        nr = vsize(pos_fd->rxbuf);
                    vdrop(pos_fd->rxbuf, nr);
                }
            }

            // even on_pollin has been called, check if srrp_mode
            if (pos_fd->srrp_mode == 1) {
                parse_packet(ctx, pos_fd);
            }
        }
    }

    LOG_DEBUG("poll_cnt: %d", ctx->poll_cnt);
    if (ctx->poll_cnt == 0) {
        if (usec != 0) {
            usleep(usec);
        } else {
            if (ctx->idle_usec != APIX_IDLE_MAX) {
                ctx->idle_usec += APIX_IDLE_MAX / 10;
                if (ctx->idle_usec > APIX_IDLE_MAX)
                    ctx->idle_usec = APIX_IDLE_MAX;
            }
            usleep(ctx->idle_usec);
        }
    } else {
        ctx->idle_usec = APIX_IDLE_MAX / 10;
    }

    // hander each msg
    handle_ctrl(ctx);
    handle_request(ctx);
    handle_response(ctx);
    handle_topic_msg(ctx);
    clear_finished_msg(ctx);

    return 0;
}

int apix_on_fd_close(struct apix *ctx, int fd, fd_close_func_t func, void *priv)
{
    struct sinkfd *sinkfd = find_sinkfd_in_apix(ctx, fd);
    if (sinkfd == NULL)
        return -EBADF;
    assert(sinkfd->events.on_close == NULL);
    sinkfd->events.on_close = func;
    sinkfd->events_priv.priv_on_close = priv;
    return 0;
}

int apix_on_fd_accept(struct apix *ctx, int fd, fd_accept_func_t func, void *priv)
{
    struct sinkfd *sinkfd = find_sinkfd_in_apix(ctx, fd);
    if (sinkfd == NULL)
        return -EBADF;
    assert(sinkfd->events.on_accept == NULL);
    sinkfd->events.on_accept = func;
    sinkfd->events_priv.priv_on_accept = priv;
    return 0;
}

int apix_on_fd_pollin(struct apix *ctx, int fd, fd_pollin_func_t func, void *priv)
{
    struct sinkfd *sinkfd = find_sinkfd_in_apix(ctx, fd);
    if (sinkfd == NULL)
        return -EBADF;
    assert(sinkfd->events.on_pollin == NULL);
    sinkfd->events.on_pollin = func;
    sinkfd->events_priv.priv_on_pollin = priv;
    return 0;
}

int apix_on_srrp_request(struct apix *ctx, int fd, srrp_request_func_t func, void *priv)
{
    struct sinkfd *sinkfd = find_sinkfd_in_apix(ctx, fd);
    if (sinkfd == NULL)
        return -EBADF;
    assert(sinkfd->events.on_request == NULL);
    sinkfd->events.on_request = func;
    sinkfd->events_priv.priv_on_request = priv;
    return 0;
}

int apix_on_srrp_response(struct apix *ctx, int fd, srrp_response_func_t func, void *priv)
{
    struct sinkfd *sinkfd = find_sinkfd_in_apix(ctx, fd);
    if (sinkfd == NULL)
        return -EBADF;
    assert(sinkfd->events.on_response == NULL);
    sinkfd->events.on_response = func;
    sinkfd->events_priv.priv_on_response = priv;
    return 0;
}

int apix_enable_srrp_mode(struct apix *ctx, int fd, uint32_t nodeid)
{
    struct sinkfd *sinkfd = find_sinkfd_in_apix(ctx, fd);
    if (sinkfd == NULL)
        return -EBADF;
    sinkfd->srrp_mode = 1;
    sinkfd->l_nodeid = nodeid;
    return 0;
}

int apix_disable_srrp_mode(struct apix *ctx, int fd)
{
    struct sinkfd *sinkfd = find_sinkfd_in_apix(ctx, fd);
    if (sinkfd == NULL)
        return -EBADF;
    sinkfd->srrp_mode = 0;
    sinkfd->l_nodeid = 0;
    return 0;
}

int apix_srrp_online(struct apix *ctx, int fd)
{
    struct sinkfd *sinkfd = find_sinkfd_in_apix(ctx, fd);
    if (sinkfd == NULL)
        return -EBADF;
    assert(sinkfd->srrp_mode == 1);

    struct srrp_packet *pac = srrp_new_ctrl(sinkfd->l_nodeid, SRRP_CTRL_ONLINE, "");
    apix_send(ctx, fd, vraw(pac->raw), pac->packet_len);
    srrp_free(pac);
    return 0;
}

int apix_srrp_offline(struct apix *ctx, int fd)
{
    struct sinkfd *sinkfd = find_sinkfd_in_apix(ctx, fd);
    if (sinkfd == NULL)
        return -EBADF;
    assert(sinkfd->srrp_mode == 1);

    struct srrp_packet *pac = srrp_new_ctrl(sinkfd->l_nodeid, SRRP_CTRL_OFFLINE, "");
    apix_send(ctx, fd, vraw(pac->raw), pac->packet_len);
    srrp_free(pac);
    return 0;
}

/**
 * apisink
 */

void apisink_init(struct apisink *sink, const char *name,
                  const struct apisink_operations *ops)
{
    assert(strlen(name) < APISINK_ID_SIZE);
    INIT_LIST_HEAD(&sink->sinkfds);
    INIT_LIST_HEAD(&sink->ln);
    snprintf(sink->id, sizeof(sink->id), "%s", name);
    sink->ops = *ops;
    sink->ctx = NULL;
}

void apisink_fini(struct apisink *sink)
{
    struct sinkfd *pos, *n;
    list_for_each_entry_safe(pos, n, &sink->sinkfds, ln_sink)
        sinkfd_destroy(pos);

    // delete from apix outside
    assert(sink->ctx == NULL);
    //if (sink->ctx)
    //    apix_sink_unregister(sink->ctx, sink);
}

int apix_sink_register(struct apix *ctx, struct apisink *sink)
{
    struct apisink *pos;
    list_for_each_entry(pos, &ctx->sinks, ln) {
        if (strcmp(sink->id, pos->id) == 0)
            return -1;
    }

    list_add(&sink->ln, &ctx->sinks);
    sink->ctx = ctx;
    return 0;
}

void apix_sink_unregister(struct apix *ctx, struct apisink *sink)
{
    UNUSED(ctx);
    list_del_init(&sink->ln);
    sink->ctx = NULL;
}

struct sinkfd *sinkfd_new()
{
    struct sinkfd *sinkfd = malloc(sizeof(struct sinkfd));
    memset(sinkfd, 0, sizeof(*sinkfd));
    sinkfd->fd = -1;
    sinkfd->type = 0;
    sinkfd->rxbuf = vec_new(1, 1024);
    sinkfd->srrp_mode = 0;
    sinkfd->l_nodeid = 0;
    sinkfd->r_nodeid = 0;
    sinkfd->sink = NULL;
    INIT_LIST_HEAD(&sinkfd->ln_sink);
    INIT_LIST_HEAD(&sinkfd->ln_ctx);
    return sinkfd;
}

void sinkfd_destroy(struct sinkfd *sinkfd)
{
    if (sinkfd->events.on_close)
        sinkfd->events.on_close(
            sinkfd->sink->ctx, sinkfd->fd, sinkfd->events_priv.priv_on_close);
    vec_delete(sinkfd->rxbuf);
    sinkfd->sink = NULL;
    list_del_init(&sinkfd->ln_sink);
    list_del_init(&sinkfd->ln_ctx);
    free(sinkfd);
}

struct sinkfd *find_sinkfd_in_apix(struct apix *ctx, int fd)
{
    struct sinkfd *pos, *n;
    list_for_each_entry_safe(pos, n, &ctx->sinkfds, ln_ctx) {
        if (pos->fd == fd)
            return pos;
    }
    return NULL;
}

struct sinkfd *find_sinkfd_in_apisink(struct apisink *sink, int fd)
{
    struct sinkfd *pos, *n;
    list_for_each_entry_safe(pos, n, &sink->sinkfds, ln_sink) {
        if (pos->fd == fd)
            return pos;
    }
    return NULL;
}

struct sinkfd *find_sinkfd_by_nodeid(struct apix *ctx, uint32_t nodeid)
{
    if (nodeid == 0) return NULL;
    struct sinkfd *pos, *n;
    list_for_each_entry_safe(pos, n, &ctx->sinkfds, ln_ctx) {
        if (pos->l_nodeid == nodeid || pos->r_nodeid == nodeid)
            return pos;
    }
    return NULL;
}
