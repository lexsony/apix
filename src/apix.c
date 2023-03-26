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
#include "srrp.h"
#include "unused.h"
#include "log.h"
#include "str.h"
#include "vec.h"

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

static void parse_packet(struct apix *ctx, struct sinkfd *sinkfd)
{
    while (vsize(sinkfd->rxbuf)) {
        uint32_t offset = srrp_next_packet_offset(
            vraw(sinkfd->rxbuf), vsize(sinkfd->rxbuf));
        if (offset != 0) {
            LOG_WARN("[%x] broken packet:", ctx);
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

            LOG_ERROR("[%x] parse packet failed: %s", ctx, vraw(sinkfd->rxbuf));
            uint32_t offset = srrp_next_packet_offset(
                vraw(sinkfd->rxbuf) + 1,
                vsize(sinkfd->rxbuf) - 1) + 1;
            vdrop(sinkfd->rxbuf, offset);
            break;
        }

        struct apimsg *msg = malloc(sizeof(*msg));
        memset(msg, 0, sizeof(*msg));
        msg->state = APIMSG_ST_NONE;
        msg->fd = sinkfd->fd;
        msg->pac = pac;
        INIT_LIST_HEAD(&msg->ln);
        list_add_tail(&msg->ln, &ctx->msgs);
        //LOG_DEBUG("[%x] parse packet: %s", ctx, srrp_get_raw(pac));

        vdrop(sinkfd->rxbuf, srrp_get_packet_len(pac));
    }
}

static int apix_response(
    struct apix *ctx, int fd, struct srrp_packet *req, const char *data)
{
    struct srrp_packet *resp = srrp_new_response(
        srrp_get_dstid(req),
        srrp_get_srcid(req),
        srrp_get_anchor(req),
        data,
        srrp_get_crc16(req));
    int rc = apix_send(ctx, fd, srrp_get_raw(resp), srrp_get_packet_len(resp));
    srrp_free(resp);
    return rc;
}

static void
handle_ctrl(struct apix *ctx, struct sinkfd *sinkfd, struct apimsg *am)
{
    assert(sinkfd->type != 'l');

    uint32_t nodeid = 0;
    if (sinkfd->type == 'a') {
        assert(sinkfd->father);
        nodeid = sinkfd->father->l_nodeid;
    } else {
        nodeid = sinkfd->l_nodeid;
    }

    if (srrp_get_srcid(am->pac) == 0) {
        struct srrp_packet *pac = srrp_new_ctrl(nodeid, SRRP_CTRL_NODEID_ZERO, "");
        apix_send(ctx, sinkfd->fd, srrp_get_raw(pac), srrp_get_packet_len(pac));
        srrp_free(pac);
        sinkfd->state = SINKFD_ST_NODEID_ZERO;
        goto out;
    }

    struct sinkfd *tmp = find_sinkfd_by_nodeid(ctx, srrp_get_srcid(am->pac));
    if (tmp != NULL && tmp != sinkfd) {
        struct srrp_packet *pac = srrp_new_ctrl(nodeid, SRRP_CTRL_NODEID_DUP, "");
        apix_send(ctx, sinkfd->fd, srrp_get_raw(pac), srrp_get_packet_len(pac));
        srrp_free(pac);
        sinkfd->state = SINKFD_ST_NODEID_DUP;
        goto out;
    }

    if (strcmp(srrp_get_anchor(am->pac), SRRP_CTRL_SYNC) == 0) {
        sinkfd->r_nodeid = srrp_get_srcid(am->pac);
        sinkfd->state = SINKFD_ST_NODEID_NORMAL;
        sinkfd->ts_sync_in = time(0);
        goto out;
    }

out:
    apimsg_finish(am);
}

static void
handle_subscribe(struct apix *ctx, struct sinkfd *sinkfd, struct apimsg *am)
{
    assert(sinkfd->type != 'l');

    for (uint32_t i = 0; i < vsize(sinkfd->sub_topics); i++) {
        if (strcmp(sget(vat(sinkfd->sub_topics, i)), srrp_get_anchor(am->pac)) == 0) {
            apix_response(ctx, am->fd, am->pac, "j:{\"err\":0}");
            apimsg_finish(am);
            return;
        }
    }

    str_t *topic = str_new(srrp_get_anchor(am->pac));
    vpush(sinkfd->sub_topics, &topic);
    apix_response(ctx, am->fd, am->pac, "j:{\"err\":0}");
    apimsg_finish(am);
}

static void
handle_unsubscribe(struct apix *ctx, struct sinkfd *sinkfd, struct apimsg *am)
{
    assert(sinkfd->type != 'l');

    for (uint32_t i = 0; i < vsize(sinkfd->sub_topics); i++) {
        if (strcmp(sget(*(str_t **)vat(sinkfd->sub_topics, i)),
                   srrp_get_anchor(am->pac)) == 0) {
            str_delete(*(str_t **)vat(sinkfd->sub_topics, i));
            vremove(sinkfd->sub_topics, i);
            break;
        }
    }

    apix_response(ctx, am->fd, am->pac, "j:{\"err\":0}");
    apimsg_finish(am);
}

static void forward_request_or_response(struct apix *ctx, struct apimsg *am)
{
    struct sinkfd *dst = NULL;

    dst = find_sinkfd_by_l_nodeid(ctx, srrp_get_dstid(am->pac));
    //LOG_DEBUG("forward_rr: dstid:%x, dst:%p", srrp_get_dstid(am->pac), dst);
    if (dst) {
        if (dst->events.on_srrp_packet) {
            dst->events.on_srrp_packet(
                ctx, am->fd, am->pac, dst->events_priv.priv_on_srrp_packet);
        } else {
            LOG_ERROR("[%x] on_srrp_packet on found: %d", ctx, dst->fd);
            apix_response(ctx, am->fd, am->pac, "j:{\"err\":500,\"Inner error\"}");
        }
        return;
    }

    dst = find_sinkfd_by_r_nodeid(ctx, srrp_get_dstid(am->pac));
    if (dst) {
        apix_send(ctx, dst->fd, srrp_get_raw(am->pac), srrp_get_packet_len(am->pac));
        return;
    }

    apix_response(ctx, am->fd, am->pac,
                  "j:{\"err\":404,\"msg\":\"Destination not found\"}");
    return;
}

static void forward_publish(struct apix *ctx, struct apimsg *am)
{
    struct sinkfd *pos;
    list_for_each_entry(pos, &ctx->sinkfds, ln_ctx) {
        for (uint32_t i = 0; i < vsize(pos->sub_topics); i++) {
            if (strcmp(sget(*(str_t **)vat(pos->sub_topics, i)),
                       srrp_get_anchor(am->pac)) == 0) {
                apix_send(ctx, pos->fd, srrp_get_raw(am->pac),
                      srrp_get_packet_len(am->pac));
            }
        }
    }
}

static void
handle_forward(struct apix *ctx, struct apimsg *am)
{
    if (srrp_get_leader(am->pac) == SRRP_REQUEST_LEADER ||
        srrp_get_leader(am->pac) == SRRP_RESPONSE_LEADER) {
        forward_request_or_response(ctx, am);
    } else if (srrp_get_leader(am->pac) == SRRP_PUBLISH_LEADER) {
        forward_publish(ctx, am);
    } else {
        assert(false);
    }

    // finish it on matter if user code change the state
    apimsg_finish(am);
}

static void
handle_request_or_response(struct apix *ctx, struct sinkfd *sinkfd, struct apimsg *am)
{
    if (!sinkfd->events.on_srrp_packet) {
        LOG_ERROR("[%x] on_srrp_packet on found: %d", ctx, sinkfd->fd);
        apix_response(ctx, am->fd, am->pac, "j:{\"err\":500,\"Inner error\"}");
        apimsg_finish(am);
        return;
    }

    sinkfd->events.on_srrp_packet(
        ctx, am->fd, am->pac, sinkfd->events_priv.priv_on_srrp_packet);
    // user code may change the state of apimsg to APIMSG_ST_FORWARD
    if (am->state == APIMSG_ST_NONE)
        apimsg_finish(am);
}

static void handle_apimsg(struct apix *ctx)
{
    struct apimsg *pos;
    list_for_each_entry(pos, &ctx->msgs, ln) {
        if (apimsg_is_finished(pos))
            continue;

        LOG_DEBUG("[%x] handle_apimsg: fd:%d, state:%d, %s",
                  ctx, pos->fd, pos->state, srrp_get_raw(pos->pac));

        struct sinkfd *src = find_sinkfd_in_apix(ctx, pos->fd);
        if (src == NULL) {
            apimsg_finish(pos);
            LOG_INFO("[%x] handle_apimsg: src fd closed, drop it, %s",
                     ctx, srrp_get_raw(pos->pac));
            continue;
        }

        assert(src->type != 'l');

        if (srrp_get_leader(pos->pac) == SRRP_CTRL_LEADER) {
            handle_ctrl(ctx, src, pos);
            continue;
        }

        if (src->r_nodeid == 0) {
            LOG_DEBUG("[%x] nodeid zero: l_nodeid:%d, r_nodeid:%d, fd:%d, state:%d, %s",
                      ctx, src->l_nodeid, src->r_nodeid,
                      pos->fd, pos->state, srrp_get_raw(pos->pac));
            apix_response(ctx, pos->fd, pos->pac,
                          "j:{\"err\":1, \"msg\":\"nodeid not sync\"}");
            apimsg_finish(pos);
            continue;
        }

        if (srrp_get_leader(pos->pac) == SRRP_SUBSCRIBE_LEADER) {
            handle_subscribe(ctx, src, pos);
            continue;
        }

        if (srrp_get_leader(pos->pac) == SRRP_UNSUBSCRIBE_LEADER) {
            handle_unsubscribe(ctx, src, pos);
            continue;
        }

        if (pos->state == APIMSG_ST_FORWARD) {
            handle_forward(ctx, pos);
            continue;
        }

        handle_request_or_response(ctx, src, pos);
    }
}

static void clear_finished_apimsg(struct apix *ctx)
{
    struct apimsg *pos, *n;
    list_for_each_entry_safe(pos, n, &ctx->msgs, ln) {
        if (apimsg_is_finished(pos))
            apimsg_delete(pos);
    }
}

static void apix_sync_sinkfd(struct apix *ctx, struct sinkfd *sinkfd)
{
    assert(sinkfd->type != 'l');

    uint32_t nodeid = 0;
    if (sinkfd->type == 'a') {
        assert(sinkfd->father);
        nodeid = sinkfd->father->l_nodeid;
    } else {
        nodeid = sinkfd->l_nodeid;
    }
    struct srrp_packet *pac = srrp_new_ctrl(nodeid, SRRP_CTRL_SYNC, "");
    apix_send(ctx, sinkfd->fd, srrp_get_raw(pac), srrp_get_packet_len(pac));
    srrp_free(pac);
    sinkfd->ts_sync_out = time(0);
}

struct apix *apix_new()
{
    struct apix *ctx = malloc(sizeof(*ctx));
    bzero(ctx, sizeof(*ctx));
    INIT_LIST_HEAD(&ctx->msgs);
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

int apix_poll(struct apix *ctx, uint64_t usec)
{
    ctx->poll_cnt = 0;
    gettimeofday(&ctx->poll_ts, NULL);

    // poll each sink
    struct apisink *pos_sink;
    list_for_each_entry(pos_sink, &ctx->sinks, ln) {
        if (pos_sink->ops.poll(pos_sink) != 0) {
            LOG_ERROR("[%x] poll err: %s", ctx, strerror(errno));
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

        // sync
        if (pos_fd->type != 'l' && pos_fd->srrp_mode == 1 &&
            pos_fd->ts_sync_out + (SINKFD_SYNC_TIMEOUT / 1000) < time(0)) {
            apix_sync_sinkfd(ctx, pos_fd);
        }
    }

    //LOG_DEBUG("[%x] poll_cnt: %d", ctx, ctx->poll_cnt);
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
    handle_apimsg(ctx);
    clear_finished_apimsg(ctx);

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

int apix_on_srrp_packet(struct apix *ctx, int fd, srrp_packet_func_t func, void *priv)
{
    struct sinkfd *sinkfd = find_sinkfd_in_apix(ctx, fd);
    if (sinkfd == NULL)
        return -EBADF;
    assert(sinkfd->events.on_srrp_packet == NULL);
    sinkfd->events.on_srrp_packet = func;
    sinkfd->events_priv.priv_on_srrp_packet = priv;
    return 0;
}

int apix_enable_srrp_mode(struct apix *ctx, int fd, uint32_t nodeid)
{
    struct sinkfd *sinkfd = find_sinkfd_in_apix(ctx, fd);
    if (sinkfd == NULL)
        return -EBADF;
    sinkfd->srrp_mode = 1;
    assert(nodeid != 0);
    sinkfd->l_nodeid = nodeid;
    if (sinkfd->type != 'l')
        apix_sync_sinkfd(ctx, sinkfd);
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

void apix_srrp_forward(struct apix *ctx, struct srrp_packet *pac)
{
    struct apimsg *pos;
    list_for_each_entry(pos, &ctx->msgs, ln) {
        if (pos->pac == pac) {
            pos->state = APIMSG_ST_FORWARD;
            return;
        }
    }
    assert(false);
}

int apix_srrp_send(struct apix *ctx, struct srrp_packet *pac)
{
    struct sinkfd *dst = find_sinkfd_by_r_nodeid(ctx, srrp_get_dstid(pac));
    if (dst == NULL) {
        return -EBADF;
    }
    apix_send(ctx, dst->fd, srrp_get_raw(pac), srrp_get_packet_len(pac));
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
    sinkfd->father = NULL;
    sinkfd->type = 0;
    sinkfd->state = SINKFD_ST_NONE;
    sinkfd->ts_sync_in = 0;
    sinkfd->ts_sync_out = 0;
    sinkfd->rxbuf = vec_new(1, 1024);
    sinkfd->srrp_mode = 0;
    sinkfd->l_nodeid = 0;
    sinkfd->r_nodeid = 0;
    sinkfd->sub_topics = vec_new(sizeof(void *), 3);
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

    while (vsize(sinkfd->sub_topics)) {
        str_t *tmp = 0;
        vpop(sinkfd->sub_topics, &tmp);
        str_delete(tmp);
    }
    vec_delete(sinkfd->sub_topics);

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

struct sinkfd *find_sinkfd_by_l_nodeid(struct apix *ctx, uint32_t nodeid)
{
    if (nodeid == 0) return NULL;
    struct sinkfd *pos, *n;
    list_for_each_entry_safe(pos, n, &ctx->sinkfds, ln_ctx) {
        if (pos->l_nodeid == nodeid)
            return pos;
    }
    return NULL;
}

struct sinkfd *find_sinkfd_by_r_nodeid(struct apix *ctx, uint32_t nodeid)
{
    if (nodeid == 0) return NULL;
    struct sinkfd *pos, *n;
    list_for_each_entry_safe(pos, n, &ctx->sinkfds, ln_ctx) {
        if (pos->r_nodeid == nodeid)
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
