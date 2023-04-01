#include <assert.h>
#include <ctype.h>
#include <errno.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <sys/time.h>
#include <sys/select.h>
#include <regex.h>

#include "apix-private.h"
#include "list.h"
#include "srrp.h"
#include "unused.h"
#include "log.h"
#include "str.h"
#include "vec.h"

/**
 * apix
 */

static void log_hex_string(const char *buf, u32 len)
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

static void parse_packet(struct apix *ctx, struct stream *stream)
{
    while (vsize(stream->rxbuf)) {
        u32 offset = srrp_next_packet_offset(
            vraw(stream->rxbuf), vsize(stream->rxbuf));
        if (offset != 0) {
            LOG_WARN("[%p:parse_packet] broken packet:", ctx);
            log_hex_string(vraw(stream->rxbuf), offset);
            vdrop(stream->rxbuf, offset);
        }
        if (vsize(stream->rxbuf) == 0)
            break;

        struct srrp_packet *pac = srrp_parse(
            vraw(stream->rxbuf), vsize(stream->rxbuf));
        if (pac == NULL) {
            if (time(0) < stream->ts_poll_recv.tv_sec + PARSE_PACKET_TIMEOUT / 1000)
                break;

            LOG_ERROR("[%p:parse_packet] wrong packet:%s", ctx, vraw(stream->rxbuf));
            u32 offset = srrp_next_packet_offset(
                vraw(stream->rxbuf) + 1,
                vsize(stream->rxbuf) - 1) + 1;
            vdrop(stream->rxbuf, offset);
            break;
        }
        vdrop(stream->rxbuf, srrp_get_packet_len(pac));
        assert(srrp_get_ver(pac) == SRRP_VERSION);

        // concatenate srrp packet
        if (stream->rxpac_unfin) {
            assert(srrp_get_fin(stream->rxpac_unfin) == SRRP_FIN_0);
            if (srrp_get_leader(pac) != srrp_get_leader(stream->rxpac_unfin) ||
                srrp_get_ver(pac) != srrp_get_ver(stream->rxpac_unfin) ||
                srrp_get_srcid(pac) != srrp_get_srcid(stream->rxpac_unfin) ||
                srrp_get_dstid(pac) != srrp_get_dstid(stream->rxpac_unfin) ||
                strcmp(srrp_get_anchor(pac), srrp_get_anchor(stream->rxpac_unfin)) != 0) {
                // drop pre pac
                srrp_free(stream->rxpac_unfin);
                // set to rxpac_unfin
                stream->rxpac_unfin = pac;
            } else {
                struct srrp_packet *tsp = stream->rxpac_unfin;
                stream->rxpac_unfin = srrp_cat(tsp, pac);
                assert(stream->rxpac_unfin != NULL);
                srrp_free(tsp);
                srrp_free(pac);
                pac = NULL;
            }
        } else {
            stream->rxpac_unfin = pac;
            pac = NULL;
        }

        LOG_TRACE("[%p:parse_packet] right packet:%s", ctx, srrp_get_raw(stream->rxpac_unfin));

        // construct apimsg if receviced fin srrp packet
        if (srrp_get_fin(stream->rxpac_unfin) == SRRP_FIN_1) {
            struct apimsg *msg = malloc(sizeof(*msg));
            memset(msg, 0, sizeof(*msg));
            msg->state = APIMSG_ST_NONE;
            msg->fd = stream->fd;
            msg->pac = stream->rxpac_unfin;
            INIT_LIST_HEAD(&msg->ln);
            list_add_tail(&msg->ln, &stream->msgs);

            stream->rxpac_unfin = NULL;
        }
    }
}

static int apix_response(
    struct apix *ctx, int fd, struct srrp_packet *req, const char *data)
{
    struct srrp_packet *resp = srrp_new_response(
        srrp_get_dstid(req),
        srrp_get_srcid(req),
        srrp_get_anchor(req),
        data);
    int rc = apix_srrp_send(ctx, fd, resp);
    srrp_free(resp);
    return rc;
}

static void
handle_ctrl(struct stream *stream, struct apimsg *am)
{
    assert(stream->type != STREAM_T_LISTEN);

    u32 nodeid = 0;
    if (stream->type == STREAM_T_ACCEPT) {
        assert(stream->father);
        nodeid = stream->father->l_nodeid;
    } else {
        nodeid = stream->l_nodeid;
    }

    if (srrp_get_srcid(am->pac) == 0) {
        struct srrp_packet *pac = srrp_new_ctrl(nodeid, SRRP_CTRL_NODEID_ZERO, "");
        apix_srrp_send(stream->ctx, stream->fd, pac);
        srrp_free(pac);
        stream->state = STREAM_ST_NODEID_ZERO;
        goto out;
    }

    struct stream *tmp = find_stream_by_nodeid(stream->ctx, srrp_get_srcid(am->pac));
    if (tmp != NULL && tmp != stream) {
        struct srrp_packet *pac = srrp_new_ctrl(nodeid, SRRP_CTRL_NODEID_DUP, "");
        apix_srrp_send(stream->ctx, stream->fd, pac);
        srrp_free(pac);
        stream->state = STREAM_ST_NODEID_DUP;
        goto out;
    }

    if (strcmp(srrp_get_anchor(am->pac), SRRP_CTRL_SYNC) == 0) {
        stream->r_nodeid = srrp_get_srcid(am->pac);
        stream->state = STREAM_ST_NODEID_NORMAL;
        stream->ts_sync_in = time(0);
        goto out;
    }

    if (strcmp(srrp_get_anchor(am->pac), SRRP_CTRL_NODEID_DUP) == 0) {
        LOG_WARN("[%p:handle_ctrl] recv nodeid dup:%s", stream->ctx, srrp_get_raw(am->pac));
        goto out;
    }

    if (strcmp(srrp_get_anchor(am->pac), SRRP_CTRL_NODEID_ZERO) == 0) {
        LOG_ERROR("[%p:handle_ctrl] recv nodeid zero:%s", stream->ctx, srrp_get_raw(am->pac));
        goto out;
    }

out:
    apimsg_finish(am);
}

static void
handle_subscribe(struct stream *stream, struct apimsg *am)
{
    assert(stream->type != STREAM_T_LISTEN);

    for (u32 i = 0; i < vsize(stream->sub_topics); i++) {
        if (strcmp(sget(vat(stream->sub_topics, i)), srrp_get_anchor(am->pac)) == 0) {
            apix_response(stream->ctx, am->fd, am->pac, "j:{\"err\":0}");
            apimsg_finish(am);
            return;
        }
    }

    str_t *topic = str_new(srrp_get_anchor(am->pac));
    vpush(stream->sub_topics, &topic);

    struct srrp_packet *pub = srrp_new_publish(
        srrp_get_anchor(am->pac), "j:{\"state\":\"sub\"}");
    apix_srrp_send(stream->ctx, am->fd, pub);
    srrp_free(pub);

    apimsg_finish(am);
}

static void
handle_unsubscribe(struct stream *stream, struct apimsg *am)
{
    assert(stream->type != STREAM_T_LISTEN);

    for (u32 i = 0; i < vsize(stream->sub_topics); i++) {
        if (strcmp(sget(*(str_t **)vat(stream->sub_topics, i)),
                   srrp_get_anchor(am->pac)) == 0) {
            str_free(*(str_t **)vat(stream->sub_topics, i));
            vremove(stream->sub_topics, i, 1);
            break;
        }
    }

    struct srrp_packet *pub = srrp_new_publish(
        srrp_get_anchor(am->pac), "j:{\"state\":\"unsub\"}");
    apix_srrp_send(stream->ctx, am->fd, pub);
    srrp_free(pub);

    apimsg_finish(am);
}

static void forward_request_or_response(struct apix *ctx, struct apimsg *am)
{
    struct stream *dst = NULL;

    dst = find_stream_by_l_nodeid(ctx, srrp_get_dstid(am->pac));
    LOG_TRACE("[%p:forward_rr_l] dstid:%x, dst:%p", ctx, srrp_get_dstid(am->pac), dst);
    if (dst) {
        list_del(&am->ln);
        list_add_tail(&am->ln, &dst->msgs);
        dst->ev.bits.srrp_packet_in = 1;
        return;
    }

    dst = find_stream_by_r_nodeid(ctx, srrp_get_dstid(am->pac));
    LOG_TRACE("[%p:forward_rr_r] dstid:%x, dst:%p", ctx, srrp_get_dstid(am->pac), dst);
    if (dst) {
        apix_srrp_send(ctx, dst->fd, am->pac);
        apimsg_finish(am);
        return;
    }

    apix_response(ctx, am->fd, am->pac,
                  "j:{\"err\":404,\"msg\":\"Destination not found\"}");
    apimsg_finish(am);
    return;
}

static void forward_publish(struct apix *ctx, struct apimsg *am)
{
    regex_t regex;
    int rc;

    struct stream *pos;
    list_for_each_entry(pos, &ctx->streams, ln_ctx) {
        for (u32 i = 0; i < vsize(pos->sub_topics); i++) {
            //LOG_TRACE("[%p:forward_publish] topic:%s, sub:%s",
            //          ctx, srrp_get_anchor(am->pac), sget(*(str_t **)vat(pos->sub_topics, i)));
            rc = regcomp(&regex, sget(*(str_t **)vat(pos->sub_topics, i)), 0);
            if (rc != 0) continue;
            rc = regexec(&regex, srrp_get_anchor(am->pac), 0, NULL, 0);
            if (rc == 0) {
                apix_srrp_send(ctx, pos->fd, am->pac);
            }
            regfree(&regex);
        }
    }

    apimsg_finish(am);
}

static void
handle_forward(struct apix *ctx, struct apimsg *am)
{
    LOG_TRACE("[%p:handle_forward] state:%d, raw:%s",
              ctx, am->state, srrp_get_raw(am->pac));

    if (srrp_get_leader(am->pac) == SRRP_REQUEST_LEADER ||
        srrp_get_leader(am->pac) == SRRP_RESPONSE_LEADER) {
        forward_request_or_response(ctx, am);
    } else if (srrp_get_leader(am->pac) == SRRP_PUBLISH_LEADER) {
        forward_publish(ctx, am);
    } else {
        assert(false);
    }
}

static void handle_apimsg(struct stream *stream)
{
    struct apimsg *pos;
    list_for_each_entry(pos, &stream->msgs, ln) {
        if (apimsg_is_finished(pos) || pos->state == APIMSG_ST_WAITING)
            continue;

        assert(srrp_get_ver(pos->pac) == SRRP_VERSION);
        LOG_TRACE("[%p:handle_apimsg] #%d msg:%p, state:%d, raw:%s",
                  stream->ctx, stream->fd, pos, pos->state, srrp_get_raw(pos->pac));

        assert(stream->type != STREAM_T_LISTEN);

        if (srrp_get_leader(pos->pac) == SRRP_CTRL_LEADER) {
            handle_ctrl(stream, pos);
            continue;
        }

        if (stream->r_nodeid == 0) {
            LOG_DEBUG("[%p:handle_apimsg] #%d nodeid zero: "
                      "l_nodeid:%d, r_nodeid:%d, state:%d, raw:%s",
                      stream->ctx, pos->fd, stream->l_nodeid, stream->r_nodeid,
                      pos->state, srrp_get_raw(pos->pac));
            if (srrp_get_leader(pos->pac) == SRRP_REQUEST_LEADER)
                apix_response(stream->ctx, pos->fd, pos->pac,
                              "j:{\"err\":1, \"msg\":\"nodeid not sync\"}");
            apimsg_finish(pos);
            continue;
        }

        if (srrp_get_leader(pos->pac) == SRRP_SUBSCRIBE_LEADER) {
            handle_subscribe(stream, pos);
            continue;
        }

        if (srrp_get_leader(pos->pac) == SRRP_UNSUBSCRIBE_LEADER) {
            handle_unsubscribe(stream, pos);
            continue;
        }

        if (pos->state == APIMSG_ST_FORWARD) {
            handle_forward(stream->ctx, pos);
            continue;
        }

        stream->ev.bits.srrp_packet_in = 1;
        pos->state = APIMSG_ST_WAITING;
        //LOG_TRACE("[%p:handle_apimsg] set srrp_packet_in", stream->ctx);
    }
}

static void clear_finished_apimsg(struct stream *stream)
{
    struct apimsg *pos, *n;
    list_for_each_entry_safe(pos, n, &stream->msgs, ln) {
        if (apimsg_is_finished(pos))
            apimsg_free(pos);
    }
}

static void sync_stream(struct stream *stream)
{
    assert(stream->type != STREAM_T_LISTEN);

    LOG_TRACE("[%p:sync_stream] #%d sync", stream->ctx, stream->fd);

    u32 nodeid = 0;
    if (stream->type == STREAM_T_ACCEPT) {
        assert(stream->father);
        nodeid = stream->father->l_nodeid;
    } else {
        nodeid = stream->l_nodeid;
    }
    struct srrp_packet *pac = srrp_new_ctrl(nodeid, SRRP_CTRL_SYNC, "");
    apix_send(stream->ctx, stream->fd, srrp_get_raw(pac), srrp_get_packet_len(pac));
    srrp_free(pac);
    stream->ts_sync_out = time(0);
}

struct apix *apix_new()
{
    struct apix *ctx = malloc(sizeof(*ctx));
    bzero(ctx, sizeof(*ctx));
    INIT_LIST_HEAD(&ctx->streams);
    INIT_LIST_HEAD(&ctx->sinks);
    return ctx;
}

void apix_drop(struct apix *ctx)
{
    struct stream *stream_pos, *stream_n;
    list_for_each_entry_safe(stream_pos, stream_n, &ctx->streams, ln_ctx) {
        stream_pos->state = STREAM_ST_FINISHED;
        stream_free(stream_pos);
    }

    struct apisink *apisink_pos, *apisink_n;
    list_for_each_entry_safe(apisink_pos, apisink_n, &ctx->sinks, ln) {
        apix_sink_unregister(apisink_pos->ctx, apisink_pos);
        apisink_fini(apisink_pos);
        free(apisink_pos);
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
    struct stream *stream = find_stream_in_apix(ctx, fd);
    if (stream == NULL)
        return -1;
    if (stream->sink && stream->sink->ops.close)
        stream->sink->ops.close(stream->sink, fd);
    return 0;
}

int apix_accept(struct apix *ctx, int fd)
{
    struct stream *stream = find_stream_in_apix(ctx, fd);
    if (stream == NULL)
        return -1;
    if (stream->sink && stream->sink->ops.accept)
        stream->sink->ops.accept(stream->sink, fd);
    return 0;
}

int apix_ioctl(struct apix *ctx, int fd, unsigned int cmd, unsigned long arg)
{
    struct stream *stream = find_stream_in_apix(ctx, fd);
    if (stream == NULL)
        return -1;
    if (stream->sink == NULL || stream->sink->ops.ioctl == NULL)
        return -1;
    return stream->sink->ops.ioctl(stream->sink, fd, cmd, arg);
}

int apix_send(struct apix *ctx, int fd, const u8 *buf, u32 len)
{
    struct stream *stream = find_stream_in_apix(ctx, fd);
    if (stream == NULL)
        return -1;
    if (stream->type == STREAM_T_LISTEN || stream->sink == NULL ||
        stream->sink->ops.send == NULL)
        return -1;

    return stream->sink->ops.send(stream->sink, fd, buf, len);
}

int apix_recv(struct apix *ctx, int fd, u8 *buf, u32 len)
{
    struct stream *stream = find_stream_in_apix(ctx, fd);
    if (stream == NULL)
        return -1;
    if (stream->sink == NULL || stream->sink->ops.recv == NULL)
        return -1;
    return stream->sink->ops.recv(stream->sink, fd, buf, len);
}

int apix_send_to_buffer(struct apix *ctx, int fd, const u8 *buf, u32 len)
{
    struct stream *stream = find_stream_in_apix(ctx, fd);
    if (stream == NULL)
        return -1;
    if (stream->type == STREAM_T_LISTEN || stream->sink == NULL ||
        stream->sink->ops.send == NULL)
        return -1;

    vpack(stream->txbuf, buf, len);
    return 0;
}

int apix_read_from_buffer(struct apix *ctx, int fd, u8 *buf, u32 len)
{
    struct stream *stream = find_stream_in_apix(ctx, fd);
    if (stream == NULL)
        return -1;
    u32 less = len < vsize(stream->rxbuf) ? len : vsize(stream->rxbuf);
    if (less) vdump(stream->rxbuf, buf, less);
    return less;
}

static int apix_poll(struct apix *ctx)
{
    ctx->poll_cnt = 0;
    gettimeofday(&ctx->poll_ts, NULL);

    // poll each sink
    struct apisink *pos_sink;
    list_for_each_entry(pos_sink, &ctx->sinks, ln) {
        if (pos_sink->ops.poll(pos_sink) != 0) {
            LOG_ERROR("[%p:apix_poll] %s(%d)", ctx, strerror(errno));
        }
    }

    // clean & sync & send & parse each streams
    struct stream *pos_fd, *n;
    list_for_each_entry_safe(pos_fd, n, &ctx->streams, ln_ctx) {
        // clean
        if (pos_fd->state == STREAM_ST_FINISHED) {
            stream_free(pos_fd);
            continue;
        }

        // sync
        if (pos_fd->type != STREAM_T_LISTEN && pos_fd->srrp_mode == 1 &&
            pos_fd->ts_sync_out + (STREAM_SYNC_TIMEOUT / 1000) < time(0)) {
            sync_stream(pos_fd);
        }

        // send txbuf to system buffer
        struct timeval tv = { 0, 0 };
        fd_set sendfds;
        FD_ZERO(&sendfds);
        FD_SET(pos_fd->fd, &sendfds);
        int rc = select(pos_fd->fd + 1, NULL, &sendfds, NULL, &tv);
        FD_CLR(pos_fd->fd, &sendfds);
        if (rc == 1) {
            if (vsize(pos_fd->txbuf)) {
                int nr = apix_send(
                    ctx, pos_fd->fd, vraw(pos_fd->txbuf), vsize(pos_fd->txbuf));
                if (nr > 0) assert((u32)nr <= vsize(pos_fd->txbuf));
                vdrop(pos_fd->txbuf, nr);
            }
        }

        // parse rxbuf to srrp_packet
        if (timercmp(&ctx->poll_ts, &pos_fd->ts_poll_recv, <)) {
            assert(vsize(pos_fd->rxbuf));
            assert(pos_fd->ev.bits.pollin);
            ctx->poll_cnt++;

            if (pos_fd->srrp_mode == 1) {
                parse_packet(ctx, pos_fd);
            }
        }

        handle_apimsg(pos_fd);
        clear_finished_apimsg(pos_fd);
    }

    return 0;
}

int apix_waiting(struct apix *ctx, u64 usec)
{
    apix_poll(ctx);

    struct stream *pos;
    list_for_each_entry(pos, &ctx->streams, ln_ctx) {
        if (pos->ev.byte != 0) {
            if (pos->ev.bits.close) {
                pos->state = STREAM_ST_FINISHED;
            }
            return pos->fd;
        }
    }

    //LOG_TRACE("[%p:apix_waiting] poll_cnt:%d", ctx, ctx->poll_cnt);
    if (usec == 0)
        usec = APIX_IDLE_MAX;
    if (ctx->poll_cnt == 0) {
        usleep(ctx->idle_usec);
        if (ctx->idle_usec != usec) {
            ctx->idle_usec += usec / 10;
            if (ctx->idle_usec > usec)
                ctx->idle_usec = usec;
        }
    } else {
        ctx->idle_usec = usec / 10;
    }

    return 0;
}

u8 apix_next_event(struct apix *ctx, int fd)
{
    struct stream *stream = find_stream_in_apix(ctx, fd);
    assert(stream);

    //LOG_TRACE("[%p:apix_next_event] #%d event %d", ctx, stream->fd, stream->ev.byte);

    if (stream->ev.bits.open) {
        stream->ev.bits.open = 0;
        return AEC_OPEN;
    }

    if (stream->ev.bits.close) {
        stream->ev.bits.close = 0;
        return AEC_CLOSE;
    }

    if (stream->ev.bits.accept) {
        stream->ev.bits.accept = 0;
        return AEC_ACCEPT;
    }

    if (stream->ev.bits.pollin) {
        stream->ev.bits.pollin = 0;
        return AEC_POLLIN;
    }

    if (stream->ev.bits.srrp_packet_in) {
        stream->ev.bits.srrp_packet_in = 0;
        struct apimsg *pos;
        list_for_each_entry(pos,&stream->msgs, ln) {
            if (pos->state == APIMSG_ST_WAITING)
                stream->ev.bits.srrp_packet_in = 1;
        }
        // check again
        if (stream->ev.bits.srrp_packet_in) {
            return AEC_SRRP_PACKET;
        }
    }

    return AEC_NONE;
}

struct srrp_packet *apix_next_srrp_packet(struct apix *ctx, int fd)
{
    struct stream *stream = find_stream_in_apix(ctx, fd);
    assert(stream);

    struct apimsg *pos;
    list_for_each_entry(pos,&stream->msgs, ln) {
        //LOG_TRACE("[%p:apix_next_srrp_packet] #%d msg:%p, state:%d, raw:%s",
        //          ctx, fd, pos, pos->state, srrp_get_raw(pos->pac));
        if (pos->state == APIMSG_ST_WAITING) {
            apimsg_finish(pos);
            return pos->pac;
        }
    }

    return NULL;
}

int apix_upgrade_to_srrp(struct apix *ctx, int fd, u32 nodeid)
{
    struct stream *stream = find_stream_in_apix(ctx, fd);
    if (stream == NULL)
        return -EBADF;
    stream->srrp_mode = 1;
    assert(nodeid != 0);
    stream->l_nodeid = nodeid;
    return 0;
}

void apix_srrp_forward(struct apix *ctx, int fd, struct srrp_packet *pac)
{
    struct stream *stream = find_stream_in_apix(ctx, fd);
    assert(stream);

    struct apimsg *pos;
    list_for_each_entry(pos, &stream->msgs, ln) {
        if (pos->pac == pac) {
            pos->state = APIMSG_ST_FORWARD;
            return;
        }
    }
    assert(false);
}

static void __apix_srrp_send(
    struct apix *ctx, int fd, const struct srrp_packet *pac)
{
    u32 idx = 0;
    struct srrp_packet *tmp_pac = NULL;

    LOG_TRACE("[%p:__apix_srrp_send] send:%s", ctx, srrp_get_raw(pac));

    // payload_len < cnt, maybe zero, should not remove this code
    if (srrp_get_payload_len(pac) < PAYLOAD_LIMIT) {
        apix_send_to_buffer(ctx, fd, srrp_get_raw(pac), srrp_get_packet_len(pac));
        return;
    }

    // payload_len > cnt, can't be zero
    while (idx != srrp_get_payload_len(pac)) {
        u32 tmp_cnt = srrp_get_payload_len(pac) - idx;
        u8 fin = 0;
        if (tmp_cnt > PAYLOAD_LIMIT) {
            tmp_cnt = PAYLOAD_LIMIT;
            fin = SRRP_FIN_0;
        } else {
            fin = SRRP_FIN_1;
        };
        tmp_pac = srrp_new(srrp_get_leader(pac),
                       fin,
                       srrp_get_srcid(pac),
                       srrp_get_dstid(pac),
                       srrp_get_anchor(pac),
                       srrp_get_payload(pac) + idx,
                       tmp_cnt);
        LOG_TRACE("[%p:__apix_srrp_send] split:%s", ctx, srrp_get_raw(tmp_pac));
        apix_send_to_buffer(ctx, fd, srrp_get_raw(tmp_pac),
                            srrp_get_packet_len(tmp_pac));
        idx += tmp_cnt;
        srrp_free(tmp_pac);
    }
}

int apix_srrp_send(struct apix *ctx, int fd, struct srrp_packet *pac)
{
    int retval = -1;

    assert(fd > 0);

    // send to src fd
    struct stream *dst_fd = find_stream_in_apix(ctx, fd);
    if (dst_fd && dst_fd->type != STREAM_T_LISTEN) {
        __apix_srrp_send(ctx, dst_fd->fd, pac);
        retval = 0;
    }

    // send to nodeid
    if (srrp_get_dstid(pac) != 0) {
        struct stream *dst_nd = find_stream_by_r_nodeid(ctx, srrp_get_dstid(pac));
        if (dst_nd && dst_nd != dst_fd) {
            __apix_srrp_send(ctx, dst_nd->fd, pac);
            retval = 0;
        }
    }

    return retval;
}

/**
 * apisink
 */

void apisink_init(struct apisink *sink, const char *name,
                  const struct apisink_operations *ops)
{
    assert(strlen(name) < APISINK_ID_SIZE);
    INIT_LIST_HEAD(&sink->streams);
    INIT_LIST_HEAD(&sink->ln);
    snprintf(sink->id, sizeof(sink->id), "%s", name);
    sink->ops = *ops;
    sink->ctx = NULL;
}

void apisink_fini(struct apisink *sink)
{
    struct stream *pos, *n;
    list_for_each_entry_safe(pos, n, &sink->streams, ln_sink)
        stream_free(pos);

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

struct stream *stream_new(struct apisink *sink)
{
    struct stream *stream = malloc(sizeof(struct stream));
    memset(stream, 0, sizeof(*stream));

    stream->fd = -1;
    stream->father = NULL;
    stream->type = 0;
    stream->state = STREAM_ST_NONE;
    stream->ts_sync_in = 0;
    stream->ts_sync_out = 0;

    stream->txbuf = vec_new(1, 2048);
    stream->rxbuf = vec_new(1, 2048);

    stream->ev.byte = 0;
    stream->ev.bits.open = 1;

    stream->srrp_mode = 0;
    stream->l_nodeid = 0;
    stream->r_nodeid = 0;
    stream->sub_topics = vec_new(sizeof(void *), 3);
    stream->rxpac_unfin = NULL;
    INIT_LIST_HEAD(&stream->msgs);

    stream->ctx = sink->ctx;
    stream->sink = sink;
    INIT_LIST_HEAD(&stream->ln_ctx);
    INIT_LIST_HEAD(&stream->ln_sink);
    list_add(&stream->ln_ctx, &sink->ctx->streams);
    list_add(&stream->ln_sink, &sink->streams);

    return stream;
}

void stream_free(struct stream *stream)
{
    if (stream->state != STREAM_ST_FINISHED) {
        stream->ev.bits.close = 1;
        return;
    }

    assert(stream->state == STREAM_ST_FINISHED);

    vec_free(stream->txbuf);
    vec_free(stream->rxbuf);

    while (vsize(stream->sub_topics)) {
        str_t *tmp = 0;
        vpop(stream->sub_topics, &tmp);
        str_free(tmp);
    }
    vec_free(stream->sub_topics);

    struct apimsg *pos, *n;
    list_for_each_entry_safe(pos, n, &stream->msgs, ln)
        apimsg_free(pos);

    stream->ctx = NULL;
    stream->sink = NULL;
    list_del_init(&stream->ln_sink);
    list_del_init(&stream->ln_ctx);
    free(stream);
}

struct stream *find_stream_in_apix(struct apix *ctx, int fd)
{
    struct stream *pos, *n;
    list_for_each_entry_safe(pos, n, &ctx->streams, ln_ctx) {
        if (pos->fd == fd)
            return pos;
    }
    return NULL;
}

struct stream *find_stream_in_apisink(struct apisink *sink, int fd)
{
    struct stream *pos, *n;
    list_for_each_entry_safe(pos, n, &sink->streams, ln_sink) {
        if (pos->fd == fd)
            return pos;
    }
    return NULL;
}

struct stream *find_stream_by_l_nodeid(struct apix *ctx, u32 nodeid)
{
    if (nodeid == 0) return NULL;
    struct stream *pos, *n;
    list_for_each_entry_safe(pos, n, &ctx->streams, ln_ctx) {
        if (pos->l_nodeid == nodeid)
            return pos;
    }
    return NULL;
}

struct stream *find_stream_by_r_nodeid(struct apix *ctx, u32 nodeid)
{
    if (nodeid == 0) return NULL;
    struct stream *pos, *n;
    list_for_each_entry_safe(pos, n, &ctx->streams, ln_ctx) {
        if (pos->r_nodeid == nodeid)
            return pos;
    }
    return NULL;
}

struct stream *find_stream_by_nodeid(struct apix *ctx, u32 nodeid)
{
    if (nodeid == 0) return NULL;
    struct stream *pos, *n;
    list_for_each_entry_safe(pos, n, &ctx->streams, ln_ctx) {
        if (pos->l_nodeid == nodeid || pos->r_nodeid == nodeid)
            return pos;
    }
    return NULL;
}
