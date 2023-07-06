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

static void parse_packet(struct stream *stream)
{
    while (vsize(stream->rxbuf)) {
        u32 offset = srrp_next_packet_offset(
            vraw(stream->rxbuf), vsize(stream->rxbuf));
        if (offset != 0) {
            LOG_WARN("[%p:parse_packet] broken packet:", stream->ctx);
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

            LOG_ERROR("[%p:parse_packet] wrong packet:%s",
                      stream->ctx, vraw(stream->rxbuf));
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
                strcmp(srrp_get_srcid(pac), srrp_get_srcid(stream->rxpac_unfin)) != 0 ||
                strcmp(srrp_get_dstid(pac), srrp_get_dstid(stream->rxpac_unfin)) != 0 ||
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

        LOG_TRACE("[%p:parse_packet] right packet:%s",
                  stream->ctx, srrp_get_raw(stream->rxpac_unfin));

        // construct message if receviced fin srrp packet
        if (srrp_get_fin(stream->rxpac_unfin) == SRRP_FIN_1) {
            struct message *msg = malloc(sizeof(*msg));
            memset(msg, 0, sizeof(*msg));
            msg->state = MESSAGE_ST_NONE;
            msg->stream = stream;
            msg->pac = stream->rxpac_unfin;
            INIT_LIST_HEAD(&msg->ln);
            list_add_tail(&msg->ln, &stream->msgs);

            stream->rxpac_unfin = NULL;
        }
    }
}

static int apix_response(
    struct stream *stream, struct srrp_packet *req, const char *data)
{
    struct srrp_packet *resp = srrp_new_response(
        srrp_get_dstid(req),
        srrp_get_srcid(req),
        srrp_get_anchor(req),
        data);
    int rc = apix_srrp_send(stream, resp);
    srrp_free(resp);
    return rc;
}

static void handle_ctrl(struct message *am)
{
    assert(am->stream->type != STREAM_T_LISTEN);

    str_t *nodeid = NULL;
    if (am->stream->type == STREAM_T_ACCEPT) {
        assert(am->stream->father);
        nodeid = am->stream->father->l_nodeid;
    } else {
        nodeid = am->stream->l_nodeid;
    }

    struct stream *tmp = find_stream_by_nodeid(
        am->stream->ctx, srrp_get_srcid(am->pac));
    if (tmp != NULL && tmp != am->stream) {
        struct srrp_packet *pac = srrp_new_ctrl(sget(nodeid), SRRP_CTRL_NODEID_DUP, "");
        apix_srrp_send(am->stream, pac);
        srrp_free(pac);
        am->stream->state = STREAM_ST_NODEID_DUP;
        goto out;
    }

    if (strcmp(srrp_get_anchor(am->pac), SRRP_CTRL_SYNC) == 0) {
        str_free(am->stream->r_nodeid);
        am->stream->r_nodeid = str_new(srrp_get_srcid(am->pac));
        am->stream->state = STREAM_ST_NODEID_NORMAL;
        am->stream->ts_sync_in = time(0);
        goto out;
    }

    if (strcmp(srrp_get_anchor(am->pac), SRRP_CTRL_NODEID_DUP) == 0) {
        LOG_WARN("[%p:handle_ctrl] recv nodeid dup:%s",
                 am->stream->ctx, srrp_get_raw(am->pac));
        goto out;
    }

out:
    message_finish(am);
}

static void handle_subscribe(struct message *am)
{
    assert(am->stream->type != STREAM_T_LISTEN);

    for (u32 i = 0; i < vsize(am->stream->sub_topics); i++) {
        if (strcmp(sget(vat(am->stream->sub_topics, i)), srrp_get_anchor(am->pac)) == 0) {
            apix_response(am->stream, am->pac, "j:{\"err\":0}");
            message_finish(am);
            return;
        }
    }

    str_t *topic = str_new(srrp_get_anchor(am->pac));
    vpush(am->stream->sub_topics, &topic);

    struct srrp_packet *pub = srrp_new_publish(
        srrp_get_anchor(am->pac), "j:{\"state\":\"sub\"}");
    apix_srrp_send(am->stream, pub);
    srrp_free(pub);

    message_finish(am);
}

static void handle_unsubscribe(struct message *am)
{
    assert(am->stream->type != STREAM_T_LISTEN);

    for (u32 i = 0; i < vsize(am->stream->sub_topics); i++) {
        if (strcmp(sget(*(str_t **)vat(am->stream->sub_topics, i)),
                   srrp_get_anchor(am->pac)) == 0) {
            str_free(*(str_t **)vat(am->stream->sub_topics, i));
            vremove(am->stream->sub_topics, i, 1);
            break;
        }
    }

    struct srrp_packet *pub = srrp_new_publish(
        srrp_get_anchor(am->pac), "j:{\"state\":\"unsub\"}");
    apix_srrp_send(am->stream, pub);
    srrp_free(pub);

    message_finish(am);
}

static void forward_request_or_response(struct message *am)
{
    struct stream *dst = NULL;

    dst = find_stream_by_l_nodeid(am->stream->ctx, srrp_get_dstid(am->pac));
    LOG_TRACE("[%p:forward_rr_l] dstid:%x, dst:%p",
              am->stream->ctx, srrp_get_dstid(am->pac), dst);
    if (dst) {
        list_del(&am->ln);
        list_add_tail(&am->ln, &dst->msgs);
        dst->ev.bits.srrp_packet_in = 1;
        return;
    }

    dst = find_stream_by_r_nodeid(am->stream->ctx, srrp_get_dstid(am->pac));
    LOG_TRACE("[%p:forward_rr_r] dstid:%x, dst:%p",
              am->stream->ctx, srrp_get_dstid(am->pac), dst);
    if (dst) {
        apix_srrp_send(dst, am->pac);
        message_finish(am);
        return;
    }

    apix_response(am->stream, am->pac,
                  "j:{\"err\":404,\"msg\":\"Destination not found\"}");
    message_finish(am);
    return;
}

static void forward_publish(struct message *am)
{
    regex_t regex;
    int rc;

    struct stream *pos;
    list_for_each_entry(pos, &am->stream->ctx->streams, ln_ctx) {
        for (u32 i = 0; i < vsize(pos->sub_topics); i++) {
            //LOG_TRACE("[%p:forward_publish] topic:%s, sub:%s",
            //          ctx, srrp_get_anchor(am->pac), sget(*(str_t **)vat(pos->sub_topics, i)));
            rc = regcomp(&regex, sget(*(str_t **)vat(pos->sub_topics, i)), 0);
            if (rc != 0) continue;
            rc = regexec(&regex, srrp_get_anchor(am->pac), 0, NULL, 0);
            if (rc == 0) {
                apix_srrp_send(pos, am->pac);
            }
            regfree(&regex);
        }
    }

    message_finish(am);
}

static void handle_forward(struct message *am)
{
    LOG_TRACE("[%p:handle_forward] state:%d, raw:%s",
              am->stream->ctx, am->state, srrp_get_raw(am->pac));

    if (srrp_get_leader(am->pac) == SRRP_REQUEST_LEADER ||
        srrp_get_leader(am->pac) == SRRP_RESPONSE_LEADER) {
        forward_request_or_response(am);
    } else if (srrp_get_leader(am->pac) == SRRP_PUBLISH_LEADER) {
        forward_publish(am);
    } else {
        assert(false);
    }
}

static void handle_message(struct stream *stream)
{
    struct message *pos;
    list_for_each_entry(pos, &stream->msgs, ln) {
        if (message_is_finished(pos) || pos->state == MESSAGE_ST_WAITING)
            continue;

        assert(srrp_get_ver(pos->pac) == SRRP_VERSION);
        LOG_TRACE("[%p:handle_message] #%d msg:%p, state:%d, raw:%s",
                  stream->ctx, stream->fd, pos, pos->state, srrp_get_raw(pos->pac));

        assert(stream->type != STREAM_T_LISTEN);

        if (srrp_get_leader(pos->pac) == SRRP_CTRL_LEADER) {
            handle_ctrl(pos);
            continue;
        }

        if (stream->r_nodeid == 0) {
            LOG_DEBUG("[%p:handle_message] #%d nodeid zero: "
                      "l_nodeid:%d, r_nodeid:%d, state:%d, raw:%s",
                      stream->ctx, pos->stream->fd, stream->l_nodeid, stream->r_nodeid,
                      pos->state, srrp_get_raw(pos->pac));
            if (srrp_get_leader(pos->pac) == SRRP_REQUEST_LEADER)
                apix_response(stream, pos->pac,
                              "j:{\"err\":1, \"msg\":\"nodeid not sync\"}");
            message_finish(pos);
            continue;
        }

        if (srrp_get_leader(pos->pac) == SRRP_SUBSCRIBE_LEADER) {
            handle_subscribe(pos);
            continue;
        }

        if (srrp_get_leader(pos->pac) == SRRP_UNSUBSCRIBE_LEADER) {
            handle_unsubscribe(pos);
            continue;
        }

        if (pos->state == MESSAGE_ST_FORWARD) {
            handle_forward(pos);
            continue;
        }

        stream->ev.bits.srrp_packet_in = 1;
        pos->state = MESSAGE_ST_WAITING;
        //LOG_TRACE("[%p:handle_message] set srrp_packet_in", stream->ctx);
    }
}

static void clear_finished_message(struct stream *stream)
{
    struct message *pos, *n;
    list_for_each_entry_safe(pos, n, &stream->msgs, ln) {
        if (message_is_finished(pos))
            message_free(pos);
    }
}

static void sync_nodeid(struct stream *stream)
{
    assert(stream->type != STREAM_T_LISTEN);

    LOG_TRACE("[%p:sync_nodeid] #%d sync", stream->ctx, stream->fd);

    str_t *nodeid = NULL;
    if (stream->type == STREAM_T_ACCEPT) {
        assert(stream->father);
        nodeid = stream->father->l_nodeid;
    } else {
        nodeid = stream->l_nodeid;
    }
    struct srrp_packet *pac = srrp_new_ctrl(sget(nodeid), SRRP_CTRL_SYNC, "");
    apix_send(stream, srrp_get_raw(pac), srrp_get_packet_len(pac));
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

    struct sink *sink_pos, *sink_n;
    list_for_each_entry_safe(sink_pos, sink_n, &ctx->sinks, ln) {
        apix_sink_unregister(sink_pos->ctx, sink_pos);
        sink_fini(sink_pos);
        free(sink_pos);
    }

    free(ctx);
}

struct stream *apix_open(struct apix *ctx, const char *sinkid, const char *addr)
{
    struct sink *pos;
    list_for_each_entry(pos, &ctx->sinks, ln) {
        if (strcmp(pos->id, sinkid) == 0) {
            assert(pos->ops.open);
            return pos->ops.open(pos, addr);
        }
    }
    return NULL;
}

struct stream *apix_accept(struct stream *stream)
{
    if (stream->sink->ops.accept == NULL)
        return NULL;
    return stream->sink->ops.accept(stream);
}

int apix_close(struct stream *stream)
{
    assert(stream->sink->ops.close);
    stream->sink->ops.close(stream);
    return 0;
}

int apix_ioctl(struct stream *stream, unsigned int cmd, unsigned long arg)
{
    if (stream->sink->ops.ioctl == NULL)
        return -1;
    return stream->sink->ops.ioctl(stream, cmd, arg);
}

int apix_send(struct stream *stream, const u8 *buf, u32 len)
{
    if (stream->type == STREAM_T_LISTEN || stream->sink->ops.send == NULL)
        return -1;
    return stream->sink->ops.send(stream, buf, len);
}

int apix_recv(struct stream *stream, u8 *buf, u32 len)
{
    if (stream->sink->ops.recv == NULL)
        return -1;
    return stream->sink->ops.recv(stream, buf, len);
}

int apix_send_to_buffer(struct stream *stream, const u8 *buf, u32 len)
{
    if (stream->type == STREAM_T_LISTEN || stream->sink->ops.send == NULL)
        return -1;
    vpack(stream->txbuf, buf, len);
    return 0;
}

int apix_read_from_buffer(struct stream *stream, u8 *buf, u32 len)
{
    u32 less = len < vsize(stream->rxbuf) ? len : vsize(stream->rxbuf);
    if (less) vdump(stream->rxbuf, buf, less);
    return less;
}

int apix_get_raw_fd(struct stream *stream)
{
    return stream->fd;
}

void apix_set_wait_timeout(struct apix *ctx, u64 usec)
{
    ctx->idle_usec = usec;
    ctx->idle_usec_max = usec;
}

static int apix_poll(struct apix *ctx)
{
    ctx->poll_cnt = 0;
    gettimeofday(&ctx->poll_ts, NULL);

    // poll each sink
    struct sink *pos_sink;
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
            sync_nodeid(pos_fd);
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
                    pos_fd, vraw(pos_fd->txbuf), vsize(pos_fd->txbuf));
                if (nr > 0) assert((u32)nr <= vsize(pos_fd->txbuf));
                vdrop(pos_fd->txbuf, nr);
            }
        }

        // parse rxbuf to srrp_packet
        // FIXME: timercmp will fail when ntpdate just time in large diff sec
        //if (timercmp(&ctx->poll_ts, &pos_fd->ts_poll_recv, <) &&
        //    vsize(pos_fd->rxbuf) && pos_fd->ev.bits.pollin) {
        if (timercmp(&ctx->poll_ts, &pos_fd->ts_poll_recv, <)) {
            assert(vsize(pos_fd->rxbuf));
            assert(pos_fd->ev.bits.pollin);
            ctx->poll_cnt++;

            if (pos_fd->srrp_mode == 1) {
                parse_packet(pos_fd);
            }
        }

        handle_message(pos_fd);
        clear_finished_message(pos_fd);
    }

    //LOG_TRACE("[%p:apix_poll] poll_cnt:%d", ctx, ctx->poll_cnt);
    return 0;
}

static void apix_idle(struct apix *ctx)
{
    if (ctx->idle_usec_max == 0)
        return;

    if (ctx->poll_cnt == 0) {
        usleep(ctx->idle_usec);
        if (ctx->idle_usec != ctx->idle_usec_max) {
            ctx->idle_usec += ctx->idle_usec_max / 10;
            if (ctx->idle_usec > ctx->idle_usec_max)
                ctx->idle_usec = ctx->idle_usec_max;
        }
    } else {
        ctx->idle_usec = ctx->idle_usec_max / 10;
    }
}

struct stream *apix_wait_stream(struct apix *ctx)
{
    apix_poll(ctx);

    struct stream *pos;
    list_for_each_entry(pos, &ctx->streams, ln_ctx) {
        if (pos->ev.byte != 0) {
            return pos;
        }
    }

    apix_idle(ctx);
    return NULL;
}

u8 apix_wait_event(struct stream *stream)
{
    apix_poll(stream->ctx);

    //LOG_TRACE("[%p:apix_wait_event] #%d event %d", ctx, stream->fd, stream->ev.byte);

    if (stream->ev.bits.open) {
        stream->ev.bits.open = 0;
        return AEC_OPEN;
    }

    if (stream->ev.bits.close) {
        stream->ev.bits.close = 0;
        stream->state = STREAM_ST_FINISHED;
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
        struct message *pos;
        list_for_each_entry(pos,&stream->msgs, ln) {
            if (pos->state == MESSAGE_ST_WAITING)
                stream->ev.bits.srrp_packet_in = 1;
        }
        // check again
        if (stream->ev.bits.srrp_packet_in) {
            return AEC_SRRP_PACKET;
        }
    }

    apix_idle(stream->ctx);
    return AEC_NONE;
}

struct srrp_packet *apix_wait_srrp_packet(struct stream *stream)
{
    apix_poll(stream->ctx);

    struct message *pos;
    list_for_each_entry(pos,&stream->msgs, ln) {
        if (pos->state == MESSAGE_ST_WAITING) {
            message_finish(pos);
            return pos->pac;
        }
    }

    apix_idle(stream->ctx);
    return NULL;
}

int apix_upgrade_to_srrp(struct stream *stream, const char *nodeid)
{
    stream->srrp_mode = 1;
    assert(nodeid != NULL);
    stream->l_nodeid = str_new(nodeid);
    return 0;
}

void apix_srrp_forward(struct stream *stream, struct srrp_packet *pac)
{
    struct message *pos;
    list_for_each_entry(pos, &stream->msgs, ln) {
        if (pos->pac == pac) {
            pos->state = MESSAGE_ST_FORWARD;
            return;
        }
    }
    assert(false);
}

static void __apix_srrp_send(
    struct stream *stream, const struct srrp_packet *pac)
{
    u32 idx = 0;
    struct srrp_packet *tmp_pac = NULL;

    LOG_TRACE("[%p:__apix_srrp_send] send:%s", stream->ctx, srrp_get_raw(pac));

    // payload_len < cnt, maybe zero, should not remove this code
    if (srrp_get_payload_len(pac) < PAYLOAD_LIMIT) {
        apix_send_to_buffer(stream, srrp_get_raw(pac), srrp_get_packet_len(pac));
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
        LOG_TRACE("[%p:__apix_srrp_send] split:%s", stream->ctx, srrp_get_raw(tmp_pac));
        apix_send_to_buffer(stream, srrp_get_raw(tmp_pac),
                            srrp_get_packet_len(tmp_pac));
        idx += tmp_cnt;
        srrp_free(tmp_pac);
    }
}

int apix_srrp_send(struct stream *stream, struct srrp_packet *pac)
{
    int retval = -1;

    // send to src stream
    if (stream->type != STREAM_T_LISTEN) {
        __apix_srrp_send(stream, pac);
        retval = 0;
    }

    // send to nodeid
    if (srrp_get_dstid(pac) != 0) {
        struct stream *nd_stream =
            find_stream_by_r_nodeid(stream->ctx, srrp_get_dstid(pac));
        if (nd_stream && nd_stream != stream) {
            __apix_srrp_send(nd_stream, pac);
            retval = 0;
        }
    }

    return retval;
}

/**
 * sink
 */

void sink_init(struct sink *sink, const char *name, const struct sink_operations *ops)
{
    assert(strlen(name) < SINK_ID_SIZE);
    INIT_LIST_HEAD(&sink->streams);
    INIT_LIST_HEAD(&sink->ln);
    snprintf(sink->id, sizeof(sink->id), "%s", name);
    sink->ops = *ops;
    sink->ctx = NULL;
}

void sink_fini(struct sink *sink)
{
    struct stream *pos, *n;
    list_for_each_entry_safe(pos, n, &sink->streams, ln_sink)
        stream_free(pos);

    // delete from apix outside
    assert(sink->ctx == NULL);
    //if (sink->ctx)
    //    apix_sink_unregister(sink->ctx, sink);
}

int apix_sink_register(struct apix *ctx, struct sink *sink)
{
    struct sink *pos;
    list_for_each_entry(pos, &ctx->sinks, ln) {
        if (strcmp(sink->id, pos->id) == 0)
            return -1;
    }

    list_add(&sink->ln, &ctx->sinks);
    sink->ctx = ctx;
    return 0;
}

void apix_sink_unregister(struct apix *ctx, struct sink *sink)
{
    UNUSED(ctx);
    list_del_init(&sink->ln);
    sink->ctx = NULL;
}

struct stream *stream_new(struct sink *sink)
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
    stream->l_nodeid = str_new("");
    stream->r_nodeid = str_new("");
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

    str_free(stream->l_nodeid);
    str_free(stream->r_nodeid);

    while (vsize(stream->sub_topics)) {
        str_t *tmp = 0;
        vpop(stream->sub_topics, &tmp);
        str_free(tmp);
    }
    vec_free(stream->sub_topics);

    struct message *pos, *n;
    list_for_each_entry_safe(pos, n, &stream->msgs, ln)
        message_free(pos);

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

struct stream *find_stream_in_sink(struct sink *sink, int fd)
{
    struct stream *pos, *n;
    list_for_each_entry_safe(pos, n, &sink->streams, ln_sink) {
        if (pos->fd == fd)
            return pos;
    }
    return NULL;
}

struct stream *find_stream_by_l_nodeid(struct apix *ctx, const char *nodeid)
{
    if (nodeid == NULL) return NULL;
    struct stream *pos, *n;
    list_for_each_entry_safe(pos, n, &ctx->streams, ln_ctx) {
        if (strcmp(sget(pos->l_nodeid), nodeid) == 0)
            return pos;
    }
    return NULL;
}

struct stream *find_stream_by_r_nodeid(struct apix *ctx, const char *nodeid)
{
    if (nodeid == 0) return NULL;
    struct stream *pos, *n;
    list_for_each_entry_safe(pos, n, &ctx->streams, ln_ctx) {
        if (strcmp(sget(pos->r_nodeid), nodeid) == 0)
            return pos;
    }
    return NULL;
}

struct stream *find_stream_by_nodeid(struct apix *ctx, const char *nodeid)
{
    if (nodeid == 0) return NULL;
    struct stream *pos, *n;
    list_for_each_entry_safe(pos, n, &ctx->streams, ln_ctx) {
        if (strcmp(sget(pos->l_nodeid), nodeid) == 0 ||
            strcmp(sget(pos->r_nodeid), nodeid) == 0)
            return pos;
    }
    return NULL;
}
