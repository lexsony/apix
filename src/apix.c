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

static void parse_packet(struct apix *ctx, struct sinkfd *sinkfd)
{
    while (vsize(sinkfd->rxbuf)) {
        u32 offset = srrp_next_packet_offset(
            vraw(sinkfd->rxbuf), vsize(sinkfd->rxbuf));
        if (offset != 0) {
            LOG_WARN("[%p:parse_packet] broken packet:", ctx);
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

            LOG_ERROR("[%p:parse_packet] wrong packet:%s", ctx, vraw(sinkfd->rxbuf));
            u32 offset = srrp_next_packet_offset(
                vraw(sinkfd->rxbuf) + 1,
                vsize(sinkfd->rxbuf) - 1) + 1;
            vdrop(sinkfd->rxbuf, offset);
            break;
        }
        vdrop(sinkfd->rxbuf, srrp_get_packet_len(pac));
        assert(srrp_get_ver(pac) == SRRP_VERSION);

        // concatenate srrp packet
        if (sinkfd->rxpac_unfin) {
            assert(srrp_get_fin(sinkfd->rxpac_unfin) == SRRP_FIN_0);
            if (srrp_get_leader(pac) != srrp_get_leader(sinkfd->rxpac_unfin) ||
                srrp_get_ver(pac) != srrp_get_ver(sinkfd->rxpac_unfin) ||
                srrp_get_srcid(pac) != srrp_get_srcid(sinkfd->rxpac_unfin) ||
                srrp_get_dstid(pac) != srrp_get_dstid(sinkfd->rxpac_unfin) ||
                strcmp(srrp_get_anchor(pac), srrp_get_anchor(sinkfd->rxpac_unfin)) != 0) {
                // drop pre pac
                srrp_free(sinkfd->rxpac_unfin);
                // set to rxpac_unfin
                sinkfd->rxpac_unfin = pac;
            } else {
                struct srrp_packet *tsp = sinkfd->rxpac_unfin;
                sinkfd->rxpac_unfin = srrp_cat(tsp, pac);
                assert(sinkfd->rxpac_unfin != NULL);
                srrp_free(tsp);
                srrp_free(pac);
                pac = NULL;
            }
        } else {
            sinkfd->rxpac_unfin = pac;
            pac = NULL;
        }

        LOG_TRACE("[%p:parse_packet] right packet:%s", ctx, srrp_get_raw(sinkfd->rxpac_unfin));

        // construct apimsg if receviced fin srrp packet
        if (srrp_get_fin(sinkfd->rxpac_unfin) == SRRP_FIN_1) {
            struct apimsg *msg = malloc(sizeof(*msg));
            memset(msg, 0, sizeof(*msg));
            msg->state = APIMSG_ST_NONE;
            msg->fd = sinkfd->fd;
            msg->pac = sinkfd->rxpac_unfin;
            INIT_LIST_HEAD(&msg->ln);
            list_add_tail(&msg->ln, &sinkfd->msgs);

            sinkfd->rxpac_unfin = NULL;
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
handle_ctrl(struct sinkfd *sinkfd, struct apimsg *am)
{
    assert(sinkfd->type != SINKFD_T_LISTEN);

    u32 nodeid = 0;
    if (sinkfd->type == SINKFD_T_ACCEPT) {
        assert(sinkfd->father);
        nodeid = sinkfd->father->l_nodeid;
    } else {
        nodeid = sinkfd->l_nodeid;
    }

    if (srrp_get_srcid(am->pac) == 0) {
        struct srrp_packet *pac = srrp_new_ctrl(nodeid, SRRP_CTRL_NODEID_ZERO, "");
        apix_srrp_send(sinkfd->ctx, sinkfd->fd, pac);
        srrp_free(pac);
        sinkfd->state = SINKFD_ST_NODEID_ZERO;
        goto out;
    }

    struct sinkfd *tmp = find_sinkfd_by_nodeid(sinkfd->ctx, srrp_get_srcid(am->pac));
    if (tmp != NULL && tmp != sinkfd) {
        struct srrp_packet *pac = srrp_new_ctrl(nodeid, SRRP_CTRL_NODEID_DUP, "");
        apix_srrp_send(sinkfd->ctx, sinkfd->fd, pac);
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

    if (strcmp(srrp_get_anchor(am->pac), SRRP_CTRL_NODEID_DUP) == 0) {
        LOG_WARN("[%p:handle_ctrl] recv nodeid dup:%s", sinkfd->ctx, srrp_get_raw(am->pac));
        goto out;
    }

    if (strcmp(srrp_get_anchor(am->pac), SRRP_CTRL_NODEID_ZERO) == 0) {
        LOG_ERROR("[%p:handle_ctrl] recv nodeid zero:%s", sinkfd->ctx, srrp_get_raw(am->pac));
        goto out;
    }

out:
    apimsg_finish(am);
}

static void
handle_subscribe(struct sinkfd *sinkfd, struct apimsg *am)
{
    assert(sinkfd->type != SINKFD_T_LISTEN);

    for (u32 i = 0; i < vsize(sinkfd->sub_topics); i++) {
        if (strcmp(sget(vat(sinkfd->sub_topics, i)), srrp_get_anchor(am->pac)) == 0) {
            apix_response(sinkfd->ctx, am->fd, am->pac, "j:{\"err\":0}");
            apimsg_finish(am);
            return;
        }
    }

    str_t *topic = str_new(srrp_get_anchor(am->pac));
    vpush(sinkfd->sub_topics, &topic);

    struct srrp_packet *pub = srrp_new_publish(
        srrp_get_anchor(am->pac), "j:{\"state\":\"sub\"}");
    apix_srrp_send(sinkfd->ctx, am->fd, pub);
    srrp_free(pub);

    apimsg_finish(am);
}

static void
handle_unsubscribe(struct sinkfd *sinkfd, struct apimsg *am)
{
    assert(sinkfd->type != SINKFD_T_LISTEN);

    for (u32 i = 0; i < vsize(sinkfd->sub_topics); i++) {
        if (strcmp(sget(*(str_t **)vat(sinkfd->sub_topics, i)),
                   srrp_get_anchor(am->pac)) == 0) {
            str_free(*(str_t **)vat(sinkfd->sub_topics, i));
            vremove(sinkfd->sub_topics, i, 1);
            break;
        }
    }

    struct srrp_packet *pub = srrp_new_publish(
        srrp_get_anchor(am->pac), "j:{\"state\":\"unsub\"}");
    apix_srrp_send(sinkfd->ctx, am->fd, pub);
    srrp_free(pub);

    apimsg_finish(am);
}

static void forward_request_or_response(struct apix *ctx, struct apimsg *am)
{
    struct sinkfd *dst = NULL;

    dst = find_sinkfd_by_l_nodeid(ctx, srrp_get_dstid(am->pac));
    LOG_TRACE("[%p:forward_rr_l] dstid:%x, dst:%p", ctx, srrp_get_dstid(am->pac), dst);
    if (dst) {
        list_del(&am->ln);
        list_add_tail(&am->ln, &dst->msgs);
        dst->ev.bits.srrp_packet_in = 1;
        return;
    }

    dst = find_sinkfd_by_r_nodeid(ctx, srrp_get_dstid(am->pac));
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

    struct sinkfd *pos;
    list_for_each_entry(pos, &ctx->sinkfds, ln_ctx) {
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

static void handle_apimsg(struct sinkfd *sinkfd)
{
    struct apimsg *pos;
    list_for_each_entry(pos, &sinkfd->msgs, ln) {
        if (apimsg_is_finished(pos) || pos->state == APIMSG_ST_WAITING)
            continue;

        assert(srrp_get_ver(pos->pac) == SRRP_VERSION);
        LOG_TRACE("[%p:handle_apimsg] #%d msg:%p, state:%d, raw:%s",
                  sinkfd->ctx, sinkfd->fd, pos, pos->state, srrp_get_raw(pos->pac));

        assert(sinkfd->type != SINKFD_T_LISTEN);

        if (srrp_get_leader(pos->pac) == SRRP_CTRL_LEADER) {
            handle_ctrl(sinkfd, pos);
            continue;
        }

        if (sinkfd->r_nodeid == 0) {
            LOG_DEBUG("[%p:handle_apimsg] #%d nodeid zero: "
                      "l_nodeid:%d, r_nodeid:%d, state:%d, raw:%s",
                      sinkfd->ctx, pos->fd, sinkfd->l_nodeid, sinkfd->r_nodeid,
                      pos->state, srrp_get_raw(pos->pac));
            if (srrp_get_leader(pos->pac) == SRRP_REQUEST_LEADER)
                apix_response(sinkfd->ctx, pos->fd, pos->pac,
                              "j:{\"err\":1, \"msg\":\"nodeid not sync\"}");
            apimsg_finish(pos);
            continue;
        }

        if (srrp_get_leader(pos->pac) == SRRP_SUBSCRIBE_LEADER) {
            handle_subscribe(sinkfd, pos);
            continue;
        }

        if (srrp_get_leader(pos->pac) == SRRP_UNSUBSCRIBE_LEADER) {
            handle_unsubscribe(sinkfd, pos);
            continue;
        }

        if (pos->state == APIMSG_ST_FORWARD) {
            handle_forward(sinkfd->ctx, pos);
            continue;
        }

        sinkfd->ev.bits.srrp_packet_in = 1;
        pos->state = APIMSG_ST_WAITING;
        //LOG_TRACE("[%p:handle_apimsg] set srrp_packet_in", sinkfd->ctx);
    }
}

static void clear_finished_apimsg(struct sinkfd *sinkfd)
{
    struct apimsg *pos, *n;
    list_for_each_entry_safe(pos, n, &sinkfd->msgs, ln) {
        if (apimsg_is_finished(pos))
            apimsg_free(pos);
    }
}

static void sync_sinkfd(struct sinkfd *sinkfd)
{
    assert(sinkfd->type != SINKFD_T_LISTEN);

    LOG_TRACE("[%p:sync_sinkfd] #%d sync", sinkfd->ctx, sinkfd->fd);

    u32 nodeid = 0;
    if (sinkfd->type == SINKFD_T_ACCEPT) {
        assert(sinkfd->father);
        nodeid = sinkfd->father->l_nodeid;
    } else {
        nodeid = sinkfd->l_nodeid;
    }
    struct srrp_packet *pac = srrp_new_ctrl(nodeid, SRRP_CTRL_SYNC, "");
    apix_send(sinkfd->ctx, sinkfd->fd, srrp_get_raw(pac), srrp_get_packet_len(pac));
    srrp_free(pac);
    sinkfd->ts_sync_out = time(0);
}

struct apix *apix_new()
{
    struct apix *ctx = malloc(sizeof(*ctx));
    bzero(ctx, sizeof(*ctx));
    INIT_LIST_HEAD(&ctx->sinkfds);
    INIT_LIST_HEAD(&ctx->sinks);
    return ctx;
}

void apix_drop(struct apix *ctx)
{
    struct sinkfd *sinkfd_pos, *sinkfd_n;
    list_for_each_entry_safe(sinkfd_pos, sinkfd_n, &ctx->sinkfds, ln_ctx) {
        sinkfd_pos->state = SINKFD_ST_FINISHED;
        sinkfd_free(sinkfd_pos);
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
    struct sinkfd *sinkfd = find_sinkfd_in_apix(ctx, fd);
    if (sinkfd == NULL)
        return -1;
    if (sinkfd->sink && sinkfd->sink->ops.close)
        sinkfd->sink->ops.close(sinkfd->sink, fd);
    return 0;
}

int apix_accept(struct apix *ctx, int fd)
{
    struct sinkfd *sinkfd = find_sinkfd_in_apix(ctx, fd);
    if (sinkfd == NULL)
        return -1;
    if (sinkfd->sink && sinkfd->sink->ops.accept)
        sinkfd->sink->ops.accept(sinkfd->sink, fd);
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

int apix_send(struct apix *ctx, int fd, const u8 *buf, u32 len)
{
    struct sinkfd *sinkfd = find_sinkfd_in_apix(ctx, fd);
    if (sinkfd == NULL)
        return -1;
    if (sinkfd->type == SINKFD_T_LISTEN || sinkfd->sink == NULL ||
        sinkfd->sink->ops.send == NULL)
        return -1;

    return sinkfd->sink->ops.send(sinkfd->sink, fd, buf, len);
}

int apix_recv(struct apix *ctx, int fd, u8 *buf, u32 len)
{
    struct sinkfd *sinkfd = find_sinkfd_in_apix(ctx, fd);
    if (sinkfd == NULL)
        return -1;
    if (sinkfd->sink == NULL || sinkfd->sink->ops.recv == NULL)
        return -1;
    return sinkfd->sink->ops.recv(sinkfd->sink, fd, buf, len);
}

int apix_send_to_buffer(struct apix *ctx, int fd, const u8 *buf, u32 len)
{
    struct sinkfd *sinkfd = find_sinkfd_in_apix(ctx, fd);
    if (sinkfd == NULL)
        return -1;
    if (sinkfd->type == SINKFD_T_LISTEN || sinkfd->sink == NULL ||
        sinkfd->sink->ops.send == NULL)
        return -1;

    vpack(sinkfd->txbuf, buf, len);
    return 0;
}

int apix_read_from_buffer(struct apix *ctx, int fd, u8 *buf, u32 len)
{
    struct sinkfd *sinkfd = find_sinkfd_in_apix(ctx, fd);
    if (sinkfd == NULL)
        return -1;
    u32 less = len < vsize(sinkfd->rxbuf) ? len : vsize(sinkfd->rxbuf);
    if (less) vdump(sinkfd->rxbuf, buf, less);
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

    // clean & sync & send & parse each sinkfds
    struct sinkfd *pos_fd, *n;
    list_for_each_entry_safe(pos_fd, n, &ctx->sinkfds, ln_ctx) {
        // clean
        if (pos_fd->state == SINKFD_ST_FINISHED) {
            sinkfd_free(pos_fd);
            continue;
        }

        // sync
        if (pos_fd->type != SINKFD_T_LISTEN && pos_fd->srrp_mode == 1 &&
            pos_fd->ts_sync_out + (SINKFD_SYNC_TIMEOUT / 1000) < time(0)) {
            sync_sinkfd(pos_fd);
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

    struct sinkfd *pos;
    list_for_each_entry(pos, &ctx->sinkfds, ln_ctx) {
        if (pos->ev.byte != 0) {
            if (pos->ev.bits.close) {
                pos->state = SINKFD_ST_FINISHED;
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
    struct sinkfd *sinkfd = find_sinkfd_in_apix(ctx, fd);
    assert(sinkfd);

    //LOG_TRACE("[%p:apix_next_event] #%d event %d", ctx, sinkfd->fd, sinkfd->ev.byte);

    if (sinkfd->ev.bits.open) {
        sinkfd->ev.bits.open = 0;
        return AEC_OPEN;
    }

    if (sinkfd->ev.bits.close) {
        sinkfd->ev.bits.close = 0;
        return AEC_CLOSE;
    }

    if (sinkfd->ev.bits.accept) {
        sinkfd->ev.bits.accept = 0;
        return AEC_ACCEPT;
    }

    if (sinkfd->ev.bits.pollin) {
        sinkfd->ev.bits.pollin = 0;
        return AEC_POLLIN;
    }

    if (sinkfd->ev.bits.srrp_packet_in) {
        sinkfd->ev.bits.srrp_packet_in = 0;
        struct apimsg *pos;
        list_for_each_entry(pos,&sinkfd->msgs, ln) {
            if (pos->state == APIMSG_ST_WAITING)
                sinkfd->ev.bits.srrp_packet_in = 1;
        }
        // check again
        if (sinkfd->ev.bits.srrp_packet_in) {
            return AEC_SRRP_PACKET;
        }
    }

    return AEC_NONE;
}

struct srrp_packet *apix_next_srrp_packet(struct apix *ctx, int fd)
{
    struct sinkfd *sinkfd = find_sinkfd_in_apix(ctx, fd);
    assert(sinkfd);

    struct apimsg *pos;
    list_for_each_entry(pos,&sinkfd->msgs, ln) {
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
    struct sinkfd *sinkfd = find_sinkfd_in_apix(ctx, fd);
    if (sinkfd == NULL)
        return -EBADF;
    sinkfd->srrp_mode = 1;
    assert(nodeid != 0);
    sinkfd->l_nodeid = nodeid;
    return 0;
}

void apix_srrp_forward(struct apix *ctx, int fd, struct srrp_packet *pac)
{
    struct sinkfd *sinkfd = find_sinkfd_in_apix(ctx, fd);
    assert(sinkfd);

    struct apimsg *pos;
    list_for_each_entry(pos, &sinkfd->msgs, ln) {
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
    struct sinkfd *dst_fd = find_sinkfd_in_apix(ctx, fd);
    if (dst_fd && dst_fd->type != SINKFD_T_LISTEN) {
        __apix_srrp_send(ctx, dst_fd->fd, pac);
        retval = 0;
    }

    // send to nodeid
    if (srrp_get_dstid(pac) != 0) {
        struct sinkfd *dst_nd = find_sinkfd_by_r_nodeid(ctx, srrp_get_dstid(pac));
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
        sinkfd_free(pos);

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

struct sinkfd *sinkfd_new(struct apisink *sink)
{
    struct sinkfd *sinkfd = malloc(sizeof(struct sinkfd));
    memset(sinkfd, 0, sizeof(*sinkfd));

    sinkfd->fd = -1;
    sinkfd->father = NULL;
    sinkfd->type = 0;
    sinkfd->state = SINKFD_ST_NONE;
    sinkfd->ts_sync_in = 0;
    sinkfd->ts_sync_out = 0;

    sinkfd->txbuf = vec_new(1, 2048);
    sinkfd->rxbuf = vec_new(1, 2048);

    sinkfd->ev.byte = 0;
    sinkfd->ev.bits.open = 1;

    sinkfd->srrp_mode = 0;
    sinkfd->l_nodeid = 0;
    sinkfd->r_nodeid = 0;
    sinkfd->sub_topics = vec_new(sizeof(void *), 3);
    sinkfd->rxpac_unfin = NULL;
    INIT_LIST_HEAD(&sinkfd->msgs);

    sinkfd->ctx = sink->ctx;
    sinkfd->sink = sink;
    INIT_LIST_HEAD(&sinkfd->ln_ctx);
    INIT_LIST_HEAD(&sinkfd->ln_sink);
    list_add(&sinkfd->ln_ctx, &sink->ctx->sinkfds);
    list_add(&sinkfd->ln_sink, &sink->sinkfds);

    return sinkfd;
}

void sinkfd_free(struct sinkfd *sinkfd)
{
    if (sinkfd->state != SINKFD_ST_FINISHED) {
        sinkfd->ev.bits.close = 1;
        return;
    }

    assert(sinkfd->state == SINKFD_ST_FINISHED);

    vec_free(sinkfd->txbuf);
    vec_free(sinkfd->rxbuf);

    while (vsize(sinkfd->sub_topics)) {
        str_t *tmp = 0;
        vpop(sinkfd->sub_topics, &tmp);
        str_free(tmp);
    }
    vec_free(sinkfd->sub_topics);

    struct apimsg *pos, *n;
    list_for_each_entry_safe(pos, n, &sinkfd->msgs, ln)
        apimsg_free(pos);

    sinkfd->ctx = NULL;
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

struct sinkfd *find_sinkfd_by_l_nodeid(struct apix *ctx, u32 nodeid)
{
    if (nodeid == 0) return NULL;
    struct sinkfd *pos, *n;
    list_for_each_entry_safe(pos, n, &ctx->sinkfds, ln_ctx) {
        if (pos->l_nodeid == nodeid)
            return pos;
    }
    return NULL;
}

struct sinkfd *find_sinkfd_by_r_nodeid(struct apix *ctx, u32 nodeid)
{
    if (nodeid == 0) return NULL;
    struct sinkfd *pos, *n;
    list_for_each_entry_safe(pos, n, &ctx->sinkfds, ln_ctx) {
        if (pos->r_nodeid == nodeid)
            return pos;
    }
    return NULL;
}

struct sinkfd *find_sinkfd_by_nodeid(struct apix *ctx, u32 nodeid)
{
    if (nodeid == 0) return NULL;
    struct sinkfd *pos, *n;
    list_for_each_entry_safe(pos, n, &ctx->sinkfds, ln_ctx) {
        if (pos->l_nodeid == nodeid || pos->r_nodeid == nodeid)
            return pos;
    }
    return NULL;
}
