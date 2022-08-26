#include <assert.h>
#include <errno.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <sys/time.h>

#include "apix-private.h"
#include "unused.h"
#include "crc16.h"
#include "list.h"
#include "atbuf.h"
#include "log.h"
#include "srrp.h"
#include "json.h"

static void parse_packet(struct apix *ctx, struct sinkfd *sinkfd)
{
    while (atbuf_used(sinkfd->rxbuf)) {
        uint32_t offset = srrp_next_packet_offset(
            atbuf_read_pos(sinkfd->rxbuf), atbuf_used(sinkfd->rxbuf));
        if (offset != 0) {
            LOG_WARN("broken packet: %s", atbuf_read_pos(sinkfd->rxbuf));
            atbuf_read_advance(sinkfd->rxbuf, offset);
        }
        if (atbuf_used(sinkfd->rxbuf) == 0)
            break;

        struct srrp_packet *pac = srrp_read_one_packet(atbuf_read_pos(sinkfd->rxbuf));
        if (pac == NULL) {
            if (time(0) < sinkfd->ts_poll_recv.tv_sec + PARSE_PACKET_TIMEOUT / 1000)
                break;

            LOG_WARN("parse packet failed: %s", atbuf_read_pos(sinkfd->rxbuf));
            uint32_t offset = srrp_next_packet_offset(
                atbuf_read_pos(sinkfd->rxbuf) + 1,
                atbuf_used(sinkfd->rxbuf) - 1) + 1;
            atbuf_read_advance(sinkfd->rxbuf, offset);
            break;
        }

        if (pac->leader == SRRP_REQUEST_LEADER) {
            struct api_request *req = malloc(sizeof(*req));
            memset(req, 0, sizeof(*req));
            req->pac = pac;
            req->state = API_REQUEST_ST_NONE;
            req->ts_create = time(0);
            req->ts_send = 0;
            req->fd = sinkfd->fd;
            req->crc16 = crc16(pac->header, pac->header_len);
            req->crc16 = crc16_crc(req->crc16, pac->data, pac->data_len);
            INIT_LIST_HEAD(&req->node);
            list_add(&req->node, &ctx->requests);
        } else if (pac->leader == SRRP_RESPONSE_LEADER) {
            struct api_response *resp = malloc(sizeof(*resp));
            memset(resp, 0, sizeof(*resp));
            resp->pac = pac;
            resp->fd = sinkfd->fd;
            INIT_LIST_HEAD(&resp->node);
            list_add(&resp->node, &ctx->responses);
        } else if (pac->leader == SRRP_SUBSCRIBE_LEADER ||
                   pac->leader == SRRP_UNSUBSCRIBE_LEADER ||
                   pac->leader == SRRP_PUBLISH_LEADER) {
            struct api_topic_msg *tmsg = malloc(sizeof(*tmsg));
            memset(tmsg, 0, sizeof(*tmsg));
            tmsg->pac = pac;
            tmsg->fd = sinkfd->fd;
            INIT_LIST_HEAD(&tmsg->node);
            list_add(&tmsg->node, &ctx->topic_msgs);
        }

        atbuf_read_advance(sinkfd->rxbuf, pac->len);
    }
}

static struct api_station *
find_station(struct list_head *stations, uint16_t sttid)
{
    struct api_station *pos;
    list_for_each_entry(pos, stations, node) {
        if (pos->sttid == sttid) {
            return pos;
        }
    }
    return NULL;
}

static struct api_topic *
find_topic(struct list_head *topics, const void *header, size_t len)
{
    struct api_topic *pos;
    list_for_each_entry(pos, topics, node) {
        if (memcmp(pos->header, header, len) == 0) {
            return pos;
        }
    }
    return NULL;
}

static void clear_unalive_station(struct apix *ctx)
{
    struct api_station *pos, *n;
    list_for_each_entry_safe(pos, n, &ctx->stations, node) {
        if (time(0) > pos->ts_alive + APIX_STATION_ALIVE_TIMEOUT / 1000) {
            LOG_DEBUG("clear unalive station: %x", pos->sttid);
            list_del(&pos->node);
            free(pos);
        }
    }
}

static void add_station(struct apix *ctx, struct api_request *req)
{
    struct api_station *stt = malloc(sizeof(*stt));
    memset(stt, 0, sizeof(*stt));
    stt->sttid = req->pac->srcid;
    stt->ts_alive = time(0);
    stt->fd = req->fd;
    INIT_LIST_HEAD(&stt->node);
    list_add(&stt->node, &ctx->stations);
}

static void topic_sub_handler(struct apix *ctx, struct api_topic_msg *tmsg)
{
    struct api_topic *topic = NULL;
    struct api_topic *pos;
    list_for_each_entry(pos, &ctx->topics, node) {
        if (memcmp(topic->header, tmsg->pac->header, strlen(topic->header)) == 0) {
            topic = pos;
            break;
        }
    }
    if (topic == NULL) {
        topic = malloc(sizeof(*topic));
        memset(topic, 0, sizeof(*topic));
        snprintf(topic->header, sizeof(topic->header), "%s", tmsg->pac->header);
        INIT_LIST_HEAD(&topic->node);
        list_add(&topic->node, &ctx->topics);
    }
    assert(topic);
    topic->fds[topic->nfds] = tmsg->fd;
    topic->nfds++;

    apix_send(ctx, tmsg->fd, "Sub OK", 6);
}

static void topic_unsub_handler(struct apix *ctx, struct api_topic_msg *tmsg)
{
    struct api_topic *topic = NULL;
    list_for_each_entry(topic, &ctx->topics, node) {
        if (strcmp(topic->header, tmsg->pac->header) == 0) {
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

    apix_send(ctx, tmsg->fd, "Unsub OK", 8);
}

static void topic_pub_handler(struct apix *ctx, struct api_topic_msg *tmsg)
{
    struct api_topic *topic = find_topic(
        &ctx->topics, tmsg->pac->header, tmsg->pac->header_len);
    if (topic) {
        for (int i = 0; i < topic->nfds; i++)
            apix_send(ctx, topic->fds[i], tmsg->pac->raw, tmsg->pac->len);
    } else {
        // do nothing, just drop this msg
        LOG_DEBUG("drop @: %s%s", tmsg->pac->header, tmsg->pac->data);
    }
}

struct apix *apix_new()
{
    struct apix *ctx = malloc(sizeof(*ctx));
    bzero(ctx, sizeof(*ctx));
    INIT_LIST_HEAD(&ctx->requests);
    INIT_LIST_HEAD(&ctx->responses);
    INIT_LIST_HEAD(&ctx->stations);
    INIT_LIST_HEAD(&ctx->topic_msgs);
    INIT_LIST_HEAD(&ctx->topics);
    INIT_LIST_HEAD(&ctx->sinkfds);
    INIT_LIST_HEAD(&ctx->sinks);
    return ctx;
}

void apix_destroy(struct apix *ctx)
{
    {
        struct api_request *pos, *n;
        list_for_each_entry_safe(pos, n, &ctx->requests, node)
            api_request_delete(pos);
    }

    {
        struct api_response *pos, *n;
        list_for_each_entry_safe(pos, n, &ctx->responses, node)
            api_response_delete(pos);
    }

    {
        struct api_station *pos, *n;
        list_for_each_entry_safe(pos, n, &ctx->stations, node) {
            list_del_init(&pos->node);
            free(pos);
        }
    }

    {
        struct api_topic_msg *pos, *n;
        list_for_each_entry_safe(pos, n, &ctx->topic_msgs, node)
            api_topic_msg_delete(pos);
    }

    {
        struct api_topic *pos, *n;
        list_for_each_entry_safe(pos, n, &ctx->topics, node) {
            list_del_init(&pos->node);
            free(pos);
        }
    }

    {
        struct sinkfd *pos, *n;
        list_for_each_entry_safe(pos, n, &ctx->sinkfds, node_ctx)
            sinkfd_destroy(pos);
    }

    {
        struct apisink *pos, *n;
        list_for_each_entry_safe(pos, n, &ctx->sinks, node) {
            apix_del_sink(ctx, pos);
            apisink_fini(pos);
        }
    }

    free(ctx);
}

static void handle_request(struct apix *ctx)
{
    struct api_request *pos, *n;
    list_for_each_entry_safe(pos, n, &ctx->requests, node) {
        if (pos->state == API_REQUEST_ST_WAIT_RESPONSE) {
            if (time(0) < pos->ts_send + API_REQUEST_TIMEOUT / 1000)
                continue;
            apix_send(ctx, pos->fd, "request timeout", 15);
            LOG_DEBUG("request timeout: %s", pos->pac->raw);
            api_request_delete(pos);
            continue;
        }

        LOG_INFO("poll >: %.4x:%s?%s", pos->pac->srcid, pos->pac->header, pos->pac->data);

        struct api_station *src = find_station(&ctx->stations, pos->pac->srcid);
        if (src == NULL)
            add_station(ctx, pos);
        else
            src->ts_alive = time(0);

        int dstid = 0;
        int nr = sscanf(pos->pac->header, "/%d/", &dstid);
        if (nr != 1) {
            apix_send(ctx, pos->fd, "STATION NOT FOUND", 17);
            api_request_delete(pos);
            continue;
        }
        struct api_station *dst = find_station(&ctx->stations, dstid);
        if (dst == NULL) {
            apix_send(ctx, pos->fd, "STATION NOT FOUND", 17);
            api_request_delete(pos);
            continue;
        }

        apix_send(ctx, dst->fd, pos->pac->raw, pos->pac->len);
        pos->state = API_REQUEST_ST_WAIT_RESPONSE;
        pos->ts_send = time(0);
    }
}

static void handle_response(struct apix *ctx)
{
    struct api_response *pos, *n;
    list_for_each_entry_safe(pos, n, &ctx->responses, node) {
        LOG_INFO("poll <: %.4x:%s?%s", pos->pac->srcid, pos->pac->header, pos->pac->data);

        struct api_request *pos_req, *n_req;
        list_for_each_entry_safe(pos_req, n_req, &ctx->requests, node) {
            if (pos_req->crc16 == pos->pac->reqcrc16 &&
                strcmp(pos_req->pac->header, pos->pac->header) == 0 &&
                pos_req->pac->srcid == pos->pac->srcid) {
                apix_send(ctx, pos_req->fd, pos->pac->raw, pos->pac->len);
                api_request_delete(pos_req);
                break;
            }
        }

        int dstid = 0;
        int nr = sscanf(pos->pac->header, "/%d/", &dstid);
        if (nr == 1) {
            struct api_station *dst = find_station(&ctx->stations, dstid);
            if (!dst)
                LOG_WARN("fake station: %d", dstid);
            else
                dst->ts_alive = time(0);
        }

        api_response_delete(pos);
    }
}

static void handle_topic_msg(struct apix *ctx)
{
    struct api_topic_msg *pos, *n;
    list_for_each_entry_safe(pos, n, &ctx->topic_msgs, node) {
        if (pos->pac->leader == SRRP_SUBSCRIBE_LEADER) {
            topic_sub_handler(ctx, pos);
            LOG_INFO("poll #: %s?%s", pos->pac->header, pos->pac->data);
        } else if (pos->pac->leader == SRRP_UNSUBSCRIBE_LEADER) {
            topic_unsub_handler(ctx, pos);
            LOG_INFO("poll %: %s?%s", pos->pac->header, pos->pac->data);
        } else {
            topic_pub_handler(ctx, pos);
            LOG_INFO("poll @: %s?%s", pos->pac->header, pos->pac->data);
        }
        api_topic_msg_delete(pos);
    }
}

int apix_poll(struct apix *ctx)
{
    ctx->poll_cnt = 0;
    gettimeofday(&ctx->poll_ts, NULL);

    // poll each sink
    struct apisink *pos_sink;
    list_for_each_entry(pos_sink, &ctx->sinks, node) {
        if (pos_sink->ops.poll(pos_sink) != 0) {
            LOG_ERROR("%s", strerror(errno));
        }
    }

    // parse each sinkfds
    struct sinkfd *pos_fd;
    list_for_each_entry(pos_fd, &ctx->sinkfds, node_ctx) {
        if (timercmp(&ctx->poll_ts, &pos_fd->ts_poll_recv, <))
            ctx->poll_cnt++;
        if (atbuf_used(pos_fd->rxbuf)) {
            parse_packet(ctx, pos_fd);
        }
    }

    LOG_DEBUG("poll_cnt: %d", ctx->poll_cnt);
    if (ctx->poll_cnt == 0) {
        if (ctx->idle_usec != APIX_IDLE_MAX) {
            ctx->idle_usec += APIX_IDLE_MAX / 10;
            if (ctx->idle_usec > APIX_IDLE_MAX)
                ctx->idle_usec = APIX_IDLE_MAX;
        }
        usleep(ctx->idle_usec);
    } else {
        ctx->idle_usec = APIX_IDLE_MAX / 10;
    }

    // hander each msg
    handle_request(ctx);
    handle_response(ctx);
    handle_topic_msg(ctx);

    // clear station which is not alive
    clear_unalive_station(ctx);

    return 0;
}

int apix_open(struct apix *ctx, const char *name, const char *addr)
{
    struct apisink *pos;
    list_for_each_entry(pos, &ctx->sinks, node) {
        if (strcmp(pos->name, name) == 0) {
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

int apix_send(struct apix *ctx, int fd, const void *buf, size_t len)
{
    struct sinkfd *sinkfd = find_sinkfd_in_apix(ctx, fd);
    if (sinkfd == NULL)
        return -1;
    if (sinkfd->sink == NULL || sinkfd->sink->ops.send == NULL)
        return -1;
    return sinkfd->sink->ops.send(sinkfd->sink, fd, buf, len);
}

int apix_recv(struct apix *ctx, int fd, void *buf, size_t size)
{
    struct sinkfd *sinkfd = find_sinkfd_in_apix(ctx, fd);
    if (sinkfd == NULL)
        return -1;
    if (sinkfd->sink == NULL || sinkfd->sink->ops.recv == NULL)
        return -1;
    return sinkfd->sink->ops.recv(sinkfd->sink, fd, buf, size);
}

void apisink_init(struct apisink *sink, const char *name, apisink_ops_t ops)
{
    assert(strlen(name) < APISINK_NAME_SIZE);
    INIT_LIST_HEAD(&sink->sinkfds);
    INIT_LIST_HEAD(&sink->node);
    snprintf(sink->name, sizeof(sink->name), "%s", name);
    sink->ops = ops;
    sink->ctx = NULL;
}

void apisink_fini(struct apisink *sink)
{
    struct sinkfd *pos, *n;
    list_for_each_entry_safe(pos, n, &sink->sinkfds, node_sink)
        sinkfd_destroy(pos);

    if (sink->ctx)
        apix_del_sink(sink->ctx, sink);
}

int apix_add_sink(struct apix *ctx, struct apisink *sink)
{
    struct apisink *pos;
    list_for_each_entry(pos, &ctx->sinks, node) {
        if (strcmp(sink->name, pos->name) == 0)
            return -1;
    }

    list_add(&sink->node, &ctx->sinks);
    sink->ctx = ctx;
    return 0;
}

void apix_del_sink(struct apix *ctx, struct apisink *sink)
{
    UNUSED(ctx);
    list_del_init(&sink->node);
    sink->ctx = NULL;
}

struct sinkfd *sinkfd_new()
{
    struct sinkfd *sinkfd = malloc(sizeof(struct sinkfd));
    memset(sinkfd, 0, sizeof(*sinkfd));
    sinkfd->fd = 0;
    sinkfd->listen = 0;
    sinkfd->txbuf = atbuf_new(0);
    sinkfd->rxbuf = atbuf_new(0);
    sinkfd->sink = NULL;
    INIT_LIST_HEAD(&sinkfd->node_sink);
    INIT_LIST_HEAD(&sinkfd->node_ctx);
    return sinkfd;
}

void sinkfd_destroy(struct sinkfd *sinkfd)
{
    sinkfd->fd = 0;
    atbuf_delete(sinkfd->txbuf);
    atbuf_delete(sinkfd->rxbuf);
    sinkfd->sink = NULL;
    list_del_init(&sinkfd->node_sink);
    list_del_init(&sinkfd->node_ctx);
    free(sinkfd);
}

struct sinkfd *find_sinkfd_in_apix(struct apix *ctx, int fd)
{
    struct sinkfd *pos, *n;
    list_for_each_entry_safe(pos, n, &ctx->sinkfds, node_ctx) {
        if (pos->fd == fd)
            return pos;
    }
    return NULL;
}

struct sinkfd *find_sinkfd_in_apisink(struct apisink *sink, int fd)
{
    struct sinkfd *pos, *n;
    list_for_each_entry_safe(pos, n, &sink->sinkfds, node_sink) {
        if (pos->fd == fd)
            return pos;
    }
    return NULL;
}
