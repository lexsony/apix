#include "srrp.h"
#include <assert.h>
#include <ctype.h>
#include <inttypes.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include "unused.h"
#include "crc16.h"
#include "str.h"
#include "vec.h"

#define CRC_SIZE 5 /* <crc16>\0 */

struct srrp_packet {
    char leader;
    uint16_t packet_len;

    uint8_t payload_fin;
    uint32_t payload_len;

    uint32_t srcid;
    uint32_t dstid;

    str_t *anchor;
    const uint8_t *payload;

    uint16_t crc16;
    vec_t *raw;
};

char srrp_get_leader(const struct srrp_packet *pac)
{
    return pac->leader;
}

uint16_t srrp_get_packet_len(const struct srrp_packet *pac)
{
    return pac->packet_len;
}

uint8_t srrp_get_payload_fin(const struct srrp_packet *pac)
{
    return pac->payload_fin;
}

uint32_t srrp_get_payload_len(const struct srrp_packet *pac)
{
    return pac->payload_len;
}

uint32_t srrp_get_srcid(const struct srrp_packet *pac)
{
    return pac->srcid;
}

uint32_t srrp_get_dstid(const struct srrp_packet *pac)
{
    return pac->dstid;
}

const char *srrp_get_anchor(const struct srrp_packet *pac)
{
    return sget(pac->anchor);
}

const uint8_t *srrp_get_payload(const struct srrp_packet *pac)
{
    return pac->payload;
}

uint16_t srrp_get_crc16(const struct srrp_packet *pac)
{
    return pac->crc16;
}

const uint8_t *srrp_get_raw(const struct srrp_packet *pac)
{
    return vraw(pac->raw);
}

void srrp_set_payload_fin(struct srrp_packet *pac, uint8_t fin)
{
    assert(fin == SRRP_PAYLOAD_FIN_0 || fin == SRRP_PAYLOAD_FIN_1);

    if (pac->payload_fin == fin)
        return;

    pac->payload_fin = fin;
    *((char *)vraw(pac->raw) + 6) = fin + '0';

    uint16_t crc = crc16(vraw(pac->raw), vsize(pac->raw) - CRC_SIZE);
    snprintf((char *)vraw(pac->raw) + vsize(pac->raw) - CRC_SIZE,
             CRC_SIZE, "%.4x", crc);
}

static vec_t *__srrp_new_raw(
    char leader, uint8_t payload_fin, uint32_t srcid, uint32_t dstid,
    const char *anchor, const char *payload)
{
    vec_t *v = vec_new(1, 0);
    assert(v);

    // leader
    vpush(v, &leader);

#ifndef VINSERT
    // packet_len
    vpack(v, "____", 4);
#endif

    // payload_fin
    vpack(v, ",", 1);
    uint8_t tmp_fin = payload_fin + '0';
    vpush(v, &tmp_fin);

    char tmp[32] = {0};

    // payload_len
    snprintf(tmp, sizeof(tmp), ",%x", (uint32_t)strlen(payload));
    vpack(v, tmp, strlen(tmp));

    if (leader == SRRP_CTRL_LEADER ||
        leader == SRRP_REQUEST_LEADER ||
        leader == SRRP_RESPONSE_LEADER) {
        // srcid
        snprintf(tmp, sizeof(tmp), ",#%x", srcid);
        vpack(v, tmp, strlen(tmp));
        // dstid
        snprintf(tmp, sizeof(tmp), ",#%x", dstid);
        vpack(v, tmp, strlen(tmp));
    }

    // anchor
    vpack(v, ":", 1);
    vpack(v, anchor, strlen(anchor));

    // payload
    if (strlen(payload)) {
        vpack(v, "?", 1);
        vpack(v, payload, strlen(payload));
    }

    // stop flag
    vpack(v, "\0", 1);

    // packet_len
#ifndef VINSERT
    uint16_t packet_len = vsize(v) + CRC_SIZE;
    assert(packet_len < SRRP_PACKET_MAX);
    snprintf(tmp, sizeof(tmp), "%.4x", packet_len);
    assert(strlen(tmp) == 4);
    memcpy((char *)vraw(v) + 1, tmp, 4);
#else
    uint16_t packet_len = vsize(v) + CRC_SIZE + 4;
    assert(packet_len < SRRP_PACKET_MAX);
    snprintf(tmp, sizeof(tmp), "%.4x", packet_len);
    assert(strlen(tmp) == 4);
    vinsert(v, 1, tmp, 4);
#endif

    // crc16
    uint16_t crc = crc16(vraw(v), vsize(v));
    snprintf(tmp, sizeof(tmp), "%.4x", crc);
    assert(strlen(tmp) == 4);
    vpack(v, tmp, strlen(tmp));
    vpack(v, "\0", 1);

    vshrink(v);
    return v;
}

static struct srrp_packet *__srrp_new(
    char leader, uint8_t payload_fin, uint32_t srcid, uint32_t dstid,
    const char *anchor, const char *payload)
{
    vec_t *v = __srrp_new_raw(
        leader, payload_fin, srcid, dstid, anchor, payload);

    struct srrp_packet *pac = calloc(1, sizeof(*pac));
    assert(pac);
    pac->raw = v;

    pac->leader = leader;
    pac->packet_len = vsize(v);
    pac->payload_fin = payload_fin;
    pac->payload_len = strlen(payload);

    pac->srcid = srcid;
    pac->dstid = dstid;

    pac->anchor = str_new(anchor);
    assert(pac->anchor);
    if (pac->payload_len == 0)
        pac->payload = vraw(pac->raw) + strlen(vraw(pac->raw));
    else
        pac->payload = (uint8_t *)strstr(vraw(pac->raw), "?") + 1;

    sscanf(vraw(v) + vsize(v) - CRC_SIZE, "%4hx", &pac->crc16);

#ifdef DEBUG_SRRP
    printf("srrp_new : %p\n", pac);
#endif
    return pac;
}

void srrp_free(struct srrp_packet *pac)
{
#ifdef DEBUG_SRRP
    printf("srrp_free: %p\n", pac);
#endif

    str_delete(pac->anchor);
    vec_delete(pac->raw);

    free(pac);
}

struct srrp_packet *srrp_move(struct srrp_packet *fst, struct srrp_packet *snd)
{
    // should not call srrp_free as it will free snd ...
    str_delete(snd->anchor);
    vec_delete(snd->raw);
    *snd = *fst;
    bzero(fst, sizeof(*fst));
    free(fst);
    return snd;
}

struct srrp_packet *srrp_cat(struct srrp_packet *fst, struct srrp_packet *snd)
{
    assert(fst->leader == snd->leader);
    assert(fst->payload_fin == SRRP_PAYLOAD_FIN_0);
    assert(fst->srcid == snd->srcid);
    assert(fst->dstid == snd->dstid);
    assert(strcmp(sget(fst->anchor), sget(snd->anchor)) == 0);

    if (snd->payload_len == 0 && snd->payload_fin == SRRP_PAYLOAD_FIN_0)
        goto out;

    fst->packet_len += snd->payload_len;
    fst->payload_fin = snd->payload_fin;
    fst->payload_len += snd->payload_len;

    for (int i = 0; i < CRC_SIZE + 1; i++) {
        char tmp;
        vpop_back(fst->raw, &tmp);
    }
    vpack(fst->raw, snd->payload, snd->payload_len);

    // stop flag
    vpack(fst->raw, "\0", 1);

    vec_t *v = __srrp_new_raw(fst->leader, fst->payload_fin,
                              fst->srcid, fst->dstid,
                              sget(fst->anchor),
                              (const char *)fst->payload);

    vec_delete(fst->raw);
    fst->raw = v;

out:
    srrp_free(snd);
    return fst;
}

uint32_t srrp_next_packet_offset(const uint8_t *buf, uint32_t len)
{
    for (uint32_t i = 0; i < len; i++) {
        if (isdigit(buf[i + 1])) {
            if (buf[i] == SRRP_CTRL_LEADER)
                return i;
            else if (buf[i] == SRRP_REQUEST_LEADER)
                return i;
            else if (buf[i] == SRRP_RESPONSE_LEADER)
                return i;
            else if (buf[i] == SRRP_SUBSCRIBE_LEADER ||
                     buf[i] == SRRP_UNSUBSCRIBE_LEADER ||
                     buf[i] == SRRP_PUBLISH_LEADER)
                return i;
        }
    }

    return len;
}

struct srrp_packet *srrp_parse(const uint8_t *buf, uint32_t len)
{
    char leader;
    uint16_t packet_len;
    uint32_t payload_fin, payload_len, srcid, dstid;
    char anchor[SRRP_ANCHOR_MAX] = {0};

    leader = buf[0];

    if (leader == SRRP_CTRL_LEADER ||
        leader == SRRP_REQUEST_LEADER ||
        leader == SRRP_RESPONSE_LEADER) {
        if (sscanf((char *)buf + 1, "%hx,%x,%x,#%x,#%x:%[^?]",
                   &packet_len, &payload_fin, &payload_len,
                   &srcid, &dstid, anchor) != 6)
            return NULL;
    } else if (leader == SRRP_SUBSCRIBE_LEADER ||
               leader == SRRP_UNSUBSCRIBE_LEADER ||
               leader == SRRP_PUBLISH_LEADER) {
        if (sscanf((char *)buf + 1, "%hx,%x,%x:%[^?]",
                   &packet_len, &payload_fin, &payload_len, anchor) != 4)
            return NULL;
    } else {
        return NULL;
    }

    if (packet_len > len)
        return NULL;

    uint16_t crc = 0;

    if (sscanf((char *)buf + packet_len - CRC_SIZE, "%4hx", &crc) != 1)
        return NULL;

    if (crc != crc16(buf, packet_len - CRC_SIZE))
        return NULL;

    struct srrp_packet *pac = calloc(1, sizeof(*pac));
    assert(pac);

    pac->raw = vec_new(1, packet_len);
    assert(pac->raw);
    vpack(pac->raw, buf, packet_len);

    pac->leader = leader;
    pac->packet_len = packet_len;
    pac->payload_fin = payload_fin;
    pac->payload_len = payload_len;

    pac->srcid = srcid;
    pac->dstid = dstid;

    pac->anchor = str_new(anchor);
    assert(pac->anchor);
    if (pac->payload_len == 0)
        pac->payload = vraw(pac->raw) + strlen(vraw(pac->raw));
    else
        pac->payload = (uint8_t *)strstr(vraw(pac->raw), "?") + 1;

    pac->crc16 = crc;
#ifdef DEBUG_SRRP
    printf("srrp_new : %p\n", pac);
#endif
    return pac;
}

struct srrp_packet *
srrp_new_ctrl(uint32_t srcid, const char *anchor, const char *payload)
{
    return __srrp_new(SRRP_CTRL_LEADER, SRRP_PAYLOAD_FIN_1,
                      srcid, 0, anchor, payload);
}

struct srrp_packet *srrp_new_request(
    uint32_t srcid, uint32_t dstid, const char *anchor, const char *payload)
{
    return __srrp_new(SRRP_REQUEST_LEADER, SRRP_PAYLOAD_FIN_1,
                      srcid, dstid, anchor, payload);
}

struct srrp_packet *srrp_new_response(
    uint32_t srcid, uint32_t dstid, const char *anchor, const char *payload)
{
    return __srrp_new(SRRP_RESPONSE_LEADER, SRRP_PAYLOAD_FIN_1,
                      srcid, dstid, anchor, payload);
}

struct srrp_packet *
srrp_new_subscribe(const char *anchor, const char *payload)
{
    return __srrp_new(SRRP_SUBSCRIBE_LEADER, SRRP_PAYLOAD_FIN_1,
                      0, 0, anchor, payload);
}

struct srrp_packet *
srrp_new_unsubscribe(const char *anchor, const char *payload)
{
    return __srrp_new(SRRP_UNSUBSCRIBE_LEADER, SRRP_PAYLOAD_FIN_1,
                      0, 0, anchor, payload);
}

struct srrp_packet *
srrp_new_publish(const char *anchor, const char *payload)
{
    return __srrp_new(SRRP_PUBLISH_LEADER, SRRP_PAYLOAD_FIN_1,
                      0, 0, anchor, payload);
}
