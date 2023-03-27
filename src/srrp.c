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

static vec_t *__srrp_new_raw(
    char leader, uint8_t fin, uint32_t srcid, uint32_t dstid,
    const char *anchor, const uint8_t *payload, uint32_t payload_len);

struct srrp_packet {
    char leader;
    uint8_t fin;
    uint16_t ver;

    uint16_t packet_len;
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

uint8_t srrp_get_fin(const struct srrp_packet *pac)
{
    return pac->fin;
}

uint16_t srrp_get_ver(const struct srrp_packet *pac)
{
    return pac->ver;
}

uint16_t srrp_get_packet_len(const struct srrp_packet *pac)
{
    return pac->packet_len;
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

void srrp_set_fin(struct srrp_packet *pac, uint8_t fin)
{
    assert(fin == SRRP_FIN_0 || fin == SRRP_FIN_1);

    if (pac->fin == fin)
        return;

    pac->fin = fin;
    *((char *)vraw(pac->raw) + 1) = fin + '0';

    uint16_t crc = crc16(vraw(pac->raw), vsize(pac->raw) - CRC_SIZE);
    snprintf((char *)vraw(pac->raw) + vsize(pac->raw) - CRC_SIZE,
             CRC_SIZE, "%.4x", crc);
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
    assert(fst->fin == SRRP_FIN_0);
    assert(fst->srcid == snd->srcid);
    assert(fst->dstid == snd->dstid);
    assert(strcmp(sget(fst->anchor), sget(snd->anchor)) == 0);

    if (snd->payload_len == 0 && snd->fin == SRRP_FIN_0)
        goto out;

    fst->packet_len += snd->payload_len;
    fst->fin = snd->fin;
    fst->payload_len += snd->payload_len;

    for (int i = 0; i < CRC_SIZE + 1; i++) {
        char tmp;
        vpop_back(fst->raw, &tmp);
    }
    vpack(fst->raw, snd->payload, snd->payload_len);

    // stop flag
    vpack(fst->raw, "\0", 1);

    vec_t *v = __srrp_new_raw(fst->leader, fst->fin,
                              fst->srcid, fst->dstid,
                              sget(fst->anchor),
                              fst->payload,
                              fst->payload_len);

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
    uint8_t fin;
    uint16_t ver, packet_len;
    uint32_t payload_len, srcid, dstid;
    char anchor[SRRP_ANCHOR_MAX] = {0};

    leader = buf[0];

    if (leader == SRRP_CTRL_LEADER ||
        leader == SRRP_REQUEST_LEADER ||
        leader == SRRP_RESPONSE_LEADER) {
        if (sscanf((char *)buf + 1, "%c%hx#%hx#%x#%x#%x:%[^?]",
                   &fin, &ver, &packet_len, &payload_len,
                   &srcid, &dstid, anchor) != 7)
            return NULL;
    } else if (leader == SRRP_SUBSCRIBE_LEADER ||
               leader == SRRP_UNSUBSCRIBE_LEADER ||
               leader == SRRP_PUBLISH_LEADER) {
        if (sscanf((char *)buf + 1, "%c%hx#%hx#%x:%[^?]",
                   &fin, &ver, &packet_len, &payload_len, anchor) != 5)
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
    pac->fin = fin;
    pac->ver = ver;
    pac->packet_len = packet_len;
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

static vec_t *__srrp_new_raw(
    char leader, uint8_t fin, uint32_t srcid, uint32_t dstid,
    const char *anchor, const uint8_t *payload, uint32_t payload_len)
{
    char tmp[32] = {0};

    vec_t *v = vec_new(1, 0);
    assert(v);

    // leader
    vpush(v, &leader);

    // fin
    uint8_t tmp_fin = fin + '0';
    vpush(v, &tmp_fin);

    // ver2
    snprintf(tmp, sizeof(tmp), "%.1x%.1x", SRRP_VERSION_MAJOR, SRRP_VERSION_MINOR);
    assert(strlen(tmp) == 2);
    vpack(v, tmp, 2);

//#define VINSERT
#ifndef VINSERT
    // packet_len
    vpack(v, "#____", 5);
#else
    vpack(v, "#", 1);
#endif

    // payload_len
    snprintf(tmp, sizeof(tmp), "#%x", payload_len);
    vpack(v, tmp, strlen(tmp));

    if (leader == SRRP_CTRL_LEADER ||
        leader == SRRP_REQUEST_LEADER ||
        leader == SRRP_RESPONSE_LEADER) {
        // srcid
        snprintf(tmp, sizeof(tmp), "#%x", srcid);
        vpack(v, tmp, strlen(tmp));
        // dstid
        snprintf(tmp, sizeof(tmp), "#%x", dstid);
        vpack(v, tmp, strlen(tmp));
    }

    // anchor
    vpack(v, ":", 1);
    vpack(v, anchor, strlen(anchor));

    // payload
    if (payload_len) {
        vpack(v, "?", 1);
        vpack(v, payload, payload_len);
    }

    // stop flag
    vpack(v, "\0", 1);

    // packet_len
#ifndef VINSERT
    uint16_t packet_len = vsize(v) + CRC_SIZE;
    assert(packet_len < SRRP_PACKET_MAX);
    snprintf(tmp, sizeof(tmp), "%.4x", packet_len);
    assert(strlen(tmp) == 4);
    memcpy((char *)vraw(v) + 5, tmp, 4);
#else
    uint16_t packet_len = vsize(v) + CRC_SIZE + 4;
    assert(packet_len < SRRP_PACKET_MAX);
    snprintf(tmp, sizeof(tmp), "%.4x", packet_len);
    assert(strlen(tmp) == 4);
    vinsert(v, 5, tmp, 4);
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

struct srrp_packet *srrp_new(
    char leader, uint8_t fin, uint32_t srcid, uint32_t dstid,
    const char *anchor, const uint8_t *payload, uint32_t payload_len)
{
    vec_t *v = __srrp_new_raw(
        leader, fin, srcid, dstid, anchor, payload, payload_len);

    struct srrp_packet *pac = calloc(1, sizeof(*pac));
    assert(pac);
    pac->raw = v;

    pac->leader = leader;
    pac->fin = fin;
    pac->ver = SRRP_VERSION;
    pac->packet_len = vsize(v);
    pac->payload_len = payload_len;

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
