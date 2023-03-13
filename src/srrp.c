#include "srrp.h"
#include <assert.h>
#include <ctype.h>
#include <inttypes.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include "str.h"
#include "unused.h"
#include "crc16.h"
#include "vec.h"

#define CRC_SIZE 5 /* <crc16>\0 */

void srrp_free(struct srrp_packet *pac)
{
    str_delete(pac->anchor);
    vec_delete(pac->raw);

    free(pac);
}

void srrp_move(struct srrp_packet *fst, struct srrp_packet *snd)
{
    // should not call srrp_free as it will free snd ...
    str_delete(snd->anchor);
    vec_delete(snd->raw);
    *snd = *fst;
    bzero(fst, sizeof(*fst));
    free(fst);
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
    uint32_t payload_offset, payload_len, srcid, dstid;
    char anchor[SRRP_ANCHOR_MAX] = {0};

    leader = buf[0];

    if (leader == SRRP_CTRL_LEADER ||
        leader == SRRP_REQUEST_LEADER ||
        leader == SRRP_RESPONSE_LEADER) {
        if (sscanf((char *)buf + 1, "%hx,%x,%x,#%x,#%x:%[^?]",
                   &packet_len, &payload_offset, &payload_len,
                   &srcid, &dstid, anchor) != 6)
            return NULL;
    } else if (leader == SRRP_SUBSCRIBE_LEADER ||
               leader == SRRP_UNSUBSCRIBE_LEADER ||
               leader == SRRP_PUBLISH_LEADER) {
        if (sscanf((char *)buf + 1, "%hx,%x,%x:%[^?]",
                   &packet_len, &payload_offset, &payload_len, anchor) != 4)
            return NULL;
    } else {
        return NULL;
    }

    if (packet_len > len)
        return NULL;

    if (packet_len > SRRP_PACKET_MAX)
        return NULL;

    uint16_t crc = 0;
    uint16_t reqcrc = 0;

    if (sscanf((char *)buf + packet_len - CRC_SIZE, "%4hx", &crc) != 1)
        return NULL;

    if (crc != crc16(buf, packet_len - CRC_SIZE))
        return NULL;

    if (leader == SRRP_RESPONSE_LEADER) {
        if (sscanf((char *)buf + packet_len - CRC_SIZE * 2, "%4hx", &reqcrc) != 1)
            return NULL;
    }

    struct srrp_packet *pac = calloc(1, sizeof(*pac));
    assert(pac);

    pac->raw = vec_new(1, packet_len);
    assert(pac->raw);
    vpack(pac->raw, buf, packet_len);

    pac->leader = leader;
    pac->packet_len = packet_len;
    pac->payload_offset = payload_offset;
    pac->payload_len = payload_len;

    pac->srcid = srcid;
    pac->dstid = dstid;

    pac->anchor = str_new(anchor);
    assert(pac->anchor);
    pac->payload = (uint8_t *)strstr(vraw(pac->raw), "?") + 1;

    pac->reqcrc16 = reqcrc;
    pac->crc16 = crc;
    return pac;
}

static struct srrp_packet *__srrp_new(
    char leader, uint32_t srcid, uint32_t dstid,
    const char *anchor, const char *payload, uint16_t reqcrc16)
{
    vec_t *v = vec_new(1, 0);
    assert(v);

    // leader
    vpush(v, &leader);

#ifndef VINSERT
    // packet_len
    vpack(v, "____", 4);
#endif

    // payload_offset
    vpack(v, ",0", 2);

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

    // reqcrc16
    if (leader == SRRP_RESPONSE_LEADER) {
        snprintf(tmp, sizeof(tmp), "%.4x", reqcrc16);
        assert(strlen(tmp) == 4);
        vpack(v, tmp, strlen(tmp));
        vpack(v, "\0", 1);
    }

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

    struct srrp_packet *pac = calloc(1, sizeof(*pac));
    assert(pac);
    pac->raw = v;

    pac->leader = leader;
    pac->packet_len = packet_len;
    pac->payload_offset = 0;
    pac->payload_len = strlen(payload);

    pac->srcid = srcid;
    pac->dstid = 0;

    pac->anchor = str_new(anchor);
    assert(pac->anchor);
    if (pac->payload_len == 0)
        pac->payload = vraw(pac->raw) + strlen(vraw(pac->raw));
    else
        pac->payload = (uint8_t *)strstr(vraw(pac->raw), "?") + 1;

    pac->reqcrc16 = reqcrc16;
    pac->crc16 = crc;

    return pac;
}

struct srrp_packet *
srrp_new_ctrl(uint32_t srcid, const char *anchor, const char *payload)
{
    return __srrp_new(SRRP_CTRL_LEADER, srcid, 0, anchor, payload, 0);
}

struct srrp_packet *srrp_new_request(
    uint32_t srcid, uint32_t dstid, const char *anchor, const char *payload)
{
    return __srrp_new(SRRP_REQUEST_LEADER, srcid, dstid, anchor, payload, 0);
}

struct srrp_packet *srrp_new_response(
    uint32_t srcid, uint32_t dstid,
    const char *anchor, const char *payload, uint16_t reqcrc16)
{
    return __srrp_new(SRRP_RESPONSE_LEADER, srcid, dstid, anchor, payload, reqcrc16);
}

struct srrp_packet *
srrp_new_subscribe(const char *anchor, const char *payload)
{
    return __srrp_new(SRRP_SUBSCRIBE_LEADER, 0, 0, anchor, payload, 0);
}

struct srrp_packet *
srrp_new_unsubscribe(const char *anchor, const char *payload)
{
    return __srrp_new(SRRP_UNSUBSCRIBE_LEADER, 0, 0, anchor, payload, 0);
}

struct srrp_packet *
srrp_new_publish(const char *anchor, const char *payload)
{
    return __srrp_new(SRRP_PUBLISH_LEADER, 0, 0, anchor, payload, 0);
}
