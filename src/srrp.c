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

#define SEQNO_MAX_LEN 32
#define LENGTH_MAX_LEN 32
#define SRCID_MAX_LEN 32

#define LEADER_SEQNO_SIZE 5 /* >0,$, */
#define LENGTH_SIZE 5       /* <len>, */
#define SRCID_SIZE 5        /* 0001: */
#define DSTID_SIZE 5        /* 8888: */
#define CRC_SIZE 5          /* <crc16>\0 */

void srrp_free(struct srrp_packet *pac)
{
    free(pac);
}

static uint16_t calc_crc(const char *buf, size_t len)
{
    return crc16(buf, len - CRC_SIZE);
}

static uint16_t parse_crc(const char *buf, size_t len)
{
    uint16_t crc;
    assert(sscanf(buf + len - CRC_SIZE, "%4hx", &crc) == 1);
    return crc;
}

static struct srrp_packet *
__srrp_parse_one_ctrl(const char *buf)
{
    assert(buf[0] == SRRP_CTRL_LEADER);

    char leader, seat;
    uint32_t seqno, len, srcid;

    int cnt = sscanf(buf, "%c%"PRIx32",%c,%4"PRIx32",%4"PRIx32":",
                     &leader, &seqno, &seat, &len, &srcid);
    if (cnt != 5) return NULL;

    const char *header_delimiter = strstr(buf, ":/");
    if (header_delimiter == NULL)
        return NULL;

    uint16_t crc = calc_crc(buf, len);
    if (parse_crc(buf, len) != crc)
        return NULL;

    struct srrp_packet *pac = calloc(1, sizeof(*pac) + len);
    memcpy(pac->raw, buf, len);
    pac->leader = leader;
    pac->seat = seat;
    pac->seqno = seqno;
    pac->len = len;
    pac->srcid = srcid;
    pac->crc16 = crc;

    pac->header = header_delimiter + 1;
    pac->header_len = strlen(pac->header);
    pac->data = NULL;
    pac->data_len = 0;

    return pac;
}

static struct srrp_packet *
__srrp_parse_one_request(const char *buf)
{
    assert(buf[0] == SRRP_REQUEST_LEADER);

    char leader, seat;
    uint32_t seqno, len, srcid, dstid;

    int cnt = sscanf(buf, "%c%"PRIx32",%c,%4"PRIx32",%4"PRIx32":%4"PRIx32":",
                     &leader, &seqno, &seat, &len, &srcid, &dstid);
    if (cnt != 6) return NULL;

    const char *header_delimiter = strstr(buf, ":/");
    if (header_delimiter == NULL)
        return NULL;

    uint16_t crc = calc_crc(buf, len);
    if (parse_crc(buf, len) != crc)
        return NULL;

    struct srrp_packet *pac = calloc(1, sizeof(*pac) + len);
    memcpy(pac->raw, buf, len);
    pac->leader = leader;
    pac->seat = seat;
    pac->seqno = seqno;
    pac->len = len;
    pac->srcid = srcid;
    pac->dstid = dstid;
    pac->crc16 = crc;

    pac->header = header_delimiter + 1;
    pac->header_len = strlen(pac->header);
    pac->data = buf + strlen(buf) + 1;
    pac->data_len = strlen(pac->data);

    return pac;
}

static struct srrp_packet *
__srrp_parse_one_response(const char *buf)
{
    assert(buf[0] == SRRP_RESPONSE_LEADER);

    char leader, seat;
    uint32_t seqno, len, srcid, dstid, reqcrc16;

    int cnt = sscanf(buf, "%c%"PRIx32",%c,%4"PRIx32",%4"PRIx32":%4"PRIx32":%4"PRIx32":",
                     &leader, &seqno, &seat, &len, &srcid, &dstid, &reqcrc16);
    if (cnt != 7) return NULL;

    const char *header_delimiter = strstr(buf, ":/");
    if (header_delimiter == NULL)
        return NULL;

    uint16_t crc = calc_crc(buf, len);
    if (parse_crc(buf, len) != crc)
        return NULL;

    struct srrp_packet *pac = calloc(1, sizeof(*pac) + len);
    memcpy(pac->raw, buf, len);
    pac->leader = leader;
    pac->seat = seat;
    pac->seqno = seqno;
    pac->len = len;
    pac->srcid = srcid;
    pac->dstid = dstid;
    pac->reqcrc16 = reqcrc16;
    pac->crc16 = crc;

    pac->header = header_delimiter + 1;
    pac->header_len = strlen(pac->header);
    pac->data = buf + strlen(buf) + 1;
    pac->data_len = strlen(pac->data);

    return pac;
}

static struct srrp_packet *
__srrp_parse_one_subpub(const char *buf)
{
    assert(buf[0] == SRRP_SUBSCRIBE_LEADER ||
           buf[0] == SRRP_UNSUBSCRIBE_LEADER ||
           buf[0] == SRRP_PUBLISH_LEADER);

    char leader, seat;
    uint32_t seqno, len;

    int cnt = sscanf(buf, "%c%"PRIx32",%c,%4"PRIx32":", &leader, &seqno, &seat, &len);
    if (cnt != 4) return NULL;

    const char *header_delimiter = strstr(buf, ":/");
    if (header_delimiter == NULL)
        return NULL;

    uint16_t crc = calc_crc(buf, len);
    if (parse_crc(buf, len) != crc)
        return NULL;

    struct srrp_packet *pac = calloc(1, sizeof(*pac) + len);
    memcpy(pac->raw, buf, len);
    pac->leader = leader;
    pac->seat = seat;
    pac->seqno = seqno;
    pac->len = len;
    pac->crc16 = crc;
    pac->header = header_delimiter + 1;
    pac->header_len = strlen(pac->header);
    pac->data = buf + strlen(buf) + 1;
    pac->data_len = strlen(pac->data);

    return pac;
}

struct srrp_packet *srrp_parse(const char *buf)
{
    const char *leader = buf;

    if (*leader == SRRP_CTRL_LEADER)
        return __srrp_parse_one_ctrl(buf);
    else if (*leader == SRRP_REQUEST_LEADER)
        return __srrp_parse_one_request(buf);
    else if (*leader == SRRP_RESPONSE_LEADER)
        return __srrp_parse_one_response(buf);
    else if (*leader == SRRP_SUBSCRIBE_LEADER ||
             *leader == SRRP_UNSUBSCRIBE_LEADER ||
             *leader == SRRP_PUBLISH_LEADER)
        return __srrp_parse_one_subpub(buf);

    return NULL;
}

struct srrp_packet *
srrp_new_ctrl(uint16_t srcid, const char *header)
{
    uint16_t len = LEADER_SEQNO_SIZE + LENGTH_SIZE + SRCID_SIZE +
        strlen(header) + 1/*\0*/ + CRC_SIZE;
    assert(len < SRRP_LENGTH_MAX);

    struct srrp_packet *pac = calloc(1, sizeof(*pac) + len);
    assert(pac);

    int nr = snprintf(pac->raw, len, "%c0,$,%.4"PRIx16",%.4"PRIx16":%s",
                      SRRP_CTRL_LEADER, len, srcid, header) + 1;
    assert((uint16_t)nr + CRC_SIZE == len);
    uint16_t crc = calc_crc(pac->raw, len);
    snprintf(pac->raw + nr, CRC_SIZE, "%.4"PRIx16"", crc);

    pac->leader = SRRP_CTRL_LEADER;
    pac->seat = '$';
    pac->seqno = 0;
    pac->len = len;
    pac->srcid = srcid;
    pac->dstid = 0;
    pac->reqcrc16 = 0;
    pac->crc16 = crc;
    pac->header = strstr(pac->raw, header);
    pac->header_len = strlen(header);
    pac->data = NULL;
    pac->data_len = 0;
    return pac;
}

struct srrp_packet *
srrp_new_request(uint16_t srcid, uint16_t dstid, const char *header, const char *data)
{
    uint16_t len = LEADER_SEQNO_SIZE + LENGTH_SIZE + SRCID_SIZE + DSTID_SIZE +
        strlen(header) + 1/*\0*/ + strlen(data) + 1/*\0*/ + CRC_SIZE;
    assert(len < SRRP_LENGTH_MAX);

    struct srrp_packet *pac = calloc(1, sizeof(*pac) + len);
    assert(pac);

    int nr = snprintf(pac->raw, len, "%c0,$,%.4"PRIx16",%.4"PRIx16":%.4"PRIx16":%s",
                      SRRP_REQUEST_LEADER, len, srcid, dstid, header) + 1;
    nr += snprintf(pac->raw + nr, len - nr, "%s", data) + 1;
    assert((uint16_t)nr + CRC_SIZE == len);
    uint16_t crc = calc_crc(pac->raw, len);
    snprintf(pac->raw + nr, CRC_SIZE, "%.4"PRIx16"", crc);

    pac->leader = SRRP_REQUEST_LEADER;
    pac->seat = '$';
    pac->seqno = 0;
    pac->len = len;
    pac->srcid = srcid;
    pac->dstid = dstid;
    pac->reqcrc16 = 0;
    pac->crc16 = crc;
    pac->header = strstr(pac->raw, header);
    pac->header_len = strlen(header);
    pac->data = pac->raw + strlen(pac->raw) + 1;
    pac->data_len = strlen(data);
    return pac;
}

struct srrp_packet *
srrp_new_response(uint16_t srcid, uint16_t dstid, uint16_t reqcrc16,
                  const char *header, const char *data)
{
    uint16_t len = LEADER_SEQNO_SIZE + LENGTH_SIZE + SRCID_SIZE + DSTID_SIZE +
        CRC_SIZE + strlen(header) + 1/*\0*/ + strlen(data) + 1/*\0*/ + CRC_SIZE;
    assert(len < SRRP_LENGTH_MAX);

    struct srrp_packet *pac = calloc(1, sizeof(*pac) + len);
    assert(pac);

    int nr = snprintf(pac->raw, len, "%c0,$,%.4"PRIx16",%.4"PRIx16":%.4"PRIx16":%.4"PRIx16":%s",
                      SRRP_RESPONSE_LEADER, len, srcid, dstid, reqcrc16, header) + 1;
    nr += snprintf(pac->raw + nr, len - nr, "%s", data) + 1;
    assert((uint16_t)nr + CRC_SIZE == len);
    uint16_t crc = calc_crc(pac->raw, len);
    snprintf(pac->raw + nr, CRC_SIZE, "%.4"PRIx16"", crc);

    pac->leader = SRRP_RESPONSE_LEADER;
    pac->seat = '$';
    pac->seqno = 0;
    pac->len = len;
    pac->srcid = srcid;
    pac->dstid = dstid;
    pac->reqcrc16 = reqcrc16;
    pac->crc16 = crc;
    pac->header = strstr(pac->raw, header);
    pac->header_len = strlen(header);
    pac->data = pac->raw + strlen(pac->raw) + 1;
    pac->data_len = strlen(data);
    return pac;
}

static struct srrp_packet *
__srrp_new_subpub(const char *header, const char *ctrl, char leader)
{
    uint16_t len = LEADER_SEQNO_SIZE + LENGTH_SIZE +
        strlen(header) + 1/*\0*/ + strlen(ctrl) + 1/*\0*/ + CRC_SIZE;
    assert(len < SRRP_LENGTH_MAX);

    struct srrp_packet *pac = calloc(1, sizeof(*pac) + len);
    assert(pac);

    int nr = snprintf(pac->raw, len, "%c0,$,%.4"PRIx16":%s",
                      leader, len, header) + 1;
    nr += snprintf(pac->raw + nr, len - nr, "%s", ctrl) + 1;
    assert((uint16_t)nr + CRC_SIZE == len);
    uint16_t crc = calc_crc(pac->raw, len);
    snprintf(pac->raw + nr, CRC_SIZE, "%.4"PRIx16"", crc);

    pac->leader = leader;
    pac->seat = '$';
    pac->seqno = 0;
    pac->len = len;
    pac->crc16 = crc;
    pac->header = strstr(pac->raw, header);
    pac->header_len = strlen(header);
    pac->data = pac->raw + strlen(pac->raw) + 1;
    pac->data_len = strlen(ctrl);
    return pac;
}

struct srrp_packet *
srrp_new_subscribe(const char *header, const char *ctrl)
{
    return __srrp_new_subpub(header, ctrl, SRRP_SUBSCRIBE_LEADER);
}

struct srrp_packet *
srrp_new_unsubscribe(const char *header, const char *ctrl)
{
    return __srrp_new_subpub(header, ctrl, SRRP_UNSUBSCRIBE_LEADER);
}

struct srrp_packet *
srrp_new_publish(const char *header, const char *data)
{
    return __srrp_new_subpub(header, data, SRRP_PUBLISH_LEADER);
}

uint32_t srrp_next_packet_offset(const char *buf, uint32_t size)
{
    for (size_t i = 0; i < size; i++) {
        if (isdigit((uint8_t)buf[i + 1])) {
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

    return size;
}
