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

void srrp_free(struct srrp_packet *pac)
{
    free(pac);
}

static struct srrp_packet *
__srrp_parse_one_request(const char *buf)
{
    assert(buf[0] == SRRP_REQUEST_LEADER);

    char leader, seat;
    uint32_t seqno, len, srcid;

    // FIXME: shall we use "%c%x,%c,%4x,%4x:%[^{}]%s" to parse header and data ?
    int cnt = sscanf(buf, "%c%"PRIx32",%c,%4"PRIx32",%4"PRIx32":",
                     &leader, &seqno, &seat, &len, &srcid);
    if (cnt != 5) return NULL;

    const char *header_delimiter = strstr(buf, ":/");
    const char *data_delimiter = strstr(buf, "?{");
    if (header_delimiter == NULL || data_delimiter == NULL)
        return NULL;

    struct srrp_packet *pac = calloc(1, sizeof(*pac) + len);
    memcpy(pac->raw, buf, len);
    pac->leader = leader;
    pac->seat = seat;
    pac->seqno = seqno;
    pac->len = len;
    pac->srcid = srcid;

    const char *header = header_delimiter + 1;
    const char *data = data_delimiter + 1;
    pac->header_len = data_delimiter - header;
    memcpy((void *)pac->header, header, pac->header_len);
    pac->data = pac->raw + (data - buf);
    pac->data_len = buf + strlen(buf) - data;

    int retval =  3 + 2 + 5 + 5 + pac->header_len + 1 + pac->data_len + 1/*stop*/;
    if (retval != pac->len) {
        free(pac);
        return NULL;
    }
    return pac;
}

static struct srrp_packet *
__srrp_parse_one_response(const char *buf)
{
    assert(buf[0] == SRRP_RESPONSE_LEADER);

    char leader, seat;
    uint32_t seqno, len, srcid, reqcrc16;

    // FIXME: shall we use "%c%x,%c,%4x,%4x:%x%[^{}]%s" to parse header and data ?
    int cnt = sscanf(buf, "%c%"PRIx32",%c,%4"PRIx32",%4"PRIx32",%"PRIx32":/",
                     &leader, &seqno, &seat, &len, &srcid, &reqcrc16);
    if (cnt != 6) return NULL;

    const char *header_delimiter = strstr(buf, ":/");
    const char *data_delimiter = strstr(buf, "?{");
    if (header_delimiter == NULL || data_delimiter == NULL)
        return NULL;

    struct srrp_packet *pac = calloc(1, sizeof(*pac) + len);
    memcpy(pac->raw, buf, len);
    pac->leader = leader;
    pac->seat = seat;
    pac->seqno = seqno;
    pac->len = len;
    pac->srcid = srcid;
    pac->reqcrc16 = reqcrc16;

    const char *header = header_delimiter + 1;
    const char *data = data_delimiter + 1;
    pac->header_len = data_delimiter - header;
    memcpy((void *)pac->header, header, pac->header_len);
    pac->data = pac->raw + (data - buf);
    pac->data_len = buf + strlen(buf) - data;

    int retval =  3 + 2 + 5 + 5 + 5 + pac->header_len + 1 + pac->data_len + 1/*stop*/;
    if (retval != pac->len) {
        free(pac);
        return NULL;
    }
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

    // FIXME: shall we use "%c%x,%c,%4x:%[^{}]%s" to parse header and data ?
    int cnt = sscanf(buf, "%c%"PRIx32",%c,%4"PRIx32":", &leader, &seqno, &seat, &len);
    if (cnt != 4) return NULL;

    const char *header_delimiter = strstr(buf, ":/");
    const char *data_delimiter = strstr(buf, "?{");
    if (header_delimiter == NULL || data_delimiter == NULL)
        return NULL;

    struct srrp_packet *pac = calloc(1, sizeof(*pac) + len);
    memcpy(pac->raw, buf, len);
    pac->leader = leader;
    pac->seat = seat;
    pac->seqno = seqno;
    pac->len = len;

    const char *header = header_delimiter + 1;
    const char *data = data_delimiter + 1;
    pac->header_len = data_delimiter - header;
    memcpy((void *)pac->header, header, pac->header_len);
    pac->data = pac->raw + (data - buf);
    pac->data_len = buf + strlen(buf) - data;

    int retval =  3 + 2 + 5 + pac->header_len + 1 + pac->data_len + 1/*stop*/;
    if (retval != pac->len) {
        return NULL;
    }
    return pac;
}

struct srrp_packet *srrp_parse(const char *buf)
{
    const char *leader = buf;

    if (*leader == SRRP_REQUEST_LEADER)
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
srrp_new_request(uint16_t srcid, const char *header, const char *data)
{
    uint32_t len = 15 + strlen(header) + 1 + strlen(data) + 1/*stop*/;
    assert(len < SRRP_LENGTH_MAX - 4/*crc16*/);

    struct srrp_packet *pac = calloc(1, sizeof(*pac) + len);
    assert(pac);

    int nr = snprintf(pac->raw, len, ">0,$,%.4"PRIx32",%.4"PRIx16":%s?%s",
                      len, srcid, header, data);
    assert(nr >= 0 && (size_t)nr + 1 == len);

    pac->leader = SRRP_REQUEST_LEADER;
    pac->seat = '$';
    pac->seqno = 0;
    pac->len = len;
    pac->srcid = srcid;
    snprintf((char *)pac->header, sizeof(pac->header), "%s", header);
    pac->header_len = strlen(header);
    pac->data_len = strlen(data);
    pac->data = pac->raw + len - pac->data_len - 1;
    return pac;
}

struct srrp_packet *
srrp_new_response(uint16_t srcid, uint16_t reqcrc16, const char *header, const char *data)
{
    uint32_t len = 15 + 5/*crc16*/ + strlen(header) + 1 + strlen(data) + 1/*stop*/;
    assert(len < SRRP_LENGTH_MAX - 4/*crc16*/);

    struct srrp_packet *pac = calloc(1, sizeof(*pac) + len);
    assert(pac);

    int nr = snprintf(pac->raw, len, "<0,$,%.4"PRIx32",%.4"PRIx16",%.4"PRIx16":%s?%s",
                      len, srcid, reqcrc16, header, data);
    assert(nr >= 0 && (size_t)nr + 1 == len);

    pac->leader = SRRP_RESPONSE_LEADER;
    pac->seat = '$';
    pac->seqno = 0;
    pac->len = len;
    pac->srcid = srcid;
    pac->reqcrc16 = reqcrc16;
    snprintf((char *)pac->header, sizeof(pac->header), "%s", header);
    pac->header_len = strlen(header);
    pac->data_len = strlen(data);
    pac->data = pac->raw + len - pac->data_len - 1;
    return pac;
}

struct srrp_packet *
srrp_new_subscribe(const char *header, const char *ctrl)
{
    uint32_t len = 10 + strlen(header) + 1 + strlen(ctrl) + 1/*stop*/;
    assert(len < SRRP_LENGTH_MAX - 4/*crc16*/);

    struct srrp_packet *pac = calloc(1, sizeof(*pac) + len);
    assert(pac);

    int nr = snprintf(pac->raw, len, "#0,$,%.4"PRIx32":%s?%s", len, header, ctrl);
    assert(nr >= 0 && (size_t)nr + 1 == len);

    pac->leader = SRRP_SUBSCRIBE_LEADER;
    pac->seat = '$';
    pac->seqno = 0;
    pac->len = len;
    snprintf((char *)pac->header, sizeof(pac->header), "%s", header);
    pac->header_len = strlen(header);
    pac->data_len = strlen(ctrl);
    pac->data = pac->raw + len - pac->data_len - 1;
    return pac;
}

struct srrp_packet *
srrp_new_unsubscribe(const char *header)
{
    uint32_t len = 10 + strlen(header) + 1 + 2/*data*/ + 1/*stop*/;
    assert(len < SRRP_LENGTH_MAX - 4/*crc16*/);

    struct srrp_packet *pac = calloc(1, sizeof(*pac) + len);
    assert(pac);

    int nr = snprintf(pac->raw, len, "%%0,$,%.4"PRIx32":%s?{}", len, header);
    assert(nr >= 0 && (size_t)nr + 1 == len);

    pac->leader = SRRP_UNSUBSCRIBE_LEADER;
    pac->seat = '$';
    pac->seqno = 0;
    pac->len = len;
    snprintf((char *)pac->header, sizeof(pac->header), "%s", header);
    pac->header_len = strlen(header);
    pac->data_len = 2;
    pac->data = pac->raw + len - pac->data_len - 1;
    return pac;
}

struct srrp_packet *
srrp_new_publish(const char *header, const char *data)
{
    uint32_t len = 10 + strlen(header) + 1 + strlen(data) + 1/*stop*/;
    assert(len < SRRP_LENGTH_MAX - 4/*crc16*/);

    struct srrp_packet *pac = calloc(1, sizeof(*pac) + len);
    assert(pac);

    int nr = snprintf(pac->raw, len, "@0,$,%.4"PRIx32":%s?%s", len, header, data);
    assert(nr >= 0 && (size_t)nr + 1 == len);

    pac->leader = SRRP_PUBLISH_LEADER;
    pac->seat = '$';
    pac->seqno = 0;
    pac->len = len;
    snprintf((char *)pac->header, sizeof(pac->header), "%s", header);
    pac->header_len = strlen(header);
    pac->data_len = strlen(data);
    pac->data = pac->raw + len - pac->data_len - 1;
    return pac;
}

uint32_t srrp_next_packet_offset(const char *buf, uint32_t size)
{
    for (size_t i = 0; i < size; i++) {
        if (isdigit((uint8_t)buf[i + 1])) {
            if (buf[i] == SRRP_REQUEST_LEADER)
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
