#ifndef __SRRP_H // simple request response protocol
#define __SRRP_H

#include <stdint.h>
#include "vec.h"
#include "str.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Data type:
 *   ascii hex: packet_len, payload_offset, payload_len, srcid, dstid, reqcrc16, crc16
 *   acsii str: anchor
 *
 * Payload type:
 *   b: binary
 *   t: txt
 *   j: json
 *
 * Ctrl: =[packet_len],[payload_offset],[payload_len],#[srcid],#0:[/anchor]?[payload_type]:[payload]\0<crc16>\0
 *   =[packet_len],0,[payload_len],#F1,#0:/online?j:{"alias":["google.com","a.google.com","b.google.com"]}\0<crc16>\0
 *
 * Request: >[packet_len],[payload_offset],[payload_len],#[srcid],<#[dstid]|@[dst]>:[/anchor]?[payload_type]:[payload]\0<crc16>\0
 *   >[packet_len],0,[payload_len],#F1,#8A8F:/echo?j:{"v": "good news"}\0<crc16>\0
 *   >[packet_len],0,[payload_len],#F1,@google.com:/echo?j:{"v":"good news"}\0<crc16>\0
 *
 * Response: <[packet_len],[payload_offset],[payload_len],#[srcid],#[dstid]:[/anchor]?[payload_type]:[payload]\0<reqcrc16>:<crc16>\0
 *   <[packet_len],0,[payload_len],#8A8F,#F1:/echo?j:{"err":0,"msg":"succ","v":"good news"}\0<crc16>\0
 *
 * Subscribe: <[packet_len],[payload_offset],[payload_len]:[/anchor]?[payload_type]:[payload]\0<crc16>\0
 *   #[packet_len],0,[payload_len]:/motor/speed?_:\0<crc16>\0
 *
 * UnSubscribe: <[packet_len],[payload_offset],[payload_len]:[/anchor]?[payload_type]:[payload]\0<crc16>\0
 *   %[packet_len],0,[payload_len]:/motor/speed?_:\0<crc16>\0
 *
 * Publish: <[packet_len],[payload_offset],[payload_len]:[/anchor]?[payload_type]:[payload]\0<crc16>\0
 *   @[packet_len],0,[payload_len]:/motor/speed?j:{"speed":12,"voltage":24}\0<crc16>\0
 */

#define SRRP_CTRL_LEADER '='
#define SRRP_REQUEST_LEADER '>'
#define SRRP_RESPONSE_LEADER '<'
#define SRRP_SUBSCRIBE_LEADER '#'
#define SRRP_UNSUBSCRIBE_LEADER '%'
#define SRRP_PUBLISH_LEADER '@'

#define SRRP_PACKET_MAX 65535
#define SRRP_DST_ALIAS_MAX 64
#define SRRP_ANCHOR_MAX 1024

#define SRRP_CTRL_ONLINE "/online"
#define SRRP_CTRL_OFFLINE "/offline"

struct srrp_packet {
    char leader;
    uint16_t packet_len;
    uint32_t payload_offset;
    uint32_t payload_len;

    uint32_t srcid;
    uint32_t dstid;

    str_t *anchor;
    const uint8_t *payload;

    uint16_t reqcrc16; /* only used by response */
    uint16_t crc16;

    vec_t *raw;
};

/**
 * srrp_free
 * - free packet created by srrp_parse & srrp_new_*
 */
void srrp_free(struct srrp_packet *pac);

/**
 * srrp_move
 * - move packet from fst to snd, then auto free fst
 */
void srrp_move(struct srrp_packet *fst, struct srrp_packet *snd);

/**
 * srrp_next_packet_offset
 * - find offset of start position of next packet
 * - call it before srrp_parse
 */
uint32_t srrp_next_packet_offset(const uint8_t *buf, uint32_t len);

/**
 * srrp_parse
 * - read one packet from buffer
 */
struct srrp_packet *srrp_parse(const uint8_t *buf, uint32_t len);

/**
 * srrp_new_ctrl
 * - create new ctrl packet
 */
struct srrp_packet *
srrp_new_ctrl(uint32_t srcid, const char *anchor, const char *payload);

/**
 * srrp_new_request
 * - create new request packet
 */
struct srrp_packet *srrp_new_request(
    uint32_t srcid, uint32_t dstid, const char *anchor, const char *payload);

/**
 * srrp_new_response
 * - create new response packet
 */
struct srrp_packet *srrp_new_response(
    uint32_t srcid, uint32_t dstid,
    const char *anchor, const char *payload, uint16_t reqcrc16);

/**
 * srrp_new_subscribe
 * - create new subscribe packet
 */
struct srrp_packet *
srrp_new_subscribe(const char *anchor, const char *payload);

/**
 * srrp_new_unsubscribe
 * - create new unsubscribe packet
 */
struct srrp_packet *
srrp_new_unsubscribe(const char *anchor, const char *payload);

/**
 * srrp_new_publish
 * - create new publish packet
 */
struct srrp_packet *
srrp_new_publish(const char *anchor, const char *payload);

#ifdef __cplusplus
}
#endif
#endif
