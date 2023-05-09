#ifndef __SRRP_H // simple request response protocol
#define __SRRP_H

#include <string.h>
#include "types.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Data type:
 *   ascii hex: packet_len, fin, payload_len, srcid, dstid, crc16
 *   acsii str: anchor
 *
 * Payload type:
 *   b: binary
 *   t: txt
 *   j: json
 *
 * Ctrl: =[fin][ver2]#[packet_len]#[payload_len]#[srcid]#0:[/anchor]?[payload_type]:[payload]\0<crc16>\0
 *   =101#[packet_len]#[payload_len]#F1#0:/sync?j:{"alias":["google.com","a.google.com","b.google.com"]}\0<crc16>\0
 *
 * Request: >[fin][ver2]#[packet_len]#[payload_len]#[srcid]#[dstid]:[/anchor]?[payload_type]:[payload]\0<crc16>\0
 *   >001#[packet_len]#[payload_len]#F1#8A8F:/echo?j:{"err":0,\0<crc16>\0
 *   >101#[packet_len]#[payload_len]#F1#8A8F:/echo?j:"msg":"ok"}\0<crc16>\0
 *
 * Response: <[fin][ver2]#[packet_len]#[payload_len]#[srcid]#[dstid]:[/anchor]?[payload_type]:[payload]\0<crc16>\0
 *   <101#[packet_len]#[payload_len]#8A8F#F1:/echo?j:{"err":0,"msg":"ok","v":"good news"}\0<crc16>\0
 *
 * Subscribe: +[fin][ver2]#[packet_len]#[payload_len]:[/anchor]?[payload_type]:[payload]\0<crc16>\0
 *   +101#[packet_len]#0:/motor/speed\0<crc16>\0
 *
 * UnSubscribe: -[fin][ver2]#[packet_len]#[payload_len]:[/anchor]?[payload_type]:[payload]\0<crc16>\0
 *   -101#[packet_len]#0:/motor/speed\0<crc16>\0
 *
 * Publish: @[fin][ver2]#[packet_len]#[payload_len]:[/anchor]?[payload_type]:[payload]\0<crc16>\0
 *   @101#[packet_len]#[payload_len]:/motor/speed?j:{"speed":12,"voltage":24}\0<crc16>\0
 */

#define SRRP_VERSION_MAJOR 0 // 0 ~ 15
#define SRRP_VERSION_MINOR 1 // 0 ~ 15
#define SRRP_VERSION ((SRRP_VERSION_MAJOR << 8) + SRRP_VERSION_MINOR)

#define SRRP_CTRL_LEADER '='
#define SRRP_REQUEST_LEADER '>'
#define SRRP_RESPONSE_LEADER '<'
#define SRRP_SUBSCRIBE_LEADER '+'
#define SRRP_UNSUBSCRIBE_LEADER '-'
#define SRRP_PUBLISH_LEADER '@'

#define SRRP_FIN_0 0
#define SRRP_FIN_1 1

#define SRRP_PACKET_MAX 65535
#define SRRP_DST_ALIAS_MAX 64
#define SRRP_ID_MAX 256
#define SRRP_ANCHOR_MAX 1024

#define SRRP_CTRL_SYNC "/sync"
#define SRRP_CTRL_NODEID_DUP "/sync/nodeid/dup"

struct srrp_packet;

char srrp_get_leader(const struct srrp_packet *pac);
u8 srrp_get_fin(const struct srrp_packet *pac);
u16 srrp_get_ver(const struct srrp_packet *pac);
u16 srrp_get_packet_len(const struct srrp_packet *pac);
u32 srrp_get_payload_len(const struct srrp_packet *pac);
const char *srrp_get_srcid(const struct srrp_packet *pac);
const char *srrp_get_dstid(const struct srrp_packet *pac);
const char *srrp_get_anchor(const struct srrp_packet *pac);
const u8 *srrp_get_payload(const struct srrp_packet *pac);
u16 srrp_get_crc16(const struct srrp_packet *pac);
const u8 *srrp_get_raw(const struct srrp_packet *pac);

void srrp_set_fin(struct srrp_packet *pac, u8 fin);

/**
 * srrp_free
 * - free packet created by srrp_parse & srrp_new_*
 */
void srrp_free(struct srrp_packet *pac);

/**
 * srrp_move
 * - move packet from fst to snd, then auto free fst.
 * - the return value is snd.
 */
struct srrp_packet *srrp_move(struct srrp_packet *fst, struct srrp_packet *snd);

/**
 * srrp_cat
 * - concatenate slice packets.
 * - the return value is a new alloc packet.
 * - the fin of fst must 0, otherwise assert will fail.
 * - the leader, srcid, dstid, anchor, must same, otherwise assert will fail.
 */
struct srrp_packet *srrp_cat(
    const struct srrp_packet *fst, const struct srrp_packet *snd);

/**
 * srrp_next_packet_offset
 * - find offset of start position of next packet
 * - call it before srrp_parse
 */
u32 srrp_next_packet_offset(const u8 *buf, u32 len);

/**
 * srrp_parse
 * - read one packet from buffer
 */
struct srrp_packet *srrp_parse(const u8 *buf, u32 len);

/**
 * srrp_new
 * - create new srrp packet
 */
struct srrp_packet *srrp_new(
    char leader, u8 fin, const char *srcid, const char *dstid,
    const char *anchor, const u8 *payload, u32 payload_len);

/**
 * srrp_new_ctrl
 * - create new ctrl packet
 */
#define srrp_new_ctrl(srcid, anchor, payload)                   \
    srrp_new(SRRP_CTRL_LEADER, SRRP_FIN_1, srcid, 0,            \
             anchor, (const u8 *)payload, strlen(payload))

/**
 * srrp_new_request
 * - create new request packet
 */
#define srrp_new_request(srcid, dstid, anchor, payload)          \
    srrp_new(SRRP_REQUEST_LEADER, SRRP_FIN_1, srcid, dstid,      \
             anchor, (const u8 *)payload, strlen(payload))

/**
 * srrp_new_response
 * - create new response packet
 */
#define srrp_new_response(srcid, dstid, anchor, payload)          \
    srrp_new(SRRP_RESPONSE_LEADER, SRRP_FIN_1, srcid, dstid,      \
             anchor, (const u8 *)payload, strlen(payload))

/**
 * srrp_new_subscribe
 * - create new subscribe packet
 */
#define srrp_new_subscribe(anchor, payload)                     \
    srrp_new(SRRP_SUBSCRIBE_LEADER, SRRP_FIN_1, 0, 0,           \
             anchor, (const u8 *)payload, strlen(payload))

/**
 * srrp_new_unsubscribe
 * - create new unsubscribe packet
 */
#define srrp_new_unsubscribe(anchor, payload)                     \
    srrp_new(SRRP_UNSUBSCRIBE_LEADER, SRRP_FIN_1, 0, 0,           \
             anchor, (const u8 *)payload, strlen(payload))

/**
 * srrp_new_publish
 * - create new publish packet
 */
#define srrp_new_publish(anchor, payload)                   \
    srrp_new(SRRP_PUBLISH_LEADER, 1, 0, 0,                  \
             anchor, (const u8 *)payload, strlen(payload))

#ifdef __cplusplus
}
#endif
#endif
