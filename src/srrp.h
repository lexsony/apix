#ifndef __SRRP_H // simple request response protocol
#define __SRRP_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Ctrl: =[0xseqno],[^|0|$],[0xlen],[0xsrcid]:header\0<crc16>\0
 *   =0,$,<len>,0001:/online\0<crc16>\0
 *   =0,$,<len>,0001:/offline\0<crc16>\0
 *   =0,$,<len>,0001:/alive\0<crc16>\0
 *
 * Request: >[0xseqno],[^|0|$],[0xlen],[0xsrcid]:[0xdstid]:header\0[j|b|t]:data\0<crc16>\0
 *   >0,$,<len>,0001:8888:/echo\0j:{name:'yon',age:18,equip:['hat','shoes']}\0<crc16>\0
 *   >1,^,<len>,0001:8888:/he\0<crc16>\0
 *   >2,0,<len>,0001:8888:llo/y\0<crc16>\0
 *   >3,$,<len>,0001:8888:\0j:{name:'myu',age:12,equip:['gun','bomb']}\0<crc16>\0
 *
 * Response: <[0xseqno],[^|0|$],[0xlen],[0xsrcid]:[0xdstid]:[reqcrc16]:header\0[j|b|t]:data\0<crc16>\0
 *   <0,$,<len>,8888:0001:<crc16>:/echo\0j:{err:0,errmsg:'succ',data:{msg:'world'}}\0<crc16>\0
 *   <1,$,<len>,8888:0001:<crc16>:/hello/y\0j:{err:1,errmsg:'fail',data:{msg:'hell'}}\0<crc16>\0
 *
 * Data type: j:json, b:byte, t:txt
 *   >0,$,<len>,0001:8888:/echo\0j:{name:'yon',age:18,equip:['hat','shoes']}\0<crc16>\0
 *   >0,$,<len>,0001:8888:/echo\0b:{\0\1\2\3\4\5}\0<crc16>\0
 *   >0,$,<len>,0001:8888:/echo\0t:hello world!\0<crc16>\0
 *
 * Subscribe: #[0xseqno],[^|0|$],[0xlen]:[topic]\0j:{ctrl}\0<crc16>\0
 *   #0,$,0038:/motor/speed\0j:{ack:0,cache:100}\0<crc16>\0
 * ctrl:
 *   - ack: 0/1, if subscriber should acknology or not each msg
 *   - cahce: 0~1024, cache msg if subscriber offline
 *
 * UnSubscribe: %[0xseqno],[^|0|$],[0xlen]:[topic]\0j:{ctrl}\0<crc16>\0
 *   %0,$,0024:/motor/speed\0j:{}\0<crc16>\0
 *
 * Publish: @[0xseqno],[^|0|$],[0xlen]:[topic]\0[j|b|t]:{data}\0<crc16>\0
 *   @0,$,0043:/motor/speed\0j:{speed:12,voltage:24}\0<crc16>\0
 */

#define SRRP_CTRL_LEADER '='
#define SRRP_REQUEST_LEADER '>'
#define SRRP_RESPONSE_LEADER '<'
#define SRRP_SUBSCRIBE_LEADER '#'
#define SRRP_UNSUBSCRIBE_LEADER '%'
#define SRRP_PUBLISH_LEADER '@'

#define SRRP_BEGIN_PACKET '^'
#define SRRP_MID_PACKET '0'
#define SRRP_END_PACKET '$'
#define SRRP_NODEID_SUBFIX ':'
#define SRRP_HEADER_SUBFIX '\0'
#define SRRP_DATA_SUBFIX '\0'
#define SRRP_CRC16_SUBFIX '\0'

#define SRRP_CTRL_ONLINE "/online"
#define SRRP_CTRL_OFFLINE "/offline"

#define SRRP_SEQNO_HIGH 966
#define SRRP_LENGTH_MAX 4096
#define SRRP_SUBSCRIBE_CACHE_MAX 1024

struct srrp_packet {
    char leader;
    char seat;
    uint16_t seqno;
    uint16_t len;

    uint16_t srcid;
    uint16_t dstid;

    uint16_t reqcrc16; /* only used by response */
    uint16_t crc16;

    const char *header;
    uint32_t header_len;

    const char *data;
    uint32_t data_len;

    // where to store the payload
    char raw[0];
};

/**
 * srrp_free
 * - free packet created by srrp_parse & srrp_new_*
 */
void srrp_free(struct srrp_packet *pac);

/**
 * srrp_parse
 * - read one packet from buffer
 */
struct srrp_packet *srrp_parse(const char *buf);

/**
 * srrp_new_ctrl
 * - create new ctrl packet
 */
struct srrp_packet *
srrp_new_ctrl(uint16_t srcid, const char *header);

/**
 * srrp_new_request
 * - create new request packet
 */
struct srrp_packet *
srrp_new_request(uint16_t srcid, uint16_t dstid, const char *header, const char *data);

/**
 * srrp_new_response
 * - create new response packet
 */
struct srrp_packet *
srrp_new_response(uint16_t srcid, uint16_t dstid, uint16_t reqcrc16,
                  const char *header, const char *data);

/**
 * srrp_new_subscribe
 * - create new subscribe packet
 */
struct srrp_packet *
srrp_new_subscribe(const char *header, const char *ctrl);

/**
 * srrp_new_unsubscribe
 * - create new unsubscribe packet
 */
struct srrp_packet *
srrp_new_unsubscribe(const char *header, const char *ctrl);

/**
 * srrp_new_publish
 * - create new publish packet
 */
struct srrp_packet *
srrp_new_publish(const char *header, const char *data);

uint32_t srrp_next_packet_offset(const char *buf, uint32_t size);

#ifdef __cplusplus
}
#endif
#endif
