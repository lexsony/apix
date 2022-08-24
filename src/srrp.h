#ifndef __SRRP_H // simple request response protocol
#define __SRRP_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Request: >[0xseqno],[^|0|$],[0xlenth],[0xsrcid]:[/dstid/header]?{data}\0<crc16>\0
 *   >0,$,<len>,0001:/8888/echo?{name:'yon',age:18,equip:['hat','shoes']}\0<crc16>\0
 *   >1,^,<len>,0001:/8888/he\0<crc16>\0
 *   >2,0,<len>,0001:llo/y\0<crc16>\0
 *   >3,$,<len>,0001:?{name:'myu',age:12,equip:['gun','bomb']}\0<crc16>\0
 *
 * Response: <[0xseqno],[^|0|$],[0xlenth],[0xsrcid],[reqcrc16]:[/dstid/header]?{data}\0<crc16>\0
 *   <0,$,<len>,0001,<crc16>:/8888/echo?{err:0,errmsg:'succ',data:{msg:'world'}}\0<crc16>\0
 *   <1,$,<len>,0001,<crc16>:/8888/hello/y?{err:1,errmsg:'fail',data:{msg:'hell'}}\0<crc16>\0
 *
 * Subscribe: #[0xseqno],[^|0|$],[0xlenth]:[topic]?{ctrl}\0<crc16>\0
 *   #0,$,0038:/motor/speed?{ack:0,cache:100}\0<crc16>\0
 * ctrl:
 *   - ack: 0/1, if subscriber should acknology or not each msg
 *   - cahce: 0~1024, cache msg if subscriber offline
 *
 * UnSubscribe: %[0xseqno],[^|0|$],[0xlenth]:[topic]?{}\0<crc16>\0
 *   %0,$,0024:/motor/speed?{}\0<crc16>\0
 *
 * Publish: @[0xseqno],[^|0|$],[0xlenth]:[topic]?{data}\0<crc16>\0
 *   @0,$,0043:/motor/speed?{speed:12,voltage:24}\0<crc16>\0
 */

#define SRRP_REQUEST_LEADER '>'
#define SRRP_RESPONSE_LEADER '<'
#define SRRP_SUBSCRIBE_LEADER '#'
#define SRRP_UNSUBSCRIBE_LEADER '%'
#define SRRP_PUBLISH_LEADER '@'

#define SRRP_BEGIN_PACKET '^'
#define SRRP_MID_PACKET '0'
#define SRRP_END_PACKET '$'
#define SRRP_HEADER_DELIMITER ':'
#define SRRP_DATA_DELIMITER '?'

#define SRRP_HEADER_LEN 128
#define SRRP_SEQNO_HIGH 966
#define SRRP_LENGTH_MAX 4096
#define SRRP_SUBSCRIBE_CACHE_MAX 1024

struct srrp_packet {
    char leader;
    char seat;
    uint16_t seqno;
    uint16_t len;
    uint16_t srcid; // request from srcid, response to srcid
    uint16_t reqcrc16; // reqcrc16 when leader is '<'
    const char header[SRRP_HEADER_LEN]; // include dstid
    uint32_t header_len;
    const char *data;
    uint32_t data_len;
    char raw[0]; // alloc length = sizeof(struct srrp_packet) + strlen(raw)
};

void srrp_free(struct srrp_packet *pac);

// the retval imply that the caller should free it

struct srrp_packet *
srrp_read_one_packet(const char *buf);

struct srrp_packet *
srrp_write_request(uint16_t sttid, const char *header, const char *data);

struct srrp_packet *
srrp_write_response(uint16_t sttid, uint16_t reqcrc16, const char *header, const char *data);

struct srrp_packet *
srrp_write_subscribe(const char *header, const char *ctrl);

struct srrp_packet *
srrp_write_unsubscribe(const char *header);

struct srrp_packet *
srrp_write_publish(const char *header, const char *data);

int srrp_next_packet_offset(const char *buf);

#ifdef __cplusplus
}
#endif
#endif
