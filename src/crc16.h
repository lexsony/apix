#ifndef _CRC_CRC16_H
#define _CRC_CRC16_H

#include <stdint.h>
#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus  */

uint16_t crc16(const uint8_t *buf, int len);
uint16_t crc16_crc(uint16_t crc, const uint8_t *buf, int len);

#ifdef __cplusplus
}
#endif /* __cplusplus  */
#endif
