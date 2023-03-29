#ifndef _CRC_CRC16_H
#define _CRC_CRC16_H

#include "types.h"

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus  */

u16 crc16(const u8 *buf, int len);
u16 crc16_crc(u16 crc, const u8 *buf, int len);

#ifdef __cplusplus
}
#endif /* __cplusplus  */
#endif
