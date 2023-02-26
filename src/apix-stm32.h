#ifndef __APIX_STM32_H
#define __APIX_STM32_H

#if defined __arm__ && !defined __unix__

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define APISINK_STM32_TCP_S  "apisink_stm32_tcp_s"
#define APISINK_STM32_TCP_C  "apisink_stm32_tcp_c"
#define APISINK_STM32_UDP_S  "apisink_stm32_udp_s"
#define APISINK_STM32_UDP_C  "apisink_stm32_udp_c"
#define APISINK_STM32_COM    "apisink_stm32_com"
#define APISINK_STM32_CAN    "apisink_stm32_can"
#define APISINK_STM32_SPI    "apisink_stm32_spi"
#define APISINK_STM32_I2C    "apisink_stm32_i2c"

#define COM_ARG_BAUD_9600 9600
#define COM_ARG_BAUD_115200 115200
#define COM_ARG_BITS_7 7
#define COM_ARG_BITS_8 8
#define COM_ARG_PARITY_O 'O'
#define COM_ARG_PARITY_E 'E'
#define COM_ARG_PARITY_N 'N'
#define COM_ARG_STOP_1 1
#define COM_ARG_STOP_2 2

struct apix;

struct ioctl_com_param {
    uint32_t baud;
    char bits;
    char parity;
    char stop;
};

#define apix_open_stm32_tcp_server(ctx, addr) \
    apix_open(ctx, APISINK_STM32_TCP_S, addr)
#define apix_open_stm32_tcp_client(ctx, addr) \
    apix_open(ctx, APISINK_STM32_TCP_C, addr)
#define apix_open_stm32_com(ctx, addr) \
    apix_open(ctx, APISINK_STM32_COM, addr)

int apix_enable_stm32(struct apix *ctx);
void apix_disable_stm32(struct apix *ctx);

#ifdef __cplusplus
}
#endif
#endif
#endif
