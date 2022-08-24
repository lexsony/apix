#ifndef __APIX_POSIX_H
#define __APIX_POSIX_H

#if defined __arm__ && !defined __unix__

#include "apix.h"
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define APISINK_STM32_TCP    "apisink_stm32_tcp"
#define APISINK_STM32_UDP    "apisink_stm32_udp"
#define APISINK_STM32_SERIAL "apisink_stm32_serial"
#define APISINK_STM32_CAN    "apisink_stm32_can"
#define APISINK_STM32_SPI    "apisink_stm32_spi"
#define APISINK_STM32_I2C    "apisink_stm32_i2c"

#define SERIAL_ARG_BAUD_9600 9600
#define SERIAL_ARG_BAUD_115200 115200
#define SERIAL_ARG_BITS_7 7
#define SERIAL_ARG_BITS_8 8
#define SERIAL_ARG_PARITY_O 'O'
#define SERIAL_ARG_PARITY_E 'E'
#define SERIAL_ARG_PARITY_N 'N'
#define SERIAL_ARG_STOP_1 1
#define SERIAL_ARG_STOP_2 2

struct ioctl_serial_param {
    uint32_t baud;
    char bits;
    char parity;
    char stop;
};

#define apibus_open_stm32_tcp(bus, addr) \
    apibus_open(bus, APISINK_STM32_TCP, addr)
#define apibus_open_stm32_serial(bus, addr) \
    apibus_open(bus, APISINK_STM32_SERIAL, addr)

int apibus_enable_stm32(struct apibus *bus);
void apibus_disable_stm32(struct apibus *bus);

#ifdef __cplusplus
}
#endif
#endif
#endif
