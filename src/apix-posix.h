#ifndef __APIX_POSIX_H
#define __APIX_POSIX_H

#if defined __unix__ || defined __linux__ || defined __APPLE__

#include <stdint.h>
#include "apix.h"

#ifdef __cplusplus
extern "C" {
#endif

#define APISINK_UNIX      "apisink_unix"
#define APISINK_TCP       "apisink_tcp"
#define APISINK_UDP       "apisink_udp"
#define APISINK_SERIAL    "apisink_serial"
#define APISINK_CAN       "apisink_can"
#define APISINK_SPI       "apisink_spi"
#define APISINK_I2C       "apisink_i2c"
#define APISINK_PIPE      "apisink_pipe"
#define APISINK_SHM       "apisink_shm"
#define APISINK_SHM_MEMFD "apisink_shm_memfd"
#define APISINK_SHM_FTOK  "apisink_shm_ftok"

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

#define apix_open_unix(ctx, addr) \
    apix_open(ctx, APISINK_UNIX, addr)
#define apix_open_tcp(ctx, addr) \
    apix_open(ctx, APISINK_TCP, addr)
#define apix_open_serial(ctx, addr) \
    apix_open(ctx, APISINK_SERIAL, addr)

int apix_enable_posix(struct apix *ctx);
void apix_disable_posix(struct apix *ctx);

#ifdef __cplusplus
}
#endif
#endif
#endif
