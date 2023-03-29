#ifndef __APIX_POSIX_H
#define __APIX_POSIX_H

#if defined __unix__ || __APPLE__

#include "types.h"

#ifdef __cplusplus
extern "C" {
#endif

#define APISINK_UNIX_S    "apisink_unix_s"
#define APISINK_UNIX_C    "apisink_unix_c"
#define APISINK_TCP_S     "apisink_tcp_s"
#define APISINK_TCP_C     "apisink_tcp_c"
#define APISINK_UDP_S     "apisink_udp_s"
#define APISINK_UDP_C     "apisink_udp_c"
#define APISINK_COM       "apisink_com"
#define APISINK_CAN       "apisink_can"
#define APISINK_SPI       "apisink_spi"
#define APISINK_I2C       "apisink_i2c"
#define APISINK_PIPE      "apisink_pipe"
#define APISINK_SHM       "apisink_shm"
#define APISINK_SHM_MEMFD "apisink_shm_memfd"
#define APISINK_SHM_FTOK  "apisink_shm_ftok"

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
    u32 baud;
    char bits;
    char parity;
    char stop;
};

#define apix_open_unix_server(ctx, addr) apix_open(ctx, APISINK_UNIX_S, addr)
#define apix_open_unix_client(ctx, addr) apix_open(ctx, APISINK_UNIX_C, addr)
#define apix_open_tcp_server(ctx, addr) apix_open(ctx, APISINK_TCP_S, addr)
#define apix_open_tcp_client(ctx, addr) apix_open(ctx, APISINK_TCP_C, addr)
#define apix_open_com(ctx, addr) apix_open(ctx, APISINK_COM, addr)
#define apix_open_can(ctx, addr) apix_open(ctx, APISINK_CAN, addr)

int apix_enable_posix(struct apix *ctx);
void apix_disable_posix(struct apix *ctx);

#ifdef __cplusplus
}
#endif
#endif
#endif
