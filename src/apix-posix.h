#ifndef __APIX_POSIX_H
#define __APIX_POSIX_H

#if defined __unix__ || __APPLE__

#include "types.h"

#ifdef __cplusplus
extern "C" {
#endif

#define SINK_UNIX_S    "sink_unix_s"
#define SINK_UNIX_C    "sink_unix_c"
#define SINK_TCP_S     "sink_tcp_s"
#define SINK_TCP_C     "sink_tcp_c"
#define SINK_UDP_S     "sink_udp_s"
#define SINK_UDP_C     "sink_udp_c"
#define SINK_COM       "sink_com"
#define SINK_CAN       "sink_can"
#define SINK_SPI       "sink_spi"
#define SINK_I2C       "sink_i2c"
#define SINK_PIPE      "sink_pipe"
#define SINK_SHM       "sink_shm"
#define SINK_SHM_MEMFD "sink_shm_memfd"
#define SINK_SHM_FTOK  "sink_shm_ftok"

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

#define apix_open_unix_server(ctx, addr) apix_open(ctx, SINK_UNIX_S, addr)
#define apix_open_unix_client(ctx, addr) apix_open(ctx, SINK_UNIX_C, addr)
#define apix_open_tcp_server(ctx, addr) apix_open(ctx, SINK_TCP_S, addr)
#define apix_open_tcp_client(ctx, addr) apix_open(ctx, SINK_TCP_C, addr)
#define apix_open_com(ctx, addr) apix_open(ctx, SINK_COM, addr)
#define apix_open_can(ctx, addr) apix_open(ctx, SINK_CAN, addr)

int apix_enable_posix(struct apix *ctx);
void apix_disable_posix(struct apix *ctx);

#ifdef __cplusplus
}
#endif
#endif
#endif
