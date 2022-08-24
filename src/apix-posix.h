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

#define apibus_open_unix(bus, addr) \
    apibus_open(bus, APISINK_UNIX, addr)
#define apibus_open_tcp(bus, addr) \
    apibus_open(bus, APISINK_TCP, addr)
#define apibus_open_serial(bus, addr) \
    apibus_open(bus, APISINK_SERIAL, addr)

int apibus_enable_posix(struct apibus *bus);
void apibus_disable_posix(struct apibus *bus);

#ifdef __cplusplus
}
#endif
#endif
#endif
