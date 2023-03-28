#ifndef __APIX_H
#define __APIX_H

#include <stdint.h>
#include "srrp.h"

#if defined __arm__ && !defined __unix__
    #include "apix-stm32.h"
#elif defined __unix__ || __APPLE__
    #include "apix-posix.h"
#else
    #error unknown platform
#endif

#ifdef __cplusplus
extern "C" {
#endif

struct apix;

enum apix_event {
    AEC_NONE = 0,
    AEC_OPEN,
    AEC_CLOSE,
    AEC_ACCEPT,
    AEC_POLLIN,
    AEC_SRRP_PACKET,
};

/**
 * apix_new
 */
struct apix *apix_new();

/**
 * apix_drop
 */
void apix_drop(struct apix *ctx);

/**
 * apix_open
 * - return the file descriptor(fd) from system
 * - never call fctrl or setsockopt inner, so the state of fd is default
 */
int apix_open(struct apix *ctx, const char *sinkid, const char *addr);

/**
 * apix_close
 * - inner call the close systemcall
 */
int apix_close(struct apix *ctx, int fd);

/**
 * apix_ioctl
 * - inner call the ioctl systemcall
 */
int apix_ioctl(struct apix *ctx, int fd, unsigned int cmd, unsigned long arg);

/**
 * apix_send
 * - inner call send or write in blocking-mode
 * - set MSG_NOSIGNAL
 * - not set O_NONBLOCK by fctrl
 */
int apix_send(struct apix *ctx, int fd, const uint8_t *buf, uint32_t len);

/**
 * apix_recv
 * - inner call recv or write in blocking-mode
 * - not set O_NONBLOCK by fctrl
 */
int apix_recv(struct apix *ctx, int fd, uint8_t *buf, uint32_t len);

/**
 * apix_send_to_buffer
 * - a nonblocking-mode send
 */
int apix_send_to_buffer(struct apix *ctx, int fd, const uint8_t *buf, uint32_t len);

/**
 * apix_read_from_buffer
 * - call this func after poll if not set on_fd_pollin and not in srrpmode,
 * - as the inner rx buffer has no chance to reduce.
 */
int apix_read_from_buffer(struct apix *ctx, int fd, uint8_t *buf, uint32_t len);

/**
 * apix_get_fd_father
 */
int apix_get_fd_father(struct apix *ctx, int fd);

/**
 * apix_waiting
 */
int apix_waiting(struct apix *ctx, uint64_t usec);

/**
 * apix_next_event
 */
uint8_t apix_next_event(struct apix *ctx, int fd);

/**
 * apix_next_srrp_packet
 */
struct srrp_packet *apix_next_srrp_packet(struct apix *ctx, int fd);

/**
 * apix_upgrade_to_srrp
 * - enable srrp mode
 */
int apix_upgrade_to_srrp(struct apix *ctx, int fd, uint32_t nodeid);

/**
 * apix_srrp_forward
 * - forward the srrp packet to the real destination through dstid
 */
void apix_srrp_forward(struct apix *ctx, int fd, struct srrp_packet *pac);

/**
 * apix_srrp_send
 * - send the srrp packet to the src fd and real destination through dstid
 */
int apix_srrp_send(struct apix *ctx, int fd, struct srrp_packet *pac);

#ifdef __cplusplus
}
#endif
#endif
