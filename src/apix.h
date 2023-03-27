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

/**
 * apix init & fini
 */

struct apix *apix_new();
void apix_destroy(struct apix *ctx);

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
 * apix is designed with poll mechanism
 * - usec: if > 0, sleelp usec while idle. if = 0, sleep less than 1s while idle
 */
int apix_poll(struct apix *ctx, uint64_t usec);

/**
 * apix_on_fd_close
 * - called after fd is closed
 */
typedef void (*fd_close_func_t)(struct apix *ctx, int fd, void *priv);
int apix_on_fd_close(struct apix *ctx, int fd, fd_close_func_t func, void *priv);

/**
 * apix_on_fd_accept
 * - called after newfd is accepted
 */
typedef void (*fd_accept_func_t)(
    struct apix *ctx, int fd, int newfd, void *priv);
int apix_on_fd_accept(struct apix *ctx, int fd, fd_accept_func_t func, void *priv);

/**
 * apix_on_fd_pollin
 * - called during apix_poll when rxbuf of fd is not empty
 * - return n(<=-1): unhandled
 * - return n(>=0): handled, and skip n bytes
 */
typedef int (*fd_pollin_func_t)(
    struct apix *ctx, int fd, const uint8_t *buf, uint32_t len, void *priv);
int apix_on_fd_pollin(struct apix *ctx, int fd, fd_pollin_func_t func, void *priv);

/**
 * apix_enable_srrp_mode
 * - enable srrp mode
 */
int apix_enable_srrp_mode(struct apix *ctx, int fd, uint32_t nodeid);

/**
 * apix_enable_srrp_mode
 * - enable srrp mode
 */
int apix_disable_srrp_mode(struct apix *ctx, int fd);

/**
 * apix_srrp_forward
 * - forward the srrp packet to the real destination through dstid
 */
void apix_srrp_forward(struct apix *ctx, struct srrp_packet *pac);

/**
 * apix_srrp_send
 * - send the srrp packet to the src fd and real destination through dstid
 */
int apix_srrp_send(struct apix *ctx, int fd, struct srrp_packet *pac);

/**
 * apix_on_srrp_packet
 * - called when received srrp packets
 */
typedef void (*srrp_packet_func_t)(
    struct apix *ctx, int fd, struct srrp_packet *pac, void *priv);
int apix_on_srrp_packet(
    struct apix *ctx, int fd, srrp_packet_func_t func, void *priv);

#ifdef __cplusplus
}
#endif
#endif
