#ifndef __APIX_H
#define __APIX_H

#include "types.h"
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
struct stream;

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
struct stream *
apix_open(struct apix *ctx, const char *sinkid, const char *addr);

/**
 * apix_close
 * - inner call the close systemcall
 */
int apix_close(struct stream *stream);

/**
 * apix_accept
 * - inner call the accept systemcall
 */
struct stream *apix_accept(struct stream *stream);

/**
 * apix_ioctl
 * - inner call the ioctl systemcall
 */
int apix_ioctl(struct stream *stream, unsigned int cmd, unsigned long arg);

/**
 * apix_send
 * - inner call send or write in blocking-mode
 * - set MSG_NOSIGNAL
 * - not set O_NONBLOCK by fctrl
 */
int apix_send(struct stream *stream, const u8 *buf, u32 len);

/**
 * apix_recv
 * - inner call recv or write in blocking-mode
 * - not set O_NONBLOCK by fctrl
 */
int apix_recv(struct stream *stream, u8 *buf, u32 len);

/**
 * apix_send_to_buffer
 * - a nonblocking-mode send
 */
int apix_send_to_buffer(struct stream *stream, const u8 *buf, u32 len);

/**
 * apix_read_from_buffer
 * - call this func after poll if not set on_fd_pollin and not in srrpmode,
 * - as the inner rx buffer has no chance to reduce.
 */
int apix_read_from_buffer(struct stream *stream, u8 *buf, u32 len);

/**
 * apix_get_raw_fd
 */
int apix_get_raw_fd(struct stream *stream);

/**
 * apix_set_wait_timeout
 * - usec: 0 => no timeout, apix_wait_* return immediately
 */
void apix_set_wait_timeout(struct apix *ctx, u64 usec);

/**
 * apix_wait_stream
 */
struct stream *apix_wait_stream(struct apix *ctx);

/**
 * apix_wait_event
 */
u8 apix_wait_event(struct stream *stream);

/**
 * apix_wait_srrp_packet
 */
struct srrp_packet *apix_wait_srrp_packet(struct stream *stream);

/**
 * apix_upgrade_to_srrp
 * - enable srrp mode
 */
int apix_upgrade_to_srrp(struct stream *stream, const char *nodeid);

/**
 * apix_srrp_forward
 * - forward the srrp packet to the real destination through dstid
 */
void apix_srrp_forward(struct stream *stream, struct srrp_packet *pac);

/**
 * apix_srrp_send
 * - send the srrp packet to the src fd and real destination through dstid
 */
int apix_srrp_send(struct stream *stream, struct srrp_packet *pac);

#ifdef __cplusplus
}
#endif
#endif
