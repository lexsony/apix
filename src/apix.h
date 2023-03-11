#ifndef __APIX_H
#define __APIX_H

#include <stddef.h>
#include "srrp.h"

#if defined __arm__ && !defined __unix__
    #include "apix-stm32.h"
#elif defined __unix__
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
 * apix set & get for private data
 */
void apix_set_private(struct apix *ctx, void *private_data);
void *apix_get_private(struct apix *ctx);

/**
 * apix fd operations
 * - treat it as UNIX style fd operations
 */

int /*fd*/ apix_open(struct apix *ctx, const char *sinkid, const char *addr);
int apix_close(struct apix *ctx, int fd);
int apix_ioctl(struct apix *ctx, int fd, unsigned int cmd, unsigned long arg);
int apix_send(struct apix *ctx, int fd, const void *buf, size_t len);
int apix_recv(struct apix *ctx, int fd, void *buf, size_t size);

/**
 * apix is designed with poll mechanism
 */
int apix_poll(struct apix *ctx);

/**
 * apix_on_fd_close
 * - called after fd is closed
 */
typedef void (*fd_close_func_t)(struct apix *ctx, int fd);
int apix_on_fd_close(struct apix *ctx, int fd, fd_close_func_t func);

/**
 * apix_on_fd_accept
 * - called after newfd is accepted
 */
typedef void (*fd_accept_func_t)(
    struct apix *ctx, int fd, int newfd);
int apix_on_fd_accept(struct apix *ctx, int fd, fd_accept_func_t func);

/**
 * apix_on_fd_pollin
 * - called during apix_poll when rxbuf of fd is not empty
 * - return n(<=-1): unhandled
 * - return n(>=0): handled, and skip n bytes
 */
typedef int (*fd_pollin_func_t)(
    struct apix *ctx, int fd, const void *buf, size_t len);
int apix_on_fd_pollin(struct apix *ctx, int fd, fd_pollin_func_t func);

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
 * apix_on_srrp_request
 * - called when received srrp requests
 */
typedef void (*srrp_request_func_t)(
    struct apix *ctx, int fd, struct srrp_packet *req, struct srrp_packet **resp);
int apix_on_srrp_request(struct apix *ctx, int fd, srrp_request_func_t func);

/**
 * apix_on_srrp_response
 * - called when received srrp responses
 */
typedef void (*srrp_response_func_t)(
    struct apix *ctx, int fd, struct srrp_packet *resp);
int apix_on_srrp_response(struct apix *ctx, int fd, srrp_response_func_t func);

#ifdef __cplusplus
}
#endif
#endif
