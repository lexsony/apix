#ifndef __APIX_H
#define __APIX_H

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

struct apix;

/**
 * apix is designed with poll mechanism
 */

struct apix *apix_new();
void apix_destroy(struct apix *ctx);
int apix_poll(struct apix *ctx);

/**
 * apix fd operations
 * - use it in UNIX style
 */

int /*fd*/ apix_open(struct apix *ctx, const char *id, const char *addr);
int apix_close(struct apix *ctx, int fd);
int apix_ioctl(struct apix *ctx, int fd, unsigned int cmd, unsigned long arg);
int apix_send(struct apix *ctx, int fd, const void *buf, size_t len);
int apix_recv(struct apix *ctx, int fd, void *buf, size_t size);

/**
 * apix events
 * - call same setting function twice will cause assert fail
 */

typedef int (*fd_close_func_t)(int fd);
int apix_on_fd_close(struct apix *ctx, int fd, fd_close_func_t func);

typedef int (*fd_accept_func_t)(int fd, int newfd);
int apix_on_fd_accept(struct apix *ctx, int fd, fd_accept_func_t func);

/**
 * pollin & pollout
 * - return 0: unhandled
 * - return n(>0): handled, and skip n bytes
 */

typedef int (*fd_pollin_func_t)(int fd, const char *buf, size_t len);
int apix_on_fd_pollin(struct apix *ctx, int fd, fd_pollin_func_t func);

typedef int (*fd_pollout_func_t)(int fd, const char *buf, size_t len);
int apix_on_fd_pollout(struct apix *ctx, int fd, fd_pollout_func_t func);

#ifdef __cplusplus
}
#endif
#endif
