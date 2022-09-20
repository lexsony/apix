#ifndef __APIX_H
#define __APIX_H

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

struct apix;

struct apix *apix_new();
void apix_destroy(struct apix *ctx);

int /*fd*/ apix_open(struct apix *ctx, const char *id, const char *addr);
int apix_close(struct apix *ctx, int fd);
int apix_ioctl(struct apix *ctx, int fd, unsigned int cmd, unsigned long arg);
int apix_send(struct apix *ctx, int fd, const void *buf, size_t len);
int apix_recv(struct apix *ctx, int fd, void *buf, size_t size);

/*
 * pollin & pollout
 *   return 0: unhandled
 *   return n(>0): handled, and skip n bytes
 */

typedef int (*close_func_t)(int fd);
typedef int (*pollin_func_t)(int fd, const char *buf, size_t len);
typedef int (*pollout_func_t)(int fd, const char *buf, size_t len);

int apix_set_callback(struct apix *ctx, int fd,
                      close_func_t close,
                      pollin_func_t pollin,
                      /*not available yet*/pollout_func_t pollout);
int apix_poll(struct apix *ctx);

#ifdef __cplusplus
}
#endif
#endif
