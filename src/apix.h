#ifndef __APIX_H
#define __APIX_H

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

struct apix;

struct apix *apix_new();
void apix_destroy(struct apix *ctx);
int apix_poll(struct apix *ctx);

int /*fd*/ apix_open(struct apix *ctx, const char *name, const char *addr);
int apix_close(struct apix *ctx, int fd);
int apix_ioctl(struct apix *ctx, int fd, unsigned int cmd, unsigned long arg);
int apix_send(struct apix *ctx, int fd, const void *buf, size_t len);
int apix_recv(struct apix *ctx, int fd, void *buf, size_t size);

#ifdef __cplusplus
}
#endif
#endif
