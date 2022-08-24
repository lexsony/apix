#ifndef __APIX_H
#define __APIX_H

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

struct apibus;

struct apibus *apibus_new();
void apibus_destroy(struct apibus *bus);
int apibus_poll(struct apibus *bus);

int /*fd*/ apibus_open(struct apibus *bus, const char *name, const char *addr);
int apibus_close(struct apibus *bus, int fd);
int apibus_ioctl(struct apibus *bus, int fd, unsigned int cmd, unsigned long arg);
int apibus_send(struct apibus *bus, int fd, const void *buf, size_t len);
int apibus_recv(struct apibus *bus, int fd, void *buf, size_t size);

#ifdef __cplusplus
}
#endif
#endif
