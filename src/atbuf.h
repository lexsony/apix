#ifndef __ATBUF_H
#define __ATBUF_H

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

#define ATBUF_DEFAULT_SIZE 1024

typedef struct atbuf atbuf_t;

atbuf_t *atbuf_new(size_t size);
void atbuf_delete(atbuf_t *self);
int atbuf_realloc(atbuf_t *self, size_t len);

char *atbuf_read_pos(atbuf_t *self);
char *atbuf_write_pos(atbuf_t *self);
size_t atbuf_read_advance(atbuf_t *self, size_t len);
size_t atbuf_write_advance(atbuf_t *self, size_t len);

size_t atbuf_size(atbuf_t *self);
size_t atbuf_garbage(atbuf_t *self);
size_t atbuf_used(atbuf_t *self);
size_t atbuf_spare(atbuf_t *self);
size_t atbuf_tidy(atbuf_t *self);
void atbuf_clear(atbuf_t *self);

size_t atbuf_peek(atbuf_t *self, void *ptr, size_t len);
size_t atbuf_read(atbuf_t *self, void *ptr, size_t len);
size_t atbuf_write(atbuf_t *self, const void *ptr, size_t len);

#ifdef __cplusplus
}
#endif

#endif
