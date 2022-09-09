#ifndef __RINGBUF_H
#define __RINGBUF_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define RINGBUF_DEFAULT_SIZE 4096

typedef struct ringbuf ringbuf_t;

ringbuf_t *ringbuf_new(size_t size);
void ringbuf_delete(ringbuf_t *self);

size_t ringbuf_size(ringbuf_t *self);
size_t ringbuf_used(ringbuf_t *self);
size_t ringbuf_spare(ringbuf_t *self);
size_t ringbuf_spare_right(ringbuf_t *self);
size_t ringbuf_spare_left(ringbuf_t *self);

char *ringbuf_write_pos(ringbuf_t *self);
char *ringbuf_read_pos(ringbuf_t *self);

void ringbuf_write_advance(ringbuf_t *self, size_t len);
void ringbuf_read_advance(ringbuf_t *self, size_t len);

size_t ringbuf_write(ringbuf_t *self, const void *ptr, size_t len);
size_t ringbuf_write_byte(ringbuf_t *self, uint8_t byte);
size_t ringbuf_peek(ringbuf_t *self, void *ptr, size_t size);
size_t ringbuf_read(ringbuf_t *self, void *ptr, size_t size);
size_t ringbuf_read_byte(ringbuf_t *self, uint8_t byte);

#ifdef __cplusplus
}
#endif
#endif
