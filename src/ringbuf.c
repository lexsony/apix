#include "ringbuf.h"
#include <assert.h>
#include <string.h>
#include <stdlib.h>

struct ringbuf {
    char *rawbuf;
    size_t size;
    size_t offset_in;
    size_t offset_out;
};

ringbuf_t *ringbuf_new(size_t size)
{
    if (size == 0)
        size = RINGBUF_DEFAULT_SIZE;

    ringbuf_t *self = (ringbuf_t*)calloc(sizeof(ringbuf_t), 1);
    if (!self) return NULL;

    self->rawbuf = (char*)calloc(size, 1);
    if (!self->rawbuf) {
        free(self);
        return NULL;
    }

    self->size = size;
    self->offset_in = 0;
    self->offset_out = 0;

    return self;
}

void ringbuf_delete(ringbuf_t *self)
{
    if (self) {
        free(self->rawbuf);
        free(self);
    }
}

size_t ringbuf_size(ringbuf_t *self)
{
    return self->size;
}

size_t ringbuf_used(ringbuf_t *self)
{
    if (self->offset_in >= self->offset_out)
        return self->offset_in - self->offset_out;
    else
        return self->offset_in + (self->size - self->offset_out);
}

size_t ringbuf_spare(ringbuf_t *self)
{
    return self->size - ringbuf_used(self);
}

size_t ringbuf_spare_right(ringbuf_t *self)
{
    if (self->offset_in < self->offset_out)
        return 0;
    else
        return self->size - self->offset_in;
}

size_t ringbuf_spare_left(ringbuf_t *self)
{
    return ringbuf_spare(self) - ringbuf_spare_right(self);
}

char *ringbuf_write_pos(ringbuf_t *self)
{
    return self->rawbuf + self->offset_in;
}

char *ringbuf_read_pos(ringbuf_t *self)
{
    return self->rawbuf + self->offset_out;
}

void ringbuf_write_advance(ringbuf_t *self, size_t len)
{
    assert(ringbuf_spare(self) >= len);
    self->offset_in = (self->offset_in + len) % self->size;
}

void ringbuf_read_advance(ringbuf_t *self, size_t len)
{
    assert(ringbuf_used(self) >= len);
    self->offset_out = (self->offset_out + len) % self->size;
}

size_t ringbuf_write(ringbuf_t *self, const void *ptr, size_t len)
{
    assert(len < self->size);
    size_t cpy_cnt = 0;

    if (self->offset_in >= self->offset_out) {
        size_t spare_right = self->size - self->offset_in;
        size_t spare_left = self->offset_out;
        if (len <= spare_right) {
            memcpy(ringbuf_write_pos(self), ptr, len);
            cpy_cnt += len;
        } else {
            memcpy(ringbuf_write_pos(self), ptr, spare_right);
            cpy_cnt += spare_right;
            if (len - spare_right <= spare_left) {
                memcpy(self->rawbuf, ptr + cpy_cnt, len - spare_right);
                cpy_cnt += len - spare_right;
            } else {
                memcpy(self->rawbuf, ptr + cpy_cnt, spare_left);
                cpy_cnt += spare_left;
            }
        }
    } else {
        size_t spare = self->offset_out - self->offset_in;
        if (len <= spare) {
            memcpy(ringbuf_write_pos(self), ptr, len);
            cpy_cnt += len;
        } else {
            memcpy(ringbuf_write_pos(self), ptr, spare);
            cpy_cnt += spare;
        }
    }

    ringbuf_write_advance(self, cpy_cnt);
    return cpy_cnt;
}

size_t ringbuf_peek(ringbuf_t *self, void *ptr, size_t size)
{
    size_t cpy_cnt = ringbuf_used(self);
    if (size < cpy_cnt)
        cpy_cnt = size;

    if (self->offset_in >= self->offset_out) {
        memcpy(ptr, ringbuf_read_pos(self), cpy_cnt);
    }
    else {
        size_t cpy_right = self->size - self->offset_out;
        size_t cpy_left = cpy_cnt - cpy_right;
        memcpy(ptr, ringbuf_read_pos(self), cpy_right);
        memcpy(ptr + cpy_right, self->rawbuf, cpy_left);
    }

    return cpy_cnt;
}

size_t ringbuf_read(ringbuf_t *self, void *ptr, size_t size)
{
    size_t cpy_cnt = ringbuf_peek(self, ptr, size);
    ringbuf_read_advance(self, cpy_cnt);
    return cpy_cnt;
}
