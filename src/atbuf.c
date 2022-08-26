#include "atbuf.h"
#include <stdlib.h>
#include <string.h>
#include <assert.h>

struct atbuf {
    char *rawbuf;
    size_t size;
    size_t offset_in;
    size_t offset_out;
};

atbuf_t *atbuf_new(size_t size)
{
    if (size == 0)
        size = ATBUF_DEFAULT_SIZE;

    atbuf_t *self = (atbuf_t*)calloc(sizeof(atbuf_t), 1);
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

void atbuf_delete(atbuf_t *self)
{
    if (self) {
        free(self->rawbuf);
        free(self);
    }
}

int atbuf_realloc(atbuf_t *self, size_t len)
{
    void *newbuf = realloc(self->rawbuf, len);
    if (newbuf) {
        self->rawbuf = newbuf;
        self->size = len;
        return 0;
    } else {
        return -1;
    }
}

char *atbuf_read_pos(atbuf_t *self)
{
    return self->rawbuf + self->offset_out;
}

char *atbuf_write_pos(atbuf_t *self)
{
    return self->rawbuf + self->offset_in;
}

size_t atbuf_read_advance(atbuf_t *self, size_t len)
{
    //assert(self->offset_out + len <= self->offset_in);
    if (self->offset_out + len > self->offset_in)
        self->offset_out = self->offset_in;
    else
        self->offset_out += len;
    atbuf_tidy(self);
    return atbuf_used(self);
}

size_t atbuf_write_advance(atbuf_t *self, size_t len)
{
    assert(self->offset_in + len < self->size);
    self->offset_in += len;
    atbuf_tidy(self);
    return atbuf_spare(self);
}

size_t atbuf_size(atbuf_t *self)
{
    return self->size;
}

size_t atbuf_garbage(atbuf_t *self)
{
    return self->offset_out;
}

size_t atbuf_used(atbuf_t *self)
{
    return self->offset_in - self->offset_out;
}

size_t atbuf_spare(atbuf_t *self)
{
    return self->size - self->offset_in;
}

size_t atbuf_tidy(atbuf_t *self)
{
    if (atbuf_used(self) == 0) {
        self->offset_in = self->offset_out = 0;
    } else if (atbuf_spare(self) < self->size>>2 ||
               atbuf_garbage(self) > self->size>>2) {
        /* method 1
        self->offset_in -= self->offset_out;
        memmove(self->rawbuf, atbuf_read_pos(self), self->offset_in);
        self->offset_out = 0;
        */
        memmove(self->rawbuf, atbuf_read_pos(self), atbuf_used(self));
        self->offset_in = atbuf_used(self);
        self->offset_out = 0;
    }

    self->rawbuf[self->offset_in] = 0;
    return atbuf_spare(self);
}

void atbuf_clear(atbuf_t *self)
{
    self->offset_in = 0;
    self->offset_out = 0;
    self->rawbuf[0] = 0;
}

size_t atbuf_peek(atbuf_t *self, void *ptr, size_t len)
{
    size_t len_can_out = len <= atbuf_used(self) ? len : atbuf_used(self);
    memcpy(ptr, atbuf_read_pos(self), len_can_out);
    return len_can_out;
}

size_t atbuf_read(atbuf_t *self, void *ptr, size_t len)
{
    int nread = atbuf_peek(self, ptr, len);
    atbuf_read_advance(self, nread);
    return nread;
}

size_t atbuf_write(atbuf_t *self, const void *ptr, size_t len)
{
    if (len > atbuf_spare(self)) {
        atbuf_tidy(self);
        atbuf_realloc(self, self->size > len ? self->size<<1 : len<<1);
    }

    size_t len_can_in = len <= atbuf_spare(self) ? len : atbuf_spare(self);
    memcpy(atbuf_write_pos(self), ptr, len_can_in);
    atbuf_write_advance(self, len_can_in);

    return len_can_in;
}
