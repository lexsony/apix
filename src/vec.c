#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include "vec.h"

struct vec {
    char *rawbuf;
    uint32_t type_size;
    uint32_t size;
    uint32_t cap;
    enum vec_alloc_type alloc_type;
    uint32_t offset;
};

vec_t *vec_new(uint32_t type_size, uint32_t cap)
{
    return vec_new_alloc(type_size, cap, VEC_ALLOC_LINEAR);
}

vec_t *vec_new_alloc(uint32_t type_size, uint32_t cap, enum vec_alloc_type alloc)
{
    vec_t *self = (vec_t*)calloc(1, sizeof(vec_t));
    if (!self) return NULL;

    if (cap == 0)
        self->rawbuf = (char*)calloc(type_size, VEC_DEFAULT_CAP);
    else
        self->rawbuf = (char*)calloc(type_size, cap);
    if (!self->rawbuf) {
        free(self);
        return NULL;
    }

    self->type_size = type_size;
    self->size = 0;
    self->cap = cap;
    self->alloc_type = alloc;
    self->offset = 0;

    return self;
}

void vec_delete(vec_t *self)
{
    if (self) {
        free(self->rawbuf);
        free(self);
    }
}

static int vec_realloc(vec_t *self, uint32_t new_cap)
{
    void *newbuf = realloc(self->rawbuf, new_cap * self->type_size);
    if (newbuf) {
        self->rawbuf = newbuf;
        self->cap = new_cap;
        return 0;
    } else {
        return -1;
    }
}

static int vec_check_cap(vec_t *self, uint32_t cnt)
{
    if (self->offset + self->size + cnt > self->cap) {
        if (self->offset) {
            void *offset = self->rawbuf + self->offset * self->type_size;
            memmove(self->rawbuf, offset, self->size * self->type_size);
            self->offset = 0;
        }
        if (self->offset + self->size + cnt > self->cap) {
            uint32_t new_cap = (self->cap + cnt) << 1;
            return vec_realloc(self, new_cap);
        }
    }
    return 0;
}

void vpush(vec_t *self, const void *value)
{
    assert(vec_check_cap(self, 1) == 0);

    void *offset = self->rawbuf + (self->offset + self->size) * self->type_size;
    memcpy(offset, value, self->type_size);
    self->size += 1;
    assert(self->offset + self->size <= self->cap);
}

void vpop(vec_t *self, /* out */ void *value)
{
    assert(self->offset + self->size <= self->cap);
    assert(self->size > 0);
    void *offset = self->rawbuf + self->offset * self->type_size;
    memcpy(value, offset, self->type_size);
    self->size -= 1;
    self->offset += 1;
}

void vpack(vec_t *self, const void *value, uint32_t cnt)
{
    assert(vec_check_cap(self, cnt) == 0);

    void *offset = self->rawbuf + (self->offset + self->size) * self->type_size;
    memcpy(offset, value, self->type_size * cnt);
    self->size += cnt;
    assert(self->offset + self->size <= self->cap);
}

void vdump(vec_t *self, /* out */ void *value, uint32_t cnt)
{
    assert(self->offset + self->size <= self->cap);
    assert(self->size > 0);
    void *offset = self->rawbuf + self->offset * self->type_size;
    memcpy(value, offset, self->type_size * cnt);
    self->size -= cnt;
    self->offset += cnt;
}

void vdrop(vec_t *self, uint32_t cnt)
{
    assert(self->offset + self->size <= self->cap);
    assert(self->size > 0);
    self->size -= cnt;
    self->offset += cnt;
}

void vshrink(vec_t *self)
{
    memmove(self->rawbuf, self->rawbuf + self->offset, self->size * self->type_size);
    self->offset = 0;

    void *newbuf = realloc(self->rawbuf, self->size * self->type_size);
    if (newbuf) {
        self->rawbuf = newbuf;
        self->cap = self->size;
    }
}

void vinsert(vec_t *self, uint32_t offset, const void *value, uint32_t cnt)
{
    if (offset > self->size) {
        assert(vec_check_cap(self, offset - self->size + cnt) == 0);
        self->size = offset;
        vpack(self, value, cnt);
    } else {
        assert(vec_check_cap(self, cnt) == 0);
        for (uint32_t i = 0; i < self->size - offset; i++) {
            memcpy(self->rawbuf + (self->size + cnt - 1 - i) * self->type_size,
                   self->rawbuf + (self->size - 1 - i) * self->type_size,
                   self->type_size);
        }
        memcpy(self->rawbuf + offset * self->type_size,
               value, cnt * self->type_size);
        self->size += cnt;
    }
}

void *vraw(vec_t *self)
{
    return self->rawbuf + self->offset * self->type_size;
}

uint32_t vsize(vec_t *self)
{
    return self->size;
}

uint32_t vcap(vec_t *self)
{
    return self->cap;
}
