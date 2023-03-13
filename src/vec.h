#ifndef __VEC_H
#define __VEC_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define VEC_DEFAULT_CAP 256

typedef struct vec vec_t;

enum vec_alloc_type {
    VEC_ALLOC_LINEAR = 0,
    //VEC_ALLOC_RANDOM,
};

vec_t *vec_new(uint32_t type_size, uint32_t cap);
vec_t *vec_new_alloc(uint32_t type_size, uint32_t cap, enum vec_alloc_type alloc);
void vec_delete(vec_t *self);

void vpush(vec_t *self, const void *value);
void vpop(vec_t *self, /* out */ void *value);

void vpack(vec_t *self, const void *value, uint32_t cnt);
void vdump(vec_t *self, /* out */ void *value, uint32_t cnt);
void vdrop(vec_t *self, uint32_t cnt);
void vshrink(vec_t *self);
void vinsert(vec_t *self, uint32_t offset, const void *value, uint32_t cnt);

/**
 * vraw: only available on VEC_ALLOC_LINEAR
 */
void *vraw(vec_t *self);

uint32_t vsize(vec_t *self);
uint32_t vcap(vec_t *self);

#ifdef __cplusplus
}
#endif

#endif
