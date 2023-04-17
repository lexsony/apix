#ifndef __VEC_H
#define __VEC_H

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

#define VEC_DEFAULT_CAP 256

typedef struct vec vec_t;
typedef vec_t vec_8_t;
typedef vec_t vec_16_t;
typedef vec_t vec_32_t;
typedef vec_t vec_64_t;
typedef vec_t vec_p_t;

enum vec_alloc_type {
    VEC_ALLOC_LINEAR = 0,
    //VEC_ALLOC_RANDOM,
};

vec_t *vec_new(size_t type_size, size_t cap);
vec_t *vec_new_alloc(size_t type_size, size_t cap, enum vec_alloc_type alloc);
void vec_free(vec_t *self);

void *vat(vec_t *self, size_t idx);

void vpush(vec_t *self, const void *value);
void vpop(vec_t *self, /* out */ void *value);

//void vpush_front(vec_t *self, const void *value);
void vpop_front(vec_t *self, /* out */ void *value);

void vpack(vec_t *self, const void *value, size_t cnt);
void vdump(vec_t *self, /* out */ void *value, size_t cnt);
void vdrop(vec_t *self, size_t cnt);
void vshrink(vec_t *self);
void vinsert(vec_t *self, size_t idx, const void *value, size_t cnt);
void vremove(vec_t *self, size_t idx, size_t cnt);

/**
 * vraw: only available on VEC_ALLOC_LINEAR
 */
void *vraw(vec_t *self);

size_t vtype(vec_t *self);
size_t vsize(vec_t *self);
size_t vcap(vec_t *self);

#ifdef __cplusplus
}
#endif

#endif
