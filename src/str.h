#ifndef __STR_H
#define __STR_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct str str_t;

str_t *str_new(const char *s);
str_t *str_new_len(const void *buf, uint32_t len);
void str_free(str_t *self);

const char *sget(str_t *self);

#ifdef __cplusplus
}
#endif

#endif
