#include <assert.h>
#include <stdlib.h>
#include <string.h>
#ifdef DEBUG_STR
#include <stdio.h>
#endif
#include "str.h"

struct str {
    char *rawbuf;
    uint32_t size;
};

str_t *str_new(const char *s)
{
    return str_new_len(s, strlen(s));
}

str_t *str_new_len(const void *buf, uint32_t len)
{
    str_t *self = (str_t*)calloc(1, sizeof(str_t));
    if (!self) return NULL;

    self->size = len + 1;
    self->rawbuf = (char*)calloc(1, self->size);
    if (!self->rawbuf) {
        free(self);
        return NULL;
    }

    memcpy(self->rawbuf, buf, len);
    assert(self->rawbuf[len] == 0);
#ifdef DEBUG_STR
    printf("str_new: %p\n", self);
#endif
    return self;
}

void str_free(str_t *self)
{
#ifdef DEBUG_STR
    printf("str_del: %p\n", self);
#endif
    if (self) {
        free(self->rawbuf);
        free(self);
    }
}

const char *sget(str_t *self)
{
    return self->rawbuf;
}
