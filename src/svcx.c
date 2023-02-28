#include "svcx.h"
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "list.h"

#define SERVICE_HEADER_LEN 256

struct service {
    char header[SERVICE_HEADER_LEN];
    void *private_data;
    struct list_head ln;
};

struct svcx {
    struct list_head services;
};

struct svcx *svcx_new()
{
    struct svcx *svcx = calloc(1, sizeof(*svcx));
    assert(svcx);
    INIT_LIST_HEAD(&svcx->services);
    return svcx;
}

void svcx_destroy(struct svcx *svcx)
{
    struct service *pos, *n;
    list_for_each_entry_safe(pos, n, &svcx->services, ln) {
        list_del(&pos->ln);
        free(pos);
    }
    free(svcx);
}

int svcx_add_service(struct svcx *svcx, const char *header, void *private_data)
{
    struct service *serv = calloc(1, sizeof(*serv));
    assert(serv);
    snprintf(serv->header, sizeof(serv->header), "%s", header);
    serv->private_data = private_data;
    INIT_LIST_HEAD(&serv->ln);
    list_add(&serv->ln, &svcx->services);
    return 0;
}

int svcx_del_service(struct svcx *svcx, const char *header)
{
    struct service *pos;
    list_for_each_entry(pos, &svcx->services, ln) {
        if (strncmp(pos->header, header, strlen(pos->header)) == 0) {
            list_del(&pos->ln);
            free(pos);
            return 0;
        }
    }
    return -1;
}

void *svcx_get_service_private(struct svcx *svcx, const char *header)
{
    struct service *pos;
    list_for_each_entry(pos, &svcx->services, ln) {
        if (strncmp(pos->header, header, strlen(pos->header)) == 0) {
            return pos->private_data;
        }
    }
    return NULL;
}

void svcx_foreach(struct svcx *svcx, svcx_foreach_func_t func)
{
    struct service *pos;
    list_for_each_entry(pos, &svcx->services, ln) {
        func(pos->header, pos->private_data);
    }
}
