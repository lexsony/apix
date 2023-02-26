#include "svcx.h"
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "list.h"

#define SERVICE_HEADER_LEN 256

struct service {
    char header[SERVICE_HEADER_LEN];
    svc_handle_func_t func;
    struct list_head ln;
};

struct svchub {
    struct list_head services;
};

struct svchub *svchub_new()
{
    struct svchub *hub = calloc(1, sizeof(*hub));
    assert(hub);
    INIT_LIST_HEAD(&hub->services);
    return hub;
}

void svchub_destroy(struct svchub *hub)
{
    struct service *pos, *n;
    list_for_each_entry_safe(pos, n, &hub->services, ln) {
        list_del(&pos->ln);
        free(pos);
    }
    free(hub);
}

int svchub_add_service(struct svchub *hub, const char *header, svc_handle_func_t func)
{
    struct service *serv = calloc(1, sizeof(*serv));
    assert(serv);
    snprintf(serv->header, sizeof(serv->header), "%s", header);
    serv->func = func;
    INIT_LIST_HEAD(&serv->ln);
    list_add(&serv->ln, &hub->services);
    return 0;
}

int svchub_del_service(struct svchub *hub, const char *header)
{
    struct service *pos;
    list_for_each_entry(pos, &hub->services, ln) {
        if (strncmp(pos->header, header, strlen(pos->header)) == 0) {
            list_del(&pos->ln);
            free(pos);
            return 0;
        }
    }
    return -1;
}

int svchub_deal(struct svchub *hub, struct srrp_packet *req, struct srrp_packet **resp)
{
    struct service *pos;
    list_for_each_entry(pos, &hub->services, ln) {
        if (strncmp(pos->header, req->header, strlen(pos->header)) == 0) {
            return pos->func(req, resp);
        }
    }
    return -1;
}
