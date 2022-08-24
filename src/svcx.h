#ifndef __SVCX_H
#define __SVCX_H

#include "srrp.h"

typedef int (*svc_handle_func_t)(struct srrp_packet *req, struct srrp_packet **resp);

struct svchub;

struct svchub *svchub_new();
void svchub_destroy(struct svchub *hub);

int svchub_add_service(struct svchub *hub, const char *header, svc_handle_func_t func);
int svchub_del_service(struct svchub *hub, const char *header);

int svchub_deal(struct svchub *hub, struct srrp_packet *req, struct srrp_packet **resp);

#endif
