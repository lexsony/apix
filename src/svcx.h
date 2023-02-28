#ifndef __SVCX_H
#define __SVCX_H

struct svcx;

typedef void (*svcx_foreach_func_t)(const char *header, void *private_data);

struct svcx *svcx_new();
void svcx_destroy(struct svcx *svcx);
int svcx_add_service(struct svcx *svcx, const char *header, void *private_data);
int svcx_del_service(struct svcx *svcx, const char *header);
void *svcx_get_service_private(struct svcx *svcx, const char *header);
void svcx_foreach(struct svcx *svcx, svcx_foreach_func_t func);

#endif
