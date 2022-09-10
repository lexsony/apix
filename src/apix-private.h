#ifndef __APIX_PRIVATE_H
#define __APIX_PRIVATE_H

#include <stdint.h>
#include <sys/time.h>
#include "apix.h"
#include "list.h"
#include "atbuf.h"
#include "srrp.h"

#define APISINK_ID_SIZE 64
#define SINKFD_ADDR_SIZE 64
#define API_HEADER_SIZE 256
#define API_TOPIC_SUBSCRIBE_MAX 32

#define API_REQUEST_ST_NONE 0
#define API_REQUEST_ST_WAIT_RESPONSE 1

#define API_REQUEST_TIMEOUT 3000 /*ms*/
#define PARSE_PACKET_TIMEOUT 1000 /*ms*/
#define APIX_IDLE_MAX (1 * 1000 * 1000) /*us*/
#define APIX_STATION_ALIVE_TIMEOUT (600 * 1000) /*ms*/

#ifdef __cplusplus
extern "C" {
#endif

/*
 * apisink
 */

struct apisink;

typedef struct apisink_ops {
    int (*open)(struct apisink *sink, const char *addr);
    int (*close)(struct apisink *sink, int fd);
    int (*ioctl)(struct apisink *sink, int fd, unsigned int cmd, unsigned long arg);
    int (*send)(struct apisink *sink, int fd, const void *buf, size_t len);
    int (*recv)(struct apisink *sink, int fd, void *buf, size_t size);
    int (*poll)(struct apisink *sink);
} apisink_ops_t;

struct apisink {
    char id[APISINK_ID_SIZE]; // identify
    apisink_ops_t ops;
    struct apix *ctx;
    struct list_head sinkfds;
    struct list_head node;
};

void apisink_init(struct apisink *sink, const char *id, apisink_ops_t ops);
void apisink_fini(struct apisink *sink);

int apix_add_sink(struct apix *ctx, struct apisink *sink);
void apix_del_sink(struct apix *ctx, struct apisink *sink);

/*
 * sinkfd
 */

struct sinkfd {
    int fd;
    int listen;
    char addr[SINKFD_ADDR_SIZE];
    atbuf_t *txbuf;
    atbuf_t *rxbuf;
    struct timeval ts_poll_recv;
    struct apisink *sink;
    struct list_head node_sink;
    struct list_head node_ctx;
};

struct sinkfd *sinkfd_new();
void sinkfd_destroy();

struct sinkfd *find_sinkfd_in_apix(struct apix *ctx, int fd);
struct sinkfd *find_sinkfd_in_apisink(struct apisink *sink, int fd);

/*
 * api_request
 * api_response
 * api_station
 * api_topic
 */

struct api_request {
    struct srrp_packet *pac;
    int state;
    uint64_t ts_create;
    uint64_t ts_send;
    int fd;
    uint16_t crc16;
    struct list_head node;
};

struct api_response {
    struct srrp_packet *pac;
    int fd;
    struct list_head node;
};

struct api_station {
    uint16_t sttid;
    uint64_t ts_alive;
    int fd;
    struct list_head node;
};

struct api_topic_msg {
    struct srrp_packet *pac;
    int fd;
    struct list_head node;
};

struct api_topic {
    char header[API_HEADER_SIZE];
    int fds[API_TOPIC_SUBSCRIBE_MAX];
    int nfds;
    struct list_head node;
};

#define api_request_delete(req) \
{ \
    list_del(&req->node); \
    srrp_free(req->pac); \
    free(req); \
}

#define api_response_delete(resp) \
{ \
    list_del(&resp->node); \
    srrp_free(resp->pac); \
    free(resp); \
}

#define api_topic_msg_delete(tmsg) \
{ \
    list_del(&tmsg->node); \
    srrp_free(tmsg->pac); \
    free(tmsg); \
}

/*
 * apix
 */

struct apix {
    struct list_head requests;
    struct list_head responses;
    struct list_head stations;
    struct list_head topic_msgs;
    struct list_head topics;
    struct list_head sinkfds;
    struct list_head sinks;
    struct timeval poll_ts;
    int poll_cnt;
    uint64_t idle_usec;
};

#ifdef __cplusplus
}
#endif
#endif
