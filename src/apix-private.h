#ifndef __APIX_PRIVATE_H
#define __APIX_PRIVATE_H

#include <stdint.h>
#include <time.h>
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

#ifdef __cplusplus
extern "C" {
#endif

/**
 * apix
 */

struct apix {
    struct list_head requests;
    struct list_head responses;
    struct list_head topic_msgs;
    struct list_head topics;
    struct list_head sinkfds;
    struct list_head sinks;
    struct timeval poll_ts;
    int poll_cnt;
    uint64_t idle_usec;
};

/**
 * apisink
 * - apix low level implement, maybe unix domain, bsd socket, uart, can ...
 */

struct apisink;

struct apisink_operations {
    int (*open)(struct apisink *sink, const char *addr);
    int (*close)(struct apisink *sink, int fd);
    int (*ioctl)(struct apisink *sink, int fd, unsigned int cmd, unsigned long arg);
    int (*send)(struct apisink *sink, int fd, const void *buf, size_t len);
    int (*recv)(struct apisink *sink, int fd, void *buf, size_t size);
    int (*poll)(struct apisink *sink);
};

struct apisink {
    char id[APISINK_ID_SIZE]; // identify
    struct apisink_operations ops;
    struct apix *ctx;
    struct list_head sinkfds;
    struct list_head ln;
};

void apisink_init(struct apisink *sink, const char *id,
                  const struct apisink_operations *ops);
void apisink_fini(struct apisink *sink);

int apix_sink_register(struct apix *ctx, struct apisink *sink);
void apix_sink_unregister(struct apix *ctx, struct apisink *sink);

/**
 * sinkfd
 * - treat it as unix fd in most situations
 * - each apisink holds several sinkfds
 */

struct sinkfd {
    int fd;
    char type; /* c: connect, l: listen, a: accept */
    char addr[SINKFD_ADDR_SIZE];

    //atbuf_t *txbuf;
    atbuf_t *rxbuf;

    uint32_t nodeid; /* nodeid of accept always equal remote connect */
    struct timeval ts_poll_recv;

    struct apix_events {
        fd_close_func_t on_close;
        fd_accept_func_t on_accept;
        fd_pollin_func_t on_pollin;
        fd_pollout_func_t on_pollout;
    } events;

    struct apisink *sink;
    struct list_head ln_sink;
    struct list_head ln_ctx;
};

struct sinkfd *sinkfd_new();
void sinkfd_destroy();

struct sinkfd *find_sinkfd_in_apix(struct apix *ctx, int fd);
struct sinkfd *find_sinkfd_in_apisink(struct apisink *sink, int fd);
struct sinkfd *find_sinkfd_by_nodeid(struct apix *ctx, int nodeid);

/**
 * api_request
 * api_response
 * api_topic
 */

struct api_request {
    struct srrp_packet *pac;
    int state;
    time_t ts_create;
    time_t ts_send;
    int fd;
    uint16_t crc16;
    struct list_head ln;
};

struct api_response {
    struct srrp_packet *pac;
    int fd;
    struct list_head ln;
};

struct api_topic_msg {
    struct srrp_packet *pac;
    int fd;
    struct list_head ln;
};

struct api_topic {
    char header[API_HEADER_SIZE];
    int fds[API_TOPIC_SUBSCRIBE_MAX];
    int nfds;
    struct list_head ln;
};

#define api_request_delete(req) \
{ \
    list_del(&req->ln); \
    srrp_free(req->pac); \
    free(req); \
}

#define api_response_delete(resp) \
{ \
    list_del(&resp->ln); \
    srrp_free(resp->pac); \
    free(resp); \
}

#define api_topic_msg_delete(tmsg) \
{ \
    list_del(&tmsg->ln); \
    srrp_free(tmsg->pac); \
    free(tmsg); \
}

#ifdef __cplusplus
}
#endif
#endif
