#ifndef __APIX_PRIVATE_H
#define __APIX_PRIVATE_H

#include <stdint.h>
#include <stdint.h>
#include <stdlib.h>
#include <time.h>
#include <sys/time.h>

#include "apix.h"
#include "list.h"
#include "vec.h"
#include "srrp.h"

#define APISINK_ID_SIZE 64
#define SINKFD_ADDR_SIZE 64
#define API_HEADER_SIZE 256
#define API_TOPIC_SUBSCRIBE_MAX 32

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
    struct list_head msgs;
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
    int (*send)(struct apisink *sink, int fd, const uint8_t *buf, uint32_t len);
    int (*recv)(struct apisink *sink, int fd, uint8_t *buf, uint32_t size);
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

    vec_t *rxbuf;

    int srrp_mode;
    uint32_t l_nodeid; /* local nodeid */
    uint32_t r_nodeid; /* remote nodeid */
    time_t ts_alive;
    struct timeval ts_poll_recv;

    struct apix_events {
        fd_close_func_t on_close;
        fd_accept_func_t on_accept;
        fd_pollin_func_t on_pollin;
        /* TODO: implement on_pollout & on_pollerr */
        srrp_request_func_t on_request;
        srrp_response_func_t on_response;
    } events;

    struct apix_events_priv {
        void *priv_on_close;
        void *priv_on_accept;
        void *priv_on_pollin;
        void *priv_on_request;
        void *priv_on_response;
    } events_priv;

    struct apisink *sink;
    struct list_head ln_sink;
    struct list_head ln_ctx;
};

struct sinkfd *sinkfd_new();
void sinkfd_destroy(struct sinkfd *sinkfd);

struct sinkfd *find_sinkfd_in_apix(struct apix *ctx, int fd);
struct sinkfd *find_sinkfd_in_apisink(struct apisink *sink, int fd);
struct sinkfd *find_sinkfd_by_nodeid(struct apix *ctx, uint32_t nodeid);

/**
 * apimsg
 * api_topic
 */

enum apimsg_type {
    APIMSG_T_CTRL = 0,
    APIMSG_T_REQUEST,
    APIMSG_T_RESPONSE,
    APIMSG_T_TOPIC_MSG,
};

enum apimsg_state {
    APIMSG_ST_NONE = 0,
    APIMSG_ST_FINISHED,
};

struct apimsg {
    int type; /* apimsg_type */
    int state;
    int fd /* src for req, dst for resp */;
    struct srrp_packet *pac;
    struct list_head ln;
};

struct api_topic {
    char header[API_HEADER_SIZE];
    int fds[API_TOPIC_SUBSCRIBE_MAX];
    int nfds;
    struct list_head ln;
};

static inline int apimsg_is_ctrl(struct apimsg *msg)
{
    return msg->type == APIMSG_T_CTRL;
}

static inline int apimsg_is_request(struct apimsg *msg)
{
    return msg->type == APIMSG_T_REQUEST;
}

static inline int apimsg_is_response(struct apimsg *msg)
{
    return msg->type == APIMSG_T_RESPONSE;
}

static inline int apimsg_is_topic_msg(struct apimsg *msg)
{
    return msg->type == APIMSG_T_TOPIC_MSG;
}

static inline int apimsg_is_finished(struct apimsg *msg)
{
    return msg->state == APIMSG_ST_FINISHED;
}

static inline void apimsg_finish(struct apimsg *msg)
{
    msg->state = APIMSG_ST_FINISHED;
}

static inline void apimsg_delete(struct apimsg *msg)
{
    list_del(&msg->ln);
    srrp_free(msg->pac);
    free(msg);
}

#ifdef __cplusplus
}
#endif
#endif
