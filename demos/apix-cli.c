#include <assert.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <signal.h>
#include <pthread.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <linux/can.h>
#include <readline/readline.h>

#include <apix/apix.h>
#include <apix/log.h>
#include <apix/atbuf.h>
#include <apix/list.h>
#include "opt.h"
#include "cli.h"

#define KBYTES 1024 * 1024
#define FD_SIZE 4096
#define FD_MAX (FD_SIZE - 1)
#define CUR_MODE_NONE "#"

struct fd_struct {
    int fd;
    int father_fd;
    char addr[64];
    const char *mode; /* unix, tcp, com, can */
    atbuf_t *msg;
    char type; /* c: connect, l: listen, a: accept */
    int can_id;
    int node_id;
    int srrp_mode;
    struct list_head services;
};

struct service {
    struct list_head ln;
    char header[256];
    char msg[1024];
};

static int exit_flag;
static struct apix *ctx;

static struct fd_struct fds[FD_SIZE];
static const char *cur_mode = CUR_MODE_NONE;
static int cur_fd = -1;
static int print_all = 0;
static int broker_mode = 0;

static void signal_handler(int sig)
{
    exit_flag = 1;
}

static struct opt opttab[] = {
    INIT_OPT_BOOL("-h", "help", false, "print this usage"),
    INIT_OPT_BOOL("-D", "debug", false, "enable debug [defaut: false]"),
    INIT_OPT_STRING("-m:", "mode", CUR_MODE_NONE, "current mode"),
    INIT_OPT_BOOL("-p", "print_all", false, "enable print all"),
    INIT_OPT_BOOL("-b", "broker_mode", false, "enable broker mode"),
    INIT_OPT_NONE(),
};

static size_t transfer_hex_string(char *buf, size_t len)
{
    int idx = 0;
    char tmp[3] = {0};
    int hex;

    for (int i = 0; i < len;) {
        if (len - i >= 4 && buf[i] == '0' && buf[i+1] == 'x') {
            tmp[0] = buf[i+2];
            tmp[1] = buf[i+3];
            sscanf(tmp, "%x", &hex);
            buf[idx] = (char)hex;
            idx++;
            i += 4;
        } else {
            buf[idx] = buf[i];
            idx++;
            i++;
        }
    }

    buf[idx] = 0;
    return idx; // new len
}

static void log_hex_string(const char *buf, size_t len)
{
    for (int i = 0; i < (int)len; i++) {
        if (isprint(buf[i]))
            printf("%c", buf[i]);
        else
            printf("_0x%.2x", buf[i]);
    }
    printf("\n");
}

static void close_fd(int fd)
{
    if (fd >= 0 && fd < sizeof(fds) / sizeof(fds[0])) {
        printf("close #%d, %s(%c)\n", fd, fds[fd].addr, fds[fd].type);
        if (cur_fd == fd)
            cur_fd = -1;
        apix_close(ctx, fd);
        fds[fd].fd = 0;
        if (fds[fd].msg) {
            atbuf_delete(fds[fd].msg);
            fds[fd].msg = NULL;
        }

        struct service *pos, *n;
        list_for_each_entry_safe(pos, n, &fds[fd].services, ln) {
            free(pos);
        }
    }
}

static void on_srrp_request(int fd, struct srrp_packet *req, struct srrp_packet **resp)
{
    int real_fd = fd;
    if (fds[fd].type == 'a')
        real_fd = fds[fd].father_fd;
    assert(real_fd != 0);

    struct service *pos;
    list_for_each_entry(pos, &fds[real_fd].services, ln) {
        if (strncmp(pos->header, req->header, strlen(pos->header)) == 0) {
            *resp = srrp_new_response(
                req->dstid, req->srcid, req->crc16, req->header, pos->msg);
            return;
        }
    }

    *resp = srrp_new_response(
        req->dstid, req->srcid, req->crc16, req->header, "{msg:'...'}");

    printf("on srrp request(%d): %s\n", real_fd, req->raw);
}

static void on_srrp_response(int fd, struct srrp_packet *resp)
{
    printf("on srrp response(%d): %s\n", fd, resp->raw);
}

static int on_fd_pollin(int fd, const char *buf, size_t len)
{
    if (broker_mode)
        return -1;

    if (fds[fd].srrp_mode == 1)
        return -1;

    if (fds[fd].msg == NULL) {
        fds[fd].msg = atbuf_new(KBYTES);
    }
    if (atbuf_spare(fds[fd].msg) < len)
        atbuf_clear(fds[fd].msg);
    atbuf_write(fds[fd].msg, buf, len);

    return len;
}

static int on_fd_close(int fd)
{
    close_fd(fd);
    return 0;
}

static int on_fd_accept(int _fd, int newfd)
{
    if (_fd > FD_MAX || newfd > FD_MAX) {
        perror("fd is too big");
        exit(-1);
    }

    apix_on_fd_pollin(ctx, newfd, on_fd_pollin);
    apix_on_fd_close(ctx, newfd, on_fd_close);
    assert(fds[newfd].fd == 0);
    fds[newfd].fd = newfd;
    strcpy(fds[newfd].addr, fds[_fd].addr);
    fds[newfd].type = 'a';
    fds[newfd].srrp_mode = fds[_fd].srrp_mode;
    INIT_LIST_HEAD(&fds[newfd].services);
    fds[newfd].father_fd = _fd;
    printf("accept #%d, %s(%c)\n", newfd, fds[newfd].addr, fds[newfd].type);
    return 0;
}

static int on_can_pollin(int fd, const char *buf, size_t len)
{
    struct can_frame *frame = (struct can_frame *)buf;

    if (frame->can_id & CAN_ERR_FLAG) {
        printf("Error frame\n");
        return sizeof(struct can_frame);
    }

    if (frame->can_id & CAN_EFF_FLAG)
        printf("ext <0x%08x> ", frame->can_id & CAN_EFF_MASK);
    else
        printf("std <0x%03x> ", frame->can_id & CAN_SFF_MASK);

    if (frame->can_id & CAN_RTR_FLAG) {
        printf("remote request\n");
        return sizeof(struct can_frame);
    }

    printf("[%d] ", frame->can_dlc);
    log_hex_string((char *)frame->data, frame->can_dlc);
    return sizeof(struct can_frame);
}

static void print_cur_msg(void)
{
    int need_hack = (rl_readline_state & RL_STATE_READCMD) > 0;
    char *saved_line;
    int saved_point;

    if (need_hack) {
        saved_point = rl_point;
        saved_line = rl_copy_text(0, rl_end);
        rl_save_prompt();
        rl_replace_line("", 0);
        rl_redisplay();
    }

    if (cur_fd != -1 && fds[cur_fd].msg && atbuf_used(fds[cur_fd].msg)) {
        printf("[%s(%c)]:\n", fds[cur_fd].addr, fds[cur_fd].type);
        char msg[256] = {0};
        size_t len = 0;
        while (1) {
            bzero(msg, sizeof(msg));
            len = atbuf_read(fds[cur_fd].msg, msg, sizeof(msg));
            if (len == 0) break;
            printf("%s", msg);
        }
        printf("\n---------------------------\n");
        atbuf_clear(fds[cur_fd].msg);
    }

    if (need_hack) {
        rl_restore_prompt();
        rl_replace_line(saved_line, 0);
        rl_point = saved_point;
        rl_redisplay();
        free(saved_line);
    }
}

static void print_all_msg(void)
{
    int need_hack = (rl_readline_state & RL_STATE_READCMD) > 0;
    char *saved_line;
    int saved_point;

    if (need_hack) {
        saved_point = rl_point;
        saved_line = rl_copy_text(0, rl_end);
        rl_save_prompt();
        rl_replace_line("", 0);
        rl_redisplay();
    }

    for (int i = 0; i < sizeof(fds) / sizeof(fds[0]); i++) {
        if (fds[i].msg && atbuf_used(fds[i].msg)) {
            printf("[%s(%c)]:\n", fds[i].addr, fds[i].type);
            char msg[256] = {0};
            size_t len = 0;
            while (1) {
                bzero(msg, sizeof(msg));
                len = atbuf_read(fds[i].msg, msg, sizeof(msg));
                if (len == 0) break;
                printf("%s", msg);
            }
            printf("\n---------------------------\n");
            atbuf_clear(fds[i].msg);
        }
    }

    if (need_hack) {
        rl_restore_prompt();
        rl_replace_line(saved_line, 0);
        rl_point = saved_point;
        rl_redisplay();
        free(saved_line);
    }
}

static void *apix_thread(void *arg)
{
    ctx = apix_new();
    apix_enable_posix(ctx);

    while (exit_flag == 0) {
        if (print_all)
            print_all_msg();
        else
            print_cur_msg();
        apix_poll(ctx);
    }

    apix_disable_posix(ctx);
    apix_destroy(ctx); // auto close all fds

    return NULL;
}

static void on_cmd_quit(const char *cmd)
{
    exit_flag = 1;
}

static void on_cmd_exit(const char *cmd)
{
    if (strcmp(cur_mode, CUR_MODE_NONE) == 0) {
        on_cmd_quit(cmd);
    } else {
        cur_mode = CUR_MODE_NONE;
        cur_fd = -1;
    }
}

static void on_cmd_print(const char *cmd)
{
    char param[64] = {0};
    int nr = sscanf(cmd, "print %s", param);
    if (nr == 1) {
        if (strcmp(param, "all") == 0)
            print_all = 1;
        else if (strcmp(param, "cur") == 0)
            print_all = 0;
    }
}

static void on_cmd_broker(const char *cmd)
{
    char param[64] = {0};
    int nr = sscanf(cmd, "broker %s", param);
    if (nr == 1) {
        if (strcmp(param, "on") == 0)
            broker_mode = 1;
        else if (strcmp(param, "off") == 0)
            broker_mode = 0;
    }
}

static void on_cmd_env(const char *cmd)
{
    printf("cur_mode: %s\n", cur_mode);
    printf("cur_fd: %d\n", cur_fd);
    printf("print: %s\n", print_all ? "all" : "cur");
    printf("broker: %s\n", broker_mode ? "on" : "off");
}

static void on_cmd_fds(const char *cmd)
{
    for (int i = 0; i < sizeof(fds) / sizeof(fds[0]); i++) {
        if (fds[i].fd == 0)
            continue;
        if (fds[i].type == 'a') {
            printf("fd: %d, type: %c, addr: %s\n",
                   fds[i].fd, fds[i].type, fds[i].addr);
        } else {
            printf("fd: %d, type: %c, addr: %s, nodeid: %d, srrpmode: %d\n",
                   fds[i].fd, fds[i].type, fds[i].addr,
                   fds[i].node_id, fds[i].srrp_mode);
        }
    }
}

static void on_cmd_use(const char *cmd)
{
    if (strcmp(cur_mode, CUR_MODE_NONE) == 0)
        return;

    int fd = 0;
    int nr = sscanf(cmd, "use %d", &fd);
    if (nr == 1) {
        if (fd >= 0 && fd < sizeof(fds) / sizeof(fds[0])) {
            if (fds[fd].type == 'a') {
                printf("cannot use accept fd\n");
            } else {
                assert(fds[fd].fd != 0);
                cur_fd = fds[fd].fd;
            }
        }
    }
}

static void on_cmd_unix(const char *cmd)
{
    if (strcmp(cur_mode, "unix") != 0) {
        cur_mode = "unix";
        cur_fd = -1;
    }
}

static void on_cmd_tcp(const char *cmd)
{
    if (strcmp(cur_mode, "tcp") != 0) {
        cur_mode = "tcp";
        cur_fd = -1;
    }
}

static void on_cmd_com(const char *cmd)
{
    if (strcmp(cur_mode, "com") != 0) {
        cur_mode = "com";
        cur_fd = -1;
    }
}

static void on_cmd_can(const char *cmd)
{
    if (strcmp(cur_mode, "can") != 0) {
        cur_mode = "can";
        cur_fd = -1;
    }
}

static void on_cmd_unix_listen(const char *cmd)
{
    if (strcmp(cur_mode, "unix") != 0)
        return;

    char addr[64] = {0};
    int nr = sscanf(cmd, "listen %s", addr);
    if (nr == 1) {
        int fd = apix_open_unix_server(ctx, addr);
        if (fd == -1) {
            perror("listen_unix");
            return;
        }
        apix_on_fd_accept(ctx, fd, on_fd_accept);
        apix_on_srrp_request(ctx, fd, on_srrp_request);
        apix_on_srrp_response(ctx, fd, on_srrp_response);
        assert(fds[fd].fd == 0);
        fds[fd].fd = fd;
        snprintf(fds[fd].addr, sizeof(fds[fd].addr), "%s", addr);
        fds[fd].type = 'l';
        fds[fd].mode = "unix";
        fds[fd].srrp_mode = 0;
        INIT_LIST_HEAD(&fds[fd].services);
        cur_fd = fd;
        printf("listen #%d, %s(%c)\n", fd, fds[fd].addr, fds[fd].type);
    }
}

static void on_cmd_tcp_listen(const char *cmd)
{
    if (strcmp(cur_mode, "tcp") != 0)
        return;

    char addr[64] = {0};
    int nr = sscanf(cmd, "listen %s", addr);
    if (nr == 1) {
        int fd = apix_open_tcp_server(ctx, addr);
        if (fd == -1) {
            perror("listen_tcp");
            return;
        }
        apix_on_fd_accept(ctx, fd, on_fd_accept);
        apix_on_srrp_request(ctx, fd, on_srrp_request);
        apix_on_srrp_response(ctx, fd, on_srrp_response);
        assert(fds[fd].fd == 0);
        fds[fd].fd = fd;
        snprintf(fds[fd].addr, sizeof(fds[fd].addr), "%s", addr);
        fds[fd].type = 'l';
        fds[fd].mode = "tcp";
        fds[fd].srrp_mode = 0;
        INIT_LIST_HEAD(&fds[fd].services);
        cur_fd = fd;
        printf("listen #%d, %s(%c)\n", fd, fds[fd].addr, fds[fd].type);
    }
}

static void on_cmd_listen(const char *cmd)
{
    if (strcmp(cur_mode, "unix") == 0) {
        on_cmd_unix_listen(cmd);
    } else if (strcmp(cur_mode, "tcp") == 0) {
        on_cmd_tcp_listen(cmd);
    }
}

static void on_cmd_unix_open(const char *cmd)
{
    if (strcmp(cur_mode, "unix") != 0)
        return;

    char addr[64] = {0};
    int nr = sscanf(cmd, "open %s", addr);
    if (nr == 1) {
        int fd = apix_open_unix_client(ctx, addr);
        if (fd == -1) {
            perror("open_unix");
            return;
        }
        apix_on_fd_pollin(ctx, fd, on_fd_pollin);
        apix_on_srrp_request(ctx, fd, on_srrp_request);
        apix_on_srrp_response(ctx, fd, on_srrp_response);
        assert(fds[fd].fd == 0);
        fds[fd].fd = fd;
        snprintf(fds[fd].addr, sizeof(fds[fd].addr), "%s", addr);
        fds[fd].type = 'c';
        fds[fd].mode = "unix";
        fds[fd].srrp_mode = 0;
        INIT_LIST_HEAD(&fds[fd].services);
        cur_fd = fd;
        printf("connect #%d, %s(%c)\n", fd, fds[fd].addr, fds[fd].type);
    }
}

static void on_cmd_tcp_open(const char *cmd)
{
    if (strcmp(cur_mode, "tcp") != 0)
        return;

    char addr[64] = {0};
    int nr = sscanf(cmd, "open %s", addr);
    if (nr != 1) {
        printf("param error\n");
        return;
    }

    int fd = apix_open_tcp_client(ctx, addr);
    if (fd == -1) {
        perror("open_tcp");
        return;
    }
    apix_on_fd_pollin(ctx, fd, on_fd_pollin);
    apix_on_srrp_request(ctx, fd, on_srrp_request);
    apix_on_srrp_response(ctx, fd, on_srrp_response);
    assert(fds[fd].fd == 0);
    fds[fd].fd = fd;
    snprintf(fds[fd].addr, sizeof(fds[fd].addr), "%s", addr);
    fds[fd].type = 'c';
    fds[fd].mode = "tcp";
    fds[fd].srrp_mode = 0;
    INIT_LIST_HEAD(&fds[fd].services);
    cur_fd = fd;
    printf("connect #%d, %s(%c)\n", fd, fds[fd].addr, fds[fd].type);
}

static void on_cmd_com_open(const char *cmd)
{
    if (strcmp(cur_mode, "com") != 0)
        return;

    char addr[64] = {0};
    int baud = 115200;
    int data_bits = 8;
    char parity = 'N';
    int stop_bits = 1;
    int nr = sscanf(cmd, "open %s,%d,%d,%c,%d",
                    addr, &baud, &data_bits, &parity, &stop_bits);
    if (nr != 5) {
        printf("param error\n");
        return;
    }

    int fd = apix_open_com(ctx, addr);
    if (fd == -1) {
        perror("open_com");
        return;
    }
    struct ioctl_com_param sp = {
        .baud = baud,
        .bits = data_bits,
        .parity = parity,
        .stop = stop_bits,
    };
    int rc = apix_ioctl(ctx, fd, 0, (unsigned long)&sp);
    if (rc == -1) {
        apix_close(ctx, fd);
        perror("ioctl_com");
        return;
    }
    apix_on_fd_pollin(ctx, fd, on_fd_pollin);
    apix_on_srrp_request(ctx, fd, on_srrp_request);
    apix_on_srrp_response(ctx, fd, on_srrp_response);
    assert(fds[fd].fd == 0);
    fds[fd].fd = fd;
    snprintf(fds[fd].addr, sizeof(fds[fd].addr), "%s", strstr(cmd, "open "));
    fds[fd].type = 'c';
    fds[fd].mode = "com";
    fds[fd].srrp_mode = 0;
    INIT_LIST_HEAD(&fds[fd].services);
    cur_fd = fd;
    printf("connect #%d, %s(%c)\n", fd, fds[fd].addr, fds[fd].type);
}

static void on_cmd_can_open(const char *cmd)
{
    if (strcmp(cur_mode, "can") != 0)
        return;

    char addr[64] = {0};
    int can_id = 0;
    int nr;
    if (strstr(cmd, ":0x"))
        nr = sscanf(cmd, "open %[^:]:0x%x", addr, &can_id);
    else
        nr = sscanf(cmd, "open %[^:]:%d", addr, &can_id);
    if (nr != 2) {
        printf("param error\n");
        return;
    }

    printf("can_id = %x\n", can_id);
    int fd = apix_open_can(ctx, addr);
    if (fd == -1) {
        perror("open_can");
        return;
    }
    apix_on_fd_pollin(ctx, fd, on_can_pollin);
    apix_on_srrp_request(ctx, fd, on_srrp_request);
    apix_on_srrp_response(ctx, fd, on_srrp_response);
    assert(fds[fd].fd == 0);
    fds[fd].fd = fd;
    snprintf(fds[fd].addr, sizeof(fds[fd].addr), "%s", strstr(cmd, "open "));
    fds[fd].type = 'c';
    fds[fd].mode = "can";
    fds[fd].can_id = can_id;
    fds[fd].srrp_mode = 0;
    INIT_LIST_HEAD(&fds[fd].services);
    cur_fd = fd;
    printf("connect #%d, %s(%c)\n", fd, fds[fd].addr, fds[fd].type);
}

static void on_cmd_open(const char *cmd)
{
    if (strcmp(cur_mode, "unix") == 0) {
        on_cmd_unix_open(cmd);
    } else if (strcmp(cur_mode, "tcp") == 0) {
        on_cmd_tcp_open(cmd);
    } else if (strcmp(cur_mode, "com") == 0) {
        on_cmd_com_open(cmd);
    } else if (strcmp(cur_mode, "can") == 0) {
        on_cmd_can_open(cmd);
    }
}

static void on_cmd_close(const char *cmd)
{
    int fd = 0;
    int nr = sscanf(cmd, "close %d", &fd);
    if (nr == 1) {
        close_fd(fd);
    } else if (strcmp(cmd, "close") == 0) {
        close_fd(cur_fd);
    }
}

static void on_cmd_send(const char *cmd)
{
    if (cur_fd == 0)
        return;

    char msg[4096] = {0};
    int nr = sscanf(cmd, "send %s", msg);
    if (nr != 1) {
        printf("param error\n");
        return;
    }

    int len = transfer_hex_string(msg, strlen(msg));

    if (strcmp(cur_mode, "can") == 0) {
        struct can_frame frame = {0};
        memcpy(frame.data, msg, len);
        frame.can_dlc = strlen(msg);
        frame.can_id = fds[cur_fd].can_id | CAN_EFF_FLAG;
        apix_send(ctx, cur_fd, &frame, sizeof(frame));
    } else {
        apix_send(ctx, cur_fd, msg, len);
    }
}

static void on_cmd_setid(const char *cmd)
{
    if (cur_fd == 0)
        return;

    if (fds[cur_fd].srrp_mode == 1) {
        printf("cannot change nodeid when in srrpmode\n");
    }

    int id = 0;
    int nr = sscanf(cmd, "setid %d", &id);
    if (nr != 1) {
        printf("param error\n");
        return;
    }

    fds[cur_fd].node_id = id;
}

static void on_cmd_srrpmode(const char *cmd)
{
    if (cur_fd == 0)
        return;

    char msg[32] = {0};
    int nr = sscanf(cmd, "srrpmode %s", msg);
    if (nr != 1) {
        printf("param error\n");
        return;
    }

    if (strcmp(msg, "on") == 0) {
        fds[cur_fd].srrp_mode = 1;
        apix_enable_srrp_mode(ctx, fds[cur_fd].fd, fds[cur_fd].node_id);
    } else if (strcmp(msg, "off") == 0) {
        fds[cur_fd].srrp_mode = 0;
        apix_disable_srrp_mode(ctx, fds[cur_fd].fd);
    } else {
        printf("param error\n");
    }
}

static void on_cmd_srrpget(const char *cmd)
{
    if (cur_fd == 0)
        return;

    if (fds[cur_fd].srrp_mode == 0) {
        printf("srrpmode is disabled\n");
        return;
    }

    int dstid = 0;
    char hdr[256] = {0};
    char msg[4096] = {0};
    int nr = sscanf(cmd, "srrpget %d:%[^?]?%[^\r\n]", &dstid, hdr, msg);
    if (nr != 3) {
        printf("param error\n");
        return;
    }

    struct srrp_packet *pac = srrp_new_request(fds[cur_fd].node_id, dstid, hdr, msg);
    if (strcmp(cur_mode, "can") == 0) {
        struct can_frame frame = {0};
        memcpy(frame.data, pac->raw, pac->len);
        frame.can_dlc = strlen(msg);
        frame.can_id = fds[cur_fd].can_id | CAN_EFF_FLAG;
        apix_send(ctx, cur_fd, &frame, sizeof(frame));
    } else {
        apix_send(ctx, cur_fd, pac->raw, pac->len);
    }
    srrp_free(pac);
}

static void on_cmd_srrpadd(const char *cmd)
{
    if (cur_fd == 0)
        return;

    if (fds[cur_fd].srrp_mode == 0) {
        printf("srrpmode is disabled\n");
        return;
    }

    char hdr[256] = {0};
    char msg[1024] = {0};
    int nr = sscanf(cmd, "srrpadd %[^?]?%[^\t\n]", hdr, msg);
    if (nr != 2) {
        printf("param error\n");
        return;
    }

    struct service *serv = calloc(1, sizeof(*serv));
    assert(serv);
    snprintf(serv->header, sizeof(serv->header), "%s", hdr);
    snprintf(serv->msg, sizeof(serv->msg), "%s", msg);
    INIT_LIST_HEAD(&serv->ln);
    list_add(&serv->ln, &fds[cur_fd].services);
}

static void on_cmd_srrpdel(const char *cmd)
{
    if (cur_fd == 0)
        return;

    if (fds[cur_fd].srrp_mode == 0) {
        printf("srrpmode is disabled\n");
        return;
    }

    char hdr[256] = {0};
    int nr = sscanf(cmd, "srrpdel %s", hdr);
    if (nr != 1) {
        printf("param error\n");
        return;
    }

    struct service *pos;
    list_for_each_entry(pos, &fds[cur_fd].services, ln) {
        if (strncmp(pos->header, hdr, strlen(pos->header)) == 0) {
            list_del(&pos->ln);
            free(pos);
            break;
        }
    }
}

static void on_cmd_srrpinfo(const char *cmd)
{
    if (cur_fd == 0)
        return;

    if (fds[cur_fd].srrp_mode == 0) {
        printf("srrpmode is disabled\n");
        return;
    }

    struct service *pos;
    list_for_each_entry(pos, &fds[cur_fd].services, ln) {
        printf("hdr: %s, msg: %s\n", pos->header, pos->msg);
    }
}

static void on_cmd_default(const char *cmd)
{
    printf("unknown command: %s\n", cmd);
    return;
}

static const struct cli_cmd cli_cmds[] = {
    { "help", on_cmd_help, "display the manual" },
    { "history", on_cmd_history, "display history of commands" },
    { "his", on_cmd_history, "display history of commands" },
    { "!", on_cmd_history_exec, "!<num>" },
    { "quit", on_cmd_quit, "quit cli" },
    { "exit", on_cmd_exit, "exit cur_mode or quit cli" },
    { "print", on_cmd_print, "print all|cur" },
    { "broker", on_cmd_broker, "broker on|off" },
    { "env", on_cmd_env, "display environments" },
    { "ll", on_cmd_fds, "list fds" },
    { "fds", on_cmd_fds, "list fds" },
    { "use", on_cmd_use, "set frontend fd" },
    { "unix", on_cmd_unix, "enter unix mode, path" },
    { "tcp", on_cmd_tcp, "enter tcp mode, ip:port" },
    { "com", on_cmd_com, "enter com mode, path,baud,data_bits,parity,stop_bits" },
    { "can", on_cmd_can, "enter can mode, device" },
    { "listen", on_cmd_listen, "listen fd" },
    { "open", on_cmd_open, "open fd" },
    { "close", on_cmd_close, "close fd" },
    { "send", on_cmd_send, "send msg" },
    { "setid", on_cmd_setid, "set node id" },
    { "srrpmode", on_cmd_srrpmode, "srrpmode on|off" },
    { "srrpget", on_cmd_srrpget, "srrpget hdr?msg" },
    { "srrpadd", on_cmd_srrpadd, "srrpadd hdr?msg" },
    { "srrpdel", on_cmd_srrpdel, "srrpdel hdr" },
    { "srrpinfo", on_cmd_srrpinfo, "srrpinfo" },
    { NULL, NULL }
};

static const struct cli_cmd cli_cmd_default = {
    "default", on_cmd_default, "default"
};

static void *cli_thread(void *arg)
{
    char prompt[256] = {0};
    cli_init(cli_cmds, &cli_cmd_default);

    while (exit_flag == 0) {
        if (cur_fd == -1) {
            snprintf(prompt, sizeof(prompt), "%s> ", cur_mode);
        } else {
            snprintf(prompt, sizeof(prompt), "%s>%s(%c:%d)> ",
                     cur_mode, fds[cur_fd].addr, fds[cur_fd].type, cur_fd);
        }
        cli_run(prompt);
    }

    cli_close();
    return NULL;
}

int main(int argc, char *argv[])
{
    log_set_level(LOG_LV_INFO);
    opt_init_from_arg(opttab, argc, argv);
    signal(SIGINT, signal_handler);
    signal(SIGQUIT, signal_handler);

    struct opt *opt;
    //opt = find_opt("debug", opttab);
    //if (opt_bool(opt))
    //    log_set_level(LOG_LV_DEBUG);
    opt = find_opt("mode", opttab);
    cur_mode = opt_string(opt);
    opt = find_opt("print_all", opttab);
    if (opt_bool(opt))
        print_all = 1;;
    opt = find_opt("broker_mode", opttab);
    if (opt_bool(opt))
        broker_mode = 1;;

    on_cmd_env("");

    pthread_t apix_pid;
    pthread_create(&apix_pid, NULL, apix_thread, NULL);
    pthread_t cli_pid;
    pthread_create(&cli_pid, NULL, cli_thread, NULL);

    while (exit_flag == 0) {
        sleep(1);
    }

    pthread_join(apix_pid, NULL);
    pthread_join(cli_pid, NULL);
    return 0;
}
