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
#include <readline/readline.h>

#include <apix.h>
#include <apix-posix.h>
#include <srrp.h>
#include <log.h>
#include <atbuf.h>
#include "opt.h"
#include "cli.h"

#define KBYTES 1024 * 1024

static int exit_flag;
static struct apix *ctx;

struct fd_struct {
    int fd;
    char addr[64];
    const char *mode;
    atbuf_t *msg;
};

static struct fd_struct fds[1024];
static const char *cur_mode = "#";
static int cur_fd = -1;
static int print_all = 0;

static void signal_handler(int sig)
{
    exit_flag = 1;
}

static struct opt opttab[] = {
    INIT_OPT_BOOL("-h", "help", false, "print this usage"),
    INIT_OPT_BOOL("-D", "debug", false, "debug mode [defaut: false]"),
    INIT_OPT_NONE(),
};

static int client_pollin(int fd, const char *buf, size_t len)
{
    if (fds[fd].msg == NULL) {
        fds[fd].msg = atbuf_new(KBYTES);
    }
    if (atbuf_spare(fds[fd].msg) < len)
        atbuf_clear(fds[fd].msg);
    atbuf_write(fds[fd].msg, buf, len);

    return len;
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
        printf("[From %s]:\n", fds[cur_fd].addr);
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
            printf("[From %s]:\n", fds[i].addr);
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
    if (strcmp(cur_mode, "#") == 0) {
        on_cmd_quit(cmd);
    } else {
        cur_mode = "#";
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

static void on_cmd_fds(const char *cmd)
{
    for (int i = 0; i < sizeof(fds) / sizeof(fds[0]); i++) {
        if (fds[i].fd == 0)
            continue;
        printf("fd: %d, addr: %s\n", fds[i].fd, fds[i].addr);
    }
}

static void on_cmd_use(const char *cmd)
{
    int fd = 0;
    int nr = sscanf(cmd, "use %d", &fd);
    if (nr == 1) {
        if (fd >= 0 && fd < sizeof(fds) / sizeof(fds[0]))
            if (fds[fd].fd != 0)
                cur_fd = fds[fd].fd;
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
        apix_on_fd_pollin(ctx, fd, client_pollin);
        assert(fds[fd].fd == 0);
        fds[fd].fd = fd;
        snprintf(fds[fd].addr, sizeof(fds[fd].addr), "%s", addr);
        cur_fd = fd;
    }
}

static void on_cmd_tcp_open(const char *cmd)
{
    if (strcmp(cur_mode, "tcp") != 0)
        return;

    char addr[64] = {0};
    int nr = sscanf(cmd, "open %s", addr);
    if (nr == 1) {
        int fd = apix_open_tcp_client(ctx, addr);
        if (fd == -1) {
            perror("open_tcp");
            return;
        }
        apix_on_fd_pollin(ctx, fd, client_pollin);
        assert(fds[fd].fd == 0);
        fds[fd].fd = fd;
        snprintf(fds[fd].addr, sizeof(fds[fd].addr), "%s", addr);
        cur_fd = fd;
    }
}

static void on_cmd_com_open(const char *cmd)
{
    if (strcmp(cur_mode, "com") != 0)
        return;

    char addr[64] = {0};
    int nr = sscanf(cmd, "open %s", addr);
    if (nr == 1) {
        int fd = apix_open_serial(ctx, addr);
        if (fd == -1) {
            perror("open_com");
            return;
        }
        apix_on_fd_pollin(ctx, fd, client_pollin);
        struct ioctl_serial_param sp = {
            .baud = SERIAL_ARG_BAUD_9600,
            .bits = SERIAL_ARG_BITS_8,
            .parity = SERIAL_ARG_PARITY_E,
            .stop = SERIAL_ARG_STOP_1,
        };
        int rc = apix_ioctl(ctx, fd, 0, (unsigned long)&sp);
        assert(rc != -1);
        assert(fds[fd].fd == 0);
        fds[fd].fd = fd;
        snprintf(fds[fd].addr, sizeof(fds[fd].addr), "%s", addr);
        cur_fd = fd;
    }
}

static void on_cmd_open(const char *cmd)
{
    if (strcmp(cur_mode, "unix") == 0) {
        on_cmd_unix_open(cmd);
    } else if (strcmp(cur_mode, "tcp") == 0) {
        on_cmd_tcp_open(cmd);
    } else if (strcmp(cur_mode, "com") == 0) {
        on_cmd_com_open(cmd);
    }
}

static void on_cmd_close(const char *cmd)
{
    int fd = 0;
    int nr = sscanf(cmd, "close %d", &fd);
    if (nr == 1) {
        if (fd >= 0 && fd < sizeof(fds) / sizeof(fds[0])) {
            if (cur_fd == fd)
                cur_fd = -1;
            apix_close(ctx, fd);
            fds[fd].fd = 0;
            if (fds[fd].msg) {
                atbuf_delete(fds[fd].msg);
                fds[fd].msg = NULL;
            }
        }
    }
}

static void on_cmd_send(const char *cmd)
{
    if (cur_fd == 0)
        return;

    char msg[4096] = {0};
    int nr = sscanf(cmd, "send %s", msg);
    if (nr == 1)
        apix_send(ctx, cur_fd, msg, strlen(msg));
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
    { "ll", on_cmd_fds, "list fds" },
    { "fds", on_cmd_fds, "list fds" },
    { "use", on_cmd_use, "set frontend fd" },
    { "unix", on_cmd_unix, "enter unix mode" },
    { "tcp", on_cmd_tcp, "enter tcp mode, ip:port" },
    { "com", on_cmd_com, "enter com mode" },
    { "open", on_cmd_open, "open fd" },
    { "close", on_cmd_close, "close fd" },
    { "send", on_cmd_send, "send msg" },
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
        if (cur_fd != -1)
            snprintf(prompt, sizeof(prompt), "%s>%s> ", cur_mode, fds[cur_fd].addr);
        else
            snprintf(prompt, sizeof(prompt), "%s> ", cur_mode);
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
