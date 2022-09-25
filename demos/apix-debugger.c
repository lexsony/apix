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
#include "opt.h"
#include "cli.h"

static int exit_flag;
static struct apix *ctx;

struct fd_struct {
    int fd;
    char addr[64];
};

static struct fd_struct fds[1024];
static int frontend;

static void signal_handler(int sig)
{
    exit_flag = 1;
}

static struct opt opttab[] = {
    INIT_OPT_BOOL("-h", "help", false, "print this usage"),
    INIT_OPT_BOOL("-D", "debug", false, "debug mode [defaut: false]"),
    INIT_OPT_STRING("-x:", "unix", "", "unix domain"),
    INIT_OPT_STRING("-t:", "tcp", "", "tcp socket"),
    //INIT_OPT_STRING("-u:", "udp", "", "udp socket"),
    INIT_OPT_STRING("-s:", "com", "", "com dev file"),
    INIT_OPT_NONE(),
};

static int client_pollin(int fd, const char *buf, size_t len)
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

    printf("%d> %s\n", fd, buf);

    if (need_hack) {
        rl_restore_prompt();
        rl_replace_line(saved_line, 0);
        rl_point = saved_point;
        rl_redisplay();
        free(saved_line);
    }

    return len;
}

static void *apix_thread(void *arg)
{
    struct opt *ud = find_opt("unix", opttab);
    struct opt *tcp = find_opt("tcp", opttab);
    struct opt *com = find_opt("com", opttab);

    ctx = apix_new();
    apix_enable_posix(ctx);

    if (strcmp(opt_string(ud), "") != 0) {
        int fd = apix_open_unix_client(ctx, opt_string(ud));
        if (fd == -1) {
            perror("open_unix");
            exit(1);
        }
        struct apix_events events = { .on_pollin = client_pollin };
        apix_set_events(ctx, fd, &events);
        assert(fds[fd].fd == 0);
        fds[fd].fd = fd;
        snprintf(fds[fd].addr, sizeof(fds[fd].addr), "%s", opt_string(ud));
        frontend = fd;
    }

    if (strcmp(opt_string(tcp), "") != 0) {
        int fd = apix_open_tcp_client(ctx, opt_string(tcp));
        if (fd == -1) {
            perror("open_tcp");
            exit(1);
        }
        struct apix_events events = { .on_pollin = client_pollin };
        apix_set_events(ctx, fd, &events);
        assert(fds[fd].fd == 0);
        fds[fd].fd = fd;
        snprintf(fds[fd].addr, sizeof(fds[fd].addr), "%s", opt_string(tcp));
        frontend = fd;
    }

    if (strcmp(opt_string(com), "") != 0) {
        int fd = apix_open_serial(ctx, opt_string(com));
        if (fd == -1) {
            perror("open_com");
            exit(1);
        }
        struct apix_events events = { .on_pollin = client_pollin };
        apix_set_events(ctx, fd, &events);
        struct ioctl_serial_param sp = {
            .baud = SERIAL_ARG_BAUD_115200,
            .bits = SERIAL_ARG_BITS_8,
            .parity = SERIAL_ARG_PARITY_N,
            .stop = SERIAL_ARG_STOP_1,
        };
        int rc = apix_ioctl(ctx, fd, 0, (unsigned long)&sp);
        assert(rc != -1);
        assert(fds[fd].fd == 0);
        fds[fd].fd = fd;
        snprintf(fds[fd].addr, sizeof(fds[fd].addr), "%s", opt_string(com));
        frontend = fd;
    }

    while (exit_flag == 0) {
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

static void on_cmd_fds(const char *cmd)
{
    for (int i = 0; i < sizeof(fds) / sizeof(fds[0]); i++) {
        if (fds[i].fd == 0)
            continue;
        printf("fd: %d, addr: %s\n", fds[i].fd, fds[i].addr);
    }
    printf("frontend: %d\n", frontend);
}

static void on_cmd_front(const char *cmd)
{
    int fd = 0;
    int nr = sscanf(cmd, "front %d", &fd);
    if (nr == 1) {
        frontend = fd;
    }
}

static void on_cmd_close(const char *cmd)
{
    int fd = 0;
    int nr = sscanf(cmd, "close %d", &fd);
    if (nr == 1) {
        apix_close(ctx, fd);
        fds[fd].fd = 0;
        if (frontend == fd)
            frontend = 0;
    }
}

static void on_cmd_unix(const char *cmd)
{
    char addr[64] = {0};
    int nr = sscanf(cmd, "unix %s", addr);
    if (nr == 1) {
        int fd = apix_open_unix_client(ctx, addr);
        if (fd == -1) {
            perror("open_unix");
            return;
        }
        struct apix_events events = { .on_pollin = client_pollin };
        apix_set_events(ctx, fd, &events);
        assert(fds[fd].fd == 0);
        fds[fd].fd = fd;
        snprintf(fds[fd].addr, sizeof(fds[fd].addr), "%s", addr);
        frontend = fd;
    }
}

static void on_cmd_tcp(const char *cmd)
{
    char addr[64] = {0};
    int nr = sscanf(cmd, "tcp %s", addr);
    if (nr == 1) {
        int fd = apix_open_tcp_client(ctx, addr);
        if (fd == -1) {
            perror("open_tcp");
            return;
        }
        struct apix_events events = { .on_pollin = client_pollin };
        apix_set_events(ctx, fd, &events);
        assert(fds[fd].fd == 0);
        fds[fd].fd = fd;
        snprintf(fds[fd].addr, sizeof(fds[fd].addr), "%s", addr);
        frontend = fd;
    }
}

static void on_cmd_com(const char *cmd)
{
    char addr[64] = {0};
    int nr = sscanf(cmd, "com %s", addr);
    if (nr == 1) {
        int fd = apix_open_serial(ctx, addr);
        if (fd == -1) {
            perror("open_com");
            return;
        }
        struct apix_events events = { .on_pollin = client_pollin };
        apix_set_events(ctx, fd, &events);
        struct ioctl_serial_param sp = {
            .baud = SERIAL_ARG_BAUD_115200,
            .bits = SERIAL_ARG_BITS_8,
            .parity = SERIAL_ARG_PARITY_N,
            .stop = SERIAL_ARG_STOP_1,
        };
        int rc = apix_ioctl(ctx, fd, 0, (unsigned long)&sp);
        assert(rc != -1);
        assert(fds[fd].fd == 0);
        fds[fd].fd = fd;
        snprintf(fds[fd].addr, sizeof(fds[fd].addr), "%s", addr);
        frontend = fd;
    }
}

static void on_cmd_default(const char *cmd)
{
    if (frontend != 0)
        apix_send(ctx, frontend, cmd, strlen(cmd));
}

static const struct cli_cmd cli_cmds[] = {
    { "help", on_cmd_help, "display the manual" },
    { "history", on_cmd_history, "display history of commands" },
    { "!", on_cmd_history_exec, "!<num>" },
    { "quit", on_cmd_quit, "exit cli" },
    { "ll", on_cmd_fds, "list fds" },
    { "fds", on_cmd_fds, "list fds" },
    { "front", on_cmd_front, "set frontend fd" },
    { "close", on_cmd_close, "close fd" },
    { "unix", on_cmd_unix, "use unix as frontend" },
    { "tcp", on_cmd_tcp, "use tcp as frontend" },
    { "com", on_cmd_com, "use com as frontend"},
    { NULL, NULL }
};

static const struct cli_cmd cli_cmd_default = {
    "default", on_cmd_default, "default"
};

static void *cli_thread(void *arg)
{
    cli_init("apix-debugger> ", cli_cmds, &cli_cmd_default);

    while (exit_flag == 0) {
        cli_run();
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
