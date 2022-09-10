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

#define FEND_UNIX 0
#define FEND_TCP 1
#define FEND_COM 2

static int exit_flag;
static int frontend;

static struct apix *ctx;
static int fd_unix;
static int fd_tcp;
static int fd_com;

static void signal_handler(int sig)
{
    exit_flag = 1;
}

static struct opt opttab[] = {
    INIT_OPT_BOOL("-h", "help", false, "print this usage"),
    INIT_OPT_BOOL("-D", "debug", false, "debug mode [defaut: false]"),
    INIT_OPT_STRING("-u:", "unix", "", "unix domain"),
    INIT_OPT_STRING("-t:", "tcp", "", "tcp socket"),
    INIT_OPT_STRING("-s:", "serial", "", "serial dev file"),
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

    printf("%s", buf);

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
    struct opt *serial = find_opt("serial", opttab);

    ctx = apix_new();
    apix_enable_posix(ctx);

    if (strcmp(opt_string(ud), "") != 0) {
        fd_unix = apix_open_unix_client(ctx, opt_string(ud));
        if (fd_unix == -1) {
            perror("open_unix");
            exit(1);
        }
        apix_set_poll_callback(ctx, fd_unix, client_pollin, NULL);
    }

    if (strcmp(opt_string(tcp), "") != 0) {
        fd_tcp = apix_open_tcp_client(ctx, opt_string(tcp));
        if (fd_tcp == -1) {
            perror("open_tcp");
            exit(1);
        }
        apix_set_poll_callback(ctx, fd_tcp, client_pollin, NULL);
    }

    if (strcmp(opt_string(serial), "") != 0) {
        fd_com = apix_open_serial(ctx, opt_string(serial));
        if (fd_com == -1) {
            perror("open_serial");
            exit(1);
        }
        apix_set_poll_callback(ctx, fd_com, client_pollin, NULL);
        struct ioctl_serial_param sp = {
            .baud = SERIAL_ARG_BAUD_115200,
            .bits = SERIAL_ARG_BITS_8,
            .parity = SERIAL_ARG_PARITY_N,
            .stop = SERIAL_ARG_STOP_1,
        };
        int rc = apix_ioctl(ctx, fd_com, 0, (unsigned long)&sp);
        assert(rc != -1);
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

static void on_cmd_unix(const char *cmd)
{
    frontend = FEND_UNIX;
}

static void on_cmd_tcp(const char *cmd)
{
    frontend = FEND_TCP;
}

static void on_cmd_com(const char *cmd)
{
    frontend = FEND_COM;
}

static void on_cmd_default(const char *cmd)
{
    if (frontend == FEND_UNIX) {
        apix_send(ctx, fd_unix, cmd, strlen(cmd));
    } else if (frontend == FEND_TCP) {
        apix_send(ctx, fd_tcp, cmd, strlen(cmd));
    } else if (frontend == FEND_COM) {
        apix_send(ctx, fd_com, cmd, strlen(cmd));
    }
}

static const struct cli_cmd cli_cmds[] = {
    { "help", on_cmd_help, "display the manual" },
    { "history", on_cmd_history, "display history of commands" },
    { "!", on_cmd_history_exec, "!<num>" },
    { "quit", on_cmd_quit, "exit cli" },
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
