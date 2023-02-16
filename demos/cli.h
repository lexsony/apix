#ifndef __INIT_CLI_H
#define __INIT_CLI_H

#ifdef __cplusplus
extern "C" {
#endif

struct cli_cmd {
    const char *name;
    void (*func)(const char *);
    const char *description;
};

void on_cmd_help(const char *cmd);
void on_cmd_history(const char *cmd);
void on_cmd_history_exec(const char *cmd);

int cli_init(const struct cli_cmd cmds[], const struct cli_cmd *def);
int cli_close(void);
int cli_run(const char *prompt);

#ifdef __cplusplus
}
#endif
#endif
