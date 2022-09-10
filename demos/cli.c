#include "cli.h"
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <readline/readline.h>
#include <readline/history.h>

#define PROMPT_SIZE 4096

static char __prompt[PROMPT_SIZE];
static const struct cli_cmd *cmdtab;
static const struct cli_cmd *cmddef;

static void process_command(const char *cmd)
{
    assert(strlen(cmd));

    for (const struct cli_cmd *item = cmdtab; item->name != NULL; item++) {
        if (strncmp(cmd, item->name, strlen(item->name)) == 0) {
            item->func(cmd);
            return;
        }
    }

    cmddef->func(cmd);
}

static char *command_generator(const char *text, int state)
{
    static int list_index, len;
    const char *name;

    if (!state) {
        list_index = 0;
        len = strlen(text);
    }

    while ((name = cmdtab[list_index++].name)) {
        if (strncmp(name, text, len) == 0)
            return strdup(name);
    }

    return NULL;
}

static char **command_completion(const char *text, int start, int end)
{
    rl_attempted_completion_over = 1;
    rl_completer_quote_characters = "\"'";
    return rl_completion_matches(text, command_generator);
}

void on_cmd_help(const char *cmd)
{
    for (const struct cli_cmd *item = cmdtab; item->name != NULL; item++)
        printf(" %-10s\t%s\n", item->name, item->description);
}

void on_cmd_history(const char *cmd)
{
    HISTORY_STATE *state = history_get_history_state();
    int index = 0;
    for (HIST_ENTRY **item = state->entries;
         item != state->entries + state->length; item++)
        printf(" %d %s\n", index++, (*item)->line);
}

void on_cmd_history_exec(const char *cmd)
{
    int index = -1;
    sscanf(cmd, "!%d", &index);
    if (index == -1) {
        printf("%s: event not found\n", cmd);
        return;
    }

    HISTORY_STATE *state = history_get_history_state();
    if (index >= state->length) {
        printf("%s: event not found\n", cmd);
        return;
    }

    char *real_cmd = (*(state->entries + index))->line;
    remove_history(state->length - 1);
    add_history(real_cmd);

    process_command(real_cmd);
}

int cli_init(const char *prompt, const struct cli_cmd cmds[], const struct cli_cmd *def)
{
    snprintf(__prompt, PROMPT_SIZE, "%s", prompt);
    cmdtab = cmds;
    cmddef = def;

    rl_attempted_completion_function = command_completion;
    return 0;
}

int cli_close(void)
{
    return 0;
}

int cli_run(void)
{
    char *line = readline(__prompt);

    // skip EOF or empty line
    if (line && *line) {
        add_history(line);
        process_command(line);
    }

    free(line);
    return 0;
}
