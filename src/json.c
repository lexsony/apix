#include "json.h"
#include <assert.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

struct json_object {
    int errno;
    char *raw;
    const char *walk_idx;
};

struct json_object *json_object_new(const char *str)
{
    struct json_object *jo = malloc(sizeof(*jo));
    memset(jo, 0, sizeof(*jo));
    jo->raw = strdup(str);
    jo->walk_idx = jo->raw;
    return jo;
}

void json_object_delete(struct json_object *jo)
{
    assert(jo);
    free(jo->raw);
    free(jo);
}

static int json_walk(struct json_object *jo, const char *str, const char *path)
{
    assert(path[0] == '/');
    assert(path[1] != 0);

    char *path_next = strchr(path + 1, '/');

    // recursive fininshed
    if (path_next == NULL) {
        const char *key = path + 1;
        int brace_cnt = 0;

        for (size_t i = 0; i < strlen(str); i++) {
                if (str[i] == '{') {
                    brace_cnt++;
                    continue;
                }
                if (str[i] == '}') {
                    brace_cnt--;
                    continue;
                }
                if (brace_cnt == 1) {
                    if (key[0] == str[i] &&
                        memcmp(key, str + i, strlen(key)) == 0) {
                        jo->walk_idx = str + i + strlen(key);
                        return 0;
                    }
                }
        }
        jo->errno = JSON_ERR_KEY;
        return -1;
    } else {
        char *key = malloc(path_next - path);
        memset(key, 0, path_next - path);
        memcpy(key, path + 1, path_next - path - 1);
        int find_key = 0;
        int brace_cnt = 0;

        for (size_t i = 0; i < strlen(str); i++) {
            if (find_key == 0) {
                if (str[i] == '{') {
                    brace_cnt++;
                    continue;
                }
                if (str[i] == '}') {
                    brace_cnt--;
                    continue;
                }
                if (brace_cnt == 1) {
                    if (key[0] == str[i] &&
                        memcmp(key, str + i, strlen(key)) == 0) {
                        find_key = 1;
                        i += strlen(key) - 1;
                        continue;
                    }
                }
            } else {
                if (str[i] == ' ' || str[i] == ':')
                    continue;
                if (str[i] != '{') {
                    jo->errno = JSON_ERR_TYPE;
                    free(key);
                    return -1;
                }
                free(key);
                return json_walk(jo, str + i, path_next);
            }
        }

        free(key);
        jo->errno = JSON_ERR_KEY;
        return -1;
    }
}

static int __json_get_string(struct json_object *jo, char *value, size_t size)
{
    assert(value != NULL);
    const char *str = jo->raw;

    for (size_t i = jo->walk_idx - jo->raw; i < strlen(jo->raw); i++) {
        if (str[i] == ' ' || str[i] == ':')
            continue;
        if (!isprint((uint8_t)str[i])) {
            jo->errno = JSON_ERR_TYPE;
            return -1;
        }
        char *value_end = NULL;
        size_t j = i;
        for (; j < strlen(str); j++) {
            if (value_end == NULL
                && isprint((uint8_t)str[j])
                && str[j] != ' '
                && str[j] != ','
                && str[j] != '}')
                continue;
            if (str[j] == ' ') {
                if (value_end == NULL)
                    value_end = (char *)(str + j);
                continue;
            }
            if (str[j] == ',' || str[j] == '}') {
                if (value_end == NULL)
                    value_end = (char *)(str + j);
                break;
            } else {
                jo->errno = JSON_ERR_TYPE;
                return -1;
            }
        }
        if (j == strlen(str)) {
            jo->errno = JSON_ERR_BRACE;
            return -1;
        }
        assert(value_end != NULL);
        if ((str[i] != '\'' && str[i] != '"') || str[i] != *(value_end-1)) {
            jo->errno = JSON_ERR_TYPE;
            return -1;
        }
        size_t cpy_cnt = value_end - str - i - 2;
        if (cpy_cnt > size - 1) cpy_cnt = size - 1;
        memcpy(value, str + i + 1, cpy_cnt);
        value[cpy_cnt] = 0;
        return 0;
    }

    jo->errno = JSON_ERR_TYPE;
    return -1;
}

int json_get_string(struct json_object *jo, const char *path, char *value, size_t size)
{
    int rc = json_walk(jo, jo->raw, path);
    if (rc != 0) return rc;
    return __json_get_string(jo, value, size);
}

static int __json_get_int(struct json_object *jo, int *value)
{
    assert(value != NULL);
    const char *str = jo->raw;

    for (size_t i = jo->walk_idx - jo->raw; i < strlen(jo->raw); i++) {
        if (str[i] == ' ' || str[i] == ':')
            continue;
        if (!isdigit((uint8_t)str[i])) {
            jo->errno = JSON_ERR_TYPE;
            return -1;
        }
        char *value_end = NULL;
        size_t j = i;
        for (; j < strlen(str); j++) {
            if (value_end == NULL && isdigit((uint8_t)str[j]))
                continue;
            if (str[j] == ' ') {
                if (value_end == NULL)
                    value_end = (char *)(str + j);
                continue;
            }
            if (str[j] == ',' || str[j] == '}') {
                if (value_end == NULL)
                    value_end = (char *)(str + j);
                break;
            } else {
                jo->errno = JSON_ERR_TYPE;
                return -1;
            }
        }
        if (j == strlen(str)) {
            jo->errno = JSON_ERR_BRACE;
            return -1;
        }
        assert(value_end != NULL);
        char tmp[32] = {0};
        memcpy(tmp, str + i, value_end - str - i);
        *value = atoi(tmp);
        return 0;
    }

    jo->errno = JSON_ERR_TYPE;
    return -1;
}

int json_get_int(struct json_object *jo, const char *path, int *value)
{
    int rc = json_walk(jo, jo->raw, path);
    if (rc != 0) return rc;
    return __json_get_int(jo, value);
}
