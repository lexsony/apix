#include "log.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <stdarg.h>
#include <time.h>
#include <sys/time.h>

#if defined(__unix__) || defined(__APPLE__)
#define CL_RESET "\033[0;0m"
#define CL_NORMAL CL_RESET
#define CL_NONE  CL_RESET
#define CL_WHITE "\033[1;29m"
#define CL_GRAY  "\033[1;30m"
#define CL_RED  "\033[1;31m"
#define CL_GREEN "\033[1;32m"
#define CL_YELLOW "\033[1;33m"
#define CL_BLUE  "\033[1;34m"
#define CL_MAGENTA "\033[1;35m"
#define CL_CYAN  "\033[1;36m"
#else
#define CL_RESET ""
#define CL_NORMAL CL_RESET
#define CL_NONE  CL_RESET
#define CL_WHITE ""
#define CL_GRAY  ""
#define CL_RED  ""
#define CL_GREEN ""
#define CL_YELLOW ""
#define CL_BLUE  ""
#define CL_MAGENTA ""
#define CL_CYAN  ""
#endif

static int limit = LOG_LV_INFO;

int log_set_level(int level)
{
    int previous = limit;
    limit = level;
    return previous;
}

static int __log_message(int level, const char *format, va_list ap)
{
    char prefix[40];

    switch (level) {
    case LOG_LV_NONE: // None
        strcpy(prefix, "");
        break;
    case LOG_LV_TRACE: // Bright Cyan, important stuff!
        strcpy(prefix, CL_CYAN"T"CL_RESET);
        break;
    case LOG_LV_DEBUG: // Bright Cyan, important stuff!
        strcpy(prefix, CL_CYAN"D"CL_RESET);
        break;
    case LOG_LV_INFO: // Bright White (Variable information)
        strcpy(prefix, CL_WHITE"I"CL_RESET);
        break;
    case LOG_LV_NOTICE: // Bright White (Less than a warning)
        strcpy(prefix, CL_WHITE"N"CL_RESET);
        break;
    case LOG_LV_WARN: // Bright Yellow
        strcpy(prefix, CL_YELLOW"W"CL_RESET);
        break;
    case LOG_LV_ERROR: // Bright Red (Regular errors)
        strcpy(prefix, CL_RED"E"CL_RESET);
        break;
    case LOG_LV_FATAL: // Bright Red (Fatal errors, abort(); if possible)
        strcpy(prefix, CL_RED"F"CL_RESET);
        break;
    default:
        printf("__log_message: Invalid level passed.\n");
        return 1;
    }

    struct timeval tmnow;
    char buf[32] = {0}, usec_buf[16] = {0};
    gettimeofday(&tmnow, NULL);
    strftime(buf, 30, "%Y-%m-%d %H:%M:%S", localtime(&tmnow.tv_sec));
    sprintf(usec_buf, ".%04d", (int)tmnow.tv_usec / 100);
    strcat(buf, usec_buf);

    printf("[%s] %s - ", buf, prefix);
    vprintf(format, ap);
    printf("\n");
    fflush(stdout);

    return 0;
}

int log_message(int level, const char *format, ...)
{
    int rc;
    va_list ap;

    assert(format && *format != '\0');

    if (level < limit && level != LOG_LV_NONE)
        return 0;

    va_start(ap, format);
    rc = __log_message(level, format, ap);
    va_end(ap);

    return rc;
}
