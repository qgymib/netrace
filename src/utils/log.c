#include <stdio.h>
#include "log.h"

#include <stdarg.h>

static const char* s_log_str[] = { "T", "D", "I", "E", "F" };

static const char* s_basename(const char* path)
{
    const char* pos = path;

    if (path == NULL)
    {
        return NULL;
    }

    for (; *path; ++path)
    {
        if (*path == '\\' || *path == '/')
        {
            pos = path + 1;
        }
    }
    return pos;
}

void nt_log(nt_log_level_t level, const char* file, const char* func, int line, const char* fmt, ...)
{
    file = s_basename(file);
    fprintf(stderr, "[%s][%s:%d][%s] ", s_log_str[level], file, line, func);

    va_list ap;
    va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    va_end(ap);

    fprintf(stderr, "\n");
}
