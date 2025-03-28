#include <stdio.h>
#include "log.h"

#include <stdarg.h>

static const char* s_log_str[] = { "T", "D", "I", "W", "E", "F" };

static char _ev_ascii_to_char(unsigned char c)
{
    if (c >= 32 && c <= 126)
    {
        return c;
    }
    return '.';
}

const char* nt_basename(const char* path)
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

void nt_log(nt_log_level_t level, const char* file, const char* func, int line, const char* fmt,
            ...)
{
    file = nt_basename(file);
    fprintf(stderr, "[%s][%s:%d][%s] ", s_log_str[level], file, line, func);

    va_list ap;
    va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    va_end(ap);

    fprintf(stderr, "\n");
}

void nt_dump(const void* data, size_t size, size_t width)
{
    const unsigned char* pdat = (unsigned char*)data;

    size_t idx_line;
    for (idx_line = 0; idx_line < size; idx_line += width)
    {
        size_t idx_colume;
        /* printf hex */
        for (idx_colume = 0; idx_colume < width; idx_colume++)
        {
            const char* postfix = (idx_colume < width - 1) ? "" : "|";

            if (idx_colume + idx_line < size)
            {
                fprintf(stdout, "%02x %s", pdat[idx_colume + idx_line], postfix);
            }
            else
            {
                fprintf(stdout, "   %s", postfix);
            }
        }
        fprintf(stdout, " ");
        /* printf char */
        for (idx_colume = 0; (idx_colume < width) && (idx_colume + idx_line < size); idx_colume++)
        {
            fprintf(stdout, "%c", _ev_ascii_to_char(pdat[idx_colume + idx_line]));
        }
        fprintf(stdout, "\n");
    }
}
