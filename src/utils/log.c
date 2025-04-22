#include <stdarg.h>
#include <stdio.h>
#include <time.h>
#include <sys/time.h>
#include "log.h"

static const char*    s_log_str[] = { "T", "D", "I", "W", "E" };
static nt_log_level_t s_log_level = NT_LOG_INFO;

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
    (void)func;
    if (level < s_log_level)
    {
        return;
    }

    struct timeval cur_time;
    gettimeofday(&cur_time, NULL);

    struct tm t;
    localtime_r(&cur_time.tv_sec, &t);

    char time_buf[64];
    strftime(time_buf, sizeof(time_buf), "%Y-%m-%d %H:%M:%S", &t);

    file = nt_basename(file);
    fprintf(stdout, "[%s.%03d][%s][%s:%d] ", time_buf, (int)(cur_time.tv_usec / 1000),
            s_log_str[level], file, line);

    va_list ap;
    va_start(ap, fmt);
    vfprintf(stdout, fmt, ap);
    va_end(ap);

    fprintf(stdout, "\n");
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

void nt_log_set_level(nt_log_level_t level)
{
    s_log_level = level;
}
