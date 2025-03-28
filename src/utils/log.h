#ifndef NT_UTILS_LOG_H
#define NT_UTILS_LOG_H

#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#define LOG_D(fmt, ...) nt_log(NT_LOG_DEBUG, __FILE__, __FUNCTION__, __LINE__, fmt, ##__VA_ARGS__)
#define LOG_I(fmt, ...) nt_log(NT_LOG_INFO, __FILE__, __FUNCTION__, __LINE__, fmt, ##__VA_ARGS__)
#define LOG_W(fmt, ...) nt_log(NT_LOG_WARN, __FILE__, __FUNCTION__, __LINE__, fmt, ##__VA_ARGS__)
#define LOG_E(fmt, ...) nt_log(NT_LOG_ERROR, __FILE__, __FUNCTION__, __LINE__, fmt, ##__VA_ARGS__)

/**
 * @brief Assert condition is established.
 * @note It is not affected by #NDEBUG.
 */
#define NT_ASSERT(a, OP, b, fmt, ...)                                                              \
    do                                                                                             \
    {                                                                                              \
        if ((a)OP(b))                                                                              \
        {                                                                                          \
            break;                                                                                 \
        }                                                                                          \
        fprintf(stderr, "%s:%d: %s: Assertion `%s %s %s` failed: " fmt ".\n", __FILE__, __LINE__,  \
                __FUNCTION__, #a, #OP, #b, ##__VA_ARGS__);                                         \
        abort();                                                                                   \
    } while (0)

/**
 * @brief Dump data into hex and print.
 */
#define NT_DUMP(data, size)                                                                        \
    do                                                                                             \
    {                                                                                              \
        LOG_D("DUMP: %s:", #data);                                                                 \
        nt_dump(data, size, 16);                                                                   \
    } while (0)

#ifdef __cplusplus
extern "C" {
#endif

typedef enum nt_log_level
{
    NT_LOG_TRACE,
    NT_LOG_DEBUG,
    NT_LOG_INFO,
    NT_LOG_WARN,
    NT_LOG_ERROR,
    NT_LOG_FATAL,
} nt_log_level_t;

void nt_log(nt_log_level_t level, const char* file, const char* func, int line, const char* fmt,
            ...);
void nt_dump(const void* data, size_t size, size_t width);
const char* nt_basename(const char* path);

#ifdef __cplusplus
}
#endif
#endif
