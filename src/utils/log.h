#ifndef NT_UTILS_LOG_H
#define NT_UTILS_LOG_H

#include <stdlib.h>
#include <string.h>

#define LOG_D(fmt, ...) nt_log(NT_LOG_DEBUG, __FILE__, __FUNCTION__, __LINE__, fmt, ##__VA_ARGS__)
#define LOG_I(fmt, ...) nt_log(NT_LOG_INFO, __FILE__, __FUNCTION__, __LINE__, fmt, ##__VA_ARGS__)
#define LOG_E(fmt, ...) nt_log(NT_LOG_ERROR, __FILE__, __FUNCTION__, __LINE__, fmt, ##__VA_ARGS__)

/**
 * @brief Fatal log
 * @warning A fatal log will abort the program.
 * @param[in] fmt Format string.
 */
#define LOG_F_ABORT(fmt, ...)                                                                                          \
    do                                                                                                                 \
    {                                                                                                                  \
        nt_log(NT_LOG_FATAL, __FILE__, __FUNCTION__, __LINE__, fmt, ##__VA_ARGS__);                                    \
        abort();                                                                                                       \
    } while (0)

#ifdef __cplusplus
extern "C" {
#endif

typedef enum nt_log_level
{
    NT_LOG_TRACE,
    NT_LOG_DEBUG,
    NT_LOG_INFO,
    NT_LOG_ERROR,
    NT_LOG_FATAL,
} nt_log_level_t;

void nt_log(nt_log_level_t level, const char* file, const char* func, int line, const char* fmt, ...);

#ifdef __cplusplus
}
#endif
#endif
