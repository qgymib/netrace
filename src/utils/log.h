#ifndef NT_UTILS_LOG_H
#define NT_UTILS_LOG_H

#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#define LOG_T(fmt, ...) nt_log(NT_LOG_TRACE, __FILE__, __FUNCTION__, __LINE__, fmt, ##__VA_ARGS__)
#define LOG_D(fmt, ...) nt_log(NT_LOG_DEBUG, __FILE__, __FUNCTION__, __LINE__, fmt, ##__VA_ARGS__)
#define LOG_I(fmt, ...) nt_log(NT_LOG_INFO, __FILE__, __FUNCTION__, __LINE__, fmt, ##__VA_ARGS__)
#define LOG_W(fmt, ...) nt_log(NT_LOG_WARN, __FILE__, __FUNCTION__, __LINE__, fmt, ##__VA_ARGS__)
#define LOG_E(fmt, ...) nt_log(NT_LOG_ERROR, __FILE__, __FUNCTION__, __LINE__, fmt, ##__VA_ARGS__)

/**
 * @brief Assert condition is established.
 * @note It is not affected by #NDEBUG.
 */
#define NT_ASSERT(exp, fmt, ...)                                                                   \
    do                                                                                             \
    {                                                                                              \
        if (exp)                                                                                   \
        {                                                                                          \
            break;                                                                                 \
        }                                                                                          \
        fprintf(stderr, "%s:%d: %s: Assertion `%s` failed: " fmt "\n", __FILE__, __LINE__,         \
                __FUNCTION__, #exp, ##__VA_ARGS__);                                                \
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
    NT_LOG_TRACE = 0,
    NT_LOG_DEBUG,
    NT_LOG_INFO,
    NT_LOG_WARN,
    NT_LOG_ERROR,
} nt_log_level_t;

/**
 * @brief Logging function.
 * @note Use LOG_*() macros.
 * @param[in] level Log level.
 * @param[in] file  Source code file.
 * @param[in] func  Source code function.
 * @param[in] line  Source code line.
 * @param[in] fmt   Format string.
 * @param[in] ...   Format arguments.
 */
void nt_log(nt_log_level_t level, const char* file, const char* func, int line, const char* fmt,
            ...);

/**
 * @brief Dump hex.
 * @param[in] data  Data address.
 * @param[in] size  Data size.
 * @param[in] width Print width. 8 or 16 is fine.
 */
void nt_dump(const void* data, size_t size, size_t width);

/**
 * @brief Get file basename.
 * @param[in] path File path.
 * @return Base name.
 */
const char* nt_basename(const char* path);

/**
 * @brief Set log level.
 * @param[in] level Log level.
 */
void nt_log_set_level(nt_log_level_t level);

#ifdef __cplusplus
}
#endif
#endif
