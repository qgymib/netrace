#ifndef NT_UTILS_MEMORY_H
#define NT_UTILS_MEMORY_H

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Allocate memory.
 * @note It never return NULL.
 * @note Use #nt_free() to free it.
 * @param[in] size Required size in bytes.
 * @return Memory address.
 */
void* nt_malloc(size_t size);

/**
 * @brief Same as calloc().
 * @note It never return NULL.
 */
void* nt_calloc(size_t nmemb, size_t size);

/**
 * @brief Same as realloc().
 * @note It never return NULL.
 */
void* nt_realloc(void* addr, size_t size);

/**
 * @brief Release memory.
 * @param[in] addr Memory address.
 */
void nt_free(void* addr);

/**
 * @brief Duplicate string.
 * @note It never return NULL.
 * @param[in] s String to duplicate.
 * @return Duplicated string.
 */
char* nt_strdup(const char* s);

#ifdef __cplusplus
}
#endif
#endif
