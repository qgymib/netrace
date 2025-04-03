#ifndef NT_UTILS_STR_H
#define NT_UTILS_STR_H

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct nt_str_arr
{
    size_t size; /** The number of elements. */
    char** data; /** String array. */
} nt_str_arr_t;

/**
 * @brief Find the last \p needle in \p haystack.
 */
const char* nt_strrstr(const char* haystack, const char* needle);

/**
 * @brief Find the last \p needle in \p haystack. The \p haystack only search in first \p len bytes.
 */
const char* nt_strnrstr(const char* haystack, size_t len, const char* needle);

/**
 * @brief Append string to array.
 * @param[in] arr   String array.
 * @param[in] str   String.
 * @param[in] len   String length.
 */
void nt_str_arr_append(nt_str_arr_t* arr, const char* str, size_t len);

/**
 * @brief Release string array.
 * @param[in] arr   String array.
 */
void nt_str_arr_free(nt_str_arr_t* arr);

#ifdef __cplusplus
}
#endif
#endif
