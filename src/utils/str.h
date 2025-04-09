#ifndef NT_UTILS_STR_H
#define NT_UTILS_STR_H

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct nt_str
{
    char*  data; /* String data. */
    size_t size; /* String size, not include terminal zero. */
} nt_str_t;

#define NT_STR_INIT { NULL, 0 }

typedef struct nt_str_arr
{
    size_t    size; /** The number of elements. */
    nt_str_t* data; /** String array. */
} nt_str_arr_t;

/**
 * @brief Release string.
 * @param[in] str String.
 */
void nt_str_free(nt_str_t* str);

/**
 * @brief Set string data.
 * @param[in] str   String container.
 * @param[in] s     C string.
 * @param[in] n     Number of bytes to copy.
 */
void nt_str_set(nt_str_t* str, const char* s, size_t n);

/**
 * @brief Append string.
 * @param[in] str   String container.
 * @param[in] s     C string.
 * @param[in] n     Number of bytes to copy.
 */
void nt_str_append(nt_str_t* str, const char* s, size_t n);

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
 * @brief Copy \p src into \p dst,
 * @param[in] dst Target array.
 * @param[in] src Source array.
 */
void nt_str_arr_copy(nt_str_arr_t* dst, const nt_str_arr_t* src);

/**
 * @brief Join string array into single string.
 * @param[out] dst  Target string.
 * @param[in] src   Source array.
 * @param[in] sep   Separator.
 */
void nt_str_arr_join(nt_str_t* dst, const nt_str_arr_t* src, const char* sep);

/**
 * @brief Release string array.
 * @param[in] arr   String array.
 */
void nt_str_arr_free(nt_str_arr_t* arr);

#ifdef __cplusplus
}
#endif
#endif
