#ifndef C_STR_H
#define C_STR_H

#include "str.h"

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief C string type.
 */
typedef char* c_str_t;

/**
 * @brief C string array type.
 */
typedef c_str_t* c_str_arr_t;

/**
 * @brief Memory realloc function protocol.
 */
typedef void* (*c_str_realloc_fn)(void*, size_t);

/**
 * @brief Set realloc functon.
 * @param[in] func Realloc function.
 * @return The old function.
 */
c_str_realloc_fn c_str_set_realloc(c_str_realloc_fn func);

/**
 * @brief Release string or array.
 * @param[in] p Object handle.
 */
void c_str_free(void* p);

/**
 * @brief Create new string.
 * @param[in] s C string.
 * @return String.
 */
c_str_t c_str_new(const char* s);

/**
 * @brief Duplicate string.
 * @param[in] s Source string.
 * @return New string.
 */
c_str_t c_str_dup(const c_str_t s);

/**
 * @brief Create new string.
 * @param[in] s C string.
 * @param[in] n String length in bytes.
 * @return String.
 */
c_str_t c_str_new_len(const char* s, size_t n);

/**
 * @brief Catenates string \p s into string \p cs.
 * @param[in] cs String.
 * @param[in] s Source string.
 * @return New string.
 */
c_str_t c_str_cat(c_str_t cs, const char* s);

/**
 * @brief Catenates string \p s into string \p cs.
 * @param[in] cs String.
 * @param[in] s Source string.
 * @param[in] n String length in bytes.
 * @return New string.
 */
c_str_t c_str_cat_len(c_str_t cs, const char* s, size_t n);

/**
 * @brief Get substring.
 * @param[in] cs  Source string.
 * @param[in] pos Start position. If pos is larger than content length in \p cs, an empty string is
 *   returned.
 * @param[in] n   Max bytes.
 * @return  New string.
 */
c_str_t c_str_substr(const c_str_t cs, size_t pos, size_t n);

/**
 * @brief Create a new string array.
 * @return String array.
 */
c_str_arr_t c_str_arr_new(void);

/**
 * @brief Get length of \p s.
 * @param[in] s String object.
 * @return Data length.
 */
size_t c_str_len(const c_str_t s);

/**
 * @brief Get the number of strings in the array.
 * @param[in] arr String array.
 * @return The number of strings.
 */
size_t c_str_arr_len(const c_str_arr_t arr);

/**
 * @brief Catenates string \p s into array \p arr.
 * @param[in] arr String array. If NULL, a new array will be created.
 * @param[in] s   String
 * @return The new string array.
 */
c_str_arr_t c_str_arr_cat(c_str_arr_t arr, const char* s);

/**
 * @brief Append string to array.
 * @param[in] arr String array. If NULL, a new array will be created.
 * @param[in] s String.
 * @param[in] n String length.
 * @return New array. The old one \p arr is invalid if return value is not NULL.
 */
c_str_arr_t c_str_arr_cat_len(c_str_arr_t arr, const char* s, size_t n);

/**
 * @brief Duplicate string array.
 * @param[in] arr String array.
 * @return String array.
 */
c_str_arr_t c_str_arr_dup(const c_str_arr_t arr);

/**
 * @brief Split string into array.
 * @param[in] s Source string.
 * @param[in] delim Split string.
 * @return String array. Use #c_str_free() to release it.
 */
c_str_arr_t c_str_split(c_str_t s, const char* delim);

#ifdef __cplusplus
}
#endif
#endif
