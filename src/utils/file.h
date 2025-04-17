#ifndef NT_UTILS_FILE_H
#define NT_UTILS_FILE_H

#include "utils/cstr.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Read file.
 * @param[in] path    File path.
 * @return File content.
 */
c_str_t nt_read_file(const char* path);

/**
 * @brief Get environment value.
 * @param[in] env Environment key.
 * @return Value, or NULL if not found.
 */
c_str_t nt_getenv(const char* env);

/**
 * @brief Get executable path.
 * @return Path.
 */
c_str_t nt_exepath(void);

/**
 * @brief Get directory components.
 */
c_str_t nt_dirname(const c_str_t path);

#ifdef __cplusplus
}
#endif
#endif
