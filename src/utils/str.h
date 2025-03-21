#ifndef NT_UTILS_STR_H
#define NT_UTILS_STR_H
#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Find the last \p needle in \p haystack.
 */
const char* nt_strrstr(const char* haystack, const char* needle);

#ifdef __cplusplus
}
#endif
#endif
