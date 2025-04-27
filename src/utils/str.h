#ifndef NT_UTILS_STR_H
#define NT_UTILS_STR_H

#include <stddef.h>
#include "utils/socket.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct
{
    char*  buff;     /* Buffer address. */
    size_t capacity; /* Total buffer size. */
    size_t size;     /* Number of bytes, excluding null byte. */
} nt_strcat_t;

typedef struct
{
    int          flags;
    size_t       count;
    nt_strcat_t* sc;
} nt_bitdecoder_t;

/**
 * @brief Static initializer for #nt_strcat_t.
 * @param[in] buff  Buffer
 * @param[in] size  Buffer size.
 */
#define NT_STRCAT_INIT(buff, size) { buff, size, 0 }

#define NT_BITDECODER_INIT(flags, sc) { flags, 0, sc }
#define NT_BITDECODER_DECODE(bd, flag)                                                             \
    do                                                                                             \
    {                                                                                              \
        int f = flag;                                                                              \
        if ((bd)->flags & f)                                                                       \
        {                                                                                          \
            (bd)->flags &= ~f;                                                                     \
            nt_strcat((bd)->sc, "%s%s", ((bd)->count++ == 0) ? "" : "|", #flag);                   \
        }                                                                                          \
    } while (0)

#define NT_BITDECODER_FINISH(bd)                                                                   \
    do                                                                                             \
    {                                                                                              \
        if ((bd)->count == 0)                                                                      \
        {                                                                                          \
            nt_strcat((bd)->sc, "0x%x", (bd)->flags);                                              \
        }                                                                                          \
        else if ((bd)->flags != 0)                                                                 \
        {                                                                                          \
            nt_strcat((bd)->sc, "|0x%x", (bd)->flags);                                             \
        }                                                                                          \
    } while (0)

/**
 * @brief Append string into \p s.
 * @param[in] sc String context.
 * @param[in] fmt Format string.
 * @param[in] ... Format arguments.
 * @return The number of bytes written.
 */
int nt_strcat(nt_strcat_t* sc, const char* fmt, ...);

/**
 * @brief Dump \p buff as hex string.
 * @param[in] sc    String context.
 * @param[in] buff  Data
 * @param[in] size  Data size.
 */
int nt_strcat_dump(nt_strcat_t* sc, void* buff, size_t size);

/**
 * @brief
 * @param sc
 * @param prefix
 * @param ret
 * @param err
 */
void nt_strcat_ret(nt_strcat_t* sc, int64_t ret, int err);

/**
 * @brief Find the last \p needle in \p haystack.
 */
const char* nt_strrstr(const char* haystack, const char* needle);

/**
 * @brief Find the last \p needle in \p haystack. The \p haystack only search in first \p len bytes.
 */
const char* nt_strnrstr(const char* haystack, size_t len, const char* needle);

const char* nt_strerrorname(int code);

int nt_str_sysdump_iovec(nt_strcat_t* sc, pid_t pid, uintptr_t iov, int iovcnt, size_t maxsize);
int nt_str_dump_msghdr(const struct msghdr* msg, pid_t pid, nt_strcat_t* sc);

int nt_str_sysdump(nt_strcat_t* sc, pid_t pid, uintptr_t addr, size_t size);

#ifdef __cplusplus
}
#endif
#endif
