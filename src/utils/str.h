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
 * @brief Appends formatted error and return value details to a string buffer.
 * @param[in,out] sc String context used for concatenation operations.
 * @param[in] ret Return value from a system call.
 * @param[in] err Error indicator; non-zero if an error occurred, otherwise zero.
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

/**
 * @brief Retrieves the string representation of an error code.
 * @param[in] code The error code to be converted to its string representation.
 * @return A pointer to the string representation of the error code, or NULL if the error code is
 * not recognized.
 */
const char* nt_strerrorname(int code);

/**
 * @brief Dumps the contents of an iovec structure for a specific process.
 * @param[in] sc String context for appending the result string.
 * @param[in] pid Process ID associated with the iovec structure.
 * @param[in] iov Address of the iovec array in the target process memory.
 * @param[in] iovcnt Number of iovec structures to process.
 * @param[in] maxsize Maximum size of data to dump from the iovec structures.
 * @return The number of bytes written to the string context.
 */
int nt_str_sysdump_iovec(nt_strcat_t* sc, pid_t pid, uintptr_t iov, int iovcnt, size_t maxsize);

/**
 * @brief Dump the contents of a message header into a string.
 * @param[in] sc The string context where the content will be appended.
 * @param[in] pid The process ID from which the message data originates.
 * @param[in] msg A pointer to the message header (`struct msghdr`) to be dumped.
 * @return The total number of bytes written to the string context.
 */
int nt_str_sysdump_msghdr(nt_strcat_t* sc, pid_t pid, const struct msghdr* msg);

/**
 * @brief Dumps a memory region from a process's address space into the provided string context.
 * @param[in] sc String context to concatenate the dumped data.
 * @param[in] pid Process ID of the target process.
 * @param[in] addr Starting address of the memory region to be dumped.
 * @param[in] size Total size of the memory region to be dumped.
 * @param[in] maxsize Maximum size of the dump output for the memory region.
 * @return The number of bytes written to \p sc, including metadata.
 */
int nt_str_sysdump(nt_strcat_t* sc, pid_t pid, uintptr_t addr, size_t size, size_t maxsize);

/**
 * @brief Dump c string.
 * @param[in] sc  String context.
 * @param[in] pid Process ID.
 * @param[in] addr `const char*` compatible address.
 * @param[in] maxsize Max dump size.
 * @return Bytes written.
 */
int nt_str_sysdump_str(nt_strcat_t* sc, pid_t pid, uintptr_t addr, size_t maxsize);

/**
 * @brief Dump socket address from a specified process's memory space into the given string context.
 * @param[in] sc String context to store the formatted output.
 * @param[in] pid Process ID of the target process.
 * @param[in] addr Address of the socket structure in the target process's memory.
 * @param[in] len Length of the socket address structure.
 * @return Dump size on success, or a negative error code on failure.
 */
int nt_str_sysdump_sockaddr(nt_strcat_t* sc, pid_t pid, uintptr_t addr, size_t len);

/**
 * @brief Dumps a string representation of a sockaddr structure into the string context.
 * @param[in,out] sc String context where the output will be appended.
 * @param[in] addr Pointer to the sockaddr structure to be dumped.
 * @return The number of bytes written to the string context.
 */
int nt_str_dump_sockaddr(nt_strcat_t* sc, const struct sockaddr* addr);

#ifdef __cplusplus
}
#endif
#endif
