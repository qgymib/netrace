#ifndef NT_TRACE_INIT_H
#define NT_TRACE_INIT_H

#include <stddef.h>
#include <sys/types.h>
#include <sys/ptrace.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct nt_syscall_info
{
    pid_t                        pid;   /* Process ID. */
    struct __ptrace_syscall_info enter; /* op == PTRACE_SYSCALL_INFO_ENTRY */
    struct __ptrace_syscall_info leave; /* op == PTRACE_SYSCALL_INFO_EXIT */
} nt_syscall_info_t;

typedef struct
{
    char*  buff;     /* Buffer address. */
    size_t capacity; /* Total buffer size. */
    size_t size;     /* Number of bytes, excluding null byte. */
} nt_strcat_t;

#define NT_STRCAT_INIT(buff, size) { buff, size, 0 }

/**
 * @brief Syscall parameters and result decode function.
 *
 * The parameter must quote with `()`, the result will be `= value`.
 * The terminating null byte must always append.
 *
 * @param[in] si Process block.
 * @param[in] buff Buffer to store information.
 * @param[in] size Buffer size.
 * @return The number of bytes would have written if \p size is large enough, excluding the
 *   terminating null byte.
 */
typedef int (*nt_syscall_decode_fn)(const nt_syscall_info_t* si, char* buff, size_t size);

/**
 * @brief Get name of syscall.
 * @param[in] id System call ID.
 * @return Name.
 */
const char* nt_syscall_name(int id);

/**
 * @brief Decode and dump syscall.
 * @param[in] si System call information.
 * @param[in] buff Buffer.
 * @param[in] size Buffer size.
 * @return The number of bytes would have written.
 */
int nt_trace_dump(const nt_syscall_info_t* si, char* buff, size_t size);

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
void nt_strcat_dump(nt_strcat_t* sc, void* buff, size_t size);

int nt_syscall_decode_close(const nt_syscall_info_t* si, char* buff, size_t size);
int nt_syscall_decode_close_range(const nt_syscall_info_t* si, char* buff, size_t size);
int nt_syscall_decode_connect(const nt_syscall_info_t* si, char* buff, size_t size);
int nt_syscall_decode_getpeername(const nt_syscall_info_t* si, char* buff, size_t size);
int nt_syscall_decode_getsockname(const nt_syscall_info_t* si, char* buff, size_t size);
int nt_syscall_decode_ioctl(const nt_syscall_info_t* si, char* buff, size_t size);
int nt_syscall_decode_pread64(const nt_syscall_info_t* si, char* buff, size_t size);
int nt_syscall_decode_read(const nt_syscall_info_t* si, char* buff, size_t size);
int nt_syscall_decode_recvfrom(const nt_syscall_info_t* si, char* buff, size_t size);
int nt_syscall_decode_sendmmsg(const nt_syscall_info_t* si, char* buff, size_t size);
int nt_syscall_decode_setsockopt(const nt_syscall_info_t* si, char* buff, size_t size);
int nt_syscall_decode_socket(const nt_syscall_info_t* si, char* buff, size_t size);
int nt_syscall_decode_write(const nt_syscall_info_t* si, char* buff, size_t size);

#ifdef __cplusplus
}
#endif
#endif
