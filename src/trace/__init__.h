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
typedef int (*nt_syscall_decode_fn)(const nt_syscall_info_t* si, int op, char* buff, size_t size);

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
int nt_trace_dump(const nt_syscall_info_t* si, int op, char* buff, size_t size);

/**
 * @brief Syscall decode functions.
 * @{
 */
int nt_syscall_decode_accept(const nt_syscall_info_t* si, int op, char* buff, size_t size);
int nt_syscall_decode_accept4(const nt_syscall_info_t* si, int op, char* buff, size_t size);
int nt_syscall_decode_access(const nt_syscall_info_t* si, int op, char* buff, size_t size);
int nt_syscall_decode_bind(const nt_syscall_info_t* si, int op, char* buff, size_t size);
int nt_syscall_decode_clone(const nt_syscall_info_t* si, int op, char* buff, size_t size);
int nt_syscall_decode_close(const nt_syscall_info_t* si, int op, char* buff, size_t size);
int nt_syscall_decode_close_range(const nt_syscall_info_t* si, int op, char* buff, size_t size);
int nt_syscall_decode_connect(const nt_syscall_info_t* si, int op, char* buff, size_t size);
int nt_syscall_decode_dup(const nt_syscall_info_t* si, int op, char* buff, size_t size);
int nt_syscall_decode_dup2(const nt_syscall_info_t* si, int op, char* buff, size_t size);
int nt_syscall_decode_dup3(const nt_syscall_info_t* si, int op, char* buff, size_t size);
int nt_syscall_decode_execve(const nt_syscall_info_t* si, int op, char* buff, size_t size);
int nt_syscall_decode_faccessat(const nt_syscall_info_t* si, int op, char* buff, size_t size);
int nt_syscall_decode_fcntl(const nt_syscall_info_t* si, int op, char* buff, size_t size);
int nt_syscall_decode_getcwd(const nt_syscall_info_t* si, int op, char* buff, size_t size);
int nt_syscall_decode_getpeername(const nt_syscall_info_t* si, int op, char* buff, size_t size);
int nt_syscall_decode_getpid(const nt_syscall_info_t* si, int op, char* buff, size_t size);
int nt_syscall_decode_getsockname(const nt_syscall_info_t* si, int op, char* buff, size_t size);
int nt_syscall_decode_getuid(const nt_syscall_info_t* si, int op, char* buff, size_t size);
int nt_syscall_decode_ioctl(const nt_syscall_info_t* si, int op, char* buff, size_t size);
int nt_syscall_decode_listen(const nt_syscall_info_t* si, int op, char* buff, size_t size);
int nt_syscall_decode_openat(const nt_syscall_info_t* si, int op, char* buff, size_t size);
int nt_syscall_decode_pipe2(const nt_syscall_info_t* si, int op, char* buff, size_t size);
int nt_syscall_decode_pread64(const nt_syscall_info_t* si, int op, char* buff, size_t size);
int nt_syscall_decode_preadv(const nt_syscall_info_t* si, int op, char* buff, size_t size);
int nt_syscall_decode_preadv2(const nt_syscall_info_t* si, int op, char* buff, size_t size);
int nt_syscall_decode_pwrite64(const nt_syscall_info_t* si, int op, char* buff, size_t size);
int nt_syscall_decode_pwritev(const nt_syscall_info_t* si, int op, char* buff, size_t size);
int nt_syscall_decode_pwritev2(const nt_syscall_info_t* si, int op, char* buff, size_t size);
int nt_syscall_decode_read(const nt_syscall_info_t* si, int op, char* buff, size_t size);
int nt_syscall_decode_readv(const nt_syscall_info_t* si, int op, char* buff, size_t size);
int nt_syscall_decode_recvfrom(const nt_syscall_info_t* si, int op, char* buff, size_t size);
int nt_syscall_decode_recvmsg(const nt_syscall_info_t* si, int op, char* buff, size_t size);
int nt_syscall_decode_sendfile(const nt_syscall_info_t* si, int op, char* buff, size_t size);
int nt_syscall_decode_sendmmsg(const nt_syscall_info_t* si, int op, char* buff, size_t size);
int nt_syscall_decode_sendmsg(const nt_syscall_info_t* si, int op, char* buff, size_t size);
int nt_syscall_decode_sendto(const nt_syscall_info_t* si, int op, char* buff, size_t size);
int nt_syscall_decode_setsockopt(const nt_syscall_info_t* si, int op, char* buff, size_t size);
int nt_syscall_decode_shutdown(const nt_syscall_info_t* si, int op, char* buff, size_t size);
int nt_syscall_decode_socket(const nt_syscall_info_t* si, int op, char* buff, size_t size);
int nt_syscall_decode_socketpair(const nt_syscall_info_t* si, int op, char* buff, size_t size);
int nt_syscall_decode_write(const nt_syscall_info_t* si, int op, char* buff, size_t size);
int nt_syscall_decode_writev(const nt_syscall_info_t* si, int op, char* buff, size_t size);
/**
 * @}
 */

#ifdef __cplusplus
}
#endif
#endif
