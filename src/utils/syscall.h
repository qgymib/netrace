#ifndef NT_UTILS_SYSCALL_H
#define NT_UTILS_SYSCALL_H

#include <sys/types.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Get syscall ID.
 * @param[in] pid   Process ID.
 */
long nt_get_syscall_id(pid_t pid);

/**
 * @brief Get syscall parameter.
 * @param[in] pid Process ID.
 * @param[in] idx Parameter index. 0-5.
 */
long nt_get_syscall_arg(pid_t pid, size_t idx);

/**
 * @brief Get return value of syscall.
 * @param[in] pid   Process ID.
 * @return Return value.
 */
long nt_get_syscall_ret(pid_t pid);

#ifdef __cplusplus
}
#endif
#endif
