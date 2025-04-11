#ifndef NT_UTILS_SYSCALL_H
#define NT_UTILS_SYSCALL_H

#include <sys/types.h>
#include <netinet/in.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Get syscall ID.
 * @param[in] pid   Process ID.
 */
long nt_syscall_get_id(pid_t pid);

/**
 * @brief Get syscall parameter.
 * @param[in] pid Process ID.
 * @param[in] idx Parameter index. 0-5.
 * @return Argument value.
 */
long nt_syscall_get_arg(pid_t pid, size_t idx);

/**
 * @brief Set syscall parameter.
 * @param[in] pid Process ID.
 * @param[in] idx Parameter index.
 * @param[in] val Parameter value.
 */
void nt_syscall_set_arg(pid_t pid, size_t idx, long val);

/**
 * @brief Get return value of syscall.
 * @param[in] pid   Process ID.
 * @return Return value.
 */
long nt_syscall_get_ret(pid_t pid);

/**
 * @brief Get data from program's space.
 * @param[in] pid   Process ID.
 * @param[in] addr  Address in program space.
 * @param[out] dst  Buffer to store data.
 * @param[in] len   Data length.
 */
void nt_syscall_getdata(pid_t pid, long addr, void* dst, size_t len);

/**
 * @brief Set data to program's space.
 * @param[in] pid   Process ID.
 * @param[in] addr  Address in program space.
 * @param[in] src   Source data.
 * @param[in] len   Data length.
 */
void nt_syscall_setdata(pid_t pid, long addr, const void* src, size_t len);

/**
 * @brief Get socket address.
 * @param[in]  pid  Process ID.
 * @param[in]  arg  Argument index, must type of (struct sockaddr*).
 * @param[out] data Socket address storage.
 * @return The address of argument.
 */
long nt_syscall_get_sockaddr(pid_t pid, int arg, struct sockaddr_storage* data);

/**
 * @brief Set socket address.
 * @param[in] pid   Process ID.
 * @param[in] addr  Address.
 * @param[in] data  Socket address.
 */
void nt_syscall_set_sockaddr(pid_t pid, long addr, const struct sockaddr_storage* data);

#ifdef __cplusplus
}
#endif
#endif
