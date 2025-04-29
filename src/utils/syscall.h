#ifndef NT_UTILS_SYSCALL_H
#define NT_UTILS_SYSCALL_H

#include <stdint.h>
#include <sys/types.h>
#include <netinet/in.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef union nt_syscall_word {
    unsigned long val;
    unsigned char buf[sizeof(unsigned long)];
} nt_syscall_word_t;

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
void nt_syscall_getdata(pid_t pid, uintptr_t addr, void* dst, size_t len);

/**
 * @brief Set data to program's space.
 * @param[in] pid   Process ID.
 * @param[in] addr  Address in program space.
 * @param[in] src   Source data.
 * @param[in] len   Data length.
 */
void nt_syscall_setdata(pid_t pid, uintptr_t addr, const void* src, size_t len);

/**
 * @brief Get socket address.
 * @param[in]  pid  Process ID.
 * @param[in]  addr  Address to read.
 * @param[out] data Socket address storage.
 * @param[in] size Max read size.
 */
int nt_syscall_get_sockaddr(pid_t pid, uintptr_t addr, struct sockaddr_storage* data, size_t size);

/**
 * @brief Set socket address.
 * @param[in] pid   Process ID.
 * @param[in] addr  Address.
 * @param[in] data  Socket address.
 * @param[in] size Max write size.
 */
int nt_syscall_set_sockaddr(pid_t pid, uintptr_t addr, const struct sockaddr_storage* data,
                            size_t size);

/**
 * @brief Get string.
 * @param[in] pid Process ID.
 * @param[in] addr Address.
 * @param[in] buff Buffer.
 * @param[in] size Buffer size.
 * @return The number of bytes written, excluding null byte.
 */
int nt_syscall_get_string(pid_t pid, uintptr_t addr, char* buff, size_t size);

#ifdef __cplusplus
}
#endif
#endif
