#ifndef NT_UTILS_SOCKET_H
#define NT_UTILS_SOCKET_H

#include <sys/socket.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Convert \p ip and \p port into socket \p addr.
 * @param[in] ip IP string.
 * @param[in] port Port number.
 * @param[out] addr Address to store result. It is recommand to use #sockaddr_storage.
 */
int nt_ip_addr(const char* ip, uint16_t port, struct sockaddr* addr);

/**
 * @brief Convert socket address into ip and port.
 * @param[in] addr Socket address.
 * @param[out] ip IP buffer.
 * @param[in] len IP buffer size.
 * @param[out] port Port number.
 * @return 0 for success, errno for failure.
 */
int nt_ip_name(const struct sockaddr* addr, char* ip, size_t len, int* port);

/**
 * @brief Set or remove nonblock flag.
 * @param[in] fd FD.
 * @param[in] set Is nonblock.
 * @return 0 if success, errno if failed.
 */
int nt_nonblock(int fd, int set);

/**
 * @brief Like read(), but handle #EINTR.
 */
ssize_t nt_read(int fd, void* buf, size_t size);

/**
 * @brief Like write(), but handle #EINTR.
 */
ssize_t nt_write(int fd, const void* buf, size_t size);

/**
 * @brief Copy socket address.
 * @param[out] dst  Destination. It is recommand to use `struct sockaddr_storage`.
 * @param[in] src Source. `struct sockaddr_in` or `struct sockaddr_in6`.
 */
void nt_sockaddr_copy(struct sockaddr* dst, const struct sockaddr* src);

#ifdef __cplusplus
}
#endif
#endif
