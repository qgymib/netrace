#ifndef NT_UTILS_SOCKET_H
#define NT_UTILS_SOCKET_H

#include <stdint.h>
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
 * @brief Set or remove close-on-exec flag.
 * @param[in] fd  FD.
 * @param[in] set Is set.
 * @return 0 if success, errno if failed.
 */
int nt_cloexec(int fd, int set);

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

/**
 * @brief Get socket type name.
 * @param[in] type
 * @return Name string.
 */
const char* nt_socktype_name(int type);

/**
 * @brief Like socket(), but set nonblock flag.
 */
int nt_socket(int domain, int type, int nonblock);

/**
 * @brief Create a socket, bind to address, and get bind address.
 * @param[in] type      #SOCK_STREAM or #SOCK_DGRAM
 * @param[in] ip        Local IP
 * @param[in] port      Local Port.
 * @param[in] nonblock  Set non-block mode.
 * @param[out] addr     (Optional) Bind address.
 * @return              Socket handle.
 */
int nt_socket_bind(int type, const char* ip, int port, int nonblock, struct sockaddr_storage* addr);

/**
 * @brief Create a socket, bind to address, and get bind address.
 * @param[in] type      #SOCK_STREAM or #SOCK_DGRAM
 * @param[in] nonblock  Set non-block mode.
 * @param[in,out] addr  Bind address.
 * @return              Socket handle.
 */
int nt_socket_bind_r(int type, int nonblock, struct sockaddr_storage* addr);

/**
 * @brief Create a TCP socket, and start listen.
 * @param[in] ip        Local IP.
 * @param[in] port      Local port.
 * @param[in] nonblock  Set non-block mode.
 * @param[out] addr     Bind address.
 * @return              Socket handle.
 */
int nt_socket_listen(const char* ip, int port, int nonblock, struct sockaddr_storage* addr);

/**
 * @brief Like accept(), but handle #EINTR.
 */
int nt_accept(int fd);

/**
 * @brief Create a socket and connect to \p addr.
 * @param[in] type      #SOCK_STREAM or #SOCK_DGRAM
 * @param[in] addr      Peer address.
 * @param[in] nonblock  Non-block flag.
 * @return              Socket handle.
 */
int nt_socket_connect(int type, const struct sockaddr_storage* addr, int nonblock);

/**
 * @brief Convert domain into string.
 * @param[in] domain AF_INET / AF_INET6
 * @return String.
 */
const char* nt_socket_domain_name(int domain);

/**
 * @brief Convert type into string.
 * @param[in] type SOCK_STREAM / SOCK_DGRAM
 * @return String.
 */
const char* nt_socket_type_name(int type);

#ifdef __cplusplus
}
#endif
#endif
