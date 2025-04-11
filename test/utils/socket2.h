#ifndef NT_TEST_UTILS_SOCKET_H
#define NT_TEST_UTILS_SOCKET_H

#include "utils/socket.h"

#ifdef __cplusplus
extern "C" {
#endif

#define NT_TIMEOUT_INFINITE ((uint32_t)(-1))

/**
 * @brief accept() with timeout.
 * @param[in] timeout Timeout in millisecond.
 * @return >=0 if success, <0 if error.
 */
int nt_accept_timed(int sockfd, struct sockaddr* addr, socklen_t* addrlen, uint32_t timeout);

int nt_send_timed(int sockfd, const void* data, size_t size, uint32_t timeout);

int nt_recv_timed(int sockfd, void* data, size_t size, uint32_t timeout);

#ifdef __cplusplus
}
#endif
#endif
