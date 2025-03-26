#ifndef NT_TEST_UTILS_SOCKET_H
#define NT_TEST_UTILS_SOCKET_H

#include "utils/socket.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief accept() with timeout.
 * @param[in] timeout Timeout in millisecond.
 * @return >=0 if success, <0 if error.
 */
int nt_accept_timed(int sockfd, struct sockaddr* addr, socklen_t* addrlen, uint32_t timeout);

#ifdef __cplusplus
}
#endif
#endif
