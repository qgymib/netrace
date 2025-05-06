#ifndef NT_RUNTIME_CHAIN_H
#define NT_RUNTIME_CHAIN_H

#include "proxy/__init__.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct nt_chain nt_chain_t;

/**
 * @brief Create chain layer.
 * @param[out] chain Handle.
 * @return 0 if success, or error code.
 */
int nt_chain_init(nt_chain_t** chain);

/**
 * @brief Destroy chain layer.
 * @param[in] chain Handle.
 */
void nt_chain_exit(nt_chain_t* chain);

/**
 * @brief Create a new proxy channel.
 * @param[in] chain Chain layer.
 * @param[in] type Data type. #SOCK_STREAM or #SOCK_DGRAM
 * @param[in] peeraddr Channel peer address.
 * @param[out] proxyaddr For SOCK_STREAM, this is the address connect to. For SOCK_DGRAM, this is
 * the address sendto.
 * @param[in] proxy The proxy to use.
 * @return Chain ID.
 */
int nt_chain_new(nt_chain_t* chain, int type, const struct sockaddr* peeraddr,
                 struct sockaddr_storage* proxyaddr, nt_proxy_t* proxy);

/**
 * @brief Delete a channel.
 * @param[in] chain Chain layer.
 * @param[in] id Chain ID.
 */
void nt_chain_delete(nt_chain_t* chain, int id);

#ifdef __cplusplus
}
#endif
#endif
