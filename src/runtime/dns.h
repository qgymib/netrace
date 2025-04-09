#ifndef NT_RUNTIME_DNS_H
#define NT_RUNTIME_DNS_H

#include <arpa/inet.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct nt_dns_proxy nt_dns_proxy_t;

typedef struct nt_dns_proxy_config
{
    struct sockaddr_storage local_addr; /* Local DNS listen address. */
    struct sockaddr_storage peer_addr;  /* Remote DNS server address. */
} nt_dns_proxy_config_t;

/**
 * @brief Create DNS server.
 * @param[out] proxy Server handle.
 * @param[in] config Configuration.
 * @return 0 if success, errno if failed.
 */
int nt_dns_proxy_create(nt_dns_proxy_t** proxy, const nt_dns_proxy_config_t* config);

/**
 * @brief Destroy DNS server.
 * @param[in] proxy Server handle.
 */
void nt_dns_proxy_destroy(nt_dns_proxy_t* proxy);

/**
 * @brief Get local bind address.
 * @param[in] proxy Proxy handle.
 * @return  Bind address.
 */
void nt_dns_proxy_local_addr(const nt_dns_proxy_t* proxy, struct sockaddr_storage* addr);

#ifdef __cplusplus
}
#endif
#endif
