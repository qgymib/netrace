#ifndef NT_RUNTIME_DNS_H
#define NT_RUNTIME_DNS_H
#ifdef __cplusplus
extern "C" {
#endif

typedef struct nt_dns_proxy nt_dns_proxy_t;

typedef struct nt_dns_proxy_config
{
    const char* ip;
    int         port;
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

#ifdef __cplusplus
}
#endif
#endif
