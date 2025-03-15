#ifndef NT_RUNTIME_SOCKS5_H
#define NT_RUNTIME_SOCKS5_H

#include "__init__.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Create a socks5 proxy.
 * @param[out] proxy Proxy object.
 * @param[in] url   Url.
 * @return 0 if success, errno if failed.
 */
int nt_proxy_socks5_create(nt_proxy_t** proxy, const char* url);

#ifdef __cplusplus
}
#endif
#endif
