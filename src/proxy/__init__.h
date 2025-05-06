#ifndef NT_PROXY_INIT_H
#define NT_PROXY_INIT_H

#include <netinet/in.h>
#include "utils/urlparser.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct nt_proxy
{
    /**
     * @brief Release this object.
     * @param[in] thiz  Object handle.
     */
    void (*release)(struct nt_proxy* thiz);

    /**
     * @brief Create a channel for proxy data.
     * @param[in] thiz  Object handle.
     * @param[in] type SOCK_STREAM / SOCK_DGRAM
     * @param[in] sv  Socket channel.
     * @param[in] peeraddr Peer address.
     * @return Channel handle.
     */
    int (*channel_create)(struct nt_proxy* thiz, int type, int sv, const struct sockaddr* peeraddr);

    /**
     * @brief Release a channel.
     * @param[in] thiz  Object handle.
     * @param[in] channel Channel.
     */
    void (*channel_release)(struct nt_proxy* thiz, int channel);
} nt_proxy_t;

typedef struct nt_proxy_protocol
{
    /**
     * @brief Scheme.
     *
     * ```
     * URI = scheme ":" ["//" authority] path ["?" query] ["#" fragment]
     * ```
     */
    const char* scheme;

    /**
     * @brief Create a new proxy object.
     * @param[out] proxy Proxy object.
     * @param[in] url URL.
     * @return 0 if success, errno if failed.
     */
    int (*make)(nt_proxy_t** proxy, const url_comp_t* url);
} nt_proxy_protocol_t;

extern const nt_proxy_protocol_t nt_proxy_protocol_raw;
extern const nt_proxy_protocol_t nt_proxy_protocol_socks5;

/**
 * @brief Create a proxy object.
 * @param[out] proxy Proxy object.
 * @param[in] url Url.
 * @return 0 if success, errno if failed.
 */
int nt_proxy_create(nt_proxy_t** proxy, const char* url);

#ifdef __cplusplus
}
#endif
#endif
