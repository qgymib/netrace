#ifndef NT_RUNTIME_H
#define NT_RUNTIME_H

#include "dns.h"
#include "utils/map.h"
#include "utils/urlparser.h"
#include "utils/ipfilter.h"
#include "utils/cmdoption.h"

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
     * @param[in] peeraddr Peer address.
     * @param[out] proxyaddr For SOCK_STREAM, this is the address connect to. For SOCK_DGRAM, this
     * is the address sendto. It is
     * @return Channel handle.
     */
    int (*channel_create)(struct nt_proxy* thiz, int type, const struct sockaddr* peeraddr,
                          struct sockaddr_storage* proxyaddr);

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

typedef struct sock_node
{
    ev_map_node_t node;
    int           fd;       /* Return value of child's socket(). */
    int           domain;   /* socket(): AF_INET/AF_INET6. */
    int           type;     /* socket(): #SOCK_STREAM / #SOCK_DGRAM */
    int           protocol; /* socket(): particular protocol to be used with the socket. */
    int           channel;
    struct sockaddr_storage peer_addr; /* Orignal connect address. */
} sock_node_t;

typedef struct prog_node
{
    ev_map_node_t node;
    pid_t         pid;          /* Process ID. */
    ev_map_t      sock_map;     /* Program socket map. Type: #sock_node_t. */
    sock_node_t*  sock_last;    /* Last socket we are tracing. */
    int           syscall;      /* System call number. */
    int           b_setup;      /* Is setup done. */
    int           b_in_syscall; /* Is entry syscall. */
} prog_node_t;

typedef struct runtime
{


    nt_proxy_t*     proxy; /* Proxy object. */
    nt_ipfilter_t*  ipfilter;
    nt_dns_proxy_t* dns;
    int dns_chid;


    pid_t    prog_pid;         /* First child pid. */

    int      prog_exit_retval; /* First child exit code. */
    ev_map_t prog_map;         /* Program tracing map. Type: #prog_node_t. */
} runtime_t;

/**
 * @brief Global runtime.
 */
extern runtime_t* G;

extern const nt_proxy_protocol_t nt_proxy_protocol_raw;
extern const nt_proxy_protocol_t nt_proxy_protocol_socks5;

/**
 * @brief Initialize global runtime.
 * @param[in] argc  Argument count.
 * @param[in] argv  Argument list.
 */
void nt_runtime_init(const nt_cmd_opt_t* opt, pid_t pid);

/**
 * @brief Cleanup runtime.
 */
void nt_runtime_cleanup(void);

/**
 * @brief Release program node.
 * @warning The node must already removed from #runtime_t::prog_map.
 * @param[in] prog Program node.
 */
void nt_prog_node_release(prog_node_t* prog);

/**
 * @brief Release socket node.
 * @warning The node must already removed from #prog_node_t::sock_map.
 * @param[in] prog Program node.
 */
void nt_sock_node_release(sock_node_t* sock);

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
