#ifndef NT_RUNTIME_H
#define NT_RUNTIME_H

#include <netinet/in.h>
#include "utils/map.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct nt_channel
{
    /**
     * @brief Release this object.
     * @param[in] thiz  Object handle.
     */
    void (*release)(struct nt_channel* thiz);

    /**
     * @brief Get proxy address.
     *
     * For SOCK_STREAM, this is the address connect to. For SOCK_DGRAM, this is the address sendto.
     *
     * @param[in] thiz  Object handle.
     * @param[out] addr Proxy address.
     * @return 0 for success, errno for failed.
     */
    int (*proxy_addr)(struct nt_channel* thiz, struct sockaddr** addr);

    /**
     * @brief Get bound address.
     *
     * This address is bound on proxy server. It is typically used in protocols which require the client to accept
     * connections from the server (DNS for example).
     *
     * @param[in] thiz  Object handle.
     * @param[in] addr  Bound address.
     * @return 0 for success, errno for failed.
     */
    int (*bound_addr)(struct nt_channel* thiz, struct sockaddr** addr);
} nt_channel_t;

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
     * @param[out] channel Channel handle.
     */
    int (*channel)(struct nt_proxy* thiz, int type, struct sockaddr* peeraddr, nt_channel_t** channel);
} nt_proxy_t;

typedef struct sock_node
{
    ev_map_node_t           node;
    int                     fd;            /* Return value of child's socket(). */
    int                     socket_domain; /* AF_INET/AF_INET6. */
    int                     socket_type;   /* SOCK_STREAM/SOCK_DGRAM */
    int                     socket_protocol;
    nt_channel_t*           channel;
    struct sockaddr_storage orig_addr; /* Orignal connect address. */
} sock_node_t;

typedef struct prog_node
{
    ev_map_node_t node;
    pid_t         pid;                    /* Process ID. */
    ev_map_t      sock_map;               /* Program socket map. Type: #sock_node_t. */
    sock_node_t*  sock_last;              /* Last socket we are tracing. */
    int           syscall;                /* System call number. */
    int           flag_setup : 1;         /* Is setup done. */
    int           flag_syscall_enter : 1; /* Is entry syscall. */
} prog_node_t;

typedef struct runtime
{
    char*       proxy_url; /* Socks5 address. */
    nt_proxy_t* proxy;     /* Proxy object. */

    char**   prog_args;        /* Arguments for child program, ending with NULL. */
    pid_t    prog_pid;         /* First child pid. */
    int      prog_pipe[2];     /* [0] for read, [1] for write. */
    int      prog_exit_retval; /* First child exit code. */
    ev_map_t prog_map;         /* Program tracing map. Type: #prog_node_t. */
} runtime_t;

/**
 * @brief Global runtime.
 */
extern runtime_t* G;

/**
 * @brief Initialize global runtime.
 * @param[in] argc  Argument count.
 * @param[in] argv  Argument list.
 */
void nt_runtime_init(int argc, char* argv[]);

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
