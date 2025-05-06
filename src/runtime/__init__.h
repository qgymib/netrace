#ifndef NT_RUNTIME_H
#define NT_RUNTIME_H

#include "proxy/__init__.h"
#include "trace/__init__.h"
#include "utils/map.h"
#include "utils/ipfilter.h"
#include "utils/cmdoption.h"
#include "chain.h"
#include "dns.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct sock_node
{
    ev_map_node_t node;
    int           fd;       /* Return value of child's socket(). */
    int           domain;   /* socket(): AF_INET/AF_INET6. */
    int           type;     /* socket(): #SOCK_STREAM / #SOCK_DGRAM */
    int           protocol; /* socket(): particular protocol to be used with the socket. */
    int           channel;  /* Proxy channel ID. */
    struct sockaddr_storage peer_addr;  /* Orignal connect address. */
    struct sockaddr_storage proxy_addr; /* Proxy address. */
} sock_node_t;

typedef struct prog_node
{
    ev_map_node_t     node;
    ev_map_t          sock_map;     /* Program socket map. Type: #sock_node_t. */
    sock_node_t*      sock_last;    /* Last socket we are tracing. */
    nt_syscall_info_t si;           /* Syscall information. */
    int               b_setup;      /* Is setup done. */
    int               b_in_syscall; /* Is entry syscall. */
    char              tdbuff[1024]; /* Trace decode buff. */
    size_t            tdbuff_sz;    /* Trace decode buff size. */
} prog_node_t;

typedef struct runtime
{
    nt_proxy_t*     proxy; /* Proxy object. */
    nt_ipfilter_t*  ipfilter;
    nt_chain_t*     chain;
    nt_dns_proxy_t* dns;
    int             dns_chid;

    pid_t    prog_pid;         /* First child pid. */
    int      prog_exit_retval; /* First child exit code. */
    ev_map_t prog_map;         /* Program tracing map. Type: #prog_node_t. */
} runtime_t;

/**
 * @brief Global runtime.
 */
extern runtime_t* G;

/**
 * @brief Program entrypoint.
 * @param[in] opt   Options.
 * @return 0 if success.
 */
int nt_run(const nt_cmd_opt_t* opt);

#ifdef __cplusplus
}
#endif
#endif
