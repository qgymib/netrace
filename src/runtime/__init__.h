#ifndef NT_RUNTIME_H
#define NT_RUNTIME_H

#include <netinet/in.h>
#include "utils/map.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct sock_node
{
    ev_map_node_t           node;
    int                     fd;        /* Return value of child's socket(). */
    int                     domain;    /* Communication domain: AF_INET/AF_INET6. */
    int                     type;      /* SOCK_STREAM/SOCK_DGRAM */
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
    char*    socks5_addr; /* Socks5 address. */
    unsigned socks5_port; /* Socks5 port. */

    int                tcp_listen_fd; /* TCP socket. */
    int                udp_listen_fd; /* UDP socket. */
    struct sockaddr_in listen_addr;   /* Listen address. */

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

#ifdef __cplusplus
}
#endif
#endif
