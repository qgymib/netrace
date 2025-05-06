#include <pthread.h>
#include <unistd.h>
#include <limits.h>
#include <sys/epoll.h>
#include <sys/eventfd.h>
#include "utils/defs.h"
#include "utils/memory.h"
#include "utils/map.h"
#include "utils/socket.h"
#include "utils/list.h"
#include "utils/log.h"
#include "chain.h"
#include "config.h"

typedef enum nt_chain_action_type
{
    NT_CHAIN_NEW,
    NT_CHAIN_DELETE,
} nt_chain_action_type_t;

typedef struct chain_sock
{
    ev_map_node_t         node;
    struct epoll_event    event;
    struct nt_chain_node* chain;
} chain_sock_t;

typedef struct nt_chain_node
{
    ev_map_node_t           node;
    int                     chain_id;         /* Chain ID */
    int                     proxy_channel_id; /* Proxy channel ID. */
    int                     type;             /* SOCK_STREAM / SOCK_DGRAM */
    nt_proxy_t*             proxy;            /* The proxy this chain use. */
    struct sockaddr_storage peer_addr;        /* Target address. */
    struct sockaddr_storage local_addr;       /* Local bind address. */
    chain_sock_t            inbound;          /* Inbound fd. */
    chain_sock_t            outbound;         /* Socket pair channel fd. (sv[0]). */
    int                     sv[2];       /* Socket pair. sv[0] is outbound, sv[1] is for proxy. */
    size_t                  ubuf_sz;     /* Upload buffer size. */
    size_t                  dbuf_sz;     /* Download buffer size. */
    uint8_t ubuf[NT_SOCKET_BUFFER_SIZE]; /* Upload buffer. From inbound to outbound. */
    uint8_t dbuf[NT_SOCKET_BUFFER_SIZE]; /* Download buffer. From outbound to inbound. */
    union {
        struct
        {
            int is_listen; /* Whether inbound is a listen fd. */
        } tcp;
        struct
        {
            struct sockaddr_storage inbound_addr; /* UDP bind address. */
        } udp;
    } u;
} nt_chain_node_t;

typedef struct nt_chain_action
{
    ev_list_node_t         node;
    nt_chain_action_type_t type;
    union {
        nt_chain_node_t* node;
        int              id;
    } data;
} nt_chain_action_t;

struct nt_chain
{
    int                epollfd;
    int                eventfd;
    struct epoll_event events[128];

    pthread_t tid;
    int       looping;
    ev_map_t  chain_table; /* #nt_chain_node_t. */
    ev_map_t  sock_table;  /* #chain_sock_t. */

    int             chid_idx;
    pthread_mutex_t actq_mutex;
    ev_list_t       actq; /* Action queue. */
};

static int s_chain_on_cmp_node(const ev_map_node_t* key1, const ev_map_node_t* key2, void* arg)
{
    (void)arg;
    const nt_chain_node_t* n1 = container_of(key1, nt_chain_node_t, node);
    const nt_chain_node_t* n2 = container_of(key2, nt_chain_node_t, node);
    if (n1->chain_id == n2->chain_id)
    {
        return 0;
    }
    return n1->chain_id < n2->chain_id ? -1 : 1;
}

static int s_chain_on_cmp_sock(const ev_map_node_t* key1, const ev_map_node_t* key2, void* arg)
{
    (void)arg;
    const chain_sock_t* s1 = container_of(key1, chain_sock_t, node);
    const chain_sock_t* s2 = container_of(key2, chain_sock_t, node);
    if (s1->event.data.fd == s2->event.data.fd)
    {
        return 0;
    }
    return s1->event.data.fd < s2->event.data.fd ? -1 : 1;
}

static void s_chain_inbound_want_read(nt_chain_t* chain, nt_chain_node_t* node)
{
    if (node->inbound.event.data.fd >= 0 && !(node->inbound.event.events & EPOLLIN))
    {
        int op = node->inbound.event.events == 0 ? EPOLL_CTL_ADD : EPOLL_CTL_MOD;
        node->inbound.event.events |= EPOLLIN;
        epoll_ctl(chain->epollfd, op, node->inbound.event.data.fd, &node->inbound.event);
    }
}

static void s_chain_outbound_want_read(nt_chain_t* chain, nt_chain_node_t* node)
{
    if (node->outbound.event.data.fd >= 0 && !(node->outbound.event.events & EPOLLIN))
    {
        int op = node->outbound.event.events == 0 ? EPOLL_CTL_ADD : EPOLL_CTL_MOD;
        node->outbound.event.events |= EPOLLIN;
        epoll_ctl(chain->epollfd, op, node->outbound.event.data.fd, &node->outbound.event);
    }
}

static void s_chain_inbound_want_write(nt_chain_t* chain, nt_chain_node_t* node)
{
    if (node->inbound.event.data.fd >= 0 && !(node->inbound.event.events & EPOLLOUT))
    {
        int op = node->inbound.event.events == 0 ? EPOLL_CTL_ADD : EPOLL_CTL_MOD;
        node->inbound.event.events |= EPOLLOUT;
        epoll_ctl(chain->epollfd, op, node->inbound.event.data.fd, &node->inbound.event);
    }
}

static void s_chain_outbound_want_write(nt_chain_t* chain, nt_chain_node_t* node)
{
    if (node->outbound.event.data.fd >= 0 && !(node->outbound.event.events & EPOLLOUT))
    {
        int op = node->outbound.event.events == 0 ? EPOLL_CTL_ADD : EPOLL_CTL_MOD;
        node->outbound.event.events |= EPOLLOUT;
        epoll_ctl(chain->epollfd, op, node->outbound.event.data.fd, &node->outbound.event);
    }
}

static void s_chain_inbound_stop_read(nt_chain_t* chain, nt_chain_node_t* node)
{
    if (node->inbound.event.data.fd >= 0 && (node->inbound.event.events & EPOLLIN))
    {
        node->inbound.event.events &= ~EPOLLIN;
        int op = node->inbound.event.events == 0 ? EPOLL_CTL_DEL : EPOLL_CTL_MOD;
        epoll_ctl(chain->epollfd, op, node->inbound.event.data.fd, &node->inbound.event);
    }
}

static void s_chain_outbound_stop_read(nt_chain_t* chain, nt_chain_node_t* node)
{
    if (node->outbound.event.data.fd >= 0 && (node->outbound.event.events & EPOLLIN))
    {
        node->outbound.event.events &= ~EPOLLIN;
        int op = node->outbound.event.events == 0 ? EPOLL_CTL_DEL : EPOLL_CTL_MOD;
        epoll_ctl(chain->epollfd, op, node->outbound.event.data.fd, &node->outbound.event);
    }
}

static void s_chain_inbound_stop_write(nt_chain_t* chain, nt_chain_node_t* node)
{
    if (node->inbound.event.data.fd >= 0 && (node->inbound.event.events & EPOLLOUT))
    {
        node->inbound.event.events &= ~EPOLLOUT;
        int op = node->inbound.event.events == 0 ? EPOLL_CTL_DEL : EPOLL_CTL_MOD;
        epoll_ctl(chain->epollfd, op, node->inbound.event.data.fd, &node->inbound.event);
    }
}

static void s_chain_outbound_stop_write(nt_chain_t* chain, nt_chain_node_t* node)
{
    if (node->outbound.event.data.fd >= 0 && (node->outbound.event.events & EPOLLOUT))
    {
        node->outbound.event.events &= ~EPOLLOUT;
        int op = node->outbound.event.events == 0 ? EPOLL_CTL_DEL : EPOLL_CTL_MOD;
        epoll_ctl(chain->epollfd, op, node->outbound.event.data.fd, &node->outbound.event);
    }
}

static void s_chain_close_inbound(nt_chain_t* chain, nt_chain_node_t* node)
{
    if (node->inbound.event.data.fd >= 0)
    {
        if (node->inbound.event.events != 0)
        {
            epoll_ctl(chain->epollfd, EPOLL_CTL_DEL, node->inbound.event.data.fd,
                      &node->inbound.event);
            node->inbound.event.events = 0;
        }
        ev_map_erase(&chain->sock_table, &node->inbound.node);
        close(node->inbound.event.data.fd);
        node->inbound.event.data.fd = -1;
    }
}

static void s_chain_close_outbound(nt_chain_t* chain, nt_chain_node_t* node)
{
    if (node->outbound.event.data.fd >= 0)
    {
        if (node->outbound.event.events != 0)
        {
            epoll_ctl(chain->epollfd, EPOLL_CTL_DEL, node->outbound.event.data.fd,
                      &node->outbound.event);
            node->outbound.event.events = 0;
        }
        ev_map_erase(&chain->sock_table, &node->outbound.node);
        close(node->outbound.event.data.fd);
        node->outbound.event.data.fd = -1;
    }
}

/**
 * @brief Deletes a chain node and releases all associated resources.
 *
 * This function is responsible for releasing resources and cleaning up a chain node
 * associated within a chain. It closes and cleans up inbound and outbound sockets,
 * releases the proxy channel if it is active, and removes the node from the chain table.
 * Finally, the memory allocated for the node is freed.
 *
 * @param[in] chain Pointer to the chain structure containing the chain table.
 * @param[in] node Pointer to the chain node to be deleted.
 *
 * The function performs the following steps:
 * - Releases the proxy channel associated with the node if active.
 * - Closes the inbound and outbound sockets associated with the node.
 * - Closes any additional socket pairs in the node.
 * - Removes the node from the chain's chain table.
 * - Frees the memory allocated for the node.
 */
static void s_chain_delete(nt_chain_t* chain, nt_chain_node_t* node)
{
    if (node->proxy_channel_id >= 0)
    {
        node->proxy->channel_release(node->proxy, node->proxy_channel_id);
        node->proxy_channel_id = -1;
    }

    s_chain_close_inbound(chain, node);
    s_chain_close_outbound(chain, node);

    if (node->sv[0] >= 0)
    {
        close(node->sv[0]);
        node->sv[0] = -1;
    }
    if (node->sv[1] >= 0)
    {
        close(node->sv[1]);
        node->sv[1] = -1;
    }

    ev_map_erase(&chain->chain_table, &node->node);
    nt_free(node);
}

static void s_chain_handle_new_tcp(nt_chain_t* chain, nt_chain_node_t* node)
{
    /* Wait for inbound accept. */
    s_chain_inbound_want_read(chain, node);

    /* Outbound cannot be read until inbound is accepted. */
}

static void s_chain_handle_new_udp(nt_chain_t* chain, nt_chain_node_t* node)
{
    s_chain_inbound_want_read(chain, node);
    s_chain_outbound_want_read(chain, node);
}

/**
 * @brief Handles the initialization of a new chain node and sets up associated resources.
 *
 * This function prepares a new chain node by inserting its inbound and outbound sockets
 * into the socket table, creating a proxy channel, and delegating further initialization
 * to specific handlers based on the node type.
 *
 * @param[in,out] chain Pointer to the chain structure containing the shared resources.
 * @param[in] node Pointer to the chain node that is being initialized.
 *
 * The function performs the following steps:
 * - Inserts the inbound and outbound sockets of the node into the chain's socket table, if valid.
 * - Sets up a proxy channel associated with the node via the proxy interface.
 * - If the proxy channel creation fails, deletes the node and exits early.
 * - Determines the node type and delegates further handling to the appropriate
 *   function.
 */
static void s_chain_handle_new(nt_chain_t* chain, nt_chain_node_t* node)
{
    /* Save to socket table. */
    if (node->inbound.event.data.fd >= 0)
    {
        ev_map_insert(&chain->sock_table, &node->inbound.node);
    }
    if (node->outbound.event.data.fd >= 0)
    {
        ev_map_insert(&chain->sock_table, &node->outbound.node);
    }

    /* Setup proxy channel. */
    node->proxy_channel_id = node->proxy->channel_create(node->proxy, node->type, node->sv[1],
                                                         (struct sockaddr*)&node->peer_addr);
    if (node->proxy_channel_id < 0)
    {
        s_chain_delete(chain, node);
        return;
    }

    switch (node->type)
    {
    case SOCK_STREAM:
        s_chain_handle_new_tcp(chain, node);
        break;
    case SOCK_DGRAM:
        s_chain_handle_new_udp(chain, node);
        break;
    default:
        break;
    }
}

static nt_chain_node_t* s_chain_find_node(nt_chain_t* chain, int id)
{
    nt_chain_node_t tmp;
    tmp.chain_id = id;

    ev_map_node_t* it = ev_map_find(&chain->chain_table, &tmp.node);
    return it != NULL ? container_of(it, nt_chain_node_t, node) : NULL;
}

static chain_sock_t* s_chain_find_sock(nt_chain_t* chain, int fd)
{
    chain_sock_t tmp;
    tmp.event.data.fd = fd;

    ev_map_node_t* it = ev_map_find(&chain->sock_table, &tmp.node);
    return it != NULL ? container_of(it, chain_sock_t, node) : NULL;
}

static void s_chain_handle_delete(nt_chain_t* chain, int id)
{
    nt_chain_node_t* node = s_chain_find_node(chain, id);
    if (node == NULL)
    {
        return;
    }

    s_chain_delete(chain, node);
}

static void s_chain_handle_action(nt_chain_t* chain)
{
    ev_list_node_t* it;
    while (1)
    {
        nt_chain_action_t* act = NULL;
        pthread_mutex_lock(&chain->actq_mutex);
        if ((it = ev_list_pop_front(&chain->actq)) != NULL)
        {
            act = container_of(it, nt_chain_action_t, node);
        }
        pthread_mutex_unlock(&chain->actq_mutex);
        if (act == NULL)
        {
            break;
        }

        switch (act->type)
        {
        case NT_CHAIN_NEW:
            s_chain_handle_new(chain, act->data.node);
            break;
        case NT_CHAIN_DELETE:
            s_chain_handle_delete(chain, act->data.id);
            break;
        }

        nt_free(act);
    }
}

static void s_chain_handle_sock_tcp_listen(nt_chain_t* chain, nt_chain_node_t* node)
{
    /* Accept client connection. */
    int fd = nt_accept(node->inbound.event.data.fd);

    /* Close listen socket. */
    s_chain_close_inbound(chain, node);

    /* Replace listen fd with connection fd. */
    node->inbound.event.data.fd = fd;
    node->inbound.event.events = 0;
    ev_map_insert(&chain->sock_table, &node->inbound.node);

    /* Read from inbound and outbound. */
    s_chain_inbound_want_read(chain, node);
    s_chain_outbound_want_read(chain, node);
}

static void s_chain_handle_tcp_inbound_r(nt_chain_t* chain, nt_chain_node_t* node)
{
    uint8_t* buf = node->ubuf + node->ubuf_sz;
    size_t   buf_sz = sizeof(node->ubuf) - node->ubuf_sz;

    ssize_t read_sz = nt_read(node->inbound.event.data.fd, buf, buf_sz);
    if (read_sz == 0)
    { /* Peer close. */
        LOG_D("[CHID=%d] Inbound peer closed. Close inbound.", node->chain_id);
        s_chain_close_inbound(chain, node);
        return;
    }
    if (read_sz < 0)
    { /* Error may occur. */
        if (read_sz != NT_ERR(EAGAIN) && read_sz != NT_ERR(EWOULDBLOCK))
        {
            LOG_D("[CHID=%d] Inbound read() failed: (%d) %s. Close inbound.", node->chain_id,
                  read_sz, NT_STRERROR(read_sz));
            s_chain_close_inbound(chain, node);
        }
        return;
    }
    node->ubuf_sz += read_sz;

    /* Write to outbound. */
    s_chain_outbound_want_write(chain, node);

    if (node->ubuf_sz == sizeof(node->ubuf))
    {
        s_chain_inbound_stop_read(chain, node);
    }
}

static void s_chain_handle_tcp_inbound_w(nt_chain_t* chain, nt_chain_node_t* node)
{
    ssize_t write_sz = nt_write(node->outbound.event.data.fd, node->dbuf, node->dbuf_sz);
    if (write_sz < 0)
    {
        LOG_D("[CHID=%d] write() failed: (%d) %s. Close inbound", node->chain_id, write_sz,
              NT_STRERROR(write_sz));
        s_chain_close_inbound(chain, node);
        return;
    }
    node->dbuf_sz -= write_sz;

    if (node->dbuf_sz < sizeof(node->dbuf))
    {
        s_chain_outbound_want_read(chain, node);
    }

    if (node->dbuf_sz > 0)
    {
        memmove(node->dbuf, node->dbuf + write_sz, node->dbuf_sz);
        s_chain_inbound_want_write(chain, node);
    }
    else
    {
        s_chain_inbound_stop_write(chain, node);
    }
}

static void s_chain_handle_tcp_outbound_r(nt_chain_t* chain, nt_chain_node_t* node)
{
    uint8_t* buf = node->dbuf + node->dbuf_sz;
    size_t   buf_sz = sizeof(node->dbuf) - node->dbuf_sz;

    ssize_t read_sz = nt_read(node->outbound.event.data.fd, buf, buf_sz);
    if (read_sz == 0)
    { /* Peer close. */
        LOG_D("[CHID=%d] Outbound peer close. Close outbound.", node->chain_id);
        s_chain_close_outbound(chain, node);
        return;
    }
    if (read_sz < 0)
    {
        if (read_sz != NT_ERR(EAGAIN) && read_sz != NT_ERR(EWOULDBLOCK))
        {
            LOG_D("[CHID=%d] read() failed: (%d) %s. Close outbound.", node->chain_id, read_sz,
                  NT_STRERROR(read_sz));
            s_chain_close_outbound(chain, node);
        }
        return;
    }
    node->dbuf_sz += read_sz;

    s_chain_inbound_want_write(chain, node);

    if (node->dbuf_sz == sizeof(node->dbuf))
    {
        s_chain_outbound_stop_read(chain, node);
    }
}

static void s_chain_handle_tcp_outbound_w(nt_chain_t* chain, nt_chain_node_t* node)
{
    ssize_t write_sz = nt_write(node->outbound.event.data.fd, node->ubuf, node->ubuf_sz);
    if (write_sz < 0)
    {
        LOG_D("[CHID=%d] write() failed: (%d) %s. Close outbound", node->chain_id, write_sz,
              NT_STRERROR(write_sz));
        s_chain_close_outbound(chain, node);
        return;
    }
    node->ubuf_sz -= write_sz;

    if (node->ubuf_sz < sizeof(node->ubuf))
    {
        s_chain_inbound_want_read(chain, node);
    }

    if (node->ubuf_sz > 0)
    {
        memmove(node->ubuf, node->ubuf + write_sz, node->ubuf_sz);
        s_chain_outbound_want_write(chain, node);
    }
    else
    {
        s_chain_outbound_stop_write(chain, node);
    }
}

static void s_chain_handle_sock_tcp_normal(nt_chain_t* chain, struct epoll_event* event,
                                           nt_chain_node_t* node)
{
    if (node->inbound.event.data.fd == event->data.fd)
    {
        if (event->events & EPOLLOUT)
        {
            s_chain_handle_tcp_inbound_w(chain, node);
        }
        if (event->events & EPOLLIN)
        {
            s_chain_handle_tcp_inbound_r(chain, node);
        }
    }
    else if (node->outbound.event.data.fd == event->data.fd)
    {
        if (event->events & EPOLLOUT)
        {
            s_chain_handle_tcp_outbound_w(chain, node);
        }
        if (event->events & EPOLLIN)
        {
            s_chain_handle_tcp_outbound_r(chain, node);
        }
    }
}

static void s_chain_handle_sock_tcp(nt_chain_t* chain, struct epoll_event* event,
                                    nt_chain_node_t* node)
{
    if (node->u.tcp.is_listen)
    {
        node->u.tcp.is_listen = 0;
        s_chain_handle_sock_tcp_listen(chain, node);
        return;
    }

    s_chain_handle_sock_tcp_normal(chain, event, node);
}

static void s_chain_handle_udp_inbound_r(nt_chain_t* chain, nt_chain_node_t* node)
{
    struct sockaddr* addr = (struct sockaddr*)&node->u.udp.inbound_addr;
    socklen_t        addr_len = sizeof(node->u.udp.inbound_addr);
    ssize_t          recv_sz =
        recvfrom(node->inbound.event.data.fd, node->ubuf, sizeof(node->ubuf), 0, addr, &addr_len);
    if (recv_sz <= 0)
    {
        s_chain_close_inbound(chain, node);
        return;
    }

    nt_write(node->outbound.event.data.fd, node->ubuf, recv_sz);
}

static void s_chain_handle_udp_outbound_r(nt_chain_t* chain, nt_chain_node_t* node)
{
    ssize_t recv_sz = nt_read(node->outbound.event.data.fd, node->dbuf, sizeof(node->dbuf));
    if (recv_sz <= 0)
    {
        s_chain_close_outbound(chain, node);
        return;
    }

    struct sockaddr* addr = (struct sockaddr*)&node->u.udp.inbound_addr;
    socklen_t        addr_len = sizeof(node->u.udp.inbound_addr);
    sendto(node->inbound.event.data.fd, node->dbuf, recv_sz, 0, addr, addr_len);
}

static void s_chain_handle_sock_udp(nt_chain_t* chain, struct epoll_event* event,
                                    nt_chain_node_t* node)
{
    if (node->inbound.event.data.fd == event->data.fd)
    {
        s_chain_handle_udp_inbound_r(chain, node);
    }
    else if (node->outbound.event.data.fd == event->data.fd)
    {
        s_chain_handle_udp_outbound_r(chain, node);
    }
}

static void s_chain_handle_sock(nt_chain_t* chain, struct epoll_event* event, chain_sock_t* sock)
{
    nt_chain_node_t* node = sock->chain;
    switch (node->type)
    {
    case SOCK_STREAM:
        s_chain_handle_sock_tcp(chain, event, node);
        break;
    case SOCK_DGRAM:
        s_chain_handle_sock_udp(chain, event, node);
        break;
    default:
        break;
    }

    if (node->inbound.event.data.fd < 0 && node->ubuf_sz == 0 && node->outbound.event.data.fd >= 0)
    {
        LOG_D("[CHID=%d] Inbound already closed, nothing to upload. Close outbound.",
              node->chain_id);
        s_chain_close_outbound(chain, node);
    }
    if (node->outbound.event.data.fd < 0 && node->dbuf_sz == 0 && node->inbound.event.data.fd >= 0)
    {
        LOG_D("[CHID=%d] Outbound already closed, nothing to download. Close inbound.",
              node->chain_id);
        s_chain_close_inbound(chain, node);
    }
    if (node->inbound.event.data.fd < 0 && node->outbound.event.data.fd < 0)
    {
        LOG_D("[CHID=%d] Both inbound and outbound are closed. Release channel.", node->chain_id);
        s_chain_delete(chain, node);
    }
}

static void s_chain_handle_event(nt_chain_t* chain, struct epoll_event* event)
{
    if (event->data.fd == chain->eventfd)
    {
        uint64_t buff;
        read(chain->eventfd, &buff, sizeof(buff));
        s_chain_handle_action(chain);
    }
    else
    {
        chain_sock_t* sock = s_chain_find_sock(chain, event->data.fd);
        if (sock != NULL)
        {
            s_chain_handle_sock(chain, event, sock);
            /* `sock` maybe invalid since here. */
        }
    }
}

static void* s_chain_loop(void* arg)
{
    nt_chain_t* chain = (nt_chain_t*)arg;
    const int   maxevents = ARRAY_SIZE(chain->events);

    int i, ret;
    while (chain->looping)
    {
        if ((ret = epoll_wait(chain->epollfd, chain->events, maxevents, 100)) == 0)
        { /* Timeout */
            continue;
        }
        if (ret < 0)
        {
            NT_ASSERT(errno == EINTR, "epoll_wait() failed: (%d) %s.", errno, strerror(errno));
            continue;
        }

        for (i = 0; i < ret; i++)
        {
            struct epoll_event* event = &chain->events[i];
            s_chain_handle_event(chain, event);
        }
    }
    return NULL;
}

static void s_chain_cleanup_chain_table(nt_chain_t* chain)
{
    ev_map_node_t* it;
    while ((it = ev_map_begin(&chain->chain_table)) != NULL)
    {
        nt_chain_node_t* node = container_of(it, nt_chain_node_t, node);
        s_chain_delete(chain, node);
    }
}

static int s_chain_new_tcp(nt_chain_node_t* node)
{
    int         ret;
    const char* ip = node->peer_addr.ss_family == AF_INET ? "127.0.0.1" : "::1";

    node->u.tcp.is_listen = 1;
    if ((ret = nt_socket_listen(ip, 0, 1, &node->local_addr)) < 0)
    {
        return ret;
    }
    node->inbound.event.data.fd = ret;

    return 0;
}

static int s_chain_new_udp(nt_chain_node_t* node)
{
    int         ret;
    const char* ip = node->peer_addr.ss_family == AF_INET ? "127.0.0.1" : "::1";
    if ((ret = nt_socket_bind(SOCK_DGRAM, ip, 0, 1, &node->local_addr)) < 0)
    {
        return ret;
    }
    node->inbound.event.data.fd = ret;

    return 0;
}

static int s_chain_new_by_type(nt_chain_node_t* node, int type)
{
    int ret;
    if (socketpair(AF_UNIX, type, 0, node->sv) != 0)
    {
        return NT_ERR(errno);
    }
    node->outbound.event.data.fd = node->sv[0];
    node->sv[0] = -1;

    switch (type)
    {
    case SOCK_STREAM:
        ret = s_chain_new_tcp(node);
        break;
    case SOCK_DGRAM:
        ret = s_chain_new_udp(node);
        break;
    default:
        ret = NT_ERR(ENOTSUP);
        break;
    }

    if (ret != 0)
    {
        if (node->sv[0] >= 0)
        {
            close(node->sv[0]);
            node->sv[0] = -1;
        }
        if (node->sv[1] >= 0)
        {
            close(node->sv[1]);
            node->sv[1] = -1;
        }
    }

    return ret;
}

static void s_chain_weakup(nt_chain_t* chain)
{
    uint64_t buff = 1;
    write(chain->eventfd, &buff, sizeof(buff));
}

int nt_chain_init(nt_chain_t** chain)
{
    int         ret;
    nt_chain_t* c = nt_calloc(1, sizeof(nt_chain_t));
    ev_map_init(&c->chain_table, s_chain_on_cmp_node, NULL);
    ev_map_init(&c->sock_table, s_chain_on_cmp_sock, NULL);
    ev_list_init(&c->actq);

    c->epollfd = epoll_create1(EPOLL_CLOEXEC);
    c->eventfd = eventfd(0, EFD_CLOEXEC);

    c->events[0].events = EPOLLIN;
    c->events[0].data.fd = c->eventfd;
    epoll_ctl(c->epollfd, EPOLL_CTL_ADD, c->eventfd, &c->events[0]);

    c->looping = 1;
    pthread_mutex_init(&c->actq_mutex, NULL);

    if ((ret = pthread_create(&c->tid, NULL, s_chain_loop, c)) != 0)
    {
        ret = NT_ERR(ret);
        goto ERR_PTHREAD_CREATE;
    }

    *chain = c;
    return 0;

ERR_PTHREAD_CREATE:
    return ret;
}

void nt_chain_exit(nt_chain_t* chain)
{
    /* Wait for thread exit. */
    chain->looping = 0;
    pthread_join(chain->tid, NULL);

    s_chain_cleanup_chain_table(chain);
    close(chain->epollfd);
    close(chain->eventfd);

    pthread_mutex_destroy(&chain->actq_mutex);
    nt_free(chain);
}

int nt_chain_new(nt_chain_t* chain, int type, const struct sockaddr* peeraddr,
                 struct sockaddr_storage* proxyaddr, nt_proxy_t* proxy)
{
    int              ret;
    nt_chain_node_t* node = nt_calloc(1, sizeof(nt_chain_node_t));
    node->type = type;
    node->proxy = proxy;
    node->proxy_channel_id = -1;
    node->sv[0] = -1;
    node->sv[1] = -1;
    node->inbound.event.data.fd = -1;
    node->inbound.chain = node;
    node->outbound.event.data.fd = -1;
    node->outbound.chain = node;
    nt_sockaddr_copy((struct sockaddr*)&node->peer_addr, peeraddr);

    if ((ret = s_chain_new_by_type(node, type)) != 0)
    {
        nt_free(node);
        return ret;
    }
    nt_sockaddr_copy((struct sockaddr*)proxyaddr, (struct sockaddr*)&node->local_addr);

    nt_chain_action_t* act = nt_malloc(sizeof(nt_chain_action_t));
    act->type = NT_CHAIN_NEW;
    act->data.node = node;

    int chid;
    pthread_mutex_lock(&chain->actq_mutex);
    {
        chid = chain->chid_idx++;
        node->chain_id = chid;
        if (chain->chid_idx == INT_MAX)
        { /* Avoid flip */
            chain->chid_idx = 0;
        }
        ev_list_push_back(&chain->actq, &act->node);
    }
    pthread_mutex_unlock(&chain->actq_mutex);

    s_chain_weakup(chain);
    return chid;
}

void nt_chain_delete(nt_chain_t* chain, int id)
{
    nt_chain_action_t* act = nt_malloc(sizeof(nt_chain_action_t));
    act->type = NT_CHAIN_DELETE;
    act->data.id = id;

    pthread_mutex_lock(&chain->actq_mutex);
    {
        ev_list_push_back(&chain->actq, &act->node);
    }
    pthread_mutex_unlock(&chain->actq_mutex);
}
