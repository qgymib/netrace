#include <unistd.h>
#include <pthread.h>
#include <sys/epoll.h>
#include "utils/defs.h"
#include "utils/log.h"
#include "utils/memory.h"
#include "utils/map.h"
#include "socket2.h"
#include "simple_server.h"

typedef struct nt_simple_server_connection
{
    ev_map_node_t      node;
    struct epoll_event event;
} nt_simple_server_connection_t;

struct nt_simple_server
{
    nt_simple_server_cb_t   cb;
    void*                   arg;
    int                     type;
    int                     listen_sock;
    int                     epollfd;
    struct epoll_event      events[64];
    ev_map_t                client_table;
    struct sockaddr_storage listen_addr;
    int                     looping;
    pthread_t               tid;
};

static void s_simple_server_handle_tcp_accept(nt_simple_server_t* srv)
{
    nt_simple_server_connection_t* conn = nt_malloc(sizeof(nt_simple_server_connection_t));
    if ((conn->event.data.fd = nt_accept(srv->listen_sock)) < 0)
    {
        nt_free(conn);
        return;
    }

    conn->event.events = EPOLLIN;
    epoll_ctl(srv->epollfd, EPOLL_CTL_ADD, conn->event.data.fd, &conn->event);
    ev_map_insert(&srv->client_table, &conn->node);
}

static void s_simple_server_release_connection(nt_simple_server_t*            srv,
                                               nt_simple_server_connection_t* conn)
{
    epoll_ctl(srv->epollfd, EPOLL_CTL_DEL, conn->event.data.fd, &conn->event);
    ev_map_erase(&srv->client_table, &conn->node);
    close(conn->event.data.fd);
    nt_free(conn);
}

static void s_simple_server_handle_event(nt_simple_server_t* srv, struct epoll_event* evt)
{
    if (evt->data.fd == srv->listen_sock)
    {
        if (srv->type == SOCK_STREAM)
        {
            s_simple_server_handle_tcp_accept(srv);
        }
        else
        {
            /* UDP, just let user handle this. */
            srv->cb(srv->listen_sock, srv->arg);
        }
        return;
    }

    nt_simple_server_connection_t tmp;
    tmp.event.data.fd = evt->data.fd;
    ev_map_node_t* it = ev_map_find(&srv->client_table, &tmp.node);
    if (it == NULL)
    {
        return;
    }
    nt_simple_server_connection_t* conn = container_of(it, nt_simple_server_connection_t, node);
    if (srv->cb(conn->event.data.fd, srv->arg) != 0)
    {
        s_simple_server_release_connection(srv, conn);
    }
}

static void* s_simple_server_thread(void* arg)
{
    int                 i, ret;
    nt_simple_server_t* srv = (nt_simple_server_t*)arg;
    const int           maxevents = ARRAY_SIZE(srv->events);

    while (srv->looping)
    {
        ret = epoll_wait(srv->epollfd, srv->events, maxevents, 100);
        NT_ASSERT(ret >= 0, "epoll_wait failed: (%d) %s.", errno, strerror(errno));
        for (i = 0; i < ret; i++)
        {
            struct epoll_event* evt = &srv->events[i];
            s_simple_server_handle_event(srv, evt);
        }
    }

    return NULL;
}

static int s_simple_srv_cmp_connection(const ev_map_node_t* key1, const ev_map_node_t* key2,
                                       void* arg)
{
    (void)arg;
    const nt_simple_server_connection_t* c1 =
        container_of(key1, nt_simple_server_connection_t, node);
    const nt_simple_server_connection_t* c2 =
        container_of(key2, nt_simple_server_connection_t, node);
    return c1->event.data.fd - c2->event.data.fd;
}

int nt_simple_server_create(nt_simple_server_t** server, int type, const char* ip, int port,
                            nt_simple_server_cb_t cb, void* arg)
{
    int                 ret;
    nt_simple_server_t* s = nt_calloc(1, sizeof(nt_simple_server_t));
    s->type = type;
    s->cb = cb;
    s->arg = arg;
    ev_map_init(&s->client_table, s_simple_srv_cmp_connection, NULL);

    if ((ret = nt_socket_bind(type, ip, port, 0, &s->listen_addr)) < 0)
    {
        goto ERR;
    }
    s->listen_sock = ret;

    if (type == SOCK_STREAM)
    {
        if (listen(s->listen_sock, 1024) < 0)
        {
            ret = NT_ERR(errno);
            goto ERR_LISTEN;
        }
    }

    if ((s->epollfd = epoll_create(1024)) < 0)
    {
        goto ERR_LISTEN;
    }

    struct epoll_event ev;
    ev.events = EPOLLIN;
    ev.data.fd = s->listen_sock;
    epoll_ctl(s->epollfd, EPOLL_CTL_ADD, s->listen_sock, &ev);

    s->looping = 1;
    if ((ret = pthread_create(&s->tid, NULL, s_simple_server_thread, s)) != 0)
    {
        ret = NT_ERR(ret);
        goto ERR_PTHREAD_CREATE;
    }

    *server = s;
    return 0;

ERR_PTHREAD_CREATE:
    close(s->epollfd);
ERR_LISTEN:
    close(s->listen_sock);
ERR:
    nt_free(s);
    return ret;
}

static void s_simple_server_cleanup_connection(nt_simple_server_t* srv)
{
    ev_map_node_t* it = ev_map_begin(&srv->client_table);
    while (it != NULL)
    {
        nt_simple_server_connection_t* conn = container_of(it, nt_simple_server_connection_t, node);
        it = ev_map_next(it);

        s_simple_server_release_connection(srv, conn);
    }
}

void nt_simple_server_destroy(nt_simple_server_t* server)
{
    server->looping = 0;
    pthread_join(server->tid, NULL);
    s_simple_server_cleanup_connection(server);
    close(server->epollfd);
    close(server->listen_sock);
    nt_free(server);
}

void nt_simple_server_get_bind_addr(nt_simple_server_t* server, struct sockaddr_storage* addr)
{
    memcpy(addr, &server->listen_addr, sizeof(*addr));
}
