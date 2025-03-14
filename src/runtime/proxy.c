#include <assert.h>
#include <stdlib.h>
#include <errno.h>
#include <pthread.h>
#include <unistd.h>
#include <sys/epoll.h>
#include "utils/defs.h"
#include "utils/list.h"
#include "utils/log.h"
#include "utils/map.h"
#include "utils/memory.h"
#include "utils/socket.h"
#include "proxy.h"
#include "__init__.h"
#include "config.h"

typedef struct channel_sock_node
{
    ev_map_node_t        node;
    struct epoll_event   event;   /* EPOLLIN / EPOLLOUT */
    struct channel_node* channel; /* Channel */
} channel_sock_node_t;

typedef struct channel_node
{
    ev_list_node_t          node;
    channel_sock_node_t     inbound;                     /* In bound. */
    channel_sock_node_t     outbound;                    /* Out bound. */
    int                     flag_outbound_connecting;    /* If outbound is in connecting. */
    size_t                  ubuf_sz;                     /* Data size in upload buffer. */
    size_t                  dbuf_sz;                     /* Data size in download buffer. */
    char                    ubuf[NT_SOCKET_BUFFER_SIZE]; /* Upload buffer. Read from inbound, and send to outbound. */
    char                    dbuf[NT_SOCKET_BUFFER_SIZE]; /* Download buffer. Read from outbound, and send to inbound. */
    struct sockaddr_storage peeraddr;                    /* Peer address. */
} channel_node_t;

typedef struct proxy_ctx
{
    int                looping; /* Looping flag. */
    pthread_t          tid;
    int                epollfd;
    struct epoll_event events[1024];
    ev_map_t           sock_map;
    ev_list_t          channel_list; /* channel_node_t. */

    pthread_mutex_t addr_queue_mutex;
    ev_list_t       addr_queue; /* #channel_node_t. */
} proxy_ctx_t;

static proxy_ctx_t* s_proxy = NULL;

static void s_channel_close_inbound(channel_node_t* channel)
{
    if (channel->inbound.event.events != 0)
    {
        epoll_ctl(s_proxy->epollfd, EPOLL_CTL_DEL, channel->inbound.event.data.fd, &channel->inbound.event);
        channel->inbound.event.events = 0;
    }
    if (channel->inbound.event.data.fd >= 0)
    {
        close(channel->inbound.event.data.fd);
        channel->inbound.event.data.fd = -1;
    }
}

static void s_channel_close_outbound(channel_node_t* channel)
{
    if (channel->outbound.event.events != 0)
    {
        epoll_ctl(s_proxy->epollfd, EPOLL_CTL_DEL, channel->outbound.event.data.fd, &channel->outbound.event);
        channel->outbound.event.events = 0;
    }
    if (channel->outbound.event.data.fd >= 0)
    {
        close(channel->outbound.event.data.fd);
        channel->outbound.event.data.fd = -1;
    }
}

static void s_channel_node_release(channel_node_t* channel)
{
    s_channel_close_inbound(channel);
    s_channel_close_outbound(channel);
    nt_free(channel);
}

static void s_channel_node_remove_and_release(channel_node_t* channel)
{
    ev_map_erase(&s_proxy->sock_map, &channel->inbound.node);
    ev_map_erase(&s_proxy->sock_map, &channel->outbound.node);
    ev_list_erase(&s_proxy->channel_list, &channel->node);
    s_channel_node_release(channel);
}

static void s_handle_tcp_listen()
{
    ev_list_node_t* it;
    int             retval;

    /* Get channel. */
    pthread_mutex_lock(&s_proxy->addr_queue_mutex);
    {
        it = ev_list_pop_front(&s_proxy->addr_queue);
    }
    pthread_mutex_unlock(&s_proxy->addr_queue_mutex);
    assert(it != NULL);

    /* Create inbound and outbound. */
    channel_node_t* channel = container_of(it, channel_node_t, node);
    channel->inbound.event.data.fd = accept(G->tcp_listen_fd, NULL, NULL);
    channel->outbound.event.data.fd = socket(channel->peeraddr.ss_family, SOCK_STREAM, 0);
    if (channel->inbound.event.data.fd < 0 || channel->outbound.event.data.fd < 0)
    {
        s_channel_node_release(channel);
        return;
    }
    nt_nonblock(channel->inbound.event.data.fd, 1);
    nt_nonblock(channel->outbound.event.data.fd, 1);

    retval = connect(channel->outbound.event.data.fd, (struct sockaddr*)&channel->peeraddr, sizeof(channel->peeraddr));
    if (retval == 0)
    {
        channel->flag_outbound_connecting = 0;
    }
    else if (errno == EAGAIN)
    {
        channel->flag_outbound_connecting = 1;
    }
    else
    {
        s_channel_node_release(channel);
        return;
    }

    ev_list_push_back(&s_proxy->channel_list, &channel->node);
    ev_map_insert(&s_proxy->sock_map, &channel->inbound.node);
    ev_map_insert(&s_proxy->sock_map, &channel->outbound.node);

    if (channel->flag_outbound_connecting)
    { /* If still connecting, wait for connect success. */
        channel->outbound.event.events = EPOLLOUT;
        epoll_ctl(s_proxy->epollfd, EPOLL_CTL_ADD, channel->outbound.event.data.fd, &channel->outbound.event);
    }
    else
    { /* If connect success, read from outbound. */
        channel->outbound.event.events = EPOLLIN;
        epoll_ctl(s_proxy->epollfd, EPOLL_CTL_ADD, channel->outbound.event.data.fd, &channel->outbound.event);
    }

    /* Read from inbound. */
    channel->inbound.event.events = EPOLLIN;
    epoll_ctl(s_proxy->epollfd, EPOLL_CTL_ADD, channel->inbound.event.data.fd, &channel->inbound.event);
}

static void s_handle_inbound_in(channel_node_t* channel)
{
    char*  buf = channel->ubuf + channel->ubuf_sz;
    size_t bufsz = sizeof(channel->ubuf) - channel->ubuf_sz;

    /* Read to upload buffer. */
    ssize_t read_sz = nt_read(channel->inbound.event.data.fd, buf, bufsz);
    if (read_sz == 0)
    { /*EOF*/
        s_channel_close_inbound(channel);
    }
    else if (read_sz < 0)
    { /* Error */
        if (errno != EAGAIN)
        {
            s_channel_close_inbound(channel);
        }
    }
    else
    {
        channel->ubuf_sz += read_sz;
    }

    /* If buffer is full, stop EPOLLIN */
    if (channel->ubuf_sz == sizeof(channel->ubuf) && channel->inbound.event.data.fd >= 0 &&
        (channel->inbound.event.events & EPOLLIN))
    {
        channel->inbound.event.events &= ~EPOLLIN;
        int op = channel->inbound.event.events == 0 ? EPOLL_CTL_DEL : EPOLL_CTL_MOD;
        epoll_ctl(s_proxy->epollfd, op, channel->inbound.event.data.fd, &channel->inbound.event);
    }

    /* Write to outbound. */
    if (channel->ubuf_sz != 0 && channel->outbound.event.data.fd >= 0 && !(channel->outbound.event.events & EPOLLOUT))
    {
        int op = channel->outbound.event.events == 0 ? EPOLL_CTL_ADD : EPOLL_CTL_MOD;
        channel->outbound.event.events |= EPOLLOUT;
        epoll_ctl(s_proxy->epollfd, op, channel->outbound.event.data.fd, &channel->outbound.event);
    }
}

static void s_handle_outbound_in(channel_node_t* channel)
{
    char*  buf = channel->dbuf + channel->dbuf_sz;
    size_t bufsz = sizeof(channel->dbuf) - channel->dbuf_sz;

    ssize_t read_sz = nt_read(channel->outbound.event.data.fd, buf, bufsz);
    if (read_sz == 0)
    { /* EOF */
        s_channel_close_outbound(channel);
    }
    else if (read_sz < 0)
    {
        if (errno != EAGAIN)
        {
            s_channel_close_outbound(channel);
        }
    }
    else
    {
        channel->dbuf_sz += read_sz;
    }

    /* If buffer is full, stop EPOLLIN */
    if (channel->dbuf_sz == sizeof(channel->dbuf) && channel->outbound.event.data.fd >= 0 &&
        (channel->outbound.event.events & EPOLLIN))
    {
        channel->outbound.event.events &= ~EPOLLIN;
        int op = channel->outbound.event.events == 0 ? EPOLL_CTL_DEL : EPOLL_CTL_MOD;
        epoll_ctl(s_proxy->epollfd, op, channel->outbound.event.data.fd, &channel->outbound.event);
    }

    if (channel->dbuf_sz != 0 && channel->inbound.event.data.fd >= 0 && !(channel->inbound.event.events & EPOLLOUT))
    {
        int op = channel->inbound.event.events == 0 ? EPOLL_CTL_ADD : EPOLL_CTL_MOD;
        channel->inbound.event.events |= EPOLLOUT;
        epoll_ctl(s_proxy->epollfd, op, channel->inbound.event.data.fd, &channel->inbound.event);
    }
}

static void s_handle_inbound_out(channel_node_t* channel)
{
    ssize_t write_sz = nt_write(channel->inbound.event.data.fd, channel->dbuf, channel->dbuf_sz);
    if (write_sz < 0)
    {
        s_channel_close_inbound(channel);
    }
    else
    {
        memmove(channel->dbuf, channel->dbuf+write_sz, channel->dbuf_sz - write_sz);
        channel->dbuf_sz -= write_sz;
    }

    /* If no data remaining, remove EPOLLOUT. */
    if (channel->dbuf_sz == 0 && channel->inbound.event.data.fd >= 0)
    {
        channel->inbound.event.events &= ~EPOLLOUT;
        int op = channel->inbound.event.events == 0 ? EPOLL_CTL_DEL : EPOLL_CTL_MOD;
        epoll_ctl(s_proxy->epollfd, op, channel->inbound.event.data.fd, &channel->inbound.event);
    }

    if (channel->outbound.event.data.fd >= 0 && !(channel->outbound.event.events & EPOLLIN) && channel->dbuf_sz < sizeof(channel->dbuf))
    {
        int op = channel->outbound.event.events == 0 ? EPOLL_CTL_ADD : EPOLL_CTL_MOD;
        channel->outbound.event.events |= EPOLLIN;
        epoll_ctl(s_proxy->epollfd, op, channel->outbound.event.data.fd, &channel->outbound.event);
    }
}

static void s_handle_outbound_out(channel_node_t* channel)
{
    ssize_t write_sz = nt_write(channel->outbound.event.data.fd, channel->ubuf, channel->ubuf_sz);
    if (write_sz < 0)
    { /* Outbound error. */
        s_channel_close_outbound(channel);
    }
    else
    {
        memmove(channel->ubuf, channel->ubuf + write_sz, channel->ubuf_sz - write_sz);
        channel->ubuf_sz -= write_sz;
    }

    /* If no data remaining, remove EPOLLOUT. */
    if (channel->ubuf_sz == 0 && channel->outbound.event.data.fd >= 0)
    {
        channel->outbound.event.events &= ~EPOLLOUT;
        int op = channel->outbound.event.events == 0 ? EPOLL_CTL_DEL : EPOLL_CTL_MOD;
        epoll_ctl(s_proxy->epollfd, op, channel->outbound.event.data.fd, &channel->outbound.event);
    }

    /* Read from inbound. */
    if (channel->inbound.event.data.fd >= 0 && !(channel->inbound.event.events & EPOLLIN) &&
        channel->ubuf_sz < sizeof(channel->ubuf))
    {
        int op = channel->inbound.event.events == 0 ? EPOLL_CTL_ADD : EPOLL_CTL_MOD;
        channel->inbound.event.events |= EPOLLIN;
        epoll_ctl(s_proxy->epollfd, op, channel->inbound.event.data.fd, &channel->inbound.event);
    }
}

static void s_handle_net(int fd, struct epoll_event* event)
{
    channel_sock_node_t tmp;
    tmp.event.data.fd = fd;
    ev_map_node_t* it = ev_map_find(&s_proxy->sock_map, &tmp.node);
    assert(it != NULL);
    channel_sock_node_t* sock = container_of(it, channel_sock_node_t, node);
    channel_node_t*      channel = sock->channel;

    if (fd == channel->inbound.event.data.fd)
    {
        if (event->events & EPOLLIN)
        {
            s_handle_inbound_in(channel);
        }
        if (event->events & EPOLLOUT)
        {
            s_handle_inbound_out(channel);
        }
    }
    else
    {
        if (event->events & EPOLLIN)
        {
            s_handle_outbound_in(channel);
        }
        if (event->events & EPOLLOUT)
        {
            s_handle_outbound_out(channel);
        }
    }

    /* If both bound is closed, remove record. */
    if (channel->inbound.event.data.fd < 0 && channel->outbound.event.data.fd < 0)
    {
        s_channel_node_remove_and_release(channel);
        return;
    }
}

static void* s_proxy_body(void* arg)
{
    (void)arg;

    int                 epollfd = s_proxy->epollfd;
    struct epoll_event* events = s_proxy->events;
    int                 maxevents = ARRAY_SIZE(s_proxy->events);
    struct epoll_event  event;

    event.events = EPOLLIN;
    event.data.fd = G->tcp_listen_fd;
    epoll_ctl(epollfd, EPOLL_CTL_ADD, G->tcp_listen_fd, &event);

    int i, ret;
    while (s_proxy->looping)
    {
        ret = epoll_wait(epollfd, events, maxevents, 100);
        if (ret == 0)
        { /* Timeout. */
            continue;
        }
        else if (ret < 0)
        {
            if (errno == EINTR)
            {
                continue;
            }
            LOG_F_ABORT("epoll_wait() failed: (%d) %s.", errno, strerror(errno));
        }

        for (i = 0; i < ret; i++)
        {
            struct epoll_event* e = &events[i];
            if (e->data.fd == G->tcp_listen_fd)
            {
                s_handle_tcp_listen();
            }
            else
            {
                s_handle_net(e->data.fd, e);
            }
        }
    }

    return NULL;
}

static int s_on_cmp_channel_sock(const ev_map_node_t* key1, const ev_map_node_t* key2, void* arg)
{
    (void)arg;
    const channel_sock_node_t* n1 = container_of(key1, channel_sock_node_t, node);
    const channel_sock_node_t* n2 = container_of(key2, channel_sock_node_t, node);
    return n1->event.data.fd - n2->event.data.fd;
}

void nt_proxy_init(void)
{
    s_proxy = nt_calloc(1, sizeof(*s_proxy));
    s_proxy->looping = 1;
    s_proxy->epollfd = -1;
    ev_list_init(&s_proxy->addr_queue);
    pthread_mutex_init(&s_proxy->addr_queue_mutex, NULL);
    ev_list_init(&s_proxy->channel_list);
    ev_map_init(&s_proxy->sock_map, s_on_cmp_channel_sock, NULL);

    if ((s_proxy->epollfd = epoll_create(1024)) < 0)
    {
        LOG_F_ABORT("epoll_create() failed: (%d) %s.", errno, strerror(errno));
    }

    int ret = pthread_create(&s_proxy->tid, NULL, s_proxy_body, NULL);
    if (ret != 0)
    {
        LOG_F_ABORT("pthread_create() failed: (%d) %s.", errno, strerror(errno));
    }
}

void nt_proxy_exit(void)
{
    if (s_proxy == NULL)
    {
        return;
    }

    s_proxy->looping = 0;
    pthread_join(s_proxy->tid, NULL);
    pthread_mutex_destroy(&s_proxy->addr_queue_mutex);

    ev_list_node_t* it;
    while ((it = ev_list_pop_front(&s_proxy->addr_queue)) != NULL)
    {
        channel_node_t* channel = container_of(it, channel_node_t, node);
        s_channel_node_release(channel);
    }
    while ((it = ev_list_begin(&s_proxy->channel_list)) != NULL)
    {
        channel_node_t* channel = container_of(it, channel_node_t, node);
        s_channel_node_remove_and_release(channel);
    }

    if (s_proxy->epollfd >= 0)
    {
        close(s_proxy->epollfd);
        s_proxy->epollfd = -1;
    }

    nt_free(s_proxy);
    s_proxy = NULL;
}

void nt_proxy_queue(const struct sockaddr* addr)
{
    channel_node_t* channel = nt_malloc(sizeof(channel_node_t));
    channel->inbound.event.data.fd = -1;
    channel->inbound.event.events = 0;
    channel->inbound.channel = channel;
    channel->outbound.event.data.fd = -1;
    channel->outbound.event.events = 0;
    channel->outbound.channel = channel;
    channel->ubuf_sz = 0;
    channel->dbuf_sz = 0;

    size_t copy_sz = addr->sa_family == AF_INET ? sizeof(struct sockaddr_in) : sizeof(struct sockaddr_in6);
    memcpy(&channel->peeraddr, addr, copy_sz);

    pthread_mutex_lock(&s_proxy->addr_queue_mutex);
    ev_list_push_back(&s_proxy->addr_queue, &channel->node);
    pthread_mutex_unlock(&s_proxy->addr_queue_mutex);
}
