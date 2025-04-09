#include <assert.h>
#include <errno.h>
#include <unistd.h>
#include <pthread.h>
#include <sys/eventfd.h>
#include <sys/epoll.h>
#include "utils/defs.h"
#include "utils/memory.h"
#include "utils/list.h"
#include "utils/socket.h"
#include "utils/log.h"
#include "config.h"
#include "__init__.h"

typedef struct raw_sock
{
    ev_map_node_t             node;
    struct epoll_event        event;
    struct proxy_raw_channel* channel;
} raw_sock_t;

typedef struct proxy_raw_channel
{
    ev_map_node_t node;
    int           chid; /* Channel ID. */
    int           type; /* SOCK_STREAM / SOCK_DGRAM */
    int           islisten;
    raw_sock_t    inbound;
    raw_sock_t    outbound;
    size_t        ubuf_sz;
    size_t        dbuf_sz;
    uint8_t       ubuf[NT_SOCKET_BUFFER_SIZE]; /* Upload buffer. From inbound to outbound. */
    uint8_t       dbuf[NT_SOCKET_BUFFER_SIZE]; /* Download buffer. From outbound to inbound. */
    struct sockaddr_storage localaddr;
    struct sockaddr_storage peeraddr;
} proxy_raw_channel_t;

typedef enum proxy_raw_action_type
{
    RAW_CHANNEL_CREATE,  /* Create channel. */
    RAW_CHANNEL_RELEASE, /* Release channel. */
} proxy_raw_action_type_t;

typedef struct proxy_raw_action
{
    ev_list_node_t          node;
    proxy_raw_action_type_t type;
    union {
        proxy_raw_channel_t* channel; /* The created channel. */
        int                  chid;    /* The channel id. */
    } data;
} proxy_raw_action_t;

typedef struct nt_proxy_raw
{
    nt_proxy_t basis;   /* Base handle. */
    int        epollfd; /* File handle for epoll. */
    int        eventfd; /* File hanle for eventfd. */

    pthread_t          tid;         /* Working thread ID. */
    int                looping;     /* Looping flag. */
    struct epoll_event events[128]; /* Events cache. */
    ev_map_t           sock_map;    /* #raw_sock_t. */
    ev_map_t           channel_map; /* #proxy_raw_channel_t. */

    pthread_mutex_t actq_mutex; /* Action queue mutex. */
    ev_list_t       actq;       /* Action queue. #proxy_raw_action_t. */
    int             chid_cnt;   /* Channel ID counter. */
} nt_proxy_raw_t;

static void s_proxy_raw_close_inbound_channel(nt_proxy_raw_t* raw, proxy_raw_channel_t* ch)
{
    if (ch->inbound.event.data.fd >= 0)
    {
        if (ch->inbound.event.events != 0)
        {
            epoll_ctl(raw->epollfd, EPOLL_CTL_DEL, ch->inbound.event.data.fd, &ch->inbound.event);
            ch->inbound.event.events = 0;
        }
        ev_map_erase(&raw->sock_map, &ch->inbound.node);
        close(ch->inbound.event.data.fd);
        ch->inbound.event.data.fd = -1;
    }
}

static void s_proxy_raw_close_outbound_channel(nt_proxy_raw_t* raw, proxy_raw_channel_t* ch)
{
    if (ch->outbound.event.data.fd >= 0)
    {
        if (ch->outbound.event.events != 0)
        {
            epoll_ctl(raw->epollfd, EPOLL_CTL_DEL, ch->outbound.event.data.fd, &ch->outbound.event);
            ch->outbound.event.events = 0;
        }
        ev_map_erase(&raw->sock_map, &ch->outbound.node);
        close(ch->outbound.event.data.fd);
        ch->outbound.event.data.fd = -1;
    }
}

static void s_proxy_raw_close_inbound_outbound_channel(nt_proxy_raw_t* raw, proxy_raw_channel_t* ch)
{
    s_proxy_raw_close_inbound_channel(raw, ch);
    s_proxy_raw_close_outbound_channel(raw, ch);
}

static void s_proxy_raw_release_channel(nt_proxy_raw_t* raw, proxy_raw_channel_t* ch)
{
    s_proxy_raw_close_inbound_outbound_channel(raw, ch);
    nt_free(ch);
}

static void s_proxy_raw_cleanup_actq(nt_proxy_raw_t* raw)
{
    ev_list_node_t* it;
    while ((it = ev_list_pop_front(&raw->actq)) != NULL)
    {
        proxy_raw_action_t* act = container_of(it, proxy_raw_action_t, node);
        if (act->type == RAW_CHANNEL_CREATE)
        {
            proxy_raw_channel_t* ch = act->data.channel;
            if (ch->inbound.event.data.fd >= 0)
            {
                ev_map_insert(&raw->sock_map, &ch->inbound.node);
            }
            if (ch->outbound.event.data.fd >= 0)
            {
                ev_map_insert(&raw->sock_map, &ch->outbound.node);
            }
            ev_map_insert(&raw->channel_map, &ch->node);
        }
        nt_free(act);
    }
}

static void s_proxy_remove_and_release_channel(nt_proxy_raw_t* raw, proxy_raw_channel_t* ch)
{
    ev_map_erase(&raw->channel_map, &ch->node);
    s_proxy_raw_release_channel(raw, ch);
}

static void s_proxy_cleanup_channel(nt_proxy_raw_t* raw)
{
    ev_map_node_t* it;
    while ((it = ev_map_begin(&raw->channel_map)) != NULL)
    {
        proxy_raw_channel_t* channel = container_of(it, proxy_raw_channel_t, node);
        s_proxy_remove_and_release_channel(raw, channel);
    }
}

static void s_proxy_raw_release(struct nt_proxy* thiz)
{
    nt_proxy_raw_t* raw = container_of(thiz, nt_proxy_raw_t, basis);

    raw->looping = 0;
    pthread_join(raw->tid, NULL);

    s_proxy_raw_cleanup_actq(raw);
    pthread_mutex_destroy(&raw->actq_mutex);

    s_proxy_cleanup_channel(raw);

    if (raw->epollfd >= 0)
    {
        close(raw->epollfd);
        raw->epollfd = -1;
    }
    if (raw->eventfd >= 0)
    {
        close(raw->eventfd);
        raw->eventfd = -1;
    }
    nt_free(raw);
}

static void s_proxy_raw_weakup(nt_proxy_raw_t* raw)
{
    uint64_t buff = 1;
    write(raw->eventfd, &buff, sizeof(buff));
}

static int s_proxy_new_channel_tcp(proxy_raw_channel_t* ch)
{
    int         ret = 0;
    const char* ip = ch->peeraddr.ss_family == AF_INET ? "127.0.0.1" : "::1";

    ch->islisten = 1;
    if ((ret = nt_socket_listen(ip, 0, 1, &ch->localaddr)) < 0)
    {
        return ret;
    }
    ch->inbound.event.data.fd = ret;

    if ((ret = nt_socket_connect(SOCK_STREAM, &ch->peeraddr, 1)) < 0)
    {
        goto ERR_BIND;
    }
    ch->outbound.event.data.fd = ret;

    return 0;

ERR_BIND:
    close(ch->inbound.event.data.fd);
    return ret;
}

static int s_proxy_raw_channel_create(struct nt_proxy* thiz, int type,
                                      const struct sockaddr*   peeraddr,
                                      struct sockaddr_storage* proxyaddr)
{
    nt_proxy_raw_t*      raw = container_of(thiz, nt_proxy_raw_t, basis);
    proxy_raw_channel_t* ch = nt_malloc(sizeof(proxy_raw_channel_t));
    ch->type = type;
    ch->inbound.event.events = 0;
    ch->inbound.channel = ch;
    ch->outbound.event.events = 0;
    ch->outbound.channel = ch;
    ch->ubuf_sz = 0;
    ch->dbuf_sz = 0;
    nt_sockaddr_copy((struct sockaddr*)&ch->peeraddr, peeraddr);

    int ret = (type == SOCK_STREAM) ? s_proxy_new_channel_tcp(ch) : NT_ERR(ENOTSUP);
    if (ret < 0)
    {
        nt_free(ch);
        return ret;
    }
    nt_sockaddr_copy((struct sockaddr*)proxyaddr, (struct sockaddr*)&ch->localaddr);

    proxy_raw_action_t* act = nt_malloc(sizeof(proxy_raw_action_t));
    act->type = RAW_CHANNEL_CREATE;
    act->data.channel = ch;

    int chid;
    pthread_mutex_lock(&raw->actq_mutex);
    {
        chid = raw->chid_cnt++;
        ch->chid = chid;
        ev_list_push_back(&raw->actq, &act->node);
    }
    pthread_mutex_unlock(&raw->actq_mutex);

    s_proxy_raw_weakup(raw);
    return chid;
}

static void s_proxy_raw_handle_event_channel_create(nt_proxy_raw_t*      raw,
                                                    proxy_raw_channel_t* channel)
{
    if (channel->inbound.event.data.fd >= 0)
    {
        ev_map_insert(&raw->sock_map, &channel->inbound.node);
    }
    if (channel->outbound.event.data.fd >= 0)
    {
        ev_map_insert(&raw->sock_map, &channel->outbound.node);
    }
    ev_map_insert(&raw->channel_map, &channel->node);

    if (channel->type == SOCK_STREAM)
    {
        channel->inbound.event.events = EPOLLIN;
        epoll_ctl(raw->epollfd, EPOLL_CTL_ADD, channel->inbound.event.data.fd,
                  &channel->inbound.event);
        return;
    }
}

static void s_proxy_raw_handle_event_channel_release(nt_proxy_raw_t* raw, int chid)
{
    proxy_raw_channel_t tmp;
    tmp.chid = chid;
    ev_map_node_t* it = ev_map_find(&raw->channel_map, &tmp.node);
    if (it == NULL)
    {
        return;
    }

    /*
     * Release channel means this side need to close, but it does not means peer
     * should be closed now This is because ubuf maybe not empty.
     */
    proxy_raw_channel_t* ch = container_of(it, proxy_raw_channel_t, node);
    s_proxy_raw_close_inbound_channel(raw, ch);
}

static void s_proxy_raw_handle_event(nt_proxy_raw_t* raw)
{
    ev_list_node_t* it;

    while (1)
    {
        proxy_raw_action_t* act = NULL;
        pthread_mutex_lock(&raw->actq_mutex);
        if ((it = ev_list_pop_front(&raw->actq)) != NULL)
        {
            act = container_of(it, proxy_raw_action_t, node);
        }
        pthread_mutex_unlock(&raw->actq_mutex);
        if (act == NULL)
        {
            break;
        }

        switch (act->type)
        {
        case RAW_CHANNEL_CREATE:
            s_proxy_raw_handle_event_channel_create(raw, act->data.channel);
            break;
        case RAW_CHANNEL_RELEASE:
            s_proxy_raw_handle_event_channel_release(raw, act->data.chid);
            break;
        }

        nt_free(act);
    }
}

static void s_proxy_raw_handle_inbound_w(nt_proxy_raw_t* raw, proxy_raw_channel_t* ch)
{
    ssize_t write_sz = nt_write(ch->inbound.event.data.fd, ch->dbuf, ch->dbuf_sz);
    if (write_sz < 0)
    {
        s_proxy_raw_close_inbound_channel(raw, ch);
    }
    else
    {
        ch->dbuf_sz -= write_sz;
    }

    /* If inbound is closed and nothing to upload, close outbound. */
    if (ch->inbound.event.data.fd < 0 && ch->ubuf_sz == 0)
    {
        s_proxy_raw_close_outbound_channel(raw, ch);
        return;
    }

    if (ch->dbuf_sz > 0)
    { /* dbuf is not empty, move buffer and try again. */
        memmove(ch->dbuf, ch->dbuf + write_sz, ch->dbuf_sz);
    }
    else if (ch->inbound.event.data.fd >= 0)
    { /* dbuf is empty, remove EPOLLOUT */
        ch->inbound.event.events &= ~EPOLLOUT;
        int op = ch->inbound.event.events == 0 ? EPOLL_CTL_DEL : EPOLL_CTL_MOD;
        epoll_ctl(raw->epollfd, op, ch->inbound.event.data.fd, &ch->inbound.event);
    }

    /* If dbuf is empty and outbound is closed, now we can close inbound. */
    if (ch->dbuf_sz == 0 && ch->outbound.event.data.fd < 0)
    {
        s_proxy_raw_close_inbound_channel(raw, ch);
        return;
    }

    /* If dbuf is not full, continue reading from outbound. */
    if (ch->dbuf_sz < sizeof(ch->dbuf) && ch->outbound.event.data.fd >= 0 &&
        !(ch->outbound.event.events & EPOLLIN))
    {
        int op = ch->outbound.event.events == 0 ? EPOLL_CTL_ADD : EPOLL_CTL_MOD;
        ch->outbound.event.events |= EPOLLIN;
        epoll_ctl(raw->epollfd, op, ch->outbound.event.data.fd, &ch->outbound.event);
    }
}

static void s_proxy_raw_handle_inbound_tcp_listen(nt_proxy_raw_t* raw, proxy_raw_channel_t* ch)
{
    /* Accept connection and close listen fd. */
    int fd = nt_accept(ch->inbound.event.data.fd);
    if (fd < 0)
    {
        s_proxy_raw_close_inbound_outbound_channel(raw, ch);
        return;
    }
    s_proxy_raw_close_inbound_channel(raw, ch);

    /* Register read. */
    ch->inbound.event.data.fd = fd;
    ch->inbound.event.events = EPOLLIN;
    epoll_ctl(raw->epollfd, EPOLL_CTL_ADD, fd, &ch->inbound.event);
}

static void s_proxy_raw_handle_inbound_tcp_r(nt_proxy_raw_t* raw, proxy_raw_channel_t* ch)
{
    int ret;

    /* Read from inbound. */
    uint8_t* buf = ch->ubuf + ch->ubuf_sz;
    size_t   bufsz = sizeof(ch->ubuf) - ch->ubuf_sz;
    ssize_t  read_sz = nt_read(ch->inbound.event.data.fd, buf, bufsz);
    if (read_sz < 0)
    {
        ret = read_sz;
        if (ret != NT_ERR(EAGAIN) && ret != NT_ERR(EWOULDBLOCK))
        { /* Peer error */
            LOG_D("[CHID=%d] Inbound read() failed: (%d) %s. Close inbound.", ch->chid, ret,
                  NT_STRERROR(ret));
            s_proxy_raw_close_inbound_channel(raw, ch);
        }
        return;
    }
    else if (read_sz == 0)
    { /* Peer close. */
        LOG_D("[CHID=%d] Inbound peer closed. Close inbound.", ch->chid);
        s_proxy_raw_close_inbound_channel(raw, ch);
        return;
    }
    else
    {
        ch->ubuf_sz += read_sz;
    }

    /* Write to outbound. */
    if (ch->outbound.event.data.fd >= 0 && ch->ubuf_sz > 0 &&
        !(ch->outbound.event.events & EPOLLOUT))
    {
        int op = ch->outbound.event.events == 0 ? EPOLL_CTL_ADD : EPOLL_CTL_MOD;
        ch->outbound.event.events |= EPOLLOUT;
        epoll_ctl(raw->epollfd, op, ch->outbound.event.data.fd, &ch->outbound.event);
    }

    /* If ubuf is full, remove EPOLLIN for inbound. */
    if (ch->inbound.event.data.fd >= 0 && ch->ubuf_sz == sizeof(ch->ubuf))
    {
        ch->inbound.event.events &= ~EPOLLIN;
        int op = ch->inbound.event.events == 0 ? EPOLL_CTL_DEL : EPOLL_CTL_MOD;
        epoll_ctl(raw->epollfd, op, ch->inbound.event.data.fd, &ch->inbound.event);
    }
}

static void s_proxy_raw_handle_inbound_r(nt_proxy_raw_t* raw, proxy_raw_channel_t* ch)
{
    if (ch->islisten)
    {
        s_proxy_raw_handle_inbound_tcp_listen(raw, ch);
        /* Cancel listen flag. */
        ch->islisten = 0;
        return;
    }

    s_proxy_raw_handle_inbound_tcp_r(raw, ch);
}

static void s_proxy_raw_handle_outbound_w(nt_proxy_raw_t* raw, proxy_raw_channel_t* ch)
{
    ssize_t write_sz = nt_write(ch->outbound.event.data.fd, ch->ubuf, ch->ubuf_sz);
    if (write_sz < 0)
    {
        s_proxy_raw_close_outbound_channel(raw, ch);
    }
    else
    {
        ch->ubuf_sz -= write_sz;
    }

    /* If outbound is closed and dbuf is empty, close inbound. */
    if (ch->outbound.event.data.fd < 0 && ch->dbuf_sz == 0)
    {
        s_proxy_raw_close_inbound_channel(raw, ch);
        return;
    }

    if (ch->ubuf_sz > 0)
    { /* ubuf is not empty, move buffer and try again. */
        memmove(ch->ubuf, ch->ubuf + write_sz, ch->ubuf_sz);
    }
    else if (ch->outbound.event.data.fd >= 0)
    { /* ubuf is empty, remove EPOLLOUT */
        ch->outbound.event.events &= ~EPOLLOUT;
        int op = ch->outbound.event.events == 0 ? EPOLL_CTL_DEL : EPOLL_CTL_MOD;
        epoll_ctl(raw->epollfd, op, ch->outbound.event.data.fd, &ch->outbound.event);
    }

    /* If ubuf is empty and inbound is closed, now we can close outbound. */
    if (ch->ubuf_sz == 0 && ch->inbound.event.data.fd < 0)
    {
        s_proxy_raw_close_outbound_channel(raw, ch);
        return;
    }

    /* If ubuf is not full, continue reading from inbound. */
    if (ch->ubuf_sz < sizeof(ch->ubuf) && !(ch->inbound.event.events & EPOLLIN))
    {
        int op = ch->inbound.event.events == 0 ? EPOLL_CTL_ADD : EPOLL_CTL_MOD;
        ch->inbound.event.events |= EPOLLIN;
        epoll_ctl(raw->epollfd, op, ch->inbound.event.data.fd, &ch->inbound.event);
    }
}

static void s_proxy_raw_handle_outbound_r(nt_proxy_raw_t* raw, proxy_raw_channel_t* ch)
{
    int      ret;
    uint8_t* buf = ch->dbuf + ch->dbuf_sz;
    size_t   bufsz = sizeof(ch->dbuf) - ch->dbuf_sz;

    ssize_t read_sz = nt_read(ch->outbound.event.data.fd, buf, bufsz);
    if (read_sz < 0)
    {
        ret = read_sz;
        if (ret != NT_ERR(EAGAIN) && ret != NT_ERR(EWOULDBLOCK))
        {
            LOG_D("[CHID=%d] Outbound read() failed: (%d) %s. Close outbound.", ch->chid, ret,
                  NT_STRERROR(ret));
            s_proxy_raw_close_outbound_channel(raw, ch);
        }
        return;
    }
    else if (read_sz == 0)
    {
        LOG_D("[CHID=%d] Outbound peer closed. Close outbound.", ch->chid);
        s_proxy_raw_close_outbound_channel(raw, ch);
        return;
    }
    else
    {
        ch->dbuf_sz += read_sz;
    }

    /* Write to inbound. */
    if (ch->inbound.event.data.fd >= 0 && ch->dbuf_sz > 0 && !(ch->inbound.event.events & EPOLLOUT))
    {
        int op = ch->inbound.event.events == 0 ? EPOLL_CTL_ADD : EPOLL_CTL_MOD;
        ch->inbound.event.events |= EPOLLOUT;
        epoll_ctl(raw->epollfd, op, ch->inbound.event.data.fd, &ch->inbound.event);
    }

    /* If dbuf is full, remove EPOLLIN for inbound. */
    if (ch->outbound.event.data.fd >= 0 && ch->dbuf_sz == sizeof(ch->dbuf))
    {
        ch->outbound.event.events &= ~EPOLLIN;
        int op = ch->outbound.event.events == 0 ? EPOLL_CTL_DEL : EPOLL_CTL_MOD;
        epoll_ctl(raw->epollfd, op, ch->outbound.event.data.fd, &ch->outbound.event);
    }
}

static void s_proxy_raw_handle_channel(nt_proxy_raw_t* raw, proxy_raw_channel_t* ch,
                                       struct epoll_event* event)
{
    if (ch->inbound.event.data.fd == event->data.fd)
    {
        if (event->events & EPOLLOUT)
        {
            s_proxy_raw_handle_inbound_w(raw, ch);
        }
        if (event->events & EPOLLIN)
        {
            s_proxy_raw_handle_inbound_r(raw, ch);
        }
    }
    else if (ch->outbound.event.data.fd == event->data.fd)
    {
        if (event->events & EPOLLOUT)
        {
            s_proxy_raw_handle_outbound_w(raw, ch);
        }
        if (event->events & EPOLLIN)
        {
            s_proxy_raw_handle_outbound_r(raw, ch);
        }
    }

    if (ch->inbound.event.data.fd < 0 && ch->ubuf_sz == 0)
    {
        LOG_D("[CHID=%d] Inbound is closed and nothing to upload. Close outbound.", ch->chid);
        s_proxy_raw_close_outbound_channel(raw, ch);
    }
    if (ch->outbound.event.data.fd < 0 && ch->dbuf_sz == 0)
    {
        LOG_D("[CHID=%d] Outbound is closed and nothing to download. Close inbound.", ch->chid);
        s_proxy_raw_close_inbound_channel(raw, ch);
    }
    if (ch->inbound.event.data.fd < 0 && ch->outbound.event.data.fd < 0)
    {
        LOG_D("[CHID=%d] Both inbound and outbound are closed. Remove channel.", ch->chid);
        s_proxy_remove_and_release_channel(raw, ch);
    }
}

static void s_proxy_raw_handle(nt_proxy_raw_t* raw, struct epoll_event* event)
{
    if (event->data.fd == raw->eventfd)
    {
        uint64_t buff;
        read(raw->eventfd, &buff, sizeof(buff));
        s_proxy_raw_handle_event(raw);
    }
    else
    {
        raw_sock_t tmp;
        tmp.event.data.fd = event->data.fd;
        ev_map_node_t* it = ev_map_find(&raw->sock_map, &tmp.node);
        assert(it != NULL);
        raw_sock_t*          sock = container_of(it, raw_sock_t, node);
        proxy_raw_channel_t* ch = sock->channel;
        s_proxy_raw_handle_channel(raw, ch, event);
    }
}

static void* s_proxy_raw_loop(void* arg)
{
    nt_proxy_raw_t* raw = arg;
    const int       maxevents = ARRAY_SIZE(raw->events);

    int i, ret;
    while (raw->looping)
    {
        ret = epoll_wait(raw->epollfd, raw->events, maxevents, 100);
        if (ret == 0)
        { /* Timeout */
            continue;
        }
        else if (ret < 0)
        {
            NT_ASSERT(errno == EINTR, "epoll_wait() failed: (%d) %s.", errno, strerror(errno));
            continue;
        }

        for (i = 0; i < ret; i++)
        {
            struct epoll_event* event = &raw->events[i];
            s_proxy_raw_handle(raw, event);
        }
    }

    return NULL;
}

static int s_proxy_raw_on_cmp_sock(const ev_map_node_t* key1, const ev_map_node_t* key2, void* arg)
{
    (void)arg;
    const raw_sock_t* s1 = container_of(key1, raw_sock_t, node);
    const raw_sock_t* s2 = container_of(key2, raw_sock_t, node);
    return s1->event.data.fd - s2->event.data.fd;
}

static int s_proxy_raw_on_cmp_channel(const ev_map_node_t* key1, const ev_map_node_t* key2,
                                      void* arg)
{
    (void)arg;
    const proxy_raw_channel_t* ch1 = container_of(key1, proxy_raw_channel_t, node);
    const proxy_raw_channel_t* ch2 = container_of(key2, proxy_raw_channel_t, node);
    return ch1->chid - ch2->chid;
}

static void s_proxy_raw_channel_release(struct nt_proxy* thiz, int channel)
{
    nt_proxy_raw_t*     raw = container_of(thiz, nt_proxy_raw_t, basis);
    proxy_raw_action_t* act = nt_malloc(sizeof(proxy_raw_action_t));
    act->type = RAW_CHANNEL_RELEASE;
    act->data.chid = channel;

    pthread_mutex_lock(&raw->actq_mutex);
    ev_list_push_back(&raw->actq, &act->node);
    pthread_mutex_unlock(&raw->actq_mutex);

    s_proxy_raw_weakup(raw);
}

static int s_proxy_raw_make(nt_proxy_t** proxy, const url_comp_t* url)
{
    (void)url;

    int             retval = 0;
    nt_proxy_raw_t* raw = nt_calloc(1, sizeof(nt_proxy_raw_t));
    raw->basis.release = s_proxy_raw_release;
    raw->basis.channel_create = s_proxy_raw_channel_create;
    raw->basis.channel_release = s_proxy_raw_channel_release;
    ev_map_init(&raw->sock_map, s_proxy_raw_on_cmp_sock, NULL);
    ev_map_init(&raw->channel_map, s_proxy_raw_on_cmp_channel, NULL);
    ev_list_init(&raw->actq);
    pthread_mutex_init(&raw->actq_mutex, NULL);

    if ((raw->epollfd = epoll_create1(EPOLL_CLOEXEC)) < 0)
    {
        retval = errno;
        goto ERR_EPOLL_CREATE;
    }
    if ((raw->eventfd = eventfd(0, EFD_CLOEXEC)) < 0)
    {
        retval = errno;
        goto ERR_EVENTFD;
    }

    struct epoll_event event;
    event.data.fd = raw->eventfd;
    event.events = EPOLLIN;
    epoll_ctl(raw->epollfd, EPOLL_CTL_ADD, raw->eventfd, &event);

    raw->looping = 1;
    if ((retval = pthread_create(&raw->tid, NULL, s_proxy_raw_loop, raw)) != 0)
    {
        goto ERR_PTHREAD_CREATE;
    }

    *proxy = &raw->basis;
    return 0;

ERR_PTHREAD_CREATE:
    close(raw->eventfd);
ERR_EVENTFD:
    close(raw->epollfd);
ERR_EPOLL_CREATE:
    pthread_mutex_destroy(&raw->actq_mutex);
    return retval;
}

const nt_proxy_protocol_t nt_proxy_protocol_raw = {
    "raw",
    s_proxy_raw_make,
};
