#include <assert.h>
#include <errno.h>
#include <pthread.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/epoll.h>
#include "utils/defs.h"
#include "utils/memory.h"
#include "utils/list.h"
#include "utils/socket.h"
#include "utils/log.h"
#include "socks5.h"
#include "config.h"

typedef enum socks5_stage
{
    SOCKS5_INIT,
    SOCKS5_AUTH,
    SOCKS5_CONNECT,
    SOCKS5_FINISH,
} socks5_stage_t;

typedef struct socks5_sock
{
    ev_map_node_t          node;
    struct epoll_event     event; /* EPOLLIN / EPOLLOUT */
    struct socks5_channel* channel;
} socks5_sock_t;

typedef struct socks5_channel
{
    ev_list_node_t          node;
    socks5_sock_t           inbound;
    socks5_sock_t           outbound;
    socks5_stage_t          stage;
    size_t                  ubuf_sz;                     /* Data size in upload buffer. */
    size_t                  dbuf_sz;                     /* Data size in download buffer. */
    uint8_t                 ubuf[NT_SOCKET_BUFFER_SIZE]; /* Upload buffer. Read from inbound, and send to outbound. */
    uint8_t                 dbuf[NT_SOCKET_BUFFER_SIZE]; /* Download buffer. Read from outbound, and send to inbound. */
    struct sockaddr_storage peeraddr;                    /* Peer address. */
} socks5_channel_t;

typedef struct nt_proxy_socks5
{
    nt_proxy_t basis; /* Base handle. */

    int                 tcp_listen_ipv4_fd;   /* TCP listen ipv4 fd. */
    struct sockaddr_in  tcp_listen_ipv4_addr; /* TCP listen ipv4 addr. */
    int                 tcp_listen_ipv6_fd;   /* TCP listen ipv6 fd. */
    struct sockaddr_in6 tcp_listen_ipv6_addr; /* TCP listen ipv6 addr. */

    struct sockaddr_storage server_addr;     /* Socks5 server address. */
    char*                   server_username; /* Socks5 server username. */
    char*                   server_password; /* Socks5 server password. */
    char*                   server_ip;       /* Socks5 server ip. */
    int                     server_port;     /* Socks5 server port. */

    pthread_t          tid;          /* Thread ID. */
    int                looping;      /* Looping flag. */
    int                epollfd;      /* epoll fd. */
    ev_map_t           sock_map;     /* #socks5_sock_t */
    ev_list_t          channel_list; /* #socks5_channel_t */
    struct epoll_event events[1024]; /* Events cache. */

    pthread_mutex_t addr_queue_mutex; /* Mutex for #nt_proxy_socks5_t::addr_queue. */
    ev_list_t       addr_queue;       /* #socks5_channel_t */
} nt_proxy_socks5_t;

static void s_socks5_release_server_info(nt_proxy_socks5_t* socks5)
{
    if (socks5->server_username != NULL)
    {
        nt_free(socks5->server_username);
        socks5->server_username = NULL;
    }
    if (socks5->server_password != NULL)
    {
        nt_free(socks5->server_password);
        socks5->server_password = NULL;
    }
    if (socks5->server_ip != NULL)
    {
        nt_free(socks5->server_ip);
        socks5->server_ip = NULL;
    }
}

static void s_socks5_close_inbound(nt_proxy_socks5_t* socks5, socks5_channel_t* channel)
{
    if (channel->inbound.event.events != 0)
    {
        epoll_ctl(socks5->epollfd, EPOLL_CTL_DEL, channel->inbound.event.data.fd, &channel->inbound.event);
        channel->inbound.event.events = 0;
    }
    if (channel->inbound.event.data.fd >= 0)
    {
        close(channel->inbound.event.data.fd);
        channel->inbound.event.data.fd = -1;
    }
}

static void s_socks5_close_outbound(nt_proxy_socks5_t* socks5, socks5_channel_t* channel)
{
    if (channel->outbound.event.events != 0)
    {
        epoll_ctl(socks5->epollfd, EPOLL_CTL_DEL, channel->outbound.event.data.fd, &channel->outbound.event);
        channel->outbound.event.events = 0;
    }
    if (channel->outbound.event.data.fd >= 0)
    {
        close(channel->outbound.event.data.fd);
        channel->outbound.event.data.fd = -1;
    }
}

static void s_socks5_close_inbound_outbound(nt_proxy_socks5_t* socks5, socks5_channel_t* channel)
{
    s_socks5_close_inbound(socks5, channel);
    s_socks5_close_outbound(socks5, channel);
}

static void s_socks5_channel_release(nt_proxy_socks5_t* socks5, socks5_channel_t* channel)
{
    s_socks5_close_inbound_outbound(socks5, channel);
    nt_free(channel);
}

static void s_socks5_close_tcp_ipv4(nt_proxy_socks5_t* socks5)
{
    if (socks5->tcp_listen_ipv4_fd >= 0)
    {
        close(socks5->tcp_listen_ipv4_fd);
        socks5->tcp_listen_ipv4_fd = -1;
    }
}

static void s_socks5_close_tcp_ipv6(nt_proxy_socks5_t* socks5)
{
    if (socks5->tcp_listen_ipv6_fd >= 0)
    {
        close(socks5->tcp_listen_ipv6_fd);
        socks5->tcp_listen_ipv6_fd = -1;
    }
}

static void s_socks5_channel_remove_and_release(nt_proxy_socks5_t* socks5, socks5_channel_t* channel)
{
    ev_list_erase(&socks5->channel_list, &channel->node);
    ev_map_erase(&socks5->sock_map, &channel->inbound.node);
    ev_map_erase(&socks5->sock_map, &channel->outbound.node);
    s_socks5_channel_release(socks5, channel);
}

static void s_nt_proxy_socks5_release(struct nt_proxy* thiz)
{
    ev_list_node_t*    it;
    nt_proxy_socks5_t* socks5 = container_of(thiz, nt_proxy_socks5_t, basis);

    socks5->looping = 0;
    pthread_join(socks5->tid, NULL);
    while ((it = ev_list_pop_front(&socks5->addr_queue)) != NULL)
    {
        socks5_channel_t* channel = container_of(it, socks5_channel_t, node);
        s_socks5_channel_release(socks5, channel);
    }
    while ((it = ev_list_begin(&socks5->channel_list)) != NULL)
    {
        socks5_channel_t* channel = container_of(it, socks5_channel_t, node);
        s_socks5_channel_remove_and_release(socks5, channel);
    }
    if (socks5->epollfd >= 0)
    {
        close(socks5->epollfd);
        socks5->epollfd = -1;
    }
    pthread_mutex_destroy(&socks5->addr_queue_mutex);
    s_socks5_close_tcp_ipv4(socks5);
    s_socks5_close_tcp_ipv6(socks5);
    s_socks5_release_server_info(socks5);
    nt_free(socks5);
}

static void s_proxy_socks5_queue(struct nt_proxy* thiz, int type, struct sockaddr* addr)
{
    if (type != SOCK_STREAM)
    {
        return;
    }

    nt_proxy_socks5_t* socks5 = container_of(thiz, nt_proxy_socks5_t, basis);
    socks5_channel_t*  channel = nt_malloc(sizeof(socks5_channel_t));
    channel->inbound.event.data.fd = -1;
    channel->inbound.event.events = 0;
    channel->inbound.channel = channel;
    channel->outbound.event.data.fd = -1;
    channel->outbound.event.events = 0;
    channel->outbound.channel = channel;
    channel->stage = SOCKS5_INIT;
    nt_sockaddr_copy((struct sockaddr*)&channel->peeraddr, addr);

    pthread_mutex_lock(&socks5->addr_queue_mutex);
    ev_list_push_back(&socks5->addr_queue, &channel->node);
    pthread_mutex_unlock(&socks5->addr_queue_mutex);
}

/**
 * @brief Parser url.
 * Syntax:
 * socks5://[user[:pass]@][host[:port]]
 */
static int s_socks5_url_parser(nt_proxy_socks5_t* socks5, const char* url)
{
    int         ret;
    const char* origurl = url;
    socks5->server_ip = NULL;
    socks5->server_port = NT_DEFAULT_SOCKS5_PORT;
    socks5->server_username = NULL;
    socks5->server_password = NULL;

    /* Check prefix. */
    if (strncmp(url, "socks5://", 9) != 0)
    {
        return EINVAL;
    }
    url += 9;

    /* Parser username and password. */
    const char* p_userpass = strstr(url, "@");
    if (p_userpass != NULL)
    {
        socks5->server_username = nt_strndup(url, p_userpass - url);
        char* p_user = strstr(socks5->server_username, ":");
        if (p_user != NULL)
        {
            socks5->server_password = nt_strdup(p_user + 1);
            *p_user = '\0';
        }

        if (strlen(socks5->server_username) > 255 || strlen(socks5->server_password) > 255)
        {
            goto ERR;
        }
        url = p_userpass + 1;
    }

    /* Passer ip and port. */
    const char* p_port = strstr(url, ":");
    if (p_port != NULL)
    {
        socks5->server_ip = nt_strndup(url, p_port - url - 1);
        if (sscanf(p_port + 1, "%d", &socks5->server_port) != 1)
        {
            LOG_E("Invalid port for `%s`.", origurl);
            ret = EINVAL;
            goto ERR;
        }
    }
    else
    {
        socks5->server_ip = nt_strdup(url);
    }

    ret = nt_ip_addr(socks5->server_ip, socks5->server_port, (struct sockaddr*)&socks5->server_addr);
    if (ret != 0)
    {
        goto ERR;
    }
    return 0;

ERR:
    s_socks5_release_server_info(socks5);
    return ret;
}

static socks5_channel_t* s_socks5_pop_addr(nt_proxy_socks5_t* socks5)
{
    ev_list_node_t* it;
    pthread_mutex_lock(&socks5->addr_queue_mutex);
    it = ev_list_pop_front(&socks5->addr_queue);
    pthread_mutex_unlock(&socks5->addr_queue_mutex);
    assert(it != NULL);
    socks5_channel_t* channel = container_of(it, socks5_channel_t, node);
    return channel;
}

static void s_socks5_handle_tcp_accept(nt_proxy_socks5_t* socks5, int listen_fd)
{
    int               ret;
    socks5_channel_t* channel = s_socks5_pop_addr(socks5);

    /* Setup inbound and outbound fd. */
    if ((channel->inbound.event.data.fd = accept(listen_fd, NULL, NULL)) < 0)
    {
        s_socks5_channel_release(socks5, channel);
        return;
    }
    nt_nonblock(channel->inbound.event.data.fd, 1);
    if ((channel->outbound.event.data.fd = socket(socks5->server_addr.ss_family, SOCK_STREAM, 0)) < 0)
    {
        s_socks5_channel_release(socks5, channel);
        return;
    }
    nt_nonblock(channel->outbound.event.data.fd, 1);

    /* Connect to socks5 server. */
    LOG_D("Connecting to socks5 server %s:%d.", socks5->server_ip, socks5->server_port);
    ret = connect(channel->outbound.event.data.fd, (struct sockaddr*)&socks5->server_addr, sizeof(socks5->server_addr));
    if (ret < 0)
    {
        ret = errno;
        if (ret != EAGAIN)
        {
            s_socks5_channel_release(socks5, channel);
            LOG_I("Connect peer failed: (%d) %s.", ret, strerror(ret));
            return;
        }
    }

    /* No matter connecting is in process or finished, we just need to wait for write event to do auth. */
    channel->outbound.event.events = EPOLLOUT;
    epoll_ctl(socks5->epollfd, EPOLL_CTL_ADD, channel->outbound.event.data.fd, &channel->outbound.event);

    /* Save record. */
    ev_list_push_back(&socks5->channel_list, &channel->node);
    ev_map_insert(&socks5->sock_map, &channel->inbound.node);
    ev_map_insert(&socks5->sock_map, &channel->outbound.node);

    /* We support USERNAME/PASSWORD. */
    channel->ubuf_sz = 4;
    channel->ubuf[0] = 5; // socks5
    channel->ubuf[1] = 2; // NMETHODS
    channel->ubuf[2] = 0; // NO AUTHENTICATION REQUIRED
    channel->ubuf[3] = 2; // USERNAME/PASSWORD

    /* Remove USERNAME/PASSWORD. */
    if (socks5->server_username == NULL)
    {
        channel->ubuf_sz = 3;
        channel->ubuf[1] = 1;
    }
}

static void s_socks5_handle_stage_init_w(nt_proxy_socks5_t* socks5, socks5_channel_t* channel)
{
    ssize_t write_sz = nt_write(channel->outbound.event.data.fd, channel->ubuf, channel->ubuf_sz);
    if (write_sz < 0)
    {
        LOG_D("Write to socks5 server failed: (%d) %s.", errno, strerror(errno));
        s_socks5_close_inbound_outbound(socks5, channel);
        return;
    }

    channel->ubuf_sz -= write_sz;
    if (channel->ubuf_sz != 0)
    { /* Not send finish. */
        memmove(channel->ubuf, channel->ubuf + write_sz, channel->ubuf_sz);
        return;
    }

    channel->outbound.event.events = EPOLLIN;
    epoll_ctl(socks5->epollfd, EPOLL_CTL_MOD, channel->outbound.event.data.fd, &channel->outbound.event);
}

/**
 * @see rfc1929
 */
static void s_socks5_handle_stage_init_setup_auth_info(nt_proxy_socks5_t* socks5, socks5_channel_t* channel)
{
    size_t username_sz = strlen(socks5->server_username);
    assert(username_sz <= 255);
    size_t password_sz = strlen(socks5->server_password);
    assert(password_sz <= 255);

    channel->ubuf_sz = 0;
    channel->ubuf[channel->ubuf_sz++] = 0x01;
    channel->ubuf[channel->ubuf_sz++] = username_sz;
    memcpy(channel->ubuf + channel->ubuf_sz, socks5->server_username, username_sz);
    channel->ubuf_sz += username_sz;
    channel->ubuf[channel->ubuf_sz++] = password_sz;
    memcpy(channel->ubuf + channel->ubuf_sz, socks5->server_password, password_sz);
    channel->ubuf_sz += password_sz;
}

static void s_socks5_handle_stage_init_r(nt_proxy_socks5_t* socks5, socks5_channel_t* channel)
{
    uint8_t* buf = channel->dbuf + channel->dbuf_sz;
    size_t   bufsz = ARRAY_SIZE(channel->dbuf) - channel->dbuf_sz;
    ssize_t  read_sz = nt_read(channel->outbound.event.data.fd, buf, bufsz);
    if (read_sz == 0)
    { /* Peer close. */
        s_socks5_close_inbound_outbound(socks5, channel);
        return;
    }
    else if (read_sz < 0)
    {
        if (errno = EAGAIN)
        { /* Try again.*/
            return;
        }
        s_socks5_close_inbound_outbound(socks5, channel);
        return;
    }
    channel->dbuf_sz += read_sz;

    if (channel->dbuf_sz < 2)
    { /* Continue read. */
        return;
    }

    switch (channel->dbuf[1])
    {
    case 0x00: /* NO AUTHENTICATION REQUIRED */
        channel->stage = SOCKS5_FINISH;
        break;
    case 0x02: /*USERNAME/PASSWORD*/
        channel->stage = SOCKS5_AUTH;
        s_socks5_handle_stage_init_setup_auth_info(socks5, channel);
        channel->outbound.event.events = EPOLLOUT;
        epoll_ctl(socks5->epollfd, EPOLL_CTL_MOD, channel->outbound.event.data.fd, &channel->outbound.event);
        break;
    case 0xff: /* NO ACCEPTABLE METHODS */
        LOG_I("Server refuse method selection.");
        // fall through
    default: /* Unsupport methods */
        s_socks5_close_inbound_outbound(socks5, channel);
        break;
    }

    channel->dbuf_sz -= 2;
    if (channel->dbuf_sz != 0)
    {
        memmove(channel->dbuf, channel->dbuf + 2, channel->dbuf_sz);
    }
}

static void s_socks5_handle_stage_init(nt_proxy_socks5_t* socks5, socks5_channel_t* channel, struct epoll_event* event)
{
    if (event->events == EPOLLOUT)
    {
        s_socks5_handle_stage_init_w(socks5, channel);
    }
    else if (event->events == EPOLLIN)
    {
        s_socks5_handle_stage_init_r(socks5, channel);
    }
    else
    {
        LOG_F_ABORT("Stage stat=%d error.", SOCKS5_INIT);
    }
}

static void s_socks5_handle_stage_auth_w(nt_proxy_socks5_t* socks5, socks5_channel_t* channel)
{
    ssize_t write_sz = nt_write(channel->outbound.event.data.fd, channel->ubuf, channel->ubuf_sz);
    if (write_sz < 0)
    {
        s_socks5_close_inbound_outbound(socks5, channel);
        return;
    }

    channel->ubuf_sz -= write_sz;
    if (channel->ubuf_sz != 0)
    { /* Continue write. */
        memmove(channel->ubuf, channel->ubuf + write_sz, channel->ubuf_sz);
        return;
    }

    channel->outbound.event.events = EPOLLIN;
    epoll_ctl(socks5->epollfd, EPOLL_CTL_MOD, channel->outbound.event.data.fd, &channel->outbound.event);
}

static void s_socks5_handle_stage_auth_r(nt_proxy_socks5_t* socks5, socks5_channel_t* channel)
{
    uint8_t* buf = channel->dbuf + channel->dbuf_sz;
    size_t   bufsz = ARRAY_SIZE(channel->dbuf) - channel->dbuf_sz;
    ssize_t  read_sz = nt_read(channel->outbound.event.data.fd, buf, bufsz);
    if (read_sz == 0)
    {
        s_socks5_close_inbound_outbound(socks5, channel);
        return;
    }
    if (read_sz < 0)
    {
        if (errno == EAGAIN)
        { /* Continue read. */
            return;
        }
        s_socks5_close_inbound_outbound(socks5, channel);
        return;
    }
    channel->dbuf_sz += read_sz;

    if (channel->dbuf_sz < 2)
    { /* Continue read. */
        return;
    }

    if (channel->dbuf[1] != 0)
    { /* Server return failure. */
        s_socks5_close_inbound_outbound(socks5, channel);
        return;
    }

    /* Change state. */
    channel->stage = SOCKS5_CONNECT;
    channel->outbound.event.events = EPOLLOUT;
    epoll_ctl(socks5->epollfd, EPOLL_CTL_MOD, channel->outbound.event.data.fd, &channel->outbound.event);

    channel->ubuf[0] = 0x05;
    channel->ubuf[1] = 0x01;
    channel->ubuf[2] = 0x00;
    if (channel->peeraddr.ss_family == AF_INET)
    {
        struct sockaddr_in* addr = (struct sockaddr_in*)&channel->peeraddr;
        channel->ubuf[3] = 0x01;
        memcpy(&channel->ubuf[4], &addr->sin_addr, 4);
        memcpy(&channel->ubuf[8], &addr->sin_port, 2);
        channel->ubuf_sz = 10;
    }
    else
    {
        struct sockaddr_in6* addr = (struct sockaddr_in6*)&channel->peeraddr;
        channel->ubuf[3] = 0x04;
        memcpy(&channel->ubuf[4], &addr->sin6_addr, 16);
        memcpy(&channel->ubuf[20], &addr->sin6_port, 2);
        channel->ubuf_sz = 22;
    }

    channel->dbuf_sz -= 2;
    if (channel->dbuf_sz != 0)
    {
        memmove(channel->dbuf, channel->dbuf + 2, channel->dbuf_sz);
    }
}

static void s_socks5_handle_stage_auth(nt_proxy_socks5_t* socks5, socks5_channel_t* channel, struct epoll_event* event)
{
    if (event->events == EPOLLOUT)
    {
        s_socks5_handle_stage_auth_w(socks5, channel);
    }
    else if (event->events == EPOLLIN)
    {
        s_socks5_handle_stage_auth_r(socks5, channel);
    }
    else
    {
        LOG_F_ABORT("Stage stat=%d error.", SOCKS5_AUTH);
    }
}

static void s_socks5_handle_stage_connect_w(nt_proxy_socks5_t* socks5, socks5_channel_t* channel)
{
    ssize_t write_sz = nt_write(channel->outbound.event.data.fd, channel->ubuf, channel->ubuf_sz);
    if (write_sz < 0)
    {
        s_socks5_close_inbound_outbound(socks5, channel);
        return;
    }

    channel->ubuf_sz -= write_sz;
    if (channel->ubuf_sz != 0)
    {
        memmove(channel->ubuf, channel->ubuf + write_sz, channel->ubuf_sz);
        return;
    }

    channel->outbound.event.events = EPOLLIN;
    epoll_ctl(socks5->epollfd, EPOLL_CTL_MOD, channel->outbound.event.data.fd, &channel->outbound.event);
}

static void s_socks5_handle_stage_connect_r(nt_proxy_socks5_t* socks5, socks5_channel_t* channel)
{
    uint8_t* buf = channel->dbuf + channel->dbuf_sz;
    size_t   bufsz = sizeof(channel->dbuf) - channel->dbuf_sz;
    ssize_t  read_sz = nt_read(channel->outbound.event.data.fd, buf, bufsz);
    if (read_sz == 0)
    {
        s_socks5_close_inbound_outbound(socks5, channel);
        return;
    }
    else if (read_sz < 0)
    {
        if (errno != EAGAIN)
        {
            s_socks5_close_inbound_outbound(socks5, channel);
        }
        return;
    }
    channel->dbuf_sz += read_sz;

    if (channel->dbuf_sz < 4)
    { /* Require atleast 4 bytes. */
        return;
    }

    if (channel->dbuf[1] != 0)
    {
        s_socks5_close_inbound_outbound(socks5, channel);
        return;
    }

    if (channel->dbuf[3] == 0x01)
    {
        if (channel->dbuf_sz < 10)
        {
            return;
        }
        channel->dbuf_sz -= 10;
    }
    else if (channel->dbuf[3] == 0x04)
    {
        if (channel->dbuf_sz < 22)
        {
            return;
        }
        channel->dbuf_sz -= 22;
    }
    else
    {
        s_socks5_close_inbound_outbound(socks5, channel);
    }

    channel->stage = SOCKS5_FINISH;
    channel->inbound.event.events = EPOLLIN;
    epoll_ctl(socks5->epollfd, EPOLL_CTL_ADD, channel->inbound.event.data.fd, &channel->inbound.event);

    LOG_D("socks5 server connect success.");
}

static void s_socks5_handle_stage_connect(nt_proxy_socks5_t* socks5, socks5_channel_t* channel,
                                          struct epoll_event* event)
{
    if (event->events == EPOLLOUT)
    {
        s_socks5_handle_stage_connect_w(socks5, channel);
    }
    else if (event->events == EPOLLIN)
    {
        s_socks5_handle_stage_connect_r(socks5, channel);
    }
    else
    {
        LOG_F_ABORT("Stage stat=%d error.", SOCKS5_CONNECT);
    }
}

static void s_socks5_handle_inbound_r(nt_proxy_socks5_t* socks5, socks5_channel_t* channel)
{
    /* Read from inbound. */
    uint8_t* buf = channel->ubuf + channel->ubuf_sz;
    size_t   bufsz = sizeof(channel->ubuf) - channel->ubuf_sz;
    ssize_t  read_sz = nt_read(channel->inbound.event.data.fd, buf, bufsz);
    if (read_sz == 0)
    { /* Peer close. */
        s_socks5_close_inbound(socks5, channel);
        return;
    }
    else if (read_sz < 0)
    {
        if (errno != EAGAIN)
        {
            s_socks5_close_inbound(socks5, channel);
        }
        return;
    }
    channel->ubuf_sz += read_sz;

    /* If ubuf is full, stop reading from inbound. */
    if (channel->ubuf_sz == sizeof(channel->ubuf) && (channel->inbound.event.events & EPOLLIN))
    {
        channel->inbound.event.events &= ~EPOLLIN;
        int op = channel->inbound.event.events == 0 ? EPOLL_CTL_DEL : EPOLL_CTL_MOD;
        epoll_ctl(socks5->epollfd, op, channel->inbound.event.data.fd, &channel->inbound.event);
    }

    /* Write to outbound. */
    if (channel->outbound.event.data.fd >= 0 && !(channel->outbound.event.events & EPOLLOUT))
    {
        int op = channel->outbound.event.events == 0 ? EPOLL_CTL_ADD : EPOLL_CTL_MOD;
        channel->outbound.event.events |= EPOLLOUT;
        epoll_ctl(socks5->epollfd, op, channel->outbound.event.data.fd, &channel->outbound.event);
    }
}

static void s_socks5_handle_inbound_w(nt_proxy_socks5_t* socks5, socks5_channel_t* channel)
{
    /* Write to inbound. */
    ssize_t write_sz = nt_write(channel->inbound.event.data.fd, channel->dbuf, channel->dbuf_sz);
    if (write_sz < 0)
    {
        s_socks5_close_inbound(socks5, channel);
        return;
    }

    channel->dbuf_sz -= write_sz;
    if (channel->dbuf_sz > 0)
    { /* Maintain buffer. */
        memmove(channel->dbuf, channel->dbuf + write_sz, channel->dbuf_sz);
    }
    else
    { /* dbuf is empty, no need write. */
        channel->inbound.event.events &= ~EPOLLOUT;
        int op = channel->inbound.event.events == 0 ? EPOLL_CTL_DEL : EPOLL_CTL_MOD;
        epoll_ctl(socks5->epollfd, op, channel->inbound.event.data.fd, &channel->inbound.event);
    }

    /* If dbuf have free space, and outbound is not reading, reset to read. */
    if (channel->dbuf_sz < sizeof(channel->dbuf) && channel->outbound.event.data.fd >= 0 &&
        !(channel->outbound.event.events & EPOLLIN))
    {
        int op = channel->outbound.event.events == 0 ? EPOLL_CTL_ADD : EPOLL_CTL_MOD;
        channel->outbound.event.events |= EPOLLIN;
        epoll_ctl(socks5->epollfd, op, channel->outbound.event.data.fd, &channel->outbound.event);
    }
}

static void s_socks5_handle_outbound_r(nt_proxy_socks5_t* socks5, socks5_channel_t* channel)
{
    /* Read from outbound. */
    uint8_t* buf = channel->dbuf + channel->dbuf_sz;
    size_t   bufsz = sizeof(channel->dbuf) - channel->dbuf_sz;
    ssize_t  read_sz = nt_read(channel->outbound.event.data.fd, buf, bufsz);
    if (read_sz == 0)
    { /* Peer close. */
        s_socks5_close_outbound(socks5, channel);
        return;
    }
    else if (read_sz < 0)
    {
        if (errno != EAGAIN)
        {
            s_socks5_close_outbound(socks5, channel);
        }
        return;
    }
    channel->dbuf_sz += read_sz;

    /* If ubuf is full, stop reading from outbound. */
    if (channel->dbuf_sz == sizeof(channel->dbuf) && (channel->outbound.event.events & EPOLLIN))
    {
        channel->outbound.event.events &= ~EPOLLIN;
        int op = channel->outbound.event.events == 0 ? EPOLL_CTL_DEL : EPOLL_CTL_MOD;
        epoll_ctl(socks5->epollfd, op, channel->outbound.event.data.fd, &channel->outbound.event);
    }

    /* Write to inbound. */
    if (channel->inbound.event.data.fd >= 0 && !(channel->inbound.event.events & EPOLLOUT))
    {
        int op = channel->inbound.event.events == 0 ? EPOLL_CTL_ADD : EPOLL_CTL_MOD;
        channel->inbound.event.events |= EPOLLOUT;
        epoll_ctl(socks5->epollfd, op, channel->inbound.event.data.fd, &channel->inbound.event);
    }
}

static void s_socks5_handle_outbound_w(nt_proxy_socks5_t* socks5, socks5_channel_t* channel)
{
    /* Write to outbound. */
    ssize_t write_sz = nt_write(channel->outbound.event.data.fd, channel->ubuf, channel->ubuf_sz);
    if (write_sz < 0)
    {
        s_socks5_close_outbound(socks5, channel);
        return;
    }

    channel->ubuf_sz -= write_sz;
    if (channel->ubuf_sz > 0)
    { /* Maintain buffer. */
        memmove(channel->ubuf, channel->ubuf + write_sz, channel->ubuf_sz);
    }
    else
    { /* ubuf is empty, no need write. */
        channel->outbound.event.events &= ~EPOLLOUT;
        int op = channel->outbound.event.events == 0 ? EPOLL_CTL_DEL : EPOLL_CTL_MOD;
        epoll_ctl(socks5->epollfd, op, channel->outbound.event.data.fd, &channel->outbound.event);
    }

    /* If ubuf have free space, and inbound is not reading, reset to read. */
    if (channel->inbound.event.data.fd >= 0 && channel->ubuf_sz < sizeof(channel->ubuf) &&
        !(channel->inbound.event.events & EPOLLIN))
    {
        int op = channel->inbound.event.events == 0 ? EPOLL_CTL_ADD : EPOLL_CTL_MOD;
        channel->inbound.event.events |= EPOLLIN;
        epoll_ctl(socks5->epollfd, op, channel->inbound.event.data.fd, &channel->inbound.event);
    }
}

static void s_socks5_handle_stage_finsih(nt_proxy_socks5_t* socks5, socks5_channel_t* channel,
                                         struct epoll_event* event)
{
    if (event->data.fd == channel->inbound.event.data.fd)
    {
        if (event->events & EPOLLIN)
        {
            s_socks5_handle_inbound_r(socks5, channel);
        }
        if (event->events & EPOLLOUT)
        {
            s_socks5_handle_inbound_w(socks5, channel);
        }
    }
    else if (event->data.fd == channel->outbound.event.data.fd)
    {
        if (event->events & EPOLLIN)
        {
            s_socks5_handle_outbound_r(socks5, channel);
        }
        if (event->events & EPOLLOUT)
        {
            s_socks5_handle_outbound_w(socks5, channel);
        }
    }
}

static void s_socks5_handle_common(nt_proxy_socks5_t* socks5, struct epoll_event* event)
{
    socks5_sock_t tmp;
    tmp.event.data.fd = event->data.fd;

    ev_map_node_t* it = ev_map_find(&socks5->sock_map, &tmp.node);
    assert(it != NULL);
    socks5_sock_t*    sock = container_of(it, socks5_sock_t, node);
    socks5_channel_t* channel = sock->channel;

    if (channel->stage != SOCKS5_FINISH && (event->events & (EPOLLRDHUP | EPOLLERR)))
    {
        s_socks5_close_inbound_outbound(socks5, channel);
        LOG_I("Connect to socks5 server failed.");
        return;
    }

    switch (channel->stage)
    {
    case SOCKS5_INIT:
        s_socks5_handle_stage_init(socks5, channel, event);
        break;
    case SOCKS5_AUTH:
        s_socks5_handle_stage_auth(socks5, channel, event);
        break;
    case SOCKS5_CONNECT:
        s_socks5_handle_stage_connect(socks5, channel, event);
        break;
    case SOCKS5_FINISH:
        s_socks5_handle_stage_finsih(socks5, channel, event);
        break;
    }

    if (channel->inbound.event.data.fd < 0 && channel->outbound.event.data.fd < 0)
    {
        s_socks5_channel_remove_and_release(socks5, channel);
    }
}

static void s_socks5_handle(nt_proxy_socks5_t* socks5, struct epoll_event* event)
{
    if (event->data.fd == socks5->tcp_listen_ipv4_fd || event->data.fd == socks5->tcp_listen_ipv6_fd)
    {
        s_socks5_handle_tcp_accept(socks5, event->data.fd);
    }
    else
    {
        s_socks5_handle_common(socks5, event);
    }
}

static void* s_socks5_loop(void* arg)
{
    nt_proxy_socks5_t* socks5 = (nt_proxy_socks5_t*)arg;
    const int          maxevents = ARRAY_SIZE(socks5->events);

    int i, ret;
    while (socks5->looping)
    {
        ret = epoll_wait(socks5->epollfd, socks5->events, maxevents, 100);
        if (ret == 0)
        { /* Timeout */
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
            struct epoll_event* event = &socks5->events[i];
            s_socks5_handle(socks5, event);
        }
    }

    return NULL;
}

static int s_socks5_setup_tcp_ipv4(nt_proxy_socks5_t* socks5)
{
    int retval = 0;
    if ((socks5->tcp_listen_ipv4_fd = socket(AF_INET, SOCK_STREAM, 0)) < 0)
    {
        return errno;
    }

    /* Bind to random port. */
    nt_ip_addr("127.0.0.1", 0, (struct sockaddr*)&socks5->tcp_listen_ipv4_addr);
    struct sockaddr* addr = (struct sockaddr*)&socks5->tcp_listen_ipv4_addr;
    socklen_t        addrlen = sizeof(socks5->tcp_listen_ipv4_addr);
    if (bind(socks5->tcp_listen_ipv4_fd, addr, addrlen) < 0)
    {
        retval = errno;
        goto ERR;
    }

    /* Get bind real port. */
    if (getsockname(socks5->tcp_listen_ipv4_fd, addr, &addrlen) < 0)
    {
        retval = errno;
        goto ERR;
    }

    /* Start listen. */
    if (listen(socks5->tcp_listen_ipv4_fd, 1024) < 0)
    {
        retval = errno;
        goto ERR;
    }

    struct epoll_event event;
    event.data.fd = socks5->tcp_listen_ipv4_fd;
    event.events = EPOLLIN;
    epoll_ctl(socks5->epollfd, EPOLL_CTL_ADD, event.data.fd, &event);

    return 0;

ERR:
    s_socks5_close_tcp_ipv4(socks5);
    return retval;
}

static int s_socks5_setup_tcp_ipv6(nt_proxy_socks5_t* socks5)
{
    int retval = 0;
    if ((socks5->tcp_listen_ipv6_fd = socket(AF_INET6, SOCK_STREAM, 0)) < 0)
    {
        return errno;
    }

    /* Bind to random port. */
    nt_ip_addr("::1", 0, (struct sockaddr*)&socks5->tcp_listen_ipv6_addr);
    struct sockaddr* addr = (struct sockaddr*)&socks5->tcp_listen_ipv6_addr;
    socklen_t        addrlen = sizeof(socks5->tcp_listen_ipv6_addr);
    if (bind(socks5->tcp_listen_ipv6_fd, addr, addrlen) < 0)
    {
        retval = errno;
        goto ERR;
    }

    /* Get bind real port. */
    if (getsockname(socks5->tcp_listen_ipv6_fd, addr, &addrlen) < 0)
    {
        retval = errno;
        goto ERR;
    }

    /* Start listen. */
    if (listen(socks5->tcp_listen_ipv6_fd, 1024) < 0)
    {
        retval = errno;
        goto ERR;
    }

    struct epoll_event event;
    event.data.fd = socks5->tcp_listen_ipv6_fd;
    event.events = EPOLLIN;
    epoll_ctl(socks5->epollfd, EPOLL_CTL_ADD, event.data.fd, &event);

    return 0;

ERR:
    s_socks5_close_tcp_ipv6(socks5);
    return retval;
}

static int s_socks5_on_cmp_sock(const ev_map_node_t* key1, const ev_map_node_t* key2, void* arg)
{
    (void)arg;
    const socks5_sock_t* s1 = container_of(key1, socks5_sock_t, node);
    const socks5_sock_t* s2 = container_of(key2, socks5_sock_t, node);
    return s1->event.data.fd - s2->event.data.fd;
}

static struct sockaddr* s_socks5_listen_addr(struct nt_proxy* thiz, int domain, int type)
{
    nt_proxy_socks5_t* socks5 = container_of(thiz, nt_proxy_socks5_t, basis);
    if (type == SOCK_DGRAM)
    {
        return NULL;
    }
    return domain == AF_INET ? (struct sockaddr*)&socks5->tcp_listen_ipv4_addr
                             : (struct sockaddr*)&socks5->tcp_listen_ipv6_addr;
}

int nt_proxy_socks5_create(nt_proxy_t** proxy, const char* url)
{
    int                retval = 0;
    nt_proxy_socks5_t* socks5 = nt_calloc(1, sizeof(nt_proxy_socks5_t));
    socks5->basis.release = s_nt_proxy_socks5_release;
    socks5->basis.queue = s_proxy_socks5_queue;
    socks5->basis.listen_addr = s_socks5_listen_addr;
    ev_map_init(&socks5->sock_map, s_socks5_on_cmp_sock, NULL);
    ev_list_init(&socks5->channel_list);
    ev_list_init(&socks5->addr_queue);
    if ((retval = s_socks5_url_parser(socks5, url)) != 0)
    {
        return retval;
    }
    if ((socks5->epollfd = epoll_create(1024)) < 0)
    {
        retval = errno;
        goto ERR_EPOLL_CREATE;
    }
    if ((retval = s_socks5_setup_tcp_ipv4(socks5)) != 0)
    {
        goto ERR_SETUP_TCP_IPV4;
    }
    if ((retval = s_socks5_setup_tcp_ipv6(socks5)) != 0)
    {
        goto ERR_SETUP_TCP_IPV6;
    }

    socks5->looping = 1;
    pthread_mutex_init(&socks5->addr_queue_mutex, NULL);
    if ((retval = pthread_create(&socks5->tid, NULL, s_socks5_loop, socks5)) != 0)
    {
        goto ERR_PTHREAD_CREATE;
    }

    *proxy = &socks5->basis;
    return 0;

ERR_PTHREAD_CREATE:
    pthread_mutex_destroy(&socks5->addr_queue_mutex);
    s_socks5_close_tcp_ipv6(socks5);
ERR_SETUP_TCP_IPV6:
    s_socks5_close_tcp_ipv4(socks5);
ERR_SETUP_TCP_IPV4:
    close(socks5->epollfd);
ERR_EPOLL_CREATE:
    s_socks5_release_server_info(socks5);
    return retval;
}
