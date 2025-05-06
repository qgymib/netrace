/**
 * @see https://datatracker.ietf.org/doc/html/rfc1928
 * @see https://www.rfc-editor.org/rfc/rfc1929.html
 */
#include <assert.h>
#include <errno.h>
#include <pthread.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/epoll.h>
#include <sys/eventfd.h>
#include "utils/defs.h"
#include "utils/memory.h"
#include "utils/list.h"
#include "utils/map.h"
#include "utils/socket.h"
#include "utils/log.h"
#include "__init__.h"
#include "config.h"

typedef enum socks5_stage
{
    SOCKS5_INIT,
    SOCKS5_AUTH,
    SOCKS5_CONNECT,
    SOCKS5_UDP,
    SOCKS5_FINISH,
} socks5_stage_t;

typedef struct socks5_sock
{
    ev_map_node_t          node;
    struct epoll_event     event; /* #EPOLLIN bit or #EPOLLOUT */
    struct socks5_channel* channel;
} socks5_sock_t;

typedef struct socks5_channel
{
    ev_map_node_t           node;
    struct nt_proxy_socks5* socks5;
    int                     chid;
    int                     type; /* #SOCK_STREAM or #SOCK_DGRAM */
    union {
        /**
         * @brief Valid if #socks5_channel_t::type is #SOCK_DGRAM.
         * #socks5_channel_t::udp::relay_fd is the socket comminucate with socks5 UDP relay server.
         */
        struct
        {
            /**
             * @brief If stage == SOCKS5_FINISH, this is the socket for tcp connection.
             * If starge != SOCKS5_FINISH, this is the socket for UDP relay server.
             */
            int associate_fd;
        } udp;
    } u;
    socks5_sock_t  inbound;
    socks5_sock_t  outbound;
    socks5_stage_t stage;
    size_t         ubuf_sz;                     /* Data size in upload buffer. */
    size_t         dbuf_sz;                     /* Data size in download buffer. */
    uint8_t        ubuf[NT_SOCKET_BUFFER_SIZE]; /* Upload buffer. From inbound to outbound. */
    uint8_t        dbuf[NT_SOCKET_BUFFER_SIZE]; /* Download buffer. From outbound to inbound. */
    struct sockaddr_storage peeraddr;           /* Peer address. Program dest address. */
    struct sockaddr_storage bindaddr;           /* Socks5 bind address. */
} socks5_channel_t;

typedef enum socks5_action_type
{
    SOCKS5_ACTION_CREATE_CHANNEL,
    SOCKS5_ACTION_RELEASE_CHANNEL,
} socks5_action_type_t;

typedef struct socks5_action
{
    ev_list_node_t       node;
    socks5_action_type_t type; /* Action type. */
    union {
        socks5_channel_t* channel; /* For #SOCKS5_ACTION_CREATE_CHANNEL, the
                                      created channel object. */
        int chid;                  /* For #SOCKS5_ACTION_RELEASE_CHANNEL, the release channel ID.
                                    */
    } u;
} socks5_action_t;

typedef struct nt_proxy_socks5
{
    nt_proxy_t basis;   /* Base handle. */
    int        epollfd; /* epoll fd. */
    int        eventfd; /* Event fd. */

    struct sockaddr_storage server_addr;     /* Socks5 server address. */
    char*                   server_username; /* Socks5 server username. */
    size_t                  server_username_sz;
    char*                   server_password; /* Socks5 server password. */
    size_t                  server_password_sz;
    char*                   server_ip;   /* Socks5 server ip. */
    int                     server_port; /* Socks5 server port. */

    pthread_t          tid;          /* Thread ID. */
    int                looping;      /* Looping flag. */
    ev_map_t           sock_map;     /* #socks5_sock_t */
    ev_map_t           channel_map;  /* #socks5_channel_t */
    struct epoll_event events[1024]; /* Events cache. */

    pthread_mutex_t actq_mutex; /* Mutex for #nt_proxy_socks5_t::socks5_action_t. */
    ev_list_t       actq;       /* #socks5_action_t */
    int             chid_cnt;   /* Channel ID counter. */
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

static void s_socks5_close_inbound(nt_proxy_socks5_t* socks5, socks5_channel_t* ch)
{
    if (ch->inbound.event.data.fd < 0)
    {
        return;
    }

    LOG_D("[CHID=%d] Close inbound fd=%d.", ch->chid, ch->inbound.event.data.fd);
    if (ch->inbound.event.events != 0)
    {
        epoll_ctl(socks5->epollfd, EPOLL_CTL_DEL, ch->inbound.event.data.fd, &ch->inbound.event);
        ch->inbound.event.events = 0;
    }
    ev_map_erase(&socks5->sock_map, &ch->inbound.node);
    close(ch->inbound.event.data.fd);
    ch->inbound.event.data.fd = -1;
}

static void s_socks5_close_outbound(nt_proxy_socks5_t* socks5, socks5_channel_t* ch)
{
    if (ch->outbound.event.data.fd < 0)
    {
        return;
    }

    LOG_D("[CHID=%d] Close outbound fd=%d.", ch->chid, ch->outbound.event.data.fd);
    if (ch->outbound.event.events != 0)
    {
        epoll_ctl(socks5->epollfd, EPOLL_CTL_DEL, ch->outbound.event.data.fd, &ch->outbound.event);
        ch->outbound.event.events = 0;
    }
    ev_map_erase(&socks5->sock_map, &ch->outbound.node);
    close(ch->outbound.event.data.fd);
    ch->outbound.event.data.fd = -1;

    if (ch->type == SOCK_DGRAM && ch->u.udp.associate_fd >= 0)
    { /* For UDP socket we also need to close association fd. */
        close(ch->u.udp.associate_fd);
        ch->u.udp.associate_fd = -1;
    }
}

static void s_socks5_close_inbound_outbound(nt_proxy_socks5_t* socks5, socks5_channel_t* channel)
{
    s_socks5_close_inbound(socks5, channel);
    s_socks5_close_outbound(socks5, channel);
}

static void s_socks5_release_channel(nt_proxy_socks5_t* socks5, socks5_channel_t* channel)
{
    s_socks5_close_inbound_outbound(socks5, channel);
    nt_free(channel);
}

static void s_socks5_channel_remove_and_release(nt_proxy_socks5_t* socks5,
                                                socks5_channel_t*  channel)
{
    ev_map_erase(&socks5->channel_map, &channel->node);
    s_socks5_release_channel(socks5, channel);
}

static void s_socks5_cleanup_actq(nt_proxy_socks5_t* socks5)
{
    ev_list_node_t* it;
    while ((it = ev_list_pop_front(&socks5->actq)) != NULL)
    {
        socks5_action_t* act = container_of(it, socks5_action_t, node);
        if (act->type == SOCKS5_ACTION_CREATE_CHANNEL)
        {
            socks5_channel_t* ch = act->u.channel;
            if (ch->inbound.event.data.fd >= 0)
            {
                ev_map_insert(&socks5->sock_map, &ch->inbound.node);
            }
            if (ch->outbound.event.data.fd >= 0)
            {
                ev_map_insert(&socks5->sock_map, &ch->outbound.node);
            }
            ev_map_insert(&socks5->channel_map, &ch->node);
        }
        nt_free(act);
    }
}

static void s_socks5_cleanup_channel(nt_proxy_socks5_t* socks5)
{
    ev_map_node_t* it;
    while ((it = ev_map_begin(&socks5->channel_map)) != NULL)
    {
        socks5_channel_t* ch = container_of(it, socks5_channel_t, node);
        s_socks5_channel_remove_and_release(socks5, ch);
    }
}

static void s_nt_proxy_socks5_release(struct nt_proxy* thiz)
{
    nt_proxy_socks5_t* socks5 = container_of(thiz, nt_proxy_socks5_t, basis);

    socks5->looping = 0;
    pthread_join(socks5->tid, NULL);

    s_socks5_cleanup_actq(socks5);
    s_socks5_cleanup_channel(socks5);

    if (socks5->epollfd >= 0)
    {
        close(socks5->epollfd);
        socks5->epollfd = -1;
    }
    if (socks5->eventfd >= 0)
    {
        close(socks5->eventfd);
        socks5->eventfd = -1;
    }
    pthread_mutex_destroy(&socks5->actq_mutex);
    s_socks5_release_server_info(socks5);
    nt_free(socks5);
}

/**
 * @brief Parser url.
 * Syntax:
 * socks5://[user[:pass]@][host[:port]]
 */
static int s_socks5_url_parser(nt_proxy_socks5_t* socks5, const url_comp_t* url)
{
    if (url->host == NULL)
    {
        socks5->server_ip = nt_strdup(NT_DEFAULT_SOCKS5_ADDR);
    }
    else
    {
        socks5->server_ip = nt_strdup(url->host);
    }

    if (url->port != NULL)
    {
        socks5->server_port = *url->port;
    }
    else
    {
        socks5->server_port = NT_DEFAULT_SOCKS5_PORT;
    }

    if (url->username != NULL)
    {
        socks5->server_username = nt_strdup(url->username);
        socks5->server_username_sz = strlen(socks5->server_username);
    }

    if (url->password != NULL)
    {
        socks5->server_password = nt_strdup(url->password);
        socks5->server_password_sz = strlen(socks5->server_password);
    }

    if (socks5->server_username_sz > 255 || socks5->server_password_sz > 255)
    {
        goto ERR_INVAL;
    }

    if (nt_ip_addr(socks5->server_ip, socks5->server_port,
                   (struct sockaddr*)&socks5->server_addr) != 0)
    {
        goto ERR_INVAL;
    }

    return 0;

ERR_INVAL:
    nt_free(socks5->server_username);
    nt_free(socks5->server_password);
    return NT_ERR(EINVAL);
}

static void s_socks5_outbound_switch_read(nt_proxy_socks5_t* socks5, socks5_channel_t* ch)
{
    int op = ch->outbound.event.events == 0 ? EPOLL_CTL_ADD : EPOLL_CTL_MOD;
    ch->outbound.event.events = EPOLLIN;
    epoll_ctl(socks5->epollfd, op, ch->outbound.event.data.fd, &ch->outbound.event);
}

static void s_socks5_outbound_switch_write(nt_proxy_socks5_t* socks5, socks5_channel_t* ch)
{
    int op = ch->outbound.event.events == 0 ? EPOLL_CTL_ADD : EPOLL_CTL_MOD;
    ch->outbound.event.events = EPOLLOUT;
    epoll_ctl(socks5->epollfd, op, ch->outbound.event.data.fd, &ch->outbound.event);
}

static void s_socks5_outbound_want_write(nt_proxy_socks5_t* socks5, socks5_channel_t* ch)
{
    if (!(ch->outbound.event.events & EPOLLOUT) && ch->outbound.event.data.fd >= 0)
    {
        int op = ch->outbound.event.events == 0 ? EPOLL_CTL_ADD : EPOLL_CTL_MOD;
        ch->outbound.event.events |= EPOLLOUT;
        epoll_ctl(socks5->epollfd, op, ch->outbound.event.data.fd, &ch->outbound.event);
    }
}

static void s_socks5_outbound_stop_write(nt_proxy_socks5_t* socks5, socks5_channel_t* ch)
{
    if ((ch->outbound.event.events & EPOLLOUT) && ch->outbound.event.data.fd >= 0)
    {
        ch->outbound.event.events &= ~EPOLLOUT;
        int op = ch->outbound.event.events == 0 ? EPOLL_CTL_DEL : EPOLL_CTL_MOD;
        epoll_ctl(socks5->epollfd, op, ch->outbound.event.data.fd, &ch->outbound.event);
    }
}

static void s_socks5_outbound_want_read(nt_proxy_socks5_t* socks5, socks5_channel_t* ch)
{
    if (!(ch->outbound.event.events & EPOLLIN) && ch->outbound.event.data.fd >= 0)
    {
        int op = ch->outbound.event.events == 0 ? EPOLL_CTL_ADD : EPOLL_CTL_MOD;
        ch->outbound.event.events |= EPOLLIN;
        epoll_ctl(socks5->epollfd, op, ch->outbound.event.data.fd, &ch->outbound.event);
    }
}

static void s_socks5_outbound_stop_read(nt_proxy_socks5_t* socks5, socks5_channel_t* ch)
{
    if ((ch->outbound.event.events & EPOLLIN) && ch->outbound.event.data.fd >= 0)
    {
        ch->outbound.event.events &= ~EPOLLIN;
        int op = ch->outbound.event.events == 0 ? EPOLL_CTL_DEL : EPOLL_CTL_MOD;
        epoll_ctl(socks5->epollfd, op, ch->outbound.event.data.fd, &ch->outbound.event);
    }
}

static void s_socks5_inbound_want_write(nt_proxy_socks5_t* socks5, socks5_channel_t* ch)
{
    if (!(ch->inbound.event.events & EPOLLOUT) && ch->inbound.event.data.fd >= 0)
    {
        int op = ch->inbound.event.events == 0 ? EPOLL_CTL_ADD : EPOLL_CTL_MOD;
        ch->inbound.event.events |= EPOLLOUT;
        epoll_ctl(socks5->epollfd, op, ch->inbound.event.data.fd, &ch->inbound.event);
    }
}

static void s_socks5_inbound_want_read(nt_proxy_socks5_t* socks5, socks5_channel_t* ch)
{
    if (!(ch->inbound.event.events & EPOLLIN) && ch->inbound.event.data.fd >= 0)
    {
        int op = ch->inbound.event.events == 0 ? EPOLL_CTL_ADD : EPOLL_CTL_MOD;
        ch->inbound.event.events |= EPOLLIN;
        epoll_ctl(socks5->epollfd, op, ch->inbound.event.data.fd, &ch->inbound.event);
    }
}

static void s_socks5_inbound_stop_write(nt_proxy_socks5_t* socks5, socks5_channel_t* ch)
{
    if ((ch->inbound.event.events & EPOLLOUT) && ch->inbound.event.data.fd >= 0)
    {
        ch->inbound.event.events &= ~EPOLLOUT;
        int op = ch->inbound.event.events == 0 ? EPOLL_CTL_DEL : EPOLL_CTL_MOD;
        epoll_ctl(socks5->epollfd, op, ch->inbound.event.data.fd, &ch->inbound.event);
    }
}

static void s_socks5_inbound_stop_read(nt_proxy_socks5_t* socks5, socks5_channel_t* ch)
{
    if ((ch->inbound.event.events & EPOLLIN) && ch->inbound.event.data.fd >= 0)
    {
        ch->inbound.event.events &= ~EPOLLIN;
        int op = ch->inbound.event.events == 0 ? EPOLL_CTL_DEL : EPOLL_CTL_MOD;
        epoll_ctl(socks5->epollfd, op, ch->inbound.event.data.fd, &ch->inbound.event);
    }
}

static void s_socks5_inbound_tcp_w(nt_proxy_socks5_t* socks5, socks5_channel_t* ch)
{
    ssize_t write_sz = nt_write(ch->inbound.event.data.fd, ch->dbuf, ch->dbuf_sz);
    if (write_sz < 0)
    {
        LOG_D("[CHID=%d] write() failed: (%d) %s. Close inbound.", ch->chid, write_sz,
              NT_STRERROR(write_sz));
        s_socks5_close_inbound(socks5, ch);
        return;
    }
    ch->dbuf_sz -= write_sz;

    if (ch->dbuf_sz < sizeof(ch->dbuf))
    {
        s_socks5_outbound_want_read(socks5, ch);
    }

    if (ch->dbuf_sz > 0)
    {
        memmove(ch->dbuf, ch->dbuf + write_sz, ch->dbuf_sz);
        s_socks5_inbound_want_write(socks5, ch);
    }
    else
    {
        s_socks5_inbound_stop_write(socks5, ch);
    }
}

static void s_socks5_inbound_read(nt_proxy_socks5_t* socks5, socks5_channel_t* ch)
{
    int      ret;
    uint8_t* buf = ch->ubuf + ch->ubuf_sz;
    size_t   bufsz = sizeof(ch->ubuf) - ch->ubuf_sz;
    ssize_t  read_sz = nt_read(ch->inbound.event.data.fd, buf, bufsz);
    if (read_sz < 0)
    {
        ret = read_sz;
        if (ret != NT_ERR(EAGAIN) && ret != NT_ERR(EWOULDBLOCK))
        {
            LOG_D("[CHID=%d] read() failed: (%d) %s. Close inbound.", ch->chid, ret,
                  NT_STRERROR(ret));
            s_socks5_close_inbound(socks5, ch);
        }
        return;
    }
    else if (read_sz == 0)
    {
        LOG_D("[CHID=%d] Peer closed, close inbound.", ch->chid);
        s_socks5_close_inbound(socks5, ch);
        return;
    }
    else
    {
        ch->ubuf_sz += read_sz;
    }

    if (ch->ubuf_sz == sizeof(ch->ubuf))
    {
        s_socks5_inbound_stop_read(socks5, ch);
    }

    /* Write to outbound. */
    if (ch->stage == SOCKS5_FINISH)
    {
        s_socks5_outbound_want_write(socks5, ch);
    }
}

static void s_socks5_outbound_stage_tcp_finish_w(nt_proxy_socks5_t* socks5, socks5_channel_t* ch)
{
    if (ch->ubuf_sz < sizeof(ch->ubuf))
    { /* Inbound can start read. */
        s_socks5_inbound_want_read(socks5, ch);
    }

    if (ch->ubuf_sz > 0)
    { /* Outbound should write data. */
        s_socks5_outbound_want_write(socks5, ch);
    }
    else
    {
        s_socks5_outbound_stop_write(socks5, ch);
    }
}

static void s_socks5_outbound_tcp_w(nt_proxy_socks5_t* socks5, socks5_channel_t* ch)
{
    ssize_t write_sz = nt_write(ch->outbound.event.data.fd, ch->ubuf, ch->ubuf_sz);
    if (write_sz < 0)
    {
        LOG_D("[CHID=%d] write() failed: (%d) %s. Close outbound", ch->chid, write_sz,
              NT_STRERROR(write_sz));
        s_socks5_close_outbound(socks5, ch);
        return;
    }
    ch->ubuf_sz -= write_sz;

    if (ch->ubuf_sz > 0)
    {
        memmove(ch->ubuf, ch->ubuf + write_sz, ch->ubuf_sz);
    }

    switch (ch->stage)
    {
    case SOCKS5_INIT:
    case SOCKS5_AUTH:
    case SOCKS5_CONNECT:
    case SOCKS5_UDP:
        if (ch->ubuf_sz == 0)
        { /* Wait for response. */
            s_socks5_outbound_switch_read(socks5, ch);
        }
        break;
    case SOCKS5_FINISH:
        s_socks5_outbound_stage_tcp_finish_w(socks5, ch);
        break;
    }
}

static void s_socks5_setup_tcp_connect(socks5_channel_t* ch)
{
    /* Change stage mark. */
    ch->stage = SOCKS5_CONNECT;

    /* Construct CONNECT request. */
    ch->ubuf[ch->ubuf_sz++] = 0x05; // socks5
    ch->ubuf[ch->ubuf_sz++] = 0x01; // CONNECT
    ch->ubuf[ch->ubuf_sz++] = 0x00; // RESERVED
    if (ch->peeraddr.ss_family == AF_INET)
    {
        struct sockaddr_in* addr = (struct sockaddr_in*)&ch->peeraddr;
        ch->ubuf[ch->ubuf_sz++] = 0x01; // ATYP=IPv4
        memcpy(&ch->ubuf[ch->ubuf_sz], &addr->sin_addr, 4);
        ch->ubuf_sz += 4;
        memcpy(&ch->ubuf[ch->ubuf_sz], &addr->sin_port, 2);
        ch->ubuf_sz += 2;
    }
    else if (ch->peeraddr.ss_family == AF_INET6)
    {
        struct sockaddr_in6* addr = (struct sockaddr_in6*)&ch->peeraddr;
        ch->ubuf[ch->ubuf_sz] = 0x04; // ATYP=IPv6
        memcpy(&ch->ubuf[ch->ubuf_sz], &addr->sin6_addr, 16);
        ch->ubuf_sz += 16;
        memcpy(&ch->ubuf[ch->ubuf_sz], &addr->sin6_port, 2);
        ch->ubuf_sz += 2;
    }
}

/**
 * @see rfc1929
 */
static void s_socks5_setup_auth(nt_proxy_socks5_t* socks5, socks5_channel_t* ch)
{
    /* Change stage. */
    ch->stage = SOCKS5_AUTH;

    /* Register outbound write. */
    s_socks5_outbound_switch_write(socks5, ch);

    /* Construct AUTH request. */
    ch->ubuf[ch->ubuf_sz++] = 0x01;
    ch->ubuf[ch->ubuf_sz++] = socks5->server_username_sz;
    memcpy(&ch->ubuf[ch->ubuf_sz], socks5->server_username, socks5->server_username_sz);
    ch->ubuf_sz += socks5->server_username_sz;
    ch->ubuf[ch->ubuf_sz++] = socks5->server_password_sz;
    memcpy(&ch->ubuf[ch->ubuf_sz], socks5->server_password, socks5->server_password_sz);
    ch->ubuf_sz += socks5->server_password_sz;
}

static void s_socks5_setup_udp_associate(socks5_channel_t* ch)
{
    ch->stage = SOCKS5_UDP;

    ch->ubuf[ch->ubuf_sz++] = 0x05; // socks5
    ch->ubuf[ch->ubuf_sz++] = 0x03; // UDP ASSOCIATE
    ch->ubuf[ch->ubuf_sz++] = 0x00; // RSV
    if (ch->peeraddr.ss_family == AF_INET)
    {
        struct sockaddr_in* addr = (struct sockaddr_in*)&ch->peeraddr;
        ch->ubuf[ch->ubuf_sz++] = 0x01; // ATYP=IPv4
        memcpy(&ch->ubuf[ch->ubuf_sz], &addr->sin_addr, 4);
        ch->ubuf_sz += 4;
        memcpy(&ch->ubuf[ch->ubuf_sz], &addr->sin_port, 2);
        ch->ubuf_sz += 2;
    }
    else
    {
        struct sockaddr_in6* addr = (struct sockaddr_in6*)&ch->peeraddr;
        ch->ubuf[ch->ubuf_sz++] = 0x04; // ATYP=IPv6
        memcpy(&ch->ubuf[ch->ubuf_sz], &addr->sin6_addr, 16);
        ch->ubuf_sz += 16;
        memcpy(&ch->ubuf[ch->ubuf_sz], &addr->sin6_port, 2);
        ch->ubuf_sz += 2;
    }
}

static void s_socks5_setup_request(nt_proxy_socks5_t* socks5, socks5_channel_t* ch)
{
    if (ch->type == SOCK_STREAM)
    {
        s_socks5_setup_tcp_connect(ch);
    }
    else
    {
        s_socks5_setup_udp_associate(ch);
    }

    /* Register for write. */
    s_socks5_outbound_switch_write(socks5, ch);
}

/**
 * @brief Handle response of version identifier/method selection messages.
 */
static void s_socks5_outbound_tcp_stage_init_r(nt_proxy_socks5_t* socks5, socks5_channel_t* ch)
{
    if (ch->dbuf_sz < 2)
    { /* Continue read. */
        s_socks5_outbound_want_read(socks5, ch);
        return;
    }

    uint8_t method = ch->dbuf[1];
    ch->dbuf_sz -= 2;
    if (ch->dbuf_sz > 0)
    {
        memmove(ch->dbuf, ch->dbuf + 2, ch->dbuf_sz);
    }

    switch (method)
    {
    case 0x00: /* NO AUTHENTICATION REQUIRED */
        s_socks5_setup_request(socks5, ch);
        break;
    case 0x02: /*USERNAME/PASSWORD*/
        s_socks5_setup_auth(socks5, ch);
        break;
    case 0xff: /* NO ACCEPTABLE METHODS */
    default:   /* Unsupport methods */
        LOG_D("[CHID=%d] Unsupport method=%u", ch->chid, method);
        s_socks5_close_inbound_outbound(socks5, ch);
        break;
    }
}

/**
 * @brief Handle response of Username/Password Authentication
 * ```
 * +----+--------+
 * |VER | STATUS |
 * +----+--------+
 * | 1  |   1    |
 * +----+--------+
 * ```
 */
static void s_socks5_outbound_tcp_stage_auth_r(nt_proxy_socks5_t* socks5, socks5_channel_t* ch)
{
    if (ch->dbuf_sz < 2)
    {
        s_socks5_outbound_want_read(socks5, ch);
        return;
    }

    uint8_t ver = ch->dbuf[0];
    uint8_t code = ch->dbuf[1];
    ch->dbuf_sz -= 2;
    if (ch->dbuf_sz > 0)
    {
        memmove(ch->dbuf, ch->dbuf + 2, ch->dbuf_sz);
    }

    if (ver != 0x05)
    {
        LOG_E("[CHID=%d] Socks5 server version verify failed: got=%u.", ch->chid, ver);
        s_socks5_close_inbound_outbound(socks5, ch);
        return;
    }
    if (code != 0)
    {
        LOG_D("[CHID=%d] socks5 auth failed: code=%u.", ch->chid, code);
        s_socks5_close_inbound_outbound(socks5, ch);
        return;
    }

    s_socks5_setup_request(socks5, ch);
}

static int s_socks5_outbound_stage_connect_r(nt_proxy_socks5_t* socks5, socks5_channel_t* ch)
{
    if (ch->dbuf_sz < 5)
    {
        return NT_ERR(EAGAIN);
    }

    /* Check protocol and CONNECT result. */
    if (ch->dbuf[0] != 0x05 || ch->dbuf[1] != 0x00)
    {
        LOG_I("[CHID=%d] Socks5 server refuse connect. Close inbound / outbound.", ch->chid);
        s_socks5_close_inbound_outbound(socks5, ch);
        return NT_ERR(EPIPE);
    }

    size_t rsp_sz = 0;
    if (ch->dbuf[3] == 0x01)
    { /* ATYP == IPv4 */
        struct sockaddr_in* addr = (struct sockaddr_in*)&ch->bindaddr;
        addr->sin_family = AF_INET;
        memcpy(&addr->sin_addr, &ch->dbuf[4], 4);
        memcpy(&addr->sin_port, &ch->dbuf[8], 2);
        rsp_sz = 10;
    }
    else if (ch->dbuf[3] == 0x04)
    { /* ATYP == IPv6 */
        struct sockaddr_in6* addr = (struct sockaddr_in6*)&ch->bindaddr;
        addr->sin6_family = AF_INET6;
        memcpy(&addr->sin6_addr, &ch->dbuf[4], 16);
        memcpy(&addr->sin6_port, &ch->dbuf[20], 2);
        rsp_sz = 22;
    }
    else
    {
        LOG_W("[CHID=%d] Unknown ATYP=%d. Close inbound / outbound.", ch->chid, ch->dbuf[3]);
        s_socks5_close_inbound_outbound(socks5, ch);
        return NT_ERR(EINVAL);
    }

    ch->dbuf_sz -= rsp_sz;
    if (ch->dbuf_sz > 0)
    {
        memmove(ch->dbuf, ch->dbuf + rsp_sz, ch->dbuf_sz);
    }

    /* Change stage. */
    ch->stage = SOCKS5_FINISH;
    s_socks5_inbound_want_read(socks5, ch);
    s_socks5_outbound_want_read(socks5, ch);
    if (ch->ubuf_sz != 0)
    {
        s_socks5_outbound_want_write(socks5, ch);
    }
    if (ch->dbuf_sz != 0)
    {
        s_socks5_inbound_want_write(socks5, ch);
    }

    return 0;
}

static void s_socks5_outbound_stage_finish_r(nt_proxy_socks5_t* socks5, socks5_channel_t* ch)
{
    /* If buffer is full, stop read. */
    if (ch->dbuf_sz == sizeof(ch->dbuf))
    {
        s_socks5_outbound_stop_read(socks5, ch);
    }

    /* Write to inbound. */
    s_socks5_inbound_want_write(socks5, ch);
}

static int s_socks5_outbound_stage_udp_r(nt_proxy_socks5_t* socks5, socks5_channel_t* ch)
{
    int ret;
    if ((ret = s_socks5_outbound_stage_connect_r(socks5, ch)) != 0)
    {
        return ret;
    }

    /*
     * Move socket to associate_fd.
     * The inbound will be used for comminucate with UDP relay server.
     */
    epoll_ctl(socks5->epollfd, EPOLL_CTL_DEL, ch->outbound.event.data.fd, &ch->outbound.event);
    ev_map_erase(&socks5->sock_map, &ch->outbound.node);
    ch->u.udp.associate_fd = ch->outbound.event.data.fd;
    ch->outbound.event.events = 0;
    ch->outbound.event.data.fd = -1;

    /* Connect to UDP relay server. */
    if ((ret = nt_socket_connect(SOCK_DGRAM, &ch->bindaddr, 1)) < 0)
    {
        LOG_W("[CHID=%d] Connect to UDP relay server failed: (%d) %s", ch->chid, ret,
              NT_STRERROR(ret));
        s_socks5_close_inbound_outbound(socks5, ch);
        return ret;
    }
    ch->outbound.event.data.fd = ret;
    NT_ASSERT(ev_map_insert(&socks5->sock_map, &ch->outbound.node) == NULL, "Conflict node");

    /* Now we can start reading from inbound and outbound. */
    s_socks5_inbound_want_read(socks5, ch);
    s_socks5_outbound_want_read(socks5, ch);
    if (ch->ubuf_sz != 0)
    {
        s_socks5_outbound_want_write(socks5, ch);
    }
    if (ch->dbuf_sz != 0)
    {
        s_socks5_inbound_want_write(socks5, ch);
    }

    return 0;
}

static void s_socks5_outbound_tcp_r(nt_proxy_socks5_t* socks5, socks5_channel_t* ch)
{
    int      ret;
    uint8_t* buf = ch->dbuf + ch->dbuf_sz;
    size_t   bufsz = sizeof(ch->dbuf) - ch->dbuf_sz;
    ssize_t  read_sz = nt_read(ch->outbound.event.data.fd, buf, bufsz);
    if (read_sz < 0)
    {
        ret = read_sz;
        if (ret != NT_ERR(EAGAIN) && ret != NT_ERR(EWOULDBLOCK))
        {
            LOG_D("[CHID=%d] read() failed: (%d) %s. Close outbound.", ch->chid, ret,
                  NT_STRERROR(ret));
            s_socks5_close_outbound(socks5, ch);
        }
        return;
    }
    if (read_sz == 0)
    {
        LOG_D("[CHID=%d] Outbound peer close. Close outbound.", ch->chid);
        s_socks5_close_outbound(socks5, ch);
        return;
    }
    ch->dbuf_sz += read_sz;

    switch (ch->stage)
    {
    case SOCKS5_INIT:
        s_socks5_outbound_tcp_stage_init_r(socks5, ch);
        break;
    case SOCKS5_AUTH:
        s_socks5_outbound_tcp_stage_auth_r(socks5, ch);
        break;
    case SOCKS5_CONNECT:
        s_socks5_outbound_stage_connect_r(socks5, ch);
        break;
    case SOCKS5_UDP:
        s_socks5_outbound_stage_udp_r(socks5, ch);
        break;
    case SOCKS5_FINISH:
        s_socks5_outbound_stage_finish_r(socks5, ch);
        break;
    }
}

static void s_socks5_inbound_udp_r(nt_proxy_socks5_t* socks5, socks5_channel_t* ch)
{
    ch->ubuf_sz = 0;

    /* Build socks5 udp header. */
    ch->ubuf[ch->ubuf_sz++] = 0x00; // RSV
    ch->ubuf[ch->ubuf_sz++] = 0x00; // RSV
    ch->ubuf[ch->ubuf_sz++] = 0x00; // FRAG
    if (ch->peeraddr.ss_family == AF_INET)
    {
        struct sockaddr_in* addr = (struct sockaddr_in*)&ch->peeraddr;
        ch->ubuf[ch->ubuf_sz++] = 0x01;
        memcpy(&ch->ubuf[ch->ubuf_sz], &addr->sin_addr, 4);
        ch->ubuf_sz += 4;
        memcpy(&ch->ubuf[ch->ubuf_sz], &addr->sin_port, 2);
        ch->ubuf_sz += 2;
    }
    else
    {
        struct sockaddr_in6* addr = (struct sockaddr_in6*)&ch->peeraddr;
        ch->ubuf[ch->ubuf_sz++] = 0x04;
        memcpy(&ch->ubuf[ch->ubuf_sz], &addr->sin6_addr, 16);
        ch->ubuf_sz += 16;
        memcpy(&ch->ubuf[ch->ubuf_sz], &addr->sin6_port, 2);
        ch->ubuf_sz += 2;
    }

    /* Append data from program. */
    uint8_t*         buf = ch->ubuf + ch->ubuf_sz;
    size_t           bufsz = sizeof(ch->ubuf) - ch->ubuf_sz;
    int              fd = ch->inbound.event.data.fd;
    ssize_t          recv_sz = nt_read(fd, buf, bufsz);
    if (recv_sz < 0)
    {
        s_socks5_close_inbound_outbound(socks5, ch);
        return;
    }
    ch->ubuf_sz += recv_sz;

    /* Send to socks5 UDP relay server. */
    ssize_t write_sz = nt_write(ch->outbound.event.data.fd, ch->ubuf, ch->ubuf_sz);
    if (write_sz < 0)
    {
        LOG_D("[CHID=%d] write() failed: (%d) %s. Close inbound and outbound.", ch->chid, write_sz,
              NT_STRERROR(write_sz));
        s_socks5_close_inbound_outbound(socks5, ch);
        return;
    }
}

static void s_socks5_outbound_udp_r(nt_proxy_socks5_t* socks5, socks5_channel_t* ch)
{
    ssize_t read_sz = nt_read(ch->outbound.event.data.fd, ch->dbuf, sizeof(ch->dbuf));
    if (read_sz < 0)
    {
        LOG_D("[CHID=%d] read() failed: (%d) %s.", ch->chid, read_sz, NT_STRERROR(read_sz));
        s_socks5_close_inbound_outbound(socks5, ch);
        return;
    }
    if (read_sz < 10)
    { /* At least 10 bytes for IPv4 datagram. */
        return;
    }
    if (ch->dbuf[0] != 0x00 && ch->dbuf[1] != 0x00)
    {
        LOG_D("[CHID=%d] Invalid message. Close inbound and outbound.", ch->chid);
        s_socks5_close_inbound_outbound(socks5, ch);
        return;
    }
    size_t offset = 0;
    if (ch->dbuf[3] == 0x01)
    {
        offset = 10;
    }
    else if (ch->dbuf[3] == 0x04)
    {
        offset = 22;
    }
    else
    {
        LOG_W("[CHID=%d] Unsupport method=%u. Close inbound and outbound.", ch->chid, ch->dbuf[3]);
        s_socks5_close_inbound_outbound(socks5, ch);
        return;
    }

    if ((size_t)read_sz < offset)
    {
        return;
    }

    uint8_t*         buff = ch->dbuf + offset;
    size_t           buffsz = read_sz - offset;
    if (nt_write(ch->inbound.event.data.fd, buff, buffsz) < 0)
    {
        LOG_W("[CHID=%d] sendto() failed: (%d) %s.", ch->chid, errno, strerror(errno));
        s_socks5_close_inbound_outbound(socks5, ch);
        return;
    }
}

static void s_socks5_handle_common(nt_proxy_socks5_t* socks5, socks5_channel_t* ch,
                                   struct epoll_event* event)
{
    if (ch->stage != SOCKS5_FINISH && (event->events & (EPOLLRDHUP | EPOLLERR)))
    {
        LOG_I("[CHID=%d] Connect to socks5 server failed. Release channel.", ch->chid);
        s_socks5_channel_remove_and_release(socks5, ch);
        return;
    }

    if (ch->inbound.event.data.fd == event->data.fd)
    {
        if (ch->type == SOCK_STREAM)
        {
            if (event->events & EPOLLOUT)
            {
                s_socks5_inbound_tcp_w(socks5, ch);
            }
            if (event->events & EPOLLIN)
            {
                s_socks5_inbound_read(socks5, ch);
            }
        }
        else if (ch->type == SOCK_DGRAM)
        {
            if (event->events & EPOLLIN)
            {
                s_socks5_inbound_udp_r(socks5, ch);
            }
        }
    }
    else if (ch->outbound.event.data.fd == event->data.fd)
    {
        if (ch->type == SOCK_STREAM || ch->stage != SOCKS5_FINISH)
        {
            if (event->events & EPOLLOUT)
            {
                s_socks5_outbound_tcp_w(socks5, ch);
            }
            if (event->events & EPOLLIN)
            {
                s_socks5_outbound_tcp_r(socks5, ch);
            }
        }
        else if (ch->type == SOCK_DGRAM)
        {
            if (event->events & EPOLLIN)
            {
                s_socks5_outbound_udp_r(socks5, ch);
            }
        }
    }

    if (ch->stage != SOCKS5_FINISH &&
        (ch->inbound.event.data.fd < 0 || ch->outbound.event.data.fd < 0))
    { /* If handshake not finished but either bound is closed, close other bound. */
        LOG_D("[CHID=%d] Handshake not finish but inbound or outbound is closed.", ch->chid);
        s_socks5_close_inbound_outbound(socks5, ch);
    }
    else
    {
        if (ch->inbound.event.data.fd < 0 && ch->ubuf_sz == 0)
        { /* If inbound is closed and nothing to upload, close outbound too. */
            LOG_D("[CHID=%d] Inbound already closed, nothing to upload. Close outbound.", ch->chid);
            s_socks5_close_outbound(socks5, ch);
        }
        if (ch->outbound.event.data.fd < 0 && ch->dbuf_sz == 0)
        { /* If outbound is closed and nothing to download, close the inbound too. */
            LOG_D("[CHID=%d] Outbound already closed, nothing to download. Close inbound.",
                  ch->chid);
            s_socks5_close_inbound(socks5, ch);
        }
    }
    if (ch->inbound.event.data.fd < 0 && ch->outbound.event.data.fd < 0)
    {
        LOG_D("[CHID=%d] Both inbound and outbound are closed. Release channel.", ch->chid);
        s_socks5_channel_remove_and_release(socks5, ch);
    }
}

static void s_socks5_handle_create_channel(nt_proxy_socks5_t* socks5, socks5_channel_t* ch)
{
    if (ch->inbound.event.data.fd >= 0)
    {
        ev_map_insert(&socks5->sock_map, &ch->inbound.node);
    }
    if (ch->outbound.event.data.fd >= 0)
    {
        ev_map_insert(&socks5->sock_map, &ch->outbound.node);
    }
    ev_map_insert(&socks5->channel_map, &ch->node);

    /*
     * For inbound we wait for outbound handshake finish.
     * For outbound we need to do socks5 handshake.
     */
    s_socks5_outbound_switch_write(socks5, ch);

    /* Construct handshake request. */
    ch->ubuf_sz = 4;
    ch->ubuf[0] = 0x05; // socks5
    ch->ubuf[1] = 0x02; // NMETHODS
    ch->ubuf[2] = 0x00; // NO AUTHENTICATION REQUIRED
    ch->ubuf[3] = 0x02; // USERNAME/PASSWORD

    if (socks5->server_username == NULL)
    { /* Remove USERNAME/PASSWORD. */
        ch->ubuf_sz = 3;
        ch->ubuf[1] = 0x01;
    }
}

static void s_socks5_handle_release_channel(nt_proxy_socks5_t* socks5, int chid)
{
    socks5_channel_t tmp;
    tmp.chid = chid;
    ev_map_node_t* it = ev_map_find(&socks5->channel_map, &tmp.node);
    if (it == NULL)
    {
        return;
    }

    socks5_channel_t* ch = container_of(it, socks5_channel_t, node);
    LOG_D("[CHID=%d] Release channel, close inbound first.", chid);
    s_socks5_close_inbound(socks5, ch);
}

static void s_socks5_handle_event(nt_proxy_socks5_t* socks5)
{
    ev_list_node_t* it;
    while (1)
    {
        socks5_action_t* act = NULL;
        pthread_mutex_lock(&socks5->actq_mutex);
        if ((it = ev_list_pop_front(&socks5->actq)) != NULL)
        {
            act = container_of(it, socks5_action_t, node);
        }
        pthread_mutex_unlock(&socks5->actq_mutex);
        if (act == NULL)
        {
            break;
        }

        switch (act->type)
        {
        case SOCKS5_ACTION_CREATE_CHANNEL:
            s_socks5_handle_create_channel(socks5, act->u.channel);
            break;

        case SOCKS5_ACTION_RELEASE_CHANNEL:
            s_socks5_handle_release_channel(socks5, act->u.chid);
            break;
        }

        nt_free(act);
    }
}

static socks5_sock_t* s_socks5_find_sock(nt_proxy_socks5_t* socks5, int fd)
{
    socks5_sock_t tmp;
    tmp.event.data.fd = fd;
    ev_map_node_t* it = ev_map_find(&socks5->sock_map, &tmp.node);
    return it != NULL ? container_of(it, socks5_sock_t, node) : NULL;
}

static void s_socks5_handle(nt_proxy_socks5_t* socks5, struct epoll_event* event)
{
    if (event->data.fd == socks5->eventfd)
    {
        uint64_t buff;
        read(socks5->eventfd, &buff, sizeof(buff));
        s_socks5_handle_event(socks5);
        return;
    }

    socks5_sock_t* sock = s_socks5_find_sock(socks5, event->data.fd);
    if (sock == NULL)
    { /* This is because the socket maybe deleted in the other event. */
        LOG_D("Ignore event for fd=%d.", event->data.fd);
        return;
    }
    socks5_channel_t* ch = sock->channel;
    s_socks5_handle_common(socks5, ch, event);
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
            NT_ASSERT(errno == EINTR, "epoll_wait() failed: (%d) %s.", errno, strerror(errno));
            continue;
        }

        for (i = 0; i < ret; i++)
        {
            struct epoll_event* event = &socks5->events[i];
            s_socks5_handle(socks5, event);
        }
    }

    return NULL;
}

static int s_socks5_on_cmp_sock(const ev_map_node_t* key1, const ev_map_node_t* key2, void* arg)
{
    (void)arg;
    const socks5_sock_t* s1 = container_of(key1, socks5_sock_t, node);
    const socks5_sock_t* s2 = container_of(key2, socks5_sock_t, node);
    return s1->event.data.fd - s2->event.data.fd;
}

static int s_socks5_channel_tcp_make(nt_proxy_socks5_t* socks5, socks5_channel_t* ch)
{
    int ret;
    if ((ret = nt_socket_connect(SOCK_STREAM, &socks5->server_addr, 1)) < 0)
    {
        return ret;
    }
    ch->outbound.event.data.fd = ret;

    return 0;
}

static void s_socks5_weakup(nt_proxy_socks5_t* socks5)
{
    uint64_t buff = 1;
    write(socks5->eventfd, &buff, sizeof(buff));
}

static int s_socks5_channel_udp_make(nt_proxy_socks5_t* socks5, socks5_channel_t* ch)
{
    int ret;

    /* Out bound is a TCP socket for handshake. The actual UDP data channel will create later. */
    if ((ret = nt_socket_connect(SOCK_STREAM, &socks5->server_addr, 1)) < 0)
    {
        return ret;
    }
    ch->outbound.event.data.fd = ret;

    return 0;
}

static int s_socks5_channel_create(struct nt_proxy* thiz, int type, int sv,
                                   const struct sockaddr* peeraddr)
{
    int ret;

    /* Only support IPv4/IPv6, for UDP and TCP. */
    if ((peeraddr->sa_family != AF_INET && peeraddr->sa_family != AF_INET6) ||
        (type != SOCK_STREAM && type != SOCK_DGRAM))
    {
        return NT_ERR(ENOTSUP);
    }

    nt_proxy_socks5_t* socks5 = container_of(thiz, nt_proxy_socks5_t, basis);
    socks5_channel_t*  ch = nt_malloc(sizeof(socks5_channel_t));
    ch->socks5 = socks5;
    ch->type = type;
    ch->inbound.event.data.fd = dup(sv);
    ch->inbound.event.events = 0;
    ch->inbound.channel = ch;
    ch->outbound.event.data.fd = -1;
    ch->outbound.event.events = 0;
    ch->outbound.channel = ch;
    ch->stage = SOCKS5_INIT;
    ch->dbuf_sz = 0;
    ch->ubuf_sz = 0;
    nt_sockaddr_copy((struct sockaddr*)&ch->peeraddr, peeraddr);

    ret = (type == SOCK_STREAM) ? s_socks5_channel_tcp_make(socks5, ch)
                                : s_socks5_channel_udp_make(socks5, ch);
    if (ret < 0)
    {
        LOG_D("Make channel failed: (%d) %s.", ret, NT_STRERROR(ret));
        nt_free(ch);
        return ret;
    }

    socks5_action_t* act = nt_malloc(sizeof(socks5_action_t));
    act->type = SOCKS5_ACTION_CREATE_CHANNEL;
    act->u.channel = ch;

    pthread_mutex_lock(&socks5->actq_mutex);
    {
        if ((ret = socks5->chid_cnt++) < 0)
        { /* Just in case overflow. */
            ret = socks5->chid_cnt = 0;
        }
        ch->chid = ret;
        ev_list_push_back(&socks5->actq, &act->node);
    }
    pthread_mutex_unlock(&socks5->actq_mutex);

    LOG_D("[CHID=%d] Create %s channel.", ch->chid, nt_socket_type_name(type));
    s_socks5_weakup(socks5);
    return ret;
}

static int s_socks5_on_cmp_channel(const ev_map_node_t* key1, const ev_map_node_t* key2, void* arg)
{
    (void)arg;
    const socks5_channel_t* ch1 = container_of(key1, socks5_channel_t, node);
    const socks5_channel_t* ch2 = container_of(key2, socks5_channel_t, node);
    return ch1->chid - ch2->chid;
}

static void s_socks5_channel_release(struct nt_proxy* thiz, int channel)
{
    nt_proxy_socks5_t* socks5 = container_of(thiz, nt_proxy_socks5_t, basis);
    socks5_action_t*   act = nt_malloc(sizeof(socks5_action_t));
    act->type = SOCKS5_ACTION_RELEASE_CHANNEL;
    act->u.chid = channel;

    pthread_mutex_lock(&socks5->actq_mutex);
    ev_list_push_back(&socks5->actq, &act->node);
    pthread_mutex_unlock(&socks5->actq_mutex);

    s_socks5_weakup(socks5);
}

static int s_socks5_create(nt_proxy_t** proxy, const url_comp_t* url)
{
    int                ret = 0;
    nt_proxy_socks5_t* socks5 = nt_calloc(1, sizeof(nt_proxy_socks5_t));
    socks5->basis.release = s_nt_proxy_socks5_release;
    socks5->basis.channel_create = s_socks5_channel_create;
    socks5->basis.channel_release = s_socks5_channel_release;
    ev_map_init(&socks5->sock_map, s_socks5_on_cmp_sock, NULL);
    ev_map_init(&socks5->channel_map, s_socks5_on_cmp_channel, NULL);
    ev_list_init(&socks5->actq);
    pthread_mutex_init(&socks5->actq_mutex, NULL);
    if ((ret = s_socks5_url_parser(socks5, url)) != 0)
    {
        goto ERR_URL_PARSER;
    }

    if ((socks5->epollfd = epoll_create1(EPOLL_CLOEXEC)) < 0)
    {
        ret = NT_ERR(errno);
        goto ERR_EPOLL_CREATE;
    }
    if ((socks5->eventfd = eventfd(0, 0)) < 0)
    {
        ret = NT_ERR(errno);
        goto ERR_EVENTFD;
    }

    struct epoll_event event;
    event.data.fd = socks5->eventfd;
    event.events = EPOLLIN;
    epoll_ctl(socks5->epollfd, EPOLL_CTL_ADD, socks5->eventfd, &event);

    socks5->looping = 1;
    if ((ret = pthread_create(&socks5->tid, NULL, s_socks5_loop, socks5)) != 0)
    {
        ret = NT_ERR(ret);
        goto ERR_PTHREAD_CREATE;
    }

    *proxy = &socks5->basis;
    return 0;

ERR_PTHREAD_CREATE:
    close(socks5->eventfd);
ERR_EVENTFD:
    close(socks5->epollfd);
ERR_EPOLL_CREATE:
    s_socks5_release_server_info(socks5);
ERR_URL_PARSER:
    pthread_mutex_destroy(&socks5->actq_mutex);
    nt_free(socks5);
    return ret;
}

const nt_proxy_protocol_t nt_proxy_protocol_socks5 = { "socks5", s_socks5_create };
