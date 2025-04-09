#include <unistd.h>
#include <pthread.h>
#include <arpa/inet.h>
#include <sys/select.h>
#include <time.h>
#include "utils/defs.h"
#include "utils/dns.h"
#include "utils/map.h"
#include "utils/memory.h"
#include "utils/socket.h"
#include "utils/str.h"
#include "utils/log.h"
#include "dns.h"
#include "config.h"

typedef struct dns_in_record
{
    ev_map_node_t           node;
    uint16_t                id;
    uint64_t                start_ts; /* Start timestamp. */
    struct sockaddr_storage peer_addr;
} dns_in_record;

struct nt_dns_proxy
{
    nt_dns_proxy_config_t config; /* User configuration. */
    int                   server_fd;
    int                   client_fd;
    int                   looping;    /* Looping flag. */
    pthread_t             tid;        /* Working thread. */
    ev_map_t              in_table;   /* #dns_in_record */
    uint8_t               rbuf[4096]; /* Receive buffer. */
};

static void s_dns_release_in_record(dns_in_record* record)
{
    nt_free(record);
}

static uint64_t s_dns_clocktime(void)
{
    struct timespec t;
    NT_ASSERT(clock_gettime(CLOCK_MONOTONIC, &t) == 0, "(%d) %s.", errno, strerror(errno));
    return t.tv_sec * 1000 + t.tv_nsec / 1000000;
}

static int s_dns_handle_input(nt_dns_proxy_t* proxy, size_t bufsz, nt_dns_msg_t* msg,
                              const struct sockaddr_storage* peer_addr)
{
    if (msg->header.qr != 0)
    { /* It has to be a DNS request. */
        return NT_ERR(EBADRQC);
    }

    /* Proxy this request. */
    ssize_t write_sz = nt_write(proxy->client_fd, proxy->rbuf, bufsz);
    if (write_sz < 0)
    {
        LOG_E("Proxy DNS message failed: (%d) %s.", errno, strerror(errno));
        abort();
    }

    /* Build query record. */
    dns_in_record* rec = nt_calloc(1, sizeof(dns_in_record));
    rec->id = msg->header.id;
    rec->start_ts = s_dns_clocktime();
    memcpy(&rec->peer_addr, peer_addr, sizeof(*peer_addr));

    /* Save record. */
    if (ev_map_insert(&proxy->in_table, &rec->node) != NULL)
    {
        LOG_D("Ignore duplicate DNS query id=%u", rec->id);
        nt_free(rec);
    }

    return 0;
}

static int s_dns_handle_server(nt_dns_proxy_t* proxy)
{
    int ret;

    /* Recv DNS message data. */
    struct sockaddr_storage peer_addr;
    struct sockaddr*        addr = (struct sockaddr*)&peer_addr;
    socklen_t               addr_len = sizeof(peer_addr);
    ssize_t                 recv_sz =
        recvfrom(proxy->server_fd, proxy->rbuf, sizeof(proxy->rbuf), 0, addr, &addr_len);
    NT_ASSERT(recv_sz >= 0, "recvfrom() failed: (%d) %s", errno, strerror(errno));

    nt_dns_msg_t* msg = NULL;
    if ((ret = nt_dns_msg_parser(&msg, proxy->rbuf, recv_sz)) < 0)
    {
        LOG_I("parser DNS message failed: %d", ret);
        return ret;
    }

    /* Handle DNS query. */
    s_dns_handle_input(proxy, recv_sz, msg, &peer_addr);
    nt_dns_msg_free(msg);

    return 0;
}

static int s_dns_handle_client(nt_dns_proxy_t* proxy)
{
    int     ret;
    ssize_t read_sz = nt_read(proxy->client_fd, proxy->rbuf, sizeof(proxy->rbuf));
    if (read_sz < 0)
    {
        LOG_E("read() failed: (%d) %s.", (int)read_sz, NT_STRERROR(read_sz));
        return read_sz;
    }

    nt_dns_msg_t* msg = NULL;
    if ((ret = nt_dns_msg_parser(&msg, proxy->rbuf, read_sz)) < 0)
    {
        return ret;
    }

    dns_in_record tmp;
    tmp.id = msg->header.id;
    ev_map_node_t* it = ev_map_find(&proxy->in_table, &tmp.node);
    if (it == NULL)
    {
        LOG_W("Ignore DNS response ID=%u", msg->header.id);
        goto FIN;
    }
    dns_in_record* rec = container_of(it, dns_in_record, node);
    sendto(proxy->server_fd, proxy->rbuf, read_sz, 0, (struct sockaddr*)&rec->peer_addr,
           sizeof(rec->peer_addr));
    ev_map_erase(&proxy->in_table, &rec->node);
    s_dns_release_in_record(rec);

FIN:
    nt_dns_msg_free(msg);
    return 0;
}

static void* s_dns_proxy_thread(void* arg)
{
    nt_dns_proxy_t* proxy = (nt_dns_proxy_t*)arg;
    int             ret;
    const int       maxfd = NT_MAX(proxy->server_fd, proxy->client_fd) + 1;

    while (proxy->looping)
    {
        fd_set rfds;
        FD_ZERO(&rfds);
        FD_SET(proxy->client_fd, &rfds);
        FD_SET(proxy->server_fd, &rfds);

        struct timeval tv;
        tv.tv_sec = 0;
        tv.tv_usec = 100 * 1000;
        if ((ret = select(maxfd, &rfds, NULL, NULL, &tv)) < 0)
        {
            LOG_E("Select failed: (%d) %s.", errno, strerror(errno));
            abort();
        }
        else if (ret == 0)
        { /* Timeout */
            continue;
        }

        if (FD_ISSET(proxy->client_fd, &rfds))
        {
            s_dns_handle_client(proxy);
        }
        if (FD_ISSET(proxy->server_fd, &rfds))
        {
            s_dns_handle_server(proxy);
        }
    }

    return NULL;
}

static int s_dns_cmp_in_record(const ev_map_node_t* key1, const ev_map_node_t* key2, void* arg)
{
    (void)arg;
    const dns_in_record* r1 = container_of(key1, dns_in_record, node);
    const dns_in_record* r2 = container_of(key2, dns_in_record, node);
    if (r1->id == r2->id)
    {
        return 0;
    }
    return r1->id < r2->id ? -1 : 1;
}

static void s_dns_cleanup_in(nt_dns_proxy_t* proxy)
{
    ev_map_node_t* it = ev_map_begin(&proxy->in_table);
    while (it != NULL)
    {
        dns_in_record* rec = container_of(it, dns_in_record, node);
        it = ev_map_next(it);

        ev_map_erase(&proxy->in_table, &rec->node);
        s_dns_release_in_record(rec);
    }
}

int nt_dns_proxy_create(nt_dns_proxy_t** proxy, const nt_dns_proxy_config_t* config)
{
    int             ret;
    nt_dns_proxy_t* p = nt_malloc(sizeof(nt_dns_proxy_t));
    memcpy(&p->config, config, sizeof(*config));
    ev_map_init(&p->in_table, s_dns_cmp_in_record, NULL);

    if ((ret = nt_socket_bind_r(SOCK_DGRAM, 1, &p->config.local_addr)) < 0)
    {
        goto ERR_BIND;
    }
    p->server_fd = ret;

    if ((ret = nt_socket_connect(SOCK_DGRAM, &p->config.peer_addr, 1)) < 0)
    {
        goto ERR_CLIENT;
    }
    p->client_fd = ret;

    p->looping = 1;
    if ((ret = pthread_create(&p->tid, NULL, s_dns_proxy_thread, p)) != 0)
    {
        goto ERR_PTHREAD_CREATE;
    }

    *proxy = p;
    return 0;

ERR_PTHREAD_CREATE:
    close(p->client_fd);
ERR_CLIENT:
    close(p->server_fd);
ERR_BIND:
    nt_free(p);
    return ret;
}

void nt_dns_proxy_destroy(nt_dns_proxy_t* proxy)
{
    /* Wait for thread exit. */
    proxy->looping = 0;
    pthread_join(proxy->tid, NULL);

    s_dns_cleanup_in(proxy);
    close(proxy->server_fd);
    proxy->server_fd = -1;

    nt_free(proxy);
}

void nt_dns_proxy_local_addr(const nt_dns_proxy_t* proxy, struct sockaddr_storage* addr)
{
    memcpy(addr, &proxy->config.local_addr, sizeof(*addr));
}
