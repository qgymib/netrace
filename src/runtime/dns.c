#include <unistd.h>
#include <pthread.h>
#include <arpa/inet.h>
#include <sys/select.h>
#include "utils/defs.h"
#include "utils/dns.h"
#include "utils/map.h"
#include "utils/memory.h"
#include "utils/socket.h"
#include "utils/log.h"
#include "dns.h"

typedef struct dns_query_record
{
    ev_map_node_t node;
} dns_query_record_t;

struct nt_dns_proxy
{
    int                     server_fd;
    struct sockaddr_storage local_addr;
    int                     looping;
    pthread_t               tid;
    ev_map_t                query_table;
    uint8_t                 recv_buf[2048];
};

static void* s_dns_proxy_thread(void* arg)
{
    nt_dns_proxy_t* proxy = (nt_dns_proxy_t*)arg;
    int             ret;
    fd_set          rfds;
    struct timeval  tv;
    int             fd = proxy->server_fd;

    while (proxy->looping)
    {
        FD_ZERO(&rfds);
        FD_SET(fd, &rfds);

        tv.tv_sec = 0;
        tv.tv_usec = 100 * 1000;
        if ((ret = select(fd + 1, &rfds, NULL, NULL, &tv)) < 0)
        {
            LOG_E("Select failed: (%d) %s.", errno, strerror(errno));
            abort();
        }
        else if (ret == 0)
        { /* Timeout */
            continue;
        }
    }

    return NULL;
}

int nt_dns_proxy_create(nt_dns_proxy_t** proxy, const nt_dns_proxy_config_t* config)
{
    int             ret;
    nt_dns_proxy_t* p = nt_malloc(sizeof(nt_dns_proxy_t));

    struct sockaddr* addr = (struct sockaddr*)&p->local_addr;
    socklen_t        addr_len = sizeof(p->local_addr);
    if ((ret = nt_ip_addr(config->ip, config->port, addr)) < 0)
    {
        goto ERR;
    }
    if ((p->server_fd = socket(p->local_addr.ss_family, SOCK_DGRAM, 0)) < 0)
    {
        goto ERR;
    }
    if ((ret = bind(p->server_fd, addr, addr_len)) != 0)
    {
        ret = NT_ERR(errno);
        goto ERR_BIND;
    }
    if ((ret = getsockname(p->server_fd, addr, &addr_len)) < 0)
    {
        ret = NT_ERR(errno);
        goto ERR_BIND;
    }
    nt_nonblock(p->server_fd, 1);

    p->looping = 1;
    if ((ret = pthread_create(&p->tid, NULL, s_dns_proxy_thread, p)) != 0)
    {
        goto ERR_BIND;
    }

    *proxy = p;
    return 0;

ERR_BIND:
    close(p->server_fd);
ERR:
    nt_free(p);
    return ret;
}

void nt_dns_proxy_destroy(nt_dns_proxy_t* proxy)
{
    proxy->looping = 0;
    pthread_join(proxy->tid, NULL);

    close(proxy->server_fd);
    proxy->server_fd = -1;

    nt_free(proxy);
}
