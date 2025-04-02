#include <pthread.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/select.h>
#include "utils/defs.h"
#include "utils/log.h"
#include "utils/memory.h"
#include "utils/map.h"
#include "__init__.h"

typedef struct dns_resolve_record
{
    ev_map_node_t           node;
    char                    host[1024]; /* Host name. */
    struct sockaddr_storage addr[2];    /* [0] for IPv4, [1] for IPv6. */
} dns_resolve_record_t;

typedef struct nt_addon_dns
{
    nt_addon_t basis;         /* Base handle. */
    int        type;          /* #SOCK_STREAM / #SOCK_DGRAM */
    int        inbound;       /* Inbound pipe. */
    int        outbound;      /* Outbound pipe. */
    int        looping;       /* Thread looping flag. */
    unsigned   ttl;           /* DNS cache timeout in minutes. */
    pthread_t  tid;           /* Thread ID. */
    ev_map_t   resolve_table; /* Resolve table. #dns_resolve_record_t */
    uint8_t    rbuf[2048];    /* UDP package does not larger than 1460 bytes. */
} nt_addon_dns_t;

static void s_addon_dns_clear_resolve(nt_addon_dns_t* dns)
{
    ev_map_node_t* it = ev_map_begin(&dns->resolve_table);
    while (it != NULL)
    {
        dns_resolve_record_t* record = container_of(it, dns_resolve_record_t, node);
        it = ev_map_next(it);
        ev_map_erase(&dns->resolve_table, &record->node);
        nt_free(record);
    }
}

static void s_addon_dns_release(struct nt_addon* thiz)
{
    nt_addon_dns_t* dns = container_of(thiz, nt_addon_dns_t, basis);
    dns->looping = 0;
    pthread_join(dns->tid, NULL);
    s_addon_dns_clear_resolve(dns);
    nt_free(dns);
}

static void* s_addon_dns_worker(void* arg)
{
    nt_addon_dns_t* dns = (nt_addon_dns_t*)arg;
    struct timeval  tv;
    fd_set          rfds;

    while (dns->looping)
    {
        tv.tv_sec = 0;
        tv.tv_usec = 100 * 1000;

        FD_ZERO(&rfds);
        FD_SET(dns->inbound, &rfds);
        int ret = select(dns->inbound + 1, &rfds, NULL, NULL, &tv);
        if (ret == 0)
        { /* Timeout. */
            continue;
        }
        NT_ASSERT(ret, >, 0, "select() failed: (%d) %s.", errno, strerror(errno));

        ssize_t read_sz = read(dns->inbound, dns->rbuf, sizeof(dns->rbuf));
        NT_ASSERT(read_sz, >=, 0, "read failed: (%d) %s.", errno, strerror(errno));
    }

    return NULL;
}

static int s_addon_parse_options(nt_addon_dns_t* dns, const url_comp_t* url)
{
    const char* s_ttl = nt_url_comp_query_default(url, "ttl", "10");
    if (sscanf(s_ttl, "%u", &dns->ttl) != 1)
    {
        return NT_ERR(EINVAL);
    }

    return 0;
}

static int s_addon_dns_cmp_record(const ev_map_node_t* key1, const ev_map_node_t* key2, void* arg)
{
    (void)arg;
    const dns_resolve_record_t* r1 = container_of(key1, dns_resolve_record_t, node);
    const dns_resolve_record_t* r2 = container_of(key2, dns_resolve_record_t, node);
    return strcasecmp(r1->host, r2->host);
}

static int s_addon_dns_make(nt_addon_t** addon, const url_comp_t* url, int type, int inbound,
                            int outbound)
{
    int             ret;
    nt_addon_dns_t* dns = nt_calloc(1, sizeof(nt_addon_dns_t));
    dns->basis.release = s_addon_dns_release;
    dns->type = type;
    dns->inbound = inbound;
    dns->outbound = outbound;
    ev_map_init(&dns->resolve_table, s_addon_dns_cmp_record, NULL);
    if ((ret = s_addon_parse_options(dns, url)) != 0)
    {
        goto ERR;
    }

    dns->looping = 1;
    if ((ret = pthread_create(&dns->tid, NULL, s_addon_dns_worker, dns)) != 0)
    {
        goto ERR;
    }

    *addon = &dns->basis;
    return 0;

ERR:
    nt_free(dns);
    return ret;
}

const nt_addon_factory_t nt_addon_factory_dns = {
    "dns",
    s_addon_dns_make,
};
