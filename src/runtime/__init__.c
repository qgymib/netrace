#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include "utils/defs.h"
#include "utils/log.h"
#include "utils/memory.h"
#include "utils/str.h"
#include "utils/urlparser.h"
#include "utils/socket.h"
#include "dns.h"
#include "config.h"
#include "__init__.h"



typedef struct nt_ipfilter_item
{
    int         type;
    const char* ip;
    unsigned    mask;
    unsigned    port;
} nt_ipfilter_item_t;

runtime_t* G = NULL;

static const nt_proxy_protocol_t* s_protocols[] = {
    &nt_proxy_protocol_raw,
    &nt_proxy_protocol_socks5,
};

static const nt_ipfilter_item_t s_ipfilter[] = {
    /* Ignore loopback */
    { SOCK_STREAM, "127.0.0.1",   32,  0 },
    { SOCK_STREAM, "::1",         128, 0 },
    { SOCK_DGRAM,  "127.0.0.1",   32,  0 },
    { SOCK_DGRAM,  "::1",         128, 0 },
    /* Ignore LAN. */
    { SOCK_STREAM, "10.0.0.0",    8,   0 },
    { SOCK_STREAM, "172.16.0.0",  12,  0 },
    { SOCK_STREAM, "192.168.0.0", 16,  0 },
    { SOCK_STREAM, "fe80::",      10,  0 },
    { SOCK_DGRAM,  "10.0.0.0",    8,   0 },
    { SOCK_DGRAM,  "172.16.0.0",  12,  0 },
    { SOCK_DGRAM,  "192.168.0.0", 16,  0 },
    { SOCK_DGRAM,  "fe80::",      10,  0 },
};

static int s_on_cmp_prog(const ev_map_node_t* key1, const ev_map_node_t* key2, void* arg)
{
    (void)arg;
    const prog_node_t* info1 = container_of(key1, prog_node_t, node);
    const prog_node_t* info2 = container_of(key2, prog_node_t, node);
    if (info1->pid == info2->pid)
    {
        return 0;
    }
    return info1->pid < info2->pid ? -1 : 1;
}



void nt_prog_node_release(prog_node_t* node)
{
    ev_map_node_t* it = ev_map_begin(&node->sock_map);
    while (it != NULL)
    {
        sock_node_t* sock = container_of(it, sock_node_t, node);
        it = ev_map_next(it);
        ev_map_erase(&node->sock_map, &sock->node);
        nt_sock_node_release(sock);
    }

    nt_free(node);
}

void nt_sock_node_release(sock_node_t* sock)
{
    if (sock->channel >= 0)
    {
        G->proxy->channel_release(G->proxy, sock->channel);
        sock->channel = -1;
    }
    nt_free(sock);
}

static void s_setup_ipfilter_to_rule(nt_ipfilter_item_t* dst, const url_comp_t* url)
{
    if (strcmp(url->scheme, "tcp") == 0)
    {
        dst->type = SOCK_STREAM;
    }
    else if (strcmp(url->scheme, "udp") == 0)
    {
        dst->type = SOCK_DGRAM;
    }
    else
    {
        LOG_E("Unknown type `%s`.", url->scheme);
        exit(EXIT_FAILURE);
    }

    if ((dst->ip = url->host) == NULL)
    {
        LOG_E("Missing host in url.");
        exit(EXIT_FAILURE);
    }

    if (url->port != NULL)
    {
        dst->port = *url->port;
    }
    else
    {
        dst->port = 0;
    }

    const char* v = nt_url_comp_query(url, "mask");
    if (v == NULL)
    {
        dst->mask = strstr(dst->ip, ":") != NULL ? 128 : 32;
    }
    else
    {
        if (sscanf(v, "%u", &dst->mask) != 1)
        {
            LOG_E("Invalid mask.\n");
            exit(EXIT_FAILURE);
        }
    }
}

static void s_setup_ipfilter_add_rule_list(const nt_ipfilter_item_t* items, size_t size)
{
    size_t i;
    for (i = 0; i < size; i++)
    {
        const nt_ipfilter_item_t* item = &items[i];
        int ret = nt_ipfiter_add(G->ipfilter, item->type, item->ip, item->mask, item->port);
        if (ret != 0)
        {
            LOG_E("Add ipfilter failed(%d): type=%d, ip=%s, mask=%u, port=%u", ret, item->type,
                  item->ip, item->mask, item->port);
            exit(EXIT_FAILURE);
        }
    }
}

static void s_setup_ipfilter_add_rule(const nt_cmd_opt_t* opt, const char* str, size_t len)
{
    if (strncmp(str, "default", len) == 0)
    {
        s_setup_ipfilter_add_rule_list(s_ipfilter, ARRAY_SIZE(s_ipfilter));
        return;
    }

    char*       url = nt_strndup(str, len);
    url_comp_t* comp = NULL;
    int         ret = nt_url_comp_parser(&comp, url);
    nt_free(url);
    if (ret != 0)
    {
        LOG_E("parse rule `%s` failed.", opt->opt_bypass);
        exit(EXIT_FAILURE);
    }

    nt_ipfilter_item_t item;
    s_setup_ipfilter_to_rule(&item, comp);
    nt_url_comp_free(comp);

    s_setup_ipfilter_add_rule_list(&item, 1);
}

static void s_setup_ipfilter(const nt_cmd_opt_t* opt)
{
    G->ipfilter = nt_ipfilter_create();

    const char* pos;
    const char* rule = opt->opt_bypass;
    for (; (pos = strstr(rule, ",")) != NULL; rule = pos + 1)
    {
        size_t len = pos - rule;
        if (len == 0)
        {
            continue;
        }
        s_setup_ipfilter_add_rule(opt, rule, pos - rule);
    }
    if (*rule != '\0')
    {
        s_setup_ipfilter_add_rule(opt, rule, strlen(rule));
    }
}

static int s_setup_dns_proxy(url_comp_t* url)
{
    int                   ret;
    nt_dns_proxy_config_t config;
    if ((ret = nt_ip_addr("127.0.0.1", 0, (struct sockaddr*)&config.local_addr)) != 0)
    {
        return ret;
    }

    const char*             ip = url->host;
    unsigned                port = url->port != NULL ? *url->port : 53;
    struct sockaddr_storage peer_addr;
    if ((ret = nt_ip_addr(ip, port, (struct sockaddr*)&peer_addr)) != 0)
    {
        return ret;
    }

#if 1
    ret = G->proxy->channel_create(G->proxy, SOCK_DGRAM, (struct sockaddr*)&peer_addr,
                                   &config.peer_addr);
    if (ret < 0)
    {
        LOG_E("Create DNS proxy channel failed.");
        return ret;
    }
    G->dns_chid = ret;

    return nt_dns_proxy_create(&G->dns, &config);
#else
    return 0;
#endif
}

void nt_runtime_init(const nt_cmd_opt_t* opt, pid_t pid)
{
    int ret;
    G = nt_calloc(1, sizeof(*G));
    G->prog_pid = pid;
    ev_map_init(&G->prog_map, s_on_cmp_prog, NULL);
    s_setup_ipfilter(opt);

    if (nt_proxy_create(&G->proxy, opt->opt_proxy) != 0)
    {
        LOG_E("Create proxy failed.");
        exit(EXIT_FAILURE);
    }

    if (opt->opt_dns != NULL)
    {
        url_comp_t* url = NULL;
        if ((ret = nt_url_comp_parser(&url, opt->opt_dns)) != 0)
        {
            LOG_E("Invalid option for `--dns`: %d.", ret);
            exit(EXIT_FAILURE);
        }
        if ((ret = s_setup_dns_proxy(url)) != 0)
        {
            LOG_E("Start DNS proxy failed: %d.", ret);
            exit(EXIT_FAILURE);
        }
        nt_url_comp_free(url);
    }
}

void nt_runtime_cleanup(void)
{
    ev_map_node_t* it;
    if (G == NULL)
    {
        return;
    }

    if (G->dns != NULL)
    {
        G->proxy->channel_release(G->proxy, G->dns_chid);
        nt_dns_proxy_destroy(G->dns);
        G->dns = NULL;
    }
    if (G->proxy != NULL)
    {
        G->proxy->release(G->proxy);
        G->proxy = NULL;
    }
    while ((it = ev_map_begin(&G->prog_map)) != NULL)
    {
        prog_node_t* info = container_of(it, prog_node_t, node);
        ev_map_erase(&G->prog_map, it);
        nt_prog_node_release(info);
    }
    if (G->ipfilter != NULL)
    {
        nt_ipfilter_destroy(G->ipfilter);
        G->ipfilter = NULL;
    }

    nt_free(G);
    G = NULL;
}

int nt_proxy_create(nt_proxy_t** proxy, const char* url)
{
    url_comp_t* comp = NULL;
    int         ret = nt_url_comp_parser(&comp, url);
    if (ret != 0)
    {
        LOG_E("Parser url failed: (%d) %s.", ret, strerror(ret));
        exit(EXIT_FAILURE);
    }

    size_t i;
    for (i = 0; i < ARRAY_SIZE(s_protocols); i++)
    {
        const nt_proxy_protocol_t* protocol = s_protocols[i];
        if (strcmp(protocol->scheme, comp->scheme) == 0)
        {
            ret = protocol->make(proxy, comp);
            goto finish;
        }
    }

    LOG_E("Unknown protocol `%s`.", comp->scheme);
    ret = NT_ERR(ENOTSUP);

finish:
    nt_url_comp_free(comp);
    return ret;
}
