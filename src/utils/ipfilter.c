#include <arpa/inet.h>
#include <string.h>
#include "utils/defs.h"
#include "utils/socket.h"
#include "utils/log.h"
#include "ipfilter.h"

typedef struct nt_ipfilter_rule
{
    int                     type;   /* #SOCK_STREAM or #SOCK_DGRAM */
    struct sockaddr_storage mask;   /* netmask. only sin_addr or sin6_addr has meaning. */
    struct sockaddr_storage masked; /* masked address. */
} nt_ipfilter_rule_t;

struct nt_ipfilter
{
    nt_ipfilter_rule_t* rules;
    size_t              rule_sz;
};

nt_ipfilter_t* nt_ipfilter_create()
{
    return calloc(1, sizeof(nt_ipfilter_rule_t));
}

void nt_ipfilter_destroy(nt_ipfilter_t* filter)
{
    free(filter->rules);
    filter->rules = NULL;
    filter->rule_sz = 0;
    free(filter);
}

static int s_ipfilter_add_ipv4(nt_ipfilter_rule_t* rule, unsigned mask)
{
    if (mask > 32)
    {
        return NT_ERR(EINVAL);
    }

    struct sockaddr_in* mask_addr = (struct sockaddr_in*)&rule->mask;
    struct sockaddr_in* masked_addr = (struct sockaddr_in*)&rule->masked;

    mask_addr->sin_addr.s_addr = htonl((mask == 0) ? 0 : (~0UL << (32 - mask)));
    masked_addr->sin_addr.s_addr &= mask_addr->sin_addr.s_addr;

    return 0;
}

static int s_ipfilter_add_ipv6(nt_ipfilter_rule_t* rule, unsigned mask)
{
    if (mask > 128)
    {
        return NT_ERR(EINVAL);
    }

    size_t               i;
    size_t               full_bytes = mask / 8;
    size_t               remaining_bits = mask % 8;
    struct sockaddr_in6* mask_addr = (struct sockaddr_in6*)&rule->mask;
    struct sockaddr_in6* masked_addr = (struct sockaddr_in6*)&rule->masked;

    for (i = 0; i < full_bytes; i++)
    {
        mask_addr->sin6_addr.s6_addr[i] = 0xFF;
    }
    if (full_bytes < 16 && remaining_bits > 0)
    {
        mask_addr->sin6_addr.s6_addr[full_bytes] = (0xFF << (8 - remaining_bits)) & 0xFF;
    }

    for (i = 0; i < 16; i++)
    {
        masked_addr->sin6_addr.s6_addr[i] &= mask_addr->sin6_addr.s6_addr[i];
    }

    return 0;
}

int nt_ipfiter_add(nt_ipfilter_t* filter, int type, const char* ip, unsigned mask, int port)
{
    filter->rule_sz++;
    filter->rules = realloc(filter->rules, sizeof(nt_ipfilter_rule_t) * filter->rule_sz);

    nt_ipfilter_rule_t* rule = &filter->rules[filter->rule_sz - 1];
    memset(rule, 0, sizeof(*rule));
    rule->type = type;

    int ret = nt_ip_addr(ip, port, (struct sockaddr*)&rule->masked);
    if (ret != 0)
    {
        goto ERR_INVAL;
    }

    if (rule->masked.ss_family == AF_INET)
    {
        if ((ret = s_ipfilter_add_ipv4(rule, mask)) != 0)
        {
            goto ERR_INVAL;
        }
    }
    else
    {
        if ((ret = s_ipfilter_add_ipv6(rule, mask)) != 0)
        {
            goto ERR_INVAL;
        }
    }

    return 0;

ERR_INVAL:
    filter->rule_sz--;
    return ret;
}

static int s_ipfilter_check_ipv4(const nt_ipfilter_rule_t* rule, const struct sockaddr_in* addr)
{
    struct sockaddr_in* mask_addr = (struct sockaddr_in*)&rule->mask;
    struct sockaddr_in* masked_addr = (struct sockaddr_in*)&rule->masked;

    if (masked_addr->sin_port != 0 && masked_addr->sin_port != addr->sin_port)
    {
        return 0;
    }

    uint32_t check_mask = mask_addr->sin_addr.s_addr & addr->sin_addr.s_addr;
    return check_mask == masked_addr->sin_addr.s_addr;
}

static int s_ipfilter_check_ipv6(const nt_ipfilter_rule_t* rule, const struct sockaddr_in6* addr)
{
    struct sockaddr_in6* mask_addr = (struct sockaddr_in6*)&rule->mask;
    struct sockaddr_in6* masked_addr = (struct sockaddr_in6*)&rule->masked;

    if (masked_addr->sin6_port != 0 && masked_addr->sin6_port != addr->sin6_port)
    {
        return 0;
    }

    size_t i;
    for (i = 0; i < ARRAY_SIZE(addr->sin6_addr.s6_addr); i++)
    {
        uint8_t check_mask = addr->sin6_addr.s6_addr[i] & mask_addr->sin6_addr.s6_addr[i];
        if (check_mask != masked_addr->sin6_addr.s6_addr[i])
        {
            return 0;
        }
    }
    return 1;
}

int nt_ipfilter_check(nt_ipfilter_t* filter, int type, const struct sockaddr* addr)
{
    size_t i;
    for (i = 0; i < filter->rule_sz; i++)
    {
        const nt_ipfilter_rule_t* rule = &filter->rules[i];
        const int                 family = rule->masked.ss_family;
        if (rule->type != type || family != addr->sa_family)
        {
            continue;
        }

        if (family == AF_INET && s_ipfilter_check_ipv4(rule, (struct sockaddr_in*)addr))
        {
            return 1;
        }
        else if (family == AF_INET6 && s_ipfilter_check_ipv6(rule, (struct sockaddr_in6*)addr))
        {
            return 1;
        }
    }

    return 0;
}
