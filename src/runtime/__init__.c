#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include "utils/defs.h"
#include "utils/log.h"
#include "utils/memory.h"
#include "utils/str.h"
#include "config.h"
#include "__init__.h"

#define NT_CMD_PARSE_OPTION(val, opt)                                                              \
    do                                                                                             \
    {                                                                                              \
        const char* _opt = (opt);                                                                  \
        size_t      _optlen = strlen(_opt);                                                        \
        if (strncmp(argv[i], _opt, _optlen) != 0)                                                  \
        {                                                                                          \
            break;                                                                                 \
        }                                                                                          \
        if (argv[i][_optlen] == '=')                                                               \
        {                                                                                          \
            val = &argv[i][_optlen + 1];                                                           \
        }                                                                                          \
        else if (i == argc - 1)                                                                    \
        {                                                                                          \
            fprintf(stderr, "Missing value for option `%s`.\n", _opt);                             \
            exit(EXIT_FAILURE);                                                                    \
        }                                                                                          \
        else                                                                                       \
        {                                                                                          \
            i++;                                                                                   \
            val = argv[i];                                                                         \
        }                                                                                          \
        continue;                                                                                  \
    } while (0)

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

// clang-format off
static const char* s_help =
CMAKE_PROJECT_NAME " - Trace and redirect network traffic (" CMAKE_PROJECT_VERSION ")\n"
"Usage: " CMAKE_PROJECT_NAME " [options] prog [prog-args]\n"
"Options:\n"
"  --proxy=socks5://[user[:pass]@][host[:port]]\n"
"      Set socks5 address.\n"
"\n"
"  --filter=RULE_LIST\n"
"      Syntax:\n"
"        RULE_LIST    := [RULE[,RULE,...]]\n"
"        RULE         := [default]\n"
"                        [TYPE://ip[:port][/?OPTIONS]]\n"
"        TYPE         := [tcp | udp]\n"
"        OPTIONS      := [OPTION[&OPTION&...]]\n"
"        OPTION       := [mask=NUMBER]\n"
"\n"
"      Description:\n"
"        Do not redirect any traffic if it match any of the rules. By default\n"
"        all traffics to LAN and loopback are ignored. By using this option,\n"
"        the builtin filter rules are overwritten, however you can use `default`\n"
"        keyword to add these rules again.\n"
"\n"
"        The `port` is optional. If it is set to non-zero, only traffic send to\n"
"        that port is ignored.\n"
"\n"
"        The `mask` is optional. If it is not set, treat as `32` for IPv4 or\n"
"        `128` for IPv6.\n"
"\n"
"      Example:\n"
"        --bypass=,\n"
"            Redirect anything.\n"
"        --bypass=udp://127.0.0.1\n"
"            Only ignore udp packets send to 127.0.0.1, no matter which\n"
"            destination port is.\n"
"        --bypass=tcp://192.168.0.1:1234\n"
"            Only ignore tcp transmissions connect to 192.168.0.1:1234\n"
"        --bypass=default,udp://0.0.0.0/?mask=0\n"
"            In addition to the default rules, ignore all IPv4 UDP transmissions.\n"
"        --bypass=default,udp://0.0.0.0/?mask=0,udp://:::53/?mask=0\n"
"            In addition to the default rules, ignore all IPv4 UDP transmissions,\n"
"            ignore all IPv6 UDP transmissions whose destination port is 53.\n"
"\n"
"  -h, --help\n"
"      Show this help and exit.\n"
;
// clang-format on

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

static void s_setup_cmdline_append_prog_args(const char* arg)
{
    /* The first argument. */
    if (G->prog_args == NULL)
    {
        G->prog_args = (char**)nt_malloc(sizeof(char*) * 2);
        G->prog_args[0] = nt_strdup(arg);
        G->prog_args[1] = NULL;
        return;
    }

    /* More arguments. */
    size_t prog_nargs = 0;
    while (G->prog_args[prog_nargs] != NULL)
    {
        prog_nargs++;
    }
    G->prog_args = nt_realloc(G->prog_args, sizeof(char*) * (prog_nargs + 2));
    G->prog_args[prog_nargs] = nt_strdup(arg);
    G->prog_args[prog_nargs + 1] = NULL;
}

static void s_setup_cmdline(int argc, char* argv[])
{
    int i;
    int flag_prog_args = 0;

    for (i = 1; i < argc; i++)
    {
        if (flag_prog_args)
        {
            s_setup_cmdline_append_prog_args(argv[i]);
            continue;
        }

        if (argv[i][0] != '-')
        {
            s_setup_cmdline_append_prog_args(argv[i]);
            flag_prog_args = 1;
            continue;
        }

        if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0)
        {
            fprintf(stdout, "%s\n", s_help);
            exit(EXIT_SUCCESS);
        }

        NT_CMD_PARSE_OPTION(G->opt_proxy, "--proxy");
        NT_CMD_PARSE_OPTION(G->opt_bypass, "--bypass");
    }

    if (G->prog_args == NULL)
    {
        LOG_E("Missing program path");
        exit(EXIT_FAILURE);
    }
    if (G->opt_proxy == NULL)
    {
        G->opt_proxy = "socks5://" NT_DEFAULT_SOCKS5_ADDR ":" STRINGIFY(NT_DEFAULT_SOCKS5_PORT);
    }
    if (G->opt_bypass == NULL)
    {
        G->opt_bypass = "default";
    }
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

static void s_setup_ipfilter_add_rule(const char* str, size_t len)
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
        LOG_E("parse rule `%s` failed.", G->opt_bypass);
        exit(EXIT_FAILURE);
    }

    nt_ipfilter_item_t item;
    s_setup_ipfilter_to_rule(&item, comp);
    nt_url_comp_free(comp);

    s_setup_ipfilter_add_rule_list(&item, 1);
}

static void s_setup_ipfilter(void)
{
    G->ipfilter = nt_ipfilter_create();

    const char* pos;
    const char* rule = G->opt_bypass;
    for (; (pos = strstr(rule, ",")) != NULL; rule = pos + 1)
    {
        size_t len = pos - rule;
        if (len == 0)
        {
            continue;
        }
        s_setup_ipfilter_add_rule(rule, pos - rule);
    }
    if (*rule != '\0')
    {
        s_setup_ipfilter_add_rule(rule, strlen(rule));
    }
}

void nt_runtime_init(int argc, char* argv[])
{
    G = nt_calloc(1, sizeof(*G));
    G->prog_pid = -1;
    G->prog_pipe[0] = -1;
    G->prog_pipe[1] = -1;
    ev_map_init(&G->prog_map, s_on_cmp_prog, NULL);
    s_setup_cmdline(argc, argv);
    s_setup_ipfilter();

    if (nt_proxy_create(&G->proxy, G->opt_proxy) != 0)
    {
        LOG_E("Create proxy failed.");
        exit(EXIT_FAILURE);
    }
}

void nt_runtime_cleanup(void)
{
    ev_map_node_t* it;
    if (G == NULL)
    {
        return;
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
    if (G->prog_args != NULL)
    {
        size_t i;
        for (i = 0; G->prog_args[i] != NULL; i++)
        {
            nt_free(G->prog_args[i]);
            G->prog_args[i] = NULL;
        }
        nt_free(G->prog_args);
        G->prog_args = NULL;
    }
    if (G->prog_pipe[0] >= 0)
    {
        close(G->prog_pipe[0]);
        G->prog_pipe[0] = -1;
    }
    if (G->prog_pipe[1] >= 0)
    {
        close(G->prog_pipe[1]);
        G->prog_pipe[1] = -1;
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
