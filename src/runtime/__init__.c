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

runtime_t* G = NULL;

static const nt_proxy_protocol_t* s_protocols[] = {
    &nt_proxy_protocol_raw,
    &nt_proxy_protocol_socks5,
};

// clang-format off
static const char* s_help =
CMAKE_PROJECT_NAME " - Trace and redirect network traffic (" CMAKE_PROJECT_VERSION ")\n"
"Usage: " CMAKE_PROJECT_NAME " [options] prog [prog-args]\n"
"Options:\n"
"  --proxy=socks5://[user[:pass]@][host[:port]]\n"
"      Set socks5 address.\n"
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
    int         i;
    int         flag_prog_args = 0;
    const char* opt;
    size_t      optlen;

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

        opt = "--proxy";
        optlen = strlen(opt);
        if (strncmp(argv[i], opt, optlen) == 0)
        {
            if (argv[i][optlen] == '=')
            {
                G->proxy_url = nt_strdup(&argv[i][optlen + 1]);
            }
            else if (i == argc - 1)
            {
                fprintf(stderr, "Missing argument for option `--proxy`.\n");
                exit(EXIT_FAILURE);
            }
            else
            {
                i++;
                G->proxy_url = nt_strdup(argv[i]);
            }

            continue;
        }
    }

    if (G->prog_args == NULL)
    {
        LOG_E("Missing program path");
        exit(EXIT_FAILURE);
    }
    if (G->proxy_url == NULL)
    {
        G->proxy_url = nt_strdup("socks5://" NT_DEFAULT_SOCKS5_ADDR ":" STRINGIFY(NT_DEFAULT_SOCKS5_PORT));
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

void nt_runtime_init(int argc, char* argv[])
{
    G = nt_calloc(1, sizeof(*G));
    G->prog_pid = -1;
    G->prog_pipe[0] = -1;
    G->prog_pipe[1] = -1;
    ev_map_init(&G->prog_map, s_on_cmp_prog, NULL);
    s_setup_cmdline(argc, argv);

    if (nt_proxy_create(&G->proxy, G->proxy_url) != 0)
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
    if (G->proxy_url != NULL)
    {
        nt_free(G->proxy_url);
        G->proxy_url = NULL;
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

    nt_free(G);
    G = NULL;
}

int nt_proxy_create(nt_proxy_t** proxy, const char* url)
{
    url_components_t* components = NULL;
    int               ret = nt_url_components_parser(&components, url);
    if (ret != 0)
    {
        LOG_E("Parser url failed: (%d) %s.", ret, strerror(ret));
        exit(EXIT_FAILURE);
    }

    size_t i;
    for (i = 0; i < ARRAY_SIZE(s_protocols); i++)
    {
        const nt_proxy_protocol_t* protocol = s_protocols[i];
        if (strcmp(protocol->scheme, components->scheme) == 0)
        {
            ret = protocol->make(proxy, components);
            goto finish;
        }
    }

    LOG_E("Unknown protocol `%s`.", components->scheme);
    ret = ENOTSUP;

finish:
    nt_url_components_free(components);
    return ret;
}
