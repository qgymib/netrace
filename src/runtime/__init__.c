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

// clang-format off
static const char* s_help =
CMAKE_PROJECT_NAME " - Trace and redirect network traffic (" CMAKE_PROJECT_VERSION ")\n"
"Usage: " CMAKE_PROJECT_NAME " [options] prog [prog-args]\n"
"Options:\n"
"  --socks5=IP\n"
"  --socks5=:PORT\n"
"  --socks5=IP:PORT\n"
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

static void s_setup_cmdline_socks5_addr(const char* value)
{
    nt_free(G->socks5_addr);
    G->socks5_addr = nt_strdup(value);
    G->socks5_port = NT_DEFAULT_SOCKS5_PORT;
}

static void s_setup_cmdline_socks5(const char* value)
{
    const char* pos = nt_strrstr(value, ":");

    /* Only address. */
    if (pos == NULL)
    {
        if (value[0] == '\0')
        {
            goto ERR_INVALID_ADDR;
        }
        s_setup_cmdline_socks5_addr(value);
        return;
    }

    /* Only port. */
    if (pos == value)
    {
        nt_free(G->socks5_addr);
        G->socks5_addr = nt_strdup(NT_DEFAULT_SOCKS5_ADDR);
        goto PARSER_PORT;
    }
    /* Check if it is a IPv6 address. */
    if (pos[-1] == ':')
    {
        s_setup_cmdline_socks5_addr(value);
        return;
    }

    size_t addrlen = pos - value;
    nt_free(G->socks5_addr);
    G->socks5_addr = nt_malloc(addrlen + 1);
    memcpy(G->socks5_addr, value, addrlen);
    G->socks5_addr[addrlen] = '\0';

PARSER_PORT:
    if (sscanf(pos + 1, "%u", &G->socks5_port) != 1)
    {
        goto ERR_INVALID_PORT;
    }

    return;

ERR_INVALID_ADDR:
    fprintf(stderr, "invalid address for argument `--socks5`.\n");
    goto ERR_EXIT;
ERR_INVALID_PORT:
    fprintf(stderr, "invalid port for argument `--socks5`.\n");
    goto ERR_EXIT;
ERR_EXIT:
    exit(EXIT_FAILURE);
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

        opt = "--socks5=";
        if (strncmp(argv[i], opt, strlen(opt)) == 0)
        {
            s_setup_cmdline_socks5(argv[i] + strlen(opt));
            continue;
        }
    }

    if (G->prog_args == NULL)
    {
        LOG_E("Missing program path");
        exit(EXIT_FAILURE);
    }
    if (G->socks5_addr == NULL)
    {
        G->socks5_addr = nt_strdup(NT_DEFAULT_SOCKS5_ADDR);
        G->socks5_port = NT_DEFAULT_SOCKS5_PORT;
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
    nt_free(sock);
}

void nt_runtime_init(int argc, char* argv[])
{
    G = nt_calloc(1, sizeof(*G));
    G->tcp_listen_fd = -1;
    G->udp_listen_fd = -1;
    G->prog_pid = -1;
    G->prog_pipe[0] = -1;
    G->prog_pipe[1] = -1;
    ev_map_init(&G->prog_map, s_on_cmp_prog, NULL);
    s_setup_cmdline(argc, argv);
}

void nt_runtime_cleanup(void)
{
    if (G == NULL)
    {
        return;
    }

    ev_map_node_t* it = ev_map_begin(&G->prog_map);
    while (it != NULL)
    {
        prog_node_t* info = container_of(it, prog_node_t, node);
        it = ev_map_next(it);
        nt_prog_node_release(info);
    }
    if (G->tcp_listen_fd >= 0)
    {
        close(G->tcp_listen_fd);
        G->tcp_listen_fd = -1;
    }
    if (G->udp_listen_fd >= 0)
    {
        close(G->udp_listen_fd);
        G->udp_listen_fd = -1;
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
    if (G->socks5_addr != NULL)
    {
        nt_free(G->socks5_addr);
        G->socks5_addr = NULL;
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
