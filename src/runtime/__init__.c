#define _GNU_SOURCE
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <sched.h>
#include <sys/syscall.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <netinet/in.h>
#include "utils/defs.h"
#include "utils/log.h"
#include "utils/memory.h"
#include "utils/str.h"
#include "utils/urlparser.h"
#include "utils/socket.h"
#include "utils/syscall.h"
#include "dns.h"
#include "config.h"
#include "__init__.h"

#define SYSCALL_SKIP(xx) ((void)(xx))

/**
 * @brief System call tracing table.
 */
/* clang-format off */
#define SYSCALL_TRACING_TABLE(xx)   \
    xx(SYS_socket,  s_trace_syscall_socket_enter,   s_trace_syscall_socket_leave)   \
    xx(SYS_close,   s_trace_syscall_close_enter,    SYSCALL_SKIP)                   \
    xx(SYS_connect, s_trace_syscall_connect_enter,  s_trace_syscall_connect_leave)  \
    xx(SYS_clone,   s_trace_syscall_clone_enter,    SYSCALL_SKIP)
/* clang-format on */

typedef struct nt_ipfilter_item
{
    int         type;
    const char* ip;
    unsigned    mask;
    unsigned    port;
} nt_ipfilter_item_t;

typedef struct log_level_pair
{
    const char*    str;
    nt_log_level_t level;
} log_level_pair;

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

static int do_child(const nt_cmd_opt_t* opt, int prog_pipe[2])
{
    int code = 0;

    /* Close the read end of the pipe. */
    close(prog_pipe[0]);
    prog_pipe[0] = -1;

    /* Setup trace. */
    if (ptrace(PTRACE_TRACEME, 0, NULL, NULL) < 0)
    {
        code = errno;
        write(prog_pipe[1], &code, sizeof(code));
    }

    /*
     * Execute program.
     * exec*() does two thing when success:
     * 1. Stop and raise `SIGTRAP` to parent.
     * 2. Close pipe.
     */
    if (execvp(opt->prog_args[0], opt->prog_args) < 0)
    {
        code = errno;
        write(prog_pipe[1], &code, sizeof(code));
    }

    return EXIT_FAILURE;
}

static void s_trace_setup(prog_node_t* info)
{
    info->b_setup = 1;

    /* Ask to trace fork() family, so we can keep eye on grandchild. */
    long trace_option =
        PTRACE_O_TRACECLONE | PTRACE_O_TRACEEXEC | PTRACE_O_TRACEFORK | PTRACE_O_TRACEVFORK;
    long ptrace_ret = ptrace(PTRACE_SETOPTIONS, info->pid, 0, trace_option);
    NT_ASSERT(ptrace_ret == 0, "ptrace failed: (%d) %s", errno, strerror(errno));
}

static prog_node_t* s_find_proc(pid_t pid)
{
    prog_node_t tmp;
    tmp.pid = pid;
    ev_map_node_t* it = ev_map_find(&G->prog_map, &tmp.node);
    if (it == NULL)
    {
        return NULL;
    }
    return container_of(it, prog_node_t, node);
}

static void s_check_child_exit_reason(int prog_pipe[2])
{
    int     code = 0;
    ssize_t read_sz = nt_read(prog_pipe[0], &code, sizeof(code));

    /* There are error from child process, probably because invalid program
     * path. */
    if (read_sz > 0)
    {
        LOG_E("Child process raise error: (%d) %s.", code, strerror(code));
        exit(EXIT_FAILURE);
    }

    /* There are error from pipe. */
    NT_ASSERT(read_sz == 0, "Pipe error: (%d) %s.", (int)read_sz, NT_STRERROR(read_sz));

    /* Pipe closed, child exec() success. */
}

static void s_trace_syscall_socket_enter(prog_node_t* prog)
{
    sock_node_t* sock = nt_calloc(1, sizeof(sock_node_t));
    sock->fd = -1;
    sock->channel = -1;
    sock->domain = nt_syscall_get_arg(prog->pid, 0);
    sock->type = nt_syscall_get_arg(prog->pid, 1) & 0xFF;
    sock->protocol = nt_syscall_get_arg(prog->pid, 2);

    /* clang-format off */
    NT_ASSERT(ev_map_insert(&prog->sock_map, &sock->node) == NULL,
        "Conflict node: pid=%d, fd=%d.", prog->pid, sock->fd);
    /* clang-format on */
    prog->sock_last = sock;
}

/**
 * @brief Release socket node.
 * @warning The node must already removed from #prog_node_t::sock_map.
 * @param[in] prog Program node.
 */
static void nt_sock_node_release(sock_node_t* sock)
{
    if (sock->channel >= 0)
    {
        G->proxy->channel_release(G->proxy, sock->channel);
        sock->channel = -1;
    }
    nt_free(sock);
}

static void s_trace_syscall_socket_leave(prog_node_t* prog)
{
    sock_node_t* sock = prog->sock_last;
    prog->sock_last = NULL;

    /* Update fd. */
    ev_map_erase(&prog->sock_map, &sock->node);
    if ((sock->fd = nt_syscall_get_ret(prog->pid)) < 0)
    {
        LOG_D("pid=%d ignore socket=%d domain=%d type=%d protocol=%d.", prog->pid, sock->fd,
              sock->domain, sock->type, sock->protocol);
        nt_sock_node_release(sock);
        return;
    }

    /* clang-format off */
    NT_ASSERT(ev_map_insert(&prog->sock_map, &sock->node) == NULL,
        "Conflict node: pid=%d, fd=%d.", prog->pid, sock->fd);
    /* clang-format on */
}

static sock_node_t* s_prog_search_sock(prog_node_t* prog, int fd)
{
    sock_node_t tmp;
    tmp.fd = fd;
    ev_map_node_t* it = ev_map_find(&prog->sock_map, &tmp.node);
    if (it == NULL)
    {
        return NULL;
    }

    return container_of(it, sock_node_t, node);
}

static void s_trace_syscall_close_enter(prog_node_t* prog)
{
    int          fd = nt_syscall_get_arg(prog->pid, 0);
    sock_node_t* sock = s_prog_search_sock(prog, fd);
    if (sock == NULL)
    {
        return;
    }

    ev_map_erase(&prog->sock_map, &sock->node);
    nt_sock_node_release(sock);
}

static void s_trace_syscall_connect_enter(prog_node_t* prog)
{
    int          fd = nt_syscall_get_arg(prog->pid, 0);
    sock_node_t* sock = s_prog_search_sock(prog, fd);
    if (sock == NULL)
    {
        LOG_E("pid=%d cannot find fd=%d.", prog->pid, fd);
        prog->sock_last = NULL;
        return;
    }
    prog->sock_last = sock;

    /* Backup connect address. */
    long p_sockaddr = nt_syscall_get_sockaddr(prog->pid, 1, &sock->peer_addr);

    /* Parser peer information. */
    char peer_ip[64];
    int  peer_port = 0;
    nt_ip_name((struct sockaddr*)&sock->peer_addr, peer_ip, sizeof(peer_ip), &peer_port);
    const char* sock_type_name = nt_socktype_name(sock->type);

    struct sockaddr_storage proxyaddr;
    if (sock->type == SOCK_DGRAM && peer_port == 53 && G->dns != NULL)
    {
        LOG_I("Proxy dns://%s:%d", peer_ip, peer_port);
        nt_dns_proxy_local_addr(G->dns, &proxyaddr);
        goto REWRITE_ADDRESS;
    }

    /* Check filter. */
    if (nt_ipfilter_check(G->ipfilter, sock->type, (struct sockaddr*)&sock->peer_addr))
    {
        LOG_I("Bypass %s://%s:%d", sock_type_name, peer_ip, peer_port);
        return;
    }
    LOG_I("Redirect %s://%s:%d", sock_type_name, peer_ip, peer_port);

    /* Create proxy channel. */
    sock->channel = G->proxy->channel_create(G->proxy, sock->type,
                                             (struct sockaddr*)&sock->peer_addr, &proxyaddr);
    if (sock->channel < 0)
    {
        return;
    }

REWRITE_ADDRESS:
    /* Overwrite connect address. */
    nt_syscall_set_sockaddr(prog->pid, p_sockaddr, &proxyaddr);
}

static void s_trace_syscall_clone_enter(prog_node_t* prog)
{
    long flags = nt_syscall_get_arg(prog->pid, 0);
    flags &= ~CLONE_UNTRACED;

    /*
     * `CLONE_PTRACE` seems useless on x86_64 and cause fork() return invalid value in aarch64.
     */
    // flags |= CLONE_PTRACE;
    nt_syscall_set_arg(prog->pid, 0, flags);
}

static void s_trace_syscall_connect_leave(prog_node_t* prog)
{
    long p_sockaddr = nt_syscall_get_arg(prog->pid, 1);

    sock_node_t* sock = prog->sock_last;
    if (sock != NULL)
    {
        size_t data_sz = sock->peer_addr.ss_family == AF_INET ? sizeof(struct sockaddr_in)
                                                              : sizeof(struct sockaddr_in6);
        nt_syscall_setdata(prog->pid, p_sockaddr, &sock->peer_addr, data_sz);
    }

    prog->sock_last = NULL;
}

static void s_trace_syscall_enter(prog_node_t* info)
{
    switch (info->syscall)
    {
        // clang-format off
#define EXPAND_SYSCALL(ID, ENTER, _) case ID: ENTER(info); break;
    SYSCALL_TRACING_TABLE(EXPAND_SYSCALL)
#undef EXPAND_SYSCALL
        // clang-format on
    default:
    }
}

static void s_trace_syscall_leave(prog_node_t* info)
{
    switch (info->syscall)
    {
        // clang-format off
#define EXPAND_SYSCALL(ID, _, LEAVE) case ID: LEAVE(info); break;
    SYSCALL_TRACING_TABLE(EXPAND_SYSCALL)
#undef EXPAND_SYSCALL
        // clang-format on
    default:
    }
}

static void s_trace_syscall(prog_node_t* info)
{
    if (!info->b_in_syscall)
    {
        info->syscall = nt_syscall_get_id(info->pid);

    SYSCALL_ENTER:
        info->b_in_syscall = 1;
        s_trace_syscall_enter(info);
    }
    else
    {
        int syscall = nt_syscall_get_id(info->pid);
        if (syscall != info->syscall)
        {
            LOG_D("syscall mismatch: pid=%d old=%d new=%d.", info->pid, info->syscall, syscall);
            info->syscall = syscall;
            goto SYSCALL_ENTER;
        }

        info->b_in_syscall = 0;
        s_trace_syscall_leave(info);
    }
}

static int s_on_cmp_sock(const ev_map_node_t* key1, const ev_map_node_t* key2, void* arg)
{
    (void)arg;
    const sock_node_t* n1 = container_of(key1, sock_node_t, node);
    const sock_node_t* n2 = container_of(key2, sock_node_t, node);
    return n1->fd - n2->fd;
}

static prog_node_t* s_prog_node_save(pid_t pid)
{
    prog_node_t* info = nt_calloc(1, sizeof(prog_node_t));
    info->pid = pid;
    ev_map_init(&info->sock_map, s_on_cmp_sock, NULL);

    ev_map_insert(&G->prog_map, &info->node);
    LOG_D("Tracing new process pid=%d.", pid);
    return info;
}

/**
 * @brief Release program node.
 * @warning The node must already removed from #runtime_t::prog_map.
 * @param[in] prog Program node.
 */
static void nt_prog_node_release(prog_node_t* node)
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

static void do_trace(const nt_cmd_opt_t* opt, int prog_pipe[2])
{
    while (ev_map_size(&G->prog_map) != 0)
    {
        int   status = 0;
        pid_t pid = wait(&status);
        if (pid < 0)
        {
            break;
        }

        prog_node_t* info = s_find_proc(pid);
        if (info == NULL)
        { /* New grandchild incoming. */
            info = s_prog_node_save(pid);
        }

        if (WIFSTOPPED(status))
        {
            int sig = WSTOPSIG(status);
            if (sig == SIGTRAP)
            {
                if (!info->b_setup)
                { /* execve() */
                    s_trace_setup(info);
                }
                else
                { /* syscall trigger. */
                    s_trace_syscall(info);
                }
                sig = 0;
            }
            else if (sig == SIGSTOP)
            {
                if (!info->b_setup)
                { /* clone() / fork() / vfork() */
                    s_trace_setup(info);
                    sig = 0;
                }
            }

            NT_ASSERT(ptrace(PTRACE_SYSCALL, pid, 0, sig) == 0, "(%d) %s", errno, strerror(errno));
            continue;
        }

        if (WIFEXITED(status) || WIFSIGNALED(status))
        {
            if (pid == G->prog_pid)
            {
                s_check_child_exit_reason(prog_pipe);
                if (WIFEXITED(status))
                {
                    G->prog_exit_retval = WEXITSTATUS(status);
                }
                else
                {
                    G->prog_exit_retval = EXIT_FAILURE;
                    LOG_W("`%s` exit abnormal, set our exitcode to %d.", opt->prog_args[0],
                          G->prog_exit_retval);
                }
            }

            ev_map_erase(&G->prog_map, &info->node);
            nt_prog_node_release(info);
            LOG_D("PID=%d exit.", pid);
            continue;
        }
    }
}

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

static int s_setup_ipfilter_add_rule_list(const nt_ipfilter_item_t* items, size_t size)
{
    size_t i;
    for (i = 0; i < size; i++)
    {
        const nt_ipfilter_item_t* item = &items[i];
        int ret = nt_ipfiter_add(G->ipfilter, item->type, item->ip, item->mask, item->port);
        if (ret != 0)
        {
            LOG_E("Add ipfilter failed(%d): type=%d, ip=%s, mask=%u, port=%u", ret, item->type,
                  item->ip == NULL ? "nil" : item->ip, item->mask, item->port);
            return NT_ERR(EINVAL);
        }
    }
    return 0;
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

static int s_setup_ipfilter_add_rule(const nt_cmd_opt_t* opt, const char* str)
{
    int ret;
    if (strcmp(str, "default") == 0)
    {
        return s_setup_ipfilter_add_rule_list(s_ipfilter, ARRAY_SIZE(s_ipfilter));
    }

    url_comp_t* comp = NULL;
    if ((ret = nt_url_comp_parser(&comp, str)) != 0)
    {
        LOG_E("parse rule `%s` failed.", opt->bypass);
        return ret;
    }

    nt_ipfilter_item_t item;
    s_setup_ipfilter_to_rule(&item, comp);

    ret = s_setup_ipfilter_add_rule_list(&item, 1);
    nt_url_comp_free(comp);

    return ret;
}

static int s_setup_ipfilter(const nt_cmd_opt_t* opt)
{
    int ret = 0;
    const char* bypass = opt->bypass != NULL ? opt->bypass : "default";
    G->ipfilter = nt_ipfilter_create();

    char* saveptr;
    char* rule = nt_strdup(bypass);
    char* s = rule;
    char* p;
    while ((p = strtok_r(s, ",", &saveptr)) != NULL)
    {
        s = NULL;
        if ((ret = s_setup_ipfilter_add_rule(opt, p)) != 0)
        {
            break;
        }
    }
    nt_free(rule);

    return ret;
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

    ret = G->proxy->channel_create(G->proxy, SOCK_DGRAM, (struct sockaddr*)&peer_addr,
                                   &config.peer_addr);
    if (ret < 0)
    {
        LOG_E("Create DNS proxy channel failed.");
        return ret;
    }
    G->dns_chid = ret;

    return nt_dns_proxy_create(&G->dns, &config);
}

/**
 * @brief Create a proxy object.
 * @param[out] proxy Proxy object.
 * @param[in] url Url.
 * @return 0 if success, errno if failed.
 */
static int nt_proxy_create(nt_proxy_t** proxy, const char* url)
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

/**
 * @brief Initialize global runtime.
 * @param[in] argc  Argument count.
 * @param[in] argv  Argument list.
 */
static void nt_runtime_init(const nt_cmd_opt_t* opt, pid_t pid)
{
    int ret;
    G = nt_calloc(1, sizeof(*G));
    G->prog_pid = pid;
    ev_map_init(&G->prog_map, s_on_cmp_prog, NULL);
    if ((ret = s_setup_ipfilter(opt)) != 0)
    {
        exit(EXIT_FAILURE);
    }

    const char* proxy = opt->proxy != NULL ? opt->proxy : NT_DEFAULT_PROXY;
    if (nt_proxy_create(&G->proxy, proxy) != 0)
    {
        LOG_E("Create proxy failed.");
        exit(EXIT_FAILURE);
    }
    LOG_D("Create proxy to `%s`.", proxy);

    if (opt->dns != NULL)
    {
        url_comp_t* url = NULL;
        if ((ret = nt_url_comp_parser(&url, opt->dns)) != 0)
        {
            LOG_E("Invalid option for `--dns`: %d.", ret);
            exit(EXIT_FAILURE);
        }
        if ((ret = s_setup_dns_proxy(url)) != 0)
        {
            LOG_E("Start DNS proxy failed: %d.", ret);
            exit(EXIT_FAILURE);
        }
        LOG_D("Setup DNS proxy to `%s`.", opt->dns);
        nt_url_comp_free(url);
    }
}

static int do_parent(const nt_cmd_opt_t* opt, int prog_pipe[2], pid_t pid)
{
    /* Close the write end of the pipe. */
    close(prog_pipe[1]);
    prog_pipe[1] = -1;

    /* Initialize global runtime. */
    nt_runtime_init(opt, pid);

    /* Save record */
    s_prog_node_save(pid);

    /* Trace child. */
    do_trace(opt, prog_pipe);
    return G->prog_exit_retval;
}

/**
 * @brief Cleanup runtime.
 */
static void nt_runtime_cleanup(void)
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

static nt_log_level_t s_cmd_opt_parse_loglevel(const char* level)
{
    static log_level_pair s_level[] = {
        { "debug", NT_LOG_DEBUG },
        { "info",  NT_LOG_INFO  },
        { "warn",  NT_LOG_WARN  },
        { "error", NT_LOG_ERROR },
    };

    if (level == NULL)
    {
        return NT_LOG_INFO;
    }

    size_t i;
    for (i = 0; i < ARRAY_SIZE(s_level); i++)
    {
        if (strcasecmp(s_level[i].str, level) == 0)
        {
            return s_level[i].level;
        }
    }

    LOG_W("Unknown log level '%s', treat as `info`", level);
    return NT_LOG_INFO;
}

int nt_run(const nt_cmd_opt_t* opt)
{
    int ret;
    nt_log_set_level(s_cmd_opt_parse_loglevel(opt->loglevel));

    /*
     * Setup pipe between parent and child, to see if there are any error before
     * executing program.
     */
    int prog_pipe[2]; /* [0] for read, [1] for write. */
    NT_ASSERT(pipe2(prog_pipe, O_CLOEXEC) == 0, "(%d) %s", errno, strerror(errno));

    pid_t prog_pid = fork();
    NT_ASSERT(prog_pid >= 0, "fork() failed: (%d) %s.", errno, strerror(errno));

    if (prog_pid == 0)
    {
        return do_child(opt, prog_pipe);
    }

    ret = do_parent(opt, prog_pipe, prog_pid);
    nt_runtime_cleanup();

    return ret;
}
