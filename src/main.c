#define _GNU_SOURCE
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <assert.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/syscall.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "utils/defs.h"
#include "utils/log.h"
#include "utils/map.h"
#include "utils/syscall.h"
#include "config.h"

#define SYSCALL_SKIP(xx) ((void)(xx))

/**
 * @brief System call tracing table.
 */
// clang-format off
#define SYSCALL_TRACING_TABLE(xx)   \
    xx(SYS_socket,  s_trace_syscall_socket_enter,   s_trace_syscall_socket_leave)   \
    xx(SYS_close,   s_trace_syscall_close_enter,    SYSCALL_SKIP)                   \
    xx(SYS_connect, SYSCALL_SKIP,                   SYSCALL_SKIP)                   \
    xx(SYS_clone,   SYSCALL_SKIP,                   SYSCALL_SKIP)
// clang-format on

typedef struct sock_node
{
    ev_map_node_t node;
    int           fd;     /* Return value of child's socket(). */
    int           domain; /* Communication domain: AF_INET/AF_INET6. */
    int           type;   /* SOCK_STREAM/SOCK_DGRAM */
} sock_node_t;

typedef struct prog_node
{
    ev_map_node_t node;
    pid_t         pid;                    /* Process ID. */
    ev_map_t      sock_map;               /* Program socket map. Type: #sock_node_t. */
    sock_node_t*  sock_last;              /* Last socket we are tracing. */
    int           syscall;                /* System call number. */
    int           flag_setup : 1;         /* Is setup done. */
    int           flag_syscall_enter : 1; /* Is entry syscall. */
} prog_node_t;

typedef struct runtime
{
    char*    socks5_addr; /* Socks5 address. */
    unsigned socks5_port; /* Socks5 port. */

    int                tcp_listen_fd; /* TCP socket. */
    int                udp_listen_fd; /* UDP socket. */
    struct sockaddr_in listen_addr;   /* Listen address. */

    char**   prog_args;    /* Arguments for child program, ending with NULL. */
    pid_t    prog_pid;     /* First child pid. */
    int      prog_pipe[2]; /* [0] for read, [1] for write. */
    ev_map_t prog_map;     /* Program tracing map. Type: #prog_node_t. */
} runtime_t;

/**
 * @brief Global runtime.
 */
static runtime_t* G = NULL;

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

static void s_prog_node_release(prog_node_t* node)
{
    ev_map_node_t* it = ev_map_begin(&node->sock_map);
    while (it != NULL)
    {
        sock_node_t* sock = container_of(it, sock_node_t, node);
        it = ev_map_next(it);
        ev_map_erase(&node->sock_map, &sock->node);
        free(sock);
    }

    free(node);
}

static void _at_exit(void)
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
        s_prog_node_release(info);
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
            free(G->prog_args[i]);
            G->prog_args[i] = NULL;
        }
        free(G->prog_args);
        G->prog_args = NULL;
    }
    if (G->socks5_addr != NULL)
    {
        free(G->socks5_addr);
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

    free(G);
    G = NULL;
}

static void s_setup_cmdline_append_prog_args(const char* arg)
{
    /* The first argument. */
    if (G->prog_args == NULL)
    {
        if ((G->prog_args = (char**)malloc(sizeof(char*) * 2)) == NULL)
        {
            LOG_F_ABORT("%s", strerror(ENOMEM));
        }
        if ((G->prog_args[0] = strdup(arg)) == NULL)
        {
            LOG_F_ABORT("%s", strerror(ENOMEM));
        }
        G->prog_args[1] = NULL;
        return;
    }

    /* More arguments. */
    size_t prog_nargs = 0;
    while (G->prog_args[prog_nargs] != NULL)
    {
        prog_nargs++;
    }
    char** new_args = realloc(G->prog_args, sizeof(char*) * (prog_nargs + 2));
    if (new_args == NULL)
    {
        LOG_F_ABORT("%s", strerror(ENOMEM));
    }
    G->prog_args = new_args;
    if ((G->prog_args[prog_nargs] = strdup(arg)) == NULL)
    {
        LOG_F_ABORT("%s", strerror(ENOMEM));
    }
    G->prog_args[prog_nargs + 1] = NULL;
}

static const char* s_strrstr(const char* haystack, const char* needle)
{
    if (*needle == '\0')
    {
        return haystack;
    }

    const char* result = NULL;
    for (;;)
    {
        char* p = strstr(haystack, needle);
        if (p == NULL)
        {
            break;
        }
        result = p;
        haystack = p + 1;
    }

    return result;
}

static void s_setup_cmdline_socks5_addr(const char* value)
{
    free(G->socks5_addr);
    if ((G->socks5_addr = strdup(value)) == NULL)
    {
        LOG_F_ABORT("%s", strerror(ENOMEM));
    }
    G->socks5_port = NT_DEFAULT_SOCKS5_PORT;
}

static void s_setup_cmdline_socks5(const char* value)
{
    const char* pos = s_strrstr(value, ":");

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
        free(G->socks5_addr);
        if ((G->socks5_addr = strdup(NT_DEFAULT_SOCKS5_ADDR)) == NULL)
        {
            LOG_F_ABORT("%s", strerror(ENOMEM));
        }
        goto PARSER_PORT;
    }
    /* Check if it is a IPv6 address. */
    if (pos[-1] == ':')
    {
        s_setup_cmdline_socks5_addr(value);
        return;
    }

    size_t addrlen = pos - value;
    free(G->socks5_addr);
    if ((G->socks5_addr = malloc(addrlen + 1)) == NULL)
    {
        LOG_F_ABORT("%s", strerror(ENOMEM));
    }
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
        if ((G->socks5_addr = strdup(NT_DEFAULT_SOCKS5_ADDR)) == NULL)
        {
            LOG_F_ABORT("%s", strerror(ENOMEM));
        }
        G->socks5_port = NT_DEFAULT_SOCKS5_PORT;
    }
}

static int do_child()
{
    int code = 0;

    /* Close the read end of the pipe. s*/
    close(G->prog_pipe[0]);
    G->prog_pipe[0] = -1;

    /* Setup trace. */
    if (ptrace(PTRACE_TRACEME, 0, NULL, NULL) < 0)
    {
        code = errno;
        write(G->prog_pipe[1], &code, sizeof(code));
    }

    /*
     * Execute program.
     * exec*() does two thing when success:
     * 1. Stop and raise `SIGTRAP` to parent.
     * 2. Close pipe.
     */
    if (execvp(G->prog_args[0], G->prog_args) < 0)
    {
        code = errno;
        write(G->prog_pipe[1], &code, sizeof(code));
    }

    return EXIT_FAILURE;
}

static void s_trace_setup(prog_node_t* info)
{
    info->flag_setup = 1;

    /* Ask to trace fork() family, so we can keep eye on grandchild. */
    int trace_option = PTRACE_O_TRACECLONE | PTRACE_O_TRACEEXEC | PTRACE_O_TRACEFORK | PTRACE_O_TRACEVFORK;
    if (ptrace(PTRACE_SETOPTIONS, info->pid, 0, trace_option) < 0)
    {
        LOG_F_ABORT("ptrace() failed: (%d) %s.", errno, strerror(errno));
    }
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

static void s_check_child_exit_reason(void)
{
    int     code = 0;
    ssize_t read_sz = 0;
    do
    {
        read_sz = read(G->prog_pipe[0], &code, sizeof(code));
    } while (read_sz < 0 && errno == EINTR);

    /* There are error from child process, probably because invalid program path. */
    if (read_sz > 0)
    {
        LOG_E("Child process raise error: (%d) %s.", code, strerror(code));
        exit(EXIT_FAILURE);
    }

    /* There are error from pipe. */
    if (read_sz < 0)
    {
        LOG_F_ABORT("Pipe error: (%d) %s.", errno, strerror(errno));
    }

    /* Pipe closed, child exec() success. */
}

static void s_trace_syscall_socket_enter(prog_node_t* prog)
{
    sock_node_t* sock = calloc(1, sizeof(sock_node_t));
    sock->fd = -1;
    sock->domain = nt_get_syscall_arg(prog->pid, 0);
    sock->type = nt_get_syscall_arg(prog->pid, 1);

    if (ev_map_insert(&prog->sock_map, &sock->node) != NULL)
    {
        LOG_F_ABORT("Conflict node: pid=%d, fd=%d.", prog->pid, sock->fd);
    }
    prog->sock_last = sock;
}

static void s_trace_syscall_socket_leave(prog_node_t* prog)
{
    sock_node_t* sock = prog->sock_last;
    prog->sock_last = NULL;

    /* Update fd. */
    ev_map_erase(&prog->sock_map, &sock->node);
    {
        sock->fd = nt_get_syscall_ret(prog->pid);
    }
    if (ev_map_insert(&prog->sock_map, &sock->node) != NULL)
    {
        LOG_F_ABORT("Conflict node: pid=%d, fd=%d.", prog->pid, sock->fd);
    }

    LOG_D("socket=%d", sock->fd);
}

static void s_trace_syscall_close_enter(prog_node_t* prog)
{
    sock_node_t tmp;
    tmp.fd = nt_get_syscall_arg(prog->pid, 0);
    ev_map_node_t* it = ev_map_find(&prog->sock_map, &tmp.node);
    if (it == NULL)
    {
        return;
    }

    sock_node_t* sock = container_of(it, sock_node_t, node);
    LOG_D("close=%d", sock->fd);

    ev_map_erase(&prog->sock_map, &sock->node);
    free(sock);
}

static void s_trace_syscall(prog_node_t* info)
{
    if (!info->flag_syscall_enter)
    {
        info->flag_syscall_enter = 1;

        info->syscall = nt_get_syscall_id(info->pid);
        switch (info->syscall)
        {
            // clang-format off
#define EXPAND_SYSCALL(ID, ENTER, _) case ID: ENTER(info); break;
        SYSCALL_TRACING_TABLE(EXPAND_SYSCALL)
#undef EXPAND_SYSCALL
            // clang-format ons
        default:
        }
    }
    else
    {
        info->flag_syscall_enter = 0;

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
    prog_node_t* info = calloc(1, sizeof(prog_node_t));
    if (info == NULL)
    {
        LOG_F_ABORT("%s", strerror(ENOMEM));
    }
    info->pid = pid;
    ev_map_init(&info->sock_map, s_on_cmp_sock, NULL);

    ev_map_insert(&G->prog_map, &info->node);
    return info;
}

static void do_trace()
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

        if (WIFEXITED(status) || WIFSIGNALED(status) || !WIFSTOPPED(status))
        {
            if (pid == G->prog_pid)
            {
                s_check_child_exit_reason();
            }

            ev_map_erase(&G->prog_map, &info->node);
            free(info);
            LOG_D("PID=%d exit", pid);
            continue;
        }

        int sig = WSTOPSIG(status);
        if (sig == SIGTRAP)
        {
            if (!info->flag_setup)
            {
                s_trace_setup(info);
            }
            else
            {
                s_trace_syscall(info);
            }
            sig = 0;
        }
        if (ptrace(PTRACE_SYSCALL, pid, 0, sig) < 0)
        {
            LOG_F_ABORT("ptrace() failed: (%d) %s.", errno, strerror(errno));
        }
    }
}

static void s_init_net_service(void)
{
    if ((G->tcp_listen_fd = socket(AF_INET, SOCK_STREAM, 0)) < 0)
    {
        LOG_F_ABORT("socket() failed: (%d) %s.", errno, strerror(errno));
    }
    if ((G->udp_listen_fd = socket(AF_INET, SOCK_DGRAM, 0)) < 0)
    {
        LOG_F_ABORT("socket() failed: (%d) %s.", errno, strerror(errno));
    }

    /* Bind to random port. */
    G->listen_addr.sin_family = AF_INET;
    G->listen_addr.sin_port = htons(0);
    inet_pton(AF_INET, "127.0.0.1", &G->listen_addr.sin_addr);
    if (bind(G->tcp_listen_fd, (struct sockaddr*)&G->listen_addr, sizeof(G->listen_addr)) < 0)
    {
        LOG_F_ABORT("bind() failed: (%d) %s.", errno, strerror(errno));
    }

    /* Get actual bind address. */
    socklen_t addrlen = sizeof(G->listen_addr);
    if (getsockname(G->tcp_listen_fd, (struct sockaddr*)&G->listen_addr, &addrlen) < 0)
    {
        LOG_F_ABORT("getsockname() failed: (%d) %s.", errno, strerror(errno));
    }

    /* Bind udp to same port. */
    if (bind(G->udp_listen_fd, (struct sockaddr*)&G->listen_addr, sizeof(G->listen_addr)) < 0)
    {
        LOG_F_ABORT("bind() failed: (%d) %s.", errno, strerror(errno));
    }

    LOG_I("mix port %d.", ntohs(G->listen_addr.sin_port));
}

static int do_parent(void)
{
    /* Close the write end of the pipe. */
    close(G->prog_pipe[1]);
    G->prog_pipe[1] = -1;

    s_init_net_service();

    /* Trace child. */
    do_trace();
    return 0;
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

int main(int argc, char* argv[])
{
    /* Register global cleanup hook */
    atexit(_at_exit);

    /* Initialize global runtime. */
    if ((G = calloc(1, sizeof(*G))) == NULL)
    {
        LOG_F_ABORT("%s", strerror(ENOMEM));
    }
    G->tcp_listen_fd = -1;
    G->udp_listen_fd = -1;
    G->prog_pid = -1;
    G->prog_pipe[0] = -1;
    G->prog_pipe[1] = -1;
    ev_map_init(&G->prog_map, s_on_cmp_prog, NULL);
    s_setup_cmdline(argc, argv);

    /* Setup pipe between parent and child, to see if there are any error before executing program. */
    if (pipe2(G->prog_pipe, O_CLOEXEC) < 0)
    {
        LOG_F_ABORT("pipe2() failed: (%d) %s.", errno, strerror(errno));
    }

    if ((G->prog_pid = fork()) < 0)
    {
        int code = errno;
        LOG_F_ABORT("fork() failed: (%d) %s.", code, strerror(code));
    }
    if (G->prog_pid == 0)
    {
        return do_child();
    }

    /* Save record */
    s_prog_node_save(G->prog_pid);

    return do_parent();
}
