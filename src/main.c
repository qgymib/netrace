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
#include "runtime/__init__.h"
#include "utils/defs.h"
#include "utils/log.h"
#include "utils/socket.h"
#include "utils/syscall.h"
#include "utils/memory.h"
#include "config.h"

#define SYSCALL_SKIP(xx) ((void)(xx))

/**
 * @brief System call tracing table.
 */
// clang-format off
#define SYSCALL_TRACING_TABLE(xx)   \
    xx(SYS_socket,  s_trace_syscall_socket_enter,   s_trace_syscall_socket_leave)   \
    xx(SYS_close,   s_trace_syscall_close_enter,    SYSCALL_SKIP)                   \
    xx(SYS_connect, s_trace_syscall_connect_enter,  s_trace_syscall_connect_leave)  \
    xx(SYS_clone,   SYSCALL_SKIP,                   SYSCALL_SKIP)
// clang-format on

static int do_child()
{
    int code = 0;

    /* Close the read end of the pipe. */
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
    long trace_option = PTRACE_O_TRACECLONE | PTRACE_O_TRACEEXEC | PTRACE_O_TRACEFORK | PTRACE_O_TRACEVFORK;
    if (ptrace(PTRACE_SETOPTIONS, info->pid, 0, trace_option) < 0)
    {
        LOG_F_ABORT("ptrace() failed: (%d) %s.", errno, strerror(errno));
    }
    LOG_D("pid=%d setup ptrace.", info->pid);
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
    sock_node_t* sock = nt_calloc(1, sizeof(sock_node_t));
    sock->fd = -1;
    sock->socket_domain = nt_get_syscall_arg(prog->pid, 0);
    sock->socket_type = nt_get_syscall_arg(prog->pid, 1) & 0xFF;
    sock->socket_protocol = nt_get_syscall_arg(prog->pid, 2);

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
    if ((sock->fd = nt_get_syscall_ret(prog->pid)) < 0)
    {
        LOG_D("pid=%d ignore socket=%d domain=%d type=%d protocol=%d.", prog->pid, sock->fd, sock->socket_domain,
              sock->socket_type, sock->socket_protocol);
        nt_sock_node_release(sock);
        return;
    }

    if (ev_map_insert(&prog->sock_map, &sock->node) != NULL)
    {
        LOG_F_ABORT("Conflict node: pid=%d, fd=%d.", prog->pid, sock->fd);
    }
    LOG_D("pid=%d socket=%d domain=%d type=%d protocol=%d.", prog->pid, sock->fd, sock->socket_domain,
          sock->socket_type, sock->socket_protocol);
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
    LOG_D("pid=%d close socket=%d", prog->pid, sock->fd);
    ev_map_erase(&prog->sock_map, &sock->node);
    nt_sock_node_release(sock);
}

static void s_trace_syscall_connect_enter(prog_node_t* prog)
{
    sock_node_t tmp;
    tmp.fd = nt_get_syscall_arg(prog->pid, 0);
    ev_map_node_t* it = ev_map_find(&prog->sock_map, &tmp.node);
    if (it == NULL)
    {
        LOG_W("pid=%d cannot find fd=%d.", prog->pid, tmp.fd);
        prog->sock_last = NULL;
        return;
    }

    sock_node_t* sock = container_of(it, sock_node_t, node);
    prog->sock_last = sock;

    /* Backup connect address. */
    long p_sockaddr = nt_get_syscall_arg(prog->pid, 1);
    nt_syscall_getdata(prog->pid, p_sockaddr, &sock->orig_addr, sizeof(struct sockaddr_in));
    if (sock->orig_addr.ss_family == AF_INET6)
    {
        nt_syscall_getdata(prog->pid, p_sockaddr, &sock->orig_addr, sizeof(struct sockaddr_in6));
    }

    /* Create proxy channel. */
    if (G->proxy->channel(G->proxy, sock->socket_type, (struct sockaddr*)&sock->orig_addr, &sock->channel) != 0)
    {
        return;
    }

    /* Overwrite connect address. */
    struct sockaddr* newaddr = NULL;
    sock->channel->proxy_addr(sock->channel, &newaddr);
    if (newaddr != NULL)
    {
        size_t newaddrlen = newaddr->sa_family == AF_INET ? sizeof(struct sockaddr_in) : sizeof(struct sockaddr_in6);
        nt_syscall_setdata(prog->pid, p_sockaddr, newaddr, newaddrlen);
    }
}

static void s_trace_syscall_connect_leave(prog_node_t* prog)
{
    long p_sockaddr = nt_get_syscall_arg(prog->pid, 1);

    sock_node_t* sock = prog->sock_last;
    if (sock != NULL)
    {
        size_t data_sz =
            sock->orig_addr.ss_family == AF_INET ? sizeof(struct sockaddr_in) : sizeof(struct sockaddr_in6);
        nt_syscall_setdata(prog->pid, p_sockaddr, &sock->orig_addr, data_sz);
    }

    prog->sock_last = NULL;
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
            // clang-format on
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
    prog_node_t* info = nt_calloc(1, sizeof(prog_node_t));
    info->pid = pid;
    ev_map_init(&info->sock_map, s_on_cmp_sock, NULL);

    ev_map_insert(&G->prog_map, &info->node);
    LOG_D("Tracing new process pid=%d.", pid);
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
                if (WIFEXITED(status))
                {
                    G->prog_exit_retval = WEXITSTATUS(status);
                }
                else
                {
                    G->prog_exit_retval = EXIT_FAILURE;
                    LOG_W("`%s` exit abnormal, set our exitcode to %d.", G->prog_args[0], G->prog_exit_retval);
                }
            }

            ev_map_erase(&G->prog_map, &info->node);
            nt_prog_node_release(info);
            LOG_D("PID=%d exit.", pid);
            continue;
        }

        int sig = WSTOPSIG(status);
        if (sig == SIGTRAP)
        {
            if (!info->flag_setup)
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
            if (!info->flag_setup)
            { /* clone() / fork() / vfork() */
                s_trace_setup(info);
                sig = 0;
            }
        }
        if (ptrace(PTRACE_SYSCALL, pid, 0, sig) < 0)
        {
            LOG_F_ABORT("ptrace() failed: (%d) %s.", errno, strerror(errno));
        }
    }
}

static int do_parent(void)
{
    /* Close the write end of the pipe. */
    close(G->prog_pipe[1]);
    G->prog_pipe[1] = -1;

    /* Trace child. */
    do_trace();
    return G->prog_exit_retval;
}

static void s_at_exit(void)
{
    nt_runtime_cleanup();
}

int main(int argc, char* argv[])
{
    /* Register global cleanup hook */
    atexit(s_at_exit);

    /* Initialize global runtime. */
    nt_runtime_init(argc, argv);

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
