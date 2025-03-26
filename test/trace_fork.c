#undef NDEBUG
#include <errno.h>
#include <assert.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stddef.h>
#include <arpa/inet.h>
#include <sys/wait.h>
#include <sys/ptrace.h>
#include <sys/socket.h>
#include <sys/user.h>
#include <sys/syscall.h>

#define ARRAY_SIZE(x) (sizeof(x) / sizeof(x[0]))

// clang-format off
#define ASSERT_EQ(x, y, fmt, ...)     \
    do {\
        int _x = (x);\
        int _y = (y);\
        if (_x == _y) {\
            break;\
        }\
        fprintf(stderr, "%s:%d: %s: Assertion `%s == %s` failed: " fmt ".\n",\
            __FILE__, __LINE__, __FUNCTION__, #x, #y, ##__VA_ARGS__);\
        abort();\
    } while (0)
// clang-format on

typedef struct prog_info
{
    pid_t pid;
    int   is_tracing;
    int   in_syscall;
    int   syscall_id;
} prog_info_t;

static void setup_trace(prog_info_t* info)
{
    long trace_option = PTRACE_O_TRACECLONE | PTRACE_O_TRACEEXEC | PTRACE_O_TRACEFORK | PTRACE_O_TRACEVFORK;
    assert(ptrace(PTRACE_SETOPTIONS, info->pid, 0, trace_option) == 0);
    info->is_tracing = 1;
}

static long get_syscall_ret(pid_t pid)
{
    int offset = offsetof(struct user, regs.rax);

    errno = 0;
    long retval = ptrace(PTRACE_PEEKUSER, pid, offset, NULL);
    assert(errno == 0);
    return retval;
}

static long get_syscall_id(pid_t pid)
{
    int offset = offsetof(struct user, regs.orig_rax);

    errno = 0;
    long val = ptrace(PTRACE_PEEKUSER, pid, offset, NULL);
    assert(errno == 0);

    return val;
}

static prog_info_t* find_prog(prog_info_t* l, size_t n, pid_t p)
{
    size_t i;
    for (i = 0; i < n; i++)
    {
        if (l[i].pid == p)
        {
            return &l[i];
        }
    }
    for (i = 0; i < n; i++)
    {
        if (l[i].pid < 0)
        {
            l[i].pid = p;
            l[i].is_tracing = 0;
            l[i].in_syscall = 0;
            printf("tracing new pid=%d.\n", p);
            return &l[i];
        }
    }
    abort();
}

static void handle_syscall(prog_info_t* info)
{
    if (!info->in_syscall)
    {
        info->in_syscall = 1;
        info->syscall_id = get_syscall_id(info->pid);
        if (info->syscall_id == SYS_clone)
        {
            info->in_syscall = 0;
        }
    }
    else
    {
        info->in_syscall = 0;

        int syscall_id = get_syscall_id(info->pid);
        ASSERT_EQ(syscall_id, info->syscall_id, "pid=%d pre=%d vs now=%d", info->pid, info->syscall_id, syscall_id);

        if (info->syscall_id == SYS_socket)
        {
            static unsigned cnt = 1;
            printf("SYS_socket count=%u pid=%d.\n", cnt++, info->pid);

            long v = get_syscall_ret(info->pid);
            if (v < 0)
            {
                fprintf(stderr, "tracee pid=%d socket()=%ld.\n", info->pid, v);
#if 1
                abort();
#endif
            }
        }
    }
}

static void do_tracing(pid_t prog_pid)
{
    int         child_running = 1;
    prog_info_t pid_infos[3] = {
        { -1, 0, 0, 0 },
        { -1, 0, 0, 0 },
        { -1, 0, 0, 0 },
    };

    while (child_running)
    {
        int          wstatus;
        pid_t        pid = wait(&wstatus);
        prog_info_t* info = find_prog(pid_infos, ARRAY_SIZE(pid_infos), pid);
        if (WIFSTOPPED(wstatus))
        {
            int sig = WSTOPSIG(wstatus);
            if (sig == SIGTRAP)
            {
                if (!info->is_tracing)
                {
                    setup_trace(info);
                }
                else
                {
                    handle_syscall(info);
                }
                sig = 0;
            }
            else if (sig == SIGSTOP)
            {
                if (!info->is_tracing)
                {
                    setup_trace(info);
                    sig = 0;
                }
            }
            assert(ptrace(PTRACE_SYSCALL, pid, 0, sig) == 0);
            continue;
        }

        if (WIFEXITED(wstatus) || WIFSIGNALED(wstatus) || WCOREDUMP(wstatus))
        {
            if (pid == prog_pid)
            {
                child_running = 0;
            }
            info->pid = -1;
        }
    }
}

static void do_tracer(void)
{
    /* Get self path. */
    static char self_path[4096];
    readlink("/proc/self/exe", self_path, sizeof(self_path));

    pid_t pid = fork();
    assert(pid >= 0);

    if (pid == 0)
    { /* For child we run outself with argument `--tracee` */
        assert(ptrace(PTRACE_TRACEME, 0, NULL, NULL) == 0);
        assert(execl(self_path, self_path, "--tracee", NULL) == 0);
        fprintf(stderr, "execl failed.\n");
        abort();
    }

    do_tracing(pid);
}

static void do_connect_and_close(struct sockaddr* addr, socklen_t size)
{
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    assert(connect(fd, addr, size) == 0);
    close(fd);
}

static void do_tracee(void)
{
    struct sockaddr_in s_addr;
    struct sockaddr*   p_addr = (struct sockaddr*)&s_addr;
    socklen_t          s_addr_sz = sizeof(s_addr);

    s_addr.sin_family = AF_INET;
    s_addr.sin_port = htons(0);
    assert(inet_pton(AF_INET, "127.0.0.1", &s_addr.sin_addr) == 1);

    /*
     * Create 1st socket to listen.
     */
    int sfd = socket(AF_INET, SOCK_STREAM, 0);
    ASSERT_EQ(bind(sfd, p_addr, s_addr_sz), 0, "(%d) %s", errno, strerror(errno));
    assert(listen(sfd, 1024) == 0);
    assert(getsockname(sfd, p_addr, &s_addr_sz) == 0);

    /*
     * Create 2nd socket to connect.
     */
    do_connect_and_close(p_addr, s_addr_sz);

    pid_t pid = fork();
    assert(pid >= 0);

    if (pid == 0)
    {
        /*
         * The 3rd socket to connect.
         */
        do_connect_and_close(p_addr, s_addr_sz);
        exit(EXIT_SUCCESS);
    }
    assert(waitpid(pid, NULL, 0) == pid);

    /*
     * @brief The 4th socket to connect.
     * This is where the problem occur. It should success (AKA. socket() success), but the traceer
     * found it return failed.
     */
    do_connect_and_close(p_addr, s_addr_sz);

    close(sfd);
}

int main(int argc, char* argv[])
{
    int i, is_tracee = 0;
    for (i = 0; i < argc; i++)
    {
        if (strcmp(argv[i], "--tracee") == 0)
        {
            is_tracee = 1;
            continue;
        }
    }

    if (is_tracee)
    {
        do_tracee();
    }
    else
    {
        do_tracer();
    }

    return 0;
}
