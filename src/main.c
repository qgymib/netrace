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
    xx(SYS_socket,  SYSCALL_SKIP,                   SYSCALL_SKIP)                   \
    xx(SYS_close,   SYSCALL_SKIP,                   SYSCALL_SKIP)                   \
    xx(SYS_connect, SYSCALL_SKIP,                   SYSCALL_SKIP)                   \
    xx(SYS_clone,   SYSCALL_SKIP,                   SYSCALL_SKIP)
// clang-format on

typedef struct prog_info
{
    ev_map_node_t node;
    pid_t         pid;
    int           syscall;
    int           flag_setup : 1;
    int           flag_syscall_enter : 1;
} prog_info_t;

typedef struct runtime
{
    char*    socks5_addr; /* Socks5 address. */
    unsigned socks5_port; /* Socks5 port. */

    char**   prog_args;    /* Arguments for child program, ending with NULL. */
    pid_t    prog_pid;     /* First child pid. */
    int      prog_pipe[2]; /* [0] for read, [1] for write. */
    ev_map_t prog_map;
} runtime_t;

extern char** environ;

/**
 * @brief Global runtime.
 */
static runtime_t* _G = NULL;

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

static void _at_exit(void)
{
    if (_G == NULL)
    {
        return;
    }

    ev_map_node_t* it = ev_map_begin(&_G->prog_map);
    while (it != NULL)
    {
        prog_info_t* info = container_of(it, prog_info_t, node);
        it = ev_map_next(it);
        free(info);
    }
    if (_G->prog_args != NULL)
    {
        size_t i;
        for (i = 0; _G->prog_args[i] != NULL; i++)
        {
            free(_G->prog_args[i]);
            _G->prog_args[i] = NULL;
        }
        free(_G->prog_args);
        _G->prog_args = NULL;
    }
    if (_G->socks5_addr != NULL)
    {
        free(_G->socks5_addr);
        _G->socks5_addr = NULL;
    }
    if (_G->prog_pipe[0] >= 0)
    {
        close(_G->prog_pipe[0]);
        _G->prog_pipe[0] = -1;
    }
    if (_G->prog_pipe[1] >= 0)
    {
        close(_G->prog_pipe[1]);
        _G->prog_pipe[1] = -1;
    }

    free(_G);
    _G = NULL;
}

static void s_setup_cmdline_append_prog_args(const char* arg)
{
    /* The first argument. */
    if (_G->prog_args == NULL)
    {
        if ((_G->prog_args = (char**)malloc(sizeof(char*) * 2)) == NULL)
        {
            LOG_F_ABORT("%s", strerror(ENOMEM));
        }
        if ((_G->prog_args[0] = strdup(arg)) == NULL)
        {
            LOG_F_ABORT("%s", strerror(ENOMEM));
        }
        _G->prog_args[1] = NULL;
        return;
    }

    /* More arguments. */
    size_t prog_nargs = 0;
    while (_G->prog_args[prog_nargs] != NULL)
    {
        prog_nargs++;
    }
    char** new_args = realloc(_G->prog_args, sizeof(char*) * (prog_nargs + 2));
    if (new_args == NULL)
    {
        LOG_F_ABORT("%s", strerror(ENOMEM));
    }
    _G->prog_args = new_args;
    if ((_G->prog_args[prog_nargs] = strdup(arg)) == NULL)
    {
        LOG_F_ABORT("%s", strerror(ENOMEM));
    }
    _G->prog_args[prog_nargs + 1] = NULL;
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
    free(_G->socks5_addr);
    if ((_G->socks5_addr = strdup(value)) == NULL)
    {
        LOG_F_ABORT("%s", strerror(ENOMEM));
    }
    _G->socks5_port = NT_DEFAULT_SOCKS5_PORT;
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
        free(_G->socks5_addr);
        if ((_G->socks5_addr = strdup(NT_DEFAULT_SOCKS5_ADDR)) == NULL)
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
    free(_G->socks5_addr);
    if ((_G->socks5_addr = malloc(addrlen + 1)) == NULL)
    {
        LOG_F_ABORT("%s", strerror(ENOMEM));
    }
    memcpy(_G->socks5_addr, value, addrlen);
    _G->socks5_addr[addrlen] = '\0';

PARSER_PORT:
    if (sscanf(pos + 1, "%u", &_G->socks5_port) != 1)
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

    if (_G->prog_args == NULL)
    {
        LOG_E("Missing program path");
        exit(EXIT_FAILURE);
    }
    if (_G->socks5_addr == NULL)
    {
        if ((_G->socks5_addr = strdup(NT_DEFAULT_SOCKS5_ADDR)) == NULL)
        {
            LOG_F_ABORT("%s", strerror(ENOMEM));
        }
        _G->socks5_port = NT_DEFAULT_SOCKS5_PORT;
    }
}

static int do_child()
{
    int code = 0;

    /* Close the read end of the pipe. s*/
    close(_G->prog_pipe[0]);
    _G->prog_pipe[0] = -1;

    /* Setup trace. */
    if (ptrace(PTRACE_TRACEME, 0, NULL, NULL) < 0)
    {
        code = errno;
        write(_G->prog_pipe[1], &code, sizeof(code));
    }

    /*
     * Execute program.
     * exec*() does two thing when success:
     * 1. Stop and raise `SIGTRAP` to parent.
     * 2. Close pipe.
     */
    if (execvp(_G->prog_args[0], _G->prog_args) < 0)
    {
        code = errno;
        write(_G->prog_pipe[1], &code, sizeof(code));
    }

    return EXIT_FAILURE;
}

static void s_trace_setup(prog_info_t* info)
{
    info->flag_setup = 1;

    /* Ask to trace fork() family, so we can keep eye on grandchild. */
    int trace_option = PTRACE_O_TRACECLONE | PTRACE_O_TRACEEXEC | PTRACE_O_TRACEFORK | PTRACE_O_TRACEVFORK;
    if (ptrace(PTRACE_SETOPTIONS, info->pid, 0, trace_option) < 0)
    {
        LOG_F_ABORT("ptrace() failed: (%d) %s.", errno, strerror(errno));
    }
}

static prog_info_t* s_find_proc(pid_t pid)
{
    prog_info_t tmp;
    tmp.pid = pid;
    ev_map_node_t* it = ev_map_find(&_G->prog_map, &tmp.node);
    if (it == NULL)
    {
        return NULL;
    }
    return container_of(it, prog_info_t, node);
}

static void s_check_child_exit_reason(void)
{
    int     code = 0;
    ssize_t read_sz = 0;
    do
    {
        read_sz = read(_G->prog_pipe[0], &code, sizeof(code));
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

    /* Pipe closed, child exec success. */
}

static void s_trace_syscall(prog_info_t* info)
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

static void do_trace()
{
    while (ev_map_size(&_G->prog_map) != 0)
    {
        int   status = 0;
        pid_t pid = wait(&status);
        if (pid < 0)
        {
            break;
        }

        prog_info_t* info = s_find_proc(pid);
        if (info == NULL)
        { /* New grandchild incoming. */
            info = calloc(1, sizeof(*info));
            info->pid = pid;
            ev_map_insert(&_G->prog_map, &info->node);
        }

        if (WIFEXITED(status) || WIFSIGNALED(status) || !WIFSTOPPED(status))
        {
            if (pid == _G->prog_pid)
            {
                s_check_child_exit_reason();
            }

            ev_map_erase(&_G->prog_map, &info->node);
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

static int do_parent()
{
    /* Close the write end of the pipe. */
    close(_G->prog_pipe[1]);
    _G->prog_pipe[1] = -1;

    /* Trace child. */
    do_trace();
    return 0;
}

static int s_on_cmp_map(const ev_map_node_t* key1, const ev_map_node_t* key2, void* arg)
{
    (void)arg;
    const prog_info_t* info1 = container_of(key1, prog_info_t, node);
    const prog_info_t* info2 = container_of(key2, prog_info_t, node);
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
    if ((_G = calloc(1, sizeof(*_G))) == NULL)
    {
        LOG_F_ABORT("%s", strerror(ENOMEM));
    }
    _G->prog_pid = -1;
    _G->prog_pipe[0] = -1;
    _G->prog_pipe[1] = -1;
    ev_map_init(&_G->prog_map, s_on_cmp_map, NULL);
    s_setup_cmdline(argc, argv);

    /* Setup pipe between parent and child, to see if there are any error before executing program. */
    if (pipe2(_G->prog_pipe, O_CLOEXEC) < 0)
    {
        LOG_F_ABORT("pipe2() failed: (%d) %s.", errno, strerror(errno));
    }

    if ((_G->prog_pid = fork()) < 0)
    {
        int code = errno;
        LOG_F_ABORT("fork() failed: (%d) %s.", code, strerror(code));
    }
    if (_G->prog_pid == 0)
    {
        return do_child();
    }

    /* Save record */
    prog_info_t* info = calloc(1, sizeof(prog_info_t));
    if (info == NULL)
    {
        LOG_F_ABORT("%s", strerror(ENOMEM));
    }
    info->pid = _G->prog_pid;
    ev_map_insert(&_G->prog_map, &info->node);

    return do_parent();
}
