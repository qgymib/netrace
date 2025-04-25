#include <assert.h>
#include <ctype.h>
#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <inttypes.h>
#include <sys/syscall.h>
#include "utils/defs.h"
#include "utils/str.h"
#include "__init__.h"

typedef struct syscall_entry
{
    int                  id;        /* System call ID. */
    const char*          name;      /* Syscall name. */
    nt_syscall_decode_fn decode_fn; /* Decode function. */
} syscall_entry_t;

/**
 * @brief System call entry list. In ascii order.
 * Syscall is not portable, so it is necessary to check if it is defined.
 */
static syscall_entry_t s_syscall_entry[] = {
    { SYS_accept,            "accept",            nt_syscall_decode_accept      },
    { SYS_accept4,           "accept4",           nt_syscall_decode_accept4     },
#if defined(SYS_access)
    { SYS_access,            "access",            NULL                          },
#endif
#if defined(SYS_arch_prctl)
    { SYS_arch_prctl,        "arch_prctl",        NULL                          },
#endif
    { SYS_bind,              "bind",              nt_syscall_decode_bind        },
    { SYS_brk,               "brk",               NULL                          },
    { SYS_chdir,             "chdir",             NULL                          },
#if defined(SYS_chmod)
    { SYS_chmod,             "chmod",             NULL                          },
#endif
    { SYS_clone,             "clone",             nt_syscall_decode_clone       },
    { SYS_clone3,            "clone3",            nt_syscall_decode_clone       },
    { SYS_close,             "close",             nt_syscall_decode_close       },
    { SYS_close_range,       "close_range",       nt_syscall_decode_close_range },
    { SYS_connect,           "connect",           nt_syscall_decode_connect     },
    { SYS_dup,               "dup",               nt_syscall_decode_dup         },
#if defined(SYS_dup2)
    { SYS_dup2,              "dup2",              nt_syscall_decode_dup2        },
#endif
    { SYS_dup3,              "dup3",              nt_syscall_decode_dup3        },
    { SYS_epoll_create1,     "epoll_create1",     NULL                          },
    { SYS_epoll_ctl,         "epoll_ctl",         NULL                          },
    { SYS_epoll_pwait,       "epoll_pwait",       NULL                          },
#if defined(SYS_epoll_wait)
    { SYS_epoll_wait,        "epoll_wait",        NULL                          },
#endif
    { SYS_eventfd2,          "eventfd2",          NULL                          },
    { SYS_exit_group,        "exit_group",        NULL                          },
    { SYS_execve,            "execve",            nt_syscall_decode_execve      },
    { SYS_faccessat,         "faccessat",         NULL                          },
    { SYS_fchmodat,          "fchmodat",          NULL                          },
    { SYS_fcntl,             "fcntl",             nt_syscall_decode_fcntl       },
    { SYS_fstat,             "fstat",             NULL                          },
    { SYS_fsync,             "fsync",             NULL                          },
    { SYS_futex,             "futex",             NULL                          },
    { SYS_getcwd,            "getcwd",            NULL                          },
    { SYS_getdents64,        "getdents64",        NULL                          },
    { SYS_getpeername,       "getpeername",       nt_syscall_decode_getpeername },
    { SYS_getpid,            "getpid",            nt_syscall_decode_getpid      },
    { SYS_getpgid,           "getpgid",           NULL                          },
    { SYS_getppid,           "getppid",           nt_syscall_decode_getpid      },
    { SYS_getrandom,         "getrandom",         NULL                          },
    { SYS_getsockname,       "getsockname",       nt_syscall_decode_getsockname },
    { SYS_getsockopt,        "getsockopt",        NULL                          },
    { SYS_getuid,            "getuid",            nt_syscall_decode_getuid      },
    { SYS_ioctl,             "ioctl",             nt_syscall_decode_ioctl       },
#if defined(SYS_link)
    { SYS_link,              "link",              NULL                          },
#endif
    { SYS_listen,            "listen",            nt_syscall_decode_listen      },
    { SYS_lseek,             "lseek",             NULL                          },
#if defined(SYS_lstat)
    { SYS_lstat,             "lstat",             NULL                          },
#endif
    { SYS_madvise,           "madvise",           NULL                          },
#if defined(SYS_mkdir)
    { SYS_mkdir,             "mkdir",             NULL                          },
#endif
    { SYS_mkdirat,           "mkdirat",           NULL                          },
    { SYS_mmap,              "mmap",              NULL                          },
    { SYS_mprotect,          "mprotect",          NULL                          },
    { SYS_munmap,            "munmap",            NULL                          },
    { SYS_newfstatat,        "newfstatat",        NULL                          },
#if defined(SYS_open)
    { SYS_open,              "open",              NULL                          },
#endif
    { SYS_openat,            "openat",            NULL                          },
    { SYS_pipe2,             "pipe2",             nt_syscall_decode_pipe2       },
#if defined(SYS_poll)
    { SYS_poll,              "poll",              NULL                          },
#endif
    { SYS_ppoll,             "ppoll",             NULL                          },
    { SYS_pread64,           "pread64",           nt_syscall_decode_pread64     },
    { SYS_prctl,             "prctl",             NULL                          },
    { SYS_prlimit64,         "prlimit64",         NULL                          },
    { SYS_pselect6,          "pselect6",          NULL                          },
    { SYS_pwrite64,          "pwrite64",          nt_syscall_decode_pwrite64    },
    { SYS_read,              "read",              nt_syscall_decode_read        },
#if defined(SYS_readlink)
    { SYS_readlink,          "readlink",          NULL                          },
#endif
    { SYS_readlinkat,        "readlinkat",        NULL                          },
#if defined(SYS_recv)
    { SYS_recv,              "recv",              NULL                          },
#endif
    { SYS_recvfrom,          "recvfrom",          nt_syscall_decode_recvfrom    },
#if defined(SYS_rename)
    { SYS_rename,            "rename",            NULL                          },
#endif
#if defined(SYS_rmdir)
    { SYS_rmdir,             "rmdir",             NULL                          },
#endif
    { SYS_rseq,              "rseq",              NULL                          },
    { SYS_rt_sigaction,      "rt_sigaction",      NULL                          },
    { SYS_rt_sigprocmask,    "rt_sigprocmask",    NULL                          },
    { SYS_sched_getaffinity, "sched_getaffinity", NULL                          },
#if defined(SYS_send)
    { SYS_send,              "send",              NULL                          },
#endif
    { SYS_sendmmsg,          "sendmmsg",          nt_syscall_decode_sendmmsg    },
    { SYS_sendmsg,           "sendmsg",           NULL                          },
    { SYS_sendto,            "sendto",            nt_syscall_decode_sendto      },
    { SYS_set_robust_list,   "set_robust_list",   NULL                          },
    { SYS_set_tid_address,   "set_tid_address",   NULL                          },
    { SYS_setsockopt,        "setsockopt",        nt_syscall_decode_setsockopt  },
    { SYS_setitimer,         "setitimer",         NULL                          },
    { SYS_shutdown,          "shutdown",          nt_syscall_decode_shutdown    },
    { SYS_sigaltstack,       "sigaltstack",       NULL                          },
    { SYS_socket,            "socket",            nt_syscall_decode_socket      },
    { SYS_socketpair,        "socketpair",        nt_syscall_decode_socketpair  },
#if defined(SYS_stat)
    { SYS_stat,              "stat",              NULL                          },
#endif
    { SYS_statfs,            "statfs",            NULL                          },
#if defined(SYS_symlink)
    { SYS_symlink,           "symlink",           NULL                          },
#endif
    { SYS_symlinkat,         "symlinkat",         NULL                          },
    { SYS_umask,             "umask",             NULL                          },
    { SYS_uname,             "uname",             NULL                          },
#if defined(SYS_unlink)
    { SYS_unlink,            "unlink",            NULL                          },
#endif
    { SYS_unlinkat,          "unlinkat",          NULL                          },
    { SYS_wait4,             "wait4",             NULL                          },
    { SYS_write,             "write",             nt_syscall_decode_write       },
};

static const char* s_escape(int c)
{
    switch (c)
    {
    case ' ':
        return " ";
    case '\n':
        return "\\n";
    case '\t':
        return "\\t";
    case '\r':
        return "\\r";
    case '\v':
        return "\\v";
    case '\f':
        return "\\f";
    case '\\':
        return "\\\\";
    default:
        break;
    }
    return NULL;
}

/**
 * @brief Get entry of syscall.
 * @param[in] id System call ID.
 * @return Entry.
 */
const syscall_entry_t* s_nt_syscall_entry(int id)
{
    size_t i;
    for (i = 0; i < ARRAY_SIZE(s_syscall_entry); i++)
    {
        if (s_syscall_entry[i].id == id)
        {
            return &s_syscall_entry[i];
        }
    }

    return NULL;
}

int nt_trace_dump(const nt_syscall_info_t* si, int op, char* buff, size_t size)
{
    int         ret;
    nt_strcat_t sc = NT_STRCAT_INIT(buff, size);

    const syscall_entry_t* entry = s_nt_syscall_entry(si->enter.entry.nr);
    if (entry == NULL)
    {
        if (op == PTRACE_SYSCALL_INFO_ENTRY)
        {
            nt_strcat(&sc, "(%d)", (int)si->enter.entry.nr);
        }
        goto FINISH;
    }

    /* Append name. */
    if (op == PTRACE_SYSCALL_INFO_ENTRY)
    {
        nt_strcat(&sc, "%s", entry->name);
    }

    if (entry->decode_fn == NULL)
    {
        if (op == PTRACE_SYSCALL_INFO_ENTRY)
        {
            nt_strcat(&sc, "()");
        }
        goto FINISH;
    }

    size_t left_sz = size - sc.size;
    if ((ret = entry->decode_fn(si, op, buff + sc.size, left_sz)) >= 0)
    {
        sc.size += (ret >= (int)left_sz) ? (left_sz - 1) : (size_t)ret;
    }

FINISH:
    if (sc.size >= size)
    {
        memcpy(buff + size - 4, "...", 4);
    }
    return sc.size;
}

const char* nt_syscall_name(int id)
{
    const syscall_entry_t* entry = s_nt_syscall_entry(id);
    return entry != NULL ? entry->name : "";
}

int nt_strcat(nt_strcat_t* s, const char* fmt, ...)
{
    char*  buff = s->buff + s->size;
    size_t size = s->capacity - s->size;

    va_list ap;
    va_start(ap, fmt);
    int ret = vsnprintf(buff, size, fmt, ap);
    va_end(ap);

    int write_sz = NT_MIN((int)size, ret);
    s->size += write_sz;
    return write_sz;
}

void nt_strcat_dump(nt_strcat_t* sc, void* buff, size_t size)
{
    size_t         i;
    unsigned char* addr = (unsigned char*)buff;

    nt_strcat(sc, "\"");
    for (i = 0; i < size; i++)
    {
        unsigned char c = addr[i];
        const char*   e = s_escape(c);
        if (e != NULL)
        {
            nt_strcat(sc, "%s", e);
        }
        else if (isprint(c))
        {
            nt_strcat(sc, "%c", c);
        }
        else
        {
            nt_strcat(sc, "\\x%02x", c);
        }
    }
    nt_strcat(sc, "\"");
}

void nt_strcat_ret(nt_strcat_t* sc, int64_t ret, int err)
{
    if (!err)
    {
        goto APPEND_CODE;
    }

    int         errcode = -ret;
    const char* s_err = nt_strerrorname(errcode);
    if (s_err == NULL)
    {
        goto APPEND_CODE;
    }

    nt_strcat(sc, "-%s (%s)", s_err, strerror(errcode));
    return;

APPEND_CODE:
    nt_strcat(sc, "%" PRId64, ret);
}
