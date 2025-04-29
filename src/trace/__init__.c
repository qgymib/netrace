#include <assert.h>
#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
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
 * @brief Array containing system call entries with their respective identifiers, names, and
 * optional decode functions.
 *
 * This static array serves as a mapping of system call IDs to their corresponding names and decode
 * handlers, enabling syscalls to be interpreted or emulated depending on the provided decode
 * function. Compile-time conditions determine the inclusion of some entries based on their
 * availability on the target platform.
 *
 * Each entry consists of:
 * - System call identifier (`SYS_*` constant),
 * - Human-readable name of the system call,
 * - Optional function pointer for decoding the syscall.
 *
 * This array is defined in ascii order and will be resort before use.
 */
static syscall_entry_t s_syscall_entry[] = {
    { SYS_accept,                  "accept",                  nt_syscall_decode_accept      },
    { SYS_accept4,                 "accept4",                 nt_syscall_decode_accept4     },
#if defined(SYS_access)
    { SYS_access,                  "access",                  nt_syscall_decode_access      },
#endif
    { SYS_acct,                    "acct",                    NULL                          },
    { SYS_add_key,                 "add_key",                 NULL                          },
    { SYS_adjtimex,                "adjtimex",                NULL                          },
#if defined(SYS_afs_syscall)
    { SYS_afs_syscall,             "afs_syscall",             NULL                          },
#endif
#if defined(SYS_alarm)
    { SYS_alarm,                   "alarm",                   NULL                          },
#endif
#if defined(SYS_arch_prctl)
    { SYS_arch_prctl,              "arch_prctl",              NULL                          },
#endif
    { SYS_bind,                    "bind",                    nt_syscall_decode_bind        },
    { SYS_bpf,                     "bpf",                     NULL                          },
    { SYS_brk,                     "brk",                     NULL                          },
#if defined(SYS_cachestat)
    { SYS_cachestat,               "cachestat",               NULL                          },
#endif
    { SYS_capget,                  "capget",                  NULL                          },
    { SYS_capset,                  "capset",                  NULL                          },
    { SYS_chdir,                   "chdir",                   NULL                          },
#if defined(SYS_chmod)
    { SYS_chmod,                   "chmod",                   NULL                          },
#endif
#if defined(SYS_chown)
    { SYS_chown,                   "chown",                   NULL                          },
#endif
    { SYS_chroot,                  "chroot",                  NULL                          },
    { SYS_clock_adjtime,           "clock_adjtime",           NULL                          },
    { SYS_clock_getres,            "clock_getres",            NULL                          },
    { SYS_clock_gettime,           "clock_gettime",           NULL                          },
    { SYS_clock_nanosleep,         "clock_nanosleep",         NULL                          },
    { SYS_clock_settime,           "clock_settime",           NULL                          },
    { SYS_clone,                   "clone",                   nt_syscall_decode_clone       },
    { SYS_clone3,                  "clone3",                  nt_syscall_decode_clone       },
    { SYS_close,                   "close",                   nt_syscall_decode_close       },
    { SYS_close_range,             "close_range",             nt_syscall_decode_close_range },
    { SYS_connect,                 "connect",                 nt_syscall_decode_connect     },
    { SYS_copy_file_range,         "copy_file_range",         NULL                          },
#if defined(SYS_creat)
    { SYS_creat,                   "creat",                   NULL                          },
#endif
#if defined(SYS_create_module)
    { SYS_create_module,           "create_module",           NULL                          },
#endif
    { SYS_delete_module,           "delete_module",           NULL                          },
    { SYS_dup,                     "dup",                     nt_syscall_decode_dup         },
#if defined(SYS_dup2)
    { SYS_dup2,                    "dup2",                    nt_syscall_decode_dup2        },
#endif
    { SYS_dup3,                    "dup3",                    nt_syscall_decode_dup3        },
#if defined(SYS_epoll_create)
    { SYS_epoll_create,            "epoll_create",            NULL                          },
#endif
    { SYS_epoll_create1,           "epoll_create1",           NULL                          },
    { SYS_epoll_ctl,               "epoll_ctl",               NULL                          },
#if defined(SYS_epoll_ctl_old)
    { SYS_epoll_ctl_old,           "epoll_ctl_old",           NULL                          },
#endif
    { SYS_epoll_pwait,             "epoll_pwait",             NULL                          },
    { SYS_epoll_pwait2,            "epoll_pwait2",            NULL                          },
#if defined(SYS_epoll_wait)
    { SYS_epoll_wait,              "epoll_wait",              NULL                          },
#endif
#if defined(SYS_epoll_wait_old)
    { SYS_epoll_wait_old,          "epoll_wait_old",          NULL                          },
#endif
#if defined(SYS_eventfd)
    { SYS_eventfd,                 "eventfd",                 NULL                          },
#endif
    { SYS_eventfd2,                "eventfd2",                NULL                          },
    { SYS_execve,                  "execve",                  nt_syscall_decode_execve      },
    { SYS_execveat,                "execveat",                NULL                          },
    { SYS_exit,                    "exit",                    NULL                          },
    { SYS_exit_group,              "exit_group",              NULL                          },
    { SYS_faccessat,               "faccessat",               nt_syscall_decode_faccessat   },
    { SYS_faccessat2,              "faccessat2",              NULL                          },
    { SYS_fadvise64,               "fadvise64",               NULL                          },
    { SYS_fallocate,               "fallocate",               NULL                          },
    { SYS_fanotify_init,           "fanotify_init",           NULL                          },
    { SYS_fanotify_mark,           "fanotify_mark",           NULL                          },
    { SYS_fchdir,                  "fchdir",                  NULL                          },
    { SYS_fchmod,                  "fchmod",                  NULL                          },
    { SYS_fchmodat,                "fchmodat",                NULL                          },
#if defined(SYS_fchmodat2)
    { SYS_fchmodat2,               "fchmodat2",               NULL                          },
#endif
    { SYS_fchown,                  "fchown",                  NULL                          },
    { SYS_fchownat,                "fchownat",                NULL                          },
    { SYS_fcntl,                   "fcntl",                   nt_syscall_decode_fcntl       },
    { SYS_fdatasync,               "fdatasync",               NULL                          },
    { SYS_fgetxattr,               "fgetxattr",               NULL                          },
    { SYS_finit_module,            "finit_module",            NULL                          },
    { SYS_flistxattr,              "flistxattr",              NULL                          },
    { SYS_flock,                   "flock",                   NULL                          },
#if defined(SYS_fork)
    { SYS_fork,                    "fork",                    NULL                          },
#endif
    { SYS_fremovexattr,            "fremovexattr",            NULL                          },
    { SYS_fsconfig,                "fsconfig",                NULL                          },
    { SYS_fsetxattr,               "fsetxattr",               NULL                          },
    { SYS_fsmount,                 "fsmount",                 NULL                          },
    { SYS_fsopen,                  "fsopen",                  NULL                          },
    { SYS_fspick,                  "fspick",                  NULL                          },
    { SYS_fstat,                   "fstat",                   NULL                          },
    { SYS_fstatfs,                 "fstatfs",                 NULL                          },
    { SYS_fsync,                   "fsync",                   NULL                          },
    { SYS_ftruncate,               "ftruncate",               NULL                          },
    { SYS_futex,                   "futex",                   NULL                          },
#if defined(SYS_futex_requeue)
    { SYS_futex_requeue,           "futex_requeue",           NULL                          },
#endif
#if defined(SYS_futex_wait)
    { SYS_futex_wait,              "futex_wait",              NULL                          },
#endif
#if defined(SYS_futex_waitv)
    { SYS_futex_waitv,             "futex_waitv",             NULL                          },
#endif
#if defined(SYS_futex_wake)
    { SYS_futex_wake,              "futex_wake",              NULL                          },
#endif
#if defined(SYS_futimesat)
    { SYS_futimesat,               "futimesat",               NULL                          },
#endif
#if defined(SYS_get_kernel_syms)
    { SYS_get_kernel_syms,         "get_kernel_syms",         NULL                          },
#endif
    { SYS_get_mempolicy,           "get_mempolicy",           NULL                          },
    { SYS_get_robust_list,         "get_robust_list",         NULL                          },
#if defined(SYS_get_thread_area)
    { SYS_get_thread_area,         "get_thread_area",         NULL                          },
#endif
    { SYS_getcpu,                  "getcpu",                  NULL                          },
    { SYS_getcwd,                  "getcwd",                  nt_syscall_decode_getcwd      },
#if defined(SYS_getdents)
    { SYS_getdents,                "getdents",                NULL                          },
#endif
    { SYS_getdents64,              "getdents64",              NULL                          },
    { SYS_getegid,                 "getegid",                 NULL                          },
    { SYS_geteuid,                 "geteuid",                 NULL                          },
    { SYS_getgid,                  "getgid",                  NULL                          },
    { SYS_getgroups,               "getgroups",               NULL                          },
    { SYS_getitimer,               "getitimer",               NULL                          },
    { SYS_getpeername,             "getpeername",             nt_syscall_decode_getpeername },
    { SYS_getpgid,                 "getpgid",                 NULL                          },
#if defined(SYS_getpgrp)
    { SYS_getpgrp,                 "getpgrp",                 NULL                          },
#endif
    { SYS_getpid,                  "getpid",                  nt_syscall_decode_getpid      },
#if defined(SYS_getpmsg)
    { SYS_getpmsg,                 "getpmsg",                 NULL                          },
#endif
    { SYS_getppid,                 "getppid",                 nt_syscall_decode_getpid      },
    { SYS_getpriority,             "getpriority",             NULL                          },
    { SYS_getrandom,               "getrandom",               NULL                          },
    { SYS_getresgid,               "getresgid",               NULL                          },
    { SYS_getresuid,               "getresuid",               NULL                          },
    { SYS_getrlimit,               "getrlimit",               NULL                          },
    { SYS_getrusage,               "getrusage",               NULL                          },
    { SYS_getsid,                  "getsid",                  NULL                          },
    { SYS_getsockname,             "getsockname",             nt_syscall_decode_getsockname },
    { SYS_getsockopt,              "getsockopt",              NULL                          },
    { SYS_gettid,                  "gettid",                  NULL                          },
    { SYS_gettimeofday,            "gettimeofday",            NULL                          },
    { SYS_getuid,                  "getuid",                  nt_syscall_decode_getuid      },
    { SYS_getxattr,                "getxattr",                NULL                          },
    { SYS_init_module,             "init_module",             NULL                          },
    { SYS_inotify_add_watch,       "inotify_add_watch",       NULL                          },
#if defined(SYS_inotify_init)
    { SYS_inotify_init,            "inotify_init",            NULL                          },
#endif
    { SYS_inotify_rm_watch,        "inotify_rm_watch",        NULL                          },
    { SYS_io_cancel,               "io_cancel",               NULL                          },
    { SYS_io_destroy,              "io_destroy",              NULL                          },
    { SYS_io_getevents,            "io_getevents",            NULL                          },
    { SYS_io_pgetevents,           "io_pgetevents",           NULL                          },
    { SYS_io_setup,                "io_setup",                NULL                          },
    { SYS_io_submit,               "io_submit",               NULL                          },
    { SYS_io_uring_enter,          "io_uring_enter",          NULL                          },
    { SYS_io_uring_register,       "io_uring_register",       NULL                          },
    { SYS_io_uring_setup,          "io_uring_setup",          NULL                          },
    { SYS_ioctl,                   "ioctl",                   nt_syscall_decode_ioctl       },
#if defined(SYS_ioperm)
    { SYS_ioperm,                  "ioperm",                  NULL                          },
#endif
#if defined(SYS_iopl)
    { SYS_iopl,                    "iopl",                    NULL                          },
#endif
    { SYS_ioprio_get,              "ioprio_get",              NULL                          },
    { SYS_ioprio_set,              "ioprio_set",              NULL                          },
    { SYS_kcmp,                    "kcmp",                    NULL                          },
    { SYS_kexec_file_load,         "kexec_file_load",         NULL                          },
    { SYS_kexec_load,              "kexec_load",              NULL                          },
    { SYS_keyctl,                  "keyctl",                  NULL                          },
    { SYS_kill,                    "kill",                    NULL                          },
    { SYS_landlock_add_rule,       "landlock_add_rule",       NULL                          },
    { SYS_landlock_create_ruleset, "landlock_create_ruleset", NULL                          },
    { SYS_landlock_restrict_self,  "landlock_restrict_self",  NULL                          },
#if defined(SYS_lchown)
    { SYS_lchown,                  "lchown",                  NULL                          },
#endif
    { SYS_lgetxattr,               "lgetxattr",               NULL                          },
#if defined(SYS_link)
    { SYS_link,                    "link",                    NULL                          },
#endif
    { SYS_linkat,                  "linkat",                  NULL                          },
    { SYS_listen,                  "listen",                  nt_syscall_decode_listen      },
    { SYS_listxattr,               "listxattr",               NULL                          },
    { SYS_llistxattr,              "llistxattr",              NULL                          },
    { SYS_lookup_dcookie,          "lookup_dcookie",          NULL                          },
    { SYS_lremovexattr,            "lremovexattr",            NULL                          },
    { SYS_lseek,                   "lseek",                   NULL                          },
    { SYS_lsetxattr,               "lsetxattr",               NULL                          },
#if defined(SYS_lstat)
    { SYS_lstat,                   "lstat",                   NULL                          },
#endif
    { SYS_madvise,                 "madvise",                 NULL                          },
#if defined(SYS_map_shadow_stack)
    { SYS_map_shadow_stack,        "map_shadow_stack",        NULL                          },
#endif
    { SYS_mbind,                   "mbind",                   NULL                          },
    { SYS_membarrier,              "membarrier",              NULL                          },
    { SYS_memfd_create,            "memfd_create",            NULL                          },
#if defined(SYS_memfd_secret)
    { SYS_memfd_secret,            "memfd_secret",            NULL                          },
#endif
    { SYS_migrate_pages,           "migrate_pages",           NULL                          },
    { SYS_mincore,                 "mincore",                 NULL                          },
#if defined(SYS_mkdir)
    { SYS_mkdir,                   "mkdir",                   NULL                          },
#endif
    { SYS_mkdirat,                 "mkdirat",                 NULL                          },
#if defined(SYS_mknod)
    { SYS_mknod,                   "mknod",                   NULL                          },
#endif
    { SYS_mknodat,                 "mknodat",                 NULL                          },
    { SYS_mlock,                   "mlock",                   NULL                          },
    { SYS_mlock2,                  "mlock2",                  NULL                          },
    { SYS_mlockall,                "mlockall",                NULL                          },
    { SYS_mmap,                    "mmap",                    NULL                          },
#if defined(SYS_modify_ldt)
    { SYS_modify_ldt,              "modify_ldt",              NULL                          },
#endif
    { SYS_mount,                   "mount",                   NULL                          },
    { SYS_mount_setattr,           "mount_setattr",           NULL                          },
    { SYS_move_mount,              "move_mount",              NULL                          },
    { SYS_move_pages,              "move_pages",              NULL                          },
    { SYS_mprotect,                "mprotect",                NULL                          },
    { SYS_mq_getsetattr,           "mq_getsetattr",           NULL                          },
    { SYS_mq_notify,               "mq_notify",               NULL                          },
    { SYS_mq_open,                 "mq_open",                 NULL                          },
    { SYS_mq_timedreceive,         "mq_timedreceive",         NULL                          },
    { SYS_mq_timedsend,            "mq_timedsend",            NULL                          },
    { SYS_mq_unlink,               "mq_unlink",               NULL                          },
    { SYS_mremap,                  "mremap",                  NULL                          },
    { SYS_msgctl,                  "msgctl",                  NULL                          },
    { SYS_msgget,                  "msgget",                  NULL                          },
    { SYS_msgrcv,                  "msgrcv",                  NULL                          },
    { SYS_msgsnd,                  "msgsnd",                  NULL                          },
    { SYS_msync,                   "msync",                   NULL                          },
    { SYS_munlock,                 "munlock",                 NULL                          },
    { SYS_munlockall,              "munlockall",              NULL                          },
    { SYS_munmap,                  "munmap",                  NULL                          },
    { SYS_name_to_handle_at,       "name_to_handle_at",       NULL                          },
    { SYS_nanosleep,               "nanosleep",               NULL                          },
    { SYS_newfstatat,              "newfstatat",              NULL                          },
    { SYS_nfsservctl,              "nfsservctl",              NULL                          },
#if defined(SYS_open)
    { SYS_open,                    "open",                    NULL                          },
#endif
    { SYS_open_by_handle_at,       "open_by_handle_at",       NULL                          },
    { SYS_open_tree,               "open_tree",               NULL                          },
    { SYS_openat,                  "openat",                  nt_syscall_decode_openat      },
    { SYS_openat2,                 "openat2",                 NULL                          },
#if defined(SYS_pause)
    { SYS_pause,                   "pause",                   NULL                          },
#endif
    { SYS_perf_event_open,         "perf_event_open",         NULL                          },
    { SYS_personality,             "personality",             NULL                          },
    { SYS_pidfd_getfd,             "pidfd_getfd",             NULL                          },
    { SYS_pidfd_open,              "pidfd_open",              NULL                          },
    { SYS_pidfd_send_signal,       "pidfd_send_signal",       NULL                          },
#if defined(SYS_pipe)
    { SYS_pipe,                    "pipe",                    NULL                          },
#endif
    { SYS_pipe2,                   "pipe2",                   nt_syscall_decode_pipe2       },
    { SYS_pivot_root,              "pivot_root",              NULL                          },
    { SYS_pkey_alloc,              "pkey_alloc",              NULL                          },
    { SYS_pkey_free,               "pkey_free",               NULL                          },
    { SYS_pkey_mprotect,           "pkey_mprotect",           NULL                          },
#if defined(SYS_poll)
    { SYS_poll,                    "poll",                    NULL                          },
#endif
    { SYS_ppoll,                   "ppoll",                   NULL                          },
    { SYS_prctl,                   "prctl",                   NULL                          },
    { SYS_pread64,                 "pread64",                 nt_syscall_decode_pread64     },
    { SYS_preadv,                  "preadv",                  nt_syscall_decode_preadv      },
    { SYS_preadv2,                 "preadv2",                 nt_syscall_decode_preadv2     },
    { SYS_prlimit64,               "prlimit64",               NULL                          },
    { SYS_process_madvise,         "process_madvise",         NULL                          },
#if defined(SYS_process_mrelease)
    { SYS_process_mrelease,        "process_mrelease",        NULL                          },
#endif
    { SYS_process_vm_readv,        "process_vm_readv",        NULL                          },
    { SYS_process_vm_writev,       "process_vm_writev",       NULL                          },
    { SYS_pselect6,                "pselect6",                NULL                          },
    { SYS_ptrace,                  "ptrace",                  NULL                          },
#if defined(SYS_putpmsg)
    { SYS_putpmsg,                 "putpmsg",                 NULL                          },
#endif
    { SYS_pwrite64,                "pwrite64",                nt_syscall_decode_pwrite64    },
    { SYS_pwritev,                 "pwritev",                 nt_syscall_decode_pwritev     },
    { SYS_pwritev2,                "pwritev2",                nt_syscall_decode_pwritev2    },
#if defined(SYS_query_module)
    { SYS_query_module,            "query_module",            NULL                          },
#endif
    { SYS_quotactl,                "quotactl",                NULL                          },
#if defined(SYS_quotactl_fd)
    { SYS_quotactl_fd,             "quotactl_fd",             NULL                          },
#endif
    { SYS_read,                    "read",                    nt_syscall_decode_read        },
    { SYS_readahead,               "readahead",               NULL                          },
#if defined(SYS_readlink)
    { SYS_readlink,                "readlink",                NULL                          },
#endif
    { SYS_readlinkat,              "readlinkat",              NULL                          },
    { SYS_readv,                   "readv",                   nt_syscall_decode_readv       },
    { SYS_reboot,                  "reboot",                  NULL                          },
#if defined(SYS_recv)
    { SYS_recv,                    "recv",                    NULL                          },
#endif
    { SYS_recvfrom,                "recvfrom",                nt_syscall_decode_recvfrom    },
    { SYS_recvmmsg,                "recvmmsg",                NULL                          },
    { SYS_recvmsg,                 "recvmsg",                 nt_syscall_decode_recvmsg     },
    { SYS_remap_file_pages,        "remap_file_pages",        NULL                          },
    { SYS_removexattr,             "removexattr",             NULL                          },
#if defined(SYS_rename)
    { SYS_rename,                  "rename",                  NULL                          },
#endif
    { SYS_renameat,                "renameat",                NULL                          },
    { SYS_renameat2,               "renameat2",               NULL                          },
    { SYS_request_key,             "request_key",             NULL                          },
    { SYS_restart_syscall,         "restart_syscall",         NULL                          },
#if defined(SYS_rmdir)
    { SYS_rmdir,                   "rmdir",                   NULL                          },
#endif
    { SYS_rseq,                    "rseq",                    NULL                          },
    { SYS_rt_sigaction,            "rt_sigaction",            NULL                          },
    { SYS_rt_sigpending,           "rt_sigpending",           NULL                          },
    { SYS_rt_sigprocmask,          "rt_sigprocmask",          NULL                          },
    { SYS_rt_sigqueueinfo,         "rt_sigqueueinfo",         NULL                          },
    { SYS_rt_sigreturn,            "rt_sigreturn",            NULL                          },
    { SYS_rt_sigsuspend,           "rt_sigsuspend",           NULL                          },
    { SYS_rt_sigtimedwait,         "rt_sigtimedwait",         NULL                          },
    { SYS_rt_tgsigqueueinfo,       "rt_tgsigqueueinfo",       NULL                          },
    { SYS_sched_get_priority_max,  "sched_get_priority_max",  NULL                          },
    { SYS_sched_get_priority_min,  "sched_get_priority_min",  NULL                          },
    { SYS_sched_getaffinity,       "sched_getaffinity",       NULL                          },
    { SYS_sched_getattr,           "sched_getattr",           NULL                          },
    { SYS_sched_getparam,          "sched_getparam",          NULL                          },
    { SYS_sched_getscheduler,      "sched_getscheduler",      NULL                          },
    { SYS_sched_rr_get_interval,   "sched_rr_get_interval",   NULL                          },
    { SYS_sched_setaffinity,       "sched_setaffinity",       NULL                          },
    { SYS_sched_setattr,           "sched_setattr",           NULL                          },
    { SYS_sched_setparam,          "sched_setparam",          NULL                          },
    { SYS_sched_setscheduler,      "sched_setscheduler",      NULL                          },
    { SYS_sched_yield,             "sched_yield",             NULL                          },
    { SYS_seccomp,                 "seccomp",                 NULL                          },
#if defined(SYS_security)
    { SYS_security,                "security",                NULL                          },
#endif
#if defined(SYS_select)
    { SYS_select,                  "select",                  NULL                          },
#endif
    { SYS_semctl,                  "semctl",                  NULL                          },
    { SYS_semget,                  "semget",                  NULL                          },
    { SYS_semop,                   "semop",                   NULL                          },
    { SYS_semtimedop,              "semtimedop",              NULL                          },
#if defined(SYS_send)
    { SYS_send,                    "send",                    NULL                          },
#endif
    { SYS_sendfile,                "sendfile",                nt_syscall_decode_sendfile    },
    { SYS_sendmmsg,                "sendmmsg",                nt_syscall_decode_sendmmsg    },
    { SYS_sendmsg,                 "sendmsg",                 nt_syscall_decode_sendmsg     },
    { SYS_sendto,                  "sendto",                  nt_syscall_decode_sendto      },
    { SYS_set_mempolicy,           "set_mempolicy",           NULL                          },
#if defined(SYS_set_mempolicy_home_node)
    { SYS_set_mempolicy_home_node, "set_mempolicy_home_node", NULL                          },
#endif
    { SYS_set_robust_list,         "set_robust_list",         NULL                          },
#if defined(SYS_set_thread_area)
    { SYS_set_thread_area,         "set_thread_area",         NULL                          },
#endif
    { SYS_set_tid_address,         "set_tid_address",         NULL                          },
    { SYS_setdomainname,           "setdomainname",           NULL                          },
    { SYS_setfsgid,                "setfsgid",                NULL                          },
    { SYS_setfsuid,                "setfsuid",                NULL                          },
    { SYS_setgid,                  "setgid",                  NULL                          },
    { SYS_setgroups,               "setgroups",               NULL                          },
    { SYS_sethostname,             "sethostname",             NULL                          },
    { SYS_setitimer,               "setitimer",               NULL                          },
    { SYS_setns,                   "setns",                   NULL                          },
    { SYS_setpgid,                 "setpgid",                 NULL                          },
    { SYS_setpriority,             "setpriority",             NULL                          },
    { SYS_setregid,                "setregid",                NULL                          },
    { SYS_setresgid,               "setresgid",               NULL                          },
    { SYS_setresuid,               "setresuid",               NULL                          },
    { SYS_setreuid,                "setreuid",                NULL                          },
    { SYS_setrlimit,               "setrlimit",               NULL                          },
    { SYS_setsid,                  "setsid",                  NULL                          },
    { SYS_setsockopt,              "setsockopt",              nt_syscall_decode_setsockopt  },
    { SYS_settimeofday,            "settimeofday",            NULL                          },
    { SYS_setuid,                  "setuid",                  NULL                          },
    { SYS_setxattr,                "setxattr",                NULL                          },
    { SYS_shmat,                   "shmat",                   NULL                          },
    { SYS_shmctl,                  "shmctl",                  NULL                          },
    { SYS_shmdt,                   "shmdt",                   NULL                          },
    { SYS_shmget,                  "shmget",                  NULL                          },
    { SYS_shutdown,                "shutdown",                nt_syscall_decode_shutdown    },
    { SYS_sigaltstack,             "sigaltstack",             NULL                          },
#if defined(SYS_signalfd)
    { SYS_signalfd,                "signalfd",                NULL                          },
#endif
    { SYS_signalfd4,               "signalfd4",               NULL                          },
    { SYS_socket,                  "socket",                  nt_syscall_decode_socket      },
    { SYS_socketpair,              "socketpair",              nt_syscall_decode_socketpair  },
    { SYS_splice,                  "splice",                  NULL                          },
#if defined(SYS_stat)
    { SYS_stat,                    "stat",                    NULL                          },
#endif
    { SYS_statfs,                  "statfs",                  NULL                          },
    { SYS_statx,                   "statx",                   NULL                          },
    { SYS_swapoff,                 "swapoff",                 NULL                          },
    { SYS_swapon,                  "swapon",                  NULL                          },
#if defined(SYS_symlink)
    { SYS_symlink,                 "symlink",                 NULL                          },
#endif
    { SYS_symlinkat,               "symlinkat",               NULL                          },
    { SYS_sync,                    "sync",                    NULL                          },
    { SYS_sync_file_range,         "sync_file_range",         NULL                          },
    { SYS_syncfs,                  "syncfs",                  NULL                          },
#if defined(SYS_sysfs)
    { SYS_sysfs,                   "sysfs",                   NULL                          },
#endif
    { SYS_sysinfo,                 "sysinfo",                 NULL                          },
    { SYS_syslog,                  "syslog",                  NULL                          },
    { SYS_tee,                     "tee",                     NULL                          },
    { SYS_tgkill,                  "tgkill",                  NULL                          },
#if defined(SYS_time)
    { SYS_time,                    "time",                    NULL                          },
#endif
    { SYS_timer_create,            "timer_create",            NULL                          },
    { SYS_timer_delete,            "timer_delete",            NULL                          },
    { SYS_timer_getoverrun,        "timer_getoverrun",        NULL                          },
    { SYS_timer_gettime,           "timer_gettime",           NULL                          },
    { SYS_timer_settime,           "timer_settime",           NULL                          },
    { SYS_timerfd_create,          "timerfd_create",          NULL                          },
    { SYS_timerfd_gettime,         "timerfd_gettime",         NULL                          },
    { SYS_timerfd_settime,         "timerfd_settime",         NULL                          },
    { SYS_times,                   "times",                   NULL                          },
    { SYS_tkill,                   "tkill",                   NULL                          },
    { SYS_truncate,                "truncate",                NULL                          },
#if defined(SYS_tuxcall)
    { SYS_tuxcall,                 "tuxcall",                 NULL                          },
#endif
    { SYS_umask,                   "umask",                   NULL                          },
    { SYS_umount2,                 "umount2",                 NULL                          },
    { SYS_uname,                   "uname",                   NULL                          },
#if defined(SYS_unlink)
    { SYS_unlink,                  "unlink",                  NULL                          },
#endif
    { SYS_unlinkat,                "unlinkat",                NULL                          },
    { SYS_unshare,                 "unshare",                 NULL                          },
#if defined(SYS_uselib)
    { SYS_uselib,                  "uselib",                  NULL                          },
#endif
    { SYS_userfaultfd,             "userfaultfd",             NULL                          },
#if defined(SYS_ustat)
    { SYS_ustat,                   "ustat",                   NULL                          },
#endif
#if defined(SYS_utime)
    { SYS_utime,                   "utime",                   NULL                          },
#endif
    { SYS_utimensat,               "utimensat",               NULL                          },
#if defined(SYS_utimes)
    { SYS_utimes,                  "utimes",                  NULL                          },
#endif
#if defined(SYS_vfork)
    { SYS_vfork,                   "vfork",                   NULL                          },
#endif
    { SYS_vhangup,                 "vhangup",                 NULL                          },
    { SYS_vmsplice,                "vmsplice",                NULL                          },
#if defined(SYS_vserver)
    { SYS_vserver,                 "vserver",                 NULL                          },
#endif
    { SYS_wait4,                   "wait4",                   NULL                          },
    { SYS_waitid,                  "waitid",                  NULL                          },
    { SYS_write,                   "write",                   nt_syscall_decode_write       },
    { SYS_writev,                  "writev",                  nt_syscall_decode_writev      },
};

static int s_on_cmp_syscall_entry(const void* a, const void* b)
{
    const syscall_entry_t* e1 = (const syscall_entry_t*)a;
    const syscall_entry_t* e2 = (const syscall_entry_t*)b;
    if (e1->id == e2->id)
    {
        return 0;
    }
    return e1->id < e2->id ? -1 : 1;
}

static void s_trace_resort_syscall_table()
{
    qsort(s_syscall_entry, ARRAY_SIZE(s_syscall_entry), sizeof(s_syscall_entry[0]),
          s_on_cmp_syscall_entry);
}

/**
 * @brief Get entry of syscall.
 * @param[in] id System call ID.
 * @return Entry.
 */
static const syscall_entry_t* s_nt_syscall_entry(int id)
{
    syscall_entry_t tmp = { id, NULL, NULL };
    return bsearch(&tmp, s_syscall_entry, ARRAY_SIZE(s_syscall_entry), sizeof(s_syscall_entry[0]),
                   s_on_cmp_syscall_entry);
}

int nt_trace_dump(const nt_syscall_info_t* si, int op, char* buff, size_t size)
{
    /* Sort syscall table to accelerate search. */
    static pthread_once_t s_once_token = PTHREAD_ONCE_INIT;
    pthread_once(&s_once_token, s_trace_resort_syscall_table);

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
