#include <assert.h>
#include <errno.h>
#include <sys/user.h>
#include <sys/ptrace.h>
#include "utils/defs.h"
#include "syscall.h"

long nt_get_syscall_id(pid_t pid)
{
    int offset = offsetof(struct user, regs.orig_rax);

    errno = 0;
    long val = ptrace(PTRACE_PEEKUSER, pid, offset);
    assert(errno == 0);

    return val;
}

long nt_get_syscall_arg(pid_t pid, size_t idx)
{
    assert(idx <= 5);

    // clang-format off
    static int offset[] = {
        offsetof(struct user, regs.rdi),
        offsetof(struct user, regs.rsi),
        offsetof(struct user, regs.rdx),
        offsetof(struct user, regs.r10),
        offsetof(struct user, regs.r8),
        offsetof(struct user, regs.r9),
    };
    // clang-format on

    errno = 0;
    long retval = ptrace(PTRACE_PEEKUSER, pid, offset[idx]);
    assert(errno == 0);
    return retval;
}

long nt_get_syscall_ret(pid_t pid)
{
    int offset = offsetof(struct user, regs.rax);

    errno = 0;
    long retval = ptrace(PTRACE_PEEKUSER, pid, offset);
    assert(errno == 0);
    return retval;
}
