#include <assert.h>
#include <errno.h>
#include <string.h>
#include <stdlib.h>
#include <sys/user.h>
#include <sys/ptrace.h>
#include "utils/defs.h"
#include "syscall.h"

typedef union syscall_word {
    long          val;
    unsigned char buf[sizeof(long)];
} syscall_word_t;

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

void nt_syscall_getdata(pid_t pid, long addr, void* dst, size_t len)
{
    size_t         read_sz = 0;
    syscall_word_t word;

    while (read_sz < len)
    {
        word.val = ptrace(PTRACE_PEEKDATA, pid, addr + read_sz, NULL);

        size_t copy_sz = len - read_sz;
        if (copy_sz > sizeof(word.val))
        {
            copy_sz = sizeof(word.val);
        }

        memcpy((char*)dst + read_sz, word.buf, copy_sz);
        read_sz += copy_sz;
    }
}

void nt_syscall_setdata(pid_t pid, long addr, const void* src, size_t len)
{
    size_t         write_sz = 0;
    syscall_word_t word;

    while (write_sz < len)
    {
        size_t copy_sz = len - write_sz;
        if (copy_sz > sizeof(word.val))
        {
            copy_sz = sizeof(word.val);
        }

        memcpy(&word.buf, (char*)src + write_sz, copy_sz);
        ptrace(PTRACE_POKEDATA, pid, addr + write_sz, word.val);

        write_sz += copy_sz;
    }
}
