#include <assert.h>
#include <errno.h>
#include <string.h>
#include <stdlib.h>
#include <sys/user.h>
#include <sys/ptrace.h>
#include "utils/defs.h"
#include "utils/log.h"
#include "syscall.h"

typedef union syscall_word {
    long          val;
    unsigned char buf[sizeof(long)];
} syscall_word_t;

#if defined(__x86_64__)

/* clang-format off */
static int s_arg_offset[] = {
    offsetof(struct user, regs.rdi),
    offsetof(struct user, regs.rsi),
    offsetof(struct user, regs.rdx),
    offsetof(struct user, regs.r10),
    offsetof(struct user, regs.r8),
    offsetof(struct user, regs.r9),
};
/* clang-format on */

long nt_syscall_get_id(pid_t pid)
{
    int offset = offsetof(struct user, regs.orig_rax);

    errno = 0;
    long val = ptrace(PTRACE_PEEKUSER, pid, offset, NULL);
    assert(errno == 0);

    return val;
}

long nt_syscall_get_ret(pid_t pid)
{
    int offset = offsetof(struct user, regs.rax);

    errno = 0;
    long retval = ptrace(PTRACE_PEEKUSER, pid, offset, NULL);
    assert(errno == 0);
    return retval;
}

long nt_syscall_get_arg(pid_t pid, size_t idx)
{
    assert(idx <= 5);

    errno = 0;
    long retval = ptrace(PTRACE_PEEKUSER, pid, s_arg_offset[idx], NULL);
    assert(errno == 0);
    return retval;
}

void nt_syscall_set_arg(pid_t pid, size_t idx, long val)
{
    assert(idx <= 5);
    long ret = ptrace(PTRACE_POKEUSER, pid, s_arg_offset[idx], val);
    assert(ret == 0);
    (void)ret;
}

#elif defined(__aarch64__)

#include <elf.h>

long nt_syscall_get_id(pid_t pid)
{
    struct user_regs_struct regs;
    struct iovec            iov = {
                   .iov_base = &regs,
                   .iov_len = sizeof(regs),
    };
    /* clang-format off */
    NT_ASSERT(ptrace(PTRACE_GETREGSET, pid, NT_PRSTATUS, &iov) == 0,
        "(%d) %s.", errno, strerror(errno));
    /* clang-format on */
    assert(iov.iov_len == sizeof(regs));
    return regs.regs[8];
}

long nt_syscall_get_ret(pid_t pid)
{
    struct user_regs_struct regs;
    struct iovec            iov = {
                   .iov_base = &regs,
                   .iov_len = sizeof(regs),
    };
    /* clang-format off */
    NT_ASSERT(ptrace(PTRACE_GETREGSET, pid, NT_PRSTATUS, &iov) == 0,
        "(%d) %s.", errno, strerror(errno));
    /* clang-format on */
    assert(iov.iov_len == sizeof(regs));
    return regs.regs[0];
}

long nt_syscall_get_arg(pid_t pid, size_t idx)
{
    struct user_regs_struct regs;
    struct iovec            iov = {
                   .iov_base = &regs,
                   .iov_len = sizeof(regs),
    };
    /* clang-format off */
    NT_ASSERT(ptrace(PTRACE_GETREGSET, pid, NT_PRSTATUS, &iov) == 0,
        "(%d) %s.", errno, strerror(errno));
    /* clang-format on */
    assert(iov.iov_len == sizeof(regs));

    return regs.regs[idx];
}

void nt_syscall_set_arg(pid_t pid, size_t idx, long val)
{
    struct user_regs_struct regs;
    struct iovec            iov = {
                   .iov_base = &regs,
                   .iov_len = sizeof(regs),
    };
    /* clang-format off */
    NT_ASSERT(ptrace(PTRACE_GETREGSET, pid, NT_PRSTATUS, &iov) == 0,
        "(%d) %s.", errno, strerror(errno));
    /* clang-format on */
    assert(iov.iov_len == sizeof(regs));

    regs.regs[idx] = val;

    /* clang-format off */
    NT_ASSERT(ptrace(PTRACE_SETREGSET, pid, NT_PRSTATUS, &iov) == 0,
        "(%d) %s.", errno, strerror(errno));
    /* clang-format on */
}

#else

#error Unsupport archive.

#endif

void nt_syscall_getdata(pid_t pid, uintptr_t addr, void* dst, size_t len)
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

void nt_syscall_setdata(pid_t pid, uintptr_t addr, const void* src, size_t len)
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

int nt_syscall_get_sockaddr(pid_t pid, uintptr_t addr, struct sockaddr_storage* data, size_t size)
{
    const size_t sockv4_len = sizeof(struct sockaddr_in);
    const size_t sockv6_len = sizeof(struct sockaddr_in6);

    if (size < sockv4_len)
    {
        return NT_ERR(EINVAL);
    }

    /* Try get IPv4 address. */
    nt_syscall_getdata(pid, addr, data, sockv4_len);

    if (data->ss_family == AF_INET6)
    {
        if (size < sockv6_len)
        {
            return NT_ERR(EINVAL);
        }

        nt_syscall_getdata(pid, addr, data, sockv6_len);
    }

    return 0;
}

int nt_syscall_set_sockaddr(pid_t pid, uintptr_t addr, const struct sockaddr_storage* data,
                            size_t size)
{
    const size_t sockv4_len = sizeof(struct sockaddr_in);
    const size_t sockv6_len = sizeof(struct sockaddr_in6);
    size_t       write_sz = data->ss_family == AF_INET ? sockv4_len : sockv6_len;
    if (size < write_sz)
    {
        return NT_ERR(EINVAL);
    }

    nt_syscall_setdata(pid, addr, data, write_sz);
    return 0;
}

int nt_syscall_get_string(pid_t pid, uintptr_t addr, char* buff, size_t size)
{
    size_t         offset = 0;
    void*          eol = NULL;
    syscall_word_t word;

    while (offset < size && eol == NULL)
    {
        errno = 0;
        word.val = ptrace(PTRACE_PEEKDATA, pid, addr + offset, NULL);
        if (errno != 0)
        {
            return NT_ERR(errno);
        }

        size_t left_sz = size - offset;
        size_t copy_sz = NT_MIN(sizeof(word), left_sz);
        if ((eol = memchr(&word.val, '\0', sizeof(word.val))) != NULL)
        {
            size_t str_len = (char*)eol - (char*)&word.val;
            copy_sz = NT_MIN(copy_sz, str_len);
        }

        memcpy(buff + offset, word.buf, copy_sz);
        offset += copy_sz;
    }

    if (offset < size)
    {
        buff[offset] = '\0';
    }
    else
    {
        buff[size - 1] = '\0';
    }
    return offset;
}
