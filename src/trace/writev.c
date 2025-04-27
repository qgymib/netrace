#include "utils/str.h"
#include "__init__.h"

static void s_decode_writev_arg0(nt_strcat_t* sc, const nt_syscall_info_t* si)
{
    int fd = si->enter.entry.args[0];
    nt_strcat(sc, "%d, ", fd);
}

static void s_decode_writev_arg1(nt_strcat_t* sc, const nt_syscall_info_t* si)
{
    uintptr_t iov = si->enter.entry.args[1];
    int       iovcnt = si->enter.entry.args[2];
    if (iov == 0)
    {
        nt_strcat(sc, "NULL, ");
        return;
    }

    nt_str_sysdump_iovec(sc, si->pid, iov, iovcnt, SIZE_MAX);
    nt_strcat(sc, ", ");
}

static void s_decode_writev_arg2(nt_strcat_t* sc, const nt_syscall_info_t* si)
{
    int iovcnt = si->enter.entry.args[2];
    nt_strcat(sc, "%d", iovcnt);
}

int nt_syscall_decode_writev(const nt_syscall_info_t* si, int op, char* buff, size_t size)
{
    nt_strcat_t sc = NT_STRCAT_INIT(buff, size);
    if (op != PTRACE_SYSCALL_INFO_EXIT)
    {
        return 0;
    }
    nt_strcat(&sc, "(");
    s_decode_writev_arg0(&sc, si);
    s_decode_writev_arg1(&sc, si);
    s_decode_writev_arg2(&sc, si);
    nt_strcat(&sc, ") = ");
    nt_strcat_ret(&sc, si->leave.exit.rval, si->leave.exit.is_error);
    return sc.size;
}
