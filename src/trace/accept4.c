#include "utils/socket.h"
#include "utils/syscall.h"
#include "utils/str.h"
#include "__init__.h"

static void s_decode_accept4_arg0(nt_strcat_t* sc, const nt_syscall_info_t* si)
{
    int sockfd = si->enter.entry.args[0];
    nt_strcat(sc, "%d, ", sockfd);
}

static void s_decode_accpet4_arg1(nt_strcat_t* sc, const nt_syscall_info_t* si, socklen_t addrlen)
{
    if (si->enter.entry.args[1] == 0 || addrlen == 0)
    {
        nt_strcat(sc, "NULL, ");
        return;
    }
    if (si->leave.exit.rval < 0)
    {
        nt_strcat(sc, "\"\", ");
        return;
    }

    nt_str_sysdump_sockaddr(sc, si->pid, si->enter.entry.args[1], addrlen);
    nt_strcat(sc, ", ");
}

static void s_decode_accpet4_arg2(nt_strcat_t* sc, const nt_syscall_info_t* si, socklen_t addrlen)
{
    if (si->enter.entry.args[2] == 0)
    {
        nt_strcat(sc, "NULL, ");
        return;
    }

    nt_strcat(sc, "%u, ", (unsigned)addrlen);
}

static void s_decode_accept4_arg3(nt_strcat_t* sc, const nt_syscall_info_t* si)
{
    int             flags = si->enter.entry.args[3];
    nt_bitdecoder_t bd = NT_BITDECODER_INIT(flags, sc);
    NT_BITDECODER_DECODE(&bd, SOCK_NONBLOCK);
    NT_BITDECODER_DECODE(&bd, SOCK_CLOEXEC);
    NT_BITDECODER_FINISH(&bd);
}

int nt_syscall_decode_accept4(const nt_syscall_info_t* si, int op, char* buff, size_t size)
{
    socklen_t   addrlen = 0;
    nt_strcat_t sc = NT_STRCAT_INIT(buff, size);
    if (op != PTRACE_SYSCALL_INFO_EXIT)
    {
        return 0;
    }
    if (si->enter.entry.args[2] != 0)
    {
        nt_syscall_getdata(si->pid, si->enter.entry.args[2], &addrlen, sizeof(addrlen));
    }
    nt_strcat(&sc, "(");
    s_decode_accept4_arg0(&sc, si);
    s_decode_accpet4_arg1(&sc, si, addrlen);
    s_decode_accpet4_arg2(&sc, si, addrlen);
    s_decode_accept4_arg3(&sc, si);
    nt_strcat(&sc, ") = ");
    nt_strcat_ret(&sc, si->leave.exit.rval, si->leave.exit.is_error);
    return sc.size;
}
