#include "utils/defs.h"
#include "utils/socket.h"
#include "utils/syscall.h"
#include "utils/str.h"
#include "__init__.h"
#include "config.h"

static void s_decode_recvfrom_arg0(nt_strcat_t* sc, const nt_syscall_info_t* si)
{
    int sockfd = si->enter.entry.args[0];
    nt_strcat(sc, "%d, ", sockfd);
}

static void s_decode_recvfrom_arg1(nt_strcat_t* sc, const nt_syscall_info_t* si)
{
    if (si->enter.entry.args[1] == 0)
    {
        nt_strcat(sc, "NULL, ");
        return;
    }
    if (si->leave.exit.rval <= 0)
    {
        nt_strcat(sc, "\"\", ");
        return;
    }

    nt_str_sysdump(sc, si->pid, si->enter.entry.args[1], si->leave.exit.rval, NT_MAX_DUMP_SIZE);
    nt_strcat(sc, ", ");
}

static void s_decode_recvfrom_arg2(nt_strcat_t* sc, const nt_syscall_info_t* si)
{
    size_t nbyte = si->enter.entry.args[2];
    nt_strcat(sc, "%zu, ", nbyte);
}

static void s_decode_recvfrom_arg3(nt_strcat_t* sc, const nt_syscall_info_t* si)
{
    nt_bitdecoder_t bd = NT_BITDECODER_INIT(si->enter.entry.args[3], sc);
    NT_BITDECODER_DECODE(&bd, MSG_CMSG_CLOEXEC);
    NT_BITDECODER_DECODE(&bd, MSG_DONTWAIT);
    NT_BITDECODER_DECODE(&bd, MSG_ERRQUEUE);
    NT_BITDECODER_DECODE(&bd, MSG_OOB);
    NT_BITDECODER_DECODE(&bd, MSG_PEEK);
    NT_BITDECODER_DECODE(&bd, MSG_TRUNC);
    NT_BITDECODER_DECODE(&bd, MSG_WAITALL);
    NT_BITDECODER_FINISH(&bd);
    nt_strcat(sc, ", ");
}

static void s_decode_recvfrom_arg4(nt_strcat_t* sc, const nt_syscall_info_t* si, socklen_t addrlen)
{
    if (si->enter.entry.args[4] == 0)
    {
        nt_strcat(sc, "NULL, ");
        return;
    }

    nt_str_sysdump_sockaddr(sc, si->pid, si->enter.entry.args[4], addrlen);
    nt_strcat(sc, ", ");
}

static void s_decode_recvfrom_arg5(nt_strcat_t* sc, const nt_syscall_info_t* si, socklen_t addrlen)
{
    if (si->enter.entry.args[5] == 0)
    {
        nt_strcat(sc, "NULL");
        return;
    }

    nt_strcat(sc, "%u", (unsigned)addrlen);
}

int nt_syscall_decode_recvfrom(const nt_syscall_info_t* si, int op, char* buff, size_t size)
{
    socklen_t   addrlen = 0;
    nt_strcat_t sc = NT_STRCAT_INIT(buff, size);
    if (op == PTRACE_SYSCALL_INFO_EXIT)
    {
        nt_strcat(&sc, "(");
        s_decode_recvfrom_arg0(&sc, si);
        s_decode_recvfrom_arg1(&sc, si);
        s_decode_recvfrom_arg2(&sc, si);
        s_decode_recvfrom_arg3(&sc, si);

        if (si->enter.entry.args[5] != 0)
        {
            nt_syscall_getdata(si->pid, si->enter.entry.args[5], &addrlen, sizeof(addrlen));
        }

        s_decode_recvfrom_arg4(&sc, si, addrlen);
        s_decode_recvfrom_arg5(&sc, si, addrlen);
        nt_strcat(&sc, ") = %ld", (long)si->leave.exit.rval);
    }

    return sc.size;
}
