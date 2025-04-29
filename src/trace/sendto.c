#include "utils/defs.h"
#include "utils/syscall.h"
#include "utils/socket.h"
#include "utils/str.h"
#include "__init__.h"
#include "config.h"

static void s_decode_sendto_arg0(nt_strcat_t* sc, const nt_syscall_info_t* si)
{
    int sockfd = si->enter.entry.args[0];
    nt_strcat(sc, "%d, ", sockfd);
}

static void s_decode_sendto_arg1(nt_strcat_t* sc, const nt_syscall_info_t* si)
{
    if (si->enter.entry.args[1] == 0)
    {
        nt_strcat(sc, "NULL, ");
        return;
    }

    nt_str_sysdump(sc, si->pid, si->enter.entry.args[1], si->enter.entry.args[2], NT_MAX_DUMP_SIZE);
    nt_strcat(sc, ", ");
}

static void s_decode_sendto_arg2(nt_strcat_t* sc, const nt_syscall_info_t* si)
{
    size_t len = si->enter.entry.args[2];
    nt_strcat(sc, "%zu, ", len);
}

static void s_decode_sendto_arg3(nt_strcat_t* sc, const nt_syscall_info_t* si)
{
    int             flags = si->enter.entry.args[3];
    nt_bitdecoder_t bd = NT_BITDECODER_INIT(flags, sc);
    NT_BITDECODER_DECODE(&bd, MSG_CONFIRM);
    NT_BITDECODER_DECODE(&bd, MSG_DONTROUTE);
    NT_BITDECODER_DECODE(&bd, MSG_DONTWAIT);
    NT_BITDECODER_DECODE(&bd, MSG_EOR);
    NT_BITDECODER_DECODE(&bd, MSG_MORE);
    NT_BITDECODER_DECODE(&bd, MSG_NOSIGNAL);
    NT_BITDECODER_DECODE(&bd, MSG_OOB);
    NT_BITDECODER_DECODE(&bd, MSG_FASTOPEN);
    NT_BITDECODER_FINISH(&bd);
    nt_strcat(sc, ", ");
}

static void s_decode_sendto_arg4(nt_strcat_t* sc, const nt_syscall_info_t* si)
{
    if (si->enter.entry.args[4] == 0)
    {
        nt_strcat(sc, "NULL, ");
        return;
    }

    nt_str_sysdump_sockaddr(sc, si->pid, si->enter.entry.args[4], si->enter.entry.args[5]);
    nt_strcat(sc, ", ");
}

static void s_decode_sendto_arg5(nt_strcat_t* sc, const nt_syscall_info_t* si)
{
    socklen_t len = si->enter.entry.args[5];
    nt_strcat(sc, "%u", (unsigned)len);
}

int nt_syscall_decode_sendto(const nt_syscall_info_t* si, int op, char* buff, size_t size)
{
    nt_strcat_t sc = NT_STRCAT_INIT(buff, size);
    if (op != PTRACE_SYSCALL_INFO_EXIT)
    {
        return 0;
    }
    nt_strcat(&sc, "(");
    s_decode_sendto_arg0(&sc, si);
    s_decode_sendto_arg1(&sc, si);
    s_decode_sendto_arg2(&sc, si);
    s_decode_sendto_arg3(&sc, si);
    s_decode_sendto_arg4(&sc, si);
    s_decode_sendto_arg5(&sc, si);
    nt_strcat(&sc, ") = ");
    nt_strcat_ret(&sc, si->leave.exit.rval, si->leave.exit.is_error);
    return sc.size;
}
