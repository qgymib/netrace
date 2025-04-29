#include "utils/str.h"
#include "utils/syscall.h"
#include "__init__.h"

static void s_decode_sendmsg_arg0(nt_strcat_t* sc, const nt_syscall_info_t* si)
{
    int sockfd = si->enter.entry.args[0];
    nt_strcat(sc, "%d, ", sockfd);
}

static void s_decode_sendmsg_arg1(nt_strcat_t* sc, const nt_syscall_info_t* si)
{
    if (si->enter.entry.args[1] == 0)
    {
        nt_strcat(sc, "NULL, ");
        return;
    }

    struct msghdr msg;
    nt_syscall_getdata(si->pid, si->enter.entry.args[1], &msg, sizeof(msg));
    nt_str_sysdump_msghdr(sc, si->pid, &msg);
    nt_strcat(sc, ", ");
}

static void s_decode_sendmsg_arg2(nt_strcat_t* sc, const nt_syscall_info_t* si)
{
    int             flags = si->enter.entry.args[2];
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
}

int nt_syscall_decode_sendmsg(const nt_syscall_info_t* si, int op, char* buff, size_t size)
{
    nt_strcat_t sc = NT_STRCAT_INIT(buff, size);
    if (op != PTRACE_SYSCALL_INFO_EXIT)
    {
        return 0;
    }
    nt_strcat(&sc, "(");
    s_decode_sendmsg_arg0(&sc, si);
    s_decode_sendmsg_arg1(&sc, si);
    s_decode_sendmsg_arg2(&sc, si);
    nt_strcat(&sc, ") = ");
    nt_strcat_ret(&sc, si->leave.exit.rval, si->leave.exit.is_error);
    return sc.size;
}
