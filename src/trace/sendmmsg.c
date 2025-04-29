#define _GNU_SOURCE
#include "utils/defs.h"
#include "utils/socket.h"
#include "utils/syscall.h"
#include "utils/str.h"
#include "__init__.h"

static void s_decode_sendmmsg_arg0(nt_strcat_t* sc, const nt_syscall_info_t* si)
{
    int sockfd = si->enter.entry.args[0];
    nt_strcat(sc, "%d, ", sockfd);
}

static void s_decode_sendmmsg_arg1(nt_strcat_t* sc, const nt_syscall_info_t* si)
{
    size_t         i;
    struct mmsghdr msgvec[3];
    unsigned int   vlen = si->enter.entry.args[2];
    size_t         hdr_len = NT_MIN(ARRAY_SIZE(msgvec), vlen);
    size_t         peek_sz = sizeof(msgvec[0]) * hdr_len;
    nt_syscall_getdata(si->pid, si->enter.entry.args[1], msgvec, peek_sz);

    nt_strcat(sc, "[");
    for (i = 0; i < hdr_len; i++)
    {
        nt_strcat(sc, "{");
        struct mmsghdr* msg = &msgvec[i];
        struct msghdr*  hdr = &msg->msg_hdr;
        nt_strcat(sc, "msg_hdr=");
        nt_str_sysdump_msghdr(sc, si->pid, hdr);
        nt_strcat(sc, ",msg_len=%u", msg->msg_len);
        nt_strcat(sc, "}%s", i == hdr_len - 1 ? "" : ",");
    }
    if (hdr_len < vlen)
    {
        nt_strcat(sc, "...");
    }
    nt_strcat(sc, "], ");
}

static void s_decode_sendmmsg_arg2(nt_strcat_t* sc, const nt_syscall_info_t* si)
{
    unsigned int vlen = si->enter.entry.args[2];
    nt_strcat(sc, "%u, ", vlen);
}

static void s_decode_sendmmsg_arg3(nt_strcat_t* sc, const nt_syscall_info_t* si)
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
}

int nt_syscall_decode_sendmmsg(const nt_syscall_info_t* si, int op, char* buff, size_t size)
{
    nt_strcat_t sc = NT_STRCAT_INIT(buff, size);
    if (op == PTRACE_SYSCALL_INFO_EXIT)
    {
        nt_strcat(&sc, "(");
        s_decode_sendmmsg_arg0(&sc, si);
        s_decode_sendmmsg_arg1(&sc, si);
        s_decode_sendmmsg_arg2(&sc, si);
        s_decode_sendmmsg_arg3(&sc, si);
        nt_strcat(&sc, ") = %d", (int)si->leave.exit.rval);
    }
    return sc.size;
}
