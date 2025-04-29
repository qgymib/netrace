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
        nt_strcat(sc, "msg_len=%u", msg->msg_len);
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
#define CHECK_CAT_FLAG(name)                                                                       \
    do                                                                                             \
    {                                                                                              \
        if (flags & name)                                                                          \
        {                                                                                          \
            nt_strcat(sc, "%s%s", flag_cnt++ == 0 ? "" : "|", #name);                              \
        }                                                                                          \
    } while (0)

    int    flags = si->enter.entry.args[3];
    size_t flag_cnt = 0;

    CHECK_CAT_FLAG(MSG_CONFIRM);
    CHECK_CAT_FLAG(MSG_DONTROUTE);
    CHECK_CAT_FLAG(MSG_DONTWAIT);
    CHECK_CAT_FLAG(MSG_EOR);
    CHECK_CAT_FLAG(MSG_MORE);
    CHECK_CAT_FLAG(MSG_NOSIGNAL);
    CHECK_CAT_FLAG(MSG_OOB);
    CHECK_CAT_FLAG(MSG_FASTOPEN);

    if (flag_cnt == 0)
    {
        nt_strcat(sc, "0");
    }

#undef CHECK_CAT_FLAG
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
