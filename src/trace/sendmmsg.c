#define _GNU_SOURCE
#include "utils/defs.h"
#include "utils/socket.h"
#include "utils/syscall.h"
#include "__init__.h"

static void s_decode_sendmmsg_arg0(nt_strcat_t* sc, const nt_syscall_info_t* si)
{
    int sockfd = si->enter.entry.args[0];
    nt_strcat(sc, "%d, ", sockfd);
}

static void s_decode_sendmmsg_arg1_msghdr_msgname(nt_strcat_t* sc, const nt_syscall_info_t* si,
                                                  struct msghdr* hdr)
{
    char                    ip[64];
    int                     port;
    struct sockaddr_storage addr;

    if (hdr->msg_name == NULL)
    {
        nt_strcat(sc, "NULL");
        return;
    }

    nt_syscall_get_sockaddr(si->pid, (uintptr_t)hdr->msg_name, &addr, hdr->msg_namelen);
    if (nt_ip_name((struct sockaddr*)&addr, ip, sizeof(ip), &port) != 0)
    {
        nt_strcat(sc, "EINVAL");
        return;
    }

    nt_strcat(sc, "{domain=%s, addr=%s, port=%d}, ", nt_socket_domain_name(addr.ss_family), ip,
              port);
}

static void s_decode_sendmmsg_arg1_msghdr_msgiov(nt_strcat_t* sc, const nt_syscall_info_t* si,
                                                 struct msghdr* hdr)
{
    unsigned char buff[32];
    struct iovec  msgiov[3];
    size_t        iov_len = NT_MIN(ARRAY_SIZE(msgiov), (size_t)hdr->msg_iovlen);
    size_t        read_sz = sizeof(msgiov[0]) * iov_len;
    nt_syscall_getdata(si->pid, (uintptr_t)hdr->msg_iov, msgiov, read_sz);

    size_t i;
    nt_strcat(sc, "[");
    for (i = 0; i < iov_len; i++)
    {
        struct iovec* io = &msgiov[i];
        size_t        buff_sz = NT_MIN(sizeof(buff), io->iov_len);
        nt_syscall_getdata(si->pid, (uintptr_t)io->iov_base, buff, buff_sz);

        nt_strcat(sc, "{iov_base=");
        nt_strcat_dump(sc, buff, buff_sz);
        if (buff_sz < io->iov_len)
        {
            nt_strcat(sc, "...");
        }
        nt_strcat(sc, ",iov_len=%lu},", (unsigned long)io->iov_len);

        if (i != iov_len - 1)
        {
            nt_strcat(sc, ",");
        }
    }
    nt_strcat(sc, "]");
}

static void s_decode_sendmmsg_arg1_msghdr_msgcontrol(nt_strcat_t* sc, const nt_syscall_info_t* si,
                                                     struct msghdr* hdr)
{
    unsigned char buff[32];
    if (hdr->msg_control == NULL)
    {
        nt_strcat(sc, "NULL");
        return;
    }

    size_t buff_sz = NT_MIN(sizeof(buff), hdr->msg_controllen);
    nt_syscall_getdata(si->pid, (uintptr_t)hdr->msg_control, buff, buff_sz);
    nt_strcat_dump(sc, buff, buff_sz);
    if (buff_sz < hdr->msg_controllen)
    {
        nt_strcat(sc, "...");
    }
}

static void s_decode_sendmmsg_arg1_msghdr(nt_strcat_t* sc, const nt_syscall_info_t* si,
                                          struct msghdr* hdr)
{
    nt_strcat(sc, "msg_name=");
    s_decode_sendmmsg_arg1_msghdr_msgname(sc, si, hdr);
    nt_strcat(sc, ",msg_namelen=%u,msg_iov=", (unsigned)hdr->msg_namelen);
    s_decode_sendmmsg_arg1_msghdr_msgiov(sc, si, hdr);
    nt_strcat(sc, ",msg_iovlen=%lu,msg_control=", (unsigned long)hdr->msg_iovlen);
    s_decode_sendmmsg_arg1_msghdr_msgcontrol(sc, si, hdr);
    nt_strcat(sc, ",msg_flags=%d", hdr->msg_flags);
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
        nt_strcat(sc, "msg_hdr={");
        s_decode_sendmmsg_arg1_msghdr(sc, si, hdr);
        nt_strcat(sc, "},");
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

int nt_syscall_decode_sendmmsg(const nt_syscall_info_t* si, char* buff, size_t size)
{
    nt_strcat_t sc = NT_STRCAT_INIT(buff, size);
    nt_strcat(&sc, "(");
    s_decode_sendmmsg_arg0(&sc, si);
    s_decode_sendmmsg_arg1(&sc, si);
    s_decode_sendmmsg_arg2(&sc, si);
    s_decode_sendmmsg_arg3(&sc, si);
    nt_strcat(&sc, ") = %d", (int)si->leave.exit.rval);
    return sc.size;
}
