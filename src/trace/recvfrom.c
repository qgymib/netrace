#include "utils/defs.h"
#include "utils/socket.h"
#include "utils/syscall.h"
#include "__init__.h"

static void s_decode_recvfrom_arg0(nt_strcat_t* sc, const nt_syscall_info_t* si)
{
    int sockfd = si->enter.entry.args[0];
    nt_strcat(sc, "%d, ", sockfd);
}

static void s_decode_recvfrom_arg1(nt_strcat_t* sc, const nt_syscall_info_t* si)
{
    char buff[32];
    if (si->enter.entry.args[1] == 0)
    {
        nt_strcat(sc, "NULL, ");
        return;
    }

    size_t buff_sz = NT_MIN(sizeof(buff), si->enter.entry.args[2]);
    nt_syscall_getdata(si->pid, si->enter.entry.args[1], buff, buff_sz);
    nt_strcat_dump(sc, buff, buff_sz);
    if (buff_sz < si->enter.entry.args[2])
    {
        nt_strcat(sc, "...");
    }
    nt_strcat(sc, ", ");
}

static void s_decode_recvfrom_arg2(nt_strcat_t* sc, const nt_syscall_info_t* si)
{
    size_t nbyte = si->enter.entry.args[2];
    nt_strcat(sc, "%zu, ", nbyte);
}

static void s_decode_recvfrom_arg3(nt_strcat_t* sc, const nt_syscall_info_t* si)
{
#define CHECK_FLAG(f)                                                                              \
    do                                                                                             \
    {                                                                                              \
        if (flags & f)                                                                             \
        {                                                                                          \
            nt_strcat(sc, "%s%s", flag_cnt++ == 0 ? "" : "|", #f);                                 \
        }                                                                                          \
    } while (0)

    int    flags = si->enter.entry.args[3];
    size_t flag_cnt = 0;

    CHECK_FLAG(MSG_CMSG_CLOEXEC);
    CHECK_FLAG(MSG_DONTWAIT);
    CHECK_FLAG(MSG_ERRQUEUE);
    CHECK_FLAG(MSG_OOB);
    CHECK_FLAG(MSG_PEEK);
    CHECK_FLAG(MSG_TRUNC);
    CHECK_FLAG(MSG_WAITALL);

    if (flag_cnt == 0)
    {
        nt_strcat(sc, "0");
    }
    nt_strcat(sc, ", ");

#undef CHECK_FLAG
}

static void s_decode_recvfrom_arg4(nt_strcat_t* sc, const nt_syscall_info_t* si, socklen_t addrlen)
{
    char                    ip[64];
    int                     port;
    struct sockaddr_storage addr;

    if (si->enter.entry.args[4] == 0)
    {
        nt_strcat(sc, "NULL, ");
        return;
    }

    nt_syscall_get_sockaddr(si->pid, si->enter.entry.args[4], &addr, addrlen);
    if (nt_ip_name((struct sockaddr*)&addr, ip, sizeof(ip), &port) != 0)
    {
        nt_strcat(sc, "EINVAL, ");
        return;
    }

    nt_strcat(sc, "{domain=%s, addr=%s, port=%d}, ", nt_socket_domain_name(addr.ss_family), ip,
              port);
}

static void s_decode_recvfrom_arg5(nt_strcat_t* sc, const nt_syscall_info_t* si, socklen_t addrlen)
{
    if (si->enter.entry.args[5] == 0)
    {
        nt_strcat(sc, "NULL");
        return;
    }

    nt_strcat(sc, "%lu", addrlen);
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
