#include "utils/socket.h"
#include "utils/syscall.h"
#include "__init__.h"

static void s_decode_getpeername_arg0(nt_strcat_t* sc, const nt_syscall_info_t* si)
{
    int sockfd = si->enter.entry.args[0];
    nt_strcat(sc, "%d, ", sockfd);
}

static void s_decode_getpeername_arg1(nt_strcat_t* sc, const nt_syscall_info_t* si,
                                      socklen_t addrlen)
{
    struct sockaddr_storage addr;
    if (si->leave.exit.rval != 0 || si->enter.entry.args[1] == 0 || addrlen == 0)
    {
        nt_strcat(sc, "NULL, ");
        return;
    }

    nt_syscall_get_sockaddr(si->pid, si->enter.entry.args[1], &addr, addrlen);

    char ip[64];
    int  port = 0;
    if (nt_ip_name((struct sockaddr*)&addr, ip, sizeof(ip), &port) != 0)
    {
        nt_strcat(sc, "EINVAL, ");
        return;
    }

    nt_strcat(sc, "{domain=%s, addr=%s, port=%d}, ", nt_socket_domain_name(addr.ss_family), ip,
              port);
}

static void s_decode_getpeername_arg2(nt_strcat_t* sc, const nt_syscall_info_t* si,
                                      socklen_t addrlen)
{
    if (si->enter.entry.args[2] == 0)
    {
        nt_strcat(sc, "NULL");
        return;
    }

    nt_strcat(sc, "%u", (unsigned)addrlen);
}

int nt_syscall_decode_getpeername(const nt_syscall_info_t* si, int op, char* buff, size_t size)
{
    socklen_t   addrlen = 0;
    nt_strcat_t sc = NT_STRCAT_INIT(buff, size);
    if (op == PTRACE_SYSCALL_INFO_EXIT)
    {
        nt_strcat(&sc, "(");
        if (si->enter.entry.args[2] != 0)
        {
            nt_syscall_getdata(si->pid, si->enter.entry.args[2], &addrlen, sizeof(addrlen));
        }

        s_decode_getpeername_arg0(&sc, si);
        s_decode_getpeername_arg1(&sc, si, addrlen);
        s_decode_getpeername_arg2(&sc, si, addrlen);
        nt_strcat(&sc, ") = ");
        nt_strcat_ret(&sc, si->leave.exit.rval, si->leave.exit.is_error);
    }
    return sc.size;
}
