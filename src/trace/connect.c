#include <unistd.h>
#include "utils/socket.h"
#include "utils/syscall.h"
#include "__init__.h"

static void s_decode_connect_arg0(nt_strcat_t* sc, const nt_syscall_info_t* si)
{
    nt_strcat(sc, "%d, ", si->enter.entry.args[0]);
}

static void s_decode_connect_arg1(nt_strcat_t* sc, const nt_syscall_info_t* si)
{
    struct sockaddr_storage addr;
    socklen_t               len = si->enter.entry.args[2];
    int ret = nt_syscall_get_sockaddr(si->pid, si->enter.entry.args[1], &addr, len);
    if (ret < 0)
    {
        nt_strcat(sc, "EINVAL");
        return;
    }

    char ip[64];
    int  port = 0;
    if (nt_ip_name((struct sockaddr*)&addr, ip, sizeof(ip), &port) != 0)
    {
        nt_strcat(sc, "EINVAL");
        return;
    }

    nt_strcat(sc, "{domain=%s, addr=%s, port=%d}, ", nt_socket_domain_name(addr.ss_family), ip,
              port);
}

static void s_decode_connect_arg2(nt_strcat_t* sc, const nt_syscall_info_t* si)
{
    nt_strcat(sc, "%lu", (unsigned long)si->enter.entry.args[2]);
}

int nt_syscall_decode_connect(const nt_syscall_info_t* si, int op, char* buff, size_t size)
{
    nt_strcat_t sc = NT_STRCAT_INIT(buff, size);
    if (op == PTRACE_SYSCALL_INFO_EXIT)
    {
        nt_strcat(&sc, "(");
        s_decode_connect_arg0(&sc, si);
        s_decode_connect_arg1(&sc, si);
        s_decode_connect_arg2(&sc, si);
        nt_strcat(&sc, ") = %d", (int)si->leave.exit.rval);
    }
    return sc.size;
}
