#include "utils/socket.h"
#include "utils/syscall.h"
#include "__init__.h"

static void s_decode_socketpair_arg0(nt_strcat_t* sc, const nt_syscall_info_t* si)
{
    int domain = si->enter.entry.args[0];
    nt_strcat(sc, "%s, ", nt_socket_domain_name(domain));
}

static void s_decode_socketpair_arg1(nt_strcat_t* sc, const nt_syscall_info_t* si)
{
    int type = si->enter.entry.args[1];
    nt_strcat(sc, "%s", nt_socket_type_name(type & 0xFF));
    if (type & SOCK_NONBLOCK)
    {
        nt_strcat(sc, "|SOCK_NONBLOCK");
    }
    nt_strcat(sc, ", ");
}

static void s_decode_socketpair_arg2(nt_strcat_t* sc, const nt_syscall_info_t* si)
{
    int protocol = si->enter.entry.args[2];
    nt_strcat(sc, "%d, ", protocol);
}

static void s_decode_socketpair_arg3(nt_strcat_t* sc, const nt_syscall_info_t* si)
{
    int sv[2];
    if (si->enter.entry.args[3] == 0)
    {
        nt_strcat(sc, "NULL");
        return;
    }

    nt_syscall_getdata(si->pid, si->enter.entry.args[3], sv, sizeof(sv));
    nt_strcat(sc, "{[0]=%d, [1]=%d}", sv[0], sv[1]);
}

int nt_syscall_decode_socketpair(const nt_syscall_info_t* si, int op, char* buff, size_t size)
{
    nt_strcat_t sc = NT_STRCAT_INIT(buff, size);
    if (op != PTRACE_SYSCALL_INFO_EXIT)
    {
        return 0;
    }
    nt_strcat(&sc, "(");
    s_decode_socketpair_arg0(&sc, si);
    s_decode_socketpair_arg1(&sc, si);
    s_decode_socketpair_arg2(&sc, si);
    s_decode_socketpair_arg3(&sc, si);
    nt_strcat(&sc, ") = ");
    nt_strcat_ret(&sc, si->leave.exit.rval, si->leave.exit.is_error);
    return sc.size;
}
