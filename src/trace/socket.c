#include "utils/socket.h"
#include "utils/str.h"
#include "__init__.h"

static void s_decode_socket_arg0(nt_strcat_t* sc, const nt_syscall_info_t* si)
{
    int domain = si->enter.entry.args[0];
    nt_strcat(sc, "%s, ", nt_socket_domain_name(domain));
}

static void s_decode_socket_arg1(nt_strcat_t* sc, const nt_syscall_info_t* si)
{
    int type = si->enter.entry.args[1];
    nt_strcat(sc, "%s", nt_socket_type_name(type & 0xFF));
    if (type & SOCK_NONBLOCK)
    {
        nt_strcat(sc, "|SOCK_NONBLOCK");
    }
    if (type & SOCK_CLOEXEC)
    {
        nt_strcat(sc, "|SOCK_CLOEXEC");
    }
    nt_strcat(sc, ", ");
}

static void s_decode_socket_arg2(nt_strcat_t* sc, const nt_syscall_info_t* si)
{
    int protocol = si->enter.entry.args[2];
    nt_strcat(sc, "%d", protocol);
}

int nt_syscall_decode_socket(const nt_syscall_info_t* si, int op, char* buff, size_t size)
{
    nt_strcat_t sc = NT_STRCAT_INIT(buff, size);
    if (op == PTRACE_SYSCALL_INFO_EXIT)
    {
        nt_strcat(&sc, "(");
        s_decode_socket_arg0(&sc, si);
        s_decode_socket_arg1(&sc, si);
        s_decode_socket_arg2(&sc, si);
        nt_strcat(&sc, ") = ");
        nt_strcat_ret(&sc, si->leave.exit.rval, si->leave.exit.is_error);
    }
    return sc.size;
}
