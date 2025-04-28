#include "utils/syscall.h"
#include "utils/socket.h"
#include "utils/str.h"
#include "__init__.h"

static void s_decode_bind_arg0(nt_strcat_t* sc, const nt_syscall_info_t* si)
{
    int sockfd = si->enter.entry.args[0];
    nt_strcat(sc, "%d, ", sockfd);
}

static void s_decode_bind_arg1(nt_strcat_t* sc, const nt_syscall_info_t* si)
{
    if (si->enter.entry.args[1] == 0)
    {
        nt_strcat(sc, "NULL, ");
        return;
    }
    nt_str_sysdump_sockaddr(sc, si->pid, si->enter.entry.args[1], si->enter.entry.args[2]);
}

static void s_decode_bind_arg2(nt_strcat_t* sc, const nt_syscall_info_t* si)
{
    socklen_t addrlen = si->enter.entry.args[2];
    nt_strcat(sc, "%u", (unsigned)addrlen);
}

int nt_syscall_decode_bind(const nt_syscall_info_t* si, int op, char* buff, size_t size)
{
    nt_strcat_t sc = NT_STRCAT_INIT(buff, size);
    if (op != PTRACE_SYSCALL_INFO_EXIT)
    {
        return 0;
    }
    nt_strcat(&sc, "(");
    s_decode_bind_arg0(&sc, si);
    s_decode_bind_arg1(&sc, si);
    s_decode_bind_arg2(&sc, si);
    nt_strcat(&sc, ") = ");
    nt_strcat_ret(&sc, si->leave.exit.rval, si->leave.exit.is_error);
    return sc.size;
}
