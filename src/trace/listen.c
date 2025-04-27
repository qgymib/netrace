#include "utils/str.h"
#include "__init__.h"

static void s_decode_listen_arg0(nt_strcat_t* sc, const nt_syscall_info_t* si)
{
    int sockfd = si->enter.entry.args[0];
    nt_strcat(sc, "%d, ", sockfd);
}

static void s_decode_listen_arg1(nt_strcat_t* sc, const nt_syscall_info_t* si)
{
    int backlog = si->enter.entry.args[1];
    nt_strcat(sc, "%d", backlog);
}

int nt_syscall_decode_listen(const nt_syscall_info_t* si, int op, char* buff, size_t size)
{
    nt_strcat_t sc = NT_STRCAT_INIT(buff, size);
    if (op != PTRACE_SYSCALL_INFO_EXIT)
    {
        return 0;
    }
    nt_strcat(&sc, "(");
    s_decode_listen_arg0(&sc, si);
    s_decode_listen_arg1(&sc, si);
    nt_strcat(&sc, ") = ");
    nt_strcat_ret(&sc, si->leave.exit.rval, si->leave.exit.is_error);
    return sc.size;
}
