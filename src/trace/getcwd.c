#include "utils/str.h"
#include "__init__.h"
#include "config.h"

static void s_decode_getcwd_arg0(nt_strcat_t* sc, const nt_syscall_info_t* si)
{
    if (si->enter.entry.args[0] == 0)
    {
        nt_strcat(sc, "NULL, ");
        return;
    }
    if (si->leave.exit.rval <= 0)
    {
        nt_strcat(sc, "\"\", ");
        return;
    }

    nt_str_sysdump(sc, si->pid, si->enter.entry.args[0], si->leave.exit.rval - 1, NT_MAX_DUMP_SIZE);
    nt_strcat(sc, ", ");
}

static void s_decode_getcwd_arg1(nt_strcat_t* sc, const nt_syscall_info_t* si)
{
    size_t size = si->enter.entry.args[1];
    nt_strcat(sc, "%zu", size);
}

int nt_syscall_decode_getcwd(const nt_syscall_info_t* si, int op, char* buff, size_t size)
{
    nt_strcat_t sc = NT_STRCAT_INIT(buff, size);
    if (op != PTRACE_SYSCALL_INFO_EXIT)
    {
        return 0;
    }
    nt_strcat(&sc, "(");
    s_decode_getcwd_arg0(&sc, si);
    s_decode_getcwd_arg1(&sc, si);
    nt_strcat(&sc, ") = ");
    nt_strcat_ret(&sc, si->leave.exit.rval, si->leave.exit.is_error);
    return sc.size;
}
