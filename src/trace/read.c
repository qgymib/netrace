#include "utils/str.h"
#include "__init__.h"

static void s_decode_read_arg0(nt_strcat_t* sc, const nt_syscall_info_t* si)
{
    nt_strcat(sc, "%d, ", (int)si->enter.entry.args[0]);
}

static void s_decode_read_arg1(nt_strcat_t* sc, const nt_syscall_info_t* si)
{
    if (si->enter.entry.args[1] == 0)
    {
        nt_strcat(sc, "NULL, ");
        return;
    }
    if (si->leave.exit.rval <= 0)
    {
        nt_strcat(sc, "\"\", ");
        return;
    }

    nt_str_sysdump(sc, si->pid, si->enter.entry.args[1], si->leave.exit.rval);
}

static void s_decode_read_arg2(nt_strcat_t* sc, const nt_syscall_info_t* si)
{
    size_t count = si->enter.entry.args[2];
    nt_strcat(sc, "%zu", count);
}

int nt_syscall_decode_read(const nt_syscall_info_t* si, int op, char* buff, size_t size)
{
    nt_strcat_t sc = NT_STRCAT_INIT(buff, size);
    if (op != PTRACE_SYSCALL_INFO_EXIT)
    {
        return 0;
    }
    nt_strcat(&sc, "(");
    s_decode_read_arg0(&sc, si);
    s_decode_read_arg1(&sc, si);
    s_decode_read_arg2(&sc, si);
    nt_strcat(&sc, ") = ");
    nt_strcat_ret(&sc, si->leave.exit.rval, si->leave.exit.is_error);
    return sc.size;
}
