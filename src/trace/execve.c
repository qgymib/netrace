#include <string.h>
#include "utils/defs.h"
#include "utils/syscall.h"
#include "utils/str.h"
#include "__init__.h"

static void s_decode_execve_arg0(nt_strcat_t* sc, const nt_syscall_info_t* si)
{
    if (si->enter.entry.args[0] == 0)
    {
        nt_strcat(sc, "NULL");
        return;
    }

    nt_str_sysdump_str(sc, si->pid, si->enter.entry.args[0]);
}

int nt_syscall_decode_execve(const nt_syscall_info_t* si, int op, char* buff, size_t size)
{
    nt_strcat_t sc = NT_STRCAT_INIT(buff, size);
    if (op == PTRACE_SYSCALL_INFO_ENTRY)
    {
        nt_strcat(&sc, "(");
        s_decode_execve_arg0(&sc, si);
        nt_strcat(&sc, ")");
    }
    if (op == PTRACE_SYSCALL_INFO_EXIT)
    {
        nt_strcat(&sc, " = %d", (int)si->leave.exit.rval);
    }
    return sc.size;
}
