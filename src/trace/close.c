#include <stdio.h>
#include "__init__.h"

int nt_syscall_decode_close(const nt_syscall_info_t* si, int op, char* buff, size_t size)
{
    nt_strcat_t sc = NT_STRCAT_INIT(buff, size);
    if (op != PTRACE_SYSCALL_INFO_EXIT)
    {
        return 0;
    }

    nt_strcat(&sc, "(%d) = ", (int)si->enter.entry.args[0]);
    nt_strcat_ret(&sc, si->leave.exit.rval, si->leave.exit.is_error);

    return sc.size;
}
