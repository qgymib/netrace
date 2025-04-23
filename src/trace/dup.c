#include <stdio.h>
#include "__init__.h"

int nt_syscall_decode_dup(const nt_syscall_info_t* si, int op, char* buff, size_t size)
{
    if (op == PTRACE_SYSCALL_INFO_EXIT)
    {
        return snprintf(buff, size, "(%d) = %d", (int)si->enter.entry.args[0],
                        (int)si->leave.exit.rval);
    }
    return 0;
}
