#include <stdio.h>
#include <sys/syscall.h>
#include "__init__.h"

#if defined(SYS_dup2)

int nt_syscall_decode_dup2(const nt_syscall_info_t* si, int op, char* buff, size_t size)
{
    if (op == PTRACE_SYSCALL_INFO_EXIT)
    {
        return snprintf(buff, size, "(%d, %d) = %d", (int)si->enter.entry.args[0],
                        (int)si->enter.entry.args[1], (int)si->leave.exit.rval);
    }
    return 0;
}

#endif
