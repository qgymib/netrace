#include <stdio.h>
#include "__init__.h"

int nt_syscall_decode_getpid(const nt_syscall_info_t* si, int op, char* buff, size_t size)
{
    if (op != PTRACE_SYSCALL_INFO_EXIT)
    {
        return 0;
    }
    return snprintf(buff, size, "() = %ld", (long)si->leave.exit.rval);
}
