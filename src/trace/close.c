#include <stdio.h>
#include "__init__.h"

int nt_syscall_decode_close(const nt_syscall_info_t* si, char* buff, size_t size)
{
    return snprintf(buff, size, "(%d) = %d", (int)si->enter.entry.args[0],
                    (int)si->leave.exit.rval);
}
