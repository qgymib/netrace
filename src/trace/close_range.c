#include <unistd.h>
#include "__init__.h"

static void s_decode_close_range_arg2(nt_strcat_t* sc, const nt_syscall_info_t* si)
{
    int flags = si->enter.entry.args[2];
    nt_strcat(sc, "%d", flags);
}

int nt_syscall_decode_close_range(const nt_syscall_info_t* si, int op, char* buff, size_t size)
{
    nt_strcat_t sc = NT_STRCAT_INIT(buff, size);
    if (op == PTRACE_SYSCALL_INFO_EXIT)
    {
        unsigned int first = si->enter.entry.args[0];
        unsigned int last = si->enter.entry.args[1];
        nt_strcat(&sc, "(%u, %u, ", first, last);
        s_decode_close_range_arg2(&sc, si);
        nt_strcat(&sc, ") = %d", (int)si->leave.exit.rval);
    }

    return sc.size;
}
