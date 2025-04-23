#include "__init__.h"

int nt_syscall_decode_clone(const nt_syscall_info_t* si, int op, char* buff, size_t size)
{
    nt_strcat_t sc = NT_STRCAT_INIT(buff, size);
    if (op == PTRACE_SYSCALL_INFO_ENTRY)
    {
        nt_strcat(&sc, "()");
    }
    else if (op == PTRACE_SYSCALL_INFO_EXIT)
    {
        nt_strcat(&sc, " = %ld", (long)si->leave.exit.rval);
    }
    return sc.size;
}
