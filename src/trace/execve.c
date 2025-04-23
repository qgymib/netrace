#include <string.h>
#include "utils/defs.h"
#include "utils/syscall.h"
#include "utils/str.h"
#include "__init__.h"

static void s_decode_execve_arg0(nt_strcat_t* sc, const nt_syscall_info_t* si)
{
    char buff[32];
    if (si->enter.entry.args[0] == 0)
    {
        nt_strcat(sc, "NULL");
        return;
    }

    int ret = nt_syscall_get_string(si->pid, si->enter.entry.args[0], buff, sizeof(buff));
    if (ret < 0)
    {
        nt_strcat(sc, "%s", nt_strerrorname(NT_RAWERR(ret)));
        return;
    }

    size_t dump_sz = ((size_t)ret >= sizeof(buff)) ? (sizeof(buff) - 1) : (size_t)ret;
    nt_strcat_dump(sc, buff, dump_sz);
    if ((size_t)ret >= sizeof(buff))
    {
        nt_strcat(sc, "...");
    }
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
