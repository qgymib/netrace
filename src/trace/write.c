#include <stdio.h>
#include "utils/defs.h"
#include "utils/str.h"
#include "utils/syscall.h"
#include "__init__.h"
#include "config.h"

static void s_decode_write_arg0(nt_strcat_t* sc, const nt_syscall_info_t* si)
{
    int fd = si->enter.entry.args[0];
    nt_strcat(sc, "%d, ", fd);
}

static void s_decode_write_arg1(nt_strcat_t* sc, const nt_syscall_info_t* si)
{
    if (si->enter.entry.args[1] == 0)
    {
        nt_strcat(sc, "NULL, ");
        return;
    }

    nt_str_sysdump(sc, si->pid, si->enter.entry.args[1], si->enter.entry.args[2], NT_MAX_DUMP_SIZE);
    nt_strcat(sc, ", ");
}

static void s_decode_write_arg2(nt_strcat_t* sc, const nt_syscall_info_t* si)
{
    size_t nbyte = si->enter.entry.args[2];
    nt_strcat(sc, "%zu", nbyte);
}

int nt_syscall_decode_write(const nt_syscall_info_t* si, int op, char* buff, size_t size)
{
    nt_strcat_t sc = NT_STRCAT_INIT(buff, size);
    if (op == PTRACE_SYSCALL_INFO_EXIT)
    {
        nt_strcat(&sc, "(");
        s_decode_write_arg0(&sc, si);
        s_decode_write_arg1(&sc, si);
        s_decode_write_arg2(&sc, si);
        nt_strcat(&sc, ") = %ld", (long)si->leave.exit.rval);
    }
    return sc.size;
}
