#include "utils/defs.h"
#include "utils/syscall.h"
#include "__init__.h"

static void s_decode_pread64_arg0(nt_strcat_t* sc, const nt_syscall_info_t* si)
{
    int fd = si->enter.entry.args[0];
    nt_strcat(sc, "%d, ", fd);
}

static void s_decode_pread64_arg1(nt_strcat_t* sc, const nt_syscall_info_t* si)
{
    char buff[32];
    if (si->enter.entry.args[1] == 0)
    {
        nt_strcat(sc, "NULL, ");
        return;
    }
    if (si->leave.exit.rval <= 0)
    {
        nt_strcat(sc, "\"\", ");
        return;
    }

    size_t read_sz = NT_MIN(sizeof(buff), (size_t)si->leave.exit.rval);
    nt_syscall_getdata(si->pid, si->enter.entry.args[1], buff, read_sz);
    nt_strcat_dump(sc, buff, read_sz);
    if (read_sz < (size_t)si->leave.exit.rval)
    {
        nt_strcat(sc, "...");
    }
    nt_strcat(sc, ", ");
}

static void s_decode_pread64_arg2(nt_strcat_t* sc, const nt_syscall_info_t* si)
{
    size_t count = si->enter.entry.args[2];
    nt_strcat(sc, "%zu, ", count);
}

static void s_decode_pread64_arg3(nt_strcat_t* sc, const nt_syscall_info_t* si)
{
    off_t offset = si->enter.entry.args[3];
    nt_strcat(sc, "%ld", (long)offset);
}

int nt_syscall_decode_pread64(const nt_syscall_info_t* si, int op, char* buff, size_t size)
{
    nt_strcat_t sc = NT_STRCAT_INIT(buff, size);
    if (op == PTRACE_SYSCALL_INFO_EXIT)
    {
        nt_strcat(&sc, "(");
        s_decode_pread64_arg0(&sc, si);
        s_decode_pread64_arg1(&sc, si);
        s_decode_pread64_arg2(&sc, si);
        s_decode_pread64_arg3(&sc, si);
        nt_strcat(&sc, ") = %ld", (long)si->leave.exit.rval);
    }
    return sc.size;
}
