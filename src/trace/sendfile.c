#include "utils/str.h"
#include "utils/syscall.h"
#include "__init__.h"

static void s_decode_sendfile_arg0(nt_strcat_t* sc, const nt_syscall_info_t* si)
{
    int out_fd = si->enter.entry.args[0];
    nt_strcat(sc, "%d, ", out_fd);
}

static void s_decode_sendfile_arg1(nt_strcat_t* sc, const nt_syscall_info_t* si)
{
    int in_fd = si->enter.entry.args[1];
    nt_strcat(sc, "%d, ", in_fd);
}

static void s_decode_sendfile_arg2(nt_strcat_t* sc, const nt_syscall_info_t* si)
{
    if (si->enter.entry.args[2] == 0)
    {
        nt_strcat(sc, "NULL, ");
        return;
    }

    off_t offset;
    nt_syscall_getdata(si->pid, si->enter.entry.args[2], &offset, sizeof(offset));
    nt_strcat(sc, "%ld, ", (long)offset);
}

static void s_decode_sendfile_arg3(nt_strcat_t* sc, const nt_syscall_info_t* si)
{
    size_t count = si->enter.entry.args[3];
    nt_strcat(sc, "%ld, ", (long)count);
}

int nt_syscall_decode_sendfile(const nt_syscall_info_t* si, int op, char* buff, size_t size)
{
    nt_strcat_t sc = NT_STRCAT_INIT(buff, size);
    if (op != PTRACE_SYSCALL_INFO_EXIT)
    {
        return 0;
    }
    nt_strcat(&sc, "(");
    s_decode_sendfile_arg0(&sc, si);
    s_decode_sendfile_arg1(&sc, si);
    s_decode_sendfile_arg2(&sc, si);
    s_decode_sendfile_arg3(&sc, si);
    nt_strcat(&sc, ") = ");
    nt_strcat_ret(&sc, si->leave.exit.rval, si->leave.exit.is_error);
    return sc.size;
}
