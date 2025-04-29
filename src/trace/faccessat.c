#include <fcntl.h>
#include "utils/str.h"
#include "__init__.h"
#include "config.h"

static void s_decode_faccessat_arg0(nt_strcat_t* sc, const nt_syscall_info_t* si)
{
    int dirfd = si->enter.entry.args[0];
    if (dirfd == AT_FDCWD)
    {
        nt_strcat(sc, "AT_FDCWD, ");
    }
    else
    {
        nt_strcat(sc, "%d, ", dirfd);
    }
}

static void s_decode_faccessat_arg1(nt_strcat_t* sc, const nt_syscall_info_t* si)
{
    nt_str_sysdump_str(sc, si->pid, si->enter.entry.args[1], NT_MAX_DUMP_SIZE);
    nt_strcat(sc, ", ");
}

static void s_decode_faccessat_arg2(nt_strcat_t* sc, const nt_syscall_info_t* si)
{
    int             mode = si->enter.entry.args[2];
    nt_bitdecoder_t bd = NT_BITDECODER_INIT(mode, sc);
    NT_BITDECODER_DECODE(&bd, R_OK);
    NT_BITDECODER_DECODE(&bd, W_OK);
    NT_BITDECODER_DECODE(&bd, X_OK);
    NT_BITDECODER_FINISH(&bd);
    nt_strcat(sc, ", ");
}

static void s_decode_faccessat_arg3(nt_strcat_t* sc, const nt_syscall_info_t* si)
{
    int             flags = si->enter.entry.args[3];
    nt_bitdecoder_t bd = NT_BITDECODER_INIT(flags, sc);
    NT_BITDECODER_DECODE(&bd, AT_EACCESS);
    NT_BITDECODER_DECODE(&bd, AT_SYMLINK_NOFOLLOW);
    NT_BITDECODER_FINISH(&bd);
}

int nt_syscall_decode_faccessat(const nt_syscall_info_t* si, int op, char* buff, size_t size)
{
    nt_strcat_t sc = NT_STRCAT_INIT(buff, size);
    if (op != PTRACE_SYSCALL_INFO_EXIT)
    {
        return 0;
    }
    nt_strcat(&sc, "(");
    s_decode_faccessat_arg0(&sc, si);
    s_decode_faccessat_arg1(&sc, si);
    s_decode_faccessat_arg2(&sc, si);
    s_decode_faccessat_arg3(&sc, si);
    nt_strcat(&sc, ") = ");
    nt_strcat_ret(&sc, si->leave.exit.rval, si->leave.exit.is_error);
    return sc.size;
}
