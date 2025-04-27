#include <sys/uio.h>
#include "utils/str.h"
#include "__init__.h"

static void s_decode_preadv2_arg0(nt_strcat_t* sc, const nt_syscall_info_t* si)
{
    int fd = si->enter.entry.args[0];
    nt_strcat(sc, "%d, ", fd);
}

static void s_decode_preadv2_arg1(nt_strcat_t* sc, const nt_syscall_info_t* si)
{
    uintptr_t iov = si->enter.entry.args[1];
    int       iovcnt = si->enter.entry.args[2];
    if (iov == 0)
    {
        nt_strcat(sc, "NULL, ");
        return;
    }
    if (si->leave.exit.rval <= 0)
    {
        nt_strcat(sc, "\"\", ");
        return;
    }

    nt_str_sysdump_iovec(sc, si->pid, iov, iovcnt, si->leave.exit.rval);
    nt_strcat(sc, ", ");
}

static void s_decode_preadv2_arg2(nt_strcat_t* sc, const nt_syscall_info_t* si)
{
    int iovcnt = si->enter.entry.args[2];
    nt_strcat(sc, "%d, ", iovcnt);
}

static void s_decode_preadv2_arg3(nt_strcat_t* sc, const nt_syscall_info_t* si)
{
    off_t offset = si->enter.entry.args[3];
    nt_strcat(sc, "%ld, ", (long)offset);
}

static void s_decode_preadv2_arg4(nt_strcat_t* sc, const nt_syscall_info_t* si)
{
    int             flags = si->enter.entry.args[4];
    nt_bitdecoder_t bd = NT_BITDECODER_INIT(flags, sc);
#if defined(RWF_DSYNC)
    NT_BITDECODER_DECODE(&bd, RWF_DSYNC);
#endif
#if defined(RWF_HIPRI)
    NT_BITDECODER_DECODE(&bd, RWF_HIPRI);
#endif
#if defined(RWF_SYNC)
    NT_BITDECODER_DECODE(&bd, RWF_SYNC);
#endif
#if defined(RWF_NOWAIT)
    NT_BITDECODER_DECODE(&bd, RWF_NOWAIT);
#endif
#if defined(RWF_APPEND)
    NT_BITDECODER_DECODE(&bd, RWF_APPEND);
#endif
    NT_BITDECODER_FINISH(&bd);
}

int nt_syscall_decode_preadv2(const nt_syscall_info_t* si, int op, char* buff, size_t size)
{
    nt_strcat_t sc = NT_STRCAT_INIT(buff, size);
    if (op != PTRACE_SYSCALL_INFO_EXIT)
    {
        return 0;
    }
    nt_strcat(&sc, "(");
    s_decode_preadv2_arg0(&sc, si);
    s_decode_preadv2_arg1(&sc, si);
    s_decode_preadv2_arg2(&sc, si);
    s_decode_preadv2_arg3(&sc, si);
    s_decode_preadv2_arg4(&sc, si);
    nt_strcat(&sc, ") = ");
    nt_strcat_ret(&sc, si->leave.exit.rval, si->leave.exit.is_error);
    return sc.size;
}
