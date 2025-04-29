#include <fcntl.h>
#include "utils/str.h"
#include "__init__.h"
#include "config.h"

static void s_decode_openat_arg0(nt_strcat_t* sc, const nt_syscall_info_t* si)
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

static void s_decode_openat_arg1(nt_strcat_t* sc, const nt_syscall_info_t* si)
{
    nt_str_sysdump_str(sc, si->pid, si->enter.entry.args[1], NT_MAX_DUMP_SIZE);
    nt_strcat(sc, ", ");
}

static void s_decode_openat_arg2(nt_strcat_t* sc, const nt_syscall_info_t* si)
{
    int             flags = si->enter.entry.args[2];
    nt_bitdecoder_t bd = NT_BITDECODER_INIT(flags, sc);
    NT_BITDECODER_DECODE(&bd, O_RDONLY);
    NT_BITDECODER_DECODE(&bd, O_WRONLY);
    NT_BITDECODER_DECODE(&bd, O_RDWR);
    NT_BITDECODER_DECODE(&bd, O_APPEND);
    NT_BITDECODER_DECODE(&bd, O_ASYNC);
    NT_BITDECODER_DECODE(&bd, O_CLOEXEC);
    NT_BITDECODER_DECODE(&bd, O_CREAT);
#if defined(O_DIRECT)
    NT_BITDECODER_DECODE(&bd, O_DIRECT);
#endif
    NT_BITDECODER_DECODE(&bd, O_DIRECTORY);
    NT_BITDECODER_DECODE(&bd, O_DSYNC);
    NT_BITDECODER_DECODE(&bd, O_EXCL);
#if defined(O_LARGEFILE)
    NT_BITDECODER_DECODE(&bd, O_LARGEFILE);
#endif
#if defined(O_NOATIME)
    NT_BITDECODER_DECODE(&bd, O_NOATIME);
#endif
    NT_BITDECODER_DECODE(&bd, O_NOCTTY);
    NT_BITDECODER_DECODE(&bd, O_NOFOLLOW);
    NT_BITDECODER_DECODE(&bd, O_NONBLOCK);
    NT_BITDECODER_DECODE(&bd, O_NDELAY);
#if defined(O_PATH)
    NT_BITDECODER_DECODE(&bd, O_PATH);
#endif
    NT_BITDECODER_DECODE(&bd, O_SYNC);
#if defined(O_TMPFILE)
    NT_BITDECODER_DECODE(&bd, O_TMPFILE);
#endif
    NT_BITDECODER_DECODE(&bd, O_TRUNC);
    NT_BITDECODER_FINISH(&bd);
}

int nt_syscall_decode_openat(const nt_syscall_info_t* si, int op, char* buff, size_t size)
{
    nt_strcat_t sc = NT_STRCAT_INIT(buff, size);
    if (op != PTRACE_SYSCALL_INFO_EXIT)
    {
        return 0;
    }
    nt_strcat(&sc, "(");
    s_decode_openat_arg0(&sc, si);
    s_decode_openat_arg1(&sc, si);
    s_decode_openat_arg2(&sc, si);
    nt_strcat(&sc, ") = ");
    nt_strcat_ret(&sc, si->leave.exit.rval, si->leave.exit.is_error);
    return sc.size;
}
