#include <fcntl.h>
#include "utils/defs.h"
#include "utils/str.h"
#include "utils/syscall.h"
#include "__init__.h"

typedef struct fcntl_cmd
{
    int         cmd;                                                /* Command ID. */
    const char* name;                                               /* Command name. */
    void (*decode_p)(nt_strcat_t* sc, const nt_syscall_info_t* si); /* Parameter decoder. */
    void (*decode_r)(nt_strcat_t* sc, const nt_syscall_info_t* si); /* Return value decoder. */
} fcntl_cmd_t;

static void s_decode_fcntl_int(nt_strcat_t* sc, const nt_syscall_info_t* si)
{
    int v = (int)si->enter.entry.args[2];
    nt_strcat(sc, "%d", v);
}

static void s_decode_fcntl_flock(nt_strcat_t* sc, const nt_syscall_info_t* si)
{
    struct flock f;
    if (si->enter.entry.args[2] == 0)
    {
        nt_strcat(sc, "NULL");
        return;
    }

    nt_syscall_getdata(si->pid, si->enter.entry.args[2], &f, sizeof(f));
    nt_strcat(sc, "{type=%d, whence=%d, start=%ld, len=%ld, pid=%d}, ", f.l_type, f.l_whence,
              (long)f.l_start, (long)f.l_len, (int)f.l_pid);
}

static void s_decode_fcntl_getfd_r(nt_strcat_t* sc, const nt_syscall_info_t* si)
{
    if (si->leave.exit.is_error)
    {
        nt_strcat_ret(sc, si->leave.exit.rval, 1);
        return;
    }

    nt_bitdecoder_t bd = NT_BITDECODER_INIT(si->leave.exit.rval, sc);
    NT_BITDECODER_DECODE(&bd, FD_CLOEXEC);
    NT_BITDECODER_FINISH(&bd);
}

static void s_decode_fcntl_setfd_p(nt_strcat_t* sc, const nt_syscall_info_t* si)
{
    nt_bitdecoder_t bd = NT_BITDECODER_INIT(si->enter.entry.args[2], sc);
    NT_BITDECODER_DECODE(&bd, FD_CLOEXEC);
    NT_BITDECODER_FINISH(&bd);
}

static void s_decode_fcntl_getfl_r(nt_strcat_t* sc, const nt_syscall_info_t* si)
{
    if (si->leave.exit.is_error)
    {
        nt_strcat_ret(sc, si->leave.exit.rval, 1);
        return;
    }

    int flags = (int)si->leave.exit.rval;
    nt_strcat(sc, "0x%x (", flags);

    nt_bitdecoder_t bd = NT_BITDECODER_INIT(flags, sc);
    /* Access modes */
    NT_BITDECODER_DECODE(&bd, O_RDONLY);
    NT_BITDECODER_DECODE(&bd, O_WRONLY);
    NT_BITDECODER_DECODE(&bd, O_RDWR);
    /* Creation and file status flags */
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

    nt_strcat(sc, ")");
}

static const fcntl_cmd_t s_fcntl_cmds[] = {
    { F_DUPFD,         "F_DUPFD",         s_decode_fcntl_int,     NULL                   },
    { F_DUPFD_CLOEXEC, "F_DUPFD_CLOEXEC", s_decode_fcntl_int,     NULL                   },
    { F_GETFD,         "F_GETFD",         NULL,                   s_decode_fcntl_getfd_r },
    { F_SETFD,         "F_SETFD",         s_decode_fcntl_setfd_p, NULL                   },
    { F_GETFL,         "F_GETFL",         NULL,                   s_decode_fcntl_getfl_r },
    { F_SETFL,         "F_SETFL",         s_decode_fcntl_int,     NULL                   },
    { F_SETLK,         "F_SETLK",         s_decode_fcntl_flock,   NULL                   },
    { F_SETLKW,        "F_SETLKW",        s_decode_fcntl_flock,   NULL                   },
    { F_GETLK,         "F_GETLK",         s_decode_fcntl_flock,   NULL                   },
    { F_GETOWN,        "F_GETOWN",        NULL,                   NULL                   },
    { F_SETOWN,        "F_SETOWN",        s_decode_fcntl_int,     NULL                   },
};

static void s_decode_fcntl_fd(nt_strcat_t* sc, const nt_syscall_info_t* si)
{
    int fd = si->enter.entry.args[0];
    nt_strcat(sc, "%d, ", fd);
}

static const fcntl_cmd_t* s_decode_fcntl_cmd(nt_strcat_t* sc, const nt_syscall_info_t* si)
{
    size_t             i;
    const fcntl_cmd_t* entry = NULL;
    int                cmd = si->enter.entry.args[1];

    for (i = 0; i < ARRAY_SIZE(s_fcntl_cmds); i++)
    {
        if (s_fcntl_cmds[i].cmd == cmd)
        {
            entry = &s_fcntl_cmds[i];
            break;
        }
    }

    if (entry == NULL)
    {
        nt_strcat(sc, "%d", cmd);
        return NULL;
    }

    nt_strcat(sc, "%s", entry->name);
    if (entry->decode_p != NULL)
    {
        nt_strcat(sc, ", ");
        entry->decode_p(sc, si);
    }

    return entry;
}

int nt_syscall_decode_fcntl(const nt_syscall_info_t* si, int op, char* buff, size_t size)
{
    const fcntl_cmd_t* cmd = NULL;
    nt_strcat_t        sc = NT_STRCAT_INIT(buff, size);
    if (op != PTRACE_SYSCALL_INFO_EXIT)
    {
        return 0;
    }
    nt_strcat(&sc, "(");
    s_decode_fcntl_fd(&sc, si);
    if ((cmd = s_decode_fcntl_cmd(&sc, si)) == NULL || cmd->decode_r == NULL)
    {
        nt_strcat(&sc, ") = %d", (int)si->leave.exit.rval);
        goto FINISH;
    }

    nt_strcat(&sc, ") = ");
    cmd->decode_r(&sc, si);

FINISH:
    return sc.size;
}
