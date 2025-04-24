#include <fcntl.h>
#include "utils/defs.h"
#include "utils/syscall.h"
#include "__init__.h"

typedef struct fcntl_cmd
{
    int         cmd;
    const char* name;
    void (*decode)(nt_strcat_t* sc, const nt_syscall_info_t* si);
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

static fcntl_cmd_t s_fcntl_cmds[] = {
    { F_DUPFD,         "F_DUPFD",         s_decode_fcntl_int   },
    { F_DUPFD_CLOEXEC, "F_DUPFD_CLOEXEC", s_decode_fcntl_int   },
    { F_GETFD,         "F_GETFD",         NULL                 },
    { F_SETFD,         "F_SETFD",         s_decode_fcntl_int   },
    { F_GETFL,         "F_GETFL",         NULL                 },
    { F_SETFL,         "F_SETFL",         s_decode_fcntl_int   },
    { F_SETLK,         "F_SETLK",         s_decode_fcntl_flock },
    { F_SETLKW,        "F_SETLKW",        s_decode_fcntl_flock },
    { F_GETLK,         "F_GETLK",         s_decode_fcntl_flock },
    { F_GETOWN,        "F_GETOWN",        NULL                 },
    { F_SETOWN,        "F_SETOWN",        s_decode_fcntl_int   },
};

static void s_decode_fcntl_fd(nt_strcat_t* sc, const nt_syscall_info_t* si)
{
    int fd = si->enter.entry.args[0];
    nt_strcat(sc, "%d, ", fd);
}

static void s_decode_fcntl_cmd(nt_strcat_t* sc, const nt_syscall_info_t* si)
{
    size_t       i;
    fcntl_cmd_t* entry = NULL;
    int          cmd = si->enter.entry.args[1];

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
        return;
    }

    nt_strcat(sc, "%s", entry->name);
    if (entry->decode != NULL)
    {
        nt_strcat(sc, ", ");
        entry->decode(sc, si);
    }
}

int nt_syscall_decode_fcntl(const nt_syscall_info_t* si, int op, char* buff, size_t size)
{
    nt_strcat_t sc = NT_STRCAT_INIT(buff, size);
    if (op != PTRACE_SYSCALL_INFO_EXIT)
    {
        return 0;
    }
    nt_strcat(&sc, "(");
    s_decode_fcntl_fd(&sc, si);
    s_decode_fcntl_cmd(&sc, si);
    nt_strcat(&sc, ") = %d", (int)si->leave.exit.rval);
    return sc.size;
}
