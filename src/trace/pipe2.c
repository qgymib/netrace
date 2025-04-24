#define _GNU_SOURCE
#include <fcntl.h>
#include <unistd.h>
#include "utils/syscall.h"
#include "__init__.h"

static void s_decode_pipe2_arg0(nt_strcat_t* sc, const nt_syscall_info_t* si)
{
    int pipefd[2];
    if (si->enter.entry.args[0] == 0)
    {
        nt_strcat(sc, "NULL");
        return;
    }

    nt_syscall_getdata(si->pid, si->enter.entry.args[0], pipefd, sizeof(pipefd));
    nt_strcat(sc, "{[0]=%d, [1]=%d}, ", pipefd[0], pipefd[1]);
}

static void s_decode_pipe2_arg1(nt_strcat_t* sc, const nt_syscall_info_t* si)
{
#define CHECK_FLAG(flag)                                                                           \
    do                                                                                             \
    {                                                                                              \
        if (flags & flag)                                                                          \
        {                                                                                          \
            nt_strcat(sc, "%s%s", flag_count++ == 0 ? "" : "|", #flag);                            \
            flags &= ~flag;                                                                        \
        }                                                                                          \
    } while (0)

    int    flags = si->enter.entry.args[1];
    size_t flag_count = 0;

    CHECK_FLAG(O_CLOEXEC);
    CHECK_FLAG(O_DIRECT);
    CHECK_FLAG(O_NONBLOCK);
#if defined(O_NOTIFICATION_PIPE)
    CHECK_FLAG(O_NOTIFICATION_PIPE);
#endif

    if (flag_count == 0)
    {
        nt_strcat(sc, "%d", flags);
    }
    else if (flags != 0)
    {
        nt_strcat(sc, "|%x", flags);
    }

#undef CHECK_FLAG
}

int nt_syscall_decode_pipe2(const nt_syscall_info_t* si, int op, char* buff, size_t size)
{
    nt_strcat_t sc = NT_STRCAT_INIT(buff, size);
    if (op != PTRACE_SYSCALL_INFO_EXIT)
    {
        return 0;
    }

    nt_strcat(&sc, "(");
    s_decode_pipe2_arg0(&sc, si);
    s_decode_pipe2_arg1(&sc, si);
    nt_strcat(&sc, ") = %d", (int)si->leave.exit.rval);

    return sc.size;
}
