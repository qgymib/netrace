#include "utils/defs.h"
#include "utils/syscall.h"
#include "utils/str.h"
#include "__init__.h"

typedef struct shutdown_how
{
    int   how;
    char* name;
} shutdown_how_t;

static const shutdown_how_t s_shutdown_how[] = {
    { SHUT_RD,   "SHUT_RD"   },
    { SHUT_WR,   "SHUT_WR"   },
    { SHUT_RDWR, "SHUT_RDWR" },
};

static void s_decode_shutdown_arg0(nt_strcat_t* sc, const nt_syscall_info_t* si)
{
    int sockfd = si->enter.entry.args[0];
    nt_strcat(sc, "%d, ", sockfd);
}

static void s_decode_shutdown_arg1(nt_strcat_t* sc, const nt_syscall_info_t* si)
{
    size_t i;
    int    how = si->enter.entry.args[1];
    for (i = 0; i < ARRAY_SIZE(s_shutdown_how); i++)
    {
        if (s_shutdown_how[i].how == how)
        {
            nt_strcat(sc, "%s", s_shutdown_how[i].name);
            return;
        }
    }
    nt_strcat(sc, "%d", how);
}

int nt_syscall_decode_shutdown(const nt_syscall_info_t* si, int op, char* buff, size_t size)
{
    nt_strcat_t sc = NT_STRCAT_INIT(buff, size);
    if (op != PTRACE_SYSCALL_INFO_EXIT)
    {
        return 0;
    }
    nt_strcat(&sc, "(");
    s_decode_shutdown_arg0(&sc, si);
    s_decode_shutdown_arg1(&sc, si);
    nt_strcat(&sc, ") = ");
    nt_strcat_ret(&sc, si->leave.exit.rval, si->leave.exit.is_error);
    return sc.size;
}
