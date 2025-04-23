#include "utils/defs.h"
#include "utils/socket.h"
#include "__init__.h"

#include <utils/syscall.h>

typedef struct optname_pair
{
    int         level;
    int         optname;
    const char* name;
    void (*decode)(nt_strcat_t* sc, const nt_syscall_info_t* si, socklen_t optlen);
} optname_pair_t;

static void s_decode_setsockopt_timeval(nt_strcat_t* sc, const nt_syscall_info_t* si,
                                        socklen_t optlen)
{
    struct timeval tv;
    nt_syscall_getdata(si->pid, si->enter.entry.args[3], &tv, optlen);
    nt_strcat(sc, "{tv_sec=%ld, tv_usec=%ld}", (long)tv.tv_sec, (long)tv.tv_usec);
}

static void s_decode_setsockopt_int(nt_strcat_t* sc, const nt_syscall_info_t* si, socklen_t optlen)
{
    int val = 0;
    nt_syscall_getdata(si->pid, si->enter.entry.args[3], &val, optlen);
    nt_strcat(sc, "%d", val);
}

static void s_decode_setsockopt_unknown(nt_strcat_t* sc, const nt_syscall_info_t* si,
                                        socklen_t optlen)
{
    char   buff[32];
    size_t read_sz = NT_MIN(sizeof(buff), optlen);
    nt_syscall_getdata(si->pid, si->enter.entry.args[3], buff, read_sz);
    nt_strcat_dump(sc, buff, read_sz);
    if (read_sz < optlen)
    {
        nt_strcat(sc, "...");
    }
}

static optname_pair_t s_setsockopt_decode[] = {
    { SOL_SOCKET, SO_KEEPALIVE,   "SO_KEEPALIVE",   s_decode_setsockopt_int     },
    { SOL_SOCKET, SO_RCVTIMEO,    "SO_RCVTIMEO",    s_decode_setsockopt_timeval },
    { SOL_SOCKET, SO_SNDTIMEO,    "SO_SNDTIMEO",    s_decode_setsockopt_timeval },
    { SOL_SOCKET, SO_TIMESTAMP,   "SO_TIMESTAMP",   NULL                        },
    { SOL_SOCKET, SO_TIMESTAMPNS, "SO_TIMESTAMPNS", NULL                        },
};

static void s_decode_setsockopt_arg0(nt_strcat_t* sc, const nt_syscall_info_t* si)
{
    int sockfd = si->enter.entry.args[0];
    nt_strcat(sc, "%d, ", sockfd);
}

static void s_decode_setsockopt_arg1(nt_strcat_t* sc, const nt_syscall_info_t* si)
{
    int level = si->enter.entry.args[1];
    if (level == SOL_SOCKET)
    {
        nt_strcat(sc, "SOL_SOCKET, ");
        return;
    }
    nt_strcat(sc, "%d, ", level);
}

static void s_decode_setsockopt_arg2(nt_strcat_t* sc, const nt_syscall_info_t* si)
{
    int level = si->enter.entry.args[1];
    int optname = si->enter.entry.args[2];

    size_t i;
    for (i = 0; i < ARRAY_SIZE(s_setsockopt_decode); i++)
    {
        if (s_setsockopt_decode[i].level == level && s_setsockopt_decode[i].optname == optname)
        {
            nt_strcat(sc, "%s, ", s_setsockopt_decode[i].name);
            return;
        }
    }
    nt_strcat(sc, "%d, ", optname);
}

static void s_decode_setsockopt_arg3(nt_strcat_t* sc, const nt_syscall_info_t* si)
{
    int level = si->enter.entry.args[1];
    int optname = si->enter.entry.args[2];

    if (si->enter.entry.args[3] == 0)
    {
        nt_strcat(sc, "NULL, ");
        return;
    }

    size_t    i;
    socklen_t optlen = si->enter.entry.args[4];

    for (i = 0; i < ARRAY_SIZE(s_setsockopt_decode); i++)
    {
        if (s_setsockopt_decode[i].level == level && s_setsockopt_decode[i].optname == optname)
        {
            if (s_setsockopt_decode[i].decode != NULL)
            {
                s_setsockopt_decode[i].decode(sc, si, optlen);
                goto FINISH;
            }
            break;
        }
    }
    s_decode_setsockopt_unknown(sc, si, optlen);

FINISH:
    nt_strcat(sc, ", ");
}

static void s_decode_setsockopt_arg4(nt_strcat_t* sc, const nt_syscall_info_t* si)
{
    socklen_t optlen = si->enter.entry.args[4];
    nt_strcat(sc, "%u", (unsigned)optlen);
}

int nt_syscall_decode_setsockopt(const nt_syscall_info_t* si, int op, char* buff, size_t size)
{
    nt_strcat_t sc = NT_STRCAT_INIT(buff, size);
    if (op == PTRACE_SYSCALL_INFO_EXIT)
    {
        nt_strcat(&sc, "(");
        s_decode_setsockopt_arg0(&sc, si);
        s_decode_setsockopt_arg1(&sc, si);
        s_decode_setsockopt_arg2(&sc, si);
        s_decode_setsockopt_arg3(&sc, si);
        s_decode_setsockopt_arg4(&sc, si);
        nt_strcat(&sc, ") = %d", (int)si->leave.exit.rval);
    }
    return sc.size;
}
