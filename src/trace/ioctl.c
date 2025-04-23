#include <sys/ioctl.h>
#include "utils/defs.h"
#include "utils/syscall.h"
#include "__init__.h"

typedef struct ioctl_request
{
    unsigned long request;
    const char*   name;
    void (*decode)(nt_strcat_t* sc, const nt_syscall_info_t* si);
} ioctl_request_t;

static void s_ioctl_decode_int(nt_strcat_t* sc, const nt_syscall_info_t* si)
{
    int val = 0;
    nt_syscall_getdata(si->pid, si->enter.entry.args[2], &val, sizeof(val));
    nt_strcat(sc, "%d", val);
}

static ioctl_request_t s_ioctl_requests[] = {
    { TCGETS,             "TCGETS",             NULL               },
    { TCSETS,             "TCSETS",             NULL               },
    { TCSETSW,            "TCSETSW",            NULL               },
    { TCSETSF,            "TCSETSF",            NULL               },
    { TCGETA,             "TCGETA",             NULL               },
    { TCSETA,             "TCSETA",             NULL               },
    { TCSETAW,            "TCSETAW",            NULL               },
    { TCSETAF,            "TCSETAF",            NULL               },
    { TCSBRK,             "TCSBRK",             NULL               },
    { TCXONC,             "TCXONC",             NULL               },
    { TCFLSH,             "TCFLSH",             NULL               },
    { TIOCEXCL,           "TIOCEXCL",           NULL               },
    { TIOCNXCL,           "TIOCNXCL",           NULL               },
    { TIOCSCTTY,          "TIOCSCTTY",          NULL               },
    { TIOCGPGRP,          "TIOCGPGRP",          NULL               },
    { TIOCSPGRP,          "TIOCSPGRP",          NULL               },
    { TIOCOUTQ,           "TIOCOUTQ",           NULL               },
    { TIOCSTI,            "TIOCSTI",            NULL               },
    { TIOCGWINSZ,         "TIOCGWINSZ",         NULL               },
    { TIOCSWINSZ,         "TIOCSWINSZ",         NULL               },
    { TIOCMGET,           "TIOCMGET",           NULL               },
    { TIOCMBIS,           "TIOCMBIS",           NULL               },
    { TIOCMBIC,           "TIOCMBIC",           NULL               },
    { TIOCMSET,           "TIOCMSET",           NULL               },
    { TIOCGSOFTCAR,       "TIOCGSOFTCAR",       NULL               },
    { TIOCSSOFTCAR,       "TIOCSSOFTCAR",       NULL               },
    { FIONREAD,           "FIONREAD",           s_ioctl_decode_int },
    { TIOCINQ,            "TIOCINQ",            NULL               },
    { TIOCLINUX,          "TIOCLINUX",          NULL               },
    { TIOCCONS,           "TIOCCONS",           NULL               },
    { TIOCGSERIAL,        "TIOCGSERIAL",        NULL               },
    { TIOCSSERIAL,        "TIOCSSERIAL",        NULL               },
    { TIOCPKT,            "TIOCPKT",            NULL               },
    { FIONBIO,            "FIONBIO",            NULL               },
    { TIOCNOTTY,          "TIOCNOTTY",          NULL               },
    { TIOCSETD,           "TIOCSETD",           NULL               },
    { TIOCGETD,           "TIOCGETD",           NULL               },
    { TCSBRKP,            "TCSBRKP",            NULL               },
    { TIOCSBRK,           "TIOCSBRK",           NULL               },
    { TIOCCBRK,           "TIOCCBRK",           NULL               },
    { TIOCGSID,           "TIOCGSID",           NULL               },
    { TIOCGRS485,         "TIOCGRS485",         NULL               },
    { TIOCSRS485,         "TIOCSRS485",         NULL               },
    { TIOCGPTN,           "TIOCGPTN",           NULL               },
    { TIOCSPTLCK,         "TIOCSPTLCK",         NULL               },
    { TIOCGDEV,           "TIOCGDEV",           NULL               },
    { TCGETX,             "TCGETX",             NULL               },
    { TCSETX,             "TCSETX",             NULL               },
    { TCSETXF,            "TCSETXF",            NULL               },
    { TCSETXW,            "TCSETXW",            NULL               },
    { TIOCSIG,            "TIOCSIG",            NULL               },
    { TIOCVHANGUP,        "TIOCVHANGUP",        NULL               },
    { TIOCGPKT,           "TIOCGPKT",           NULL               },
    { TIOCGPTLCK,         "TIOCGPTLCK",         NULL               },
    { TIOCGEXCL,          "TIOCGEXCL",          NULL               },
    { TIOCGPTPEER,        "TIOCGPTPEER",        NULL               },
    { FIONCLEX,           "FIONCLEX",           NULL               },
    { FIOCLEX,            "FIOCLEX",            NULL               },
    { FIOASYNC,           "FIOASYNC",           NULL               },
    { TIOCSERCONFIG,      "TIOCSERCONFIG",      NULL               },
    { TIOCSERGWILD,       "TIOCSERGWILD",       NULL               },
    { TIOCSERSWILD,       "TIOCSERSWILD",       NULL               },
    { TIOCGLCKTRMIOS,     "TIOCGLCKTRMIOS",     NULL               },
    { TIOCSLCKTRMIOS,     "TIOCSLCKTRMIOS",     NULL               },
    { TIOCSERGSTRUCT,     "TIOCSERGSTRUCT",     NULL               },
    { TIOCSERGETLSR,      "TIOCSERGETLSR",      NULL               },
    { TIOCSERGETMULTI,    "TIOCSERGETMULTI",    NULL               },
    { TIOCSERSETMULTI,    "TIOCSERSETMULTI",    NULL               },
    { TIOCMIWAIT,         "TIOCMIWAIT",         NULL               },
    { TIOCGICOUNT,        "TIOCGICOUNT",        NULL               },
    { FIOQSIZE,           "FIOQSIZE",           NULL               },
    { TIOCPKT_DATA,       "TIOCPKT_DATA",       NULL               },
    { TIOCPKT_FLUSHREAD,  "TIOCPKT_FLUSHREAD",  NULL               },
    { TIOCPKT_FLUSHWRITE, "TIOCPKT_FLUSHWRITE", NULL               },
    { TIOCPKT_STOP,       "TIOCPKT_STOP",       NULL               },
    { TIOCPKT_START,      "TIOCPKT_START",      NULL               },
    { TIOCPKT_NOSTOP,     "TIOCPKT_NOSTOP",     NULL               },
    { TIOCPKT_DOSTOP,     "TIOCPKT_DOSTOP",     NULL               },
    { TIOCPKT_IOCTL,      "TIOCPKT_IOCTL",      NULL               },
    { TIOCSER_TEMT,       "TIOCSER_TEMT",       NULL               },
};

static void s_decode_ioctl_arg0(nt_strcat_t* sc, const nt_syscall_info_t* si)
{
    int fd = si->enter.entry.args[0];
    nt_strcat(sc, "%d, ", fd);
}

static void s_decode_ioctl_arg1(nt_strcat_t* sc, const nt_syscall_info_t* si)
{
    size_t                 i;
    const ioctl_request_t* r = NULL;
    unsigned long          request = si->enter.entry.args[1];

    for (i = 0; i < ARRAY_SIZE(s_ioctl_requests); i++)
    {
        const ioctl_request_t* req = &s_ioctl_requests[i];
        if (req->request == request)
        {
            r = req;
            break;
        }
    }

    if (r == NULL)
    {
        nt_strcat(sc, "%lu", request);
        return;
    }

    nt_strcat(sc, "%s", r->name);
    if (r->decode != NULL)
    {
        nt_strcat(sc, ", ");
        r->decode(sc, si);
    }
}

int nt_syscall_decode_ioctl(const nt_syscall_info_t* si, int op, char* buff, size_t size)
{
    nt_strcat_t sc = NT_STRCAT_INIT(buff, size);
    if (op == PTRACE_SYSCALL_INFO_EXIT)
    {
        nt_strcat(&sc, "(");
        s_decode_ioctl_arg0(&sc, si);
        s_decode_ioctl_arg1(&sc, si);
        nt_strcat(&sc, ") = %d", (int)si->leave.exit.rval);
    }
    return sc.size;
}
