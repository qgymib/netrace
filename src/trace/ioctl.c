#include <sys/ioctl.h>
#include "utils/defs.h"
#include "utils/syscall.h"
#include "__init__.h"

typedef struct ioctl_request
{
    unsigned long request;                                          /* Request ID. */
    const char*   name;                                             /* Request name. */
    void (*decode_p)(nt_strcat_t* sc, const nt_syscall_info_t* si); /* Parameter decoder. */
    void (*decode_r)(nt_strcat_t* sc, const nt_syscall_info_t* si); /* Return value decoder. */
} ioctl_request_t;

static void s_ioctl_decode_int_p(nt_strcat_t* sc, const nt_syscall_info_t* si)
{
    int val = 0;
    nt_syscall_getdata(si->pid, si->enter.entry.args[2], &val, sizeof(val));
    nt_strcat(sc, "%d", val);
}

static void s_ioctl_decode_int(nt_strcat_t* sc, const nt_syscall_info_t* si)
{
    nt_strcat(sc, "%d", (int)si->enter.entry.args[2]);
}

static void s_ioctl_decode_ret(nt_strcat_t* sc, const nt_syscall_info_t* si)
{
    nt_strcat_ret(sc, si->leave.exit.rval, si->leave.exit.is_error);
}

static const ioctl_request_t s_ioctl_requests[] = {
    { TCGETS,             "TCGETS",             NULL,                 s_ioctl_decode_ret },
    { TCSETS,             "TCSETS",             NULL,                 NULL               },
    { TCSETSW,            "TCSETSW",            NULL,                 NULL               },
    { TCSETSF,            "TCSETSF",            NULL,                 NULL               },
    { TCGETA,             "TCGETA",             NULL,                 NULL               },
    { TCSETA,             "TCSETA",             NULL,                 NULL               },
    { TCSETAW,            "TCSETAW",            NULL,                 NULL               },
    { TCSETAF,            "TCSETAF",            NULL,                 NULL               },
    { TCSBRK,             "TCSBRK",             NULL,                 NULL               },
    { TCXONC,             "TCXONC",             NULL,                 NULL               },
    { TCFLSH,             "TCFLSH",             s_ioctl_decode_int,   NULL               },
    { TIOCEXCL,           "TIOCEXCL",           NULL,                 NULL               },
    { TIOCNXCL,           "TIOCNXCL",           NULL,                 NULL               },
    { TIOCSCTTY,          "TIOCSCTTY",          NULL,                 NULL               },
    { TIOCGPGRP,          "TIOCGPGRP",          NULL,                 NULL               },
    { TIOCSPGRP,          "TIOCSPGRP",          NULL,                 NULL               },
    { TIOCOUTQ,           "TIOCOUTQ",           s_ioctl_decode_int_p, NULL               },
    { TIOCSTI,            "TIOCSTI",            NULL,                 NULL               },
    { TIOCGWINSZ,         "TIOCGWINSZ",         NULL,                 s_ioctl_decode_ret },
    { TIOCSWINSZ,         "TIOCSWINSZ",         NULL,                 NULL               },
    { TIOCMGET,           "TIOCMGET",           NULL,                 NULL               },
    { TIOCMBIS,           "TIOCMBIS",           NULL,                 NULL               },
    { TIOCMBIC,           "TIOCMBIC",           NULL,                 NULL               },
    { TIOCMSET,           "TIOCMSET",           NULL,                 NULL               },
    { TIOCGSOFTCAR,       "TIOCGSOFTCAR",       NULL,                 NULL               },
    { TIOCSSOFTCAR,       "TIOCSSOFTCAR",       NULL,                 NULL               },
    { FIONREAD,           "FIONREAD",           s_ioctl_decode_int_p, NULL               },
    { TIOCINQ,            "TIOCINQ",            s_ioctl_decode_int_p, NULL               },
    { TIOCLINUX,          "TIOCLINUX",          NULL,                 NULL               },
    { TIOCCONS,           "TIOCCONS",           NULL,                 NULL               },
    { TIOCGSERIAL,        "TIOCGSERIAL",        NULL,                 NULL               },
    { TIOCSSERIAL,        "TIOCSSERIAL",        NULL,                 NULL               },
    { TIOCPKT,            "TIOCPKT",            NULL,                 NULL               },
    { FIONBIO,            "FIONBIO",            NULL,                 NULL               },
    { TIOCNOTTY,          "TIOCNOTTY",          NULL,                 NULL               },
    { TIOCSETD,           "TIOCSETD",           NULL,                 NULL               },
    { TIOCGETD,           "TIOCGETD",           NULL,                 NULL               },
    { TCSBRKP,            "TCSBRKP",            NULL,                 NULL               },
    { TIOCSBRK,           "TIOCSBRK",           NULL,                 NULL               },
    { TIOCCBRK,           "TIOCCBRK",           NULL,                 NULL               },
    { TIOCGSID,           "TIOCGSID",           NULL,                 NULL               },
    { TIOCGRS485,         "TIOCGRS485",         NULL,                 NULL               },
    { TIOCSRS485,         "TIOCSRS485",         NULL,                 NULL               },
    { TIOCGPTN,           "TIOCGPTN",           NULL,                 NULL               },
    { TIOCSPTLCK,         "TIOCSPTLCK",         NULL,                 NULL               },
    { TIOCGDEV,           "TIOCGDEV",           NULL,                 NULL               },
    { TCGETX,             "TCGETX",             NULL,                 NULL               },
    { TCSETX,             "TCSETX",             NULL,                 NULL               },
    { TCSETXF,            "TCSETXF",            NULL,                 NULL               },
    { TCSETXW,            "TCSETXW",            NULL,                 NULL               },
    { TIOCSIG,            "TIOCSIG",            NULL,                 NULL               },
    { TIOCVHANGUP,        "TIOCVHANGUP",        NULL,                 NULL               },
    { TIOCGPKT,           "TIOCGPKT",           NULL,                 NULL               },
    { TIOCGPTLCK,         "TIOCGPTLCK",         NULL,                 NULL               },
    { TIOCGEXCL,          "TIOCGEXCL",          NULL,                 NULL               },
    { TIOCGPTPEER,        "TIOCGPTPEER",        NULL,                 NULL               },
    { FIONCLEX,           "FIONCLEX",           NULL,                 NULL               },
    { FIOCLEX,            "FIOCLEX",            NULL,                 NULL               },
    { FIOASYNC,           "FIOASYNC",           NULL,                 NULL               },
    { TIOCSERCONFIG,      "TIOCSERCONFIG",      NULL,                 NULL               },
    { TIOCSERGWILD,       "TIOCSERGWILD",       NULL,                 NULL               },
    { TIOCSERSWILD,       "TIOCSERSWILD",       NULL,                 NULL               },
    { TIOCGLCKTRMIOS,     "TIOCGLCKTRMIOS",     NULL,                 NULL               },
    { TIOCSLCKTRMIOS,     "TIOCSLCKTRMIOS",     NULL,                 NULL               },
    { TIOCSERGSTRUCT,     "TIOCSERGSTRUCT",     NULL,                 NULL               },
    { TIOCSERGETLSR,      "TIOCSERGETLSR",      s_ioctl_decode_int_p, NULL               },
    { TIOCSERGETMULTI,    "TIOCSERGETMULTI",    NULL,                 NULL               },
    { TIOCSERSETMULTI,    "TIOCSERSETMULTI",    NULL,                 NULL               },
    { TIOCMIWAIT,         "TIOCMIWAIT",         NULL,                 NULL               },
    { TIOCGICOUNT,        "TIOCGICOUNT",        NULL,                 NULL               },
    { FIOQSIZE,           "FIOQSIZE",           NULL,                 NULL               },
    { TIOCPKT_DATA,       "TIOCPKT_DATA",       NULL,                 NULL               },
    { TIOCPKT_FLUSHREAD,  "TIOCPKT_FLUSHREAD",  NULL,                 NULL               },
    { TIOCPKT_FLUSHWRITE, "TIOCPKT_FLUSHWRITE", NULL,                 NULL               },
    { TIOCPKT_STOP,       "TIOCPKT_STOP",       NULL,                 NULL               },
    { TIOCPKT_START,      "TIOCPKT_START",      NULL,                 NULL               },
    { TIOCPKT_NOSTOP,     "TIOCPKT_NOSTOP",     NULL,                 NULL               },
    { TIOCPKT_DOSTOP,     "TIOCPKT_DOSTOP",     NULL,                 NULL               },
    { TIOCPKT_IOCTL,      "TIOCPKT_IOCTL",      NULL,                 NULL               },
    { TIOCSER_TEMT,       "TIOCSER_TEMT",       NULL,                 NULL               },
};

static void s_decode_ioctl_fd(nt_strcat_t* sc, const nt_syscall_info_t* si)
{
    int fd = si->enter.entry.args[0];
    nt_strcat(sc, "%d, ", fd);
}

static const ioctl_request_t* s_decode_ioctl_request(nt_strcat_t* sc, const nt_syscall_info_t* si)
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
        return NULL;
    }

    nt_strcat(sc, "%s", r->name);
    if (r->decode_p != NULL)
    {
        nt_strcat(sc, ", ");
        r->decode_p(sc, si);
    }

    return r;
}

int nt_syscall_decode_ioctl(const nt_syscall_info_t* si, int op, char* buff, size_t size)
{
    const ioctl_request_t* r = NULL;
    nt_strcat_t            sc = NT_STRCAT_INIT(buff, size);
    if (op != PTRACE_SYSCALL_INFO_EXIT)
    {
        return 0;
    }
    nt_strcat(&sc, "(");
    s_decode_ioctl_fd(&sc, si);
    if ((r = s_decode_ioctl_request(&sc, si)) == NULL || r->decode_r == NULL)
    {
        nt_strcat(&sc, ") = %d", (int)si->leave.exit.rval);
        goto FINISH;
    }

    nt_strcat(&sc, ") = ");
    r->decode_r(&sc, si);

FINISH:
    return sc.size;
}
