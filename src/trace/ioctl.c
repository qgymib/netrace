#include <sys/ioctl.h>
#include <net/if.h>
#include <stdlib.h>
#include <pthread.h>
#include "utils/defs.h"
#include "utils/str.h"
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

static void s_ioctl_decode_ifreq(nt_strcat_t* sc, const nt_syscall_info_t* si)
{
    struct ifreq req;
    if (si->enter.entry.args[2] == 0)
    {
        nt_strcat(sc, "NULL");
        return;
    }

    nt_syscall_getdata(si->pid, si->enter.entry.args[2], &req, sizeof(req));
    nt_strcat(sc, "%d", req.ifr_ifindex);
}

/**
 * @brief Array of ioctl requests, containing details about ioctl command codes,
 *        their string representations, and optional decode and return handlers.
 *
 * This static array maps ioctl command constants to their associated string names
 * along with optional callback functions for request-specific decoding or return
 * value decoding. Each entry in the array consists of:
 *  - A command code (e.g., FIOASYNC, TIOCGWINSZ).
 *  - The string name for the command (e.g., "FIOASYNC").
 *  - An optional decoding function pointer for request arguments.
 *  - An optional decoding function pointer for interpreting returned values.
 *
 * The array helps in associating ioctl commands with their metadata for use in
 * debugging, logging, and handling different ioctl operations.
 *
 * This structure is particularly useful in debugging or implementing
 * tools to interpret ioctl commands sent to file descriptors in low-level
 * system operations.
 *
 * It is defined in ascii order and will be sort before use.
 */
static ioctl_request_t s_ioctl_requests[] = {
    { FIOASYNC,           "FIOASYNC",           NULL,                 NULL               },
    { FIOCLEX,            "FIOCLEX",            NULL,                 NULL               },
    { FIONBIO,            "FIONBIO",            s_ioctl_decode_int_p, NULL               },
    { FIONREAD,           "FIONREAD",           s_ioctl_decode_int_p, NULL               },
    { FIONCLEX,           "FIONCLEX",           NULL,                 NULL               },
    { FIOQSIZE,           "FIOQSIZE",           NULL,                 NULL               },
    { SIOCGIFINDEX,       "SIOCGIFINDEX",       s_ioctl_decode_ifreq, s_ioctl_decode_ret },
    { TCFLSH,             "TCFLSH",             s_ioctl_decode_int,   NULL               },
    { TCGETA,             "TCGETA",             NULL,                 NULL               },
    { TCGETX,             "TCGETX",             NULL,                 NULL               },
    { TCGETS,             "TCGETS",             NULL,                 s_ioctl_decode_ret },
    { TCSBRK,             "TCSBRK",             NULL,                 NULL               },
    { TCSBRKP,            "TCSBRKP",            NULL,                 NULL               },
    { TCSETA,             "TCSETA",             NULL,                 NULL               },
    { TCSETAF,            "TCSETAF",            NULL,                 NULL               },
    { TCSETAW,            "TCSETAW",            NULL,                 NULL               },
    { TCSETS,             "TCSETS",             NULL,                 NULL               },
    { TCSETSF,            "TCSETSF",            NULL,                 NULL               },
    { TCSETSW,            "TCSETSW",            NULL,                 NULL               },
    { TCSETX,             "TCSETX",             NULL,                 NULL               },
    { TCSETXF,            "TCSETXF",            NULL,                 NULL               },
    { TCSETXW,            "TCSETXW",            NULL,                 NULL               },
    { TCXONC,             "TCXONC",             NULL,                 NULL               },
    { TIOCCBRK,           "TIOCCBRK",           NULL,                 NULL               },
    { TIOCCONS,           "TIOCCONS",           NULL,                 NULL               },
    { TIOCEXCL,           "TIOCEXCL",           NULL,                 NULL               },
    { TIOCGDEV,           "TIOCGDEV",           NULL,                 NULL               },
    { TIOCGETD,           "TIOCGETD",           NULL,                 NULL               },
    { TIOCGEXCL,          "TIOCGEXCL",          NULL,                 NULL               },
    { TIOCGICOUNT,        "TIOCGICOUNT",        NULL,                 NULL               },
    { TIOCGLCKTRMIOS,     "TIOCGLCKTRMIOS",     NULL,                 NULL               },
    { TIOCGPGRP,          "TIOCGPGRP",          NULL,                 NULL               },
    { TIOCGPKT,           "TIOCGPKT",           NULL,                 NULL               },
    { TIOCGPTLCK,         "TIOCGPTLCK",         NULL,                 NULL               },
    { TIOCGPTN,           "TIOCGPTN",           NULL,                 NULL               },
    { TIOCGPTPEER,        "TIOCGPTPEER",        NULL,                 NULL               },
    { TIOCGRS485,         "TIOCGRS485",         NULL,                 NULL               },
    { TIOCGSERIAL,        "TIOCGSERIAL",        NULL,                 NULL               },
    { TIOCGSOFTCAR,       "TIOCGSOFTCAR",       NULL,                 NULL               },
    { TIOCGSID,           "TIOCGSID",           NULL,                 NULL               },
    { TIOCGWINSZ,         "TIOCGWINSZ",         NULL,                 s_ioctl_decode_ret },
    { TIOCINQ,            "TIOCINQ",            s_ioctl_decode_int_p, NULL               },
    { TIOCLINUX,          "TIOCLINUX",          NULL,                 NULL               },
    { TIOCMBIC,           "TIOCMBIC",           NULL,                 NULL               },
    { TIOCMBIS,           "TIOCMBIS",           NULL,                 NULL               },
    { TIOCMGET,           "TIOCMGET",           NULL,                 NULL               },
    { TIOCMIWAIT,         "TIOCMIWAIT",         NULL,                 NULL               },
    { TIOCMSET,           "TIOCMSET",           NULL,                 NULL               },
    { TIOCNOTTY,          "TIOCNOTTY",          NULL,                 NULL               },
    { TIOCNXCL,           "TIOCNXCL",           NULL,                 NULL               },
    { TIOCOUTQ,           "TIOCOUTQ",           s_ioctl_decode_int_p, NULL               },
    { TIOCPKT,            "TIOCPKT",            NULL,                 NULL               },
    { TIOCPKT_DATA,       "TIOCPKT_DATA",       NULL,                 NULL               },
    { TIOCPKT_DOSTOP,     "TIOCPKT_DOSTOP",     NULL,                 NULL               },
    { TIOCPKT_FLUSHREAD,  "TIOCPKT_FLUSHREAD",  NULL,                 NULL               },
    { TIOCPKT_FLUSHWRITE, "TIOCPKT_FLUSHWRITE", NULL,                 NULL               },
    { TIOCPKT_IOCTL,      "TIOCPKT_IOCTL",      NULL,                 NULL               },
    { TIOCPKT_NOSTOP,     "TIOCPKT_NOSTOP",     NULL,                 NULL               },
    { TIOCPKT_START,      "TIOCPKT_START",      NULL,                 NULL               },
    { TIOCPKT_STOP,       "TIOCPKT_STOP",       NULL,                 NULL               },
    { TIOCSER_TEMT,       "TIOCSER_TEMT",       NULL,                 NULL               },
    { TIOCSBRK,           "TIOCSBRK",           NULL,                 NULL               },
    { TIOCSERCONFIG,      "TIOCSERCONFIG",      NULL,                 NULL               },
    { TIOCSERGETLSR,      "TIOCSERGETLSR",      s_ioctl_decode_int_p, NULL               },
    { TIOCSERGETMULTI,    "TIOCSERGETMULTI",    NULL,                 NULL               },
    { TIOCSERGSTRUCT,     "TIOCSERGSTRUCT",     NULL,                 NULL               },
    { TIOCSERGWILD,       "TIOCSERGWILD",       NULL,                 NULL               },
    { TIOCSERSETMULTI,    "TIOCSERSETMULTI",    NULL,                 NULL               },
    { TIOCSERSWILD,       "TIOCSERSWILD",       NULL,                 NULL               },
    { TIOCSETD,           "TIOCSETD",           NULL,                 NULL               },
    { TIOCSCTTY,          "TIOCSCTTY",          NULL,                 NULL               },
    { TIOCSIG,            "TIOCSIG",            NULL,                 NULL               },
    { TIOCSLCKTRMIOS,     "TIOCSLCKTRMIOS",     NULL,                 NULL               },
    { TIOCSPGRP,          "TIOCSPGRP",          NULL,                 NULL               },
    { TIOCSPTLCK,         "TIOCSPTLCK",         NULL,                 NULL               },
    { TIOCSRS485,         "TIOCSRS485",         NULL,                 NULL               },
    { TIOCSSERIAL,        "TIOCSSERIAL",        NULL,                 NULL               },
    { TIOCSSOFTCAR,       "TIOCSSOFTCAR",       NULL,                 NULL               },
    { TIOCSTI,            "TIOCSTI",            NULL,                 NULL               },
    { TIOCSWINSZ,         "TIOCSWINSZ",         NULL,                 NULL               },
    { TIOCVHANGUP,        "TIOCVHANGUP",        NULL,                 NULL               },
};

static void s_decode_ioctl_fd(nt_strcat_t* sc, const nt_syscall_info_t* si)
{
    int fd = si->enter.entry.args[0];
    nt_strcat(sc, "%d, ", fd);
}

static int s_ioctl_on_cmp_ioctl_requests(const void* a, const void* b)
{
    const ioctl_request_t* r1 = (const ioctl_request_t*)a;
    const ioctl_request_t* r2 = (const ioctl_request_t*)b;
    if (r1->request == r2->request)
    {
        return 0;
    }
    return r1->request < r2->request ? -1 : 1;
}

static void s_ioctl_resort_ioctl_requests(void)
{
    qsort(s_ioctl_requests, ARRAY_SIZE(s_ioctl_requests), sizeof(s_ioctl_requests[0]),
          s_ioctl_on_cmp_ioctl_requests);
}

static const ioctl_request_t* s_ioctl_find_request(unsigned long request)
{
    static pthread_once_t s_once = PTHREAD_ONCE_INIT;
    pthread_once(&s_once, s_ioctl_resort_ioctl_requests);

    ioctl_request_t k = { request, NULL, NULL, NULL };
    return bsearch(&k, s_ioctl_requests, ARRAY_SIZE(s_ioctl_requests), sizeof(s_ioctl_requests[0]),
                   s_ioctl_on_cmp_ioctl_requests);
}

static const ioctl_request_t* s_decode_ioctl_request(nt_strcat_t* sc, const nt_syscall_info_t* si)
{
    unsigned long          request = si->enter.entry.args[1];
    const ioctl_request_t* r = s_ioctl_find_request(request);
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
