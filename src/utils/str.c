#include <errno.h>
#include <string.h>
#include <stdarg.h>
#include <stdio.h>
#include <ctype.h>
#include <inttypes.h>
#include <pthread.h>
#include <stdlib.h>
#include "utils/defs.h"
#include "utils/syscall.h"
#include "trace/__init__.h"
#include "config.h"
#include "str.h"

typedef struct errno_name
{
    int         code; /* Error code. */
    const char* name; /* Error name. */
} errno_name_t;

static errno_name_t s_errno_name[] = {
    { E2BIG,           "E2BIG"           },
    { EACCES,          "EACCES"          },
    { EADDRINUSE,      "EADDRINUSE"      },
    { EADDRNOTAVAIL,   "EADDRNOTAVAIL"   },
    { EAFNOSUPPORT,    "EAFNOSUPPORT"    },
    { EAGAIN,          "EAGAIN"          },
    { EALREADY,        "EALREADY"        },
    { EBADE,           "EBADE"           },
    { EBADF,           "EBADF"           },
    { EBADFD,          "EBADFD"          },
    { EBADMSG,         "EBADMSG"         },
    { EBADR,           "EBADR"           },
    { EBADRQC,         "EBADRQC"         },
    { EBADSLT,         "EBADSLT"         },
    { EBUSY,           "EBUSY"           },
    { ECANCELED,       "ECANCELED"       },
    { ECHILD,          "ECHILD"          },
    { ECHRNG,          "ECHRNG"          },
    { ECOMM,           "ECOMM"           },
    { ECONNABORTED,    "ECONNABORTED"    },
    { ECONNREFUSED,    "ECONNREFUSED"    },
    { ECONNRESET,      "ECONNRESET"      },
    { EDEADLK,         "EDEADLK"         },
    { EDEADLOCK,       "EDEADLOCK"       },
    { EDESTADDRREQ,    "EDESTADDRREQ"    },
    { EDOM,            "EDOM"            },
    { EDQUOT,          "EDQUOT"          },
    { EEXIST,          "EEXIST"          },
    { EFAULT,          "EFAULT"          },
    { EFBIG,           "EFBIG"           },
    { EHOSTDOWN,       "EHOSTDOWN"       },
    { EHOSTUNREACH,    "EHOSTUNREACH"    },
    { EHWPOISON,       "EHWPOISON"       },
    { EIDRM,           "EIDRM"           },
    { EILSEQ,          "EILSEQ"          },
    { EINPROGRESS,     "EINPROGRESS"     },
    { EINTR,           "EINTR"           },
    { EINVAL,          "EINVAL"          },
    { EIO,             "EIO"             },
    { EISCONN,         "EISCONN"         },
    { EISDIR,          "EISDIR"          },
    { EISNAM,          "EISNAM"          },
    { EKEYEXPIRED,     "EKEYEXPIRED"     },
    { EKEYREJECTED,    "EKEYREJECTED"    },
    { EKEYREVOKED,     "EKEYREVOKED"     },
    { EL2HLT,          "EL2HLT"          },
    { EL2NSYNC,        "EL2NSYNC"        },
    { EL3HLT,          "EL3HLT"          },
    { EL3RST,          "EL3RST"          },
    { ELIBACC,         "ELIBACC"         },
    { ELIBBAD,         "ELIBBAD"         },
    { ELIBMAX,         "ELIBMAX"         },
    { ELIBSCN,         "ELIBSCN"         },
    { ELIBEXEC,        "ELIBEXEC"        },
    { ELNRNG,          "ELNRNG"          },
    { ELOOP,           "ELOOP"           },
    { EMEDIUMTYPE,     "EMEDIUMTYPE"     },
    { EMFILE,          "EMFILE"          },
    { EMLINK,          "EMLINK"          },
    { EMSGSIZE,        "EMSGSIZE"        },
    { EMULTIHOP,       "EMULTIHOP"       },
    { ENAMETOOLONG,    "ENAMETOOLONG"    },
    { ENETDOWN,        "ENETDOWN"        },
    { ENETRESET,       "ENETRESET"       },
    { ENETUNREACH,     "ENETUNREACH"     },
    { ENFILE,          "ENFILE"          },
    { ENOANO,          "ENOANO"          },
    { ENOBUFS,         "ENOBUFS"         },
    { ENODATA,         "ENODATA"         },
    { ENODEV,          "ENODEV"          },
    { ENOENT,          "ENOENT"          },
    { ENOEXEC,         "ENOEXEC"         },
    { ENOKEY,          "ENOKEY"          },
    { ENOLCK,          "ENOLCK"          },
    { ENOLINK,         "ENOLINK"         },
    { ENOMEDIUM,       "ENOMEDIUM"       },
    { ENOMEM,          "ENOMEM"          },
    { ENOMSG,          "ENOMSG"          },
    { ENONET,          "ENONET"          },
    { ENOPKG,          "ENOPKG"          },
    { ENOPROTOOPT,     "ENOPROTOOPT"     },
    { ENOSPC,          "ENOSPC"          },
    { ENOSR,           "ENOSR"           },
    { ENOSTR,          "ENOSTR"          },
    { ENOSYS,          "ENOSYS"          },
    { ENOTBLK,         "ENOTBLK"         },
    { ENOTCONN,        "ENOTCONN"        },
    { ENOTDIR,         "ENOTDIR"         },
    { ENOTEMPTY,       "ENOTEMPTY"       },
    { ENOTRECOVERABLE, "ENOTRECOVERABLE" },
    { ENOTSOCK,        "ENOTSOCK"        },
    { ENOTSUP,         "ENOTSUP"         },
    { ENOTTY,          "ENOTTY"          },
    { ENOTUNIQ,        "ENOTUNIQ"        },
    { ENXIO,           "ENXIO"           },
    { EOPNOTSUPP,      "EOPNOTSUPP"      },
    { EOVERFLOW,       "EOVERFLOW"       },
    { EOWNERDEAD,      "EOWNERDEAD"      },
    { EPERM,           "EPERM"           },
    { EPROTONOSUPPORT, "EPROTONOSUPPORT" },
    { EPIPE,           "EPIPE"           },
    { EPROTO,          "EPROTO"          },
    { EPROTONOSUPPORT, "EPROTONOSUPPORT" },
    { EPROTOTYPE,      "EPROTOTYPE"      },
    { ERANGE,          "ERANGE"          },
    { EREMCHG,         "EREMCHG"         },
    { EREMOTE,         "EREMOTE"         },
    { EREMOTEIO,       "EREMOTEIO"       },
    { ERESTART,        "ERESTART"        },
    { ERFKILL,         "ERFKILL"         },
    { EROFS,           "EROFS"           },
    { ESHUTDOWN,       "ESHUTDOWN"       },
    { ESPIPE,          "ESPIPE"          },
    { ESOCKTNOSUPPORT, "ESOCKTNOSUPPORT" },
    { ESRCH,           "ESRCH"           },
    { ESTALE,          "ESTALE"          },
    { ESTRPIPE,        "ESTRPIPE"        },
    { ETIME,           "ETIME"           },
    { ETIMEDOUT,       "ETIMEDOUT"       },
    { ETOOMANYREFS,    "ETOOMANYREFS"    },
    { ETXTBSY,         "ETXTBSY"         },
    { EUCLEAN,         "EUCLEAN"         },
    { EUNATCH,         "EUNATCH"         },
    { EUSERS,          "EUSERS"          },
    { EWOULDBLOCK,     "EWOULDBLOCK"     },
    { EXDEV,           "EXDEV"           },
    { EXFULL,          "EXFULL"          },
};

static const char* s_escape(int c)
{
    switch (c)
    {
    case ' ':
        return " ";
    case '\n':
        return "\\n";
    case '\t':
        return "\\t";
    case '\r':
        return "\\r";
    case '\v':
        return "\\v";
    case '\f':
        return "\\f";
    case '\\':
        return "\\\\";
    default:
        break;
    }
    return NULL;
}

static int s_on_cmp_errno_name(const void* a, const void* b)
{
    const errno_name_t* n1 = (errno_name_t*)a;
    const errno_name_t* n2 = (errno_name_t*)b;
    if (n1->code == n2->code)
    {
        return 0;
    }
    return n1->code < n2->code ? -1 : 1;
}

static void s_strerrorname_resort_syscall_table()
{
    qsort(s_errno_name, ARRAY_SIZE(s_errno_name), sizeof(s_errno_name[0]), s_on_cmp_errno_name);
}

const char* nt_strrstr(const char* haystack, const char* needle)
{
    if (*needle == '\0')
    {
        return haystack;
    }

    const char* result = NULL;
    for (;;)
    {
        char* p = strstr(haystack, needle);
        if (p == NULL)
        {
            break;
        }
        result = p;
        haystack = p + 1;
    }

    return result;
}

const char* nt_strnrstr(const char* haystack, size_t len, const char* needle)
{
    if (!haystack || !needle || len == 0)
    {
        return NULL;
    }

    size_t needle_len = strlen(needle);

    if (needle_len == 0)
    {
        return haystack; // Empty needle is always found at the beginning
    }

    if (needle_len > len)
    {
        return NULL; // Needle is longer than search area
    }

    // Start from the last possible position where needle could fit
    const char* search_start = haystack + len - needle_len;
    const char* result = NULL;

    // Search backwards
    while (search_start >= haystack)
    {
        if (strncmp(search_start, needle, needle_len) == 0)
        {
            result = search_start;
            break;
        }
        search_start--;
    }

    return result;
}

const char* nt_strerrorname(int code)
{
    static pthread_once_t s_once_token = PTHREAD_ONCE_INIT;
    pthread_once(&s_once_token, s_strerrorname_resort_syscall_table);

    errno_name_t  tmp = { code, NULL };
    errno_name_t* r = bsearch(&tmp, s_errno_name, ARRAY_SIZE(s_errno_name), sizeof(s_errno_name[0]),
                              s_on_cmp_errno_name);
    return r != NULL ? r->name : NULL;
}

int nt_strcat(nt_strcat_t* s, const char* fmt, ...)
{
    char*  buff = s->buff + s->size;
    size_t size = s->capacity - s->size;

    va_list ap;
    va_start(ap, fmt);
    int ret = vsnprintf(buff, size, fmt, ap);
    va_end(ap);

    int write_sz = ret >= (int)size ? (int)(size - 1) : ret;
    s->size += write_sz;
    return ret;
}

int nt_strcat_dump(nt_strcat_t* sc, void* buff, size_t size)
{
    size_t         i;
    int            ret = 0;
    unsigned char* addr = (unsigned char*)buff;

    ret += nt_strcat(sc, "\"");
    for (i = 0; i < size; i++)
    {
        unsigned char c = addr[i];
        const char*   e = s_escape(c);
        if (e != NULL)
        {
            ret += nt_strcat(sc, "%s", e);
        }
        else if (isprint(c))
        {
            ret += nt_strcat(sc, "%c", c);
        }
        else
        {
            ret += nt_strcat(sc, "\\x%02x", c);
        }
    }
    ret += nt_strcat(sc, "\"");

    return ret;
}

void nt_strcat_ret(nt_strcat_t* sc, int64_t ret, int err)
{
    nt_strcat(sc, "%" PRId64, ret);

    if (!err)
    {
        return;
    }

    int         errcode = -ret;
    const char* s_err = nt_strerrorname(errcode);
    if (s_err == NULL)
    {
        return;
    }

    nt_strcat(sc, " %s (%s)", s_err, strerror(errcode));
}

static int s_str_dump_msghdr_msgname(const struct msghdr* msg, pid_t pid, nt_strcat_t* sc)
{
    if (msg->msg_name == NULL)
    {
        return nt_strcat(sc, "NULL");
    }

    struct sockaddr_storage addr;
    nt_syscall_get_sockaddr(pid, (uintptr_t)msg->msg_name, &addr, msg->msg_namelen);

    char ip[64];
    int  port;
    if (nt_ip_name((struct sockaddr*)&addr, ip, sizeof(ip), &port) != 0)
    {
        return nt_strcat(sc, "EINVAL");
    }

    return nt_strcat(sc, "{domain=%s, addr=%s, port=%d}", nt_socket_domain_name(addr.ss_family), ip,
                     port);
}

static int s_str_dump_msghdr_msgcontrol(const struct msghdr* msg, pid_t pid, nt_strcat_t* sc)
{
    int           ret = 0;
    unsigned char buff[NT_MAX_DUMP_SIZE];
    if (msg->msg_control == NULL)
    {
        return nt_strcat(sc, "NULL");
    }

    size_t buff_sz = NT_MIN(sizeof(buff), msg->msg_controllen);
    nt_syscall_getdata(pid, (uintptr_t)msg->msg_control, buff, buff_sz);
    ret += nt_strcat_dump(sc, buff, buff_sz);
    if (buff_sz < msg->msg_controllen)
    {
        ret += nt_strcat(sc, "...");
    }

    return ret;
}

static int s_str_sysdump_iovec_one(const struct iovec* iov, size_t size, pid_t pid, nt_strcat_t* sc)
{
    int    ret = 0;
    size_t dump_sz = NT_MIN(iov->iov_len, size);

    ret += nt_strcat(sc, "{iov_base=");
    ret += nt_str_sysdump(sc, pid, (uintptr_t)iov->iov_base, dump_sz);
    ret += nt_strcat(sc, ",iov_len=%lu}", (unsigned long)iov->iov_len);

    return ret;
}

int nt_str_sysdump_iovec(nt_strcat_t* sc, pid_t pid, uintptr_t iov, int iovcnt, size_t maxsize)
{
    int          ret = 0;
    struct iovec msgiov[3];
    int          iov_len = NT_MIN((int)ARRAY_SIZE(msgiov), iovcnt);
    size_t       read_sz = sizeof(msgiov[0]) * iov_len;
    if (iov == 0)
    {
        return nt_strcat(sc, "NULL");
    }
    if (iov_len <= 0 || maxsize == 0)
    {
        return nt_strcat(sc, "{}");
    }
    nt_syscall_getdata(pid, (uintptr_t)iov, msgiov, read_sz);

    if (iovcnt > 1)
    {
        ret += nt_strcat(sc, "[");
    }

    int i;
    for (i = 0; i < iov_len && maxsize > 0; i++)
    {
        struct iovec* io = &msgiov[i];
        size_t        read_sz = NT_MIN(io->iov_len, maxsize);
        ret += s_str_sysdump_iovec_one(io, read_sz, pid, sc);
        if (i != iov_len - 1)
        {
            ret += nt_strcat(sc, ",");
        }
        maxsize -= read_sz;
    }

    if (iovcnt > 1)
    {
        ret += nt_strcat(sc, "]");
    }

    return ret;
}

int nt_str_dump_msghdr(const struct msghdr* msg, pid_t pid, nt_strcat_t* sc)
{
    int ret = 0;

    ret += nt_strcat(sc, "{msg_name=");
    ret += s_str_dump_msghdr_msgname(msg, pid, sc);
    ret += nt_strcat(sc, ",msg_namelen=%u, msg_iov=", (unsigned)msg->msg_namelen);
    ret += nt_str_sysdump_iovec(sc, pid, (uintptr_t)msg->msg_iov, msg->msg_iovlen, SIZE_MAX);
    ret += nt_strcat(sc, ",msg_iovlen=%u, msg_control=", (unsigned)msg->msg_iovlen);
    ret += s_str_dump_msghdr_msgcontrol(msg, pid, sc);
    ret += nt_strcat(sc, ",msg_controllen=%u, msg_flags=%u}", (unsigned)msg->msg_namelen,
                     (unsigned)msg->msg_flags);

    return ret;
}

int nt_str_sysdump(nt_strcat_t* sc, pid_t pid, uintptr_t addr, size_t size)
{
    int           ret = 0;
    unsigned char buff[NT_MAX_DUMP_SIZE];
    size_t        read_sz = NT_MIN(sizeof(buff), size);

    if (addr == 0)
    {
        return nt_strcat(sc, "NULL");
    }
    nt_syscall_getdata(pid, addr, buff, read_sz);

    ret += nt_strcat_dump(sc, buff, read_sz);
    if (read_sz < size)
    {
        ret += nt_strcat(sc, "...");
    }

    return ret;
}

int nt_str_sysdump_str(nt_strcat_t* sc, pid_t pid, uintptr_t addr)
{
    int  ret;
    char buff[NT_MAX_DUMP_SIZE];
    if ((ret = nt_syscall_get_string(pid, addr, buff, sizeof(buff))) < 0)
    {
        return ret;
    }

    size_t dump_sz = ((size_t)ret >= sizeof(buff)) ? (sizeof(buff) - 1) : (size_t)ret;
    ret = nt_strcat_dump(sc, buff, dump_sz);
    if (dump_sz == (sizeof(buff) - 1))
    {
        ret += nt_strcat(sc, "...");
    }

    return ret;
}

int nt_str_dump_sockaddr(nt_strcat_t* sc, const struct sockaddr* addr)
{
    int  ret = 0;
    char ip[128];
    int  port = 0;
    if (nt_ip_name(addr, ip, sizeof(ip), &port) != 0)
    {
        return nt_strcat(sc, "EINVAL");
    }

    ret += nt_strcat(sc, "{family=%s", nt_socket_domain_name(addr->sa_family));
    if (addr->sa_family == AF_INET || addr->sa_family == AF_INET6)
    {
        ret += nt_strcat(sc, ",addr=%s, port=%d", ip, port);
    }
    else if (addr->sa_family == AF_UNIX)
    {
        ret += nt_strcat(sc, ",path=");
        ret += nt_strcat_dump(sc, ip, strlen(ip));
    }
    ret += nt_strcat(sc, "}");

    return ret;
}

int nt_str_sysdump_sockaddr(nt_strcat_t* sc, pid_t pid, uintptr_t addr, size_t len)
{
    int                     ret;
    struct sockaddr_storage sockaddr;

    if ((ret = nt_syscall_get_sockaddr(pid, addr, &sockaddr, len)) != 0)
    {
        return ret;
    }

    return nt_str_dump_sockaddr(sc, (struct sockaddr*)&sockaddr);
}
