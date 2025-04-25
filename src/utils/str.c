#include <errno.h>
#include <string.h>
#include "utils/defs.h"
#include "utils/memory.h"
#include "str.h"

typedef struct errno_name
{
    int         code; /* Error code. */
    const char* name; /* Error name. */
} errno_name_t;

static errno_name_t s_errno_name[] = {
    { EACCES,          "EACCES"          },
    { EADDRINUSE,      "EADDRINUSE"      },
    { EADDRNOTAVAIL,   "EADDRNOTAVAIL"   },
    { EAFNOSUPPORT,    "EAFNOSUPPORT"    },
    { EAGAIN,          "EAGAIN"          },
    { EALREADY,        "EALREADY"        },
    { EBADF,           "EBADF"           },
    { EBUSY,           "EBUSY"           },
    { ECONNREFUSED,    "ECONNREFUSED"    },
    { EDQUOT,          "EDQUOT"          },
    { EFAULT,          "EFAULT"          },
    { EINPROGRESS,     "EINPROGRESS"     },
    { EINTR,           "EINTR"           },
    { EIO,             "EIO"             },
    { EISCONN,         "EISCONN"         },
    { EMFILE,          "EMFILE"          },
    { ENETUNREACH,     "ENETUNREACH"     },
    { ENFILE,          "ENFILE"          },
    { ENOBUFS,         "ENOBUFS"         },
    { ENOENT,          "ENOENT"          },
    { ENOMEM,          "ENOMEM"          },
    { ENOSPC,          "ENOSPC"          },
    { ENOTSOCK,        "ENOTSOCK"        },
    { ENOTTY,          "ENOTTY"          },
    { EPERM,           "EPERM"           },
    { EPROTONOSUPPORT, "EPROTONOSUPPORT" },
    { EPROTOTYPE,      "EPROTOTYPE"      },
    { ESRCH,           "ESRCH"           },
    { ETIMEDOUT,       "ETIMEDOUT"       },
};

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
    size_t i;
    for (i = 0; i < ARRAY_SIZE(s_errno_name); i++)
    {
        if (s_errno_name[i].code == code)
        {
            return s_errno_name[i].name;
        }
    }
    return NULL;
}
