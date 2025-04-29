#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdio.h>
#include <pthread.h>
#include <arpa/inet.h>
#include <sys/ioctl.h>
#include <sys/un.h>
#include <stdlib.h>
#include "utils/defs.h"
#include "utils/socket.h"

/**
 * @brief Array containing mappings of socket type IDs to their corresponding names.
 *
 * This array defines a list of socket type identifiers (`type`) and their associated
 * string representations (`name`). Each element in the array corresponds to a specific
 * socket type commonly used in network programming, such as `SOCK_STREAM` or `SOCK_DGRAM`.
 *
 * The primary purpose of this array is to enable the conversion of socket type integer
 * identifiers into human-readable names, which is particularly useful for debugging
 * and displaying socket configuration details in networking applications.
 *
 * Each entry in the array is structured as defined by the `nt_type_name_t` type, which includes:
 * - `type`: An integer representing the socket type (e.g., `SOCK_STREAM`).
 * - `name`: A string literal containing the human-readable name of the socket type (e.g.,
 * `"SOCK_STREAM"`).
 *
 * The array is defined in a fixed order and can be leveraged by functions to perform
 * operations such as mapping, searching, or displaying type information.
 */
static const nt_type_name_t s_socket_type_name[] = {
    { SOCK_STREAM,    "SOCK_STREAM"    },
    { SOCK_DGRAM,     "SOCK_DGRAM"     },
    { SOCK_SEQPACKET, "SOCK_SEQPACKET" },
    { SOCK_RAW,       "SOCK_RAW"       },
    { SOCK_RDM,       "SOCK_RDM"       },
    { SOCK_PACKET,    "SOCK_PACKET"    },
};

/**
 * @brief Array containing mappings of domain family type IDs to their respective names.
 *
 * This array provides a predefined list of domain family type identifiers (`type`) mapped
 * to their string representations (`name`). Each element in the array corresponds to
 * a specific domain family used in socket programming, identified by its type
 * (e.g., `AF_INET`, `AF_UNIX`) and its associated string name (e.g., `"AF_INET"`, `"AF_UNIX"`).
 *
 * The array facilitates converting domain family type identifiers into human-readable names,
 * making it useful for debugging and understanding socket configurations in networking
 * and communication applications.
 *
 * The structure of each entry in the array is specified by the `nt_type_name_t` type,
 * which includes the following fields:
 * - `type`: An integer representing the domain family type (e.g., `AF_INET`).
 * - `name`: A string literal representing the name of the domain family (e.g., `"AF_INET"`).
 *
 * This array is defined in ascii order, and will be sorted as needed by functions within the file
 * to facilitate specific operations, such as searching.
 */
static nt_type_name_t s_socket_domain_name[] = {
    { AF_ALG,       "AF_ALG"       },
    { AF_APPLETALK, "AF_APPLETALK" },
    { AF_AX25,      "AF_AX25"      },
    { AF_BLUETOOTH, "AF_BLUETOOTH" },
    { AF_CAN,       "AF_CAN"       },
    { AF_DECnet,    "AF_DECnet"    },
    { AF_KCM,       "AF_KCM"       },
    { AF_KEY,       "AF_KEY"       },
    { AF_IB,        "AF_IB"        },
    { AF_INET,      "AF_INET"      },
    { AF_INET6,     "AF_INET6"     },
    { AF_IPX,       "AF_IPX"       },
    { AF_LLC,       "AF_LLC"       },
    { AF_LOCAL,     "AF_LOCAL"     },
    { AF_MPLS,      "AF_MPLS"      },
    { AF_NETLINK,   "AF_NETLINK"   },
    { AF_PACKET,    "AF_PACKET"    },
    { AF_PPPOX,     "AF_PPPOX"     },
    { AF_RDS,       "AF_RDS"       },
    { AF_TIPC,      "AF_TIPC"      },
    { AF_UNIX,      "AF_UNIX"      },
    { AF_VSOCK,     "AF_VSOCK"     },
    { AF_X25,       "AF_X25"       },
    { AF_XDP,       "AF_XDP"       },
};

/**
 * @brief Array containing mappings of protocol type IDs to their respective names.
 *
 * This array provides a predefined list of protocol type identifiers (`type`) mapped
 * to their string representations (`name`). Each element in the array represents a
 * specific protocol, identified by its type (e.g., `IPPROTO_TCP`) and its corresponding
 * string name (e.g., `"IPPROTO_TCP"`).
 *
 * The array can be used in networking applications to map protocol type IDs
 * to human-readable protocol names, facilitating protocol identification and
 * debugging within the code.
 *
 * The structure of each entry in the array is defined by the `nt_type_name_t` type,
 * consisting of two fields:
 * - `type`: The integer identifier representing the protocol type.
 * - `name`: The constant character string representing the name of the protocol.
 *
 * This array is defined in ascii order, and will be sorted as needed by functions within the file
 * to facilitate specific operations, such as searching.
 */
static nt_type_name_t s_socket_protocol_name[] = {
    { IPPROTO_AH,       "IPPROTO_AH"       },
    { IPPROTO_BEETPH,   "IPPROTO_BEETPH"   },
    { IPPROTO_COMP,     "IPPROTO_COMP"     },
    { IPPROTO_DCCP,     "IPPROTO_DCCP"     },
    { IPPROTO_EGP,      "IPPROTO_EGP"      },
    { IPPROTO_ENCAP,    "IPPROTO_ENCAP"    },
    { IPPROTO_ESP,      "IPPROTO_ESP"      },
    { IPPROTO_ETHERNET, "IPPROTO_ETHERNET" },
    { IPPROTO_GRE,      "IPPROTO_GRE"      },
    { IPPROTO_ICMP,     "IPPROTO_ICMP"     },
    { IPPROTO_IDP,      "IPPROTO_IDP"      },
    { IPPROTO_IGMP,     "IPPROTO_IGMP"     },
    { IPPROTO_IP,       "IPPROTO_IP"       },
    { IPPROTO_IPV6,     "IPPROTO_IPV6"     },
    { IPPROTO_IPIP,     "IPPROTO_IPIP"     },
    { IPPROTO_L2TP,     "IPPROTO_L2TP"     },
    { IPPROTO_MPLS,     "IPPROTO_MPLS"     },
    { IPPROTO_MPTCP,    "IPPROTO_MPTCP"    },
    { IPPROTO_MTP,      "IPPROTO_MTP"      },
    { IPPROTO_PIM,      "IPPROTO_PIM"      },
    { IPPROTO_PUP,      "IPPROTO_PUP"      },
    { IPPROTO_RAW,      "IPPROTO_RAW"      },
    { IPPROTO_RSVP,     "IPPROTO_RSVP"     },
    { IPPROTO_SCTP,     "IPPROTO_SCTP"     },
    { IPPROTO_TCP,      "IPPROTO_TCP"      },
    { IPPROTO_TP,       "IPPROTO_TP"       },
    { IPPROTO_UDP,      "IPPROTO_UDP"      },
    { IPPROTO_UDPLITE,  "IPPROTO_UDPLITE"  },
};

static int s_on_cmp_type_name(const void* a, const void* b)
{
    const nt_type_name_t* pa = (const nt_type_name_t*)a;
    const nt_type_name_t* pb = (const nt_type_name_t*)b;
    if (pa->type == pb->type)
    {
        return 0;
    }
    return pa->type < pb->type ? -1 : 1;
}

static void s_on_sort_protocol_name()
{
    qsort(s_socket_protocol_name, ARRAY_SIZE(s_socket_protocol_name),
          sizeof(s_socket_protocol_name[0]), s_on_cmp_type_name);
}

static void s_on_sort_domain_name()
{
    qsort(s_socket_domain_name, ARRAY_SIZE(s_socket_domain_name), sizeof(s_socket_domain_name[0]),
          s_on_cmp_type_name);
}

int nt_ip_addr(const char* ip, uint16_t port, struct sockaddr* addr)
{
    int ret;
    int family = strstr(ip, ":") != NULL ? AF_INET6 : AF_INET;
    if (family == AF_INET)
    {
        struct sockaddr_in* p_addr = (struct sockaddr_in*)addr;
        p_addr->sin_family = AF_INET;
        p_addr->sin_port = htons(port);
        ret = inet_pton(AF_INET, ip, &p_addr->sin_addr);
    }
    else
    {
        struct sockaddr_in6* p_addr = (struct sockaddr_in6*)addr;
        p_addr->sin6_family = AF_INET6;
        p_addr->sin6_port = htons(port);
        ret = inet_pton(AF_INET6, ip, &p_addr->sin6_addr);
    }

    if (ret == 0)
    { /* ip not contain a character string representing a valid network address. */
        return NT_ERR(EINVAL);
    }
    return ret == 1 ? 0 : NT_ERR(errno);
}

int nt_ip_name(const struct sockaddr* addr, char* ip, size_t len, int* port)
{
    if (addr->sa_family == AF_INET)
    {
        const struct sockaddr_in* p_addr = (struct sockaddr_in*)addr;
        if (port != NULL)
        {
            *port = ntohs(p_addr->sin_port);
        }

        if (ip != NULL)
        {
            return inet_ntop(AF_INET, &p_addr->sin_addr, ip, len) != NULL ? 0 : NT_ERR(ENOSPC);
        }
    }
    else if (addr->sa_family == AF_INET6)
    {
        const struct sockaddr_in6* p_addr = (struct sockaddr_in6*)addr;
        if (port != NULL)
        {
            *port = ntohs(p_addr->sin6_port);
        }
        if (ip != NULL)
        {
            return inet_ntop(AF_INET6, &p_addr->sin6_addr, ip, len) != NULL ? 0 : NT_ERR(ENOSPC);
        }
    }
    else if (addr->sa_family == AF_UNIX)
    {
        const struct sockaddr_un* p_addr = (struct sockaddr_un*)addr;
        if (port != NULL)
        {
            *port = 0;
        }
        if (ip != NULL)
        {
            snprintf(ip, len, "%s", p_addr->sun_path);
        }
    }
    else
    {
        return NT_ERR(ENOTSUP);
    }

    return 0;
}

int nt_nonblock(int fd, int set)
{
#if defined(_AIX) || defined(__APPLE__) || defined(__DragonFly__) || defined(__FreeBSD__) ||       \
    defined(__FreeBSD_kernel__) || defined(__linux__) || defined(__OpenBSD__) ||                   \
    defined(__NetBSD__)
    int r;

    do
    {
        r = ioctl(fd, FIONBIO, &set);
    } while (r == -1 && errno == EINTR);

    if (r)
    {
        return NT_ERR(errno);
    }

    return 0;
#else
    int flags;

    int r = fcntl(fd, F_GETFL);
    if (r == -1)
    {
        return NT_ERR(errno);
    }

    /* Bail out now if already set/clear. */
    if (!!(r & O_NONBLOCK) == !!set)
    {
        return 0;
    }

    if (set)
    {
        flags = r | O_NONBLOCK;
    }
    else
    {
        flags = r & ~O_NONBLOCK;
    }

    do
    {
        r = fcntl(fd, F_SETFL, flags);
    } while (r == -1 && errno == EINTR);

    if (r)
    {
        return NT_ERR(errno);
    }

    return 0;
#endif
}

int nt_cloexec(int fd, int set)
{
#if defined(_AIX) || defined(__APPLE__) || defined(__DragonFly__) || defined(__FreeBSD__) ||       \
    defined(__FreeBSD_kernel__) || defined(__linux__) || defined(__OpenBSD__) ||                   \
    defined(__NetBSD__)
    int r;

    do
    {
        r = ioctl(fd, set ? FIOCLEX : FIONCLEX);
    } while (r == -1 && errno == EINTR);

    if (r)
    {
        return NT_ERR(errno);
    }

    return 0;
#else
    int r, flags;

    do
    {
        r = fcntl(fd);
    }
    whlie(r == -1 && errno == EINTR);
    if (r == -1)
    {
        return NT_ERR(errno);
    }

    /* Bail out now if already set/clear. */
    if (!!(r & FD_CLOEXEC) == !!set)
    {
        return 0;
    }

    if (set)
    {
        flags = r | FD_CLOEXEC;
    }
    else
    {
        flags = r & ~FD_CLOEXEC;
    }

    do
    {
        r = fcntl(fd, F_SETFD, flags);
    } while (r == -1 && errno == EINTR);

    if (r)
    {
        return NT_ERR(errno);
    }

    return 0;
#endif
}

ssize_t nt_read(int fd, void* buf, size_t size)
{
    ssize_t read_sz;
    do
    {
        read_sz = read(fd, buf, size);
    } while (read_sz == -1 && errno == EINTR);

    return read_sz >= 0 ? read_sz : NT_ERR(errno);
}

ssize_t nt_write(int fd, const void* buf, size_t size)
{
    ssize_t write_sz;
    do
    {
        write_sz = write(fd, buf, size);
    } while (write_sz == -1 && errno == EINTR);

    return write_sz >= 0 ? write_sz : NT_ERR(errno);
}

void nt_sockaddr_copy(struct sockaddr* dst, const struct sockaddr* src)
{
    size_t copy_sz =
        src->sa_family == AF_INET ? sizeof(struct sockaddr_in) : sizeof(struct sockaddr_in6);
    memcpy(dst, src, copy_sz);
}

int nt_socket(int domain, int type, int nonblock)
{
    int fd = socket(domain, type | SOCK_CLOEXEC, 0);
    if (fd < 0)
    {
        return NT_ERR(errno);
    }

    int ret = nt_nonblock(fd, nonblock);
    if (ret < 0)
    {
        close(fd);
        return ret;
    }

    return fd;
}

int nt_socket_bind(int type, const char* ip, int port, int nonblock, struct sockaddr_storage* addr)
{
    int                     ret;
    struct sockaddr_storage tmp_addr;
    if (addr == NULL)
    {
        addr = &tmp_addr;
    }

    if ((ret = nt_ip_addr(ip, port, (struct sockaddr*)addr)) < 0)
    {
        return ret;
    }

    return nt_socket_bind_r(type, nonblock, addr);
}

int nt_socket_bind_r(int type, int nonblock, struct sockaddr_storage* addr)
{
    int              fd, ret;
    struct sockaddr* p_addr = (struct sockaddr*)addr;
    socklen_t        addr_len = sizeof(*addr);

    if ((fd = nt_socket(addr->ss_family, type, nonblock)) < 0)
    {
        return NT_ERR(errno);
    }
    if (bind(fd, p_addr, addr_len) != 0)
    {
        ret = NT_ERR(errno);
        goto ERR;
    }
    if (getsockname(fd, p_addr, &addr_len) < 0)
    {
        ret = NT_ERR(errno);
        goto ERR;
    }

    return fd;

ERR:
    close(fd);
    return ret;
}

int nt_socket_listen(const char* ip, int port, int nonblock, struct sockaddr_storage* addr)
{
    int fd = nt_socket_bind(SOCK_STREAM, ip, port, nonblock, addr);
    if (fd < 0)
    {
        return fd;
    }

    int ret = listen(fd, SOMAXCONN);
    if (ret < 0)
    {
        ret = NT_ERR(errno);
        close(fd);
        return ret;
    }

    return fd;
}

int nt_accept(int fd)
{
    int c;
    do
    {
        c = accept(fd, NULL, NULL);
    } while (c < 0 && errno == EINTR);

    int ret = nt_cloexec(c, 1);
    if (ret != 0)
    {
        close(c);
        return ret;
    }

    return c;
}

int nt_socket_connect(int type, const struct sockaddr_storage* addr, int nonblock)
{
    int fd, ret;
    if ((fd = nt_socket(addr->ss_family, type, nonblock)) < 0)
    {
        return fd;
    }

    do
    {
        ret = connect(fd, (struct sockaddr*)addr, sizeof(*addr));
    } while (ret == -1 && errno == EINTR);
    if (ret == 0)
    {
        return fd;
    }

    ret = errno;
    if (ret == EINPROGRESS || ret == EAGAIN)
    {
        return fd;
    }

    close(fd);
    return NT_ERR(ret);
}

const char* nt_socket_domain_name(int domain)
{
    static pthread_once_t s_once = PTHREAD_ONCE_INIT;
    pthread_once(&s_once, s_on_sort_domain_name);

    nt_type_name_t  key = { domain, NULL };
    nt_type_name_t* r = bsearch(&key, s_socket_domain_name, ARRAY_SIZE(s_socket_domain_name),
                                sizeof(s_socket_domain_name[0]), s_on_cmp_type_name);
    return r != NULL ? r->name : NULL;
}

const char* nt_socket_type_name(int type)
{
    size_t i;
    for (i = 0; i < ARRAY_SIZE(s_socket_type_name); i++)
    {
        if (s_socket_type_name[i].type == type)
        {
            return s_socket_type_name[i].name;
        }
    }

    return NULL;
}

const char* nt_socket_protocol_name(int protocol)
{
    static pthread_once_t s_once = PTHREAD_ONCE_INIT;
    pthread_once(&s_once, s_on_sort_protocol_name);

    nt_type_name_t  key = { protocol, NULL };
    nt_type_name_t* r = bsearch(&key, s_socket_protocol_name, ARRAY_SIZE(s_socket_protocol_name),
                                sizeof(s_socket_protocol_name[0]), s_on_cmp_type_name);
    return r != NULL ? r->name : NULL;
}
