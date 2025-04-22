#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <arpa/inet.h>
#include <sys/ioctl.h>
#include "utils/defs.h"
#include "utils/socket.h"

typedef struct nt_socket__name
{
    int         domain;
    const char* name;
} nt_socket_domain_name_t;

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
    else
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

const char* nt_socktype_name(int type)
{
    switch (type)
    {
        /* clang-format off */
    case SOCK_STREAM:       return "tcp";
    case SOCK_DGRAM:        return "udp";
    case SOCK_SEQPACKET:    return "seqpacket";
    case SOCK_RAW:          return "raw";
    case SOCK_RDM:          return "drm";
    case SOCK_PACKET:       return "packet";
    default:                break;
        /* clang-format on */
    }

    return "unknown";
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
    static const nt_socket_domain_name_t s_name[] = {
        { AF_UNIX,      "AF_UNIX"      },
        { AF_LOCAL,     "AF_LOCAL"     },
        { AF_INET,      "AF_INET"      },
        { AF_AX25,      "AF_AX25"      },
        { AF_IPX,       "AF_IPX"       },
        { AF_APPLETALK, "AF_APPLETALK" },
        { AF_X25,       "AF_X25"       },
        { AF_INET6,     "AF_INET6"     },
        { AF_DECnet,    "AF_DECnet"    },
        { AF_KEY,       "AF_KEY"       },
        { AF_NETLINK,   "AF_NETLINK"   },
        { AF_PACKET,    "AF_PACKET"    },
        { AF_RDS,       "AF_RDS"       },
        { AF_PPPOX,     "AF_PPPOX"     },
        { AF_LLC,       "AF_LLC"       },
        { AF_IB,        "AF_IB"        },
        { AF_MPLS,      "AF_MPLS"      },
        { AF_CAN,       "AF_CAN"       },
        { AF_TIPC,      "AF_TIPC"      },
        { AF_BLUETOOTH, "AF_BLUETOOTH" },
        { AF_ALG,       "AF_ALG"       },
        { AF_VSOCK,     "AF_VSOCK"     },
        { AF_KCM,       "AF_KCM"       },
        { AF_XDP,       "AF_XDP"       },
    };

    size_t i;
    for (i = 0; i < ARRAY_SIZE(s_name); i++)
    {
        if (s_name[i].domain == domain)
        {
            return s_name[i].name;
        }
    }

    return "unknown";
}

const char* nt_socket_type_name(int type)
{
    static const nt_socket_domain_name_t s_name[] = {
        { SOCK_STREAM,    "SOCK_STREAM"    },
        { SOCK_DGRAM,     "SOCK_DGRAM"     },
        { SOCK_SEQPACKET, "SOCK_SEQPACKET" },
        { SOCK_RAW,       "SOCK_RAW"       },
        { SOCK_RDM,       "SOCK_RDM"       },
        { SOCK_PACKET,    "SOCK_PACKET"    },
    };

    size_t i;
    for (i = 0; i < ARRAY_SIZE(s_name); i++)
    {
        if (s_name[i].domain == type)
        {
            return s_name[i].name;
        }
    }

    return "unknown";
}
