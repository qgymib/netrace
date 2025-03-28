#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <arpa/inet.h>
#include <sys/ioctl.h>
#include "utils/defs.h"
#include "utils/socket.h"

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

ssize_t nt_read(int fd, void* buf, size_t size)
{
    ssize_t read_sz;
    do
    {
        read_sz = read(fd, buf, size);
    } while (read_sz == -1 && errno == EINTR);
    return read_sz;
}

ssize_t nt_write(int fd, const void* buf, size_t size)
{
    ssize_t write_sz;
    do
    {
        write_sz = write(fd, buf, size);
    } while (write_sz == -1 && errno == EINTR);
    return write_sz;
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
