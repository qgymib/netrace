#include <errno.h>
#include <stdlib.h>
#include <sys/select.h>
#include "utils/defs.h"
#include "utils/time.h"
#include "socket2.h"

int nt_accept_timed(int sockfd, struct sockaddr* addr, socklen_t* addrlen, uint32_t timeout)
{
    fd_set rdset;
    FD_ZERO(&rdset);
    FD_SET(sockfd, &rdset);

    struct timeval tv = { 0, 0 };
    while (timeout >= 1000)
    {
        tv.tv_sec++;
        timeout -= 1000;
    }
    tv.tv_usec = timeout * 1000;

    int ret = select(sockfd + 1, &rdset, NULL, NULL, &tv);
    if (ret == 0)
    {
        return NT_ERR(ETIMEDOUT);
    }
    else if (ret < 0)
    {
        return NT_ERR(errno);
    }

    do
    {
        ret = accept(sockfd, addr, addrlen);
    } while (ret == -1 && errno == EINTR);

    return ret < 0 ? NT_ERR(errno) : ret;
}

int nt_send_timed(int sockfd, const void* data, size_t size, uint32_t timeout)
{
    const uint8_t* p_data = data;
    const uint64_t start_time = nt_clock_gettime_ms();
    size_t         offset = 0;

    while (offset < size)
    {
        const uint64_t now_time = nt_clock_gettime_ms();
        uint64_t       diff_time = now_time - start_time;
        if (diff_time >= timeout)
        {
            return NT_ERR(ETIMEDOUT);
        }
        diff_time = timeout - diff_time;

        fd_set wfds;
        FD_ZERO(&wfds);
        FD_SET(sockfd, &wfds);

        struct timeval tv;
        tv.tv_sec = diff_time / 1000;
        tv.tv_usec = (diff_time % 1000) * 1000;
        if (select(sockfd + 1, NULL, &wfds, NULL, &tv) == 0)
        {
            return NT_ERR(ETIMEDOUT);
        }

        ssize_t write_sz = nt_write(sockfd, p_data + offset, size - offset);
        if (write_sz < 0)
        {
            return write_sz;
        }
        offset += write_sz;
    }

    return offset;
}

int nt_recv_timed(int sockfd, void* data, size_t size, uint32_t timeout)
{
    size_t   offset = 0;
    uint64_t start_time = nt_clock_gettime_ms();

    while (offset < size)
    {
        uint64_t now_time = nt_clock_gettime_ms();
        uint64_t diff_time = now_time - start_time;
        if (diff_time >= timeout)
        {
            return NT_ERR(ETIMEDOUT);
        }
        diff_time = timeout - diff_time;

        fd_set rfds;
        FD_ZERO(&rfds);
        FD_SET(sockfd, &rfds);

        struct timeval tv;
        tv.tv_sec = diff_time / 1000;
        tv.tv_usec = (diff_time % 1000) * 1000;
        if (select(sockfd + 1, &rfds, NULL, NULL, &tv) == 0)
        {
            return NT_ERR(ETIMEDOUT);
        }

        ssize_t read_sz = nt_read(sockfd, (uint8_t*)data + offset, size - offset);
        if (read_sz < 0)
        {
            return read_sz;
        }
        else if (read_sz == 0)
        {
            break;
        }
        offset += read_sz;
    }

    return offset;
}
