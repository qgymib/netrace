#include <errno.h>
#include <stdlib.h>
#include <sys/select.h>
#include "utils/defs.h"
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
