#undef NDEBUG
#include <assert.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include "tools/slice.h"
#include "utils/socket.h"
#include "runtime.h"

typedef struct test_connect_ctx
{
    int listen_fd;
} test_connect_ctx_t;

static test_connect_ctx_t* s_connect = NULL;

/**
 * @brief Create a new tcp socket and bind to specific address and to listen.
 * @param[out] fd The created fd.
 * @param[in] ip IP.
 * @param[in] port Port.
 * @param[in] type SOCK_STREAM / SOCK_DGRAM
 * @return 0 for success, or errno for error.
 */
static int s_tcp_listen(int* fd, const char* ip, int port, int type)
{
    int family = strstr(ip, ":") != NULL ? AF_INET6 : AF_INET;
    int sockfd = socket(family, type, 0);
    if (sockfd < 0)
    {
        return errno;
    }

    struct sockaddr_storage sockaddr;
    nt_ip_addr(ip, port, (struct sockaddr*)&sockaddr);

    if (bind(sockfd, (struct sockaddr*)&sockaddr, sizeof(sockaddr)) < 0)
    {
        close(sockfd);
        return errno;
    }

    if (listen(sockfd, 1024) < 0)
    {
        close(sockfd);
        return errno;
    }

    *fd = sockfd;
    return 0;
}

TEST_FIXTURE_SETUP(connect)
{
    s_connect = calloc(1, sizeof(test_connect_ctx_t));
    s_connect->listen_fd = -1;
}

TEST_FIXTURE_TEARDOWN(connect)
{
    close(s_connect->listen_fd);
    free(s_connect);
    s_connect = NULL;
}

TEST_SUBROUTE(connect_memory_consistency_ipv4_0)
{
    const char* data = nt_slice_data();
    const char* ip = "127.0.0.1";
    int port = 0;
    assert(sscanf(data, "--port=%d", &port) == 1);

    struct sockaddr_in addr, back;
    memset(&addr, 0, sizeof(addr));
    nt_ip_addr(ip, port, (struct sockaddr*)&addr);
    memcpy(&back, &addr, sizeof(addr));

    int clientfd = socket(AF_INET, SOCK_STREAM, 0);
    assert(clientfd >= 0);
    assert(connect(clientfd, (struct sockaddr*)&addr, sizeof(addr)) == 0);
    close(clientfd);

    assert(memcmp(&addr, &back, sizeof(addr)) == 0);
}

TEST_F(connect, memory_consistency_ipv4)
{
    /* Listen random IPv4 port. */
    ASSERT_EQ_INT(s_tcp_listen(&s_connect->listen_fd, "127.0.0.1", 0, SOCK_STREAM), 0);

    /* Get actual listen port. */
    struct sockaddr_in addr;
    socklen_t          addrlen = sizeof(addr);
    ASSERT_EQ_INT(getsockname(s_connect->listen_fd, (struct sockaddr*)&addr, &addrlen), 0);

    char buff[64];
    snprintf(buff, sizeof(buff), "--port=%d", ntohs(addr.sin_port));
    TEST_CHECK_SUBROUTE(connect_memory_consistency_ipv4_0, buff);
}
