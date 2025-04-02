#undef NDEBUG
#include <assert.h>
#include <errno.h>
#include <stdlib.h>
#include <unistd.h>
#include <pthread.h>
#include <arpa/inet.h>
#include <sys/wait.h>
#include <sys/socket.h>
#include "utils/socket2.h"
#include "tools/slice.h"
#include "runtime.h"

typedef struct test_grandchild
{
    int                listen_fd;
    struct sockaddr_in listen_addr;
    int                looping;
    pthread_t          tid;
} test_grandchild_t;

static test_grandchild_t* s_grandchild = NULL;

static void* s_grandchild_worker(void* arg)
{
    (void)arg;

    while (s_grandchild->looping)
    {
        int fd = nt_accept_timed(s_grandchild->listen_fd, NULL, NULL, 100);
        if (fd >= 0)
        {
            close(fd);
        }
    }

    return NULL;
}

TEST_FIXTURE_SETUP(grandchild)
{
    s_grandchild = calloc(1, sizeof(test_grandchild_t));
    s_grandchild->listen_fd = socket(AF_INET, SOCK_STREAM, 0);
    ASSERT_GE_INT(s_grandchild->listen_fd, 0);

    /* Bind to random local port. */
    struct sockaddr* addr = (struct sockaddr*)&s_grandchild->listen_addr;
    socklen_t        addrlen = sizeof(s_grandchild->listen_addr);
    nt_ip_addr("127.0.0.1", 0, addr);
    ASSERT_EQ_INT(bind(s_grandchild->listen_fd, addr, addrlen), 0);

    /* Get bind address. */
    ASSERT_EQ_INT(getsockname(s_grandchild->listen_fd, addr, &addrlen), 0);

    /* Start listen. */
    ASSERT_EQ_INT(listen(s_grandchild->listen_fd, 1024), 0);

    s_grandchild->looping = 1;
    ASSERT_EQ_INT(pthread_create(&s_grandchild->tid, NULL, s_grandchild_worker, NULL), 0);
}

TEST_FIXTURE_TEARDOWN(grandchild)
{
    s_grandchild->looping = 0;
    pthread_join(s_grandchild->tid, NULL);

    close(s_grandchild->listen_fd);
    free(s_grandchild);
    s_grandchild = NULL;
}

static void s_grandchild_connect_and_close(struct sockaddr_in* remote)
{
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    NT_ASSERT(fd, >=, 0, "socket() failed: (%d) %s", errno, strerror(errno));

    assert(connect(fd, (struct sockaddr*)remote, sizeof(*remote)) == 0);

    /* Get peer address. */
    struct sockaddr_in peeraddr;
    struct sockaddr*   addr = (struct sockaddr*)&peeraddr;
    socklen_t          addrlen = sizeof(peeraddr);
    assert(getpeername(fd, addr, &addrlen) == 0);

    /*
     *
     *
     */
    int remote_port = ntohs(remote->sin_port);
    int peer_port = ntohs(peeraddr.sin_port);
    /* clang-format off */
    NT_ASSERT(peer_port, !=, remote_port,
        "peer_port=%d, remote_port=%d.\n"
        "The `remote_port` is where the test want to connect to. The `peer_port` is where\n"
        "the test actually connect to. Due to the destination is overwritten by netrace,\n"
        "these two value should be different."
        , peer_port, remote_port);
    /* clang-format on */

    close(fd);
}

TEST_SUBROUTE(grandchild_connect)
{
    const char* data = nt_slice_data();
    const char* ip = "127.0.0.1";
    int         port = 0;
    assert(sscanf(data, "--port=%d", &port) == 1);

    struct sockaddr_in addr;
    nt_ip_addr(ip, port, (struct sockaddr*)&addr);
    s_grandchild_connect_and_close(&addr);

    pid_t pid = fork();
    assert(pid >= 0);

    if (pid == 0)
    {
        s_grandchild_connect_and_close(&addr);
        return;
    }

    int wstatus = 0;
    assert(waitpid(pid, &wstatus, 0) == pid);
    assert(WIFEXITED(wstatus));
    assert(WEXITSTATUS(wstatus) == 0);

    s_grandchild_connect_and_close(&addr);
}

TEST_F(grandchild, connect)
{
    char buff[64];
    snprintf(buff, sizeof(buff), "--port=%d", ntohs(s_grandchild->listen_addr.sin_port));
    TEST_CHECK_SUBROUTE(grandchild_connect, buff);
}
