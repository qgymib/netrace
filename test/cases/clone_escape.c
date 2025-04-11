#define _GNU_SOURCE
#include <errno.h>
#include <sched.h>
#include <unistd.h>
#include <pthread.h>
#include <sys/wait.h>
#include "utils/defs.h"
#include "utils/memory.h"
#include "utils/socket2.h"
#include "utils/msg.h"
#include "tools/slice.h"
#include "runtime.h"

typedef struct test_syscall_clone
{
    int                     listen_sock;
    struct sockaddr_storage bind_addr;
    struct sockaddr_storage peer_addr;
    uint8_t                 buff[4 * 1024];
} test_syscall_clone_t;

static test_syscall_clone_t* s_test_syscall_clone = NULL;

TEST_FIXTURE_SETUP(syscall)
{
    s_test_syscall_clone = nt_calloc(1, sizeof(test_syscall_clone_t));
    s_test_syscall_clone->listen_sock =
        nt_socket_listen("127.0.0.1", 0, 0, &s_test_syscall_clone->bind_addr);
    ASSERT_GE_INT(s_test_syscall_clone->listen_sock, 0);
}

TEST_FIXTURE_TEARDOWN(syscall)
{
    close(s_test_syscall_clone->listen_sock);
    nt_free(s_test_syscall_clone);
    s_test_syscall_clone = NULL;
}

static int s_syscall_clone_granchild(void* arg)
{
    int                     port = (int)(uintptr_t)arg;
    struct sockaddr_storage peer_addr;
    NT_ASSERT(nt_ip_addr("127.0.0.1", port, (struct sockaddr*)&peer_addr) == 0,
              "Convert to addr failed");

    int fd = nt_socket_connect(SOCK_STREAM, &peer_addr, 0);
    NT_ASSERT(fd >= 0, "(%d) %s.", fd, NT_STRERROR(fd));

    struct sockaddr_storage local_addr;
    socklen_t               addr_len = sizeof(local_addr);
    NT_ASSERT(getsockname(fd, (struct sockaddr*)&local_addr, &addr_len) == 0, "(%d) %s.", errno,
              strerror(errno));

    NT_ASSERT(nt_msg_send(fd, &local_addr, sizeof(local_addr)) == sizeof(local_addr),
              "Message send failed");
    close(fd);

    return 0;
}

TEST_SUBROUTE(syscall_clone_escape)
{
    const char* args = nt_slice_data();
    int         port = 0;
    NT_ASSERT(sscanf(args, "--port=%d", &port) == 1, "Invalid argument");

    size_t stack_sz = 8 * 1024 * 1024; /* 8M Stack should be enough. */
    char*  p_stack = nt_malloc(stack_sz);
    pid_t  pid = clone(s_syscall_clone_granchild, p_stack + stack_sz,
                       CLONE_CHILD_CLEARTID | CLONE_CHILD_SETTID | CLONE_UNTRACED,
                       (void*)(uintptr_t)port, NULL);
    waitpid(pid, NULL, 0);

    nt_free(p_stack);
}

static void* s_syscall_clone_escape_thread(void* arg)
{
    (void)arg;

    int              srvfd = s_test_syscall_clone->listen_sock;
    struct sockaddr* addr = (struct sockaddr*)&s_test_syscall_clone->peer_addr;
    socklen_t        addr_len = sizeof(s_test_syscall_clone->peer_addr);
    int              fd = accept(srvfd, addr, &addr_len);
    ASSERT_GE_INT(fd, 0);

    ASSERT_EQ_INT(nt_msg_recv(fd, s_test_syscall_clone->buff, sizeof(s_test_syscall_clone->buff)),
                  sizeof(struct sockaddr_storage));

    close(fd);

    return NULL;
}

TEST_F(syscall, clone)
{
    pthread_t tid;
    pthread_create(&tid, NULL, s_syscall_clone_escape_thread, NULL);

    /* Run program */
    {
        int              port = 0;
        struct sockaddr* addr = (struct sockaddr*)&s_test_syscall_clone->bind_addr;
        ASSERT_EQ_INT(nt_ip_name(addr, NULL, 0, &port), 0);

        char buff[64];
        snprintf(buff, sizeof(buff), "--port=%d", port);
        TEST_CHECK_SUBROUTE(syscall_clone_escape, buff);
    }

    pthread_join(tid, NULL);

    /* This is the client port from the server. */
    int peer_port = 0;
    ASSERT_EQ_INT(
        nt_ip_name((struct sockaddr*)&s_test_syscall_clone->peer_addr, NULL, 0, &peer_port), 0);
    /* This is the client port from the client. */
    int client_port = 0;
    ASSERT_EQ_INT(nt_ip_name((struct sockaddr*)s_test_syscall_clone->buff, NULL, 0, &client_port),
                  0);
    /* These two port should different. */
    ASSERT_NE_INT(peer_port, client_port);
}
