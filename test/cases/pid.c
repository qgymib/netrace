#include <errno.h>
#include <unistd.h>
#include <pthread.h>
#include <fcntl.h>
#include "utils/defs.h"
#include "utils/memory.h"
#include "utils/msg.h"
#include "utils/socket2.h"
#include "utils/time.h"
#include "utils/cstr.h"
#include "runtime.h"

typedef struct test_pid
{
    int                     listen_fd;
    struct sockaddr_storage listen_addr;
} test_pid_t;

static test_pid_t* s_test_pid = NULL;

TEST_FIXTURE_SETUP(pid)
{
    s_test_pid = nt_calloc(1, sizeof(test_pid_t));
    s_test_pid->listen_fd = nt_socket_listen("127.0.0.1", 0, 0, &s_test_pid->listen_addr);
    ASSERT_GE_INT(s_test_pid->listen_fd, 0);
}

TEST_FIXTURE_TEARDOWN(pid)
{
    close(s_test_pid->listen_fd);
    nt_free(s_test_pid);
    s_test_pid = NULL;
}

static void* s_test_pid_srv_thread(void* arg)
{
    (void)arg;
    int client_fd = nt_accept_timed(s_test_pid->listen_fd, NULL, NULL, NT_TIMEOUT_INFINITE);
    ASSERT_GE_INT(client_fd, 0);

    struct sockaddr_storage local_addr;
    socklen_t               addr_len = sizeof(local_addr);
    NT_ASSERT(getsockname(client_fd, (struct sockaddr*)&local_addr, &addr_len) == 0, "(%d) %s.",
              errno, strerror(errno));

    size_t send_sz = sizeof(local_addr);
    NT_ASSERT(nt_msg_send(client_fd, &local_addr, send_sz) == (int)send_sz, "");

    close(client_fd);
    return NULL;
}

static c_str_t s_read_file(const char* path)
{
    int fd = open(path, O_RDONLY);
    if (fd < 0)
    {
        return NULL;
    }

    c_str_t buf = c_str_new("");

    char    buff[1024];
    int     total_sz = 0;
    ssize_t read_sz;
    while ((read_sz = nt_read(fd, buff, sizeof(buff))) > 0)
    {
        buf = c_str_cat_len(buf, buff, read_sz);
        total_sz += read_sz;
    }

    close(fd);
    return buf;
}

static int s_split_tracerid(const char* s, size_t n, void* arg)
{
    (void)n;
    (void)arg;
    const char* pat = "TracerPid:";
    return strncmp(s, pat, strlen(pat));
}

static int s_test_is_traced(void)
{
    /* Read status */
    c_str_t data = s_read_file("/proc/self/status");
    ASSERT_NE_PTR(data, NULL);

    /* Split into lines, find out lines start with `TracerPid:` */
    c_str_arr_t tracer_line = c_str_split_ex(data, "\n", 1, s_split_tracerid, NULL);
    c_str_free(data);
    ASSERT_EQ_SIZE(c_str_arr_len(tracer_line), 1);

    /* Split */
    c_str_arr_t kv = c_str_split(tracer_line[0], ":");
    c_str_free(tracer_line);
    ASSERT_EQ_SIZE(c_str_arr_len(kv), 2);
    kv[1] = c_str_simplified(kv[1]);

    int ret = strcmp(kv[1], "0");
    c_str_free(kv);

    return ret;
}

TEST_F(pid, attach)
{
    pthread_t tid;
    pthread_create(&tid, NULL, s_test_pid_srv_thread, NULL);

    while (!s_test_is_traced())
    {
        nt_sleep(100);
    }

    pthread_join(tid, NULL);
}
