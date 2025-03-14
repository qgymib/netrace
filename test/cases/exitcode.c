#include <sys/wait.h>
#include "runtime.h"

TEST(exitcode, passthrough)
{
    int status = 0;

    char buff[64];
    snprintf(buff, sizeof(buff), "--code=%d", 23);
    ASSERT_EQ_INT(nt_exec(&status, g_test->netrace_path, g_test->netrace_test_path, "--", "exit", buff, NULL), 0);

    ASSERT_NE_INT(WIFEXITED(status), 0);
    ASSERT_EQ_INT(WEXITSTATUS(status), 23);
}
