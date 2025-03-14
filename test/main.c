#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include "tools/__init__.h"
#include "runtime.h"

static void s_before_all_test(int argc, char* argv[])
{
    int         i;
    const char* opt;

    g_test = calloc(1, sizeof(test_ctx_t));
    for (i = 0; i < argc; i++)
    {
        if (strcmp(argv[i], "--") == 0)
        {
            if (i == argc - 1)
            {
                fprintf(stderr, "Missing tool name after `-- `.\n");
                exit(EXIT_FAILURE);
            }
            i++;
            int ret = nt_test_tool_exec(argv[i], argc - i, argv + i);
            exit(ret);
        }

        opt = "--netrace=";
        if (strncmp(argv[i], opt, strlen(opt)) == 0)
        {
            free(g_test->netrace_path);
            g_test->netrace_path = strdup(argv[i] + strlen(opt));
            continue;
        }
    }

    if (g_test->netrace_path == NULL)
    {
        fprintf(stderr, "Missing argument `--netrace`.\n");
        exit(EXIT_FAILURE);
    }

    readlink("/proc/self/exe", g_test->netrace_test_path, sizeof(g_test->netrace_test_path));
}

static void s_after_all_test()
{
    free(g_test->netrace_path);
    g_test->netrace_path = NULL;

    free(g_test);
    g_test = NULL;
}

int main(int argc, char* argv[])
{
    // clang-format off
    cutest_hook_t hook = {
        s_before_all_test,
        s_after_all_test,
        NULL,
        NULL,
        NULL,
        NULL,
        NULL,
        NULL,
    };
    // clang-format on

    return cutest_run_tests(argc, argv, stdout, &hook);
}
