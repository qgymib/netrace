#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include "__init__.h"

static int nt_test_tool_exit_main(int argc, char* argv[])
{
    int         i;
    const char* opt;
    int         code = 0;

    for (i = 0; i < argc; i++)
    {
        opt = "--code=";
        if (strncmp(argv[i], opt, strlen(opt)) == 0)
        {
            if (sscanf(argv[i] + strlen(opt), "%d", &code) != 1)
            {
                fprintf(stderr, "Invalid argument to `--code`.\n");
                exit(EXIT_FAILURE);
            }
        }
    }

    exit(code);
}

// clang-format off
const nt_test_tool_t nt_test_tool_exit = {
"exit", nt_test_tool_exit_main,
"--code=number\n"
"    Set exit code.\n"
};
// clang-format on
