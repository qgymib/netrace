#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include "utils/defs.h"
#include "__init__.h"

static const nt_test_tool_t* s_tools[] = {
    &nt_test_tool_exit,
    &nt_test_tool_help,
    &nt_test_tool_slice,
};

// clang-format off
static const char* s_test_help =
"This program contains tests written using cutest. You can use the\n"
"following command line flags to control its behavior:\n"
"\n"
"Test Selection:\n"
"  --help\n"
"      Show what features cutest support.\n"
"\n"
"Tool Selection:\n"
"  --\n"
"      By using `-- [CMD]` (pay attention to the space) you are able to launch\n"
"      builtin tools. Anything followed by `--` will be treat as command\n"
"      arguments to builtin tools. After builtin tools finished, the program\n"
"      will exit.\n";
// clang-format on

static void _print_help(const char* help, const char* prefix)
{
    size_t i;
    int    flag_need_prefix = 1;

    for (i = 0; help[i] != '\0'; i++)
    {
        if (flag_need_prefix)
        {
            flag_need_prefix = 0;
            printf("%s", prefix);
        }

        printf("%c", help[i]);

        if (help[i] == '\n')
        {
            flag_need_prefix = 1;
        }
    }
}

static int nt_test_tool_help_main(int argc, char* argv[])
{
    (void)argc;
    (void)argv;

    fprintf(stdout, "%s", s_test_help);

    size_t i;
    for (i = 0; i < ARRAY_SIZE(s_tools); i++)
    {
        const nt_test_tool_t* tool = s_tools[i];
        fprintf(stdout, "  -- %s\n", tool->name);
        if (tool->help != NULL)
        {
            _print_help(tool->help, "      ");
        }
    }

    return 0;
}

// clang-format off
const nt_test_tool_t nt_test_tool_help = {
"help", nt_test_tool_help_main,
"Show this help and exit.\n"
};
// clang-format on

int nt_test_tool_exec(const char* name, int argc, char* argv[])
{
    size_t i;
    for (i = 0; i < ARRAY_SIZE(s_tools); i++)
    {
        const nt_test_tool_t* tool = s_tools[i];
        if (strcmp(tool->name, name) == 0)
        {
            return tool->entry(argc, argv);
        }
    }

    fprintf(stderr, "Unknown tool `%s`.\n", name);
    exit(EXIT_FAILURE);
}
