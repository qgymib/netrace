#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "utils/defs.h"
#include "runtime.h"
#include "slice.h"
#include "__init__.h"

static int s_on_cmp_slice(const ev_map_node_t* key1, const ev_map_node_t* key2, void* arg)
{
    (void)arg;
    const test_slice_t* s1 = container_of(key1, test_slice_t, node);
    const test_slice_t* s2 = container_of(key2, test_slice_t, node);
    return strcmp(s1->name, s2->name);
}

static ev_map_t      s_slice_map = EV_MAP_INIT(s_on_cmp_slice, NULL);
static test_slice_t* s_slice = NULL;
static const char*   s_data = NULL;

static int nt_test_tool_slice_main(int argc, char* argv[])
{
    const char* opt;
    size_t      optlen;
    int         i;
    const char* name = NULL;
    for (i = 0; i < argc; i++)
    {
        opt = "--name";
        optlen = strlen(opt);
        if (strncmp(argv[i], opt, optlen) == 0)
        {
            if (argv[i][optlen] == '=')
            {
                name = argv[i] + optlen + 1;
            }
            else if (i == argc - 1)
            {
                fprintf(stderr, "Missing value for `--name`.\n");
                abort();
            }
            else
            {
                i++;
                name = argv[i];
            }

            continue;
        }

        opt = "--data";
        optlen = strlen(opt);
        if (strncmp(argv[i], opt, optlen) == 0)
        {
            if (argv[i][optlen] == '=')
            {
                s_data = argv[i] + optlen;
            }
            else if (i == argc - 1)
            {
                fprintf(stderr, "Missing value for `--data`.\n");
                abort();
            }
            else
            {
                i++;
                s_data = argv[i];
            }
            continue;
        }
    }

    if (name == NULL)
    {
        fprintf(stderr, "Missing argument `--name`.\n");
        abort();
    }

    test_slice_t tmp;
    tmp.name = name;
    ev_map_node_t* it = ev_map_find(&s_slice_map, &tmp.node);
    if (it == NULL)
    {
        fprintf(stderr, "Cannot find `%s`.\n", name);
        abort();
    }

    s_slice = container_of(it, test_slice_t, node);
    s_slice->entry();

    return 0;
}

// clang-format off
const nt_test_tool_t nt_test_tool_slice = {
"slice", nt_test_tool_slice_main,
"Execute a function, for internal usage.\n"
"  --name=[name]\n"
"      Specific function address to execute. The function must have protocol:\n"
"      `int (*)(const char*)`\n"
"  --data=[string]\n"
"      String passed to function.\n"
};
// clang-format on

void nt_register_slice(test_slice_t* slice)
{
    ev_map_insert(&s_slice_map, &slice->node);
}

int nt_netrace_slice(const char* name, const char* data)
{
    int wstatus = 0;

    ASSERT_EQ_INT(nt_exec(&wstatus, g_test->netrace_path, g_test->netrace_test_path, "--", "slice", "--name", name,
                          "--data", data, NULL),
                  0);
    ASSERT_NE_INT(WIFEXITED(wstatus), 0);
    return WEXITSTATUS(wstatus);
}

const char* nt_slice_data(void)
{
    return s_data;
}
