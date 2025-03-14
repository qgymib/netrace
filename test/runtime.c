#include <errno.h>
#include <stdarg.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include "runtime.h"

test_ctx_t* g_test = NULL;

static int nt_exec_parent(pid_t pid, int* status)
{
    int wstatus;
    if (waitpid(pid, &wstatus, 0) < 0)
    {
        return errno;
    }

    *status = wstatus;
    return 0;
}

int nt_exec(int* status, const char* file, ...)
{
    int    ret = 0;
    char** argv = malloc(sizeof(char*) * 2);
    size_t narg = 1;
    argv[0] = strdup(file);
    argv[1] = NULL;

    va_list ap;
    va_start(ap, file);
    {
        const char* v;
        for (v = va_arg(ap, const char*); v != NULL; narg++, v = va_arg(ap, const char*))
        {
            argv = realloc(argv, sizeof(char*) * (narg + 2));
            argv[narg] = strdup(v);
            argv[narg + 1] = NULL;
        }
    }
    va_end(ap);

    pid_t pid = fork();
    if (pid < 0)
    {
        return errno;
    }

    if (pid == 0)
    {
        execv(file, argv);
        exit(EXIT_FAILURE);
    }
    else
    {
        ret = nt_exec_parent(pid, status);
    }

    for (narg = 0; argv[narg] != NULL; narg++)
    {
        free(argv[narg]);
    }
    free(argv);

    return ret;
}
