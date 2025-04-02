#ifndef NT_TEST_RUNTIME_H
#define NT_TEST_RUNTIME_H

#include "cutest.h"
#include "utils/log.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef void (*nt_slice_fn)(const char* data);

typedef struct test_ctx
{
    char* netrace_path;            /* Path to netrace. */
    char  netrace_test_path[4096]; /* Path to test suit. */
} test_ctx_t;

extern test_ctx_t* g_test;

/**
 * @brief Execute program and get return status.
 * @param[out] status Status information.
 * @param[in] file Program path.
 * @param[in] ... Program arguments, must end with NULL.
 * @return 0 for execute success, or errno.
 */
int nt_exec(int* status, const char* file, ...);

#ifdef __cplusplus
}
#endif
#endif
