#ifndef NT_TEST_TOOL_SLICE_H
#define NT_TEST_TOOL_SLICE_H

#include "utils/map.h"

#define TEST_SUBROUTE(FUNC)                                                                                            \
    TEST_C_API void s_ntest_body_##FUNC(void);                                                                         \
    TEST_INITIALIZER(ntest_initializer_##FUNC)                                                                         \
    {                                                                                                                  \
        static test_slice_t slice = {                                                                                  \
            EV_MAP_NODE_INIT,                                                                                          \
            #FUNC,                                                                                                     \
            s_ntest_body_##FUNC,                                                                                       \
        };                                                                                                             \
        nt_register_slice(&slice);                                                                                     \
    }                                                                                                                  \
    TEST_C_API void s_ntest_body_##FUNC(void)

/**
 * @brief Call subroute and check result.
 */
#define TEST_CHECK_SUBROUTE(FUNC, data) ASSERT_EQ_INT(nt_netrace_slice(#FUNC, data), 0)

#ifdef __cplusplus
extern "C" {
#endif

typedef struct test_slice
{
    ev_map_node_t node;
    const char*   name;
    void (*entry)(void);
} test_slice_t;

/**
 * @brief Register slice.
 */
void nt_register_slice(test_slice_t* slice);

/**
 * @brief Run slice.
 * @warning Use #TEST_CHECK_SUBROUTE().
 * @param[in] name The name of slice.
 * @param[in] data Slice parameter.
 * @return If success.
 */
int nt_netrace_slice(const char* name, const char* data);

/**
 * @brief Get slice data.
 * @return Data.
 */
const char* nt_slice_data(void);

#ifdef __cplusplus
}
#endif
#endif
