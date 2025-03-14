#ifndef NT_TEST_TOOL_INIT_H
#define NT_TEST_TOOL_INIT_H
#ifdef __cplusplus
extern "C" {
#endif

typedef struct nt_test_tool
{
    /**
     * @brief Command name.
     */
    const char* name;

    /**
     * @brief Command entrypoint.
     * @param[in] argc The number of arguments.
     * @param[in] argv Argument list.
     * @return Exit code.
     */
    int (*entry)(int argc, char* argv[]);

    /**
     * @brief Help message.
     */
    const char* help;
} nt_test_tool_t;

extern const nt_test_tool_t nt_test_tool_exit;
extern const nt_test_tool_t nt_test_tool_help;
extern const nt_test_tool_t nt_test_tool_slice;

/**
 * @brief Find and execute tool.
 * @param[in] name Tool name.
 * @param[in] argc The number of arguments.
 * @param[in] argv Argument list.
 * @return Exit code.
 */
int nt_test_tool_exec(const char* name, int argc, char* argv[]);

#ifdef __cplusplus
}
#endif
#endif
