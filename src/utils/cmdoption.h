#ifndef NT_UTILS_CMD_OPTION_H
#define NT_UTILS_CMD_OPTION_H

#include "utils/log.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct nt_cmd_opt
{
    const char*    opt_proxy;  /* --proxy */
    const char*    opt_bypass; /* --bypass */
    const char*    opt_dns;    /* --dns */
    nt_log_level_t log_level;  /* --loglevel */
    char**         prog_args;  /* Arguments for child program, ending with NULL. */
} nt_cmd_opt_t;

/**
 * @brief Parser command line options.
 * @param[out] opt  Options.
 * @param[in] argc  The number of arguments.
 * @param[in] argv  Argument list.
 */
void nt_cmd_opt_parse(nt_cmd_opt_t* opt, int argc, char** argv);

/**
 * @brief Release command line options.
 * @param[in] opt Options.
 */
void nt_cmd_opt_free(nt_cmd_opt_t* opt);

#ifdef __cplusplus
}
#endif
#endif
