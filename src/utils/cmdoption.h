#ifndef NT_UTILS_CMD_OPTION_H
#define NT_UTILS_CMD_OPTION_H

#include "utils/cstr.h"
#include "utils/log.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct nt_cmd_opt
{
    nt_log_level_t log_level;  /* --loglevel */
    c_str_t        opt_proxy;  /* --proxy */
    c_str_t        opt_bypass; /* --bypass */
    c_str_t        opt_dns;    /* --dns */
    pid_t*         pid;        /* --pid */
    c_str_arr_t    prog_args;  /* Arguments for child program, ending with NULL. */
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
