#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "utils/defs.h"
#include "utils/memory.h"
#include "utils/log.h"
#include "cmdoption.h"
#include "config.h"

#define NT_CMD_PARSE_OPTION(val, opt)                                                              \
    do                                                                                             \
    {                                                                                              \
        const char* _opt = (opt);                                                                  \
        size_t      _optlen = strlen(_opt);                                                        \
        if (strncmp(argv[i], _opt, _optlen) != 0)                                                  \
        {                                                                                          \
            break;                                                                                 \
        }                                                                                          \
        if (argv[i][_optlen] == '=')                                                               \
        {                                                                                          \
            val = &argv[i][_optlen + 1];                                                           \
        }                                                                                          \
        else if (i == argc - 1)                                                                    \
        {                                                                                          \
            fprintf(stderr, "Missing value for option `%s`.\n", _opt);                             \
            exit(EXIT_FAILURE);                                                                    \
        }                                                                                          \
        else                                                                                       \
        {                                                                                          \
            i++;                                                                                   \
            val = argv[i];                                                                         \
        }                                                                                          \
        goto CONTINUE;                                                                             \
    } while (0)

/* clang-format off */
static const char* s_help =
CMAKE_PROJECT_NAME " - Trace and redirect network traffic (" NT_VERSION ")\n"
"Usage: " CMAKE_PROJECT_NAME " [options] prog [prog-args]\n"
"Options:\n"
"  --bypass=RULE_LIST\n"
"      Syntax:\n"
"        RULE_LIST    := [RULE[,RULE,...]]\n"
"        RULE         := [default]\n"
"                        [TYPE://ip[:port][/?OPTIONS]]\n"
"        TYPE         := [tcp | udp]\n"
"        OPTIONS      := [OPTION[&OPTION&...]]\n"
"        OPTION       := [mask=NUMBER]\n"
"\n"
"      Description:\n"
"        Do not redirect any traffic if it match any of the rules. By default\n"
"        all traffics to LAN and loopback are ignored. By using this option,\n"
"        the builtin filter rules are overwritten, however you can use `default`\n"
"        keyword to add these rules again.\n"
"\n"
"        The `port` is optional. If it is set to non-zero, only traffic send to\n"
"        that port is ignored.\n"
"\n"
"        The `mask` is optional. If it is not set, treat as `32` for IPv4 or\n"
"        `128` for IPv6.\n"
"\n"
"      Example:\n"
"        --bypass=,\n"
"            Redirect anything.\n"
"        --bypass=udp://127.0.0.1\n"
"            Only ignore udp packets send to 127.0.0.1, no matter which\n"
"            destination port is.\n"
"        --bypass=tcp://192.168.0.1:1234\n"
"            Only ignore tcp transmissions connect to 192.168.0.1:1234\n"
"        --bypass=default,udp://0.0.0.0/?mask=0\n"
"            In addition to the default rules, ignore all IPv4 UDP transmissions.\n"
"        --bypass=default,udp://0.0.0.0/?mask=0,udp://:::53/?mask=0\n"
"            In addition to the default rules, ignore all IPv4 UDP transmissions,\n"
"            ignore all IPv6 UDP transmissions whose destination port is 53.\n"
"\n"
"  --config=[path]\n"
"      Set configuration file path to load.\n"
"\n"
"  --dns=udp://ip[:port]\n"
"      End DNS redirection. If this option is enabled, " CMAKE_PROJECT_NAME " start a builtin\n"
"      DNS proxy, and redirect DNS request to the server.\n"
"\n"
"      The `port` is optional. If it is not set, treat as `53`.\n"
"\n"
"  --gid=[gid]\n"
"      Set group ID.\n"
"\n"
"  -h, --help\n"
"      Show this help and exit.\n"
"\n"
"  --loglevel=[debug|info|warn|error]\n"
"      Set log level, case insensitive. By default set to `info`.\n"
"\n"
"  --proxy=socks5://[user[:pass]@][host[:port]]\n"
"      Set socks5 address.\n"
"\n"
"  --uid=[uid]\n"
"      Set user ID.\n"
;
/* clang-format on */

void nt_cmd_opt_parse(nt_cmd_opt_t* opt, int argc, char** argv)
{
    int         i, flag_prog_args = 0;
    const char* opt_bypass = NULL;
    const char* opt_config = NULL;
    const char* opt_dns = NULL;
    const char* opt_gid = NULL;
    const char* log_level = NULL;
    const char* opt_proxy = NULL;
    const char* opt_uid = NULL;

    for (i = 1; i < argc; i++)
    {
        if (flag_prog_args)
        {
            opt->prog_args = c_str_arr_cat(opt->prog_args, argv[i]);
            continue;
        }

        if (argv[i][0] != '-')
        {
            opt->prog_args = c_str_arr_cat(opt->prog_args, argv[i]);
            flag_prog_args = 1;
            continue;
        }

        if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0)
        {
            fprintf(stdout, "%s\n", s_help);
            exit(EXIT_SUCCESS);
        }

        NT_CMD_PARSE_OPTION(opt_bypass, "--bypass");
        NT_CMD_PARSE_OPTION(opt_config, "--config");
        NT_CMD_PARSE_OPTION(opt_dns, "--dns");
        NT_CMD_PARSE_OPTION(opt_gid, "--gid");
        NT_CMD_PARSE_OPTION(log_level, "--loglevel");
        NT_CMD_PARSE_OPTION(opt_proxy, "--proxy");
        NT_CMD_PARSE_OPTION(opt_uid, "--uid");

        LOG_E("Unknown option `%s`.", argv[i]);
        exit(EXIT_FAILURE);

    CONTINUE:
    }

    opt->bypass = (opt_bypass != NULL) ? c_str_new(opt_bypass) : NULL;
    opt->config = (opt_config != NULL) ? c_str_new(opt_config) : NULL;
    opt->dns = (opt_dns != NULL) ? c_str_new(opt_dns) : NULL;
    opt->gid = (opt_gid != NULL) ? c_str_new(opt_gid) : NULL;
    opt->proxy = (opt_proxy != NULL) ? c_str_new(opt_proxy) : NULL;
    opt->loglevel = (log_level != NULL) ? c_str_new(log_level) : NULL;
    opt->uid = (opt_uid != NULL) ? c_str_new(opt_uid) : NULL;
    if (opt->prog_args == NULL)
    {
        LOG_E("Missing program path");
        exit(EXIT_FAILURE);
    }
}

void nt_cmd_opt_free(nt_cmd_opt_t* opt)
{
    c_str_free(opt->bypass);
    c_str_free(opt->config);
    c_str_free(opt->dns);
    c_str_free(opt->gid);
    c_str_free(opt->loglevel);
    c_str_free(opt->proxy);
    c_str_free(opt->uid);
    c_str_free(opt->prog_args);
}
