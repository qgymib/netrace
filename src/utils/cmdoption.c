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
        continue;                                                                                  \
    } while (0)

/* clang-format off */
static const char* s_help =
CMAKE_PROJECT_NAME " - Trace and redirect network traffic (" CMAKE_PROJECT_VERSION ")\n"
"Usage: " CMAKE_PROJECT_NAME " [options] prog [prog-args]\n"
"Options:\n"
"  --proxy=socks5://[user[:pass]@][host[:port]]\n"
"      Set socks5 address.\n"
"\n"
"  --dns=udp://ip[:port]\n"
"      End DNS redirection. If this option is enabled, " CMAKE_PROJECT_NAME " start a builtin\n"
"      DNS proxy, and redirect DNS request to the server.\n"
"\n"
"      The `port` is optional. If it is not set, treat as `53`.\n"
"\n"
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
"  -h, --help\n"
"      Show this help and exit.\n"
;
/* clang-format on */

static void s_setup_cmdline_append_prog_args(nt_cmd_opt_t* opt,const char* arg)
{
    /* The first argument. */
    if (opt->prog_args == NULL)
    {
        opt->prog_args = (char**)nt_malloc(sizeof(char*) * 2);
        opt->prog_args[0] = nt_strdup(arg);
        opt->prog_args[1] = NULL;
        return;
    }

    /* More arguments. */
    size_t prog_nargs = 0;
    while (opt->prog_args[prog_nargs] != NULL)
    {
        prog_nargs++;
    }
    opt->prog_args = nt_realloc(opt->prog_args, sizeof(char*) * (prog_nargs + 2));
    opt->prog_args[prog_nargs] = nt_strdup(arg);
    opt->prog_args[prog_nargs + 1] = NULL;
}

void nt_cmd_opt_parse(nt_cmd_opt_t* opt, int argc, char** argv)
{
    int i, flag_prog_args=0;
    memset(opt, 0, sizeof(*opt));

    for (i = 1; i < argc; i++)
    {
        if (flag_prog_args)
        {
            s_setup_cmdline_append_prog_args(opt, argv[i]);
            continue;
        }

        if (argv[i][0] != '-')
        {
            s_setup_cmdline_append_prog_args(opt, argv[i]);
            flag_prog_args = 1;
            continue;
        }

        if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0)
        {
            fprintf(stdout, "%s\n", s_help);
            exit(EXIT_SUCCESS);
        }

        NT_CMD_PARSE_OPTION(opt->opt_proxy, "--proxy");
        NT_CMD_PARSE_OPTION(opt->opt_bypass, "--bypass");
        NT_CMD_PARSE_OPTION(opt->opt_dns, "--dns");
    }

    if (opt->prog_args == NULL)
    {
        LOG_E("Missing program path");
        exit(EXIT_FAILURE);
    }
    if (opt->opt_proxy == NULL)
    {
        opt->opt_proxy = "socks5://" NT_DEFAULT_SOCKS5_ADDR ":" STRINGIFY(NT_DEFAULT_SOCKS5_PORT);
    }
    if (opt->opt_bypass == NULL)
    {
        opt->opt_bypass = "default";
    }
}

void nt_cmd_opt_free(nt_cmd_opt_t* opt)
{
    size_t i;
    for (i = 0; opt->prog_args != NULL && opt->prog_args[i] != NULL; i++)
    {
        nt_free(opt->prog_args[i]);
    }
    nt_free(opt->prog_args);
}
