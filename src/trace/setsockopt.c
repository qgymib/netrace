#include <netinet/ip.h>
#include "utils/defs.h"
#include "utils/socket.h"
#include "utils/syscall.h"
#include "utils/str.h"
#include "__init__.h"
#include "config.h"

/**
 * @brief Socket option decode function.
 * @param[in] sc        String context.
 * @param[in] si        Syscall information.
 * @param[in] optlen    Option length.
 */
typedef void (*sock_option_decode_fn)(nt_strcat_t* sc, const nt_syscall_info_t* si,
                                      socklen_t optlen);

typedef struct sock_option
{
    int                   level;  /* Option level. */
    int                   option; /* Option ID. */
    const char*           name;   /* Option name. */
    sock_option_decode_fn decode; /* Parameter decoder. */
} sock_option_t;

/**
 * @brief An array that maps socket option protocol levels to their corresponding names.
 *
 * This array provides a mapping between protocol level constants used in socket-related
 * operations (e.g., setsockopt) and their human-readable string representations.
 * Each entry in the array associates a protocol level value (e.g., `SOL_SOCKET`, `SOL_IP`)
 * with its corresponding descriptive name.
 *
 * The entries in this array facilitate converting protocol level identifiers into readable
 * formats for debugging, logging, or other human-facing contexts. These mappings cover
 * various protocol families and transport mechanisms supported by the network stack.
 *
 * @note The array entries are used for processing and displaying meaningful information
 *       about socket options across multiple protocol layers in the system.
 *       If a protocol level does not match any entry in the array, the numeric value of
 *       the level is typically displayed instead.
 */
static const nt_type_name_t s_sockopt_level_name[] = {
    { SOL_AAL,       "SOL_AAL"       },
    { SOL_ALG,       "SOL_ALG"       },
    { SOL_ATM,       "SOL_ATM"       },
    { SOL_BLUETOOTH, "SOL_BLUETOOTH" },
    { SOL_CAIF,      "SOL_CAIF"      },
    { SOL_DCCP,      "SOL_DCCP"      },
    { SOL_DECNET,    "SOL_DECNET"    },
    { SOL_ICMPV6,    "SOL_ICMPV6"    },
    { SOL_IP,        "SOL_IP"        },
    { SOL_IPV6,      "SOL_IPV6"      },
    { SOL_IRDA,      "SOL_IRDA"      },
    { SOL_IUCV,      "SOL_IUCV"      },
    { SOL_KCM,       "SOL_KCM"       },
    { SOL_LLC,       "SOL_LLC"       },
    { SOL_NETBEUI,   "SOL_NETBEUI"   },
    { SOL_NETLINK,   "SOL_NETLINK"   },
    { SOL_NFC,       "SOL_NFC"       },
    { SOL_PACKET,    "SOL_PACKET"    },
    { SOL_PNPIPE,    "SOL_PNPIPE"    },
    { SOL_PPPOL2TP,  "SOL_PPPOL2TP"  },
    { SOL_RAW,       "SOL_RAW"       },
    { SOL_RDS,       "SOL_RDS"       },
    { SOL_RXRPC,     "SOL_RXRPC"     },
    { SOL_SOCKET,    "SOL_SOCKET"    },
    { SOL_TIPC,      "SOL_TIPC"      },
    { SOL_TLS,       "SOL_TLS"       },
    { SOL_X25,       "SOL_X25"       },
    { SOL_XDP,       "SOL_XDP"       },
};

/**
 * @brief An array that maps IP type-of-service (TOS) values to their human-readable names.
 *
 * This array provides a mapping between specific TOS constants used in IP header configuration
 * and their descriptive string representations. These TOS values are commonly used to specify
 * the desired quality of service for IP packets, such as low delay, high throughput, high
 * reliability, or low cost.
 *
 * Each entry in the array associates a TOS value (e.g., `IPTOS_LOWDELAY`) with a corresponding
 * readable name, enabling interpretation and display of these values in debugging or logging
 * contexts.
 *
 * @note The array is used as a reference for decoding and displaying TOS values in relevant system
 *       calls (e.g., `setsockopt`) or network operations involving TOS settings.
 *       If a TOS value does not match any entry in the array, its numeric value is typically
 *       displayed.
 */
static const nt_type_name_t s_sockopt_tos_name[] = {
    { IPTOS_LOWDELAY,    "IPTOS_LOWDELAY"    },
    { IPTOS_THROUGHPUT,  "IPTOS_THROUGHPUT"  },
    { IPTOS_RELIABILITY, "IPTOS_RELIABILITY" },
    { IPTOS_LOWCOST,     "IPTOS_LOWCOST"     },
};

static void s_decode_setsockopt_timeval(nt_strcat_t* sc, const nt_syscall_info_t* si,
                                        socklen_t optlen)
{
    struct timeval tv;
    nt_syscall_getdata(si->pid, si->enter.entry.args[3], &tv, optlen);
    nt_strcat(sc, "{tv_sec=%ld, tv_usec=%ld}", (long)tv.tv_sec, (long)tv.tv_usec);
}

static void s_decode_setsockopt_int(nt_strcat_t* sc, const nt_syscall_info_t* si, socklen_t optlen)
{
    int val = 0;
    nt_syscall_getdata(si->pid, si->enter.entry.args[3], &val, optlen);
    nt_strcat(sc, "%d", val);
}

static void s_decode_setsockopt_tos(nt_strcat_t* sc, const nt_syscall_info_t* si, socklen_t optlen)
{
    int val = 0;
    nt_syscall_getdata(si->pid, si->enter.entry.args[3], &val, optlen);

    size_t i;
    for (i = 0; i < ARRAY_SIZE(s_sockopt_tos_name); i++)
    {
        if (s_sockopt_tos_name[i].type == val)
        {
            nt_strcat(sc, "%s", s_sockopt_tos_name[i].name);
            return;
        }
    }
    nt_strcat(sc, "%d", val);
}

static void s_decode_setsockopt_unknown(nt_strcat_t* sc, const nt_syscall_info_t* si,
                                        socklen_t optlen)
{
    if (si->enter.entry.args[3] == 0)
    {
        nt_strcat(sc, "NULL");
        return;
    }
    nt_str_sysdump(sc, si->pid, si->enter.entry.args[3], optlen, NT_MAX_DUMP_SIZE);
}

/**
 * @brief An array of socket option definitions used for decoding setsockopt parameters.
 *
 * This array contains definitions of socket options, grouped by protocol level,
 * with corresponding option constants, human-readable names, and parameter decoding
 * functions. Each entry in the array specifies:
 * - The protocol level (e.g., SOL_IP, SOL_SOCKET, etc.).
 * - The specific option identifier for the protocol level.
 * - The name of the option as a string for debugging or human-readable output.
 * - A pointer to a decoding function that interprets the option's value based on its type
 *   (e.g., integer, time structure).
 *
 * If a decoding function is set to `NULL`, no specific decoding logic is applied for that option.
 *
 * @note The decoding functions, where applicable, handle various data types (e.g., integers,
 *       time-related structures), or map integer values to human-readable string constants.
 *       For example, `IP_TOS` uses a dedicated decoding function to handle Type of Service (ToS)
 *       values.
 */
static const sock_option_t s_setsockopt_decode[] = {
    { SOL_IP,     IP_RECVERR,     "IP_RECVERR",     s_decode_setsockopt_int     },
    { SOL_IP,     IP_TOS,         "IP_TOS",         s_decode_setsockopt_tos     },
    { SOL_IPV6,   IPV6_V6ONLY,    "IPV6_V6ONLY",    s_decode_setsockopt_int     },
    { SOL_SOCKET, SO_KEEPALIVE,   "SO_KEEPALIVE",   s_decode_setsockopt_int     },
    { SOL_SOCKET, SO_RCVTIMEO,    "SO_RCVTIMEO",    s_decode_setsockopt_timeval },
    { SOL_SOCKET, SO_REUSEADDR,   "SO_REUSEADDR",   s_decode_setsockopt_int     },
    { SOL_SOCKET, SO_SNDTIMEO,    "SO_SNDTIMEO",    s_decode_setsockopt_timeval },
    { SOL_SOCKET, SO_TIMESTAMP,   "SO_TIMESTAMP",   NULL                        },
    { SOL_SOCKET, SO_TIMESTAMPNS, "SO_TIMESTAMPNS", NULL                        },
};

static void s_decode_setsockopt_arg0(nt_strcat_t* sc, const nt_syscall_info_t* si)
{
    int sockfd = si->enter.entry.args[0];
    nt_strcat(sc, "%d, ", sockfd);
}

static void s_decode_setsockopt_arg1(nt_strcat_t* sc, int level)
{
    size_t i;
    for (i = 0; i < ARRAY_SIZE(s_sockopt_level_name); i++)
    {
        if (s_sockopt_level_name[i].type == level)
        {
            nt_strcat(sc, "%s, ", s_sockopt_level_name[i].name);
            return;
        }
    }

    nt_strcat(sc, "%d, ", level);
}

static void s_decode_setsockopt_arg2(nt_strcat_t* sc, int option, const sock_option_t* opt)
{
    if (opt != NULL)
    {
        nt_strcat(sc, "%s, ", opt->name);
        return;
    }
    nt_strcat(sc, "%d, ", option);
}

static void s_decode_setsockopt_arg3(nt_strcat_t* sc, const nt_syscall_info_t* si,
                                     const sock_option_t* opt)
{
    if (si->enter.entry.args[3] == 0)
    {
        nt_strcat(sc, "NULL, ");
        return;
    }

    socklen_t optlen = si->enter.entry.args[4];
    if (opt == NULL)
    {
        s_decode_setsockopt_unknown(sc, si, optlen);
    }
    else
    {
        opt->decode(sc, si, optlen);
    }

    nt_strcat(sc, ", ");
}

static void s_decode_setsockopt_arg4(nt_strcat_t* sc, const nt_syscall_info_t* si)
{
    socklen_t optlen = si->enter.entry.args[4];
    nt_strcat(sc, "%u", (unsigned)optlen);
}

/**
 * @brief Finds a socket option entry matching the given protocol level and option ID.
 *
 * This function searches through the predefined array of socket options to locate
 * an entry that matches the specified `level` and `option` values. If a match is
 * found, it returns a pointer to the corresponding socket option structure.
 * Otherwise, it returns `NULL`.
 *
 * The socket option structure contains important metadata about socket options,
 * such as the protocol level, option ID, human-readable name, and a function
 * pointer for custom decoding, if applicable. This function is used to facilitate
 * the identification and processing of specific socket options in network operations.
 *
 * @param[in] level The protocol level of the socket option (e.g., `SOL_SOCKET` or `SOL_IP`).
 * @param[in] option The option identifier within the specified protocol level (e.g.,
 *   `SO_KEEPALIVE`).
 * @return A pointer to the matching socket option structure if found; `NULL` otherwise.
 */
static const sock_option_t* s_setsockopt_find(int level, int option)
{
    size_t i;
    for (i = 0; i < ARRAY_SIZE(s_setsockopt_decode); i++)
    {
        if (s_setsockopt_decode[i].level == level && s_setsockopt_decode[i].option == option)
        {
            return &s_setsockopt_decode[i];
        }
    }
    return NULL;
}

int nt_syscall_decode_setsockopt(const nt_syscall_info_t* si, int op, char* buff, size_t size)
{
    const sock_option_t* opt = NULL;
    nt_strcat_t          sc = NT_STRCAT_INIT(buff, size);
    if (op != PTRACE_SYSCALL_INFO_EXIT)
    {
        return 0;
    }

    nt_strcat(&sc, "(");
    int level = si->enter.entry.args[1];
    int option = si->enter.entry.args[2];
    opt = s_setsockopt_find(level, option);

    s_decode_setsockopt_arg0(&sc, si);
    s_decode_setsockopt_arg1(&sc, level);
    s_decode_setsockopt_arg2(&sc, option, opt);
    s_decode_setsockopt_arg3(&sc, si, opt);
    s_decode_setsockopt_arg4(&sc, si);
    nt_strcat(&sc, ") = %d", (int)si->leave.exit.rval);

    return sc.size;
}
