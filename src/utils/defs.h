#ifndef NT_UTILS_DEFINES_H
#define NT_UTILS_DEFINES_H

#include <errno.h>

#ifndef offsetof
#define offsetof(type, member) ((size_t)&(((type*)0)->member))
#endif

#ifndef container_of
#if defined(__GNUC__) || defined(__clang__)
#define container_of(ptr, type, member)                                                            \
    ({                                                                                             \
        const typeof(((type*)0)->member)* __mptr = (ptr);                                          \
        (type*)((char*)__mptr - offsetof(type, member));                                           \
    })
#else
#define container_of(ptr, type, member) ((type*)((char*)(ptr) - offsetof(type, member)))
#endif
#endif

#ifndef NT_MAX
#define NT_MAX(a, b) ((a) > (b) ? (a) : (b))
#endif

#ifndef NT_MIN
#define NT_MIN(a, b) ((a) < (b) ? (a) : (b))
#endif

#ifndef ARRAY_SIZE
#define ARRAY_SIZE(x) (sizeof(x) / sizeof(x[0]))
#endif

/**
 * @brief Align \p size to \p align, who's value is larger or equal to \p size
 *   and can be divided with no remainder by \p align.
 * @note \p align must equal to 2^n
 */
#define ALIGN_SIZE(size, align)                                                                    \
    (((uintptr_t)(size) + ((uintptr_t)(align) - 1)) & ~((uintptr_t)(align) - 1))

#ifndef STRINGIFY
#define STRINGIFY(x) STRINGIFY2(x)
#define STRINGIFY2(x) #x
#endif

/**
 * @brief Check if \p addr is AF_INET or AF_INET6.
 * @param[in] addr `struct sockaddr*` compatible address.
 */
#define NT_IS_IP_FAMILY(addr)                                                                      \
    ((((struct sockaddr*)(addr))->sa_family == AF_INET) ||                                         \
     (((struct sockaddr*)(addr))->sa_family == AF_INET6))

/**
 * @brief Convert posix errno to netrace errno.
 */
#if EDOM > 0
#define NT_ERR(x) (-(x))
#define NT_STRERROR(x) strerror(-(x))
#else
#define NT_ERR(x) (x)
#define NT_STRERROR(x) strerror(x)
#endif

/**
 * @brief Get original system errno.
 * @param[in] x Wrapped errno
 * @return Raw system errno.
 */
#define NT_RAWERR(x) NT_ERR(x)

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Structure representing a mapping between a type identifier and its corresponding name.
 *
 * The `nt_type_name` structure is used to define an association between a numeric type identifier
 * and its human-readable name as a string. This structure is primarily intended to facilitate
 * converting numeric constants, such as those used for socket types or domains, into
 * descriptive textual representations. Such mappings are often useful for debugging,
 * user interface displays, or log outputs.
 *
 * The structure consists of the following members:
 * - `type`: An integer representing the numeric identifier for the type (e.g., a socket type or
 *   domain).
 * - `name`: A pointer to a constant character string representing the human-readable name
 *   of the type.
 *
 * Instances of this structure are typically organized into arrays, which can then
 * be used to define mappings for various identifiers.
 */
typedef struct nt_type_name
{
    int         type; /* Type ID */
    const char* name; /* Type name. */
} nt_type_name_t;

#ifdef __cplusplus
}
#endif
#endif
