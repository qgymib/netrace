#ifndef NT_UTILS_DEFINES_H
#define NT_UTILS_DEFINES_H

#include <errno.h>

#ifndef offsetof
#define offsetof(type, member) ((size_t)&(((type*)0)->member))
#endif

#ifndef container_of
#if defined(__GNUC__) || defined(__clang__)
#define container_of(ptr, type, member)                                                                                \
    ({                                                                                                                 \
        const typeof(((type*)0)->member)* __mptr = (ptr);                                                              \
        (type*)((char*)__mptr - offsetof(type, member));                                                               \
    })
#else
#define container_of(ptr, type, member) ((type*)((char*)(ptr) - offsetof(type, member)))
#endif
#endif

#ifndef NT_MAX
#define NT_MAX(a, b)    ((a) > (b) ? (a) : (b))
#endif

#ifndef NT_MIN
#define NT_MIN(a, b)    ((a) < (b) ? (a) : (b))
#endif

#ifndef ARRAY_SIZE
#define ARRAY_SIZE(x) (sizeof(x) / sizeof(x[0]))
#endif

#ifndef STRINGIFY
#define STRINGIFY(x) STRINGIFY2(x)
#define STRINGIFY2(x) #x
#endif

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

#endif
