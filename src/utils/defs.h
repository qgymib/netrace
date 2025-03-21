#ifndef NT_UTILS_DEFINES_H
#define NT_UTILS_DEFINES_H

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

#ifndef ARRAY_SIZE
#define ARRAY_SIZE(x) (sizeof(x) / sizeof(x[0]))
#endif

#ifndef STRINGIFY
#define STRINGIFY(x)    STRINGIFY2(x)
#define STRINGIFY2(x)   #x
#endif

#endif
