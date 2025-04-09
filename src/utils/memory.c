#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include "utils/log.h"
#include "memory.h"

void* nt_malloc(size_t size)
{
    void* p = malloc(size);
    NT_ASSERT(p != NULL, "%s", strerror(ENOMEM));
    return p;
}

void* nt_calloc(size_t nmemb, size_t size)
{
    void* p = calloc(nmemb, size);
    NT_ASSERT(p != NULL, "%s", strerror(ENOMEM));
    return p;
}

void* nt_realloc(void* addr, size_t size)
{
    void* p = realloc(addr, size);
    NT_ASSERT(p != NULL, "%s", strerror(ENOMEM));
    return p;
}

void nt_free(void* addr)
{
    free(addr);
}

char* nt_strdup(const char* s)
{
    char* c = strdup(s);
    NT_ASSERT(c != NULL, "%s", strerror(ENOMEM));
    return c;
}

char* nt_strndup(const char* s, size_t n)
{
    size_t copy_sz = 0;
    for (; s[copy_sz] != '\0' && copy_sz < n; copy_sz++)
    {
    }

    char* c = nt_malloc(copy_sz + 1);
    memcpy(c, s, copy_sz);
    c[copy_sz] = '\0';
    return c;
}
