#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include "utils/log.h"
#include "memory.h"

void* nt_malloc(size_t size)
{
    void* p = malloc(size);
    if (p == NULL)
    {
        LOG_F_ABORT("%s", strerror(ENOMEM));
    }
    return p;
}

void* nt_calloc(size_t nmemb, size_t size)
{
    void* p = calloc(nmemb, size);
    if (p == NULL)
    {
        LOG_F_ABORT("%s", strerror(ENOMEM));
    }
    return p;
}

void* nt_realloc(void* addr, size_t size)
{
    void* p = realloc(addr, size);
    if (p == NULL)
    {
        LOG_F_ABORT("%s", strerror(ENOMEM));
    }
    return p;
}

void nt_free(void* addr)
{
    free(addr);
}

char* nt_strdup(const char* s)
{
    char* c = strdup(s);
    if (c == NULL)
    {
        LOG_F_ABORT("%s", strerror(ENOMEM));
    }
    return c;
}
