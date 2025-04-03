#include <string.h>
#include "utils/memory.h"
#include "str.h"

const char* nt_strrstr(const char* haystack, const char* needle)
{
    if (*needle == '\0')
    {
        return haystack;
    }

    const char* result = NULL;
    for (;;)
    {
        char* p = strstr(haystack, needle);
        if (p == NULL)
        {
            break;
        }
        result = p;
        haystack = p + 1;
    }

    return result;
}

const char* nt_strnrstr(const char* haystack, size_t len, const char* needle)
{
    if (!haystack || !needle || len == 0)
    {
        return NULL;
    }

    size_t needle_len = strlen(needle);

    if (needle_len == 0)
    {
        return haystack; // Empty needle is always found at the beginning
    }

    if (needle_len > len)
    {
        return NULL; // Needle is longer than search area
    }

    // Start from the last possible position where needle could fit
    const char* search_start = haystack + len - needle_len;
    const char* result = NULL;

    // Search backwards
    while (search_start >= haystack)
    {
        if (strncmp(search_start, needle, needle_len) == 0)
        {
            result = search_start;
            break;
        }
        search_start--;
    }

    return result;
}

void nt_str_arr_append(nt_str_arr_t* arr, const char* str, size_t len)
{
    arr->size++;
    arr->data = nt_realloc(arr->data, sizeof(char*) * arr->size);
    arr->data[arr->size - 1] = nt_strndup(str, len);
}

void nt_str_arr_free(nt_str_arr_t* arr)
{
    size_t i;
    for (i = 0; i < arr->size; i++)
    {
        nt_free(arr->data[i]);
    }
    nt_free(arr->data);
    arr->data = NULL;
    arr->size = 0;
}
