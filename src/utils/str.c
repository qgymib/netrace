#include <string.h>
#include "utils/memory.h"
#include "str.h"

void nt_str_free(nt_str_t* str)
{
    nt_free(str->data);
    str->data = NULL;
    str->size = 0;
}

void nt_str_set(nt_str_t* str, const char* s, size_t n)
{
    nt_str_free(str);
    nt_str_append(str, s, n);
}

void nt_str_append(nt_str_t* str, const char* s, size_t n)
{
    size_t new_sz = str->size + n;
    str->data = nt_realloc(str->data, new_sz + 1);
    memcpy(str->data + str->size, s, n);
    str->size = new_sz;
    str->data[new_sz] = '\0';
}

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
    arr->data = nt_realloc(arr->data, sizeof(*arr->data) * arr->size);
    nt_str_t* s = &arr->data[arr->size - 1];
    s->data = NULL;
    s->size = 0;
    nt_str_set(s, str, len);
}

void nt_str_arr_copy(nt_str_arr_t* dst, const nt_str_arr_t* src)
{
    size_t i;
    for (i = 0; i < src->size; i++)
    {
        const nt_str_t* s = &src->data[i];
        nt_str_arr_append(dst, s->data, s->size);
    }
}

void nt_str_arr_join(nt_str_t* dst, const nt_str_arr_t* src, const char* sep)
{
    size_t i;
    size_t sep_sz = strlen(sep);

    for (i = 0; i < src->size; i++)
    {
        const nt_str_t* s = &src->data[i];
        nt_str_append(dst, s->data, s->size);
        if (i != src->size - 1)
        {
            nt_str_append(dst, sep, sep_sz);
        }
    }
}

void nt_str_arr_free(nt_str_arr_t* arr)
{
    size_t i;
    for (i = 0; i < arr->size; i++)
    {
        nt_str_free(&arr->data[i]);
    }
    nt_free(arr->data);
    arr->data = NULL;
    arr->size = 0;
}
