#include <assert.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <ctype.h>
#include "cstr.h"

/**
 * @brief Get generic header.
 * @param[in] p Pointer
 * @return Header address.
 */
#define CSTR_HEAD(p) ((c_str_hdr_t*)((char*)(p) - sizeof(c_str_hdr_t)))

#define CSTR_STRING(p) container_of(CSTR_HEAD(p), c_str_string_t, header)
#define CSTR_ARRAY(p) container_of(CSTR_HEAD(p), c_str_array_t, header)

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

#define CSTR_MAGIC 0x5ca8

typedef enum c_str_type
{
    STR_TYPE_STR = 0x01 << 0,
    STR_TYPE_ARR = 0x01 << 1,
} c_str_type_t;

typedef struct c_str_hdr
{
#if !defined(NDEBUG)
    uint32_t magic;
#endif
    uintptr_t flags;
    char      data[];
} c_str_hdr_t;

typedef struct c_str_string
{
    size_t      size; /* String length, not including NULL terminator. */
    c_str_hdr_t header;
} c_str_string_t;

typedef struct c_str_array
{
    size_t      size; /* Array size, not including NULL terminator. */
    c_str_hdr_t header;
} c_str_array_t;

static c_str_realloc_fn s_realloc = realloc;

static void s_str_free_array(c_str_array_t* arr)
{
    size_t   i;
    c_str_t* p = (c_str_t*)arr->header.data;
    for (i = 0; i < arr->size; i++)
    {
        c_str_t s = p[i];
        if (s != NULL)
        {
            c_str_free(s);
        }
    }
    s_realloc(arr, 0);
}

c_str_realloc_fn c_str_set_realloc(c_str_realloc_fn func)
{
    c_str_realloc_fn ret = s_realloc;
    s_realloc = func;
    return ret;
}

void c_str_free(void* p)
{
    if (p == NULL)
    {
        return;
    }

    c_str_hdr_t* hdr = CSTR_HEAD(p);
    assert(hdr->magic == CSTR_MAGIC);

    if (hdr->flags & STR_TYPE_STR)
    {
        c_str_string_t* s = container_of(hdr, c_str_string_t, header);
        s_realloc(s, 0);
        return;
    }

    c_str_array_t* arr = container_of(hdr, c_str_array_t, header);
    assert(arr->header.magic == CSTR_MAGIC);
    s_str_free_array(arr);
}

c_str_t c_str_new(const char* s)
{
    size_t n = strlen(s);
    return c_str_new_len(s, n);
}

c_str_t c_str_new_len(const char* s, size_t n)
{
    size_t          malloc_sz = sizeof(c_str_string_t) + n + 1;
    c_str_string_t* str = s_realloc(NULL, malloc_sz);
    if (str == NULL)
    {
        return NULL;
    }

#if !defined(NDEBUG)
    str->header.magic = CSTR_MAGIC;
#endif
    str->size = n;
    str->header.flags = STR_TYPE_STR;
    memcpy(str->header.data, s, n);
    str->header.data[n] = '\0';

    return str->header.data;
}

c_str_t c_str_cat_len(c_str_t cs, const char* s, size_t n)
{
    c_str_string_t* str = CSTR_STRING(cs);
    size_t          new_sz = str->size + n;
    size_t          malloc_sz = sizeof(c_str_string_t) + new_sz + 1;
    c_str_string_t* new_str = s_realloc(str, malloc_sz);
    if (new_str == NULL)
    {
        return NULL;
    }
    memcpy(new_str->header.data + new_str->size, s, n);
    new_str->size = new_sz;
    new_str->header.data[new_sz] = '\0';
    return new_str->header.data;
}

c_str_t c_str_simplified(c_str_t cs)
{
    c_str_string_t* str = CSTR_STRING(cs);
    size_t          str_sz = str->size;
    size_t          i;
    for (i = 0; i < str_sz;)
    {
        char*  pos = str->header.data + i;
        size_t left_sz = str->size - i;
        if (isspace(*pos))
        {
            memmove(pos, pos + 1, left_sz - 1);
            str_sz--;
        }
        else
        {
            i++;
        }
    }
    str->size = str_sz;
    size_t          malloc_sz = sizeof(c_str_string_t) + str_sz + 1;
    c_str_string_t* new_str = s_realloc(str, malloc_sz);

    /* It is Ok if realloc failed. The original string still works. */
    return new_str != NULL ? new_str->header.data : str->header.data;
}

c_str_arr_t c_str_arr_new(void)
{
    size_t         malloc_sz = sizeof(c_str_array_t) + sizeof(c_str_t);
    c_str_array_t* arr = s_realloc(NULL, malloc_sz);
    if (arr == NULL)
    {
        return NULL;
    }

#if !defined(NDEBUG)
    arr->header.magic = CSTR_MAGIC;
#endif
    arr->size = 0;
    arr->header.flags = STR_TYPE_ARR;
    c_str_t* p = (c_str_t*)arr->header.data;
    *p = NULL;

    return p;
}

size_t c_str_len(const c_str_t s)
{
    const c_str_string_t* str = CSTR_STRING(s);
    return str->size;
}

size_t c_str_arr_len(const c_str_arr_t arr)
{
    c_str_array_t* arr2 = CSTR_ARRAY(arr);
    assert(arr2->header.magic == CSTR_MAGIC);
    return arr2->size;
}

c_str_arr_t c_str_arr_cat(c_str_arr_t arr, const char* s)
{
    return c_str_arr_cat_len(arr, s, strlen(s));
}

c_str_arr_t c_str_arr_cat_len(c_str_arr_t arr, const char* s, size_t n)
{
    if (arr == NULL)
    {
        arr = c_str_arr_new();
    }

    c_str_array_t* arr2 = CSTR_ARRAY(arr);
    assert(arr2->header.magic == CSTR_MAGIC);

    arr2->size++;

    size_t         new_sz = sizeof(c_str_array_t) + (arr2->size + 1) * sizeof(c_str_t);
    c_str_array_t* new_arr = s_realloc(arr2, new_sz);
    if (new_arr == NULL)
    {
        return NULL;
    }
    c_str_t* p = (c_str_t*)new_arr->header.data;
    p[new_arr->size - 1] = c_str_new_len(s, n);
    p[new_arr->size] = NULL;
    return p;
}

c_str_arr_t c_str_arr_dup(const c_str_arr_t arr)
{
    size_t      i;
    c_str_arr_t dup = c_str_arr_new();
    for (i = 0; i < c_str_arr_len(arr); i++)
    {
        c_str_t     s = arr[i];
        size_t      s_sz = c_str_len(s);
        c_str_arr_t new_dup = c_str_arr_cat_len(dup, s, s_sz);
        if (new_dup == NULL)
        {
            c_str_free(dup);
            return NULL;
        }
        dup = new_dup;
    }
    return dup;
}

c_str_arr_t c_str_split(const c_str_t s, const char* delim)
{
    return c_str_split_ex(s, delim, strlen(delim), NULL, NULL);
}

c_str_arr_t c_str_split_ex(const c_str_t s, const char* delim, size_t delim_sz,
                           c_str_split_map_fn fn, void* arg)
{
    size_t      offset = 0;
    size_t      s_sz = c_str_len(s);
    c_str_arr_t arr = c_str_arr_new();
    c_str_arr_t new_arr;
    if (arr == NULL)
    {
        return NULL;
    }

    const char* pos = NULL;
    while (offset < s_sz)
    {
        const char* start = s + offset;
        size_t      length = s_sz - offset;
        pos = memmem(start, length, delim, delim_sz);
        if (pos == NULL)
        {
            break;
        }
        size_t slice_sz = pos - start;

        if (fn == NULL || fn(start, slice_sz, arg) == 0)
        {
            if ((new_arr = c_str_arr_cat_len(arr, start, slice_sz)) == NULL)
            {
                c_str_free(arr);
                return NULL;
            }
            arr = new_arr;
        }
        offset = pos - s + delim_sz;
    }

    const char* start = s + offset;
    size_t      slice_sz = s_sz - offset;
    if (fn == NULL || fn(start, slice_sz, arg) == 0)
    {
        if ((new_arr = c_str_arr_cat_len(arr, start, slice_sz)) == NULL)
        {
            c_str_free(arr);
            return NULL;
        }
        arr = new_arr;
    }

    return arr;
}
