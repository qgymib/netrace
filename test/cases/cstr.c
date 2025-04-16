#include "utils/cstr.h"
#include "runtime.h"

TEST(cstr, new)
{
    const char* d = "hello world";
    c_str_t     s = c_str_new(d);
    ASSERT_EQ_STR(s, d);
    ASSERT_EQ_SIZE(c_str_len(s), strlen(d));
    c_str_free(s);
}

TEST(cstr, new_len)
{
#define S1 "hello"
#define S2 "world"

    const char* d = S1 " " S2;
    c_str_t     s = c_str_new_len(d, strlen(S1));
    ASSERT_EQ_STR(s, S1);
    ASSERT_EQ_SIZE(c_str_len(s), strlen(S1));
    c_str_free(s);

#undef S1
#undef S2
}

TEST(cstr, arr_cat)
{
    const char* d = "hello";
    c_str_t*    arr = c_str_arr_new();
    ASSERT_EQ_PTR(arr[0], NULL);
    arr = c_str_arr_cat(arr, d);
    ASSERT_EQ_STR(arr[0], d);
    ASSERT_EQ_PTR(arr[1], NULL);
    ASSERT_EQ_SIZE(c_str_arr_len(arr), 1);
    c_str_free(arr);
}

TEST(cstr, split)
{
#define S1 "hello"
#define S2 "world"

    c_str_t  d = c_str_new(S1 " " S2);
    c_str_t* arr = c_str_split(d, " ");
    ASSERT_EQ_SIZE(c_str_arr_len(arr), 2);
    ASSERT_EQ_STR(arr[0], S1);
    ASSERT_EQ_STR(arr[1], S2);
    ASSERT_EQ_PTR(arr[2], NULL);
    c_str_free(d);
    c_str_free(arr);

#undef S1
#undef S2
}
