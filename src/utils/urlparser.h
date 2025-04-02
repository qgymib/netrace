#ifndef NT_UTILS_URL_PARSER_H
#define NT_UTILS_URL_PARSER_H

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct url_query
{
    char* k;
    char* v;
} url_query_t;

typedef struct url_comp
{
    char*        scheme;
    char*        username;
    char*        password;
    char*        host;
    unsigned*    port;
    char*        path;
    url_query_t* query;
    size_t       query_sz;
} url_comp_t;

/**
 * @brief Parser url into components.
 * @param[out] comp components.
 * @param[in] url   URL.
 * @return 0 if success, errno if failed.
 */
int nt_url_comp_parser(url_comp_t** comp, const char* url);

/**
 * @brief Release components.
 * @param[in] comp components
 */
void nt_url_comp_free(url_comp_t* comp);

/**
 * @brief Query value.
 * @param[in] comp components.
 * @return Value string. NULL if not exist.
 */
const char* nt_url_comp_query(const url_comp_t* comp, const char* k);

#ifdef __cplusplus
}
#endif
#endif
