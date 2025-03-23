#ifndef NT_UTILS_URL_PARSER_H
#define NT_UTILS_URL_PARSER_H
#ifdef __cplusplus
extern "C" {
#endif

typedef struct url_components
{
    char*     scheme;
    char*     username;
    char*     password;
    char*     host;
    unsigned* port;
} url_components_t;

int nt_url_components_parser(url_components_t** components, const char* url);

void nt_url_components_free(url_components_t* components);

#ifdef __cplusplus
}
#endif
#endif
