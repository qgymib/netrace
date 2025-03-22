#include <errno.h>
#include <stdio.h>
#include <string.h>
#include "utils/memory.h"
#include "urlparser.h"

int nt_url_components_parser(url_components_t** components, const char* url)
{
    int               ret = 0;
    url_components_t* comp = nt_calloc(1, sizeof(url_components_t));
    const char*       scheme_eol = strstr(url, "://");
    if (scheme_eol == NULL)
    {
        ret = EINVAL;
        goto ERR;
    }
    comp->scheme = nt_strndup(url, scheme_eol - url);
    url = scheme_eol + 3;

    const char* userpass_eol = strstr(url, "@");
    if (userpass_eol != NULL)
    {
        comp->username = nt_strndup(url, userpass_eol - url);
        char* user_eol = strstr(comp->username, ":");
        if (user_eol != NULL)
        {
            comp->password = nt_strdup(user_eol + 1);
            *user_eol = '\0';
        }
        url = userpass_eol + 1;
    }

    const char* host_eol = strstr(url, ":");
    if (host_eol != NULL)
    {
        comp->host = nt_strndup(url, host_eol - url);
        comp->port = nt_malloc(sizeof(*comp->port));
        if (sscanf(host_eol + 1, "%u", comp->port) != 1)
        {
            ret = EINVAL;
            goto ERR;
        }
    }
    else if (url[0] != '\0')
    {
        comp->host = nt_strdup(url);
    }

    *components = comp;
    return 0;

ERR:
    nt_url_components_free(comp);
    return ret;
}

void nt_url_components_free(url_components_t* components)
{
    if (components->scheme != NULL)
    {
        nt_free(components->scheme);
        components->scheme = NULL;
    }
    if (components->username != NULL)
    {
        nt_free(components->username);
        components->username = NULL;
    }
    if (components->password != NULL)
    {
        nt_free(components->password);
        components->password = NULL;
    }
    if (components->host != NULL)
    {
        nt_free(components->host);
        components->host = NULL;
    }
    if (components->port != NULL)
    {
        nt_free(components->port);
        components->port = NULL;
    }
    nt_free(components);
}
