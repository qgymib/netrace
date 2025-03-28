#define _GNU_SOURCE
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include "utils/defs.h"
#include "utils/memory.h"
#include "utils/log.h"
#include "urlparser.h"

static int s_url_parse_scheme(url_components_t* comp, const char** url)
{
    const char* scheme_eol = strstr(*url, "://");
    if (scheme_eol == NULL)
    {
        return NT_ERR(EINVAL);
    }

    comp->scheme = nt_strndup(*url, scheme_eol - *url);
    *url = scheme_eol + 3;
    return 0;
}

static int s_url_parse_authority(url_components_t* comp, const char** url)
{
    if (**url == '\0')
    {
        return 0;
    }

    /* Find where authority ends. */
    const char* authority_eol = strstr(*url, "/");
    size_t      url_len = (authority_eol != NULL) ? (authority_eol - *url) : strlen(*url);

    /* Parser username and password. */
    const char* userpass_eol = memmem(*url, url_len, "@", 1);
    if (userpass_eol != NULL)
    {
        size_t      userpass_len = userpass_eol - *url;
        const char* user_eol = memmem(*url, userpass_len, ":", 1);
        if (user_eol != NULL)
        {
            comp->username = nt_strndup(*url, user_eol - *url);
            comp->password = nt_strndup(user_eol + 1, userpass_eol - user_eol);
        }
        else
        {
            comp->username = nt_strndup(*url, userpass_len);
        }

        url_len -= userpass_eol - *url;
        *url = userpass_eol + 1;
    }

    return 0;
}

int nt_url_components_parser(url_components_t** components, const char* url)
{
    int               ret = 0;
    const char*       dup_url = url;
    url_components_t* comp = nt_calloc(1, sizeof(url_components_t));
    if ((ret = s_url_parse_scheme(comp, &url)) != 0)
    {
        goto ERR;
    }

    *components = comp;
    return 0;

ERR:
    LOG_E("URL `%s` parser error at %d.", dup_url, url - dup_url);
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
    if (components->query != NULL)
    {
        size_t i;
        for (i = 0; i < components->query_sz; i++)
        {
            nt_free(components->query[i].k);
            nt_free(components->query[i].v);
        }
        nt_free(components->query);
    }
    nt_free(components);
}
