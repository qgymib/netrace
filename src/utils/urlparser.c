#define _GNU_SOURCE
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include "utils/defs.h"
#include "utils/log.h"
#include "utils/str.h"
#include "urlparser.h"

static int s_url_parse_scheme(url_comp_t* comp, const char** url)
{
    const char* scheme_eol = strstr(*url, "://");
    if (scheme_eol == NULL)
    {
        return NT_ERR(EINVAL);
    }

    comp->scheme = strndup(*url, scheme_eol - *url);
    *url = scheme_eol + 3;
    return 0;
}

static int s_url_parse_authority(url_comp_t* comp, const char** url)
{
    if (**url == '\0')
    {
        return 0;
    }

    /* Find where authority ends. */
    const char* authority_eol = strstr(*url, "/");
    size_t      url_len = (authority_eol != NULL) ? (size_t)(authority_eol - *url) : strlen(*url);

    /* Parser username and password. */
    const char* userpass_eol = memmem(*url, url_len, "@", 1);
    if (userpass_eol != NULL)
    {
        size_t      userpass_len = userpass_eol - *url;
        const char* user_eol = memmem(*url, userpass_len, ":", 1);
        if (user_eol != NULL)
        {
            comp->username = strndup(*url, user_eol - *url);
            comp->password = strndup(user_eol + 1, userpass_eol - user_eol - 1);
        }
        else
        {
            comp->username = strndup(*url, userpass_len);
        }

        url_len -= userpass_eol - *url + 1;
        *url = userpass_eol + 1;
    }

    /* Parser address and port. */
    const char* addr_eol = nt_strnrstr(*url, url_len, ":");
    if (addr_eol != NULL)
    {
        if (addr_eol == *url)
        { /* Single `:` should not occur at start of address. */
            *url = addr_eol;
            return NT_ERR(EINVAL);
        }
        if (addr_eol[-1] == ':')
        { /* This is IPv6 address. */
            comp->host = strndup(*url, url_len);
        }
        else
        { /* This is IPv4 address. */
            comp->host = strndup(*url, addr_eol - *url);
            comp->port = malloc(sizeof(*comp->port));
            char* s_port = strndup(addr_eol + 1, url_len - (addr_eol - *url) - 1);
            int   scan_ret = sscanf(s_port, "%u", comp->port);
            free(s_port);
            if (scan_ret != 1)
            {
                *url = addr_eol + 1;
                return NT_ERR(EINVAL);
            }
        }
    }
    else
    {
        comp->host = strndup(*url, url_len);
    }

    *url += (authority_eol != NULL) ? (url_len + 1) : url_len;
    return 0;
}

static int s_url_parse_path(url_comp_t* comp, const char** url)
{
    if (**url == '\0')
    {
        return 0;
    }

    const char* pos = strpbrk(*url, "#?");
    if (pos == NULL)
    {
        comp->path = strdup(*url);
        *url += strlen(*url);
        return 0;
    }

    if (pos == *url)
    {
        return 0;
    }

    size_t path_len = pos - *url;
    comp->path = strndup(*url, path_len);
    *url += path_len;

    return 0;
}

static void s_url_parse_query_value(url_query_t* q)
{
    char* pos = strstr(q->k, "=");
    if (pos != NULL)
    {
        q->v = pos + 1;
        *pos = '\0';
    }
}

static void s_url_append_query(url_comp_t* comp, const char* data, size_t size)
{
    comp->query_sz++;
    comp->query = realloc(comp->query, sizeof(*comp->query) * comp->query_sz);
    url_query_t* q = &comp->query[comp->query_sz - 1];
    q->k = strndup(data, size);
    q->v = NULL;
    s_url_parse_query_value(q);
}

static int s_url_parse_query(url_comp_t* comp, const char** url)
{
    if (**url == '\0' || **url == '#')
    {
        return 0;
    }
    if (**url != '?')
    {
        return NT_ERR(EINVAL);
    }
    *url += 1;

    const char* pos;
    while ((pos = strpbrk(*url, "#&")) != NULL)
    {
        if (*pos == '#')
        {
            break;
        }
        if (pos == *url)
        {
            *url += 1;
            continue;
        }

        s_url_append_query(comp, *url, pos - *url);
        *url = pos + 1;
    }

    if (pos == NULL)
    {
        if (**url != '\0')
        {
            size_t url_len = strlen(*url);
            s_url_append_query(comp, *url, url_len);
            *url += url_len;
        }
        return 0;
    }

    if (**url == '#')
    {
        return 0;
    }

    s_url_append_query(comp, *url, pos - *url);
    *url = pos;
    return 0;

    return 0;
}

int nt_url_comp_parser(url_comp_t** components, const char* url)
{
    int               ret = 0;
    const char*       dup_url = url;
    url_comp_t* comp = calloc(1, sizeof(url_comp_t));
    if ((ret = s_url_parse_scheme(comp, &url)) != 0)
    {
        goto ERR;
    }
    if ((ret = s_url_parse_authority(comp, &url)) != 0)
    {
        goto ERR;
    }
    if ((ret = s_url_parse_path(comp, &url)) != 0)
    {
        goto ERR;
    }
    if ((ret = s_url_parse_query(comp, &url)) != 0)
    {
        goto ERR;
    }

    *components = comp;
    return 0;

ERR:
    LOG_E("URL `%s` parser error at %d.", dup_url, url - dup_url);
    nt_url_comp_free(comp);
    return ret;
}

void nt_url_comp_free(url_comp_t* comp)
{
    if (comp->scheme != NULL)
    {
        free(comp->scheme);
        comp->scheme = NULL;
    }
    if (comp->username != NULL)
    {
        free(comp->username);
        comp->username = NULL;
    }
    if (comp->password != NULL)
    {
        free(comp->password);
        comp->password = NULL;
    }
    if (comp->host != NULL)
    {
        free(comp->host);
        comp->host = NULL;
    }
    if (comp->port != NULL)
    {
        free(comp->port);
        comp->port = NULL;
    }
    if (comp->path != NULL)
    {
        free(comp->path);
        comp->path = NULL;
    }
    if (comp->query != NULL)
    {
        size_t i;
        for (i = 0; i < comp->query_sz; i++)
        {
            free(comp->query[i].k);
            /* No need to free v, it just point to subrange of k. */
        }
        free(comp->query);
    }
    free(comp);
}

const char* nt_url_comp_query(const url_comp_t* comp, const char* k)
{
    size_t i;
    for (i = 0; i < comp->query_sz; i++)
    {
        const url_query_t* q = &comp->query[i];
        if (strcmp(q->k, k) == 0)
        {
            return q->v;
        }
    }

    return NULL;
}
