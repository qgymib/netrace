#include "utils/defs.h"
#include "utils/log.h"
#include "__init__.h"

static const nt_proxy_protocol_t* s_protocols[] = {
    &nt_proxy_protocol_raw,
    &nt_proxy_protocol_socks5,
};

int nt_proxy_create(nt_proxy_t** proxy, const char* url)
{
    url_comp_t* comp = NULL;
    int         ret = nt_url_comp_parser(&comp, url);
    if (ret != 0)
    {
        LOG_E("Parser url failed: (%d) %s.", ret, strerror(ret));
        exit(EXIT_FAILURE);
    }

    size_t i;
    for (i = 0; i < ARRAY_SIZE(s_protocols); i++)
    {
        const nt_proxy_protocol_t* protocol = s_protocols[i];
        if (strcmp(protocol->scheme, comp->scheme) == 0)
        {
            ret = protocol->make(proxy, comp);
            goto finish;
        }
    }

    LOG_E("Unknown protocol `%s`.", comp->scheme);
    ret = NT_ERR(ENOTSUP);

finish:
    nt_url_comp_free(comp);
    return ret;
}
