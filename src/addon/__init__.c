#include "utils/defs.h"
#include "utils/log.h"
#include "__init__.h"

static const nt_addon_factory_t* s_addon_factory_table[] = {
    &nt_addon_factory_dns,
};

int nt_addon_make(nt_addon_t** addon, const char* url, int type, int inbound, int outbound)
{
    url_comp_t* comp = NULL;
    int         ret = nt_url_comp_parser(&comp, url);
    if (ret != 0)
    {
        LOG_E("Url `%s` parser failed.", url);
        return ret;
    }

    size_t i;
    ret = NT_ERR(ENOTSUP);
    for (i = 0; i < ARRAY_SIZE(s_addon_factory_table); i++)
    {
        const nt_addon_factory_t* factory = s_addon_factory_table[i];
        if (strcmp(factory->scheme, comp->scheme) == 0)
        {
            ret = factory->make(addon, comp, type, inbound, outbound);
            break;
        }
    }

    nt_url_comp_free(comp);
    return ret;
}
