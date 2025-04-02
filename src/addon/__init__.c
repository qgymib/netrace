#include "utils/defs.h"
#include "utils/log.h"
#include "__init__.h"

static const nt_addon_factory_t* s_addons[] = {
    &nt_addon_dns,
};

int nt_addon_make(nt_addon_t** addon, const char* url, int inbound, int outbound)
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
    for (i = 0; i < ARRAY_SIZE(s_addons); i++)
    {
        const nt_addon_factory_t* factory = s_addons[i];
        if (strcmp(factory->scheme, comp->scheme) == 0)
        {
            ret = factory->make(addon, comp, inbound, outbound);
            break;
        }
    }

    nt_url_comp_free(comp);
    return ret;
}
