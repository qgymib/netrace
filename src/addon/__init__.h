#ifndef NT_ADDON_INIT_H
#define NT_ADDON_INIT_H

#include "utils/urlparser.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct nt_addon
{
    /**
     * @brief Release this object.
     * @param[in] thiz  Object handle.
     */
    void (*release)(struct nt_addon* thiz);
} nt_addon_t;

typedef struct nt_addon_factory
{
    /**
     * @brief Addon scheme.
     */
    const char* scheme;

    /**
     * @brief Create function.
     * @param[out] addon    Addon handle.
     * @param[in] url       URL.
     * @param[in] inbound   Inbound file descriptor.
     * @param[in] outbound  Outbound file descriptor.
     * @return 0 for success, or errno.
     */
    int (*make)(nt_addon_t** addon, const url_comp_t* url, int inbound, int outbound);
} nt_addon_factory_t;

extern const nt_addon_factory_t nt_addon_dns;

/**
 * @brief Create addon.
 * @param[out] addon    Addon handle.
 * @param[in] url       Creation URL.
 * @param[in] inbound   Inbound file descriptor.
 * @param[in] outbound  Outbound file descriptor.
 * @return 0 if success, errno if failed.
 */
int nt_addon_make(nt_addon_t** addon, const char* url, int inbound, int outbound);

#ifdef __cplusplus
}
#endif
#endif
