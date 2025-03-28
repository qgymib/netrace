#ifndef NT_UTILS_IP_FILTER_H
#define NT_UTILS_IP_FILTER_H

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct nt_ipfilter nt_ipfilter_t;

/**
 * @brief Create ipfilter.
 * @return Handle.
 */
nt_ipfilter_t* nt_ipfilter_create();

/**
 * @brief Destroy ipfilter.
 * @param[in] filter Handle.
 */
void nt_ipfilter_destroy(nt_ipfilter_t* filter);

/**
 * @brief Add filter.
 * @param[in] filter Filter.
 * @param[in] type #SOCK_STREAM or #SOCK_DGRAM
 * @param[in] ip IP
 * @param[in] mask CIDR prefix
 * @return 0 if success.
 */
int nt_ipfiter_add(nt_ipfilter_t* filter, int type, const char* ip, unsigned mask, int port);

/**
 * @brief Check if \p addr match any of filter.
 * @param[in] filter Filter handle.
 * @param[in] type Address type. #SOCK_STREAM or #SOCK_DGRAM.
 * @param[in] addr Address to check.
 * @return boolean.
 */
int nt_ipfilter_check(nt_ipfilter_t* filter, int type, const struct sockaddr* addr);

#ifdef __cplusplus
}
#endif
#endif
