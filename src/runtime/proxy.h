#ifndef NT_RUNTIME_PROXY_H
#define NT_RUNTIME_PROXY_H

#include <netinet/in.h>

#ifdef __cplusplus
extern "C" {
#endif

void nt_proxy_init(void);
void nt_proxy_exit(void);
void nt_proxy_queue(const struct sockaddr* addr);

#ifdef __cplusplus
}
#endif
#endif
