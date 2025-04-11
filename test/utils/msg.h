#ifndef NT_TEST_UTILS_MESSAGE_H
#define NT_TEST_UTILS_MESSAGE_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct nt_msg_header
{
    uint32_t magic;
    uint32_t msg_sz;
} nt_msg_header;

int nt_msg_send(int fd, const void* data, size_t size);

int nt_msg_recv(int fd, void* data, size_t size);

#ifdef __cplusplus
}
#endif
#endif
