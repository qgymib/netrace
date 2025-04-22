#include "__init__.h"

int nt_syscall_decode_getsockname(const nt_syscall_info_t* si, char* buff, size_t size)
{
    return nt_syscall_decode_getpeername(si, buff, size);
}
