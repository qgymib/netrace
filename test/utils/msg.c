#include <sys/select.h>
#include "utils/defs.h"
#include "utils/log.h"
#include "utils/socket2.h"
#include "msg.h"

#include <utils/memory.h>

#define NT_MSG_MAGIC 0x12345678

int nt_msg_send(int fd, const void* data, size_t size)
{
    int ret;

    nt_msg_header header = { NT_MSG_MAGIC, size };
    if ((ret = nt_send_timed(fd, &header, sizeof(header), NT_TIMEOUT_INFINITE)) < 0)
    {
        return ret;
    }
    if (ret != sizeof(header))
    {
        return NT_ERR(EIO);
    }

    if ((ret = nt_send_timed(fd, data, size, NT_TIMEOUT_INFINITE)) < 0)
    {
        return ret;
    }
    if ((size_t)ret != size)
    {
        return NT_ERR(EIO);
    }

    return size;
}

int nt_msg_recv(int fd, void* data, size_t size)
{
    int           ret;
    nt_msg_header header = { 0, 0 };
    if ((ret = nt_recv_timed(fd, &header, sizeof(header), NT_TIMEOUT_INFINITE)) < 0)
    {
        return ret;
    }
    if (ret != sizeof(header))
    {
        return NT_ERR(EIO);
    }

    size_t buf_sz = NT_MIN(header.msg_sz, size);
    if ((ret = nt_recv_timed(fd, data, size, NT_TIMEOUT_INFINITE)) < 0)
    {
        return ret;
    }
    NT_ASSERT((size_t)ret == buf_sz, "Message trunked.");

    if (buf_sz == header.msg_sz)
    {
        return buf_sz;
    }

    size_t left_sz = header.msg_sz - buf_sz;
    char*  buf = nt_malloc(left_sz);
    nt_recv_timed(fd, buf, left_sz, NT_TIMEOUT_INFINITE);
    nt_free(buf);

    return header.msg_sz;
}
