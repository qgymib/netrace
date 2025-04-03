#include <assert.h>
#include <string.h>
#include <arpa/inet.h>
#include "utils/defs.h"
#include "utils/log.h"
#include "utils/memory.h"
#include "dns.h"

#define DNS_MASK_QR (0x8000)
#define DNS_MASK_OPCODE (0x7800)
#define DNS_MASK_AA (0x0400)
#define DNS_MASK_TC (0x0200)
#define DNS_MASK_RD (0x0100)
#define DNS_MASK_RA (0x0080)
#define DNS_MASK_Z (0x0070)
#define DNS_MASK_RCODE (0x000F)

static void s_dns_msg_free_question(nt_dns_msg_t* msg)
{
    size_t i, j;
    for (i = 0; i < msg->header.qdcount; i++)
    {
        nt_dns_question_t* q = &msg->questions[i];
        for (j = 0; j < q->nqname; j++)
        {
            nt_free(q->qnames[j]);
        }
        nt_free(q->qnames);
    }
    nt_free(msg->questions);
}

static void s_dns_msg_free_resource(nt_dns_resource_t* resource, size_t n)
{
    size_t i;
    for (i = 0; i < n; i++)
    {
        nt_dns_resource_t* r = &resource[i];
        nt_free(r->name);
        nt_free(r->rdata);
    }
    nt_free(resource);
}

static int s_dns_is_pointer(uint8_t u8)
{
    return u8 & 0xC0;
}

static uint16_t s_dns_get_u16(const uint8_t* p)
{
    uint16_t data = 0;
    memcpy(&data, p, 2);
    return ntohs(data);
}

static uint32_t s_dns_get_u32(const uint8_t* p)
{
    uint32_t data = 0;
    memcpy(&data, p, 4);
    return ntohl(data);
}

static uint16_t s_dns_get_offset(uint8_t h, uint8_t l)
{
    return (h & 0x3F) << 8 | l;
}

/**
 * @brief Trace a pointer to start of actual string.
 */
static ssize_t s_dns_trace_pointer(const uint8_t* data, size_t size, size_t pos)
{
    uint8_t high = data[pos];
    if (!s_dns_is_pointer(high))
    {
        return pos;
    }

    if (pos + 1 >= size)
    {
        return NT_ERR(EINVAL);
    }

    uint8_t low = data[pos + 1];
    pos = s_dns_get_offset(high, low);
    if (pos >= size)
    {
        return NT_ERR(EINVAL);
    }

    return s_dns_trace_pointer(data, size, pos);
}

static int s_dns_parse_question(nt_dns_msg_t* pkg, const uint8_t* data, size_t size, size_t pos)
{
    size_t i;
    size_t offset = pos;

    pkg->questions = nt_calloc(pkg->header.qdcount, sizeof(nt_dns_question_t));
    for (i = 0; i < pkg->header.qdcount; i++)
    {
        nt_dns_question_t* q = &pkg->questions[i];
        while (1)
        {
            if (offset > size)
            {
                return NT_ERR(EINVAL);
            }
            uint8_t name_sz = data[offset++];
            if (name_sz == 0)
            {
                break;
            }

            const uint8_t* name_start = NULL;
            if (s_dns_is_pointer(name_sz))
            {
                ssize_t ref = s_dns_trace_pointer(data, size, offset - 1);
                if (ref < 0)
                {
                    return ref;
                }
                else if ((size_t)ref > size)
                {
                    return NT_ERR(EINVAL);
                }
                name_sz = data[ref];
                name_start = &data[ref + 1];
                offset += 2;
            }
            else
            {
                if (offset + name_sz > size)
                {
                    return NT_ERR(EINVAL);
                }
                name_start = &data[offset];
                offset += name_sz;
            }

            q->nqname++;
            q->qnames = nt_realloc(q->qnames, sizeof(char*) * q->nqname);
            q->qnames[q->nqname - 1] = nt_malloc(name_sz + 1);
            memcpy(q->qnames[q->nqname - 1], name_start, name_sz);
            q->qnames[q->nqname - 1][name_sz] = '\0';
        }

        if (offset + 4 > size)
        {
            return NT_ERR(EINVAL);
        }
        q->qtype = s_dns_get_u16(&data[offset]);
        offset += 2;
        q->qclass = s_dns_get_u16(&data[offset]);
        offset += 2;
    }

    return offset - pos;
}

static int s_dns_parse_resource(nt_dns_resource_t** dst, size_t n, const uint8_t* data, size_t size,
                                size_t pos)
{
    if (n == 0)
    {
        return 0;
    }
    *dst = nt_calloc(n, sizeof(nt_dns_resource_t));

    size_t i, offset = pos;
    for (i = 0; i < n; i++)
    {
        nt_dns_resource_t* r = *dst + i;
        if (offset + 1 >= size)
        {
            return NT_ERR(EINVAL);
        }

        uint8_t name_sz = data[offset++];
        if (s_dns_is_pointer(name_sz))
        {
            ssize_t ref = s_dns_trace_pointer(data, size, offset - 1);
            if (ref < 0)
            {
                return ref;
            }

            name_sz = data[ref];
            if ((size_t)ref + 1 + name_sz > size)
            {
                return NT_ERR(EINVAL);
            }
            r->name = nt_malloc(name_sz + 1);
            memcpy(r->name, &data[ref + 1], name_sz);
            r->name[name_sz] = '\0';
            offset += 2;
        }
        else
        {
            if (offset + name_sz > size)
            {
                return NT_ERR(EINVAL);
            }
            r->name = nt_malloc(name_sz + 1);
            memcpy(r->name, data + offset, name_sz);
            r->name[name_sz] = '\0';
            offset += name_sz;
        }

        if (offset + 10 > size)
        {
            return NT_ERR(EINVAL);
        }

        r->type = s_dns_get_u16(&data[offset]);
        offset += 2;

        r->class = s_dns_get_u16(&data[offset]);
        offset += 2;

        r->ttl = s_dns_get_u32(&data[offset]);
        offset += 4;

        r->rdlength = s_dns_get_u16(&data[offset]);
        offset += 2;

        if (offset + r->rdlength > size)
        {
            return NT_ERR(EINVAL);
        }

        r->rdata = nt_malloc(r->rdlength);
        memcpy(r->rdata, &data[offset], r->rdlength);
        offset += r->rdlength;
    }

    return 0;
}

int nt_dns_msg_parser(nt_dns_msg_t** msg, const void* data, size_t size)
{
    int            ret;
    const uint8_t* ptr = (uint8_t*)data;
    if (size < 12)
    {
        return NT_ERR(EINVAL);
    }

    nt_dns_msg_t* pkg = nt_calloc(1, sizeof(nt_dns_msg_t));
    pkg->header.id = s_dns_get_u16(&ptr[0]);

    uint16_t fields = s_dns_get_u16(&ptr[2]);
    pkg->header.qr = (fields & DNS_MASK_QR) >> 15;
    pkg->header.opcode = (fields & DNS_MASK_OPCODE) >> 11;
    pkg->header.aa = (fields & DNS_MASK_AA) >> 10;
    pkg->header.tc = (fields & DNS_MASK_TC) >> 9;
    pkg->header.rd = (fields & DNS_MASK_RD) >> 8;
    pkg->header.ra = (fields & DNS_MASK_RA) >> 7;
    pkg->header.z = (fields & DNS_MASK_Z) >> 4;
    pkg->header.rcode = (fields & DNS_MASK_RCODE);

    pkg->header.qdcount = s_dns_get_u16(&ptr[4]);
    pkg->header.ancount = s_dns_get_u16(&ptr[6]);
    pkg->header.nscount = s_dns_get_u16(&ptr[8]);
    pkg->header.arcount = s_dns_get_u16(&ptr[10]);

    size_t offset = 12;
    if ((ret = s_dns_parse_question(pkg, ptr, size, offset)) < 0)
    {
        goto ERR;
    }
    offset += ret;

    if ((ret = s_dns_parse_resource(&pkg->answer, pkg->header.ancount, ptr, size, offset)) < 0)
    {
        goto ERR;
    }
    offset += ret;

    if ((ret = s_dns_parse_resource(&pkg->authority, pkg->header.nscount, ptr, size, offset)) < 0)
    {
        goto ERR;
    }
    offset += ret;

    if ((ret = s_dns_parse_resource(&pkg->additional, pkg->header.arcount, ptr, size, offset)) < 0)
    {
        goto ERR;
    }
    offset += ret;

    *msg = pkg;
    return offset;

ERR:
    nt_dns_msg_free(pkg);
    return ret;
}

void nt_dns_msg_free(nt_dns_msg_t* msg)
{
    s_dns_msg_free_question(msg);
    s_dns_msg_free_resource(msg->answer, msg->header.ancount);
    s_dns_msg_free_resource(msg->authority, msg->header.nscount);
    s_dns_msg_free_resource(msg->additional, msg->header.arcount);
}
