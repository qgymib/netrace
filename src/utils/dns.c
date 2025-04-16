#include <assert.h>
#include <string.h>
#include <arpa/inet.h>
#include "utils/defs.h"
#include "utils/log.h"
#include "utils/memory.h"
#include "utils/random.h"
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
    size_t i;
    for (i = 0; i < msg->header.qdcount; i++)
    {
        nt_dns_question_t* q = &msg->questions[i];
        c_str_free(q->qname);
    }
    nt_free(msg->questions);
}

static void s_dns_msg_free_resource(nt_dns_resource_t* resource, size_t n)
{
    size_t i;
    for (i = 0; i < n; i++)
    {
        nt_dns_resource_t* r = &resource[i];
        c_str_free(r->name);
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

static void s_dns_set_u8(uint8_t* p, uint8_t x)
{
    *p = x;
}

static void s_dns_set_u16(uint8_t* p, uint16_t x)
{
    uint16_t data = htons(x);
    memcpy(p, &data, 2);
}

static void s_dns_set_u32(uint8_t* p, uint32_t x)
{
    uint32_t data = htonl(x);
    memcpy(p, &data, 4);
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
    size_t cnt;
    for (cnt = 0; cnt < 64; cnt++)
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
    }

    return NT_ERR(ELOOP);
}

static ssize_t s_dns_parse_labels(c_str_arr_t* labels, const uint8_t* data, size_t size,
                                  size_t pos)
{
    ssize_t ref, ret = 0;
    size_t  offset = pos;
    int     jump = 0;
    while (1)
    {
        if ((ref = s_dns_trace_pointer(data, size, offset)) < 0)
        {
            return ref;
        }
        else if ((size_t)ref != offset)
        {
            jump = 1;
            ret = 2;
        }

        uint8_t len = data[ref++];
        if (len == 0)
        {
            if (!jump)
            {
                ret = ref - pos;
            }
            break;
        }
        else if ((size_t)ref + len >= size)
        {
            return NT_ERR(EINVAL);
        }
        *labels = c_str_arr_cat_len(*labels, (char*)&data[ref], len);

        offset = ref + len;
        if (!jump)
        {
            ret = offset - pos;
        }
    }

    return ret;
}

static int s_dns_parse_question(nt_dns_msg_t* pkg, const uint8_t* data, size_t size, size_t pos)
{
    size_t i;
    size_t offset = pos;

    pkg->questions = nt_calloc(pkg->header.qdcount, sizeof(nt_dns_question_t));
    for (i = 0; i < pkg->header.qdcount; i++)
    {
        nt_dns_question_t* q = &pkg->questions[i];
        ssize_t            ref = s_dns_parse_labels(&q->qname, data, size, offset);
        if (ref < 0)
        {
            return ref;
        }
        offset += ref;

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
        if (offset + 1 > size)
        {
            return NT_ERR(EINVAL);
        }

        ssize_t ref = s_dns_parse_labels(&r->name, data, size, offset);
        if (ref < 0)
        {
            return ref;
        }
        offset += ref;

        if (offset + 9 >= size)
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

        if (offset + r->rdlength - 1 >= size)
        {
            return NT_ERR(EINVAL);
        }

        r->rdata = nt_malloc(r->rdlength);
        memcpy(r->rdata, &data[offset], r->rdlength);
        offset += r->rdlength;
    }

    return offset - pos;
}

static int s_dns_build_label(uint8_t* buff, size_t size, const c_str_arr_t label)
{
    size_t i;
    size_t offset = 0;
    for (i = 0; i < c_str_arr_len(label); i++)
    {
        const c_str_t s = label[i];
        if (offset + c_str_len(s) >= size)
        {
            return NT_ERR(ENOSPC);
        }

        s_dns_set_u8(&buff[offset++], c_str_len(s));
        memcpy(&buff[offset], s, c_str_len(s));
        offset += c_str_len(s);
    }
    if (offset >= size)
    {
        return NT_ERR(ENOSPC);
    }
    s_dns_set_u8(&buff[offset++], 0);

    return offset;
}

static int s_dns_build_question(uint8_t* buff, size_t size, const nt_dns_question_t* req, size_t n)
{
    int    ret;
    size_t i, offset = 0;
    for (i = 0; i < n; i++)
    {
        const nt_dns_question_t* q = &req[i];
        if ((ret = s_dns_build_label(buff + offset, size - offset, q->qname)) < 0)
        {
            return ret;
        }
        offset += ret;

        if (offset + 4 - 1 >= size)
        {
            return NT_ERR(ENOSPC);
        }

        s_dns_set_u16(&buff[offset], q->qtype);
        offset += 2;
        s_dns_set_u16(&buff[offset], q->qclass);
        offset += 2;
    }

    return offset;
}

static int s_dns_build_resource(uint8_t* buff, size_t size, const nt_dns_resource_t* res, size_t n)
{
    int    ret;
    size_t i, offset = 0;
    for (i = 0; i < n; i++)
    {
        const nt_dns_resource_t* r = &res[i];
        if ((ret = s_dns_build_label(buff + offset, size - offset, r->name)) < 0)
        {
            return ret;
        }
        offset += ret;

        if (offset + 10 + r->rdlength - 1 >= size)
        {
            return NT_ERR(ENOSPC);
        }
        s_dns_set_u16(buff + offset, r->type);
        offset += 2;
        s_dns_set_u16(buff + offset, r->class);
        offset += 2;
        s_dns_set_u32(buff + offset, r->ttl);
        offset += 4;
        s_dns_set_u16(buff + offset, r->rdlength);
        offset += 2;
        memcpy(buff + offset, r->rdata, r->rdlength);
        offset += r->rdlength;
    }

    return offset;
}

static nt_dns_question_t* s_dns_copy_question(const nt_dns_question_t* req, size_t n)
{
    size_t             i;
    nt_dns_question_t* new_req = nt_calloc(n, sizeof(*req));

    for (i = 0; i < n; i++)
    {
        const nt_dns_question_t* q = &req[i];
        new_req[i].qname = c_str_arr_dup(q->qname);
        new_req[i].qtype = q->qtype;
        new_req[i].qclass = q->qclass;
    }

    return new_req;
}

static nt_dns_resource_t* s_dns_copy_resource(const nt_dns_resource_t* res, size_t n)
{
    size_t             i;
    nt_dns_resource_t* new_res = nt_calloc(n, sizeof(*res));

    for (i = 0; i < n; i++)
    {
        const nt_dns_resource_t* r = &res[i];
        new_res[i].name = c_str_arr_dup(r->name);
        new_res[i].type = r->type;
        new_res[i].class = r->class;
        new_res[i].ttl = r->ttl;
        new_res[i].rdlength = r->rdlength;
        new_res[i].rdata = nt_malloc(r->rdlength);
        memcpy(new_res[i].rdata, r->rdata, r->rdlength);
    }

    return new_res;
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
    nt_free(msg);
}

int nt_dns_msg_build(const nt_dns_msg_t* msg, void* buff, size_t size)
{
    int      ret;
    uint8_t* p = (uint8_t*)buff;
    if (size < 12)
    {
        return NT_ERR(ENOSPC);
    }

    /* ID */
    s_dns_set_u16(&p[0], msg->header.id);
    /* Bit:16-31 */
    uint16_t fields = (!!msg->header.qr << 15)              /* QR */
                      | ((msg->header.opcode & 0x0F) << 11) /* Opcode */
                      | (!!msg->header.aa << 10)            /* AA */
                      | (!!msg->header.tc << 9)             /* TC */
                      | (!!msg->header.rd << 8)             /* RD */
                      | (!!msg->header.ra << 7)             /* RA */
                      | ((msg->header.z & 0x07) << 4)       /* Z */
                      | ((msg->header.rcode & 0x0F) << 0) /* RCODE */;
    s_dns_set_u16(&p[2], fields);
    /* QDCOUNT */
    s_dns_set_u16(&p[4], msg->header.qdcount);
    /* ANCOUNT */
    s_dns_set_u16(&p[6], msg->header.ancount);
    /* NSCOUNT */
    s_dns_set_u16(&p[8], msg->header.nscount);
    /* ARCOUNT */
    s_dns_set_u16(&p[10], msg->header.arcount);

    size_t offset = 12;
    if ((ret = s_dns_build_question(p + offset, size - offset, msg->questions,
                                    msg->header.qdcount)) < 0)
    {
        return ret;
    }
    offset += ret;

    if ((ret = s_dns_build_resource(p + offset, size - offset, msg->answer, msg->header.ancount)) <
        0)
    {
        return ret;
    }
    offset += ret;

    if ((ret = s_dns_build_resource(p + offset, size - offset, msg->authority,
                                    msg->header.nscount)) < 0)
    {
        return ret;
    }
    offset += ret;

    if ((ret = s_dns_build_resource(p + offset, size - offset, msg->additional,
                                    msg->header.arcount)) < 0)
    {
        return ret;
    }
    offset += ret;

    return offset;
}

nt_dns_msg_t* nt_dns_msg_copy(const nt_dns_msg_t* msg)
{
    nt_dns_msg_t* pkg = nt_calloc(1, sizeof(nt_dns_msg_t));
    memcpy(&pkg->header, &msg->header, sizeof(msg->header));
    pkg->questions = s_dns_copy_question(msg->questions, msg->header.qdcount);
    pkg->answer = s_dns_copy_resource(msg->answer, msg->header.ancount);
    pkg->authority = s_dns_copy_resource(msg->authority, msg->header.nscount);
    pkg->additional = s_dns_copy_resource(msg->additional, msg->header.arcount);

    return pkg;
}
