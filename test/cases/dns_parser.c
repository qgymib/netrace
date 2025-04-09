#include "utils/dns.h"
#include "runtime.h"

static nt_dns_msg_t* s_dns_msg = NULL;

TEST_FIXTURE_SETUP(dns_parser)
{
}

TEST_FIXTURE_TEARDOWN(dns_parser)
{
    if (s_dns_msg != NULL)
    {
        nt_dns_msg_free(s_dns_msg);
        s_dns_msg = NULL;
    }
}

TEST_F(dns_parser, query)
{
    /* clang-format off */
    /*
     * Transaction ID: 0xb214
     * Flags: 0x0100 Standard query
     *   0... .... .... .... = Response: Message is a query
     *   .000 0... .... .... = Opcode: Standard query (0)
     *   .... ..0. .... .... = Truncated: Message is not truncated
     *   .... ...1 .... .... = Recursion desired: Do query recursively
     *   .... .... .0.. .... = Z: reserved (0)
     *   .... .... ...0 .... = Non-authenticated data: Unacceptable
     * Questions: 1
     * Answer RRs: 0
     * Authority RRs: 0
     * Additional RRs: 0
     * Queries
     *   content-signature-2.cdn.mozilla.net: type A, class IN
     *     Name: content-signature-2.cdn.mozilla.net
     *     [Name Length: 35]
     *     [Label Count: 4]
     *     Type: A (1) (Host Address)
     *     Class: IN (0x0001)
     */
    /* clang-format on */
    static const uint8_t data[] = {
        0xb2, 0x14, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, /* ........ */
        0x00, 0x00, 0x00, 0x00, 0x13, 0x63, 0x6f, 0x6e, /* .....con */
        0x74, 0x65, 0x6e, 0x74, 0x2d, 0x73, 0x69, 0x67, /* tent-sig */
        0x6e, 0x61, 0x74, 0x75, 0x72, 0x65, 0x2d, 0x32, /* nature-2 */
        0x03, 0x63, 0x64, 0x6e, 0x07, 0x6d, 0x6f, 0x7a, /* .cdn.moz */
        0x69, 0x6c, 0x6c, 0x61, 0x03, 0x6e, 0x65, 0x74, /* illa.net */
        0x00, 0x00, 0x01, 0x00, 0x01,                   /* .....    */
    };

    ASSERT_EQ_INT(nt_dns_msg_parser(&s_dns_msg, data, sizeof(data)), sizeof(data));
    ASSERT_EQ_UINT(s_dns_msg->header.id, 0xb214);
    ASSERT_EQ_UINT(s_dns_msg->header.qr, 0);
    ASSERT_EQ_UINT(s_dns_msg->header.opcode, 0);
    ASSERT_EQ_UINT(s_dns_msg->header.aa, 0);
    ASSERT_EQ_UINT(s_dns_msg->header.tc, 0);
    ASSERT_EQ_UINT(s_dns_msg->header.rd, 1);
    ASSERT_EQ_UINT(s_dns_msg->header.ra, 0);
    ASSERT_EQ_UINT(s_dns_msg->header.z, 0);
    ASSERT_EQ_UINT(s_dns_msg->header.rcode, 0);
    ASSERT_EQ_UINT(s_dns_msg->header.qdcount, 1);
    ASSERT_EQ_UINT(s_dns_msg->header.ancount, 0);
    ASSERT_EQ_UINT(s_dns_msg->header.nscount, 0);
    ASSERT_EQ_UINT(s_dns_msg->header.arcount, 0);
    ASSERT_EQ_SIZE(s_dns_msg->questions[0].qname.size, 4);
    ASSERT_EQ_STR(s_dns_msg->questions[0].qname.data[0].data, "content-signature-2");
    ASSERT_EQ_STR(s_dns_msg->questions[0].qname.data[1].data, "cdn");
    ASSERT_EQ_STR(s_dns_msg->questions[0].qname.data[2].data, "mozilla");
    ASSERT_EQ_STR(s_dns_msg->questions[0].qname.data[3].data, "net");
    ASSERT_EQ_UINT(s_dns_msg->questions[0].qtype, 1);
    ASSERT_EQ_UINT(s_dns_msg->questions[0].qclass, 1);
}

TEST_F(dns_parser, response)
{
    /* clang-format off */
    /*
     * Transaction ID: 0xb214
     * Flags: 0x8180 Standard query response, No error
     *   1... .... .... .... = Response: Message is a response
     *   .000 0... .... .... = Opcode: Standard query (0)
     *   .... .0.. .... .... = Authoritative: Server is not an authority for domain
     *   .... ..0. .... .... = Truncated: Message is not truncated
     *   .... ...1 .... .... = Recursion desired: Do query recursively
     *   .... .... 1... .... = Recursion available: Server can do recursive queries
     *   .... .... .0.. .... = Z: reserved (0)
     *   .... .... ..0. .... = Answer authenticated: Answer/authority portion was not authenticated by the server
     *   .... .... ...0 .... = Non-authenticated data: Unacceptable
     *   .... .... .... 0000 = Reply code: No error (0)
     * Questions: 1
     * Answer RRs: 3
     * Authority RRs: 0
     * Additional RRs: 0
     * Queries
     *   content-signature-2.cdn.mozilla.net: type A, class IN
     *     Name: content-signature-2.cdn.mozilla.net
     *     [Name Length: 35]
     *     [Label Count: 4]
     *     Type: A (1) (Host Address)
     *     Class: IN (0x0001)
     * Answers
     *   content-signature-2.cdn.mozilla.net: type CNAME, class IN, cname content-signature-chains.prod.autograph.services.mozaws.net
     *     Name: content-signature-2.cdn.mozilla.net
     *     Type: CNAME (5) (Canonical NAME for an alias)
     *     Class: IN (0x0001)
     *     Time to live: 300 (5 minutes)
     *     Data length: 58
     *     CNAME: content-signature-chains.prod.autograph.services.mozaws.net
     *   content-signature-chains.prod.autograph.services.mozaws.net: type CNAME, class IN, cname prod.content-signature-chains.prod.webservices.mozgcp.net
     *     Name: content-signature-chains.prod.autograph.services.mozaws.net
     *     Type: CNAME (5) (Canonical NAME for an alias)
     *     Class: IN (0x0001)
     *     Time to live: 231 (3 minutes, 51 seconds)
     *     Data length: 56
     *     CNAME: prod.content-signature-chains.prod.webservices.mozgcp.net
     *   prod.content-signature-chains.prod.webservices.mozgcp.net: type A, class IN, addr 34.160.144.191
     *     Name: prod.content-signature-chains.prod.webservices.mozgcp.net
     *     Type: A (1) (Host Address)
     *     Class: IN (0x0001)
     *     Time to live: 193 (3 minutes, 13 seconds)
     *     Data length: 4
     *     Address: 34.160.144.191
     */
    /* clang-format on */
    static const uint8_t data[] = {
        0xb2, 0x14, 0x81, 0x80, 0x00, 0x01, 0x00, 0x03, /* ........ */
        0x00, 0x00, 0x00, 0x00, 0x13, 0x63, 0x6f, 0x6e, /* .....con */
        0x74, 0x65, 0x6e, 0x74, 0x2d, 0x73, 0x69, 0x67, /* tent-sig */
        0x6e, 0x61, 0x74, 0x75, 0x72, 0x65, 0x2d, 0x32, /* nature-2 */
        0x03, 0x63, 0x64, 0x6e, 0x07, 0x6d, 0x6f, 0x7a, /* .cdn.moz */
        0x69, 0x6c, 0x6c, 0x61, 0x03, 0x6e, 0x65, 0x74, /* illa.net */
        0x00, 0x00, 0x01, 0x00, 0x01, 0xc0, 0x0c, 0x00, /* ........ */
        0x05, 0x00, 0x01, 0x00, 0x00, 0x01, 0x2c, 0x00, /* ......,. */
        0x3a, 0x18, 0x63, 0x6f, 0x6e, 0x74, 0x65, 0x6e, /* :.conten */
        0x74, 0x2d, 0x73, 0x69, 0x67, 0x6e, 0x61, 0x74, /* t-signat */
        0x75, 0x72, 0x65, 0x2d, 0x63, 0x68, 0x61, 0x69, /* ure-chai */
        0x6e, 0x73, 0x04, 0x70, 0x72, 0x6f, 0x64, 0x09, /* ns.prod. */
        0x61, 0x75, 0x74, 0x6f, 0x67, 0x72, 0x61, 0x70, /* autograp */
        0x68, 0x08, 0x73, 0x65, 0x72, 0x76, 0x69, 0x63, /* h.servic */
        0x65, 0x73, 0x06, 0x6d, 0x6f, 0x7a, 0x61, 0x77, /* es.mozaw */
        0x73, 0xc0, 0x2c, 0xc0, 0x41, 0x00, 0x05, 0x00, /* s.,.A... */
        0x01, 0x00, 0x00, 0x00, 0xe7, 0x00, 0x38, 0x04, /* ......8. */
        0x70, 0x72, 0x6f, 0x64, 0x18, 0x63, 0x6f, 0x6e, /* prod.con */
        0x74, 0x65, 0x6e, 0x74, 0x2d, 0x73, 0x69, 0x67, /* tent-sig */
        0x6e, 0x61, 0x74, 0x75, 0x72, 0x65, 0x2d, 0x63, /* nature-c */
        0x68, 0x61, 0x69, 0x6e, 0x73, 0x04, 0x70, 0x72, /* hains.pr */
        0x6f, 0x64, 0xb,  0x77, 0x65, 0x62, 0x73, 0x65, /* od.webse */
        0x72, 0x76, 0x69, 0x63, 0x65, 0x73, 0x06, 0x6d, /* rvices.m */
        0x6f, 0x7a, 0x67, 0x63, 0x70, 0xc0, 0x2c, 0xc0, /* ozgcp.,. */
        0x87, 0x0,  0x01, 0x00, 0x01, 0x00, 0x00, 0x00, /* ........ */
        0xc1, 0x00, 0x04, 0x22, 0xa0, 0x90, 0xbf,       /* ..."...  */
    };
    ASSERT_EQ_INT(nt_dns_msg_parser(&s_dns_msg, data, sizeof(data)), sizeof(data));

    ASSERT_EQ_UINT(s_dns_msg->header.id, 0xb214);
    ASSERT_EQ_UINT(s_dns_msg->header.qr, 1);
    ASSERT_EQ_UINT(s_dns_msg->header.opcode, 0);
    ASSERT_EQ_UINT(s_dns_msg->header.aa, 0);
    ASSERT_EQ_UINT(s_dns_msg->header.tc, 0);
    ASSERT_EQ_UINT(s_dns_msg->header.rd, 1);
    ASSERT_EQ_UINT(s_dns_msg->header.ra, 1);
    ASSERT_EQ_UINT(s_dns_msg->header.z, 0);
    ASSERT_EQ_UINT(s_dns_msg->header.rcode, 0);
    ASSERT_EQ_UINT(s_dns_msg->header.qdcount, 1);
    ASSERT_EQ_UINT(s_dns_msg->header.ancount, 3);
    ASSERT_EQ_UINT(s_dns_msg->header.nscount, 0);
    ASSERT_EQ_UINT(s_dns_msg->header.arcount, 0);

    ASSERT_EQ_SIZE(s_dns_msg->questions[0].qname.size, 4);
    ASSERT_EQ_STR(s_dns_msg->questions[0].qname.data[0].data, "content-signature-2");
    ASSERT_EQ_STR(s_dns_msg->questions[0].qname.data[1].data, "cdn");
    ASSERT_EQ_STR(s_dns_msg->questions[0].qname.data[2].data, "mozilla");
    ASSERT_EQ_STR(s_dns_msg->questions[0].qname.data[3].data, "net");
    ASSERT_EQ_UINT(s_dns_msg->questions[0].qtype, 1);
    ASSERT_EQ_UINT(s_dns_msg->questions[0].qclass, 1);

    ASSERT_EQ_SIZE(s_dns_msg->answer[0].name.size, 4);
    ASSERT_EQ_STR(s_dns_msg->answer[0].name.data[0].data, "content-signature-2");
    ASSERT_EQ_STR(s_dns_msg->answer[0].name.data[1].data, "cdn");
    ASSERT_EQ_STR(s_dns_msg->answer[0].name.data[2].data, "mozilla");
    ASSERT_EQ_STR(s_dns_msg->answer[0].name.data[3].data, "net");

    ASSERT_EQ_SIZE(s_dns_msg->answer[1].name.size, 6);
    ASSERT_EQ_STR(s_dns_msg->answer[1].name.data[0].data, "content-signature-chains");
    ASSERT_EQ_STR(s_dns_msg->answer[1].name.data[1].data, "prod");
    ASSERT_EQ_STR(s_dns_msg->answer[1].name.data[2].data, "autograph");
    ASSERT_EQ_STR(s_dns_msg->answer[1].name.data[3].data, "services");
    ASSERT_EQ_STR(s_dns_msg->answer[1].name.data[4].data, "mozaws");
    ASSERT_EQ_STR(s_dns_msg->answer[1].name.data[5].data, "net");

    ASSERT_EQ_SIZE(s_dns_msg->answer[2].name.size, 6);
    ASSERT_EQ_STR(s_dns_msg->answer[2].name.data[0].data, "prod");
    ASSERT_EQ_STR(s_dns_msg->answer[2].name.data[1].data, "content-signature-chains");
    ASSERT_EQ_STR(s_dns_msg->answer[2].name.data[2].data, "prod");
    ASSERT_EQ_STR(s_dns_msg->answer[2].name.data[3].data, "webservices");
    ASSERT_EQ_STR(s_dns_msg->answer[2].name.data[4].data, "mozgcp");
    ASSERT_EQ_STR(s_dns_msg->answer[2].name.data[5].data, "net");
}
