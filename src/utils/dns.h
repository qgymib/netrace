/**
 * @file
 * @see https://datatracker.ietf.org/doc/html/rfc1035
 *
 * All communications inside of the domain protocol are carried in a single
 * format called a message.  The top level format of message is divided
 * into 5 sections (some of which are empty in certain cases) shown below:
 *
 *     +---------------------+
 *     |        Header       |
 *     +---------------------+
 *     |       Question      | the question for the name server
 *     +---------------------+
 *     |        Answer       | RRs answering the question
 *     +---------------------+
 *     |      Authority      | RRs pointing toward an authority
 *     +---------------------+
 *     |      Additional     | RRs holding additional information
 *     +---------------------+
 *
 * The header section is always present.  The header includes fields that
 * specify which of the remaining sections are present, and also specify
 * whether the message is a query or a response, a standard query or some
 * other opcode, etc.
 *
 * The names of the sections after the header are derived from their use in
 * standard queries.  The question section contains fields that describe a
 * question to a name server.  These fields are a query type (QTYPE), a
 * query class (QCLASS), and a query domain name (QNAME).  The last three
 * sections have the same format: a possibly empty list of concatenated
 * resource records (RRs).  The answer section contains RRs that answer the
 * question; the authority section contains RRs that point toward an
 * authoritative name server; the additional records section contains RRs
 * which relate to the query, but are not strictly answers for the
 * question.
 */
#ifndef NT_UTILS_DNS_H
#define NT_UTILS_DNS_H

#include <stdint.h>
#include "utils/str.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef enum nt_dns_type
{
    DNS_TYPE_A = 1,     /* A host address */
    DNS_TYPE_NS = 2,    /* An authoritative name server */
    DNS_TYPE_MD = 3,    /* A mail destination (Obsolete - use MX) */
    DNS_TYPE_MF = 4,    /* A mail forwarder (Obsolete - use MX) */
    DNS_TYPE_CNAME = 5, /* The canonical name for an alias */
    DNS_TYPE_SOA = 6,   /* Marks the start of a zone of authority */
    DNS_TYPE_MB = 7,    /* A mailbox domain name (EXPERIMENTAL) */
    DNS_TYPE_MG = 8,    /* A mail group member (EXPERIMENTAL) */
} nt_dns_type_t;

typedef enum nt_dns_qtype
{
    DNS_QTYPE_AXFR = 252,  /* A request for a transfer of an entire zone */
    DNS_QTYPE_MAILB = 253, /* A request for mailbox-related records (MB, MG or MR) */
    DNS_QTYPE_MAILA = 254, /* A request for mail agent RRs (Obsolete - see MX) */
    DNS_QTYPE_ANY = 255,   /* A request for all records */
} nt_dns_qtype_t;

/**
 * @brief 12 Bytes DNS message header.
 */
typedef struct nt_dns_header
{
    /**
     * @brief A 16 bit identifier assigned by the program that generates any
     * kind of query.
     *
     * This identifier is copied the corresponding reply and can be used by the
     * requester to match up replies to outstanding queries.
     */
    uint16_t id;

    /**
     * @brief A one bit field that specifies whether this message is a query (0),
     * or a response (1).
     */
    uint8_t qr;

    /**
     * @brief A four bit field that specifies kind of query in this message.
     *
     * This value is set by the originator of a query and copied into the
     * response. The values are:
     * 0               a standard query (QUERY)
     * 1               an inverse query (IQUERY)
     * 2               a server status request (STATUS)
     * 3-15            reserved for future use
     */
    uint8_t opcode;

    /**
     * @brief Authoritative Answer - this bit is valid in responses, and
     * specifies that the responding name server is an authority for the domain
     * name in question section.
     *
     * Note that the contents of the answer section may have multiple owner names
     * because of aliases. The AA bit corresponds to the name which matches the
     * query name, or the first owner name in the answer section.
     */
    uint8_t aa;

    /**
     * @brief TrunCation - specifies that this message was truncated due to length
     * greater than that permitted on the transmission channel.
     */
    uint8_t tc;

    /**
     * @brief Recursion Desired - this bit may be set in a query and is copied
     * into the response. If RD is set, it directs the name server to pursue
     * the query recursively. Recursive query support is optional.
     */
    uint8_t rd;

    /**
     * @brief Recursion Available - this be is set or cleared in a response, and
     * denotes whether recursive query support is available in the name server.
     */
    uint8_t ra;

    /**
     * @brief Reserved for future use. Must be zero in all queries and responses.
     */
    uint8_t z;

    /**
     * @brief Response code - this 4 bit field is set as part of responses. The
     * values have the following interpretation:
     * 0               No error condition
     * 1               Format error - The name server was
     *                 unable to interpret the query.
     * 2               Server failure - The name server was
     *                 unable to process this query due to a
     *                 problem with the name server.
     * 3               Name Error - Meaningful only for
     *                 responses from an authoritative name
     *                 server, this code signifies that the
     *                 domain name referenced in the query does
     *                 not exist.
     * 4               Not Implemented - The name server does
     *                 not support the requested kind of query.
     * 5               Refused - The name server refuses to
     *                 perform the specified operation for
     *                 policy reasons.  For example, a name
     *                 server may not wish to provide the
     *                 information to the particular requester,
     *                 or a name server may not wish to perform
     *                 a particular operation (e.g., zone
     *                 transfer) for particular data.
     * 6-15            Reserved for future use.
     */
    uint8_t rcode;

    /**
     * @brief An unsigned 16 bit integer specifying the number of entries in the
     * question section.
     */
    uint16_t qdcount;

    /**
     * @brief An unsigned 16 bit integer specifying the number of resource records
     * in the answer section.
     */
    uint16_t ancount;

    /**
     * @brief An unsigned 16 bit integer specifying the number of name server
     * resource records in the authority records section.
     */
    uint16_t nscount;

    /**
     * @brief An unsigned 16 bit integer specifying the number of resource records
     * in the additional records section.
     */
    uint16_t arcount;
} nt_dns_header_t;

typedef struct nt_dns_question
{
    /**
     * @brief A domain name represented as a sequence of labels.
     */
    nt_str_arr_t qname;

    /**
     * @brief A two octet code which specifies the type of the query.
     * The values for this field include all codes valid for a TYPE field,
     * together with some more general codes which can match more than one type of RR.
     * @see #nt_dns_type_t
     * @see #nt_dns_qtype_t
     */
    uint16_t qtype;

    /**
     * @brief A two octet code that specifies the class of the query.
     * For example, the QCLASS field is IN for the Internet.
     */
    uint16_t qclass;
} nt_dns_question_t;

typedef struct nt_dns_resource
{
    /**
     * @brief A domain name to which this resource record pertains.
     */
    nt_str_arr_t name;

    /**
     * @brief Two octets containing one of the RR type codes.
     * This field specifies the meaning of the data in the RDATA field.
     */
    uint16_t type;

    /**
     * @brief Two octets which specify the class of the data in the RDATA field.
     */
    uint16_t class;

    /**
     * @brief A 32 bit unsigned integer that specifies the time interval (in
     * seconds) that the resource record may be cached before it should be discarded.
     *
     * Zero values are interpreted to mean that the RR can only be used for the
     * transaction in progress, and should not be cached.
     */
    uint32_t ttl;

    /**
     * @brief An unsigned 16 bit integer that specifies the length in octets of
     * the RDATA field.
     */
    uint16_t rdlength;

    /**
     * @brief A variable length string of octets that describes the resource.
     *
     * The format of this information varies according to the TYPE and CLASS of
     * the resource record.
     *
     * For example, the if the TYPE is A and the CLASS is IN, the RDATA field
     * is a 4 octet ARPA Internet address.
     */
    void* rdata;
} nt_dns_resource_t;

typedef struct nt_dns_msg
{
    nt_dns_header_t    header;
    nt_dns_question_t* questions;
    nt_dns_resource_t* answer;
    nt_dns_resource_t* authority;
    nt_dns_resource_t* additional;
} nt_dns_msg_t;

/**
 * @brief Parser DNS message.
 * @param[out] msg  DNS message.
 * @param[in] data  Message data.
 * @param[in] size Message size.
 * @return >=0 if success, < 0 if failed.
 */
int nt_dns_msg_parser(nt_dns_msg_t** msg, const void* data, size_t size);

/**
 * @brief Release DNS message.
 * @param[in] msg   DNS message.
 */
void nt_dns_msg_free(nt_dns_msg_t* msg);

/**
 * @brief Build DNS message.
 * @param[in] msg   DNS message.
 * @param[in] buff  Buffer to store message.
 * @param[in] size  Buffer size.
 * @return  Message size.
 */
int nt_dns_msg_build(const nt_dns_msg_t* msg, void* buff, size_t size);

/**
 * @brief Copy DNS message.
 * @param[in] msg   DNS message.
 * @return  Duplicated DNS message.
 */
nt_dns_msg_t* nt_dns_msg_copy(const nt_dns_msg_t* msg);

#ifdef __cplusplus
}
#endif
#endif
