/**
 * @copyright Copyright (c) 2022, Alibaba Group Holding Limited
 *
 * MASQUE common utilities for CONNECT-UDP / CONNECT-IP test clients.
 * Provides HTTP Datagram framing (RFC 9297) and Capsule Protocol helpers.
 */

#ifndef MASQUE_COMMON_H
#define MASQUE_COMMON_H

#include <stdint.h>
#include <stddef.h>
#include <string.h>

/**
 * QUIC variable-length integer encoding (RFC 9000, Section 16).
 * These are simplified helpers for the MASQUE framing layer.
 */

/* Return the number of bytes needed to encode a varint value */
static inline size_t
masque_varint_len(uint64_t value)
{
    if (value < 0x40) {
        return 1;
    } else if (value < 0x4000) {
        return 2;
    } else if (value < 0x40000000) {
        return 4;
    } else {
        return 8;
    }
}

/* Encode a varint into buf. Returns number of bytes written. */
static inline size_t
masque_varint_encode(uint8_t *buf, size_t buflen, uint64_t value)
{
    size_t len = masque_varint_len(value);
    if (buflen < len) {
        return 0;
    }

    switch (len) {
    case 1:
        buf[0] = (uint8_t)value;
        break;
    case 2:
        buf[0] = (uint8_t)(0x40 | (value >> 8));
        buf[1] = (uint8_t)(value & 0xFF);
        break;
    case 4:
        buf[0] = (uint8_t)(0x80 | (value >> 24));
        buf[1] = (uint8_t)((value >> 16) & 0xFF);
        buf[2] = (uint8_t)((value >> 8) & 0xFF);
        buf[3] = (uint8_t)(value & 0xFF);
        break;
    case 8:
        buf[0] = (uint8_t)(0xC0 | (value >> 56));
        buf[1] = (uint8_t)((value >> 48) & 0xFF);
        buf[2] = (uint8_t)((value >> 40) & 0xFF);
        buf[3] = (uint8_t)((value >> 32) & 0xFF);
        buf[4] = (uint8_t)((value >> 24) & 0xFF);
        buf[5] = (uint8_t)((value >> 16) & 0xFF);
        buf[6] = (uint8_t)((value >> 8) & 0xFF);
        buf[7] = (uint8_t)(value & 0xFF);
        break;
    }
    return len;
}

/**
 * Decode a varint from buf. Returns number of bytes consumed, or 0 on error.
 * On success, *value is set to the decoded integer.
 */
static inline size_t
masque_varint_decode(const uint8_t *buf, size_t buflen, uint64_t *value)
{
    if (buflen == 0) {
        return 0;
    }

    uint8_t prefix = buf[0] >> 6;
    size_t len = (size_t)(1 << prefix);

    if (buflen < len) {
        return 0;
    }

    *value = buf[0] & 0x3F;
    for (size_t i = 1; i < len; i++) {
        *value = (*value << 8) | buf[i];
    }

    return len;
}

/**
 * HTTP Datagram framing for CONNECT-UDP (RFC 9297 + RFC 9298).
 *
 * QUIC DATAGRAM payload layout:
 *   [Quarter-Stream-ID : varint] [Context-ID : varint = 0x00] [UDP payload]
 *
 * Quarter-Stream-ID = request_stream_id / 4
 */

/**
 * Frame a UDP payload into an HTTP Datagram buffer.
 * Returns the total framed length, or 0 on error.
 *
 * @param out       output buffer
 * @param outlen    output buffer capacity
 * @param stream_id the QUIC stream ID of the H3 request (will be divided by 4)
 * @param payload   the raw UDP payload
 * @param paylen    length of the UDP payload
 */
static inline size_t
masque_frame_udp_datagram(uint8_t *out, size_t outlen,
                          uint64_t stream_id,
                          const uint8_t *payload, size_t paylen)
{
    uint64_t quarter_id = stream_id / 4;
    size_t qid_len = masque_varint_len(quarter_id);
    size_t ctx_len = 1;  /* context_id = 0 → 1 byte varint */
    size_t total = qid_len + ctx_len + paylen;

    if (outlen < total) {
        return 0;
    }

    size_t off = 0;
    off += masque_varint_encode(out + off, outlen - off, quarter_id);
    out[off++] = 0x00;  /* context_id = 0 */
    memcpy(out + off, payload, paylen);

    return total;
}

/**
 * Unframe an HTTP Datagram received via QUIC DATAGRAM.
 * Returns the offset to the UDP payload within the buffer, or 0 on error.
 * On success, *quarter_stream_id and *context_id are set,
 * and *payload_len is set to the remaining payload length.
 *
 * @param buf              received datagram buffer
 * @param buflen           length of the buffer
 * @param quarter_stream_id  [out] the quarter-stream-ID
 * @param context_id       [out] the context ID
 * @param payload_offset   [out] offset to the UDP payload within buf
 * @param payload_len      [out] length of the UDP payload
 */
static inline int
masque_unframe_udp_datagram(const uint8_t *buf, size_t buflen,
                            uint64_t *quarter_stream_id, uint64_t *context_id,
                            size_t *payload_offset, size_t *payload_len)
{
    size_t off = 0;
    size_t n;

    n = masque_varint_decode(buf + off, buflen - off, quarter_stream_id);
    if (n == 0) {
        return -1;
    }
    off += n;

    n = masque_varint_decode(buf + off, buflen - off, context_id);
    if (n == 0) {
        return -1;
    }
    off += n;

    *payload_offset = off;
    *payload_len = buflen - off;
    return 0;
}

/**
 * Calculate the maximum UDP payload size that can fit in a single datagram.
 *
 * @param mss        the MSS from xqc_h3_ext_datagram_get_mss()
 * @param stream_id  the QUIC stream ID of the H3 request
 */
static inline size_t
masque_udp_mss(size_t mss, uint64_t stream_id)
{
    uint64_t quarter_id = stream_id / 4;
    size_t overhead = masque_varint_len(quarter_id) + 1; /* +1 for context_id=0 */
    if (mss <= overhead) {
        return 0;
    }
    return mss - overhead;
}

/**
 * Capsule Protocol (RFC 9297, Section 3.2).
 *
 * Capsule wire format:
 *   [Capsule Type : varint] [Capsule Length : varint] [Capsule Value]
 *
 * Used by CONNECT-IP (RFC 9484) for control messages on the H3 stream.
 */

/* RFC 9297 capsule types */
#define MASQUE_CAPSULE_DATAGRAM         0x00

/* RFC 9484 capsule types for CONNECT-IP */
#define MASQUE_CAPSULE_ADDRESS_ASSIGN   0x01
#define MASQUE_CAPSULE_ADDRESS_REQUEST  0x02
#define MASQUE_CAPSULE_ROUTE_ADVERTISEMENT  0x03

/**
 * Encode a capsule into buf.
 * Returns the total encoded length, or 0 on error (buffer too small).
 *
 * @param out       output buffer
 * @param outlen    output buffer capacity
 * @param type      capsule type
 * @param payload   capsule value (may be NULL if paylen == 0)
 * @param paylen    length of the capsule value
 */
static inline size_t
masque_capsule_encode(uint8_t *out, size_t outlen,
                      uint64_t type,
                      const uint8_t *payload, size_t paylen)
{
    size_t type_len = masque_varint_len(type);
    size_t len_len = masque_varint_len((uint64_t)paylen);
    size_t total = type_len + len_len + paylen;

    if (outlen < total) {
        return 0;
    }

    size_t off = 0;
    off += masque_varint_encode(out + off, outlen - off, type);
    off += masque_varint_encode(out + off, outlen - off, (uint64_t)paylen);
    if (paylen > 0 && payload != NULL) {
        memcpy(out + off, payload, paylen);
    }

    return total;
}

/**
 * Decode a capsule header from buf.
 * Returns 0 on success, -1 on error (buffer too small / truncated).
 *
 * On success:
 *   *type           = capsule type
 *   *payload_offset = offset to the capsule value within buf
 *   *payload_len    = length of the capsule value
 *
 * Note: caller must verify buf has at least (payload_offset + payload_len) bytes.
 *
 * @param buf              input buffer
 * @param buflen           length of input buffer
 * @param type             [out] capsule type
 * @param payload_offset   [out] offset to capsule value
 * @param payload_len      [out] length of capsule value
 */
static inline int
masque_capsule_decode(const uint8_t *buf, size_t buflen,
                      uint64_t *type,
                      size_t *payload_offset, size_t *payload_len)
{
    size_t off = 0;
    size_t n;

    n = masque_varint_decode(buf + off, buflen - off, type);
    if (n == 0) {
        return -1;
    }
    off += n;

    uint64_t len64;
    n = masque_varint_decode(buf + off, buflen - off, &len64);
    if (n == 0) {
        return -1;
    }
    off += n;

    *payload_offset = off;
    *payload_len = (size_t)len64;
    return 0;
}

/**
 * CONNECT-IP Address Assign capsule payload (RFC 9484, Section 4.7.1).
 *
 * Payload format:
 *   [Request ID : varint] [IP Version : 1 byte] [IP Address : 4 or 16 bytes]
 *   [IP Prefix Length : 1 byte]
 *
 * This is a simplified parser for a single assigned address.
 */
static inline int
masque_parse_address_assign(const uint8_t *payload, size_t paylen,
                            uint64_t *request_id,
                            uint8_t *ip_version,
                            uint8_t *ip_addr, size_t *ip_addr_len,
                            uint8_t *prefix_len)
{
    size_t off = 0;
    size_t n;

    n = masque_varint_decode(payload + off, paylen - off, request_id);
    if (n == 0) {
        return -1;
    }
    off += n;

    if (off >= paylen) {
        return -1;
    }
    *ip_version = payload[off++];

    size_t addr_len;
    if (*ip_version == 4) {
        addr_len = 4;
    } else if (*ip_version == 6) {
        addr_len = 16;
    } else {
        return -1;
    }

    if (off + addr_len + 1 > paylen) {
        return -1;
    }

    memcpy(ip_addr, payload + off, addr_len);
    *ip_addr_len = addr_len;
    off += addr_len;

    *prefix_len = payload[off];
    return 0;
}

/**
 * Build an ADDRESS_REQUEST capsule payload (RFC 9484, Section 4.7.2).
 *
 * Payload format (same as ADDRESS_ASSIGN):
 *   [Request ID : varint] [IP Version : 1 byte] [IP Address : 4 or 16 bytes]
 *   [IP Prefix Length : 1 byte]
 *
 * To request any IPv4 address: ip_addr={0,0,0,0}, prefix_len=0.
 * Returns the payload length written, or 0 on error.
 *
 * @param buf         output buffer for the payload (NOT the full capsule)
 * @param buflen      output buffer capacity
 * @param request_id  unique request identifier
 * @param ip_version  4 or 6
 * @param ip_addr     preferred IP address (or all-zeros for any)
 * @param prefix_len  requested prefix length
 */
static inline size_t
masque_build_address_request(uint8_t *buf, size_t buflen,
                              uint64_t request_id, uint8_t ip_version,
                              const uint8_t *ip_addr, uint8_t prefix_len)
{
    size_t addr_len;
    if (ip_version == 4) {
        addr_len = 4;
    } else if (ip_version == 6) {
        addr_len = 16;
    } else {
        return 0;
    }

    size_t rid_len = masque_varint_len(request_id);
    size_t total = rid_len + 1 + addr_len + 1; /* rid + ip_ver + addr + pfx */

    if (buflen < total) {
        return 0;
    }

    size_t off = 0;
    off += masque_varint_encode(buf + off, buflen - off, request_id);
    buf[off++] = ip_version;
    memcpy(buf + off, ip_addr, addr_len);
    off += addr_len;
    buf[off++] = prefix_len;

    return off;
}

/**
 * Parse a single ROUTE_ADVERTISEMENT entry (RFC 9484, Section 4.7.3).
 *
 * Entry format:
 *   [IP Version : 1 byte] [Start IP : 4 or 16 bytes]
 *   [End IP : 4 or 16 bytes] [IP Protocol : 1 byte]
 *
 * The capsule payload may contain multiple entries back-to-back.
 * Call this in a loop, advancing the buffer by *bytes_consumed each time.
 *
 * Returns 0 on success, -1 on error (truncated / invalid).
 *
 * @param payload        input buffer (at current parse position)
 * @param paylen         remaining bytes in buffer
 * @param ip_version     [out] 4 or 6
 * @param start_ip       [out] start of IP range (4 or 16 bytes)
 * @param end_ip         [out] end of IP range (4 or 16 bytes)
 * @param ip_addr_len    [out] 4 (IPv4) or 16 (IPv6)
 * @param ip_protocol    [out] IP protocol number (0 = all)
 * @param bytes_consumed [out] number of bytes consumed for this entry
 */
static inline int
masque_parse_route_advertisement(const uint8_t *payload, size_t paylen,
                                  uint8_t *ip_version,
                                  uint8_t *start_ip, uint8_t *end_ip,
                                  size_t *ip_addr_len, uint8_t *ip_protocol,
                                  size_t *bytes_consumed)
{
    size_t off = 0;

    if (off >= paylen) {
        return -1;
    }
    *ip_version = payload[off++];

    size_t addr_len;
    if (*ip_version == 4) {
        addr_len = 4;
    } else if (*ip_version == 6) {
        addr_len = 16;
    } else {
        return -1;
    }

    /* Need: start_ip + end_ip + ip_protocol */
    if (off + addr_len + addr_len + 1 > paylen) {
        return -1;
    }

    memcpy(start_ip, payload + off, addr_len);
    off += addr_len;
    memcpy(end_ip, payload + off, addr_len);
    off += addr_len;
    *ip_addr_len = addr_len;
    *ip_protocol = payload[off++];

    *bytes_consumed = off;
    return 0;
}

/**
 * IPv4 header / ICMP checksum (RFC 1071).
 * Computes the ones' complement of the ones' complement sum.
 */
static inline uint16_t
masque_ip_checksum(const uint8_t *data, size_t len)
{
    uint32_t sum = 0;
    for (size_t i = 0; i + 1 < len; i += 2) {
        sum += ((uint16_t)data[i] << 8) | data[i + 1];
    }
    if (len & 1) {
        sum += (uint16_t)data[len - 1] << 8;
    }
    while (sum >> 16) {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    return (uint16_t)~sum;
}

/**
 * Build a minimal IPv4 ICMP Echo Request packet.
 * Returns the total packet length (32), or 0 on error.
 *
 * @param buf     output buffer (must be >= 32 bytes)
 * @param buflen  output buffer capacity
 * @param src_ip  source IPv4 address (4 bytes)
 * @param dst_ip  destination IPv4 address (4 bytes)
 */
static inline size_t
masque_build_icmp_echo(uint8_t *buf, size_t buflen,
                       const uint8_t src_ip[4], const uint8_t dst_ip[4])
{
    const size_t ip_hdr_len = 20;
    const size_t icmp_len = 12;  /* 8 header + 4 data */
    const size_t total = ip_hdr_len + icmp_len;

    if (buflen < total) {
        return 0;
    }
    memset(buf, 0, total);

    /* IPv4 header */
    buf[0] = 0x45;              /* Version=4, IHL=5 (20 bytes) */
    buf[1] = 0x00;              /* DSCP/ECN */
    buf[2] = (uint8_t)(total >> 8);
    buf[3] = (uint8_t)(total & 0xFF);
    buf[4] = 0x00; buf[5] = 0x01; /* Identification */
    buf[6] = 0x00; buf[7] = 0x00; /* Flags + Fragment Offset */
    buf[8] = 64;                /* TTL */
    buf[9] = 1;                 /* Protocol: ICMP */
    memcpy(buf + 12, src_ip, 4);
    memcpy(buf + 16, dst_ip, 4);

    uint16_t ip_cksum = masque_ip_checksum(buf, ip_hdr_len);
    buf[10] = (uint8_t)(ip_cksum >> 8);
    buf[11] = (uint8_t)(ip_cksum & 0xFF);

    /* ICMP Echo Request */
    uint8_t *icmp = buf + ip_hdr_len;
    icmp[0] = 8;                /* Type: Echo Request */
    icmp[1] = 0;                /* Code */
    icmp[4] = 0x00; icmp[5] = 0x01; /* Identifier */
    icmp[6] = 0x00; icmp[7] = 0x01; /* Sequence Number */
    icmp[8] = 'T'; icmp[9] = 'E'; icmp[10] = 'S'; icmp[11] = 'T';

    uint16_t icmp_cksum = masque_ip_checksum(icmp, icmp_len);
    icmp[2] = (uint8_t)(icmp_cksum >> 8);
    icmp[3] = (uint8_t)(icmp_cksum & 0xFF);

    return total;
}

#endif /* MASQUE_COMMON_H */
