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

#endif /* MASQUE_COMMON_H */
