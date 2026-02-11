/**
 * @copyright Copyright (c) 2022, Alibaba Group Holding Limited
 *
 * Unit tests for MASQUE common utilities (masque_common.h).
 * Tests varint encoding/decoding, HTTP Datagram framing, and MSS calculation.
 */

#include <CUnit/CUnit.h>
#include <string.h>
#include "tests/masque_common.h"

/* ── Varint encode/decode round-trip ── */

static void
test_varint_len(void)
{
    /* 1-byte: 0..63 */
    CU_ASSERT_EQUAL(masque_varint_len(0), 1);
    CU_ASSERT_EQUAL(masque_varint_len(63), 1);

    /* 2-byte: 64..16383 */
    CU_ASSERT_EQUAL(masque_varint_len(64), 2);
    CU_ASSERT_EQUAL(masque_varint_len(16383), 2);

    /* 4-byte: 16384..1073741823 */
    CU_ASSERT_EQUAL(masque_varint_len(16384), 4);
    CU_ASSERT_EQUAL(masque_varint_len(1073741823ULL), 4);

    /* 8-byte: 1073741824.. */
    CU_ASSERT_EQUAL(masque_varint_len(1073741824ULL), 8);
    CU_ASSERT_EQUAL(masque_varint_len(4611686018427387903ULL), 8);
}

static void
test_varint_roundtrip(void)
{
    uint64_t test_values[] = {
        0, 1, 63, 64, 16383, 16384,
        1073741823ULL, 1073741824ULL,
        4611686018427387903ULL,  /* max varint */
    };
    size_t nvalues = sizeof(test_values) / sizeof(test_values[0]);

    uint8_t buf[8];
    for (size_t i = 0; i < nvalues; i++) {
        uint64_t val = test_values[i];
        size_t expected_len = masque_varint_len(val);

        memset(buf, 0xFF, sizeof(buf));
        size_t enc_len = masque_varint_encode(buf, sizeof(buf), val);
        CU_ASSERT_EQUAL(enc_len, expected_len);

        uint64_t decoded = 0;
        size_t dec_len = masque_varint_decode(buf, sizeof(buf), &decoded);
        CU_ASSERT_EQUAL(dec_len, expected_len);
        CU_ASSERT_EQUAL(decoded, val);
    }
}

static void
test_varint_buffer_underflow(void)
{
    uint8_t buf[8];

    /* encode: buffer too small */
    CU_ASSERT_EQUAL(masque_varint_encode(buf, 0, 0), 0);
    CU_ASSERT_EQUAL(masque_varint_encode(buf, 1, 64), 0);   /* needs 2 bytes */
    CU_ASSERT_EQUAL(masque_varint_encode(buf, 3, 16384), 0); /* needs 4 bytes */
    CU_ASSERT_EQUAL(masque_varint_encode(buf, 7, 1073741824ULL), 0); /* needs 8 */

    /* decode: empty buffer */
    uint64_t val = 0xDEAD;
    CU_ASSERT_EQUAL(masque_varint_decode(buf, 0, &val), 0);

    /* decode: buffer shorter than indicated length */
    buf[0] = 0x40; /* 2-byte prefix, but only 1 byte provided */
    CU_ASSERT_EQUAL(masque_varint_decode(buf, 1, &val), 0);
}

/* ── UDP datagram framing ── */

static void
test_udp_framing_roundtrip(void)
{
    const uint8_t payload[] = "Hello MASQUE!";
    size_t paylen = sizeof(payload) - 1; /* exclude NUL */
    uint8_t framed[256];

    /* stream_id=0 → quarter_id=0 (1-byte varint) */
    size_t flen = masque_frame_udp_datagram(framed, sizeof(framed),
                                             0, payload, paylen);
    CU_ASSERT(flen > 0);
    CU_ASSERT_EQUAL(flen, 1 + 1 + paylen); /* qid(1) + ctx(1) + payload */

    uint64_t qid, ctx;
    size_t poff, plen;
    int rc = masque_unframe_udp_datagram(framed, flen, &qid, &ctx, &poff, &plen);
    CU_ASSERT_EQUAL(rc, 0);
    CU_ASSERT_EQUAL(qid, 0);
    CU_ASSERT_EQUAL(ctx, 0);
    CU_ASSERT_EQUAL(plen, paylen);
    CU_ASSERT(memcmp(framed + poff, payload, paylen) == 0);

    /* stream_id=4 → quarter_id=1 */
    flen = masque_frame_udp_datagram(framed, sizeof(framed),
                                      4, payload, paylen);
    CU_ASSERT(flen > 0);
    rc = masque_unframe_udp_datagram(framed, flen, &qid, &ctx, &poff, &plen);
    CU_ASSERT_EQUAL(rc, 0);
    CU_ASSERT_EQUAL(qid, 1);

    /* large stream_id=1024 → quarter_id=256 (2-byte varint) */
    flen = masque_frame_udp_datagram(framed, sizeof(framed),
                                      1024, payload, paylen);
    CU_ASSERT(flen > 0);
    CU_ASSERT_EQUAL(flen, 2 + 1 + paylen); /* qid(2) + ctx(1) + payload */
    rc = masque_unframe_udp_datagram(framed, flen, &qid, &ctx, &poff, &plen);
    CU_ASSERT_EQUAL(rc, 0);
    CU_ASSERT_EQUAL(qid, 256);
}

static void
test_udp_framing_errors(void)
{
    const uint8_t payload[] = "test";
    uint8_t framed[4]; /* too small */

    /* buffer too small for framing */
    size_t flen = masque_frame_udp_datagram(framed, 2, 0, payload, 4);
    CU_ASSERT_EQUAL(flen, 0);

    /* unframe: truncated buffer (only quarter_id, no context_id) */
    uint8_t trunc[1] = {0x00};
    uint64_t qid, ctx;
    size_t poff, plen;
    int rc = masque_unframe_udp_datagram(trunc, 1, &qid, &ctx, &poff, &plen);
    /* should fail: only 1 byte = quarter_id OK, but no room for context_id */
    CU_ASSERT(rc == -1 || plen == 0);

    /* unframe: empty buffer */
    rc = masque_unframe_udp_datagram(trunc, 0, &qid, &ctx, &poff, &plen);
    CU_ASSERT_EQUAL(rc, -1);
}

/* ── MSS calculation ── */

static void
test_udp_mss(void)
{
    /* stream_id=0 → quarter_id=0 → varint_len=1, overhead=2 */
    CU_ASSERT_EQUAL(masque_udp_mss(1200, 0), 1198);

    /* stream_id=1024 → quarter_id=256 → varint_len=2, overhead=3 */
    CU_ASSERT_EQUAL(masque_udp_mss(1200, 1024), 1197);

    /* mss == overhead → 0 */
    CU_ASSERT_EQUAL(masque_udp_mss(2, 0), 0);

    /* mss < overhead → 0 */
    CU_ASSERT_EQUAL(masque_udp_mss(1, 0), 0);
    CU_ASSERT_EQUAL(masque_udp_mss(0, 0), 0);
}

/* ── Capsule Protocol ── */

static void
test_capsule_roundtrip(void)
{
    const uint8_t payload[] = "IP packet data";
    size_t paylen = sizeof(payload) - 1;
    uint8_t buf[256];

    /* encode DATAGRAM capsule (type=0) */
    size_t enc_len = masque_capsule_encode(buf, sizeof(buf),
                                            MASQUE_CAPSULE_DATAGRAM,
                                            payload, paylen);
    CU_ASSERT(enc_len > 0);
    CU_ASSERT_EQUAL(enc_len, 1 + 1 + paylen); /* type(1) + len(1) + payload */

    uint64_t type;
    size_t poff, plen;
    int rc = masque_capsule_decode(buf, enc_len, &type, &poff, &plen);
    CU_ASSERT_EQUAL(rc, 0);
    CU_ASSERT_EQUAL(type, MASQUE_CAPSULE_DATAGRAM);
    CU_ASSERT_EQUAL(plen, paylen);
    CU_ASSERT(memcmp(buf + poff, payload, paylen) == 0);

    /* encode ADDRESS_ASSIGN capsule (type=1) */
    enc_len = masque_capsule_encode(buf, sizeof(buf),
                                     MASQUE_CAPSULE_ADDRESS_ASSIGN,
                                     payload, paylen);
    CU_ASSERT(enc_len > 0);
    rc = masque_capsule_decode(buf, enc_len, &type, &poff, &plen);
    CU_ASSERT_EQUAL(rc, 0);
    CU_ASSERT_EQUAL(type, MASQUE_CAPSULE_ADDRESS_ASSIGN);
    CU_ASSERT_EQUAL(plen, paylen);

    /* empty payload capsule */
    enc_len = masque_capsule_encode(buf, sizeof(buf),
                                     MASQUE_CAPSULE_ROUTE_ADVERTISEMENT,
                                     NULL, 0);
    CU_ASSERT(enc_len > 0);
    CU_ASSERT_EQUAL(enc_len, 2); /* type(1) + len=0(1) */
    rc = masque_capsule_decode(buf, enc_len, &type, &poff, &plen);
    CU_ASSERT_EQUAL(rc, 0);
    CU_ASSERT_EQUAL(type, MASQUE_CAPSULE_ROUTE_ADVERTISEMENT);
    CU_ASSERT_EQUAL(plen, 0);
}

static void
test_capsule_errors(void)
{
    uint8_t buf[4];

    /* buffer too small for encode */
    CU_ASSERT_EQUAL(masque_capsule_encode(buf, 1, 0, (const uint8_t *)"x", 1), 0);

    /* decode: empty buffer */
    uint64_t type;
    size_t poff, plen;
    CU_ASSERT_EQUAL(masque_capsule_decode(buf, 0, &type, &poff, &plen), -1);

    /* decode: only type byte, no length */
    buf[0] = 0x01;
    CU_ASSERT_EQUAL(masque_capsule_decode(buf, 1, &type, &poff, &plen), -1);
}

static void
test_address_assign_parse(void)
{
    /* Build an ADDRESS_ASSIGN payload:
     * request_id=0 (1 byte), ip_version=4 (1 byte),
     * ip_addr=10.0.0.1 (4 bytes), prefix_len=32 (1 byte) */
    uint8_t payload[7];
    payload[0] = 0x00;  /* request_id = 0 */
    payload[1] = 4;     /* IPv4 */
    payload[2] = 10;    /* 10.0.0.1 */
    payload[3] = 0;
    payload[4] = 0;
    payload[5] = 1;
    payload[6] = 32;    /* /32 */

    uint64_t req_id;
    uint8_t ip_ver, ip_addr[16], pfx_len;
    size_t ip_addr_len;
    int rc = masque_parse_address_assign(payload, sizeof(payload),
                                          &req_id, &ip_ver,
                                          ip_addr, &ip_addr_len, &pfx_len);
    CU_ASSERT_EQUAL(rc, 0);
    CU_ASSERT_EQUAL(req_id, 0);
    CU_ASSERT_EQUAL(ip_ver, 4);
    CU_ASSERT_EQUAL(ip_addr_len, 4);
    CU_ASSERT_EQUAL(ip_addr[0], 10);
    CU_ASSERT_EQUAL(ip_addr[1], 0);
    CU_ASSERT_EQUAL(ip_addr[2], 0);
    CU_ASSERT_EQUAL(ip_addr[3], 1);
    CU_ASSERT_EQUAL(pfx_len, 32);

    /* IPv6 test: request_id=1, ip_version=6, ::1/128 */
    uint8_t payload6[19];
    payload6[0] = 0x01;  /* request_id = 1 */
    payload6[1] = 6;     /* IPv6 */
    memset(payload6 + 2, 0, 15);
    payload6[17] = 1;    /* ::1 */
    payload6[18] = 128;  /* /128 */

    rc = masque_parse_address_assign(payload6, sizeof(payload6),
                                      &req_id, &ip_ver,
                                      ip_addr, &ip_addr_len, &pfx_len);
    CU_ASSERT_EQUAL(rc, 0);
    CU_ASSERT_EQUAL(req_id, 1);
    CU_ASSERT_EQUAL(ip_ver, 6);
    CU_ASSERT_EQUAL(ip_addr_len, 16);
    CU_ASSERT_EQUAL(pfx_len, 128);

    /* truncated payload: missing prefix_len */
    rc = masque_parse_address_assign(payload, 6, &req_id, &ip_ver,
                                      ip_addr, &ip_addr_len, &pfx_len);
    CU_ASSERT_EQUAL(rc, -1);

    /* invalid IP version */
    payload[1] = 5;
    rc = masque_parse_address_assign(payload, sizeof(payload),
                                      &req_id, &ip_ver,
                                      ip_addr, &ip_addr_len, &pfx_len);
    CU_ASSERT_EQUAL(rc, -1);
}

/* ── Entry point ── */

void
xqc_test_masque(void)
{
    test_varint_len();
    test_varint_roundtrip();
    test_varint_buffer_underflow();
    test_udp_framing_roundtrip();
    test_udp_framing_errors();
    test_udp_mss();
    test_capsule_roundtrip();
    test_capsule_errors();
    test_address_assign_parse();
}
