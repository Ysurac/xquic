/**
 * @copyright Copyright (c) 2022, Alibaba Group Holding Limited
 *
 * MASQUE protocol helpers implementation.
 * See xqc_h3_ext_masque.h for API documentation.
 */

#include "src/http3/xqc_h3_ext_masque.h"
#include "src/common/utils/vint/xqc_variable_len_int.h"

#include <string.h>


/* ── HTTP Datagram framing (RFC 9297 + RFC 9298) ── */

xqc_int_t
xqc_h3_ext_masque_frame_udp(uint8_t *out, size_t outlen, size_t *written,
                             uint64_t stream_id,
                             const uint8_t *payload, size_t paylen)
{
    if (out == NULL || written == NULL) {
        return -XQC_EPARAM;
    }
    if (paylen > 0 && payload == NULL) {
        return -XQC_EPARAM;
    }

    *written = 0;

    uint64_t quarter_id = stream_id / 4;
    size_t qid_len = xqc_put_varint_len(quarter_id);
    size_t ctx_len = 1;  /* context_id = 0 → 1 byte varint */
    size_t total = qid_len + ctx_len + paylen;

    if (outlen < total) {
        return -XQC_ENOBUF;
    }

    uint8_t *p = out;
    p = xqc_put_varint(p, quarter_id);
    *p++ = 0x00;  /* context_id = 0 */
    if (paylen > 0) {
        memcpy(p, payload, paylen);
    }

    *written = total;
    return XQC_OK;
}

xqc_int_t
xqc_h3_ext_masque_unframe_udp(const uint8_t *buf, size_t buflen,
                               uint64_t *quarter_stream_id, uint64_t *context_id,
                               const uint8_t **payload, size_t *payload_len)
{
    if (buf == NULL || quarter_stream_id == NULL || context_id == NULL
        || payload == NULL || payload_len == NULL)
    {
        return -XQC_EPARAM;
    }

    const uint8_t *p = buf;
    const uint8_t *end = buf + buflen;
    int n;

    n = xqc_vint_read(p, end, quarter_stream_id);
    if (n < 0) {
        return -XQC_EPARAM;
    }
    p += n;

    n = xqc_vint_read(p, end, context_id);
    if (n < 0) {
        return -XQC_EPARAM;
    }
    p += n;

    *payload = p;
    *payload_len = (size_t)(end - p);
    return XQC_OK;
}

size_t
xqc_h3_ext_masque_udp_mss(size_t dgram_mss, uint64_t stream_id)
{
    uint64_t quarter_id = stream_id / 4;
    size_t overhead = xqc_put_varint_len(quarter_id) + 1; /* +1 for context_id=0 */
    if (dgram_mss <= overhead) {
        return 0;
    }
    return dgram_mss - overhead;
}


/* ── Capsule Protocol (RFC 9297 Section 3.2) ── */

xqc_int_t
xqc_h3_ext_capsule_encode(uint8_t *out, size_t outlen, size_t *written,
                           uint64_t type,
                           const uint8_t *payload, size_t paylen)
{
    if (out == NULL || written == NULL) {
        return -XQC_EPARAM;
    }
    if (paylen > 0 && payload == NULL) {
        return -XQC_EPARAM;
    }

    *written = 0;

    size_t type_len = xqc_put_varint_len(type);
    size_t len_len = xqc_put_varint_len((uint64_t)paylen);
    size_t total = type_len + len_len + paylen;

    if (outlen < total) {
        return -XQC_ENOBUF;
    }

    uint8_t *p = out;
    p = xqc_put_varint(p, type);
    p = xqc_put_varint(p, (uint64_t)paylen);
    if (paylen > 0) {
        memcpy(p, payload, paylen);
    }

    *written = total;
    return XQC_OK;
}

xqc_int_t
xqc_h3_ext_capsule_decode(const uint8_t *buf, size_t buflen,
                           uint64_t *type,
                           const uint8_t **payload, size_t *payload_len,
                           size_t *bytes_consumed)
{
    if (buf == NULL || type == NULL || payload == NULL
        || payload_len == NULL || bytes_consumed == NULL)
    {
        return -XQC_EPARAM;
    }

    const uint8_t *p = buf;
    const uint8_t *end = buf + buflen;
    int n;

    n = xqc_vint_read(p, end, type);
    if (n < 0) {
        return -XQC_EPARAM;
    }
    p += n;

    uint64_t len64;
    n = xqc_vint_read(p, end, &len64);
    if (n < 0) {
        return -XQC_EPARAM;
    }
    p += n;

    *payload = p;
    *payload_len = (size_t)len64;
    *bytes_consumed = (size_t)(p - buf) + (size_t)len64;
    return XQC_OK;
}


/* ── CONNECT-IP capsule types (RFC 9484) ── */

xqc_int_t
xqc_h3_ext_connectip_parse_address_assign(const uint8_t *payload, size_t paylen,
                                           uint64_t *request_id,
                                           uint8_t *ip_version,
                                           uint8_t *ip_addr, size_t *ip_addr_len,
                                           uint8_t *prefix_len)
{
    if (payload == NULL || request_id == NULL || ip_version == NULL
        || ip_addr == NULL || ip_addr_len == NULL || prefix_len == NULL)
    {
        return -XQC_EPARAM;
    }

    const uint8_t *p = payload;
    const uint8_t *end = payload + paylen;
    int n;

    n = xqc_vint_read(p, end, request_id);
    if (n < 0) {
        return -XQC_EPARAM;
    }
    p += n;

    if (p >= end) {
        return -XQC_EPARAM;
    }
    *ip_version = *p++;

    size_t addr_len;
    if (*ip_version == 4) {
        addr_len = 4;
    } else if (*ip_version == 6) {
        addr_len = 16;
    } else {
        return -XQC_EPARAM;
    }

    if (p + addr_len + 1 > end) {
        return -XQC_EPARAM;
    }

    memcpy(ip_addr, p, addr_len);
    *ip_addr_len = addr_len;
    p += addr_len;

    *prefix_len = *p;
    return XQC_OK;
}

xqc_int_t
xqc_h3_ext_connectip_build_address_request(uint8_t *buf, size_t buflen,
                                            size_t *written,
                                            uint64_t request_id,
                                            uint8_t ip_version,
                                            const uint8_t *ip_addr,
                                            uint8_t prefix_len)
{
    if (buf == NULL || written == NULL || ip_addr == NULL) {
        return -XQC_EPARAM;
    }

    *written = 0;

    size_t addr_len;
    if (ip_version == 4) {
        addr_len = 4;
    } else if (ip_version == 6) {
        addr_len = 16;
    } else {
        return -XQC_EPARAM;
    }

    size_t rid_len = xqc_put_varint_len(request_id);
    size_t total = rid_len + 1 + addr_len + 1; /* rid + ip_ver + addr + pfx */

    if (buflen < total) {
        return -XQC_ENOBUF;
    }

    uint8_t *p = buf;
    p = xqc_put_varint(p, request_id);
    *p++ = ip_version;
    memcpy(p, ip_addr, addr_len);
    p += addr_len;
    *p++ = prefix_len;

    *written = (size_t)(p - buf);
    return XQC_OK;
}

xqc_int_t
xqc_h3_ext_connectip_parse_route_advertisement(const uint8_t *payload,
                                                size_t paylen,
                                                uint8_t *ip_version,
                                                uint8_t *start_ip,
                                                uint8_t *end_ip,
                                                size_t *ip_addr_len,
                                                uint8_t *ip_protocol,
                                                size_t *bytes_consumed)
{
    if (payload == NULL || ip_version == NULL || start_ip == NULL
        || end_ip == NULL || ip_addr_len == NULL || ip_protocol == NULL
        || bytes_consumed == NULL)
    {
        return -XQC_EPARAM;
    }

    const uint8_t *p = payload;
    const uint8_t *end = payload + paylen;

    if (p >= end) {
        return -XQC_EPARAM;
    }
    *ip_version = *p++;

    size_t addr_len;
    if (*ip_version == 4) {
        addr_len = 4;
    } else if (*ip_version == 6) {
        addr_len = 16;
    } else {
        return -XQC_EPARAM;
    }

    /* Need: start_ip + end_ip + ip_protocol */
    if (p + addr_len + addr_len + 1 > end) {
        return -XQC_EPARAM;
    }

    memcpy(start_ip, p, addr_len);
    p += addr_len;
    memcpy(end_ip, p, addr_len);
    p += addr_len;
    *ip_addr_len = addr_len;
    *ip_protocol = *p++;

    *bytes_consumed = (size_t)(p - payload);
    return XQC_OK;
}
