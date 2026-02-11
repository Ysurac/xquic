/**
 * @copyright Copyright (c) 2022, Alibaba Group Holding Limited
 *
 * MASQUE CONNECT-UDP test client (RFC 9298).
 * Connects to a MASQUE proxy via H3, establishes a CONNECT-UDP tunnel,
 * and sends/receives UDP datagrams through it.
 *
 * Usage:
 *   masque_client -a <proxy_addr> -p <proxy_port> \
 *                 -T <target_host> -P <target_port> \
 *                 [-d <data_to_send>] [-k] [-l <log_level>]
 *
 * Interop target: quic-go/masque-go proxy
 */

#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <signal.h>
#include <fcntl.h>
#include <time.h>
#include <inttypes.h>

#include <event2/event.h>

#include <xquic/xquic.h>
#include <xquic/xquic_typedef.h>
#include <xquic/xqc_http3.h>

#include "platform.h"
#include "masque_common.h"

extern xqc_usec_t xqc_now(void);

#ifndef XQC_SYS_WINDOWS
#include <unistd.h>
#include <sys/socket.h>
#include <netdb.h>
#include <getopt.h>
#endif

/* ──────────────────────────────────────────────────────────── */
/*  Constants                                                   */
/* ──────────────────────────────────────────────────────────── */

#define MASQUE_PACKET_BUF_LEN       1600
#define MASQUE_MAX_HEADER_CNT       16
#define MASQUE_LOG_BUF_LEN          2048
#define MASQUE_DEFAULT_LOG_LEVEL    XQC_LOG_DEBUG

/* ──────────────────────────────────────────────────────────── */
/*  Data structures                                             */
/* ──────────────────────────────────────────────────────────── */

typedef struct masque_ctx_s         masque_ctx_t;
typedef struct masque_conn_s        masque_conn_t;
typedef struct masque_tunnel_s      masque_tunnel_t;

struct masque_ctx_s {
    xqc_engine_t           *engine;
    struct event_base      *eb;
    struct event           *ev_engine;     /* timer for xqc_engine_main_logic */
    int                     log_fd;
};

struct masque_conn_s {
    masque_ctx_t           *ctx;
    xqc_cid_t              cid;

    int                     fd;            /* UDP socket to proxy */
    struct event           *ev_socket;     /* read event on fd */
    struct event           *ev_timeout;    /* idle timeout */

    struct sockaddr_in6     local_addr;
    socklen_t               local_addrlen;
    struct sockaddr_in6     peer_addr;
    socklen_t               peer_addrlen;

    xqc_h3_conn_t         *h3_conn;

    size_t                  dgram_mss;     /* datagram MSS from H3 ext */

    masque_tunnel_t        *tunnel;        /* single tunnel for now */

    int                     connected;     /* H3 handshake done */
    int                     settings_ok;   /* peer SETTINGS received */
};

struct masque_tunnel_s {
    masque_conn_t          *conn;
    xqc_h3_request_t      *h3_request;
    xqc_stream_id_t         stream_id;

    char                    target_host[256];
    int                     target_port;

    int                     headers_sent;
    int                     response_ok;   /* got 2xx from proxy */

    /* payload to send */
    const char             *send_data;
    size_t                  send_data_len;
    int                     send_done;

    /* received data */
    uint8_t                 recv_buf[65536];
    size_t                  recv_len;
    int                     recv_done;
};

/* ──────────────────────────────────────────────────────────── */
/*  Globals (command-line args)                                 */
/* ──────────────────────────────────────────────────────────── */

static char     g_proxy_addr[256]       = "127.0.0.1";
static int      g_proxy_port            = 4443;
static char     g_target_host[256]      = "127.0.0.1";
static int      g_target_port           = 9999;
static char     g_send_data[4096]       = "Hello MASQUE!";
static int      g_no_crypto             = 0;
static int      g_log_level             = MASQUE_DEFAULT_LOG_LEVEL;
static char     g_proxy_host[256]       = "";  /* SNI host, defaults to proxy_addr */
static char     g_uri_path[1024]        = "";  /* override .well-known URI template */
static int      g_allow_self_signed     = 0;   /* -S: accept self-signed certs */

/* ──────────────────────────────────────────────────────────── */
/*  Forward declarations                                        */
/* ──────────────────────────────────────────────────────────── */

static void masque_engine_cb(int fd, short what, void *arg);
static void masque_socket_read_cb(int fd, short what, void *arg);
static void masque_timeout_cb(int fd, short what, void *arg);

/* ──────────────────────────────────────────────────────────── */
/*  Logging                                                     */
/* ──────────────────────────────────────────────────────────── */

static void
masque_write_log(xqc_log_level_t lvl, const void *buf, size_t sz, void *eng_user_data)
{
    masque_ctx_t *ctx = (masque_ctx_t *)eng_user_data;
    if (ctx->log_fd >= 0) {
        int unused __attribute__((unused));
        unused = write(ctx->log_fd, buf, sz);
        unused = write(ctx->log_fd, "\n", 1);
    }
}

/* ──────────────────────────────────────────────────────────── */
/*  Engine timer callback                                       */
/* ──────────────────────────────────────────────────────────── */

static void
masque_set_event_timer(xqc_usec_t wake_after, void *eng_user_data)
{
    masque_ctx_t *ctx = (masque_ctx_t *)eng_user_data;
    struct timeval tv;
    tv.tv_sec  = (long)(wake_after / 1000000);
    tv.tv_usec = (long)(wake_after % 1000000);
    event_add(ctx->ev_engine, &tv);
}

static void
masque_engine_cb(int fd, short what, void *arg)
{
    masque_ctx_t *ctx = (masque_ctx_t *)arg;
    xqc_engine_main_logic(ctx->engine);
}

/* ──────────────────────────────────────────────────────────── */
/*  Transport write callbacks                                   */
/* ──────────────────────────────────────────────────────────── */

static ssize_t
masque_write_socket(const unsigned char *buf, size_t size,
                    const struct sockaddr *peer_addr, socklen_t peer_addrlen,
                    void *conn_user_data)
{
    masque_conn_t *conn = (masque_conn_t *)conn_user_data;
    ssize_t res;

    do {
        set_sys_errno(0);
        res = sendto(conn->fd, buf, size, 0, peer_addr, peer_addrlen);
        if (res < 0) {
            if (get_sys_errno() == EAGAIN) {
                return XQC_SOCKET_EAGAIN;
            }
            printf("[masque] write_socket error: %s\n", strerror(get_sys_errno()));
        }
    } while (res < 0 && get_sys_errno() == EINTR);

    return res;
}

static ssize_t
masque_write_socket_ex(uint64_t path_id, const unsigned char *buf, size_t size,
                       const struct sockaddr *peer_addr, socklen_t peer_addrlen,
                       void *conn_user_data)
{
    /* single-path: ignore path_id */
    return masque_write_socket(buf, size, peer_addr, peer_addrlen, conn_user_data);
}

/* ──────────────────────────────────────────────────────────── */
/*  Transport misc callbacks (stubs)                            */
/* ──────────────────────────────────────────────────────────── */

static void
masque_save_token(const unsigned char *token, unsigned token_len, void *user)
{
    /* no-op for test client */
}

static void
masque_save_session(const char *data, size_t len, void *user)
{
    /* no-op */
}

static void
masque_save_tp(const char *data, size_t len, void *user)
{
    /* no-op */
}

/* ──────────────────────────────────────────────────────────── */
/*  Tunnel: send Extended CONNECT headers                       */
/* ──────────────────────────────────────────────────────────── */

static int
masque_tunnel_send_headers(masque_tunnel_t *tun)
{
    if (tun->headers_sent) {
        return 0;
    }

    /* Build URI path: /.well-known/masque/udp/{host}/{port}/ */
    char path[1024];
    if (g_uri_path[0] != '\0') {
        snprintf(path, sizeof(path), "%s", g_uri_path);
    } else {
        snprintf(path, sizeof(path), "/.well-known/masque/udp/%s/%d/",
                 tun->target_host, tun->target_port);
    }

    /* Build :authority */
    char authority[512];
    snprintf(authority, sizeof(authority), "%s:%d",
             g_proxy_host[0] ? g_proxy_host : g_proxy_addr, g_proxy_port);

    xqc_http_header_t headers[] = {
        { .name  = {.iov_base = ":method",    .iov_len = 7},
          .value = {.iov_base = "CONNECT",    .iov_len = 7},
          .flags = 0 },
        { .name  = {.iov_base = ":protocol",  .iov_len = 9},
          .value = {.iov_base = "connect-udp", .iov_len = 11},
          .flags = 0 },
        { .name  = {.iov_base = ":scheme",    .iov_len = 7},
          .value = {.iov_base = "https",       .iov_len = 5},
          .flags = 0 },
        { .name  = {.iov_base = ":authority",  .iov_len = 10},
          .value = {.iov_base = authority,     .iov_len = strlen(authority)},
          .flags = 0 },
        { .name  = {.iov_base = ":path",      .iov_len = 5},
          .value = {.iov_base = path,          .iov_len = strlen(path)},
          .flags = 0 },
        { .name  = {.iov_base = "capsule-protocol", .iov_len = 16},
          .value = {.iov_base = "?1",                .iov_len = 2},
          .flags = 0 },
    };

    xqc_http_headers_t hdrs = {
        .headers  = headers,
        .count    = sizeof(headers) / sizeof(headers[0]),
        .capacity = sizeof(headers) / sizeof(headers[0]),
    };

    printf("[masque] Sending Extended CONNECT: %s %s %s\n",
           "CONNECT", path, authority);

    /* fin=0: keep the stream open for capsules/datagrams */
    ssize_t ret = xqc_h3_request_send_headers(tun->h3_request, &hdrs, 0);
    if (ret < 0) {
        printf("[masque] send_headers error: %zd\n", ret);
        return -1;
    }

    tun->stream_id = xqc_h3_stream_id(tun->h3_request);
    tun->headers_sent = 1;

    printf("[masque] Headers sent, stream_id=%" PRIu64
           ", quarter_id=%" PRIu64 "\n",
           tun->stream_id, tun->stream_id / 4);

    return 0;
}

/* ──────────────────────────────────────────────────────────── */
/*  Tunnel: send UDP payload via HTTP Datagram                  */
/* ──────────────────────────────────────────────────────────── */

static int
masque_tunnel_send_dgram(masque_tunnel_t *tun, const uint8_t *data, size_t len)
{
    masque_conn_t *conn = tun->conn;

    if (!tun->response_ok) {
        printf("[masque] Cannot send datagram: tunnel not established\n");
        return -1;
    }

    /* Frame the UDP payload with quarter-stream-ID + context_id=0 */
    uint8_t framed[65536];
    size_t framed_len = masque_frame_udp_datagram(
        framed, sizeof(framed), tun->stream_id, data, len);
    if (framed_len == 0) {
        printf("[masque] Failed to frame datagram (too large?)\n");
        return -1;
    }

    uint64_t dgram_id = 0;
    xqc_int_t ret = xqc_h3_ext_datagram_send(
        conn->h3_conn, framed, framed_len, &dgram_id, XQC_DATA_QOS_HIGH);
    if (ret < 0) {
        if (ret == -XQC_EAGAIN) {
            printf("[masque] datagram send EAGAIN, will retry\n");
            return -XQC_EAGAIN;
        }
        printf("[masque] datagram send error: %d\n", ret);
        return ret;
    }

    printf("[masque] Sent datagram: %zu bytes payload, dgram_id=%" PRIu64 "\n",
           len, dgram_id);
    return 0;
}

/* ──────────────────────────────────────────────────────────── */
/*  H3 datagram callbacks                                       */
/* ──────────────────────────────────────────────────────────── */

static void
masque_dgram_read_cb(xqc_h3_conn_t *h3c, const void *data, size_t data_len,
                     void *user_data, uint64_t recv_time)
{
    masque_conn_t *conn = (masque_conn_t *)user_data;
    masque_tunnel_t *tun = conn->tunnel;

    if (tun == NULL) {
        printf("[masque] dgram_read: no tunnel\n");
        return;
    }

    /* Unframe: [quarter-stream-ID] [context_id] [payload] */
    uint64_t qsid = 0, ctx_id = 0;
    size_t pay_off = 0, pay_len = 0;
    if (masque_unframe_udp_datagram(data, data_len, &qsid, &ctx_id,
                                    &pay_off, &pay_len) < 0) {
        printf("[masque] dgram_read: failed to unframe datagram\n");
        return;
    }

    /* Verify quarter-stream-ID matches our tunnel */
    uint64_t expected_qsid = tun->stream_id / 4;
    if (qsid != expected_qsid) {
        printf("[masque] dgram_read: unexpected quarter_stream_id=%" PRIu64
               " (expected %" PRIu64 ")\n", qsid, expected_qsid);
        return;
    }

    const uint8_t *payload = (const uint8_t *)data + pay_off;

    printf("[masque] Received datagram: %zu bytes payload, ctx_id=%" PRIu64 "\n",
           pay_len, ctx_id);

    /* Store received data */
    if (tun->recv_len + pay_len <= sizeof(tun->recv_buf)) {
        memcpy(tun->recv_buf + tun->recv_len, payload, pay_len);
        tun->recv_len += pay_len;
    }

    /* Print as string if printable */
    if (pay_len > 0 && pay_len < 4096) {
        printf("[masque] Payload: %.*s\n", (int)pay_len, payload);
    }

    tun->recv_done = 1;

    /* For the test: after receiving a response, close the connection */
    printf("[masque] Echo received, closing tunnel\n");
    xqc_h3_request_close(tun->h3_request);
    xqc_h3_conn_close(conn->ctx->engine, &conn->cid);
}

static void
masque_dgram_write_cb(xqc_h3_conn_t *h3c, void *user_data)
{
    masque_conn_t *conn = (masque_conn_t *)user_data;
    masque_tunnel_t *tun = conn->tunnel;

    if (tun == NULL || tun->send_done) {
        return;
    }

    if (tun->response_ok && !tun->send_done) {
        printf("[masque] dgram_write: tunnel ready, sending data\n");
        int ret = masque_tunnel_send_dgram(tun,
            (const uint8_t *)tun->send_data, tun->send_data_len);
        if (ret == 0) {
            tun->send_done = 1;
        }
    }
}

static void
masque_dgram_mss_cb(xqc_h3_conn_t *h3c, size_t mss, void *user_data)
{
    masque_conn_t *conn = (masque_conn_t *)user_data;
    conn->dgram_mss = mss;
    printf("[masque] Datagram MSS updated: %zu\n", mss);

    if (conn->tunnel) {
        size_t udp_mss = masque_udp_mss(mss, conn->tunnel->stream_id);
        printf("[masque] Effective UDP MSS: %zu\n", udp_mss);
    }
}

static void
masque_dgram_acked_cb(xqc_h3_conn_t *h3c, uint64_t dgram_id, void *user_data)
{
    printf("[masque] Datagram acked: dgram_id=%" PRIu64 "\n", dgram_id);
}

static int
masque_dgram_lost_cb(xqc_h3_conn_t *h3c, uint64_t dgram_id, void *user_data)
{
    printf("[masque] Datagram lost: dgram_id=%" PRIu64 "\n", dgram_id);
    return 0;  /* don't retransmit */
}

/* ──────────────────────────────────────────────────────────── */
/*  H3 connection callbacks                                     */
/* ──────────────────────────────────────────────────────────── */

static int
masque_h3_conn_create_cb(xqc_h3_conn_t *h3c, const xqc_cid_t *cid,
                         void *user_data)
{
    masque_conn_t *conn = (masque_conn_t *)user_data;
    conn->h3_conn = h3c;

    /* Set datagram user_data to conn so dgram callbacks can find it */
    xqc_h3_ext_datagram_set_user_data(h3c, conn);

    printf("[masque] H3 connection created\n");
    return 0;
}

static int
masque_h3_conn_close_cb(xqc_h3_conn_t *h3c, const xqc_cid_t *cid,
                        void *user_data)
{
    masque_conn_t *conn = (masque_conn_t *)user_data;
    printf("[masque] H3 connection closed\n");

    /* Stop event loop */
    event_base_loopbreak(conn->ctx->eb);
    return 0;
}

static void
masque_h3_handshake_finished_cb(xqc_h3_conn_t *h3c, void *user_data)
{
    masque_conn_t *conn = (masque_conn_t *)user_data;
    conn->connected = 1;
    printf("[masque] H3 handshake finished\n");

    /* Now open the CONNECT-UDP tunnel */
    masque_tunnel_t *tun = conn->tunnel;
    if (tun && !tun->headers_sent) {
        /* Create H3 request for the tunnel */
        tun->h3_request = xqc_h3_request_create(
            conn->ctx->engine, &conn->cid, NULL, tun);
        if (tun->h3_request == NULL) {
            printf("[masque] Failed to create H3 request\n");
            return;
        }

        masque_tunnel_send_headers(tun);
    }
}

static void
masque_h3_conn_init_settings_cb(xqc_h3_conn_t *h3c,
                                xqc_h3_conn_settings_t *settings,
                                void *user_data)
{
    /* Enable Extended CONNECT and HTTP Datagrams in our SETTINGS */
    settings->enable_connect_protocol = 1;
    settings->h3_datagram = 1;

    printf("[masque] Settings initialized: enable_connect_protocol=1, h3_datagram=1\n");
}

/* ──────────────────────────────────────────────────────────── */
/*  H3 request callbacks                                        */
/* ──────────────────────────────────────────────────────────── */

static int
masque_h3_request_close_cb(xqc_h3_request_t *h3r, void *user_data)
{
    masque_tunnel_t *tun = (masque_tunnel_t *)user_data;
    printf("[masque] H3 request closed (stream_id=%" PRIu64 ")\n",
           tun->stream_id);
    return 0;
}

static int
masque_h3_request_read_cb(xqc_h3_request_t *h3r,
                          xqc_request_notify_flag_t flag,
                          void *user_data)
{
    masque_tunnel_t *tun = (masque_tunnel_t *)user_data;
    masque_conn_t *conn = tun->conn;

    if (flag & XQC_REQ_NOTIFY_READ_HEADER) {
        uint8_t fin = 0;
        xqc_http_headers_t *headers = xqc_h3_request_recv_headers(h3r, &fin);
        if (headers == NULL) {
            printf("[masque] Failed to read response headers\n");
            return -1;
        }

        printf("[masque] Response headers (%zu):\n", headers->count);
        for (size_t i = 0; i < headers->count; i++) {
            printf("  %.*s: %.*s\n",
                   (int)headers->headers[i].name.iov_len,
                   (char *)headers->headers[i].name.iov_base,
                   (int)headers->headers[i].value.iov_len,
                   (char *)headers->headers[i].value.iov_base);

            /* Check for 2xx status */
            if (headers->headers[i].name.iov_len == 7 &&
                memcmp(headers->headers[i].name.iov_base, ":status", 7) == 0) {
                int status = atoi((const char *)headers->headers[i].value.iov_base);
                if (status >= 200 && status < 300) {
                    tun->response_ok = 1;
                    printf("[masque] CONNECT-UDP tunnel established! (status=%d)\n",
                           status);

                    /* Send the test payload */
                    if (!tun->send_done && tun->send_data && tun->send_data_len > 0) {
                        int ret = masque_tunnel_send_dgram(tun,
                            (const uint8_t *)tun->send_data, tun->send_data_len);
                        if (ret == 0) {
                            tun->send_done = 1;
                        }
                    }
                } else {
                    printf("[masque] Proxy rejected CONNECT-UDP: status=%d\n", status);
                }
            }
        }
    }

    if (flag & XQC_REQ_NOTIFY_READ_BODY) {
        /* Capsule data on the DATA stream (fallback path, not primary for CONNECT-UDP) */
        uint8_t body_buf[4096];
        uint8_t fin = 0;
        ssize_t n = xqc_h3_request_recv_body(h3r, body_buf, sizeof(body_buf), &fin);
        if (n > 0) {
            printf("[masque] Received %zd bytes on DATA stream (capsule?)\n", n);
        }
    }

    return 0;
}

static int
masque_h3_request_write_cb(xqc_h3_request_t *h3r, void *user_data)
{
    /* Write callback - can send more data if needed */
    return 0;
}

/* ──────────────────────────────────────────────────────────── */
/*  Socket I/O                                                  */
/* ──────────────────────────────────────────────────────────── */

static int
masque_create_socket(masque_conn_t *conn)
{
    int fd;
    int flags;

    fd = socket(conn->peer_addr.sin6_family, SOCK_DGRAM, 0);
    if (fd < 0) {
        printf("[masque] socket() error: %s\n", strerror(errno));
        return -1;
    }

    /* non-blocking */
    flags = fcntl(fd, F_GETFL, 0);
    fcntl(fd, F_SETFL, flags | O_NONBLOCK);

    /* connect to proxy so send() works */
    if (connect(fd, (struct sockaddr *)&conn->peer_addr, conn->peer_addrlen) < 0) {
        printf("[masque] connect() error: %s\n", strerror(errno));
        close(fd);
        return -1;
    }

    /* get local addr */
    conn->local_addrlen = sizeof(conn->local_addr);
    getsockname(fd, (struct sockaddr *)&conn->local_addr, &conn->local_addrlen);

    return fd;
}

static void
masque_socket_read_cb(int fd, short what, void *arg)
{
    masque_conn_t *conn = (masque_conn_t *)arg;
    unsigned char buf[MASQUE_PACKET_BUF_LEN];
    ssize_t recv_size;
    struct sockaddr_in6 from_addr;
    socklen_t from_len = sizeof(from_addr);

    do {
        recv_size = recvfrom(fd, buf, sizeof(buf), 0,
                             (struct sockaddr *)&from_addr, &from_len);
        if (recv_size < 0) {
            if (get_sys_errno() == EAGAIN) {
                break;
            }
            printf("[masque] recvfrom error: %s\n", strerror(get_sys_errno()));
            break;
        }

        if (recv_size == 0) {
            break;
        }

        xqc_int_t ret = xqc_engine_packet_process(
            conn->ctx->engine, buf, (size_t)recv_size,
            (struct sockaddr *)&conn->local_addr, conn->local_addrlen,
            (struct sockaddr *)&from_addr, from_len,
            (xqc_msec_t)xqc_now(), conn);
        if (ret != XQC_OK) {
            printf("[masque] packet_process error: %d\n", ret);
            return;
        }
    } while (recv_size > 0);

    xqc_engine_finish_recv(conn->ctx->engine);
}

static void
masque_timeout_cb(int fd, short what, void *arg)
{
    masque_conn_t *conn = (masque_conn_t *)arg;
    printf("[masque] Connection timed out\n");
    event_base_loopbreak(conn->ctx->eb);
}

/* ──────────────────────────────────────────────────────────── */
/*  DNS resolution helper                                       */
/* ──────────────────────────────────────────────────────────── */

static int
masque_resolve(const char *host, int port, struct sockaddr_in6 *addr, socklen_t *addrlen)
{
    struct addrinfo hints = {0}, *res = NULL;
    char port_str[16];
    snprintf(port_str, sizeof(port_str), "%d", port);

    hints.ai_family   = AF_UNSPEC;
    hints.ai_socktype = SOCK_DGRAM;

    int rc = getaddrinfo(host, port_str, &hints, &res);
    if (rc != 0 || res == NULL) {
        printf("[masque] DNS resolution failed for %s:%d: %s\n",
               host, port, gai_strerror(rc));
        return -1;
    }

    memset(addr, 0, sizeof(*addr));

    if (res->ai_family == AF_INET) {
        /* Map IPv4 to IPv6-mapped address for uniform handling */
        struct sockaddr_in *v4 = (struct sockaddr_in *)res->ai_addr;
        addr->sin6_family = AF_INET6;
        addr->sin6_port = v4->sin_port;
        /* ::ffff:a.b.c.d */
        addr->sin6_addr.s6_addr[10] = 0xFF;
        addr->sin6_addr.s6_addr[11] = 0xFF;
        memcpy(&addr->sin6_addr.s6_addr[12], &v4->sin_addr, 4);
        *addrlen = sizeof(struct sockaddr_in6);
    } else {
        memcpy(addr, res->ai_addr, res->ai_addrlen);
        *addrlen = res->ai_addrlen;
    }

    freeaddrinfo(res);
    return 0;
}

/* ──────────────────────────────────────────────────────────── */
/*  Main                                                        */
/* ──────────────────────────────────────────────────────────── */

static void
masque_usage(const char *prog)
{
    printf("Usage: %s [options]\n"
           "  -a <addr>    Proxy address (default: 127.0.0.1)\n"
           "  -p <port>    Proxy port (default: 4443)\n"
           "  -H <host>    Proxy SNI host (default: same as addr)\n"
           "  -T <host>    Target host for CONNECT-UDP (default: 127.0.0.1)\n"
           "  -P <port>    Target port for CONNECT-UDP (default: 9999)\n"
           "  -d <data>    Data to send through tunnel (default: 'Hello MASQUE!')\n"
           "  -U <path>    Override URI template path\n"
           "  -S           Allow self-signed certificates\n"
           "  -k           No encryption (testing only)\n"
           "  -l <level>   Log level 0-5 (default: %d)\n"
           "  -h           Show this help\n",
           prog, MASQUE_DEFAULT_LOG_LEVEL);
}

int
main(int argc, char *argv[])
{
    int opt;
    while ((opt = getopt(argc, argv, "a:p:H:T:P:d:U:Skl:h")) != -1) {
        switch (opt) {
        case 'a': strncpy(g_proxy_addr, optarg, sizeof(g_proxy_addr) - 1); break;
        case 'p': g_proxy_port = atoi(optarg); break;
        case 'H': strncpy(g_proxy_host, optarg, sizeof(g_proxy_host) - 1); break;
        case 'T': strncpy(g_target_host, optarg, sizeof(g_target_host) - 1); break;
        case 'P': g_target_port = atoi(optarg); break;
        case 'd': strncpy(g_send_data, optarg, sizeof(g_send_data) - 1); break;
        case 'U': strncpy(g_uri_path, optarg, sizeof(g_uri_path) - 1); break;
        case 'S': g_allow_self_signed = 1; break;
        case 'k': g_no_crypto = 1; break;
        case 'l': g_log_level = atoi(optarg); break;
        case 'h':
        default:
            masque_usage(argv[0]);
            return opt == 'h' ? 0 : 1;
        }
    }

    xqc_platform_init_env();
    signal(SIGPIPE, SIG_IGN);

    /* ── Allocate context ── */
    masque_ctx_t ctx = {0};
    ctx.log_fd = open("masque_client.log", O_WRONLY | O_CREAT | O_TRUNC, 0644);

    /* ── Event base ── */
    ctx.eb = event_base_new();
    if (ctx.eb == NULL) {
        printf("[masque] event_base_new failed\n");
        return 1;
    }

    /* ── Engine timer ── */
    ctx.ev_engine = event_new(ctx.eb, -1, 0, masque_engine_cb, &ctx);

    /* ── Engine callbacks ── */
    xqc_engine_callback_t engine_cbs = {
        .log_callbacks = {
            .xqc_log_write_err  = masque_write_log,
            .xqc_log_write_stat = masque_write_log,
        },
        .set_event_timer = masque_set_event_timer,
    };

    xqc_transport_callbacks_t transport_cbs = {
        .write_socket    = masque_write_socket,
        .write_socket_ex = masque_write_socket_ex,
        .save_token      = masque_save_token,
        .save_session_cb = masque_save_session,
        .save_tp_cb      = masque_save_tp,
    };

    /* ── Engine config ── */
    xqc_config_t engine_cfg;
    if (xqc_engine_get_default_config(&engine_cfg, XQC_ENGINE_CLIENT) != XQC_OK) {
        printf("[masque] get_default_config failed\n");
        return 1;
    }
    engine_cfg.cfg_log_level = g_log_level;

    /* ── TLS config ── */
    xqc_engine_ssl_config_t ssl_cfg = {0};
    ssl_cfg.ciphers = XQC_TLS_CIPHERS;
    ssl_cfg.groups  = XQC_TLS_GROUPS;

    /* ── Create engine ── */
    ctx.engine = xqc_engine_create(XQC_ENGINE_CLIENT, &engine_cfg,
                                   &ssl_cfg, &engine_cbs, &transport_cbs, &ctx);
    if (ctx.engine == NULL) {
        printf("[masque] xqc_engine_create failed\n");
        return 1;
    }

    /* ── H3 callbacks ── */
    xqc_h3_callbacks_t h3_cbs = {
        .h3c_cbs = {
            .h3_conn_create_notify     = masque_h3_conn_create_cb,
            .h3_conn_close_notify      = masque_h3_conn_close_cb,
            .h3_conn_handshake_finished = masque_h3_handshake_finished_cb,
            .h3_conn_init_settings     = masque_h3_conn_init_settings_cb,
        },
        .h3r_cbs = {
            .h3_request_close_notify   = masque_h3_request_close_cb,
            .h3_request_read_notify    = masque_h3_request_read_cb,
            .h3_request_write_notify   = masque_h3_request_write_cb,
        },
        .h3_ext_dgram_cbs = {
            .dgram_read_notify         = masque_dgram_read_cb,
            .dgram_write_notify        = masque_dgram_write_cb,
            .dgram_mss_updated_notify  = masque_dgram_mss_cb,
            .dgram_acked_notify        = masque_dgram_acked_cb,
            .dgram_lost_notify         = masque_dgram_lost_cb,
        },
    };

    if (xqc_h3_ctx_init(ctx.engine, &h3_cbs) != XQC_OK) {
        printf("[masque] xqc_h3_ctx_init failed\n");
        return 1;
    }

    /* ── Allocate connection ── */
    masque_conn_t conn = {0};
    conn.ctx = &ctx;

    /* Resolve proxy address */
    if (masque_resolve(g_proxy_addr, g_proxy_port,
                       &conn.peer_addr, &conn.peer_addrlen) < 0) {
        return 1;
    }

    /* Create socket */
    conn.fd = masque_create_socket(&conn);
    if (conn.fd < 0) {
        return 1;
    }

    /* Socket read event */
    conn.ev_socket = event_new(ctx.eb, conn.fd, EV_READ | EV_PERSIST,
                               masque_socket_read_cb, &conn);
    event_add(conn.ev_socket, NULL);

    /* Idle timeout (30 seconds) */
    conn.ev_timeout = event_new(ctx.eb, -1, 0, masque_timeout_cb, &conn);
    struct timeval tv_timeout = { .tv_sec = 30, .tv_usec = 0 };
    event_add(conn.ev_timeout, &tv_timeout);

    /* ── Allocate tunnel ── */
    masque_tunnel_t tunnel = {0};
    tunnel.conn = &conn;
    strncpy(tunnel.target_host, g_target_host, sizeof(tunnel.target_host) - 1);
    tunnel.target_port = g_target_port;
    tunnel.send_data = g_send_data;
    tunnel.send_data_len = strlen(g_send_data);
    conn.tunnel = &tunnel;

    /* ── Open H3 connection ── */
    xqc_conn_settings_t conn_settings = {0};
    conn_settings.proto_version = XQC_VERSION_V1;
    conn_settings.max_datagram_frame_size = 65535;

    xqc_conn_ssl_config_t conn_ssl_cfg = {0};
    if (g_allow_self_signed) {
        conn_ssl_cfg.cert_verify_flag = XQC_TLS_CERT_FLAG_NEED_VERIFY
                                      | XQC_TLS_CERT_FLAG_ALLOW_SELF_SIGNED;
    }

    const char *sni = g_proxy_host[0] ? g_proxy_host : g_proxy_addr;

    printf("[masque] Connecting to proxy %s:%d (SNI: %s)\n",
           g_proxy_addr, g_proxy_port, sni);
    printf("[masque] Target: %s:%d\n", g_target_host, g_target_port);

    const xqc_cid_t *cid = xqc_h3_connect(
        ctx.engine, &conn_settings, NULL, 0, sni, g_no_crypto,
        &conn_ssl_cfg, (struct sockaddr *)&conn.peer_addr, conn.peer_addrlen,
        &conn);
    if (cid == NULL) {
        printf("[masque] xqc_h3_connect failed\n");
        return 1;
    }
    memcpy(&conn.cid, cid, sizeof(xqc_cid_t));

    /* ── Run event loop ── */
    printf("[masque] Entering event loop...\n");
    event_base_dispatch(ctx.eb);

    /* ── Cleanup ── */
    printf("[masque] Event loop exited\n");

    if (tunnel.recv_done) {
        printf("[masque] SUCCESS: Received %zu bytes through tunnel\n", tunnel.recv_len);
    } else {
        printf("[masque] No data received through tunnel\n");
    }

    event_free(conn.ev_socket);
    event_free(conn.ev_timeout);
    close(conn.fd);

    xqc_engine_destroy(ctx.engine);
    event_free(ctx.ev_engine);
    event_base_free(ctx.eb);

    if (ctx.log_fd >= 0) {
        close(ctx.log_fd);
    }

    return tunnel.recv_done ? 0 : 1;
}
