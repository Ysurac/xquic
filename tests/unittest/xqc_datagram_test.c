/**
 * @copyright Copyright (c) 2022, Alibaba Group Holding Limited
 */

#include "xqc_datagram_test.h"
#include <CUnit/CUnit.h>
#include "src/transport/xqc_conn.h"
#include "src/transport/xqc_engine.h"
#include "src/transport/xqc_frame.h"
#include "src/transport/xqc_frame_parser.h"
#include "src/transport/xqc_packet_out.h"
#include "src/transport/xqc_packet_in.h"
#include "src/transport/xqc_multipath.h"
#include "src/transport/xqc_send_queue.h"
#include "src/transport/xqc_datagram.h"
#include "xqc_common_test.h"

void
xqc_test_receive_invalid_dgram()
{
    xqc_int_t ret;

    xqc_connection_t *conn = test_engine_connect();
    CU_ASSERT(conn != NULL);

    const unsigned char payload[100];

    xqc_packet_out_t *packet_out;
    packet_out = xqc_write_new_packet(conn, XQC_PTYPE_SHORT_HEADER);
    CU_ASSERT(packet_out != NULL);

    ret = xqc_gen_datagram_frame(packet_out, payload, (size_t)100);
    CU_ASSERT(ret == XQC_OK);

    xqc_packet_in_t pkt_in;
    pkt_in.pos = packet_out->po_payload;
    pkt_in.last = packet_out->po_buf + packet_out->po_used_size;
    conn->local_settings.max_datagram_frame_size = 0;

    ret = xqc_process_datagram_frame(conn, &pkt_in);
    CU_ASSERT(ret == -XQC_EPROTO);

    conn->local_settings.max_datagram_frame_size = 50;
    ret = xqc_process_datagram_frame(conn, &pkt_in);
    CU_ASSERT(ret == -XQC_EPROTO);

    conn->local_settings.max_datagram_frame_size = 120;
    ret = xqc_process_datagram_frame(conn, &pkt_in);
    CU_ASSERT(ret == XQC_OK);

    xqc_engine_destroy(conn->engine);
}

void
xqc_test_datagram_send_on_path()
{
    xqc_int_t ret;
    uint64_t dgram_id = 0;

    /* 1. NULL connection */
    ret = xqc_datagram_send_on_path(NULL, "test", 4, &dgram_id,
                                     XQC_DATA_QOS_HIGH, 0);
    CU_ASSERT_EQUAL(ret, -XQC_EPARAM);

    /* 2. NULL data with non-zero length */
    xqc_connection_t *conn = test_engine_connect();
    CU_ASSERT(conn != NULL);
    ret = xqc_datagram_send_on_path(conn, NULL, 100, &dgram_id,
                                     XQC_DATA_QOS_HIGH, 0);
    CU_ASSERT_EQUAL(ret, -XQC_EPARAM);

    /* 3. Invalid path_id (path not found) —
     *    test_engine_connect creates a conn but no extra paths,
     *    so path_id=999 should not exist. */
    conn->conn_flag |= XQC_CONN_FLAG_CAN_SEND_1RTT;
    conn->remote_settings.max_datagram_frame_size = 1200;
    conn->dgram_mss = 1200;
    ret = xqc_datagram_send_on_path(conn, "test", 4, &dgram_id,
                                     XQC_DATA_QOS_HIGH, 999);
    CU_ASSERT_EQUAL(ret, -XQC_EMP_PATH_NOT_FOUND);

    /* 4. 1RTT not established — should return EAGAIN */
    conn->conn_flag &= ~XQC_CONN_FLAG_CAN_SEND_1RTT;
    ret = xqc_datagram_send_on_path(conn, "test", 4, &dgram_id,
                                     XQC_DATA_QOS_HIGH, 0);
    /* path 0 exists (initial path) but 1RTT not ready */
    CU_ASSERT(ret == -XQC_EMP_PATH_NOT_FOUND || ret == -XQC_EAGAIN);

    xqc_engine_destroy(conn->engine);
}

void
xqc_test_datagram_frame_path_pinning()
{
    xqc_connection_t *conn = test_engine_connect();
    CU_ASSERT(conn != NULL);

    conn->conn_flag |= XQC_CONN_FLAG_CAN_SEND_1RTT;
    conn->remote_settings.max_datagram_frame_size = 1200;
    conn->dgram_mss = 1200;

    const unsigned char data[] = "path-pin-test";
    uint64_t dgram_id = 0;
    int ret;

    /* Test 1: pin_to_path=FALSE — no path flag should be set */
    ret = xqc_write_datagram_frame_to_packet(
        conn, XQC_PTYPE_SHORT_HEADER,
        data, sizeof(data), &dgram_id, XQC_FALSE,
        XQC_DATA_QOS_HIGH, 0, XQC_FALSE);
    CU_ASSERT_EQUAL(ret, XQC_OK);

    /* Find the packet that was just created (last in send queue) */
    xqc_packet_out_t *po;
    xqc_list_head_t *pos;
    xqc_packet_out_t *last_po = NULL;
    xqc_list_for_each(pos, &conn->conn_send_queue->sndq_send_packets) {
        po = xqc_list_entry(pos, xqc_packet_out_t, po_list);
        last_po = po;
    }
    CU_ASSERT(last_po != NULL);
    if (last_po) {
        CU_ASSERT((last_po->po_path_flag & XQC_PATH_SPECIFIED_BY_DATAGRAM) == 0);
    }

    /* Test 2: pin_to_path=TRUE — flag and path_id should be set */
    uint64_t target_path_id = 42;
    ret = xqc_write_datagram_frame_to_packet(
        conn, XQC_PTYPE_SHORT_HEADER,
        data, sizeof(data), &dgram_id, XQC_FALSE,
        XQC_DATA_QOS_HIGH, target_path_id, XQC_TRUE);
    CU_ASSERT_EQUAL(ret, XQC_OK);

    /* Find the newest packet */
    last_po = NULL;
    xqc_list_for_each(pos, &conn->conn_send_queue->sndq_send_packets) {
        po = xqc_list_entry(pos, xqc_packet_out_t, po_list);
        last_po = po;
    }
    CU_ASSERT(last_po != NULL);
    if (last_po) {
        CU_ASSERT(last_po->po_path_flag & XQC_PATH_SPECIFIED_BY_DATAGRAM);
        CU_ASSERT_EQUAL(last_po->po_path_id, target_path_id);
    }

    xqc_engine_destroy(conn->engine);
}


static int xqc_test_dgram_write_notified;

static void
xqc_test_dgram_write_notify(xqc_connection_t *conn, void *user_data)
{
    xqc_test_dgram_write_notified++;
}

/*
 * max_dgram_unsent_packets: a datagram write is refused once that many
 * packets wait unsent, and the writer is woken only after half of them
 * have gone. The flush is deferred (TICKING + defer_send_flush) so the
 * send does not run the engine, which would drain the queue.
 */
void
xqc_test_datagram_unsent_cap()
{
    const uint32_t cap = 16;
    static unsigned char data[1000];
    uint64_t dgram_id = 0;
    xqc_int_t ret = XQC_OK;
    int i;

    xqc_connection_t *conn = test_engine_connect();
    CU_ASSERT_FATAL(conn != NULL);

    conn->conn_flag |= XQC_CONN_FLAG_CAN_SEND_1RTT | XQC_CONN_FLAG_TICKING;
    conn->conn_settings.defer_send_flush = 1;
    conn->conn_settings.max_dgram_unsent_packets = cap;
    conn->remote_settings.max_datagram_frame_size = 1200;
    conn->dgram_mss = 1200;

    for (i = 0; i < 4 * (int)cap; i++) {
        ret = xqc_datagram_send(conn, data, sizeof(data), &dgram_id, XQC_DATA_QOS_HIGH);
        if (ret != XQC_OK) {
            break;
        }
    }

    uint64_t unsent = xqc_send_queue_get_unsent_packets_num(conn->conn_send_queue);
    CU_ASSERT_EQUAL(ret, -XQC_EAGAIN);
    CU_ASSERT(unsent >= cap);
    CU_ASSERT(unsent <= cap + 1);
    CU_ASSERT((conn->conn_flag & XQC_CONN_FLAG_DGRAM_WAIT_FOR_UNSENT) != 0);

    /* the other two entry points stop at the same cap */
    struct iovec iov = {.iov_base = data, .iov_len = sizeof(data)};
    size_t sent_cnt = 1, sent_bytes = 1;
    ret = xqc_datagram_send_multiple(conn, &iov, NULL, 1, &sent_cnt, &sent_bytes,
                                     XQC_DATA_QOS_HIGH);
    CU_ASSERT_EQUAL(ret, -XQC_EAGAIN);
    CU_ASSERT_EQUAL(sent_cnt, 0);
    ret = xqc_datagram_send_on_path(conn, data, sizeof(data), &dgram_id,
                                    XQC_DATA_QOS_HIGH, 0);
    CU_ASSERT_EQUAL(ret, -XQC_EAGAIN);
    CU_ASSERT_EQUAL(xqc_send_queue_get_unsent_packets_num(conn->conn_send_queue), unsent);

    /* no wake-up while more than half the cap is still unsent */
    conn->app_proto_cbs.dgram_cbs.datagram_write_notify = xqc_test_dgram_write_notify;
    conn->conn_flag |= XQC_CONN_FLAG_UPPER_CONN_EXIST;
    xqc_test_dgram_write_notified = 0;
    xqc_datagram_notify_unsent_room(conn);
    CU_ASSERT_EQUAL(xqc_test_dgram_write_notified, 0);
    CU_ASSERT((conn->conn_flag & XQC_CONN_FLAG_DGRAM_WAIT_FOR_UNSENT) != 0);

    /* a cap of twice the backlog stands for half of it being sent */
    conn->conn_settings.max_dgram_unsent_packets = (uint32_t)(2 * unsent);
    xqc_datagram_notify_unsent_room(conn);
    CU_ASSERT_EQUAL(xqc_test_dgram_write_notified, 1);
    CU_ASSERT((conn->conn_flag & XQC_CONN_FLAG_DGRAM_WAIT_FOR_UNSENT) == 0);

    /* once only */
    xqc_datagram_notify_unsent_room(conn);
    CU_ASSERT_EQUAL(xqc_test_dgram_write_notified, 1);

    /* no cap: the same backlog is accepted */
    conn->conn_settings.max_dgram_unsent_packets = 0;
    ret = xqc_datagram_send(conn, data, sizeof(data), &dgram_id, XQC_DATA_QOS_HIGH);
    CU_ASSERT_EQUAL(ret, XQC_OK);

    conn->conn_flag &= ~(XQC_CONN_FLAG_UPPER_CONN_EXIST | XQC_CONN_FLAG_TICKING);
    xqc_engine_destroy(conn->engine);
}

/*
 * max_dgram_unsent_delay_ms: the cap follows what the paths drain in that
 * time. A connection with no bandwidth sample yet gets the 64-packet floor,
 * well under a 1024-packet max_dgram_unsent_packets.
 */
void
xqc_test_datagram_unsent_delay_cap()
{
    static unsigned char data[1000];
    uint64_t dgram_id = 0;
    xqc_int_t ret = XQC_OK;
    int i;

    xqc_connection_t *conn = test_engine_connect();
    CU_ASSERT_FATAL(conn != NULL);

    conn->conn_flag |= XQC_CONN_FLAG_CAN_SEND_1RTT | XQC_CONN_FLAG_TICKING;
    conn->conn_settings.defer_send_flush = 1;
    conn->conn_settings.max_dgram_unsent_packets = 1024;
    conn->conn_settings.max_dgram_unsent_delay_ms = 50;
    conn->remote_settings.max_datagram_frame_size = 1200;
    conn->dgram_mss = 1200;

    for (i = 0; i < 1024; i++) {
        ret = xqc_datagram_send(conn, data, sizeof(data), &dgram_id, XQC_DATA_QOS_HIGH);
        if (ret != XQC_OK) {
            break;
        }
    }

    uint64_t unsent = xqc_send_queue_get_unsent_packets_num(conn->conn_send_queue);
    CU_ASSERT_EQUAL(ret, -XQC_EAGAIN);
    CU_ASSERT(unsent >= 64);
    CU_ASSERT(unsent <= 65);

    /* without the delay budget, the packet cap applies again */
    conn->conn_settings.max_dgram_unsent_delay_ms = 0;
    ret = xqc_datagram_send(conn, data, sizeof(data), &dgram_id, XQC_DATA_QOS_HIGH);
    CU_ASSERT_EQUAL(ret, XQC_OK);

    conn->conn_flag &= ~XQC_CONN_FLAG_TICKING;
    xqc_engine_destroy(conn->engine);
}
