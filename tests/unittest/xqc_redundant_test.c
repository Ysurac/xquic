/**
 * @copyright Copyright (c) 2026, mp0rta
 *
 * Redundant (broadcast) scheduler invariant tests.
 *
 * These tests exercise the public scheduler callback table
 * (xqc_redundant_scheduler_cb) against a minimal hand-built connection +
 * path-context fixture, mirroring the xqc_wrr_test.c fixture style. Unlike
 * WRR, this scheduler actually allocates and queues packet_out replicas, so
 * the fixture also carries a minimal xqc_send_queue_t (just the two list
 * heads xqc_packet_out_get()/xqc_send_queue_insert_send() touch) rather
 * than the full xqc_send_queue_create() machinery, which requires a real
 * connection memory pool.
 */

#include <CUnit/CUnit.h>
#include <stdlib.h>
#include <string.h>

#include "xquic/xquic.h"
#include "xquic/xquic_typedef.h"
#include "src/common/xqc_list.h"
#include "src/transport/xqc_conn.h"
#include "src/transport/xqc_multipath.h"
#include "src/transport/xqc_packet_out.h"
#include "src/transport/xqc_send_ctl.h"
#include "src/transport/xqc_send_queue.h"
#include "src/transport/xqc_frame.h"
#include "src/transport/scheduler/xqc_scheduler_redundant.h"
#include "src/common/xqc_log.h"

#include "xqc_redundant_test.h"

/* ───────────────────────── mocked CC callback ───────────────────────── */

typedef struct {
    uint64_t cwnd_bytes;
} redundant_mock_cong_t;

static uint64_t
redundant_mock_get_cwnd(void *cong)
{
    return ((redundant_mock_cong_t *)cong)->cwnd_bytes;
}

static const xqc_cong_ctrl_callback_t REDUNDANT_MOCK_CC = {
    .xqc_cong_ctl_get_cwnd = redundant_mock_get_cwnd,
    /* other callbacks unused by the scheduler path under test */
};

/* ───────────────────────── fixture ───────────────────────── */

#define REDUNDANT_TEST_MAX_PATHS 4

typedef struct {
    xqc_connection_t       conn;
    xqc_log_t               log;
    xqc_send_queue_t        send_queue;

    /* path state, owned here so callers can mutate freely between invocations */
    xqc_path_ctx_t          paths[REDUNDANT_TEST_MAX_PATHS];
    xqc_send_ctl_t          send_ctls[REDUNDANT_TEST_MAX_PATHS];
    redundant_mock_cong_t   cong_states[REDUNDANT_TEST_MAX_PATHS];
    int                     n_paths_owned;

    /* scheduler state — opaque heap blob sized by xqc_scheduler_size */
    void                   *scheduler;
} redundant_test_fixture_t;

static void
redundant_test_setup(redundant_test_fixture_t *f)
{
    memset(f, 0, sizeof(*f));

    f->log.log_level = XQC_LOG_FATAL;  /* suppress per-test noise */
    f->conn.log = &f->log;
    f->conn.pkt_out_size = 1500;
    f->conn.conn_send_queue = &f->send_queue;
    xqc_init_list_head(&f->conn.conn_paths_list);

    f->send_queue.sndq_conn = &f->conn;
    xqc_init_list_head(&f->send_queue.sndq_send_packets);
    xqc_init_list_head(&f->send_queue.sndq_free_packets);

    size_t sz = xqc_redundant_scheduler_cb.xqc_scheduler_size();
    f->scheduler = calloc(1, sz > 0 ? sz : 1);
    CU_ASSERT_PTR_NOT_NULL_FATAL(f->scheduler);
    xqc_redundant_scheduler_cb.xqc_scheduler_init(f->scheduler, &f->log, NULL);
}

static void
redundant_test_teardown(redundant_test_fixture_t *f)
{
    if (f->scheduler) {
        free(f->scheduler);
        f->scheduler = NULL;
    }
}

/* Attach a new ACTIVE/AVAILABLE path to the connection. cwnd_bytes /
 * inflight_bytes drive xqc_send_packet_cwnd_allows() through the mocked CC
 * callback; set inflight == cwnd to simulate a cwnd-blocked path. */
static xqc_path_ctx_t *
redundant_test_add_path(redundant_test_fixture_t *f, uint64_t path_id,
    xqc_usec_t srtt_us, uint64_t cwnd_bytes, uint32_t inflight_bytes)
{
    CU_ASSERT(f->n_paths_owned < REDUNDANT_TEST_MAX_PATHS);
    if (f->n_paths_owned >= REDUNDANT_TEST_MAX_PATHS) {
        return NULL;
    }
    int i = f->n_paths_owned++;

    xqc_path_ctx_t         *p   = &f->paths[i];
    xqc_send_ctl_t         *ctl = &f->send_ctls[i];
    redundant_mock_cong_t   *cs  = &f->cong_states[i];

    memset(p, 0, sizeof(*p));
    memset(ctl, 0, sizeof(*ctl));
    memset(cs, 0, sizeof(*cs));

    p->path_id          = path_id;
    p->path_state       = XQC_PATH_STATE_ACTIVE;
    p->app_path_status  = XQC_APP_PATH_STATUS_AVAILABLE;
    p->path_send_ctl    = ctl;
    /* xqc_path_get_perf_class() dereferences parent_conn->conn_settings */
    p->parent_conn      = &f->conn;
    xqc_init_list_head(&p->path_schedule_buf[XQC_SEND_TYPE_NORMAL]);
    xqc_init_list_head(&p->path_schedule_buf[XQC_SEND_TYPE_NORMAL_HIGH_PRI]);
    xqc_init_list_head(&p->path_schedule_buf[XQC_SEND_TYPE_RETRANS]);
    xqc_init_list_head(&p->path_schedule_buf[XQC_SEND_TYPE_PTO_PROBE]);
    xqc_init_list_head(&p->path_reinj_tmp_buf);

    cs->cwnd_bytes      = cwnd_bytes;

    ctl->ctl_path       = p;
    ctl->ctl_conn       = &f->conn;
    ctl->ctl_srtt       = srtt_us;
    ctl->ctl_cong       = cs;
    ctl->ctl_cong_callback = &REDUNDANT_MOCK_CC;
    ctl->ctl_bytes_in_flight = inflight_bytes;

    xqc_list_add_tail(&p->path_list, &f->conn.conn_paths_list);
    return p;
}

/* Allocate a real packet_out from the fixture's send_queue free list (so
 * xqc_packet_out_copy()'s po_buf memcpy has a real, correctly-sized source
 * buffer to read from) and fill in the fields the scheduler and its
 * replication path care about. */
static xqc_packet_out_t *
redundant_test_make_packet_out(redundant_test_fixture_t *f, uint32_t used_size)
{
    xqc_packet_out_t *po = xqc_packet_out_get(&f->send_queue);
    CU_ASSERT_PTR_NOT_NULL_FATAL(po);

    po->po_frame_types = XQC_FRAME_BIT_DATAGRAM;  /* ack-eliciting, drives the cwnd check */
    po->po_used_size   = used_size;
    po->po_stream_id   = 4;
    po->po_stream_offset = 0;
    return po;
}

static int
redundant_test_list_len(xqc_list_head_t *head)
{
    int n = 0;
    xqc_list_head_t *pos;
    xqc_list_for_each(pos, head) {
        n++;
    }
    return n;
}

static uint64_t
redundant_test_invoke_ex(redundant_test_fixture_t *f, xqc_packet_out_t *po,
    int reinject, xqc_bool_t *cc_blk_out)
{
    xqc_bool_t cc_blk = XQC_FALSE;
    xqc_path_ctx_t *p = xqc_redundant_scheduler_cb.xqc_scheduler_get_path(
        f->scheduler, &f->conn, po,
        /* check_cwnd */ 1, reinject, &cc_blk);
    if (cc_blk_out) {
        *cc_blk_out = cc_blk;
    }
    return p ? p->path_id : UINT64_MAX;
}

/* ───────────────────────── tests ───────────────────────── */

void
xqc_test_redundant_two_paths_primary_and_replica(void)
{
    redundant_test_fixture_t f;
    redundant_test_setup(&f);

    xqc_path_ctx_t *p0 = redundant_test_add_path(&f, 0, /* srtt */ 5000,  64 * 1024, 0);
    xqc_path_ctx_t *p1 = redundant_test_add_path(&f, 1, /* srtt */ 50000, 64 * 1024, 0);

    xqc_packet_out_t *po = redundant_test_make_packet_out(&f, 120);

    uint64_t sel = redundant_test_invoke_ex(&f, po, /* reinject */ 0, NULL);
    CU_ASSERT_EQUAL(sel, 0);  /* lower SRTT wins as primary */

    /* primary path itself gets no replica (caller queues the original there) */
    CU_ASSERT_EQUAL(redundant_test_list_len(&p0->path_schedule_buf[XQC_SEND_TYPE_NORMAL]), 0);

    /* the other path gets exactly one replica */
    CU_ASSERT_EQUAL(redundant_test_list_len(&p1->path_schedule_buf[XQC_SEND_TYPE_NORMAL]), 1);

    xqc_packet_out_t *replica = xqc_list_entry(
        p1->path_schedule_buf[XQC_SEND_TYPE_NORMAL].next, xqc_packet_out_t, po_list);
    CU_ASSERT_EQUAL(replica->po_used_size, po->po_used_size);
    CU_ASSERT_EQUAL(replica->po_stream_id, po->po_stream_id);
    CU_ASSERT_TRUE(replica->po_path_flag & XQC_PATH_SPECIFIED_BY_REINJ);
    CU_ASSERT_EQUAL(replica->po_path_id, p1->path_id);
    CU_ASSERT_PTR_EQUAL(replica->po_origin, po);
    CU_ASSERT_EQUAL(po->po_origin_ref_cnt, 1);

    redundant_test_teardown(&f);
}

void
xqc_test_redundant_three_paths_replicate_to_all_others(void)
{
    redundant_test_fixture_t f;
    redundant_test_setup(&f);

    xqc_path_ctx_t *p0 = redundant_test_add_path(&f, 0, 5000,  64 * 1024, 0);
    xqc_path_ctx_t *p1 = redundant_test_add_path(&f, 1, 20000, 64 * 1024, 0);
    xqc_path_ctx_t *p2 = redundant_test_add_path(&f, 2, 50000, 64 * 1024, 0);

    xqc_packet_out_t *po = redundant_test_make_packet_out(&f, 80);

    uint64_t sel = redundant_test_invoke_ex(&f, po, 0, NULL);
    CU_ASSERT_EQUAL(sel, 0);

    CU_ASSERT_EQUAL(redundant_test_list_len(&p0->path_schedule_buf[XQC_SEND_TYPE_NORMAL]), 0);
    CU_ASSERT_EQUAL(redundant_test_list_len(&p1->path_schedule_buf[XQC_SEND_TYPE_NORMAL]), 1);
    CU_ASSERT_EQUAL(redundant_test_list_len(&p2->path_schedule_buf[XQC_SEND_TYPE_NORMAL]), 1);
    CU_ASSERT_EQUAL(po->po_origin_ref_cnt, 2);

    redundant_test_teardown(&f);
}

void
xqc_test_redundant_cwnd_blocked_path_gets_no_replica(void)
{
    redundant_test_fixture_t f;
    redundant_test_setup(&f);

    xqc_path_ctx_t *p0 = redundant_test_add_path(&f, 0, 5000, 64 * 1024, 0);
    /* path 1 is cwnd-blocked: inflight == cwnd */
    xqc_path_ctx_t *p1 = redundant_test_add_path(&f, 1, 20000, 64 * 1024, 64 * 1024);

    xqc_packet_out_t *po = redundant_test_make_packet_out(&f, 100);

    uint64_t sel = redundant_test_invoke_ex(&f, po, 0, NULL);
    CU_ASSERT_EQUAL(sel, 0);

    CU_ASSERT_EQUAL(redundant_test_list_len(&p1->path_schedule_buf[XQC_SEND_TYPE_NORMAL]), 0);
    CU_ASSERT_EQUAL(po->po_origin_ref_cnt, 0);

    redundant_test_teardown(&f);
}

void
xqc_test_redundant_frozen_path_excluded(void)
{
    redundant_test_fixture_t f;
    redundant_test_setup(&f);

    xqc_path_ctx_t *p0 = redundant_test_add_path(&f, 0, 5000, 64 * 1024, 0);
    xqc_path_ctx_t *p1 = redundant_test_add_path(&f, 1, 20000, 64 * 1024, 0);
    p1->app_path_status = XQC_APP_PATH_STATUS_FROZEN;

    xqc_packet_out_t *po = redundant_test_make_packet_out(&f, 100);

    uint64_t sel = redundant_test_invoke_ex(&f, po, 0, NULL);
    CU_ASSERT_EQUAL(sel, 0);
    CU_ASSERT_EQUAL(redundant_test_list_len(&p1->path_schedule_buf[XQC_SEND_TYPE_NORMAL]), 0);

    redundant_test_teardown(&f);
}

void
xqc_test_redundant_reinject_call_returns_single_path_no_replica(void)
{
    redundant_test_fixture_t f;
    redundant_test_setup(&f);

    xqc_path_ctx_t *p0 = redundant_test_add_path(&f, 0, 5000,  64 * 1024, 0);
    xqc_path_ctx_t *p1 = redundant_test_add_path(&f, 1, 20000, 64 * 1024, 0);

    xqc_packet_out_t *po = redundant_test_make_packet_out(&f, 100);
    /* simulate the packet's original transmission having gone out on path 0:
     * the selective-reinjection pass asks for "a" (single) other path. */
    po->po_path_id = 0;

    uint64_t sel = redundant_test_invoke_ex(&f, po, /* reinject */ 1, NULL);
    CU_ASSERT_EQUAL(sel, 1);  /* only remaining path, origin path 0 skipped */

    /* no fan-out: neither path's NORMAL buffer gets a replica from this call */
    CU_ASSERT_EQUAL(redundant_test_list_len(&p0->path_schedule_buf[XQC_SEND_TYPE_NORMAL]), 0);
    CU_ASSERT_EQUAL(redundant_test_list_len(&p1->path_schedule_buf[XQC_SEND_TYPE_NORMAL]), 0);
    CU_ASSERT_EQUAL(po->po_origin_ref_cnt, 0);

    redundant_test_teardown(&f);
}

void
xqc_test_redundant_all_paths_cwnd_blocked_returns_null_and_cc_blocked(void)
{
    redundant_test_fixture_t f;
    redundant_test_setup(&f);

    redundant_test_add_path(&f, 0, 10000, 16 * 1024, 16 * 1024);
    redundant_test_add_path(&f, 1, 10000, 16 * 1024, 16 * 1024);

    xqc_packet_out_t *po = redundant_test_make_packet_out(&f, 100);

    xqc_bool_t cc_blk = XQC_FALSE;
    uint64_t sel = redundant_test_invoke_ex(&f, po, 0, &cc_blk);

    CU_ASSERT_EQUAL(sel, UINT64_MAX);
    CU_ASSERT_TRUE(cc_blk);
    CU_ASSERT_EQUAL(po->po_origin_ref_cnt, 0);

    redundant_test_teardown(&f);
}

void
xqc_test_redundant_single_path_no_replica_no_crash(void)
{
    redundant_test_fixture_t f;
    redundant_test_setup(&f);

    redundant_test_add_path(&f, 0, 10000, 64 * 1024, 0);

    xqc_packet_out_t *po = redundant_test_make_packet_out(&f, 100);

    uint64_t sel = redundant_test_invoke_ex(&f, po, 0, NULL);
    CU_ASSERT_EQUAL(sel, 0);
    CU_ASSERT_EQUAL(po->po_origin_ref_cnt, 0);

    redundant_test_teardown(&f);
}
