/**
 * @copyright Copyright (c) 2026, mp0rta
 *
 * DSCP scheduler invariant tests.
 *
 * These tests exercise the public scheduler callback table
 * (xqc_dscp_scheduler_cb) against a minimal hand-built connection +
 * path-context fixture, mirroring the xqc_wrr_test.c fixture style. The
 * cong-control callback table is mocked so each path's cwnd / inflight can
 * be set independently. SRTT is poked directly into the per-path send_ctl.
 *
 * Like WRR/WRTT, the DSCP scheduler has no wall-clock-driven state, so the
 * fixture doesn't need a fake clock — every invariant is observable purely
 * from the sequence of paths returned across consecutive scheduler calls.
 */

#include <CUnit/CUnit.h>
#include <stdlib.h>
#include <string.h>

#include "xquic/xquic.h"
#include "xquic/xquic_typedef.h"
#include "src/transport/xqc_conn.h"
#include "src/transport/xqc_multipath.h"
#include "src/transport/xqc_packet_out.h"
#include "src/transport/xqc_send_ctl.h"
#include "src/transport/xqc_frame.h"
#include "src/transport/scheduler/xqc_scheduler_dscp.h"
#include "src/common/xqc_log.h"

#include "xqc_dscp_test.h"

/* ───────────────────────── mocked CC callback ───────────────────────── */

typedef struct {
    uint64_t cwnd_bytes;
} dscp_mock_cong_t;

static uint64_t
dscp_mock_get_cwnd(void *cong)
{
    return ((dscp_mock_cong_t *)cong)->cwnd_bytes;
}

static const xqc_cong_ctrl_callback_t DSCP_MOCK_CC = {
    .xqc_cong_ctl_get_cwnd = dscp_mock_get_cwnd,
    /* other callbacks unused by the DSCP scheduler path */
};

/* ───────────────────────── fixture ───────────────────────── */

#define DSCP_TEST_MAX_PATHS 4

typedef struct {
    xqc_connection_t      conn;
    xqc_log_t             log;

    /* path state, owned here so callers can mutate freely between invocations */
    xqc_path_ctx_t        paths[DSCP_TEST_MAX_PATHS];
    xqc_send_ctl_t        send_ctls[DSCP_TEST_MAX_PATHS];
    dscp_mock_cong_t      cong_states[DSCP_TEST_MAX_PATHS];
    int                   n_paths_owned;
} dscp_test_fixture_t;

static void
dscp_test_setup(dscp_test_fixture_t *f)
{
    memset(f, 0, sizeof(*f));

    f->log.log_level = XQC_LOG_FATAL;  /* suppress per-test noise */
    f->conn.log = &f->log;
    xqc_init_list_head(&f->conn.conn_paths_list);
}

static void
dscp_test_teardown(dscp_test_fixture_t *f)
{
    (void)f;
}

/* Attach a new path to the connection with the given static DSCP mask
 * (0 = unassigned). Defaults the path to ACTIVE with the given SRTT and a
 * cwnd big enough to never block — set inflight separately to simulate
 * cwnd-block. */
static xqc_path_ctx_t *
dscp_test_add_path(dscp_test_fixture_t *f, uint64_t path_id, uint64_t dscp_mask,
                    xqc_usec_t srtt_us, uint64_t cwnd_bytes, uint32_t inflight_bytes)
{
    CU_ASSERT(f->n_paths_owned < DSCP_TEST_MAX_PATHS);
    if (f->n_paths_owned >= DSCP_TEST_MAX_PATHS) {
        return NULL;
    }
    int i = f->n_paths_owned++;

    xqc_path_ctx_t    *p   = &f->paths[i];
    xqc_send_ctl_t    *ctl = &f->send_ctls[i];
    dscp_mock_cong_t  *cs  = &f->cong_states[i];

    memset(p, 0, sizeof(*p));
    memset(ctl, 0, sizeof(*ctl));
    memset(cs, 0, sizeof(*cs));

    p->path_id          = path_id;
    p->path_state       = XQC_PATH_STATE_ACTIVE;
    p->app_path_status  = XQC_APP_PATH_STATUS_AVAILABLE;
    p->path_dscp_mask   = dscp_mask;
    p->path_send_ctl    = ctl;

    cs->cwnd_bytes      = cwnd_bytes;

    ctl->ctl_path       = p;
    ctl->ctl_conn       = &f->conn;
    ctl->ctl_srtt       = srtt_us;
    ctl->ctl_cong       = cs;
    ctl->ctl_cong_callback = &DSCP_MOCK_CC;
    ctl->ctl_bytes_in_flight = inflight_bytes;

    xqc_list_add_tail(&p->path_list, &f->conn.conn_paths_list);
    return p;
}

/* Build a minimal in-flight-bearing datagram packet_out tagged with the
 * given DSCP class. dscp == 0 routes through the scheduler's untagged
 * MinRTT path; any other value (1-63) routes through the DSCP-mask path. */
static void
dscp_test_make_packet_out(xqc_packet_out_t *po, uint8_t dscp)
{
    memset(po, 0, sizeof(*po));
    po->po_dscp        = dscp;
    /* DATAGRAM bit is "can be in flight" so xqc_send_packet_cwnd_allows
     * actually runs the cwnd check — this makes inflight-vs-cwnd
     * comparisons in the fixture meaningful. */
    po->po_frame_types = XQC_FRAME_BIT_DATAGRAM;
    po->po_used_size   = 100;
}

/* Drive one scheduler call and return the selected path_id (or UINT64_MAX
 * if scheduler returned NULL). */
static uint64_t
dscp_test_invoke_ex(dscp_test_fixture_t *f, uint8_t dscp, xqc_bool_t *cc_blk_out)
{
    xqc_packet_out_t po;
    dscp_test_make_packet_out(&po, dscp);
    xqc_bool_t cc_blk = XQC_FALSE;
    xqc_path_ctx_t *p = xqc_dscp_scheduler_cb.xqc_scheduler_get_path(
        NULL, &f->conn, &po,
        /* check_cwnd */ 1, /* reinject */ 0, &cc_blk);
    if (cc_blk_out) {
        *cc_blk_out = cc_blk;
    }
    return p ? p->path_id : UINT64_MAX;
}

static uint64_t
dscp_test_invoke(dscp_test_fixture_t *f, uint8_t dscp)
{
    return dscp_test_invoke_ex(f, dscp, NULL);
}

/* ───────────────────────── tests ───────────────────────── */

/* Untagged packets (po_dscp == 0), including control packets, use plain
 * MinRTT across every usable path and ignore any configured DSCP masks. */
void
xqc_test_dscp_untagged_uses_minrtt_ignoring_masks(void)
{
    dscp_test_fixture_t f;
    dscp_test_setup(&f);

    /* path 0 is assigned class 46 (EF) and has high RTT; path 1 is
     * unassigned and has low RTT. Untagged traffic must ignore the mask
     * and go by RTT alone. */
    dscp_test_add_path(&f, 0, XQC_DSCP_BIT(46), 50000, 64 * 1024, 0);
    dscp_test_add_path(&f, 1, 0,                5000,  64 * 1024, 0);

    for (int i = 0; i < 3; i++) {
        CU_ASSERT_EQUAL(dscp_test_invoke(&f, 0 /* untagged */), 1);
    }

    dscp_test_teardown(&f);
}

/* A tagged packet is routed to the path whose mask includes that DSCP
 * class, even when another usable path has lower RTT. */
void
xqc_test_dscp_tagged_routes_to_assigned_path(void)
{
    dscp_test_fixture_t f;
    dscp_test_setup(&f);

    /* path 0: assigned EF (46), high RTT. path 1: unassigned, low RTT. */
    dscp_test_add_path(&f, 0, XQC_DSCP_BIT(46), 50000, 64 * 1024, 0);
    dscp_test_add_path(&f, 1, 0,                5000,  64 * 1024, 0);

    for (int i = 0; i < 3; i++) {
        CU_ASSERT_EQUAL(dscp_test_invoke(&f, 46 /* EF */), 0);
    }

    /* Meanwhile untagged traffic still prefers the low-RTT path. */
    CU_ASSERT_EQUAL(dscp_test_invoke(&f, 0), 1);

    dscp_test_teardown(&f);
}

/* When two paths share the same DSCP class in their mask, the tagged
 * packet is scheduled by MinRTT between just those two. */
void
xqc_test_dscp_tagged_breaks_tie_by_minrtt_among_assigned(void)
{
    dscp_test_fixture_t f;
    dscp_test_setup(&f);

    /* All three paths are assigned class 34 (AF41); path 2 has the best
     * RTT and a third, unassigned path is even faster but must not be
     * picked for tagged traffic. */
    dscp_test_add_path(&f, 0, XQC_DSCP_BIT(34), 20000, 64 * 1024, 0);
    dscp_test_add_path(&f, 1, XQC_DSCP_BIT(34), 30000, 64 * 1024, 0);
    dscp_test_add_path(&f, 2, XQC_DSCP_BIT(34), 10000, 64 * 1024, 0);
    dscp_test_add_path(&f, 3, 0,                1000,  64 * 1024, 0);

    for (int i = 0; i < 3; i++) {
        CU_ASSERT_EQUAL(dscp_test_invoke(&f, 34 /* AF41 */), 2);
    }

    dscp_test_teardown(&f);
}

/* When the assigned path for a tagged packet is cwnd-blocked (but other,
 * unassigned paths are sendable), the scheduler degrades to plain MinRTT
 * across every usable path instead of stalling. */
void
xqc_test_dscp_tagged_falls_back_to_minrtt_when_assigned_path_blocked(void)
{
    dscp_test_fixture_t f;
    dscp_test_setup(&f);

    /* path 0: assigned class 46, but cwnd-blocked (inflight == cwnd). */
    dscp_test_add_path(&f, 0, XQC_DSCP_BIT(46), 10000, 16 * 1024, 16 * 1024);
    /* path 1: unassigned, sendable. */
    dscp_test_add_path(&f, 1, 0, 20000, 64 * 1024, 0);

    xqc_bool_t cc_blk = XQC_TRUE;
    uint64_t sel = dscp_test_invoke_ex(&f, 46, &cc_blk);
    CU_ASSERT_EQUAL(sel, 1);
    CU_ASSERT_FALSE(cc_blk);

    dscp_test_teardown(&f);
}

/* When no path is assigned the packet's DSCP class at all, the scheduler
 * falls back to plain MinRTT across every usable path. */
void
xqc_test_dscp_tagged_falls_back_to_minrtt_when_no_path_assigned(void)
{
    dscp_test_fixture_t f;
    dscp_test_setup(&f);

    /* Neither path is assigned class 10 (AF11). */
    dscp_test_add_path(&f, 0, XQC_DSCP_BIT(46), 30000, 64 * 1024, 0);
    dscp_test_add_path(&f, 1, XQC_DSCP_BIT(34), 10000, 64 * 1024, 0);

    for (int i = 0; i < 3; i++) {
        CU_ASSERT_EQUAL(dscp_test_invoke(&f, 10 /* AF11, unassigned */), 1);
    }

    dscp_test_teardown(&f);
}

/* When every usable path is cwnd-blocked (assigned or not), the scheduler
 * returns NULL and reports cc_blocked = TRUE. */
void
xqc_test_dscp_all_paths_cwnd_blocked_returns_null_and_cc_blocked(void)
{
    dscp_test_fixture_t f;
    dscp_test_setup(&f);

    dscp_test_add_path(&f, 0, XQC_DSCP_BIT(46), 10000, 16 * 1024, 16 * 1024);
    dscp_test_add_path(&f, 1, 0,                10000, 16 * 1024, 16 * 1024);

    xqc_bool_t cc_blk = XQC_FALSE;
    uint64_t sel = dscp_test_invoke_ex(&f, 46, &cc_blk);
    CU_ASSERT_EQUAL(sel, UINT64_MAX);
    CU_ASSERT_TRUE(cc_blk);

    /* Same for untagged traffic. */
    cc_blk = XQC_FALSE;
    sel = dscp_test_invoke_ex(&f, 0, &cc_blk);
    CU_ASSERT_EQUAL(sel, UINT64_MAX);
    CU_ASSERT_TRUE(cc_blk);

    dscp_test_teardown(&f);
}

/* A path with dscp_mask == 0 (the default / unassigned) is still eligible
 * for untagged traffic and for the MinRTT fallback of tagged traffic. */
void
xqc_test_dscp_unassigned_path_still_used_as_fallback(void)
{
    dscp_test_fixture_t f;
    dscp_test_setup(&f);

    xqc_path_ctx_t *p = dscp_test_add_path(&f, 0, 0, 10000, 64 * 1024, 0);
    CU_ASSERT_PTR_NOT_NULL_FATAL(p);

    CU_ASSERT_EQUAL(dscp_test_invoke(&f, 0), 0);
    CU_ASSERT_EQUAL(dscp_test_invoke(&f, 46), 0);

    dscp_test_teardown(&f);
}
