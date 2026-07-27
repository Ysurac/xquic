/**
 * @copyright Copyright (c) 2026, mp0rta
 *
 * WRR scheduler invariant tests.
 *
 * These tests exercise the public scheduler callback table
 * (xqc_wrr_scheduler_cb) against a minimal hand-built connection +
 * path-context fixture, mirroring the xqc_wlb_test.c fixture style. The
 * cong-control callback table is mocked so each path's cwnd / inflight can
 * be set independently. SRTT is poked directly into the per-path send_ctl.
 *
 * Unlike WLB, WRR has no flow table and no wall-clock-driven state, so the
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
#include "src/transport/scheduler/xqc_scheduler_wrr.h"
#include "src/common/xqc_log.h"

#include "xqc_wrr_test.h"

/* ───────────────────────── mocked CC callback ───────────────────────── */

typedef struct {
    uint64_t cwnd_bytes;
} wrr_mock_cong_t;

static uint64_t
wrr_mock_get_cwnd(void *cong)
{
    return ((wrr_mock_cong_t *)cong)->cwnd_bytes;
}

static const xqc_cong_ctrl_callback_t WRR_MOCK_CC = {
    .xqc_cong_ctl_get_cwnd = wrr_mock_get_cwnd,
    /* other callbacks unused by the WRR scheduler path */
};

/* ───────────────────────── fixture ───────────────────────── */

#define WRR_TEST_MAX_PATHS 4

typedef struct {
    xqc_connection_t      conn;
    xqc_log_t             log;

    /* path state, owned here so callers can mutate freely between invocations */
    xqc_path_ctx_t        paths[WRR_TEST_MAX_PATHS];
    xqc_send_ctl_t        send_ctls[WRR_TEST_MAX_PATHS];
    wrr_mock_cong_t       cong_states[WRR_TEST_MAX_PATHS];
    int                   n_paths_owned;

    /* scheduler state — opaque heap blob sized by xqc_scheduler_size */
    void                 *scheduler;
} wrr_test_fixture_t;

static void
wrr_test_setup(wrr_test_fixture_t *f)
{
    memset(f, 0, sizeof(*f));

    f->log.log_level = XQC_LOG_FATAL;  /* suppress per-test noise */
    f->conn.log = &f->log;
    xqc_init_list_head(&f->conn.conn_paths_list);

    /* Allocate scheduler state and init through the public vtable so the
     * test exercises exactly the production code path. */
    size_t sz = xqc_wrr_scheduler_cb.xqc_scheduler_size();
    f->scheduler = calloc(1, sz);
    CU_ASSERT_PTR_NOT_NULL_FATAL(f->scheduler);
    xqc_wrr_scheduler_cb.xqc_scheduler_init(f->scheduler, &f->log, NULL);
}

static void
wrr_test_teardown(wrr_test_fixture_t *f)
{
    if (f->scheduler) {
        free(f->scheduler);
        f->scheduler = NULL;
    }
}

/* Attach a new path to the connection with the given static WRR weight.
 * Defaults the path to ACTIVE with the given SRTT and a cwnd big enough to
 * never block — set inflight separately to simulate cwnd-block. */
static xqc_path_ctx_t *
wrr_test_add_path(wrr_test_fixture_t *f, uint64_t path_id, uint32_t weight,
                  xqc_usec_t srtt_us, uint64_t cwnd_bytes, uint32_t inflight_bytes)
{
    CU_ASSERT(f->n_paths_owned < WRR_TEST_MAX_PATHS);
    if (f->n_paths_owned >= WRR_TEST_MAX_PATHS) {
        return NULL;
    }
    int i = f->n_paths_owned++;

    xqc_path_ctx_t   *p   = &f->paths[i];
    xqc_send_ctl_t   *ctl = &f->send_ctls[i];
    wrr_mock_cong_t  *cs  = &f->cong_states[i];

    memset(p, 0, sizeof(*p));
    memset(ctl, 0, sizeof(*ctl));
    memset(cs, 0, sizeof(*cs));

    p->path_id          = path_id;
    p->path_state       = XQC_PATH_STATE_ACTIVE;
    p->app_path_status  = XQC_APP_PATH_STATUS_AVAILABLE;
    p->path_weight       = weight;
    p->path_send_ctl    = ctl;

    cs->cwnd_bytes      = cwnd_bytes;

    ctl->ctl_path       = p;
    ctl->ctl_conn       = &f->conn;
    ctl->ctl_srtt       = srtt_us;
    ctl->ctl_cong       = cs;
    ctl->ctl_cong_callback = &WRR_MOCK_CC;
    ctl->ctl_bytes_in_flight = inflight_bytes;

    xqc_list_add_tail(&p->path_list, &f->conn.conn_paths_list);
    return p;
}

static void
wrr_test_detach_path(xqc_path_ctx_t *p)
{
    xqc_list_del_init(&p->path_list);
}

static void
wrr_test_reattach_path(wrr_test_fixture_t *f, xqc_path_ctx_t *p)
{
    xqc_list_add_tail(&p->path_list, &f->conn.conn_paths_list);
}

/* Build a minimal in-flight-bearing datagram packet_out. flow_hash == 0
 * routes through the scheduler's MinRTT control-packet path; any other
 * value routes through the WRR weighted path. */
static void
wrr_test_make_packet_out(xqc_packet_out_t *po, uint32_t flow_hash)
{
    memset(po, 0, sizeof(*po));
    po->po_flow_hash   = flow_hash;
    /* DATAGRAM bit is "can be in flight" so xqc_send_packet_cwnd_allows
     * actually runs the cwnd check — this makes inflight-vs-cwnd
     * comparisons in the fixture meaningful. */
    po->po_frame_types = XQC_FRAME_BIT_DATAGRAM;
    po->po_used_size   = 100;
}

/* Drive one scheduler call and return the selected path_id (or UINT64_MAX
 * if scheduler returned NULL). */
static uint64_t
wrr_test_invoke_ex(wrr_test_fixture_t *f, uint32_t flow_hash, xqc_bool_t *cc_blk_out)
{
    xqc_packet_out_t po;
    wrr_test_make_packet_out(&po, flow_hash);
    xqc_bool_t cc_blk = XQC_FALSE;
    xqc_path_ctx_t *p = xqc_wrr_scheduler_cb.xqc_scheduler_get_path(
        f->scheduler, &f->conn, &po,
        /* check_cwnd */ 1, /* reinject */ 0, &cc_blk);
    if (cc_blk_out) {
        *cc_blk_out = cc_blk;
    }
    return p ? p->path_id : UINT64_MAX;
}

static uint64_t
wrr_test_invoke(wrr_test_fixture_t *f, uint32_t flow_hash)
{
    return wrr_test_invoke_ex(f, flow_hash, NULL);
}

/* ───────────────────────── tests ───────────────────────── */

/* Equal weights (1:1) must alternate strictly across calls — smooth WRR,
 * not "drain one path then the other". */
void
xqc_test_wrr_equal_weights_alternate(void)
{
    wrr_test_fixture_t f;
    wrr_test_setup(&f);

    wrr_test_add_path(&f, 0, /* weight */ 1, 10000, 64 * 1024, 0);
    wrr_test_add_path(&f, 1, /* weight */ 1, 10000, 64 * 1024, 0);

    uint64_t seq[8];
    for (int i = 0; i < 8; i++) {
        seq[i] = wrr_test_invoke(&f, 0xABCD);
    }

    int on0 = 0, on1 = 0;
    for (int i = 0; i < 8; i++) {
        if (seq[i] == 0) {
            on0++;
        } else if (seq[i] == 1) {
            on1++;
        }
        if (i > 0) {
            /* strict alternation: consecutive picks must differ */
            CU_ASSERT_NOT_EQUAL(seq[i], seq[i - 1]);
        }
    }
    CU_ASSERT_EQUAL(on0, 4);
    CU_ASSERT_EQUAL(on1, 4);

    wrr_test_teardown(&f);
}

/* Weights 3:1 must produce a 3:1 selection ratio over one full weight
 * period (4 calls), and the minority path must be interleaved rather than
 * confined to a single trailing burst (i.e. more than one contiguous run
 * of the majority path). */
void
xqc_test_wrr_weighted_ratio_3_1(void)
{
    wrr_test_fixture_t f;
    wrr_test_setup(&f);

    wrr_test_add_path(&f, 0, /* weight */ 3, 10000, 64 * 1024, 0);
    wrr_test_add_path(&f, 1, /* weight */ 1, 10000, 64 * 1024, 0);

    uint64_t seq[8];
    for (int i = 0; i < 8; i++) {
        seq[i] = wrr_test_invoke(&f, 0x1234);
    }

    /* First full period (4 calls): exactly 3 on path 0, 1 on path 1. */
    int on0 = 0, on1 = 0;
    for (int i = 0; i < 4; i++) {
        if (seq[i] == 0) {
            on0++;
        } else if (seq[i] == 1) {
            on1++;
        }
    }
    CU_ASSERT_EQUAL(on0, 3);
    CU_ASSERT_EQUAL(on1, 1);

    /* Interleaving: path 1 must appear before the last slot of the period
     * (an uninterrupted "A A A B" burst would fail this). */
    xqc_bool_t saw_minority_before_last = XQC_FALSE;
    for (int i = 0; i < 3; i++) {
        if (seq[i] == 1) {
            saw_minority_before_last = XQC_TRUE;
        }
    }
    CU_ASSERT_TRUE(saw_minority_before_last);

    /* Ratio holds over a second period too (state persists across calls). */
    on0 = on1 = 0;
    for (int i = 4; i < 8; i++) {
        if (seq[i] == 0) {
            on0++;
        } else if (seq[i] == 1) {
            on1++;
        }
    }
    CU_ASSERT_EQUAL(on0, 3);
    CU_ASSERT_EQUAL(on1, 1);

    wrr_test_teardown(&f);
}

/* A cwnd-blocked path is skipped for selection but keeps accruing
 * current_weight; once sendable again it wins the very next pick instead
 * of losing its rotation share. */
void
xqc_test_wrr_blocked_path_still_accrues_and_catches_up(void)
{
    wrr_test_fixture_t f;
    wrr_test_setup(&f);

    wrr_test_add_path(&f, 0, 1, 10000, 64 * 1024, 0);
    /* path 1 starts cwnd-blocked: inflight == cwnd */
    wrr_test_add_path(&f, 1, 1, 10000, 64 * 1024, 64 * 1024);

    /* While path 1 is blocked, every pick must go to path 0. */
    for (int i = 0; i < 3; i++) {
        CU_ASSERT_EQUAL(wrr_test_invoke(&f, 0x1111), 0);
    }

    /* Unblock path 1 — its accrued weight advantage must win immediately. */
    f.send_ctls[1].ctl_bytes_in_flight = 0;
    CU_ASSERT_EQUAL(wrr_test_invoke(&f, 0x1111), 1);

    wrr_test_teardown(&f);
}

/* Control packets (po_flow_hash == 0) must use plain MinRTT and never
 * touch WRR weight state: a heavily weight-skewed but high-RTT path must
 * never be chosen for control traffic, and a run of control calls must not
 * perturb the weighted ratio seen by subsequent app-data calls. */
void
xqc_test_wrr_control_packets_use_minrtt_and_dont_perturb_weight_state(void)
{
    wrr_test_fixture_t f;
    wrr_test_setup(&f);

    /* path 0: huge weight, high RTT.  path 1: tiny weight, low RTT. */
    wrr_test_add_path(&f, 0, /* weight */ 10, /* srtt */ 50000, 64 * 1024, 0);
    wrr_test_add_path(&f, 1, /* weight */ 1,  /* srtt */ 5000,  64 * 1024, 0);

    for (int i = 0; i < 5; i++) {
        CU_ASSERT_EQUAL(wrr_test_invoke(&f, 0 /* control */), 1 /* lowest RTT */);
    }

    /* First app-data call after the control-packet run must still reflect
     * a pristine weight state: path 0 (weight 10) wins immediately. */
    CU_ASSERT_EQUAL(wrr_test_invoke(&f, 0xCAFE /* app data */), 0);

    wrr_test_teardown(&f);
}

/* When every usable path is cwnd-blocked, the scheduler must return NULL
 * and report cc_blocked = TRUE (never silently pick an unsendable path). */
void
xqc_test_wrr_all_paths_cwnd_blocked_returns_null_and_cc_blocked(void)
{
    wrr_test_fixture_t f;
    wrr_test_setup(&f);

    wrr_test_add_path(&f, 0, 1, 10000, 16 * 1024, 16 * 1024);
    wrr_test_add_path(&f, 1, 1, 10000, 16 * 1024, 16 * 1024);

    xqc_bool_t cc_blk = XQC_FALSE;
    uint64_t sel = wrr_test_invoke_ex(&f, 0xBEEF, &cc_blk);

    CU_ASSERT_EQUAL(sel, UINT64_MAX);
    CU_ASSERT_TRUE(cc_blk);

    wrr_test_teardown(&f);
}

/* weight = 0 must be treated as weight = 1 (equal priority), matching
 * WRTT's documented convention — two weight-0 paths must still alternate
 * evenly rather than starving one of them. */
void
xqc_test_wrr_weight_zero_treated_as_one(void)
{
    wrr_test_fixture_t f;
    wrr_test_setup(&f);

    wrr_test_add_path(&f, 0, /* weight */ 0, 10000, 64 * 1024, 0);
    wrr_test_add_path(&f, 1, /* weight */ 0, 10000, 64 * 1024, 0);

    int on0 = 0, on1 = 0;
    for (int i = 0; i < 8; i++) {
        uint64_t sel = wrr_test_invoke(&f, 0x2222);
        if (sel == 0) {
            on0++;
        } else if (sel == 1) {
            on1++;
        }
    }
    CU_ASSERT_EQUAL(on0, 4);
    CU_ASSERT_EQUAL(on1, 4);

    wrr_test_teardown(&f);
}

/* Removing a path from the connection's path list must not crash the
 * scheduler; the surviving path keeps being selected, and a path that
 * reappears later resumes normal scheduling. */
void
xqc_test_wrr_path_removed_no_crash(void)
{
    wrr_test_fixture_t f;
    wrr_test_setup(&f);

    wrr_test_add_path(&f, 0, 1, 10000, 64 * 1024, 0);
    xqc_path_ctx_t *p1 = wrr_test_add_path(&f, 1, 1, 10000, 64 * 1024, 0);

    (void)wrr_test_invoke(&f, 0x3333);
    (void)wrr_test_invoke(&f, 0x3333);

    wrr_test_detach_path(p1);

    /* Only path 0 remains — must be selected every time, no crash. */
    for (int i = 0; i < 3; i++) {
        CU_ASSERT_EQUAL(wrr_test_invoke(&f, 0x3333), 0);
    }

    wrr_test_reattach_path(&f, p1);

    /* Both paths usable again — must still produce valid selections from
     * {0, 1} with no crash. */
    for (int i = 0; i < 4; i++) {
        uint64_t sel = wrr_test_invoke(&f, 0x3333);
        CU_ASSERT_TRUE(sel == 0 || sel == 1);
    }

    wrr_test_teardown(&f);
}
