/**
 * @copyright Copyright (c) 2026, mp0rta
 *
 * Standby-path tests for the path-picking schedulers. Same fixture style as
 * xqc_wlb_test.c: a hand-built connection and path contexts, a mocked
 * congestion controller and a fake clock, driven through each scheduler's
 * callback table. The connection carries the default scheduler_params so
 * xqc_path_get_perf_class classifies paths as it does in production.
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
#include "src/transport/scheduler/xqc_scheduler_wlb.h"
#include "src/transport/scheduler/xqc_scheduler_minrtt.h"
#include "src/transport/scheduler/xqc_scheduler_wrr.h"
#include "src/transport/scheduler/xqc_scheduler_wrtt.h"
#include "src/transport/scheduler/xqc_scheduler_dscp.h"
#include "src/transport/scheduler/xqc_scheduler_rap.h"
#include "src/common/xqc_log.h"
#include "src/common/xqc_time.h"

#include "xqc_scheduler_standby_test.h"

#define SB_MAX_PATHS        4
#define SB_FLOW_UNPINNED    0xFFFFFFFFU
#define SB_NO_PATH          UINT64_MAX
#define SB_ROUNDS           300

static xqc_usec_t sb_now_us = 1000000;

static xqc_usec_t
sb_fake_now(void)
{
    return sb_now_us;
}

typedef struct {
    uint64_t cwnd_bytes;
    uint32_t bandwidth_Bps;
} sb_mock_cong_t;

static uint64_t
sb_mock_get_cwnd(void *cong)
{
    return ((sb_mock_cong_t *)cong)->cwnd_bytes;
}

static uint32_t
sb_mock_get_bandwidth(void *cong)
{
    return ((sb_mock_cong_t *)cong)->bandwidth_Bps;
}

static const xqc_cong_ctrl_callback_t SB_MOCK_CC = {
    .xqc_cong_ctl_get_cwnd = sb_mock_get_cwnd,
    .xqc_cong_ctl_get_bandwidth_estimate = sb_mock_get_bandwidth,
};

typedef struct {
    xqc_connection_t                conn;
    xqc_log_t                       log;
    xqc_path_ctx_t                  paths[SB_MAX_PATHS];
    xqc_send_ctl_t                  send_ctls[SB_MAX_PATHS];
    sb_mock_cong_t                  cong[SB_MAX_PATHS];
    int                             n_paths;
    const xqc_scheduler_callback_t *cb;
    void                           *scheduler;
    xqc_timestamp_pt                saved_ts;
} sb_fixture_t;

static void
sb_setup(sb_fixture_t *f, const xqc_scheduler_callback_t *cb)
{
    memset(f, 0, sizeof(*f));
    f->log.log_level = XQC_LOG_FATAL;
    f->conn.log = &f->log;
    xqc_init_list_head(&f->conn.conn_paths_list);

    /* production defaults (xqc_conn.c default_conn_settings) */
    f->conn.conn_settings.scheduler_params.bw_Bps_thr = 375000;
    f->conn.conn_settings.scheduler_params.loss_percent_thr_high = 30;
    f->conn.conn_settings.scheduler_params.loss_percent_thr_low = 10;
    f->conn.conn_settings.scheduler_params.pto_cnt_thr = 2;
    f->conn.conn_settings.scheduler_params.rtt_us_thr_high = 2000000;
    f->conn.conn_settings.scheduler_params.rtt_us_thr_low = 500000;

    f->cb = cb;
    size_t sz = cb->xqc_scheduler_size();
    f->scheduler = calloc(1, sz > 0 ? sz : 1);
    CU_ASSERT_PTR_NOT_NULL_FATAL(f->scheduler);
    cb->xqc_scheduler_init(f->scheduler, &f->log, NULL);
    f->conn.scheduler = f->scheduler;
    f->conn.scheduler_callback = cb;

    f->saved_ts = xqc_monotonic_timestamp;
    xqc_monotonic_timestamp = sb_fake_now;
    sb_now_us = 1000000;
}

static void
sb_teardown(sb_fixture_t *f)
{
    xqc_monotonic_timestamp = f->saved_ts;
    free(f->scheduler);
    f->scheduler = NULL;
}

/* ACTIVE path with plenty of cwnd and a bandwidth estimate well above
 * bw_Bps_thr, so its class is set by srtt and status alone. */
static xqc_path_ctx_t *
sb_add_path(sb_fixture_t *f, uint64_t path_id, xqc_usec_t srtt_us,
            xqc_app_path_status_t status)
{
    CU_ASSERT_FATAL(f->n_paths < SB_MAX_PATHS);
    int i = f->n_paths++;
    xqc_path_ctx_t *p = &f->paths[i];
    xqc_send_ctl_t *ctl = &f->send_ctls[i];
    sb_mock_cong_t *cs = &f->cong[i];

    memset(p, 0, sizeof(*p));
    memset(ctl, 0, sizeof(*ctl));
    cs->cwnd_bytes = 10 * 1024 * 1024;
    cs->bandwidth_Bps = 10 * 1024 * 1024;

    p->path_id = path_id;
    p->path_state = XQC_PATH_STATE_ACTIVE;
    p->app_path_status = status;
    p->path_weight = 1;
    p->path_send_ctl = ctl;
    p->parent_conn = &f->conn;

    ctl->ctl_path = p;
    ctl->ctl_conn = &f->conn;
    ctl->ctl_srtt = srtt_us;
    ctl->ctl_cong = cs;
    ctl->ctl_cong_callback = &SB_MOCK_CC;
    ctl->ctl_delivered_time = sb_now_us;

    xqc_list_add_tail(&p->path_list, &f->conn.conn_paths_list);
    return p;
}

static void
sb_block_cwnd(sb_fixture_t *f, xqc_path_ctx_t *p)
{
    int i = (int)(p - f->paths);
    f->send_ctls[i].ctl_bytes_in_flight = (uint32_t)f->cong[i].cwnd_bytes;
}

typedef enum {
    SB_PKT_DATAGRAM,    /* po_flow_hash as given */
    SB_PKT_STREAM,
    SB_PKT_CONTROL,
} sb_pkt_kind_t;

static uint64_t
sb_invoke_full(sb_fixture_t *f, sb_pkt_kind_t kind, uint32_t flow_hash,
               uint8_t dscp, int reinject, uint64_t origin_path_id,
               xqc_bool_t *cc_blocked_out)
{
    xqc_packet_out_t po;
    memset(&po, 0, sizeof(po));
    po.po_used_size = 100;
    po.po_path_id = origin_path_id;
    po.po_dscp = dscp;
    switch (kind) {
    case SB_PKT_DATAGRAM:
        po.po_frame_types = XQC_FRAME_BIT_DATAGRAM;
        po.po_flow_hash = flow_hash;
        break;
    case SB_PKT_STREAM:
        po.po_frame_types = XQC_FRAME_BIT_STREAM;
        break;
    case SB_PKT_CONTROL:
        po.po_frame_types = XQC_FRAME_BIT_ACK;
        break;
    }

    xqc_bool_t cc_blocked = XQC_FALSE;
    xqc_path_ctx_t *p = f->cb->xqc_scheduler_get_path(
        f->scheduler, &f->conn, &po, /* check_cwnd */ 1, reinject, &cc_blocked);
    if (cc_blocked_out) {
        *cc_blocked_out = cc_blocked;
    }
    return p ? p->path_id : SB_NO_PATH;
}

static uint64_t
sb_invoke(sb_fixture_t *f, sb_pkt_kind_t kind, uint32_t flow_hash)
{
    return sb_invoke_full(f, kind, flow_hash, 0, 0, 0, NULL);
}

/* Count the packets of a mixed workload that land on path_id: unpinned
 * datagrams, eight pinned flows, STREAM and control packets. */
static int
sb_mixed_hits(sb_fixture_t *f, uint64_t path_id, int rounds)
{
    int hits = 0;
    for (int r = 0; r < rounds; r++) {
        hits += sb_invoke(f, SB_PKT_DATAGRAM, SB_FLOW_UNPINNED) == path_id;
        hits += sb_invoke(f, SB_PKT_DATAGRAM, 0x1000 + (uint32_t)(r % 8)) == path_id;
        hits += sb_invoke(f, SB_PKT_STREAM, 0) == path_id;
        hits += sb_invoke(f, SB_PKT_CONTROL, 0) == path_id;
        sb_now_us += 10000;
    }
    return hits;
}

void
xqc_test_standby_wlb_backup_idle_until_primary_lost(void)
{
    sb_fixture_t f;
    sb_setup(&f, &xqc_wlb_scheduler_cb);

    /* the backup has the lower RTT: only its status keeps it idle */
    xqc_path_ctx_t *primary = sb_add_path(&f, 0, 20000, XQC_APP_PATH_STATUS_AVAILABLE);
    xqc_path_ctx_t *backup = sb_add_path(&f, 1, 10000, XQC_APP_PATH_STATUS_STANDBY);
    (void)backup;

    CU_ASSERT_EQUAL(sb_mixed_hits(&f, 1, SB_ROUNDS), 0);

    /* primary gone: the standby path takes everything */
    xqc_list_del_init(&primary->path_list);
    CU_ASSERT_EQUAL(sb_mixed_hits(&f, 1, SB_ROUNDS), 4 * SB_ROUNDS);

    /* primary back: the standby path is idle again, pins included */
    xqc_list_add_tail(&primary->path_list, &f.conn.conn_paths_list);
    CU_ASSERT_EQUAL(sb_mixed_hits(&f, 1, SB_ROUNDS), 0);

    /* demoted rather than removed: an ACTIVE but FROZEN primary does not
     * hold the standby path back */
    primary->app_path_status = XQC_APP_PATH_STATUS_FROZEN;
    CU_ASSERT_EQUAL(sb_mixed_hits(&f, 1, SB_ROUNDS), 4 * SB_ROUNDS);

    sb_teardown(&f);
}

void
xqc_test_standby_wlb_pinned_flow_leaves_path_turning_standby(void)
{
    sb_fixture_t f;
    sb_setup(&f, &xqc_wlb_scheduler_cb);

    sb_add_path(&f, 0, 20000, XQC_APP_PATH_STATUS_AVAILABLE);
    xqc_path_ctx_t *p1 = sb_add_path(&f, 1, 20000, XQC_APP_PATH_STATUS_AVAILABLE);

    /* pin 16 flows across both paths (equal weights alternate pins) */
    int on_p1 = 0;
    for (uint32_t h = 0; h < 16; h++) {
        (void)sb_invoke(&f, SB_PKT_DATAGRAM, 0x2000 + h);
    }
    for (uint32_t h = 0; h < 16; h++) {
        on_p1 += sb_invoke(&f, SB_PKT_DATAGRAM, 0x2000 + h) == 1;
    }
    CU_ASSERT(on_p1 > 0);

    p1->app_path_status = XQC_APP_PATH_STATUS_STANDBY;
    for (int r = 0; r < 4; r++) {
        for (uint32_t h = 0; h < 16; h++) {
            CU_ASSERT_EQUAL(sb_invoke(&f, SB_PKT_DATAGRAM, 0x2000 + h), 0);
        }
        sb_now_us += 500000;
    }

    sb_teardown(&f);
}

void
xqc_test_standby_wlb_blocked_primary_does_not_spill(void)
{
    sb_fixture_t f;
    sb_setup(&f, &xqc_wlb_scheduler_cb);

    xqc_path_ctx_t *primary = sb_add_path(&f, 0, 20000, XQC_APP_PATH_STATUS_AVAILABLE);
    sb_add_path(&f, 1, 20000, XQC_APP_PATH_STATUS_STANDBY);
    sb_block_cwnd(&f, primary);

    xqc_bool_t cc_blocked = XQC_FALSE;
    CU_ASSERT_EQUAL(sb_invoke_full(&f, SB_PKT_DATAGRAM, SB_FLOW_UNPINNED, 0, 0, 0,
                                   &cc_blocked), SB_NO_PATH);
    CU_ASSERT_TRUE(cc_blocked);
    cc_blocked = XQC_FALSE;
    CU_ASSERT_EQUAL(sb_invoke_full(&f, SB_PKT_DATAGRAM, 0x3000, 0, 0, 0,
                                   &cc_blocked), SB_NO_PATH);
    CU_ASSERT_TRUE(cc_blocked);
    cc_blocked = XQC_FALSE;
    CU_ASSERT_EQUAL(sb_invoke_full(&f, SB_PKT_STREAM, 0, 0, 0, 0, &cc_blocked),
                    SB_NO_PATH);
    CU_ASSERT_TRUE(cc_blocked);

    sb_teardown(&f);
}

void
xqc_test_standby_wlb_reinject_may_use_standby(void)
{
    sb_fixture_t f;
    sb_setup(&f, &xqc_wlb_scheduler_cb);

    sb_add_path(&f, 0, 20000, XQC_APP_PATH_STATUS_AVAILABLE);
    sb_add_path(&f, 1, 20000, XQC_APP_PATH_STATUS_STANDBY);

    CU_ASSERT_EQUAL(sb_invoke_full(&f, SB_PKT_STREAM, 0, 0, 1, 0, NULL), 1);
    CU_ASSERT_EQUAL(sb_invoke_full(&f, SB_PKT_DATAGRAM, 0x4000, 0, 1, 0, NULL), 1);
    /* and a non-reinjected packet right after still avoids it */
    CU_ASSERT_EQUAL(sb_invoke(&f, SB_PKT_STREAM, 0), 0);

    sb_teardown(&f);
}

static int
sb_unpinned_hits(sb_fixture_t *f, uint64_t path_id, int n)
{
    int hits = 0;
    for (int i = 0; i < n; i++) {
        hits += sb_invoke(f, SB_PKT_DATAGRAM, SB_FLOW_UNPINNED) == path_id;
    }
    return hits;
}

static void
sb_perf_class_case(const xqc_scheduler_callback_t *cb)
{
    sb_fixture_t f;

    /* available path LOW (failing: srtt above rtt_us_thr_high), standby
     * HIGH: the standby path is the better class and is used */
    sb_setup(&f, cb);
    sb_add_path(&f, 0, 3000000, XQC_APP_PATH_STATUS_AVAILABLE);
    sb_add_path(&f, 1, 20000, XQC_APP_PATH_STATUS_STANDBY);
    CU_ASSERT_EQUAL(sb_invoke(&f, SB_PKT_STREAM, 0), 1);
    CU_ASSERT(sb_unpinned_hits(&f, 1, 20) > 0);
    sb_teardown(&f);

    /* available path MID because loaded (srtt above 3x the connection's
     * min srtt, which the idle standby path sets), standby HIGH: held back,
     * unlike under the backup scheduler */
    sb_setup(&f, cb);
    sb_add_path(&f, 0, 40000, XQC_APP_PATH_STATUS_AVAILABLE);
    sb_add_path(&f, 1, 10000, XQC_APP_PATH_STATUS_STANDBY);
    CU_ASSERT_EQUAL(sb_invoke(&f, SB_PKT_STREAM, 0), 0);
    CU_ASSERT_EQUAL(sb_unpinned_hits(&f, 1, 20), 0);
    sb_teardown(&f);

    /* available path MID because slow (bandwidth estimate under
     * bw_Bps_thr), standby HIGH: held back */
    sb_setup(&f, cb);
    sb_add_path(&f, 0, 20000, XQC_APP_PATH_STATUS_AVAILABLE);
    sb_add_path(&f, 1, 20000, XQC_APP_PATH_STATUS_STANDBY);
    f.cong[0].bandwidth_Bps = 100000;
    CU_ASSERT_EQUAL(sb_invoke(&f, SB_PKT_STREAM, 0), 0);
    CU_ASSERT_EQUAL(sb_unpinned_hits(&f, 1, 20), 0);
    sb_teardown(&f);

    /* both MID (a FROZEN path still sets the min srtt): held back */
    sb_setup(&f, cb);
    sb_add_path(&f, 0, 40000, XQC_APP_PATH_STATUS_AVAILABLE);
    sb_add_path(&f, 1, 35000, XQC_APP_PATH_STATUS_STANDBY);
    sb_add_path(&f, 2, 10000, XQC_APP_PATH_STATUS_FROZEN);
    CU_ASSERT_EQUAL(sb_invoke(&f, SB_PKT_STREAM, 0), 0);
    CU_ASSERT_EQUAL(sb_unpinned_hits(&f, 1, 20), 0);
    sb_teardown(&f);

    /* both LOW: the available path holds the standby path back */
    sb_setup(&f, cb);
    sb_add_path(&f, 0, 3000000, XQC_APP_PATH_STATUS_AVAILABLE);
    sb_add_path(&f, 1, 2500000, XQC_APP_PATH_STATUS_STANDBY);
    CU_ASSERT_EQUAL(sb_invoke(&f, SB_PKT_STREAM, 0), 0);
    CU_ASSERT_EQUAL(sb_unpinned_hits(&f, 1, 20), 0);
    sb_teardown(&f);
}

void
xqc_test_standby_perf_class_rule(void)
{
    sb_perf_class_case(&xqc_wlb_scheduler_cb);
    sb_perf_class_case(&xqc_minrtt_scheduler_cb);
}

static void
sb_other_case(const xqc_scheduler_callback_t *cb)
{
    sb_fixture_t f;
    sb_setup(&f, cb);

    xqc_path_ctx_t *primary = sb_add_path(&f, 0, 20000, XQC_APP_PATH_STATUS_AVAILABLE);
    xqc_path_ctx_t *backup = sb_add_path(&f, 1, 10000, XQC_APP_PATH_STATUS_STANDBY);
    /* everything that would otherwise favour the backup */
    backup->path_weight = 10;
    backup->path_dscp_mask = 1ULL << 10;

    for (int r = 0; r < 50; r++) {
        CU_ASSERT_EQUAL(sb_invoke(&f, SB_PKT_DATAGRAM, SB_FLOW_UNPINNED), 0);
        CU_ASSERT_EQUAL(sb_invoke(&f, SB_PKT_DATAGRAM, 0x5000 + (uint32_t)r), 0);
        CU_ASSERT_EQUAL(sb_invoke_full(&f, SB_PKT_DATAGRAM, 0x5000, 10, 0, 0, NULL), 0);
        CU_ASSERT_EQUAL(sb_invoke(&f, SB_PKT_STREAM, 0), 0);
        CU_ASSERT_EQUAL(sb_invoke(&f, SB_PKT_CONTROL, 0), 0);
    }

    /* reinjection off the primary may use the standby path */
    CU_ASSERT_EQUAL(sb_invoke_full(&f, SB_PKT_STREAM, 0, 0, 1, 0, NULL), 1);

    /* only standby paths left: they carry data */
    xqc_list_del_init(&primary->path_list);
    CU_ASSERT_EQUAL(sb_invoke(&f, SB_PKT_DATAGRAM, SB_FLOW_UNPINNED), 1);
    CU_ASSERT_EQUAL(sb_invoke_full(&f, SB_PKT_DATAGRAM, 0x5000, 10, 0, 0, NULL), 1);
    CU_ASSERT_EQUAL(sb_invoke(&f, SB_PKT_STREAM, 0), 1);

    sb_teardown(&f);
}

void
xqc_test_standby_other_schedulers(void)
{
    sb_other_case(&xqc_minrtt_scheduler_cb);
    sb_other_case(&xqc_wrr_scheduler_cb);
    sb_other_case(&xqc_wrtt_scheduler_cb);
    sb_other_case(&xqc_dscp_scheduler_cb);
    sb_other_case(&xqc_rap_scheduler_cb);
}
