/**
 * @copyright Copyright (c) 2026, mp0rta
 *
 * WLB (Weighted Load Balancing) multipath scheduler for QUIC Datagrams.
 *
 * Key difference from MinRTT: packets belonging to the same inner flow
 * (identified by po_flow_hash) are pinned to the same QUIC path.  This
 * prevents TCP reordering inside VPN tunnels while still aggregating
 * bandwidth across paths via weighted round-robin of flows.
 *
 * Algorithm:
 *   1. Compute real-time weights for all active paths using an iterative
 *      LATE model (Yang 2021) simplified for unreliable datagrams:
 *      no FR/RTO categories, expected-value cwnd update per round.
 *   2. Distribute packets via OLB round-based WRR (deficit counter).
 *   3. Pin inner flows to paths via hash table to prevent TCP reordering.
 *   4. If no path can send (all cwnd-blocked), fall back to MinRTT.
 *
 * References:
 *   - OLB: "Optimal Load Balancing", Computer Communications, 2017
 *   - LATE: "Loss-Aware Throughput Estimation", IEEE TWC, 2021
 */

#include "src/transport/scheduler/xqc_scheduler_wlb.h"
#include "src/transport/scheduler/xqc_scheduler_common.h"
#include "src/transport/xqc_send_ctl.h"
#include "src/transport/xqc_multipath.h"
#include "src/common/xqc_time.h"
#include <stdlib.h>

/* ---------- constants ---------- */

#define WLB_MAX_PATHS         XQC_MAX_PATHS_COUNT
#define LATE_MSS              1200    /* typical QUIC datagram payload bytes */

/* Flow table — open-addressing hash table for flow-to-path pinning */
#define WLB_FLOW_TABLE_SIZE   4096
#define WLB_FLOW_TABLE_MASK   (WLB_FLOW_TABLE_SIZE - 1)
#define WLB_MAX_PROBE         16      /* linear probe limit */
#define WLB_FLOW_EXPIRE_US    (60ULL * 1000000)  /* 60 s idle expiry */

/* ---------- data types ---------- */

/** Flow table entry — maps an inner-flow hash to a QUIC path. */
typedef struct {
    uint32_t    hash;       /* 0 = empty slot */
    uint64_t    path_id;
    uint64_t    last_ts;    /* last-used timestamp (usec) */
} wlb_flow_entry_t;

/** Per-path WRR state. */
typedef struct {
    uint64_t    path_id;
    uint64_t    weight;     /* LATE estimated throughput (scaled ×1000) */
    int64_t     deficit;    /* WRR deficit counter */
} wlb_path_weight_t;

/** Top-level scheduler state, allocated by xquic via xqc_wlb_scheduler_size(). */
typedef struct {
    wlb_path_weight_t   paths[WLB_MAX_PATHS];
    int                  n_paths;
    wlb_flow_entry_t    *flows;          /* heap-allocated flow table */
    uint64_t             last_expire_ts;  /* throttle expire scans to 1/sec */
    xqc_log_t           *log;
} xqc_wlb_scheduler_t;

/* ================================================================
 *  Flow table helpers
 *
 *  Open-addressing hash table with linear probing.  Entries expire
 *  after WLB_FLOW_EXPIRE_US of inactivity (scanned at most once/sec).
 * ================================================================ */

/**
 * Look up a flow by its hash.
 * Returns the matching entry, or NULL if not found within the probe window.
 */
static wlb_flow_entry_t *
wlb_flow_lookup(xqc_wlb_scheduler_t *s, uint32_t hash)
{
    if (hash == 0 || !s->flows) {
        return NULL;
    }
    uint32_t idx = hash & WLB_FLOW_TABLE_MASK;
    for (int i = 0; i < WLB_MAX_PROBE; i++) {
        wlb_flow_entry_t *e = &s->flows[(idx + i) & WLB_FLOW_TABLE_MASK];
        if (e->hash == hash) {
            return e;
        }
        if (e->hash == 0) {
            return NULL;
        }
    }
    return NULL;
}

/**
 * Insert or update a flow→path mapping.
 * On probe-region exhaustion, overwrites the first slot (LRU-ish eviction).
 */
static void
wlb_flow_insert(xqc_wlb_scheduler_t *s, uint32_t hash, uint64_t path_id, uint64_t now_us)
{
    if (hash == 0 || !s->flows) {
        return;
    }
    uint32_t idx = hash & WLB_FLOW_TABLE_MASK;
    for (int i = 0; i < WLB_MAX_PROBE; i++) {
        wlb_flow_entry_t *e = &s->flows[(idx + i) & WLB_FLOW_TABLE_MASK];
        if (e->hash == 0 || e->hash == hash) {
            e->hash    = hash;
            e->path_id = path_id;
            e->last_ts = now_us;
            return;
        }
    }
    /* Probe region full — overwrite first slot */
    wlb_flow_entry_t *e = &s->flows[idx];
    e->hash    = hash;
    e->path_id = path_id;
    e->last_ts = now_us;
}

/**
 * Expire idle flow entries.  Scans the full table at most once per second
 * to amortize cost.
 */
static void
wlb_flow_expire(xqc_wlb_scheduler_t *s, uint64_t now_us)
{
    if (!s->flows || (now_us - s->last_expire_ts) < 1000000) {
        return;
    }
    s->last_expire_ts = now_us;
    for (int i = 0; i < WLB_FLOW_TABLE_SIZE; i++) {
        wlb_flow_entry_t *e = &s->flows[i];
        if (e->hash != 0 && (now_us - e->last_ts) > WLB_FLOW_EXPIRE_US) {
            e->hash = 0;
        }
    }
}

/* ---------- path helpers ---------- */

/** Find an active, non-frozen path context by path_id. */
static xqc_path_ctx_t *
wlb_find_path_ctx(xqc_connection_t *conn, uint64_t path_id)
{
    xqc_list_head_t *pos, *next;
    xqc_path_ctx_t  *path;
    xqc_list_for_each_safe(pos, next, &conn->conn_paths_list) {
        path = xqc_list_entry(pos, xqc_path_ctx_t, path_list);
        if (path->path_id == path_id
            && path->path_state == XQC_PATH_STATE_ACTIVE
            && path->app_path_status != XQC_APP_PATH_STATUS_FROZEN)
        {
            return path;
        }
    }
    return NULL;
}

/* ================================================================
 *  LATE throughput estimation — Datagram-simplified iterative model
 *
 *  QUIC Datagrams are unreliable: no FR/RTO at the QUIC layer.
 *  Instead of 3-category recursive splitting, we use an iterative
 *  per-round model with expected-value cwnd updates:
 *
 *    Each round:
 *      delivered += w * (1 - loss)
 *      p_no_loss  = (1 - loss)^w
 *      w_next     = p_no_loss * grow(w) + (1 - p_no_loss) * max(w/2, 1)
 * ================================================================ */

/**
 * Compute base^n via binary exponentiation (no libm dependency).
 */
static double
late_ipow(double base, int n)
{
    if (n <= 0) {
        return 1.0;
    }
    double result = 1.0;
    double b = base;
    int e = n;
    while (e > 0) {
        if (e & 1) {
            result *= b;
        }
        b *= b;
        e >>= 1;
    }
    return result;
}

/**
 * Iterative LATE estimate for QUIC Datagrams, aligned with BBR2+ behavior.
 *
 * Returns expected number of packets delivered within time budget T.
 * Models per-round binomial loss with expected-value cwnd transitions
 * (no FR/RTO since datagrams are unreliable).
 *
 * BBR2+ alignment (xqc_bbr2.c):
 *   - loss_thresh = 0.02: loss below 2% is tolerated (no cwnd reduction)
 *   - beta = 0.3: cwnd shrinks to 70% on loss (not 50% like Reno)
 *   - fast_convergence: lower bounds reset every 5-9 RTTs, so we cap
 *     the number of loss-reduction rounds to avoid compounding beyond
 *     what BBR2+ actually sustains
 *
 * @param T_us      time budget (microseconds)
 * @param rtt_us    path RTT (microseconds)
 * @param cwnd      congestion window (packets)
 * @param ssthresh  slow-start threshold (packets)
 * @param loss      per-packet loss probability [0, 1]
 */
static double
late_estimate_dgram(double T_us, double rtt_us,
                    int cwnd, int ssthresh, double loss)
{
    if (T_us <= 0.0 || cwnd <= 0 || rtt_us <= 0.0) {
        return 0.0;
    }
    if (loss < 0.0) loss = 0.0;
    if (loss > 1.0) loss = 1.0;

    /* BBR2 tolerates up to 2% random loss without reducing (xqc_bbr2_loss_thresh) */
    if (loss < 0.02) {
        loss = 0.0;
    }

    /* T < RTT/2 — nothing delivered */
    if (T_us < rtt_us / 2.0) {
        return 0.0;
    }

    double N = 0.0;
    double w = (double)cwnd;
    double sst = (double)ssthresh;
    double remaining = T_us;
    int rounds = 0;

    /*
     * BBR2+ fast_convergence resets bw_lo/inflight_lo every 5-9 RTTs
     * (xqc_bbr2_fast_convergence_probe_round_base=4, rand=4).
     * Cap loss-reduction rounds to 7 (midpoint) to prevent unrealistic
     * compounding beyond a single probe cycle.
     */
    const int max_loss_rounds = 7;

    while (remaining >= rtt_us / 2.0 && w >= 0.5) {
        /* Packets delivered this round: E[successes] = w·(1-l) */
        N += w * (1.0 - loss);

        /* Probability of zero loss this round */
        double p_no_loss = late_ipow(1.0 - loss, (int)(w + 0.5));
        double p_loss = 1.0 - p_no_loss;

        /* cwnd growth (no loss): SS doubles, CA increments */
        double w_grow;
        if (w < sst) {
            w_grow = 2.0 * w;
            if (w_grow > sst) w_grow = sst;
        } else {
            w_grow = w + 1.0;
        }

        /*
         * cwnd shrink (loss): BBR2 beta=0.3 → retain 70%
         * (xqc_bbr2_inflight_lo_beta = 0.3, applied as 1-beta = 0.7)
         *
         * After max_loss_rounds, stop compounding shrink — BBR2+ would
         * have reset lower bounds and re-probed by then.
         */
        double w_shrink;
        if (rounds < max_loss_rounds) {
            w_shrink = w * 0.7;
        } else {
            w_shrink = w;  /* no further reduction after reset cycle */
        }
        if (w_shrink < 1.0) w_shrink = 1.0;

        /* Expected-value cwnd for next round */
        double w_next = p_no_loss * w_grow + p_loss * w_shrink;
        double sst_next = p_no_loss * sst + p_loss * w_shrink;

        w = w_next;
        sst = sst_next;
        remaining -= rtt_us;
        rounds++;
    }

    return N;
}

/**
 * Compute LATE weight for a path.
 *
 * @param path         the path to evaluate
 * @param max_rtt_us   maximum SRTT across all active paths (microseconds)
 * @return weight proportional to estimated throughput (scaled ×1000)
 */
static uint64_t
wlb_compute_weight(xqc_path_ctx_t *path, uint64_t max_rtt_us)
{
    xqc_send_ctl_t *ctl = path->path_send_ctl;

    uint64_t srtt_us = xqc_send_ctl_get_srtt(ctl);
    if (srtt_us == 0) {
        return 1;
    }

    /* cwnd in packets */
    uint64_t cwnd_bytes = ctl->ctl_cong_callback->xqc_cong_ctl_get_cwnd(ctl->ctl_cong);
    int cwnd_pkts = (int)(cwnd_bytes / LATE_MSS);
    if (cwnd_pkts < 1) cwnd_pkts = 1;

    /* ssthresh: BBR2 has no traditional ssthresh.
     * Use 2×cwnd so LATE's SS phase models BBR2's probing headroom. */
    int ssthresh = cwnd_pkts * 2;

    /* Loss probability [0, 1] */
    double loss = xqc_path_recent_loss_rate(path) / 100.0;
    if (loss < 0.0) loss = 0.0;
    if (loss > 1.0) loss = 1.0;

    /* Time budget: max_rtt / 2 (LATE scheduling window) */
    double T_us = (double)max_rtt_us / 2.0;
    if (T_us < (double)srtt_us) {
        T_us = (double)srtt_us;     /* ensure at least 1 RTT of budget */
    }

    double N = late_estimate_dgram(T_us, (double)srtt_us,
                                   cwnd_pkts, ssthresh, loss);

    /* Scale ×1000 to preserve precision in integer weight */
    uint64_t weight = (uint64_t)(N * 1000.0);
    return weight > 0 ? weight : 1;
}

/* ================================================================
 *  WRR scheduling
 *
 *  OLB-style deficit-counter WRR.  Each round adds a normalized quantum
 *  (weight / min_weight) to each path's deficit.  The path with the
 *  highest positive deficit is selected and its deficit decremented.
 *  When all deficits are exhausted, a new round begins and LATE weights
 *  are recomputed from real-time path metrics.
 * ================================================================ */

/**
 * Refresh path list and LATE weights from real-time metrics.
 * Deficit counters are preserved for paths that already existed (by path_id).
 */
static void
wlb_refresh_paths(xqc_wlb_scheduler_t *s, xqc_connection_t *conn)
{
    xqc_list_head_t *pos, *next;
    xqc_path_ctx_t  *path;

    /* Save old state for deficit preservation */
    wlb_path_weight_t old[WLB_MAX_PATHS];
    int old_n = s->n_paths;
    memcpy(old, s->paths, sizeof(wlb_path_weight_t) * old_n);

    /* First pass: find max SRTT across active paths */
    uint64_t max_rtt_us = 0;
    xqc_list_for_each_safe(pos, next, &conn->conn_paths_list) {
        path = xqc_list_entry(pos, xqc_path_ctx_t, path_list);
        if (path->path_state != XQC_PATH_STATE_ACTIVE
            || path->app_path_status == XQC_APP_PATH_STATUS_FROZEN)
        {
            continue;
        }
        uint64_t srtt = xqc_send_ctl_get_srtt(path->path_send_ctl);
        if (srtt > max_rtt_us) {
            max_rtt_us = srtt;
        }
    }
    if (max_rtt_us == 0) {
        max_rtt_us = 50000;  /* 50ms default */
    }

    /* Second pass: compute LATE weights and build path list */
    int n = 0;
    xqc_list_for_each_safe(pos, next, &conn->conn_paths_list) {
        path = xqc_list_entry(pos, xqc_path_ctx_t, path_list);
        if (path->path_state != XQC_PATH_STATE_ACTIVE
            || path->app_path_status == XQC_APP_PATH_STATUS_FROZEN)
        {
            continue;
        }
        if (n >= WLB_MAX_PATHS) {
            break;
        }
        s->paths[n].path_id = path->path_id;
        s->paths[n].weight  = wlb_compute_weight(path, max_rtt_us);

        /* Preserve deficit for existing paths */
        s->paths[n].deficit = 0;
        for (int j = 0; j < old_n; j++) {
            if (old[j].path_id == path->path_id) {
                s->paths[n].deficit = old[j].deficit;
                break;
            }
        }
        n++;
    }
    s->n_paths = n;
}

/**
 * Check if all paths have exhausted their deficit (round complete).
 */
static xqc_bool_t
wlb_needs_new_round(xqc_wlb_scheduler_t *s)
{
    for (int i = 0; i < s->n_paths; i++) {
        if (s->paths[i].deficit > 0) {
            return XQC_FALSE;
        }
    }
    return XQC_TRUE;
}

/**
 * Start a new WRR round: add normalized weight quantum to deficit counters.
 * Weights are normalized so that min_weight maps to 1.
 */
static void
wlb_start_round(xqc_wlb_scheduler_t *s)
{
    if (s->n_paths == 0) {
        return;
    }

    uint64_t min_w = UINT64_MAX;
    for (int i = 0; i < s->n_paths; i++) {
        if (s->paths[i].weight < min_w) {
            min_w = s->paths[i].weight;
        }
    }
    if (min_w == 0) {
        min_w = 1;
    }

    for (int i = 0; i < s->n_paths; i++) {
        int64_t quantum = (int64_t)(s->paths[i].weight / min_w);
        if (quantum < 1) {
            quantum = 1;
        }
        s->paths[i].deficit += quantum;
    }
}

/**
 * WRR: select the path with the highest deficit that can send.
 */
static uint64_t
wlb_wrr_select(xqc_wlb_scheduler_t *s, xqc_connection_t *conn,
                xqc_packet_out_t *packet_out, int check_cwnd)
{
    int best = -1;
    int64_t best_deficit = INT64_MIN;

    for (int i = 0; i < s->n_paths; i++) {
        xqc_path_ctx_t *path = wlb_find_path_ctx(conn, s->paths[i].path_id);
        if (path == NULL) {
            continue;
        }
        if (check_cwnd && !xqc_scheduler_check_path_can_send(path, packet_out, check_cwnd)) {
            continue;
        }
        if (s->paths[i].deficit > best_deficit) {
            best_deficit = s->paths[i].deficit;
            best = i;
        }
    }

    if (best >= 0) {
        s->paths[best].deficit -= 1;
        return s->paths[best].path_id;
    }
    return UINT64_MAX;
}

/* ================================================================
 *  MinRTT fallback
 *
 *  Used for non-datagram packets (po_flow_hash == 0) and when WRR
 *  has no active paths.  Selects the path with the lowest SRTT that
 *  has cwnd headroom.
 * ================================================================ */

static xqc_path_ctx_t *
wlb_minrtt_fallback(xqc_connection_t *conn, xqc_packet_out_t *packet_out,
                     int check_cwnd, int reinject, xqc_bool_t *cc_blocked)
{
    xqc_path_ctx_t *best_path = NULL;
    uint64_t best_srtt = UINT64_MAX;
    xqc_bool_t reached_cwnd_check = XQC_FALSE;
    xqc_list_head_t *pos, *next;
    xqc_path_ctx_t *path;

    if (cc_blocked) {
        *cc_blocked = XQC_FALSE;
    }

    xqc_list_for_each_safe(pos, next, &conn->conn_paths_list) {
        path = xqc_list_entry(pos, xqc_path_ctx_t, path_list);

        if (path->path_state != XQC_PATH_STATE_ACTIVE
            || path->app_path_status == XQC_APP_PATH_STATUS_FROZEN
            || (reinject && (packet_out->po_path_id == path->path_id)))
        {
            continue;
        }

        if (!reached_cwnd_check) {
            reached_cwnd_check = XQC_TRUE;
            if (cc_blocked) {
                *cc_blocked = XQC_TRUE;
            }
        }

        if (!xqc_scheduler_check_path_can_send(path, packet_out, check_cwnd)) {
            continue;
        }

        if (cc_blocked) {
            *cc_blocked = XQC_FALSE;
        }

        uint64_t srtt = xqc_send_ctl_get_srtt(path->path_send_ctl);
        if (srtt < best_srtt) {
            best_srtt = srtt;
            best_path = path;
        }
    }
    return best_path;
}

/* ================================================================
 *  Scheduler callback interface
 * ================================================================ */

static size_t
xqc_wlb_scheduler_size(void)
{
    return sizeof(xqc_wlb_scheduler_t);
}

static void
xqc_wlb_scheduler_init(void *scheduler, xqc_log_t *log, xqc_scheduler_params_t *param)
{
    xqc_wlb_scheduler_t *s = (xqc_wlb_scheduler_t *)scheduler;
    memset(s, 0, sizeof(*s));
    s->log = log;
    s->flows = calloc(WLB_FLOW_TABLE_SIZE, sizeof(wlb_flow_entry_t));
}

/**
 * Main scheduling entry point.
 *
 * 1. Non-datagram packets (po_flow_hash == 0) → MinRTT fallback.
 * 2. Check flow table for an existing pinning — reuse if path is available.
 * 3. Otherwise, WRR selects a new path and pins the flow to it.
 */
static xqc_path_ctx_t *
xqc_wlb_scheduler_get_path(void *scheduler,
    xqc_connection_t *conn, xqc_packet_out_t *packet_out,
    int check_cwnd, int reinject, xqc_bool_t *cc_blocked)
{
    xqc_wlb_scheduler_t *s = (xqc_wlb_scheduler_t *)scheduler;

    /* Non-datagram packets → MinRTT fallback */
    if (packet_out->po_flow_hash == 0) {
        return wlb_minrtt_fallback(conn, packet_out, check_cwnd, reinject, cc_blocked);
    }

    if (cc_blocked) {
        *cc_blocked = XQC_FALSE;
    }

    uint64_t now_us = xqc_monotonic_timestamp();

    /* Flow table lookup — reuse existing flow→path pinning */
    wlb_flow_expire(s, now_us);

    wlb_flow_entry_t *entry = wlb_flow_lookup(s, packet_out->po_flow_hash);
    if (entry) {
        xqc_path_ctx_t *path = wlb_find_path_ctx(conn, entry->path_id);
        if (path && xqc_scheduler_check_path_can_send(path, packet_out, check_cwnd)) {
            entry->last_ts = now_us;
            return path;
        }
        /* Sticky path unavailable — will reassign below */
    }

    /* Start new WRR round if current round is exhausted.
     * Recompute LATE weights from real-time metrics at round boundary. */
    if (wlb_needs_new_round(s)) {
        wlb_refresh_paths(s, conn);
        wlb_start_round(s);
    }

    if (s->n_paths == 0) {
        return wlb_minrtt_fallback(conn, packet_out, check_cwnd, reinject, cc_blocked);
    }

    /* Single active path — skip WRR overhead */
    if (s->n_paths == 1) {
        xqc_path_ctx_t *path = wlb_find_path_ctx(conn, s->paths[0].path_id);
        if (path && xqc_scheduler_check_path_can_send(path, packet_out, check_cwnd)) {
            wlb_flow_insert(s, packet_out->po_flow_hash, path->path_id, now_us);
            return path;
        }
        if (cc_blocked) {
            *cc_blocked = XQC_TRUE;
        }
        return NULL;
    }

    /* WRR assignment — pin this flow to the selected path */
    uint64_t sel_path_id = wlb_wrr_select(s, conn, packet_out, check_cwnd);
    if (sel_path_id != UINT64_MAX) {
        wlb_flow_insert(s, packet_out->po_flow_hash, sel_path_id, now_us);
        xqc_path_ctx_t *path = wlb_find_path_ctx(conn, sel_path_id);
        xqc_log(conn->log, XQC_LOG_DEBUG,
                 "|wlb|select|path_id:%ui|n_paths:%d|",
                 sel_path_id, s->n_paths);
        return path;
    }

    /* All paths cwnd-blocked */
    if (cc_blocked) {
        *cc_blocked = XQC_TRUE;
    }
    return NULL;
}

static void
xqc_wlb_scheduler_handle_path_event(void *scheduler,
    xqc_path_ctx_t *path, xqc_scheduler_path_event_t event, void *event_arg)
{
    /* No action needed — weights are recomputed at round boundary */
}

static void
xqc_wlb_scheduler_handle_conn_event(void *scheduler,
    xqc_connection_t *conn, xqc_scheduler_conn_event_t event, void *event_arg)
{
    /* No action needed */
}

const xqc_scheduler_callback_t xqc_wlb_scheduler_cb = {
    .xqc_scheduler_size             = xqc_wlb_scheduler_size,
    .xqc_scheduler_init             = xqc_wlb_scheduler_init,
    .xqc_scheduler_get_path         = xqc_wlb_scheduler_get_path,
    .xqc_scheduler_handle_path_event = xqc_wlb_scheduler_handle_path_event,
    .xqc_scheduler_handle_conn_event = xqc_wlb_scheduler_handle_conn_event,
};
