/**
 * @copyright Copyright (c) 2026, mp0rta
 *
 * WRR (Weighted Round Robin) multipath scheduler.
 *
 * Smooth weighted round-robin (the algorithm behind nginx's weighted
 * upstream balancer and LVS): every call, each usable path accrues
 *
 *     current_weight += weight
 *
 * and the sendable path with the highest current_weight is chosen, then
 * has the round's total_weight subtracted back off:
 *
 *     chosen->current_weight -= total_weight
 *
 * This interleaves selections in proportion to weight instead of bursting
 * (weights 3:1 give "A A B A A A B ..." rather than "AAA B AAA B ..."),
 * which is what distinguishes WRR from WRTT: WRTT always drains the single
 * highest-weight path until it is cwnd-blocked before ever trying another;
 * WRR spreads load across paths continuously according to the weight
 * ratio, which is usually the better fit when weights represent known
 * relative link capacity rather than a strict preference order.
 *
 * A path that is usable but temporarily cwnd-blocked still accrues
 * current_weight — it isn't selected, but it keeps its place in the
 * rotation and catches up once headroom frees up, so a transient stall on
 * one path doesn't cost it its share of the long-run distribution.
 *
 * Per-path state (current_weight) is kept in the scheduler's heap-allocated
 * block, keyed by path_id, and is rebuilt against the live path list on
 * every call: paths no longer present are dropped, newly seen paths start
 * at current_weight=0.
 *
 * Non-datagram QUIC packets (po_flow_hash == 0) use plain MinRTT and do not
 * touch the WRR state, so control traffic (ACKs, handshake) always takes
 * the lowest-latency path instead of being spread thin by the rotation.
 *
 * Weights are read live from path->path_weight on every call (same field
 * WRTT uses, set via xqc_conn_set_path_weight()). weight=0 is treated as
 * weight=1 (equal priority).
 */

#include "src/transport/scheduler/xqc_scheduler_wrr.h"
#include "src/transport/scheduler/xqc_scheduler_common.h"
#include "src/transport/xqc_send_ctl.h"
#include "src/transport/xqc_multipath.h"

#define WRR_PTO_SKIP_THRESH  3   /* skip paths with >= 3 consecutive PTOs */
#define WRR_MAX_PATHS        XQC_PATH_HARD_CAP

/* ------------------------------------------------------------------ */

typedef struct {
    uint64_t     path_id;
    int64_t      current_weight;
    xqc_bool_t   seen;   /* scratch flag, valid only during one wrr_select() call */
} wrr_path_state_t;

typedef struct {
    wrr_path_state_t paths[WRR_MAX_PATHS];
    int               n_paths;
} xqc_wrr_scheduler_t;

static size_t
xqc_wrr_scheduler_size(void)
{
    return sizeof(xqc_wrr_scheduler_t);
}

static void
xqc_wrr_scheduler_init(void *scheduler, xqc_log_t *log, xqc_scheduler_params_t *param)
{
    memset(scheduler, 0, sizeof(xqc_wrr_scheduler_t));
}

/* ------------------------------------------------------------------ */

static xqc_bool_t
wrr_path_is_usable(xqc_path_ctx_t *path, int reinject, xqc_packet_out_t *packet_out)
{
    return path->path_state == XQC_PATH_STATE_ACTIVE
        && path->app_path_status != XQC_APP_PATH_STATUS_FROZEN
        && !(path->path_flag & XQC_PATH_FLAG_SOCKET_ERROR)
        && !(path->path_send_ctl
             && path->path_send_ctl->ctl_pto_count >= WRR_PTO_SKIP_THRESH)
        && !(reinject && path->path_id == packet_out->po_path_id);
}

/* Find the persistent weight-state slot for path_id, creating one
 * (current_weight starting at 0) if this path hasn't been seen before. */
static wrr_path_state_t *
wrr_find_or_add(xqc_wrr_scheduler_t *s, uint64_t path_id)
{
    for (int i = 0; i < s->n_paths; i++) {
        if (s->paths[i].path_id == path_id) {
            return &s->paths[i];
        }
    }
    if (s->n_paths < WRR_MAX_PATHS) {
        wrr_path_state_t *e = &s->paths[s->n_paths++];
        e->path_id = path_id;
        e->current_weight = 0;
        return e;
    }
    return NULL;
}

/* Drop state entries for paths that no longer exist / weren't seen usable
 * this call, so churn (failover, reconnect) doesn't leak slots forever. */
static void
wrr_compact_unseen(xqc_wrr_scheduler_t *s)
{
    int kept = 0;
    for (int i = 0; i < s->n_paths; i++) {
        if (s->paths[i].seen) {
            if (kept != i) {
                s->paths[kept] = s->paths[i];
            }
            kept++;
        }
    }
    s->n_paths = kept;
}

/*
 * Smooth WRR pass: accrue weight on every usable path, then return the
 * highest-current_weight path among those that can currently send.
 */
static xqc_path_ctx_t *
wrr_select(xqc_wrr_scheduler_t *s, xqc_connection_t *conn,
           xqc_packet_out_t *packet_out, int check_cwnd, int reinject,
           xqc_bool_t *cc_blocked)
{
    for (int i = 0; i < s->n_paths; i++) {
        s->paths[i].seen = XQC_FALSE;
    }

    xqc_list_head_t *pos, *next;
    xqc_path_ctx_t   *path;
    xqc_path_ctx_t   *candidate       = NULL;
    wrr_path_state_t *candidate_state = NULL;
    int64_t           total_weight    = 0;
    xqc_bool_t        any_usable      = XQC_FALSE;
    xqc_bool_t        any_sendable    = XQC_FALSE;

    xqc_list_for_each_safe(pos, next, &conn->conn_paths_list) {
        path = xqc_list_entry(pos, xqc_path_ctx_t, path_list);

        if (!wrr_path_is_usable(path, reinject, packet_out)) {
            continue;
        }
        any_usable = XQC_TRUE;

        wrr_path_state_t *st = wrr_find_or_add(s, path->path_id);
        if (st == NULL) {
            continue;  /* WRR_MAX_PATHS exhausted; defensive, not expected */
        }
        st->seen = XQC_TRUE;

        uint32_t w = (path->path_weight > 0) ? path->path_weight : 1;
        st->current_weight += w;
        total_weight += w;

        xqc_log(conn->log, XQC_LOG_DEBUG,
                "|wrr|candidate|path_id:%ui|weight:%ud|current_weight:%lld|",
                path->path_id, w, (long long)st->current_weight);

        if (!xqc_scheduler_check_path_can_send(path, packet_out, check_cwnd)) {
            continue;
        }
        any_sendable = XQC_TRUE;

        if (candidate == NULL || st->current_weight > candidate_state->current_weight) {
            candidate       = path;
            candidate_state = st;
        }
    }

    wrr_compact_unseen(s);

    if (cc_blocked) {
        *cc_blocked = any_usable && !any_sendable;
    }

    if (candidate_state != NULL) {
        candidate_state->current_weight -= total_weight;
    }

    return candidate;
}

/*
 * Plain MinRTT selection for control traffic (po_flow_hash == 0). Does not
 * touch WRR state — control packets shouldn't consume rotation credit or
 * be spread across paths by weight.
 */
static xqc_path_ctx_t *
wrr_minrtt_select(xqc_connection_t *conn, xqc_packet_out_t *packet_out,
                   int check_cwnd, int reinject, xqc_bool_t *cc_blocked)
{
    xqc_path_ctx_t *best = NULL;
    uint64_t best_rtt = UINT64_MAX;
    xqc_bool_t any_usable = XQC_FALSE;
    xqc_bool_t any_sendable = XQC_FALSE;

    xqc_list_head_t *pos, *next;
    xqc_path_ctx_t  *path;

    xqc_list_for_each_safe(pos, next, &conn->conn_paths_list) {
        path = xqc_list_entry(pos, xqc_path_ctx_t, path_list);

        if (!wrr_path_is_usable(path, reinject, packet_out)) {
            continue;
        }
        any_usable = XQC_TRUE;

        if (!xqc_scheduler_check_path_can_send(path, packet_out, check_cwnd)) {
            continue;
        }
        any_sendable = XQC_TRUE;

        uint64_t rtt = xqc_send_ctl_get_srtt(path->path_send_ctl);
        if (rtt < best_rtt) {
            best_rtt = rtt;
            best = path;
        }
    }

    if (cc_blocked) {
        *cc_blocked = any_usable && !any_sendable;
    }

    return best;
}

static xqc_path_ctx_t *
xqc_wrr_scheduler_get_path(void *scheduler,
    xqc_connection_t *conn, xqc_packet_out_t *packet_out,
    int check_cwnd, int reinject, xqc_bool_t *cc_blocked)
{
    xqc_wrr_scheduler_t *s = (xqc_wrr_scheduler_t *)scheduler;

    /* Non-datagram QUIC control frames: pure MinRTT (ignore weights) */
    if (packet_out->po_flow_hash == 0) {
        return wrr_minrtt_select(conn, packet_out, check_cwnd, reinject, cc_blocked);
    }

    xqc_path_ctx_t *path = wrr_select(s, conn, packet_out, check_cwnd, reinject, cc_blocked);

    xqc_log(conn->log, XQC_LOG_DEBUG,
            "|wrr|select|path_id:%i|",
            path ? (int)path->path_id : -1);

    return path;
}

const xqc_scheduler_callback_t xqc_wrr_scheduler_cb = {
    .xqc_scheduler_size     = xqc_wrr_scheduler_size,
    .xqc_scheduler_init     = xqc_wrr_scheduler_init,
    .xqc_scheduler_get_path = xqc_wrr_scheduler_get_path,
};
