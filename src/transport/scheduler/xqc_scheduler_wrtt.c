/**
 * @copyright Copyright (c) 2026, mp0rta
 *
 * WRTT (Weight + RTT) multipath scheduler.
 *
 * Path selection priority:
 *   1. Higher static weight wins (set via xqc_conn_set_path_weight).
 *   2. Among paths with the same weight, lower RTT wins.
 *   3. When the best path is cwnd-blocked, the next-best path takes the
 *      packet — providing bandwidth aggregation without round-robin.
 *
 * No scheduler state is needed: the algorithm is a single pass over the
 * path list on every call, identical in structure to MinRTT but with
 * weight as the primary sort key.
 *
 * Non-datagram QUIC packets (po_flow_hash == 0) always use pure MinRTT
 * so that control traffic stays on the lowest-latency path regardless of
 * the configured weights.
 */

#include "src/transport/scheduler/xqc_scheduler_wrtt.h"
#include "src/transport/scheduler/xqc_scheduler_common.h"
#include "src/transport/xqc_send_ctl.h"
#include "src/transport/xqc_multipath.h"

#define WRTT_PTO_SKIP_THRESH  3   /* skip paths with >= 3 consecutive PTOs */

/* ------------------------------------------------------------------ */

static size_t
xqc_wrtt_scheduler_size(void)
{
    return 0;
}

static void
xqc_wrtt_scheduler_init(void *scheduler, xqc_log_t *log, xqc_scheduler_params_t *param)
{
    return;
}

/* ------------------------------------------------------------------ */

static xqc_bool_t
wrtt_path_is_usable(xqc_path_ctx_t *path, int reinject, xqc_packet_out_t *packet_out)
{
    return path->path_state == XQC_PATH_STATE_ACTIVE
        && path->app_path_status != XQC_APP_PATH_STATUS_FROZEN
        && !(path->path_flag & XQC_PATH_FLAG_SOCKET_ERROR)
        && !(path->path_send_ctl
             && path->path_send_ctl->ctl_pto_count >= WRTT_PTO_SKIP_THRESH)
        && !(reinject && path->path_id == packet_out->po_path_id);
}

/*
 * Select the best sendable path using weight as the primary key and RTT
 * as the tiebreaker.
 *
 * One pass over all paths:
 *   - Track the highest weight seen among sendable paths.
 *   - Among paths at that weight, track the one with minimum RTT.
 *   - Also track the overall best cc_blocked candidate (for the return
 *     value of cc_blocked when every path is cwnd-full).
 */
static xqc_path_ctx_t *
wrtt_select(xqc_connection_t *conn, xqc_packet_out_t *packet_out,
            int check_cwnd, int reinject, xqc_bool_t *cc_blocked)
{
    xqc_path_ctx_t *best = NULL;
    uint32_t best_weight = 0;
    uint64_t best_rtt = UINT64_MAX;
    xqc_bool_t any_active = XQC_FALSE;

    if (cc_blocked) {
        *cc_blocked = XQC_FALSE;
    }

    xqc_list_head_t *pos, *next;
    xqc_path_ctx_t  *path;

    xqc_list_for_each_safe(pos, next, &conn->conn_paths_list) {
        path = xqc_list_entry(pos, xqc_path_ctx_t, path_list);

        if (!wrtt_path_is_usable(path, reinject, packet_out)) {
            continue;
        }

        any_active = XQC_TRUE;
        if (cc_blocked) {
            *cc_blocked = XQC_TRUE;  /* at least one path reached the cwnd gate */
        }

        if (!xqc_scheduler_check_path_can_send(path, packet_out, check_cwnd)) {
            continue;
        }

        if (cc_blocked) {
            *cc_blocked = XQC_FALSE;
        }

        uint32_t w   = (path->path_weight > 0) ? path->path_weight : 1;
        uint64_t rtt = xqc_send_ctl_get_srtt(path->path_send_ctl);

        xqc_log(conn->log, XQC_LOG_DEBUG,
                "|wrtt|candidate|path_id:%ui|weight:%ud|rtt:%llu|best_weight:%ud|",
                path->path_id, w, (unsigned long long)rtt, best_weight);

        if (w > best_weight || (w == best_weight && rtt < best_rtt)) {
            best_weight = w;
            best_rtt    = rtt;
            best        = path;
        }
    }

    (void)any_active;
    return best;
}

static xqc_path_ctx_t *
xqc_wrtt_scheduler_get_path(void *scheduler,
    xqc_connection_t *conn, xqc_packet_out_t *packet_out,
    int check_cwnd, int reinject, xqc_bool_t *cc_blocked)
{
    /* Non-datagram QUIC control frames: pure MinRTT (ignore weights) */
    if (packet_out->po_flow_hash == 0) {
        return wrtt_select(conn, packet_out, check_cwnd, reinject, cc_blocked);
    }

    xqc_path_ctx_t *path = wrtt_select(conn, packet_out, check_cwnd, reinject, cc_blocked);

    xqc_log(conn->log, XQC_LOG_DEBUG,
            "|wrtt|select|path_id:%i|",
            path ? (int)path->path_id : -1);

    return path;
}

const xqc_scheduler_callback_t xqc_wrtt_scheduler_cb = {
    .xqc_scheduler_size     = xqc_wrtt_scheduler_size,
    .xqc_scheduler_init     = xqc_wrtt_scheduler_init,
    .xqc_scheduler_get_path = xqc_wrtt_scheduler_get_path,
};
