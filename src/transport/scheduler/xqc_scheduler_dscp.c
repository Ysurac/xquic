/**
 * @copyright Copyright (c) 2026, mp0rta
 *
 * DSCP (policy routing) multipath scheduler.
 *
 * Path selection:
 *   1. If the packet carries a DSCP tag (po_dscp in 1..63, set by the
 *      application via xqc_conn_set_dscp() before send), restrict the
 *      candidate set to paths whose mask (xqc_conn_set_path_dscp_mask())
 *      includes that class, then pick the lowest-RTT sendable path among
 *      them.
 *   2. If no path is assigned that class, or every assigned path is
 *      currently unusable / cwnd-blocked, fall back to plain MinRTT
 *      across every usable path — the traffic still moves, just without
 *      its preferred link, rather than stalling.
 *   3. Untagged packets (po_dscp == 0 — the default, which also covers
 *      every non-datagram control packet that never touches po_dscp)
 *      always use plain MinRTT across every usable path, ignoring masks
 *      entirely.
 *
 * No scheduler state is needed: like WRTT, this is a single pass (two at
 * most, for the tagged-with-fallback case) over the path list on every
 * call. DSCP masks and weights are independent knobs — a path can carry
 * both a static weight (for WRTT/WRR) and a DSCP mask (for this
 * scheduler); this scheduler only reads path_dscp_mask.
 */

#include "src/transport/scheduler/xqc_scheduler_dscp.h"
#include "src/transport/scheduler/xqc_scheduler_common.h"
#include "src/transport/xqc_send_ctl.h"
#include "src/transport/xqc_multipath.h"

#define DSCP_PTO_SKIP_THRESH  3   /* skip paths with >= 3 consecutive PTOs */

/* ------------------------------------------------------------------ */

static size_t
xqc_dscp_scheduler_size(void)
{
    return 0;
}

static void
xqc_dscp_scheduler_init(void *scheduler, xqc_log_t *log, xqc_scheduler_params_t *param)
{
    return;
}

/* ------------------------------------------------------------------ */

static xqc_bool_t
dscp_path_is_usable(xqc_path_ctx_t *path, int reinject, xqc_packet_out_t *packet_out)
{
    return path->path_state == XQC_PATH_STATE_ACTIVE
        && path->app_path_status != XQC_APP_PATH_STATUS_FROZEN
        && !(path->path_flag & XQC_PATH_FLAG_SOCKET_ERROR)
        && !(path->path_send_ctl
             && path->path_send_ctl->ctl_pto_count >= DSCP_PTO_SKIP_THRESH)
        && !(reinject && path->path_id == packet_out->po_path_id);
}

/*
 * MinRTT selection over usable, sendable paths. When required_mask is
 * non-zero, candidates are further restricted to paths whose
 * path_dscp_mask overlaps it (i.e. paths assigned this DSCP class);
 * required_mask == 0 means "no restriction" (plain MinRTT).
 */
static xqc_path_ctx_t *
dscp_pick_minrtt(xqc_connection_t *conn, xqc_packet_out_t *packet_out,
                  int check_cwnd, int reinject, uint64_t required_mask,
                  xqc_bool_t *cc_blocked)
{
    xqc_path_ctx_t *best = NULL;
    uint64_t best_rtt = UINT64_MAX;
    xqc_bool_t any_usable = XQC_FALSE;
    xqc_bool_t any_sendable = XQC_FALSE;

    xqc_list_head_t *pos, *next;
    xqc_path_ctx_t  *path;

    xqc_list_for_each_safe(pos, next, &conn->conn_paths_list) {
        path = xqc_list_entry(pos, xqc_path_ctx_t, path_list);

        if (!dscp_path_is_usable(path, reinject, packet_out)) {
            continue;
        }

        if (required_mask && !(path->path_dscp_mask & required_mask)) {
            continue;   /* not assigned this DSCP class */
        }

        any_usable = XQC_TRUE;

        if (!xqc_scheduler_check_path_can_send(path, packet_out, check_cwnd)) {
            continue;
        }
        any_sendable = XQC_TRUE;

        uint64_t rtt = xqc_send_ctl_get_srtt(path->path_send_ctl);

        xqc_log(conn->log, XQC_LOG_DEBUG,
                "|dscp|candidate|path_id:%ui|rtt:%llu|required_mask:%ui|",
                path->path_id, (unsigned long long)rtt, required_mask);

        if (rtt < best_rtt) {
            best_rtt = rtt;
            best     = path;
        }
    }

    if (cc_blocked) {
        *cc_blocked = any_usable && !any_sendable;
    }

    return best;
}

static xqc_path_ctx_t *
xqc_dscp_scheduler_get_path(void *scheduler,
    xqc_connection_t *conn, xqc_packet_out_t *packet_out,
    int check_cwnd, int reinject, xqc_bool_t *cc_blocked)
{
    uint8_t dscp = packet_out->po_dscp;

    if (dscp == 0) {
        /* Untagged (default), and every non-datagram control packet. */
        xqc_path_ctx_t *path = dscp_pick_minrtt(conn, packet_out, check_cwnd,
                                                 reinject, 0, cc_blocked);

        xqc_log(conn->log, XQC_LOG_DEBUG,
                "|dscp|select|untagged|path_id:%i|",
                path ? (int)path->path_id : -1);
        return path;
    }

    uint64_t mask = 1ULL << (dscp & 0x3F);
    xqc_path_ctx_t *path = dscp_pick_minrtt(conn, packet_out, check_cwnd,
                                             reinject, mask, cc_blocked);
    if (path != NULL) {
        xqc_log(conn->log, XQC_LOG_DEBUG,
                "|dscp|select|dscp:%ud|path_id:%ui|dedicated|", dscp, path->path_id);
        return path;
    }

    /* No dedicated path currently usable for this class: degrade to plain
     * MinRTT across every path instead of stalling the traffic. */
    path = dscp_pick_minrtt(conn, packet_out, check_cwnd, reinject, 0, cc_blocked);

    xqc_log(conn->log, XQC_LOG_DEBUG,
            "|dscp|select|dscp:%ud|path_id:%i|fallback_minrtt|", dscp,
            path ? (int)path->path_id : -1);
    return path;
}

const xqc_scheduler_callback_t xqc_dscp_scheduler_cb = {
    .xqc_scheduler_size     = xqc_dscp_scheduler_size,
    .xqc_scheduler_init     = xqc_dscp_scheduler_init,
    .xqc_scheduler_get_path = xqc_dscp_scheduler_get_path,
};
