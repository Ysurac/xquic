/**
 * @copyright Copyright (c) 2026, mp0rta
 *
 * Redundant (broadcast) multipath scheduler.
 *
 * Sends every packet on every currently usable path simultaneously,
 * trading bandwidth for maximum loss resilience: as long as ONE path
 * delivers a copy, the data arrives. Intended for low-bitrate,
 * loss/latency-critical traffic (control channels, keepalives, VoIP)
 * where never losing a packet to a single link's transient loss or
 * outage matters far more than aggregating throughput across links.
 *
 * Path selection:
 *   - One path is picked as "primary" using the same min-RTT-in-best-
 *     perf-class logic as xqc_minrtt_scheduler, and returned normally
 *     so the caller (xqc_conn_schedule_packets) appends the *original*
 *     packet_out to it under the correct send_type (NORMAL, RETRANS,
 *     PTO_PROBE, ...).
 *   - For every other ACTIVE, non-frozen path whose cwnd currently
 *     allows the packet, a replica is created (xqc_packet_out_copy) and
 *     queued directly onto that path's XQC_SEND_TYPE_NORMAL schedule
 *     buffer via xqc_path_send_buffer_append(), bypassing the scheduler
 *     entirely on this and future rounds (same technique used by
 *     xqc_conn_try_reinject_packet() in xqc_reinjection.c).
 *   - Unlike the backup/minrtt/wrr/wrtt schedulers, both AVAILABLE and
 *     STANDBY perf classes are treated as fair game for replicas: the
 *     whole point of this scheduler is to ignore the available/standby
 *     preference and use every link that is up.
 *
 * Loss/ack bookkeeping is free: xqc_packet_out_copy() links each replica
 * to the original via po_origin/po_origin_ref_cnt, and xqc_send_ctl.c
 * already treats "any copy of po_origin acked" as "the data is
 * delivered, do not retransmit the rest" (see xqc_send_ctl_can_retrans
 * checking packet_out->po_origin->po_acked). No changes needed there.
 *
 * Known limitation (sketch-level): send_type isn't threaded through the
 * xqc_scheduler_callback_t interface, so replicas are always queued as
 * XQC_SEND_TYPE_NORMAL even when the original packet being scheduled is
 * a RETRANS/PTO_PROBE/HIGH_PRI packet. Only the primary path (returned
 * to the caller) gets the packet under its real send_type. Acceptable
 * for control/low-rate traffic; would need a small interface change
 * (passing send_type into xqc_scheduler_get_path) to fix properly.
 *
 * When called with reinject == 1 (the connection's separate selective
 * reinjection pass, see xqc_conn_try_reinject_packet), this scheduler
 * just returns a single best path like xqc_minrtt_scheduler: this
 * scheduler already puts a copy on every path by construction, so
 * layering selective reinjection on top would only multiply duplicates.
 */

#include "src/transport/scheduler/xqc_scheduler_redundant.h"
#include "src/transport/scheduler/xqc_scheduler_common.h"
#include "src/transport/xqc_send_ctl.h"
#include "src/transport/xqc_send_queue.h"
#include "src/transport/xqc_packet_out.h"
#include "src/transport/xqc_multipath.h"


static size_t
xqc_redundant_scheduler_size(void)
{
    return 0;
}

static void
xqc_redundant_scheduler_init(void *scheduler, xqc_log_t *log, xqc_scheduler_params_t *param)
{
    return;
}

/* Duplicate packet_out onto `path`'s NORMAL schedule buffer. Best-effort:
 * on allocation failure we just skip this path rather than failing the
 * whole scheduling round. */
static void
xqc_redundant_scheduler_duplicate_to_path(xqc_connection_t *conn,
    xqc_packet_out_t *packet_out, xqc_path_ctx_t *path)
{
    xqc_send_queue_t *send_queue = conn->conn_send_queue;

    xqc_packet_out_t *po_copy = xqc_packet_out_get(send_queue);
    if (po_copy == NULL) {
        xqc_log(conn->log, XQC_LOG_DEBUG,
                "|REDUNDANT|no free packet_out for replica|path:%ui|", path->path_id);
        return;
    }

    xqc_packet_out_copy(po_copy, packet_out);
    xqc_packet_out_remove_ack_frame(po_copy);

    po_copy->po_flag &= ~XQC_POF_RETRANSED;
    po_copy->po_flag &= ~XQC_POF_SPURIOUS_LOSS;
    po_copy->po_path_flag |= XQC_PATH_SPECIFIED_BY_REINJ;

    xqc_send_queue_insert_send(po_copy, &send_queue->sndq_send_packets, send_queue);
    xqc_path_send_buffer_append(path, po_copy, &path->path_schedule_buf[XQC_SEND_TYPE_NORMAL]);

    xqc_log(conn->log, XQC_LOG_DEBUG,
            "|REDUNDANT|replica queued|path:%ui|stream_id:%ui|stream_offset:%ui|"
            "origin_path:%ui|origin_pkt_num:%ui|",
            path->path_id, po_copy->po_stream_id, po_copy->po_stream_offset,
            packet_out->po_path_id, packet_out->po_pkt.pkt_num);
}

xqc_path_ctx_t *
xqc_redundant_scheduler_get_path(void *scheduler,
    xqc_connection_t *conn, xqc_packet_out_t *packet_out, int check_cwnd, int reinject,
    xqc_bool_t *cc_blocked)
{
    xqc_path_ctx_t *best_path[XQC_PATH_CLASS_PERF_CLASS_SIZE];
    xqc_path_perf_class_t path_class;

    xqc_list_head_t *pos, *next;
    xqc_path_ctx_t *path, *primary;
    xqc_send_ctl_t *send_ctl;

    uint64_t path_srtt = 0;
    xqc_bool_t reached_cwnd_check = XQC_FALSE;
    xqc_bool_t path_can_send = XQC_FALSE;

    for (path_class = XQC_PATH_CLASS_AVAILABLE_HIGH;
         path_class < XQC_PATH_CLASS_PERF_CLASS_SIZE;
         path_class++)
    {
        best_path[path_class] = NULL;
    }

    if (cc_blocked) {
        *cc_blocked = XQC_FALSE;
    }

    /* pass 1: pick the primary path exactly like xqc_minrtt_scheduler */
    xqc_list_for_each_safe(pos, next, &conn->conn_paths_list) {
        path = xqc_list_entry(pos, xqc_path_ctx_t, path_list);

        path_class = xqc_path_get_perf_class(path);

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

        path_can_send = xqc_scheduler_check_path_can_send(path, packet_out, check_cwnd);
        if (!path_can_send) {
            continue;
        }

        if (cc_blocked) {
            *cc_blocked = XQC_FALSE;
        }

        path_srtt = xqc_send_ctl_get_srtt(path->path_send_ctl);
        if (best_path[path_class] == NULL
            || path_srtt < best_path[path_class]->path_send_ctl->ctl_srtt)
        {
            best_path[path_class] = path;
        }
    }

    primary = NULL;
    for (path_class = XQC_PATH_CLASS_AVAILABLE_HIGH;
         path_class < XQC_PATH_CLASS_PERF_CLASS_SIZE;
         path_class++)
    {
        if (best_path[path_class] != NULL) {
            primary = best_path[path_class];
            break;
        }
    }

    if (primary == NULL) {
        xqc_log(conn->log, XQC_LOG_DEBUG, "|REDUNDANT|No available paths to schedule|conn:%p|", conn);
        return NULL;
    }

    /* the selective-reinjection pass already asked for a single extra
     * path for this packet; don't fan it out further on top of that. */
    if (reinject) {
        return primary;
    }

    /* pass 2: put a replica on every other usable path */
    xqc_list_for_each_safe(pos, next, &conn->conn_paths_list) {
        path = xqc_list_entry(pos, xqc_path_ctx_t, path_list);

        if (path == primary
            || path->path_state != XQC_PATH_STATE_ACTIVE
            || path->app_path_status == XQC_APP_PATH_STATUS_FROZEN)
        {
            continue;
        }

        if (!xqc_scheduler_check_path_can_send(path, packet_out, check_cwnd)) {
            continue;
        }

        xqc_redundant_scheduler_duplicate_to_path(conn, packet_out, path);
    }

    xqc_log(conn->log, XQC_LOG_DEBUG, "|REDUNDANT|primary path:%ui|frame_type:%s|"
            "pn:%ui|size:%ud|",
            primary->path_id,
            xqc_frame_type_2_str(conn->engine, packet_out->po_frame_types),
            packet_out->po_pkt.pkt_num, packet_out->po_used_size);

    return primary;
}

const xqc_scheduler_callback_t xqc_redundant_scheduler_cb = {
    .xqc_scheduler_size             = xqc_redundant_scheduler_size,
    .xqc_scheduler_init             = xqc_redundant_scheduler_init,
    .xqc_scheduler_get_path         = xqc_redundant_scheduler_get_path,
};
