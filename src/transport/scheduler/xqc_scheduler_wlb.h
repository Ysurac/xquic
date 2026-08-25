/**
 * @copyright Copyright (c) 2026, mp0rta
 *
 * WLB (Weighted Load Balancing) multipath scheduler for QUIC Datagrams.
 *
 * Flow-affinity WRR with LATE-based weight estimation.
 * Inner flows are pinned to paths via hash table to prevent TCP reordering.
 */

#ifndef _XQC_SCHEDULER_WLB_H_INCLUDED_
#define _XQC_SCHEDULER_WLB_H_INCLUDED_

#include <xquic/xquic_typedef.h>
#include <xquic/xquic.h>

extern const xqc_scheduler_callback_t xqc_wlb_scheduler_cb;

int xqc_wlb_scheduler_set_policy(void *scheduler, xqc_connection_t *conn,
                                 xqc_wlb_policy_t policy);
int xqc_wlb_scheduler_copy_path_stats(void *scheduler, xqc_wlb_path_stats_t *out,
                                      size_t capacity, size_t *out_count);
void xqc_wlb_scheduler_on_app_packet_acked(void *scheduler, uint64_t path_id,
                                          uint64_t payload_bytes,
                                          uint64_t ack_time_us);
xqc_bool_t xqc_wlb_scheduler_is_callback(
    const xqc_scheduler_callback_t *scheduler_callback);

#endif /* _XQC_SCHEDULER_WLB_H_INCLUDED_ */
