/**
 * @copyright Copyright (c) 2026, mp0rta
 *
 * WLB (Weighted Load Balancing) scheduler — flow-affinity multipath scheduler.
 *
 * Based on OLB (Optimal Load Balancing, Computer Communications 2017) for WRR
 * deficit-counter mechanism, and LATE (Loss-Aware Throughput Estimation,
 * IEEE TWC 2021) for the weight calculation formula.
 *
 * Key difference from MinRTT: packets belonging to the same inner flow
 * (identified by po_flow_hash) are pinned to the same QUIC path.  This
 * prevents TCP reordering inside VPN tunnels while still aggregating
 * bandwidth across paths via weighted round-robin of flows.
 */

#ifndef _XQC_SCHEDULER_WLB_H_INCLUDED_
#define _XQC_SCHEDULER_WLB_H_INCLUDED_

#include <xquic/xquic_typedef.h>
#include <xquic/xquic.h>

extern const xqc_scheduler_callback_t xqc_wlb_scheduler_cb;

#endif /* _XQC_SCHEDULER_WLB_H_INCLUDED_ */
