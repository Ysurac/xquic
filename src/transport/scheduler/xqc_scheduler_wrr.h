/**
 * @copyright Copyright (c) 2026, mp0rta
 *
 * WRR (Weighted Round Robin) multipath scheduler.
 *
 * Distributes packets across paths in proportion to their static weight
 * (set via xqc_conn_set_path_weight) using the smooth weighted round-robin
 * algorithm — analogous to:
 *   ip route default nexthop via gw1 weight 3 nexthop via gw2 weight 1
 *
 * Unlike WRTT, which always sends on the single highest-weight path until
 * it is cwnd-blocked, WRR interleaves selections across all usable paths
 * in proportion to their weight (e.g. weights 3:1 yield roughly
 * A A B A A A B ... rather than a long burst on one path). This trades a
 * little of WRTT's low-latency bias for smoother, more predictable
 * bandwidth aggregation across paths of known relative capacity.
 *
 * Set weights with xqc_conn_set_path_weight(). Paths with weight=0 are
 * treated as weight=1. Non-datagram packets fall back to pure MinRTT so
 * control traffic isn't spread thin by the rotation.
 */

#ifndef _XQC_SCHEDULER_WRR_H_INCLUDED_
#define _XQC_SCHEDULER_WRR_H_INCLUDED_

#include <xquic/xquic_typedef.h>
#include <xquic/xquic.h>

extern const xqc_scheduler_callback_t xqc_wrr_scheduler_cb;

#endif /* _XQC_SCHEDULER_WRR_H_INCLUDED_ */
