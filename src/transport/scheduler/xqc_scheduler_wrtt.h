/**
 * @copyright Copyright (c) 2026, mp0rta
 *
 * WRTT (Weight + RTT) multipath scheduler.
 *
 * Selects paths by static weight first (higher = preferred), then by RTT
 * as a tiebreaker within paths of the same weight — analogous to:
 *   ip route default nexthop via gw1 weight 3 nexthop via gw2 weight 1
 *
 * Unlike WRR there is no round-robin distribution: the highest-weight,
 * lowest-RTT path handles all traffic until its cwnd is full, at which
 * point the next-best path takes the overflow.  This gives bandwidth
 * aggregation without reordering on homogeneous (equal-weight) links.
 *
 * Set weights with xqc_conn_set_path_weight(). Paths with weight=0 are
 * treated as weight=1. Non-datagram packets fall back to pure MinRTT.
 */

#ifndef _XQC_SCHEDULER_WRTT_H_INCLUDED_
#define _XQC_SCHEDULER_WRTT_H_INCLUDED_

#include <xquic/xquic_typedef.h>
#include <xquic/xquic.h>

extern const xqc_scheduler_callback_t xqc_wrtt_scheduler_cb;

#endif /* _XQC_SCHEDULER_WRTT_H_INCLUDED_ */
