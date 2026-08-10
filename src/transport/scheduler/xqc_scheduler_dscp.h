/**
 * @copyright Copyright (c) 2026, mp0rta
 *
 * DSCP (policy routing) multipath scheduler.
 *
 * Routes each packet to the path assigned to carry its DSCP class,
 * analogous to Linux policy routing:
 *   iptables -t mangle -A OUTPUT -j DSCP --set-dscp N
 *   ip rule add fwmark N table T ; ip route add default dev ethX table T
 *
 * Packets are tagged per-datagram with xqc_conn_set_dscp() before send
 * (mirroring xqc_conn_set_dgram_flow_hash() for WLB); paths are assigned
 * the DSCP classes they may carry with xqc_conn_set_path_dscp_mask()
 * (mirroring xqc_conn_set_path_weight() for WRTT/WRR). A path's mask may
 * carry more than one DSCP class; a DSCP class may be assigned to more
 * than one path, in which case MinRTT breaks the tie between them.
 *
 * Packets without a tag (po_dscp == 0, the default — covers DSCP class 0
 * / CS0 / best-effort, and every non-datagram control packet, which never
 * sets po_dscp at all) are scheduled by plain MinRTT across every usable
 * path, exactly like WRR/WRTT's control-packet fallback.
 *
 * Packets tagged with a DSCP class (po_dscp in 1..63) are scheduled by
 * MinRTT restricted to the path(s) whose xqc_conn_set_path_dscp_mask()
 * mask includes that class. If no path is currently assigned that class,
 * or every assigned path is down / cwnd-blocked, the scheduler degrades
 * to plain MinRTT across every usable path rather than stalling that
 * traffic class — resilience over strict class isolation, consistent
 * with the rest of this scheduler set.
 */

#ifndef _XQC_SCHEDULER_DSCP_H_INCLUDED_
#define _XQC_SCHEDULER_DSCP_H_INCLUDED_

#include <xquic/xquic_typedef.h>
#include <xquic/xquic.h>

extern const xqc_scheduler_callback_t xqc_dscp_scheduler_cb;

#endif /* _XQC_SCHEDULER_DSCP_H_INCLUDED_ */
