/**
 * @copyright Copyright (c) 2026, mp0rta
 *
 * DSCP scheduler invariant tests.
 *
 * Tests the documented contract of the DSCP scheduler
 * (xqc_scheduler_dscp.c header comment) under controlled path-state
 * fixtures. The scheduler is exercised through its public callback table;
 * per-path cwnd / SRTT are driven via mocked congestion-control callbacks
 * so each test isolates one invariant.
 */
#ifndef XQC_DSCP_TEST_H_INCLUDED
#define XQC_DSCP_TEST_H_INCLUDED

/* Untagged packets (po_dscp == 0), including control packets, use plain
 * MinRTT across every usable path and ignore any configured DSCP masks. */
void xqc_test_dscp_untagged_uses_minrtt_ignoring_masks(void);

/* A tagged packet is routed to the path whose mask includes that DSCP
 * class, even when another usable path has lower RTT. */
void xqc_test_dscp_tagged_routes_to_assigned_path(void);

/* When two paths share the same DSCP class in their mask, the tagged
 * packet is scheduled by MinRTT between just those two. */
void xqc_test_dscp_tagged_breaks_tie_by_minrtt_among_assigned(void);

/* When the assigned path for a tagged packet is cwnd-blocked (but other,
 * unassigned paths are sendable), the scheduler degrades to plain MinRTT
 * across every usable path instead of stalling. */
void xqc_test_dscp_tagged_falls_back_to_minrtt_when_assigned_path_blocked(void);

/* When no path is assigned the packet's DSCP class at all, the scheduler
 * falls back to plain MinRTT across every usable path. */
void xqc_test_dscp_tagged_falls_back_to_minrtt_when_no_path_assigned(void);

/* When every usable path is cwnd-blocked (assigned or not), the scheduler
 * returns NULL and reports cc_blocked = TRUE. */
void xqc_test_dscp_all_paths_cwnd_blocked_returns_null_and_cc_blocked(void);

/* A path with dscp_mask == 0 (the default / unassigned) is still eligible
 * for untagged traffic and for the MinRTT fallback of tagged traffic. */
void xqc_test_dscp_unassigned_path_still_used_as_fallback(void);

#endif /* XQC_DSCP_TEST_H_INCLUDED */
