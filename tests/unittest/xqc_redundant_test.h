/**
 * @copyright Copyright (c) 2026, mp0rta
 *
 * Redundant (broadcast) scheduler invariant tests.
 *
 * Tests the documented contract of the redundant scheduler
 * (xqc_scheduler_redundant.c header comment) under controlled path-state
 * fixtures. The scheduler is exercised through its public callback table;
 * per-path cwnd / SRTT are driven via mocked congestion-control callbacks,
 * mirroring the xqc_wrr_test.c / xqc_wlb_test.c fixture style.
 */
#ifndef XQC_REDUNDANT_TEST_H_INCLUDED
#define XQC_REDUNDANT_TEST_H_INCLUDED

/* With two usable paths, the lower-SRTT path is returned as primary and
 * the other path receives exactly one replica queued directly onto its
 * NORMAL schedule buffer, linked to the original via po_origin. */
void xqc_test_redundant_two_paths_primary_and_replica(void);

/* With three usable paths, one is returned as primary and each of the
 * other two receives its own replica. */
void xqc_test_redundant_three_paths_replicate_to_all_others(void);

/* A cwnd-blocked non-primary path must not receive a replica, even
 * though the primary path is still schedulable. */
void xqc_test_redundant_cwnd_blocked_path_gets_no_replica(void);

/* A frozen path is excluded from both primary selection and replication. */
void xqc_test_redundant_frozen_path_excluded(void);

/* When called with reinject == 1 (the connection's selective-reinjection
 * pass), the scheduler must behave like plain MinRTT: return a single
 * path and create no replicas, since this scheduler already covers every
 * link on the normal scheduling pass. */
void xqc_test_redundant_reinject_call_returns_single_path_no_replica(void);

/* When every usable path is cwnd-blocked, the scheduler returns NULL and
 * reports cc_blocked = TRUE, with no replicas created anywhere. */
void xqc_test_redundant_all_paths_cwnd_blocked_returns_null_and_cc_blocked(void);

/* With only one active path, the scheduler returns it as primary and
 * does not crash despite there being no path to replicate onto. */
void xqc_test_redundant_single_path_no_replica_no_crash(void);

#endif /* XQC_REDUNDANT_TEST_H_INCLUDED */
