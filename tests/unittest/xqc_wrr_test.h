/**
 * @copyright Copyright (c) 2026, mp0rta
 *
 * WRR scheduler invariant tests.
 *
 * Tests the documented contract of the WRR scheduler
 * (xqc_scheduler_wrr.c header comment) under controlled path-state
 * fixtures. The scheduler is exercised through its public callback table;
 * per-path cwnd / SRTT are driven via mocked congestion-control callbacks
 * so each test isolates one invariant.
 */
#ifndef XQC_WRR_TEST_H_INCLUDED
#define XQC_WRR_TEST_H_INCLUDED

/* Equal weights alternate strictly 1:1 across calls (smooth WRR, not
 * bursty). */
void xqc_test_wrr_equal_weights_alternate(void);

/* Weights 3:1 produce a 3:1 selection ratio over one full weight period,
 * with the minority path interleaved rather than isolated to a trailing
 * burst. */
void xqc_test_wrr_weighted_ratio_3_1(void);

/* A cwnd-blocked path is skipped for selection but keeps accruing
 * current_weight; once it becomes sendable again it "catches up" and wins
 * the very next selection instead of losing its rotation share. */
void xqc_test_wrr_blocked_path_still_accrues_and_catches_up(void);

/* Non-datagram (control) packets use plain MinRTT and never touch the WRR
 * weight state — a run of control-packet calls must not perturb the
 * weighted distribution seen by subsequent app-data calls. */
void xqc_test_wrr_control_packets_use_minrtt_and_dont_perturb_weight_state(void);

/* When every usable path is cwnd-blocked, the scheduler returns NULL and
 * reports cc_blocked = TRUE. */
void xqc_test_wrr_all_paths_cwnd_blocked_returns_null_and_cc_blocked(void);

/* weight = 0 is treated as weight = 1 (equal priority), matching WRTT's
 * documented convention. */
void xqc_test_wrr_weight_zero_treated_as_one(void);

/* Removing a path from the connection's path list must not crash the
 * scheduler; the surviving path keeps being selected, and a path that
 * reappears later (e.g. same path_id after failover) resumes normal
 * scheduling. */
void xqc_test_wrr_path_removed_no_crash(void);

#endif /* XQC_WRR_TEST_H_INCLUDED */
