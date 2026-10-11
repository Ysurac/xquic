/**
 * @copyright Copyright (c) 2026, mp0rta
 *
 * Standby-path tests for the path-picking schedulers.
 *
 * draft-ietf-quic-multipath-21 PATH_STATUS_BACKUP: a standby path is not
 * used while an available path exists. The schedulers apply
 * xqc_scheduler_standby_skip: no new data on a standby path while a working
 * (HIGH or MID class) available path exists, nor while a failing (LOW)
 * one exists and the standby path is LOW too; data again once none
 * remains; reinjection may use a standby path.
 */
#ifndef XQC_SCHEDULER_STANDBY_TEST_H_INCLUDED
#define XQC_SCHEDULER_STANDBY_TEST_H_INCLUDED

/* WLB: a standby path carries no datagram (pinned or unpinned), STREAM or
 * control packet while the available path is up, takes everything once the
 * available path is gone, and is idle again when it returns. */
void xqc_test_standby_wlb_backup_idle_until_primary_lost(void);

/* WLB: flows pinned to a path that turns standby move to the available
 * path. */
void xqc_test_standby_wlb_pinned_flow_leaves_path_turning_standby(void);

/* WLB: a cwnd-blocked available path does not spill onto a standby path;
 * the scheduler reports cc_blocked instead. */
void xqc_test_standby_wlb_blocked_primary_does_not_spill(void);

/* WLB: a reinjected copy may use the standby path. */
void xqc_test_standby_wlb_reinject_may_use_standby(void);

/* WLB and MinRTT: an available path in the MID class (slow or loaded) holds
 * back a HIGH standby path; one in the LOW class (failing) lets a better
 * standby path carry data but holds back a LOW one. */
void xqc_test_standby_perf_class_rule(void);

/* MinRTT, WRR, WRTT, DSCP and RAP: the standby path is skipped even when it
 * has the lower RTT, the higher weight or the DSCP class, carries data once
 * only standby paths remain, and takes reinjected copies. */
void xqc_test_standby_other_schedulers(void);

#endif /* XQC_SCHEDULER_STANDBY_TEST_H_INCLUDED */
