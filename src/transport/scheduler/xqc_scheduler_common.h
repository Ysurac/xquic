#ifndef _XQC_SCHEDULER_COMMON_H_INCLUDED_
#define _XQC_SCHEDULER_COMMON_H_INCLUDED_

#include <xquic/xquic.h>
#include <xquic/xquic_typedef.h>
#include "src/transport/xqc_multipath.h"

xqc_bool_t xqc_scheduler_check_path_can_send(xqc_path_ctx_t *path, xqc_packet_out_t *packet_out, int check_cwnd);

/*
 * Standby (draft-ietf-quic-multipath-21 PATH_STATUS_BACKUP) filter for the
 * schedulers that pick among all paths: a standby path does not get new
 * data while a working available path exists, whether or not that path has
 * cwnd room right now. Standby paths carry data again once none remains,
 * and reinjected packets may always use them.
 *
 * "Working" uses the performance classes of xqc_path_get_perf_class over
 * ACTIVE, non-FROZEN paths. An available path in the HIGH or MID class
 * holds every standby path back. One in the LOW class only (failing: PTOs,
 * loss above loss_percent_thr_high or srtt above rtt_us_thr_high) holds
 * back LOW standby paths and lets a better one carry data, as
 * xqc_scheduler_backup.c does. Unlike that scheduler, a MID available path
 * does not free a HIGH standby path: MID is reached by a slow link
 * (bandwidth estimate under bw_Bps_thr) or a loaded one (srtt above three
 * times the smallest srtt, which an idle standby path often holds), and
 * either would put a backup link into permanent use.
 *
 * Build it once per get_path call with xqc_scheduler_standby_filter_init,
 * then ask xqc_scheduler_standby_skip for each candidate. When the
 * connection has no standby path, or no available one, the filter is
 * inactive and costs one walk of the path list.
 *
 * Not part of xqc_scheduler_check_path_can_send on purpose: the backup
 * schedulers use that predicate and must keep seeing standby paths.
 */
#define XQC_SCHED_STANDBY_CACHE_SIZE 8

typedef struct xqc_sched_standby_filter_s {
    xqc_bool_t              active;
    xqc_path_perf_class_t   best_available_class;
    /* decisions for the first standby paths, so a scheduler that tests the
     * same path several times per call classifies it once */
    int                     n_cached;
    xqc_path_ctx_t         *cached_path[XQC_SCHED_STANDBY_CACHE_SIZE];
    xqc_bool_t              cached_skip[XQC_SCHED_STANDBY_CACHE_SIZE];
} xqc_sched_standby_filter_t;

void xqc_scheduler_standby_filter_init(xqc_sched_standby_filter_t *filter,
    xqc_connection_t *conn, int reinject);

xqc_bool_t xqc_scheduler_standby_skip(const xqc_sched_standby_filter_t *filter,
    xqc_path_ctx_t *path);

#endif
