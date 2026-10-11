#include "src/transport/scheduler/xqc_scheduler_common.h"
#include "src/transport/xqc_multipath.h"
#include "src/transport/xqc_packet_out.h"
#include "src/transport/xqc_send_ctl.h"

xqc_bool_t
xqc_scheduler_check_path_can_send(xqc_path_ctx_t *path, xqc_packet_out_t *packet_out, int check_cwnd)
{
    xqc_send_ctl_t *send_ctl = path->path_send_ctl;
    uint32_t schedule_bytes = path->path_schedule_bytes;

    /* normal packets in send list will be blocked by cc */
    if (check_cwnd && (!xqc_send_packet_cwnd_allows(send_ctl, packet_out, schedule_bytes, 0)))
    {
        xqc_log(send_ctl->ctl_conn->log, XQC_LOG_DEBUG, "|path:%ui|blocked by cwnd|", path->path_id);
        return XQC_FALSE;
    }

    return XQC_TRUE;
}

static xqc_bool_t
xqc_scheduler_standby_candidate(xqc_path_ctx_t *path)
{
    /* the same paths the backup scheduler classifies */
    return path->path_state == XQC_PATH_STATE_ACTIVE
           && path->app_path_status != XQC_APP_PATH_STATUS_FROZEN;
}

static xqc_bool_t
xqc_scheduler_standby_decide(const xqc_sched_standby_filter_t *filter,
    xqc_path_ctx_t *path)
{
    /* A HIGH or MID available path holds every standby path back, without
     * classifying it. Behind a LOW one only a LOW standby path is held
     * back: STANDBY_LOW is the one standby class above AVAILABLE_LOW. */
    if (filter->best_available_class <= XQC_PATH_CLASS_AVAILABLE_MID) {
        return XQC_TRUE;
    }
    return xqc_path_get_perf_class(path) > filter->best_available_class;
}

void
xqc_scheduler_standby_filter_init(xqc_sched_standby_filter_t *filter,
    xqc_connection_t *conn, int reinject)
{
    xqc_list_head_t *pos, *next;
    xqc_path_ctx_t *path;
    xqc_path_perf_class_t path_class;
    xqc_bool_t has_available = XQC_FALSE;
    xqc_bool_t has_standby = XQC_FALSE;

    filter->active = XQC_FALSE;
    filter->best_available_class = XQC_PATH_CLASS_PERF_CLASS_SIZE;
    filter->n_cached = 0;

    /* a reinjected copy may ride a standby path */
    if (reinject) {
        return;
    }

    xqc_list_for_each_safe(pos, next, &conn->conn_paths_list) {
        path = xqc_list_entry(pos, xqc_path_ctx_t, path_list);
        if (!xqc_scheduler_standby_candidate(path)) {
            continue;
        }
        if (path->app_path_status == XQC_APP_PATH_STATUS_AVAILABLE) {
            has_available = XQC_TRUE;

        } else {
            has_standby = XQC_TRUE;
        }
    }

    if (!has_available || !has_standby) {
        return;
    }

    xqc_list_for_each_safe(pos, next, &conn->conn_paths_list) {
        path = xqc_list_entry(pos, xqc_path_ctx_t, path_list);
        if (!xqc_scheduler_standby_candidate(path)
            || path->app_path_status != XQC_APP_PATH_STATUS_AVAILABLE)
        {
            continue;
        }
        path_class = xqc_path_get_perf_class(path);
        if (path_class < filter->best_available_class) {
            filter->best_available_class = path_class;
            if (path_class <= XQC_PATH_CLASS_AVAILABLE_MID) {
                break;  /* holds every standby path back already */
            }
        }
    }

    filter->active = XQC_TRUE;

    xqc_list_for_each_safe(pos, next, &conn->conn_paths_list) {
        if (filter->n_cached >= XQC_SCHED_STANDBY_CACHE_SIZE) {
            break;
        }
        path = xqc_list_entry(pos, xqc_path_ctx_t, path_list);
        if (!xqc_scheduler_standby_candidate(path)
            || path->app_path_status == XQC_APP_PATH_STATUS_AVAILABLE)
        {
            continue;
        }
        filter->cached_path[filter->n_cached] = path;
        filter->cached_skip[filter->n_cached] =
            xqc_scheduler_standby_decide(filter, path);
        filter->n_cached++;
    }

    xqc_log(conn->log, XQC_LOG_DEBUG,
            "|standby_filter|best_available_class:%d|standby_paths_cached:%d|",
            filter->best_available_class, filter->n_cached);
}

xqc_bool_t
xqc_scheduler_standby_skip(const xqc_sched_standby_filter_t *filter,
    xqc_path_ctx_t *path)
{
    if (!filter->active
        || path->app_path_status == XQC_APP_PATH_STATUS_AVAILABLE
        || !xqc_scheduler_standby_candidate(path))
    {
        return XQC_FALSE;
    }

    for (int i = 0; i < filter->n_cached; i++) {
        if (filter->cached_path[i] == path) {
            return filter->cached_skip[i];
        }
    }

    return xqc_scheduler_standby_decide(filter, path);
}
