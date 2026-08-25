/**
 * @copyright Copyright (c) 2026, mp0rta
 *
 * Standalone CUnit driver for the WLB scheduler tests, used while the
 * upstream run_tests target has unrelated build issues (FEC symbol
 * mismatch when XQC_ENABLE_PKM is off, masque test uninitialized vars).
 * Lets the WLB suite be exercised in isolation against the same
 * libxquic-static.a the production build links.
 */
#include <stdio.h>
#include <CUnit/Basic.h>
#include <CUnit/CUnit.h>

#include "xqc_wlb_test.h"

static int wlb_suite_init(void) { return 0; }
static int wlb_suite_clean(void) { return 0; }

int
main(void)
{
    if (CU_initialize_registry() != CUE_SUCCESS) {
        return (int)CU_get_error();
    }

    CU_pSuite s = CU_add_suite("wlb", wlb_suite_init, wlb_suite_clean);
    if (s == NULL) {
        CU_cleanup_registry();
        return (int)CU_get_error();
    }

    if (NULL == CU_add_test(s, "asym_p1_pin_to_wide",
                            xqc_test_wlb_asym_p1_pin_to_wide)
        || NULL == CU_add_test(s, "asym_p1_pin_to_wide_when_wide_blocked",
                               xqc_test_wlb_asym_p1_pin_to_wide_when_wide_blocked)
        || NULL == CU_add_test(s, "soft_pin_no_repin_on_block",
                               xqc_test_wlb_soft_pin_no_repin_on_block)
        || NULL == CU_add_test(s, "sym_multiflow_distributes",
                               xqc_test_wlb_sym_multiflow_distributes)
        || NULL == CU_add_test(s, "recovery_prefer_skips_initial_path_addition",
                               xqc_test_wlb_recovery_prefer_skips_initial_path_addition)
        || NULL == CU_add_test(s, "recovery_prefer_fires_after_real_failover",
                               xqc_test_wlb_recovery_prefer_fires_after_real_failover)
        || NULL == CU_add_test(s, "single_path_does_not_pin",
                               xqc_test_wlb_single_path_does_not_pin)
        || NULL == CU_add_test(s, "new_path_detected_without_expire_throttle",
                               xqc_test_wlb_new_path_detected_without_expire_throttle)
        || NULL == CU_add_test(s, "reinject_bypasses_pin",
                               xqc_test_wlb_reinject_bypasses_pin)
        || NULL == CU_add_test(s, "stream_data_distributes",
                               xqc_test_wlb_stream_data_distributes)
        || NULL == CU_add_test(s, "stream_data_weights_asymmetric_paths",
                               xqc_test_wlb_stream_data_weights_asymmetric_paths)
        || NULL == CU_add_test(s, "stream_path_replacement_refreshes_cache",
                               xqc_test_wlb_stream_path_replacement_refreshes_cache)
        || NULL == CU_add_test(s, "control_packets_use_minrtt",
                               xqc_test_wlb_control_packets_use_minrtt)
        || NULL == CU_add_test(s, "evicted_path_gets_recovery_probe",
                               xqc_test_wlb_evicted_path_gets_recovery_probe)
        || NULL == CU_add_test(s, "blackholed_path_does_not_stall_rounds",
                               xqc_test_wlb_blackholed_path_does_not_stall_rounds)
        || NULL == CU_add_test(s, "unpinned_blackhole_refreshes_topology",
                               xqc_test_wlb_unpinned_blackhole_refreshes_topology)
        || NULL == CU_add_test(s, "routine_path_event_preserves_round",
                               xqc_test_wlb_routine_path_event_preserves_round)
        || NULL == CU_add_test(s, "measured_goodput_ignores_loss_penalty",
                               xqc_test_wlb_measured_goodput_ignores_loss_penalty)
        || NULL == CU_add_test(s, "equal_goodput_is_balanced",
                               xqc_test_wlb_equal_goodput_is_balanced)
        || NULL == CU_add_test(s, "four_to_one_goodput_after_acked_warmup",
                               xqc_test_wlb_four_to_one_goodput_after_acked_warmup)
        || NULL == CU_add_test(s, "new_path_gets_warmup_floor",
                               xqc_test_wlb_new_path_gets_warmup_floor)
        || NULL == CU_add_test(s, "steady_path_gets_exploration_floor",
                               xqc_test_wlb_steady_path_gets_exploration_floor)
        || NULL == CU_add_test(s, "active_time_ends_warmup",
                               xqc_test_wlb_active_time_ends_warmup)
        || NULL == CU_add_test(s, "idle_time_does_not_end_warmup",
                               xqc_test_wlb_idle_time_does_not_end_warmup)
        || NULL == CU_add_test(s, "latency_policy_uses_minrtt",
                               xqc_test_wlb_latency_policy_uses_minrtt)
        || NULL == CU_add_test(s, "path_stats_snapshot",
                               xqc_test_wlb_path_stats_snapshot)
        || NULL == CU_add_test(s, "pinned_flow_refreshes_delivery_sample",
                               xqc_test_wlb_pinned_flow_refreshes_delivery_sample)
        || NULL == CU_add_test(s, "warmup_time_only_credits_selected_path",
                               xqc_test_wlb_warmup_time_only_credits_selected_path)
        || NULL == CU_add_test(s, "throughput_policy_resets_delivery_learning",
                               xqc_test_wlb_throughput_policy_resets_delivery_learning)
        || NULL == CU_add_test(s, "topology_refresh_clears_packet_deficit",
                               xqc_test_wlb_topology_refresh_clears_packet_deficit)
        || NULL == CU_add_test(s, "topology_refresh_clears_pin_deficit",
                               xqc_test_wlb_topology_refresh_clears_pin_deficit)
        || NULL == CU_add_test(s, "ewma_uses_exact_seven_eighths_history",
                               xqc_test_wlb_ewma_uses_exact_seven_eighths_history)
        || NULL == CU_add_test(s, "loss_above_two_percent_downweights_path",
                               xqc_test_wlb_loss_above_two_percent_downweights_path)
        || NULL == CU_add_test(s, "public_scid_policy_and_truncated_stats",
                               xqc_test_wlb_public_scid_policy_and_truncated_stats)
        || NULL == CU_add_test(s, "control_delivery_does_not_advance_learning",
                               xqc_test_wlb_control_delivery_does_not_advance_learning)
        || NULL == CU_add_test(s, "application_delivery_advances_learning",
                               xqc_test_wlb_application_delivery_advances_learning)
        || NULL == CU_add_test(s, "latency_policy_populates_stats_before_payload",
                               xqc_test_wlb_latency_policy_populates_stats_before_payload)
        || NULL == CU_add_test(s, "latency_policy_syncs_path_add_remove",
                               xqc_test_wlb_latency_policy_syncs_path_add_remove)
        || NULL == CU_add_test(s, "rejected_0rtt_does_not_advance_learning",
                               xqc_test_wlb_rejected_0rtt_does_not_advance_learning)
        || NULL == CU_add_test(s, "duplicate_ack_counts_application_once",
                               xqc_test_wlb_duplicate_ack_counts_application_once))
    {
        CU_cleanup_registry();
        return (int)CU_get_error();
    }

    CU_basic_set_mode(CU_BRM_VERBOSE);
    CU_basic_run_tests();
    unsigned failed = CU_get_number_of_tests_failed();
    CU_cleanup_registry();
    return (int)failed;
}
