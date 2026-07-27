/**
 * @copyright Copyright (c) 2026, mp0rta
 *
 * Standalone CUnit driver for the WRR scheduler tests, mirroring
 * xqc_wlb_test_main.c — lets the WRR suite be exercised in isolation
 * against the same libxquic-static.a the production build links, without
 * needing the full run_tests target.
 */
#include <stdio.h>
#include <CUnit/Basic.h>
#include <CUnit/CUnit.h>

#include "xqc_wrr_test.h"

static int wrr_suite_init(void) { return 0; }
static int wrr_suite_clean(void) { return 0; }

int
main(void)
{
    if (CU_initialize_registry() != CUE_SUCCESS) {
        return (int)CU_get_error();
    }

    CU_pSuite s = CU_add_suite("wrr", wrr_suite_init, wrr_suite_clean);
    if (s == NULL) {
        CU_cleanup_registry();
        return (int)CU_get_error();
    }

    if (NULL == CU_add_test(s, "equal_weights_alternate",
                            xqc_test_wrr_equal_weights_alternate)
        || NULL == CU_add_test(s, "weighted_ratio_3_1",
                               xqc_test_wrr_weighted_ratio_3_1)
        || NULL == CU_add_test(s, "blocked_path_still_accrues_and_catches_up",
                               xqc_test_wrr_blocked_path_still_accrues_and_catches_up)
        || NULL == CU_add_test(s, "control_packets_use_minrtt_and_dont_perturb_weight_state",
                               xqc_test_wrr_control_packets_use_minrtt_and_dont_perturb_weight_state)
        || NULL == CU_add_test(s, "all_paths_cwnd_blocked_returns_null_and_cc_blocked",
                               xqc_test_wrr_all_paths_cwnd_blocked_returns_null_and_cc_blocked)
        || NULL == CU_add_test(s, "weight_zero_treated_as_one",
                               xqc_test_wrr_weight_zero_treated_as_one)
        || NULL == CU_add_test(s, "path_removed_no_crash",
                               xqc_test_wrr_path_removed_no_crash))
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
