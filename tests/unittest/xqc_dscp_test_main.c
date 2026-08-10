/**
 * @copyright Copyright (c) 2026, mp0rta
 *
 * Standalone CUnit driver for the DSCP scheduler tests, mirroring
 * xqc_wrr_test_main.c — lets the DSCP suite be exercised in isolation
 * against the same libxquic-static.a the production build links, without
 * needing the full run_tests target.
 */
#include <stdio.h>
#include <CUnit/Basic.h>
#include <CUnit/CUnit.h>

#include "xqc_dscp_test.h"

static int dscp_suite_init(void) { return 0; }
static int dscp_suite_clean(void) { return 0; }

int
main(void)
{
    if (CU_initialize_registry() != CUE_SUCCESS) {
        return (int)CU_get_error();
    }

    CU_pSuite s = CU_add_suite("dscp", dscp_suite_init, dscp_suite_clean);
    if (s == NULL) {
        CU_cleanup_registry();
        return (int)CU_get_error();
    }

    if (NULL == CU_add_test(s, "untagged_uses_minrtt_ignoring_masks",
                            xqc_test_dscp_untagged_uses_minrtt_ignoring_masks)
        || NULL == CU_add_test(s, "tagged_routes_to_assigned_path",
                               xqc_test_dscp_tagged_routes_to_assigned_path)
        || NULL == CU_add_test(s, "tagged_breaks_tie_by_minrtt_among_assigned",
                               xqc_test_dscp_tagged_breaks_tie_by_minrtt_among_assigned)
        || NULL == CU_add_test(s, "tagged_falls_back_to_minrtt_when_assigned_path_blocked",
                               xqc_test_dscp_tagged_falls_back_to_minrtt_when_assigned_path_blocked)
        || NULL == CU_add_test(s, "tagged_falls_back_to_minrtt_when_no_path_assigned",
                               xqc_test_dscp_tagged_falls_back_to_minrtt_when_no_path_assigned)
        || NULL == CU_add_test(s, "all_paths_cwnd_blocked_returns_null_and_cc_blocked",
                               xqc_test_dscp_all_paths_cwnd_blocked_returns_null_and_cc_blocked)
        || NULL == CU_add_test(s, "unassigned_path_still_used_as_fallback",
                               xqc_test_dscp_unassigned_path_still_used_as_fallback))
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
