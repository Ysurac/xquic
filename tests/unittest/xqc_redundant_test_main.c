/**
 * @copyright Copyright (c) 2026, mp0rta
 *
 * Standalone CUnit driver for the redundant scheduler tests, mirroring
 * xqc_wrr_test_main.c — lets the suite be exercised in isolation against
 * the same libxquic-static.a the production build links, without needing
 * the full run_tests target.
 */
#include <stdio.h>
#include <CUnit/Basic.h>
#include <CUnit/CUnit.h>

#include "xqc_redundant_test.h"

static int redundant_suite_init(void) { return 0; }
static int redundant_suite_clean(void) { return 0; }

int
main(void)
{
    if (CU_initialize_registry() != CUE_SUCCESS) {
        return (int)CU_get_error();
    }

    CU_pSuite s = CU_add_suite("redundant", redundant_suite_init, redundant_suite_clean);
    if (s == NULL) {
        CU_cleanup_registry();
        return (int)CU_get_error();
    }

    if (NULL == CU_add_test(s, "two_paths_primary_and_replica",
                            xqc_test_redundant_two_paths_primary_and_replica)
        || NULL == CU_add_test(s, "three_paths_replicate_to_all_others",
                               xqc_test_redundant_three_paths_replicate_to_all_others)
        || NULL == CU_add_test(s, "cwnd_blocked_path_gets_no_replica",
                               xqc_test_redundant_cwnd_blocked_path_gets_no_replica)
        || NULL == CU_add_test(s, "frozen_path_excluded",
                               xqc_test_redundant_frozen_path_excluded)
        || NULL == CU_add_test(s, "reinject_call_returns_single_path_no_replica",
                               xqc_test_redundant_reinject_call_returns_single_path_no_replica)
        || NULL == CU_add_test(s, "all_paths_cwnd_blocked_returns_null_and_cc_blocked",
                               xqc_test_redundant_all_paths_cwnd_blocked_returns_null_and_cc_blocked)
        || NULL == CU_add_test(s, "single_path_no_replica_no_crash",
                               xqc_test_redundant_single_path_no_replica_no_crash))
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
