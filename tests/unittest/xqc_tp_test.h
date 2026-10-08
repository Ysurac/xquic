/**
 * @copyright Copyright (c) 2022, Alibaba Group Holding Limited
 */

#ifndef _XQC_TP_TEST_H_
#define _XQC_TP_TEST_H_

void xqc_test_transport_params();
void xqc_test_tp_value_not_longer_than_len(void);
void xqc_test_tp_value_matches_len_decodes(void);
void xqc_test_tp_cid_overflow();
void xqc_test_check_transport_params_cids();

#endif
