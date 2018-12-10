/*
 * Copyright (c) 2018 Dell Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may
 * not use this file except in compliance with the License. You may obtain
 * a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
 *
 * THIS CODE IS PROVIDED ON AN *AS IS* BASIS, WITHOUT WARRANTIES OR
 * CONDITIONS OF ANY KIND, EITHER EXPRESS OR IMPLIED, INCLUDING WITHOUT
 * LIMITATION ANY IMPLIED WARRANTIES OR CONDITIONS OF TITLE, FITNESS
 * FOR A PARTICULAR PURPOSE, MERCHANTABLITY OR NON-INFRINGEMENT.
 *
 * See the Apache Version 2.0 License for specific language governing
 * permissions and limitations under the License.
 */

#ifndef _NAS_ACL_DB_UT_H_
#define _NAS_ACL_DB_UT_H_

#include "nas_ndi_obj_id_table.h"

#define UT_RESET_NPU  100
#define UT_RESET_FTYPE 100
#define UT_RESET_ATYPE 100
int& ut_simulate_ndi_entry_create_error ();
int& ut_simulate_ndi_entry_delete_error();
int& ut_simulate_ndi_entry_priority_error();
int& ut_simulate_ndi_entry_filter_error_npu();
int& ut_simulate_ndi_entry_filter_error_ftype();
int& ut_simulate_ndi_entry_action_error_npu();
int& ut_simulate_ndi_entry_action_error_atype ();
#endif
