/*
 * Copyright (c) 2016 Dell Inc.
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

#include "cps_api_errors.h"
#include "nas_acl_cps_ut.h"

void intf_init (npu_id_t num_npus, npu_port_t num_ports);
void  nas_acl_ut_env_init ()
{
    nas_switch_init();
    intf_init (NAS_ACL_UT_MAX_NPUS, NAS_ACL_UT_NUM_PORTS_PER_NPU);
}

cps_api_return_code_t
nas_acl_ut_cps_api_commit (cps_api_transaction_params_t *param,
                           bool                          rollback_required)
{
    cps_api_return_code_t rc = cps_api_ret_code_OK;
    int                   index;
    int                   max;

    max = cps_api_object_list_size (param->change_list);

    for (index = 0; index < max; ++index) {

        rc = nas_acl_cps_api_write (NULL, param, index);

        if (rc != cps_api_ret_code_OK) {
            ut_printf ("%s(): nas_acl_cps_api_write() failed. \r\n", __FUNCTION__);
            break;
        }
    }

    if ((rc != cps_api_ret_code_OK) && (rollback_required == true)) {

        max = index;

        for (index = 0 ; index < max ; ++index ) {

            rc = nas_acl_cps_api_write (NULL, param, index);

            if (rc != cps_api_ret_code_OK) {
                ut_printf ("%s(): ROLLBACK failed. Index - %d.\r\n",
                           __FUNCTION__, index);
            }
        }
    }

    return rc;
}

cps_api_return_code_t nas_acl_ut_cps_api_get (cps_api_get_params_t *param,
                                              size_t                index)
{
    cps_api_return_code_t rc = cps_api_ret_code_OK;

    rc = nas_acl_cps_api_read (NULL, param, index);

    return rc;
}

bool nas_acl_ut_is_on_target ()
{
    return false;
}
