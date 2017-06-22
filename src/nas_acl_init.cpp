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

/*!
 * \file   nas_acl_init.cpp
 * \brief  NAS ACL Entry Point
 * \date   02-2015
 */
#include "cps_api_events.h"
#include "cps_api_operation.h"
#include "nas_acl_log.h"
#include "std_error_codes.h"
#include "nas_acl_cps.h"
#include "nas_udf_cps.h"
#include "nas_acl_init.h"
#include "std_mutex_lock.h"

/*** NAS ACL Main Control block ***/
std_mutex_lock_create_static_init_fast (nas_acl_mutex);

static t_std_error _cps_init ()
{
    cps_api_operation_handle_t       handle;
    cps_api_return_code_t            rc;
    cps_api_registration_functions_t f;

    rc = cps_api_operation_subsystem_init (&handle,1);

    if (rc != cps_api_ret_code_OK) {
        NAS_ACL_LOG_ERR ("NAS ACL CPS Subsystem Init failed");
        return STD_ERR(QOS, FAIL, rc);
    }

    memset (&f, 0, sizeof(f));

    f.handle             = handle;
    f._read_function     = nas_acl_cps_api_read;
    f._write_function    = nas_acl_cps_api_write;
    f._rollback_function = nas_acl_cps_api_rollback;

    /*
     * Register all ACL objects
     * TODO: Need to check with CPS app teams, if ACL needs to register for
     * OBSERVED state.
     */
    cps_api_key_init (&f.key,
                      cps_api_qualifier_TARGET,
                      cps_api_obj_CAT_BASE_ACL,
                      0, /* register all sub-categories */
                      0);

    rc = cps_api_register (&f);

    if (rc != cps_api_ret_code_OK) {
        NAS_ACL_LOG_ERR ("NAS ACL CPS object Register failed");
        return STD_ERR(QOS, FAIL, rc);
    }

    memset (&f, 0, sizeof(f));

    f.handle             = handle;
    f._read_function     = nas_udf_cps_api_read;
    f._write_function    = nas_udf_cps_api_write;
    f._rollback_function = nas_udf_cps_api_rollback;

    /*
     * Register all UDF objects
     */
    cps_api_key_init (&f.key,
                      cps_api_qualifier_TARGET,
                      cps_api_obj_CAT_BASE_UDF,
                      0, /* register all sub-categories */
                      0);

    rc = cps_api_register (&f);

    if (rc != cps_api_ret_code_OK) {
        NAS_ACL_LOG_ERR ("NAS UDF CPS object Register failed");
        return STD_ERR(QOS, FAIL, rc);
    }


    return STD_ERR_OK;
}

int nas_acl_lock () noexcept
{
    return (std_mutex_lock (&nas_acl_mutex));
}

int nas_acl_unlock () noexcept
{
    return (std_mutex_unlock (&nas_acl_mutex));
}

extern "C" {

t_std_error nas_acl_init(void)
{
    t_std_error rc = STD_ERR_OK;

    NAS_ACL_LOG_BRIEF ("Initializing NAS-ACL");

    do {
        if ((rc = _cps_init ()) != STD_ERR_OK) {
            break;
        }

    } while (0);

    return rc;
}
}
