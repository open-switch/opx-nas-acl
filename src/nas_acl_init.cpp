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
#include "cps_class_map.h"
#include "cps_api_events.h"
#include "cps_api_operation.h"
#include "cps_class_map.h"
#include "cps_api_object_key.h"
#include "nas_acl_log.h"
#include "std_error_codes.h"
#include "nas_acl_cps.h"
#include "nas_udf_cps.h"
#include "nas_acl_init.h"
#include "nas_acl_log.h"
#include "nas_if_utils.h"
#include "dell-base-if.h"
#include "std_mutex_lock.h"
#include "dell-base-if-phy.h"

static bool nas_acl_if_set_handler(cps_api_object_t obj, void *context)
{
    const char *if_name = nullptr;
    cps_api_object_attr_t name_attr = cps_api_get_key_data(obj, IF_INTERFACES_INTERFACE_NAME);
    if (name_attr != nullptr) {
        if_name = (const char *)cps_api_object_attr_data_bin(name_attr);
    }
    NAS_ACL_LOG_BRIEF("Handling configuration message for interface %s",
               if_name != nullptr ? if_name : "UNKNOWN");

    cps_api_object_attr_t if_index_attr =
        cps_api_get_key_data(obj, DELL_BASE_IF_CMN_IF_INTERFACES_INTERFACE_IF_INDEX);
    if (if_index_attr == NULL) {
        NAS_ACL_LOG_ERR("Could not find ifindex attribute");
        return true;
    }
    uint32_t ifidx = cps_api_object_attr_data_u32(if_index_attr);

    cps_api_operation_types_t op = cps_api_object_type_operation(cps_api_object_key(obj));
    nas_int_port_mapping_t status = nas_int_phy_port_UNMAPPED;
    if (op == cps_api_oper_SET && nas_get_phy_port_mapping_change(obj, &status)) {
        NAS_ACL_LOG_BRIEF("Interface mapping changed to: %s",
                   status == nas_int_phy_port_MAPPED ? "Mapped" : "Un-mapped");
    } else {
        // Only listen to Interface mapping status change event
        return true;
    }

    cps_api_object_attr_t npu_attr = cps_api_object_attr_get(obj,
                                    BASE_IF_PHY_IF_INTERFACES_INTERFACE_NPU_ID);
    cps_api_object_attr_t port_attr = cps_api_object_attr_get(obj,
                                    BASE_IF_PHY_IF_INTERFACES_INTERFACE_PORT_ID);

    if (npu_attr == nullptr || port_attr == nullptr ) {
        NAS_ACL_LOG_BRIEF("Interface object does not have npu/port");
        return true;
    }

    npu_id_t npu_id = cps_api_object_attr_data_u32(npu_attr);
    npu_port_t npu_port = cps_api_object_attr_data_u32(port_attr);

    nas_switch_id_t switch_id = NAS_ACL_DEFAULT_SWITCH_ID();
    try {
        nas_acl_switch& sw = nas_acl_get_switch(switch_id);
        sw.process_intf_acl_bind(ifidx, npu_id, npu_port);
    } catch (nas::base_exception& e) {
        NAS_ACL_LOG_ERR("Err_code: 0x%x, fn: %s (), %s", e.err_code,
                        e.err_fn.c_str(), e.err_msg.c_str());
    } catch (std::exception& e) {
        NAS_ACL_LOG_ERR("Unknown Err: %s", e.what());
    }

    return true;
}

/*** NAS ACL Main Control block ***/
static std_mutex_lock_create_static_init_fast (nas_acl_mutex);

static t_std_error _cps_init ()
{
    cps_api_operation_handle_t       handle;
    cps_api_return_code_t            rc;
    cps_api_registration_functions_t f;
    char buff[CPS_API_KEY_STR_MAX];

    rc = cps_api_operation_subsystem_init (&handle,1);

    if (rc != cps_api_ret_code_OK) {
        NAS_ACL_LOG_ERR ("NAS ACL CPS Subsystem Init failed");
        return STD_ERR(ACL, FAIL, rc);
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
        return STD_ERR(ACL, FAIL, rc);
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
        return STD_ERR(ACL, FAIL, rc);
    }

    memset (&f, 0, sizeof(f));
    /*
     * Register to delete entries Action for for next-hop group
     */
    if (!cps_api_key_from_attr_with_qual(&f.key,BASE_ACL_CLEAR_ACL_ENTRIES_FOR_NH_OBJ,
                                         cps_api_qualifier_TARGET)) {
        NAS_ACL_LOG_ERR ("Could not translate %d to key %s",
                        (int)(BASE_ACL_CLEAR_ACL_ENTRIES_FOR_NH_OBJ),
                        cps_api_key_print(&f.key,buff,sizeof(buff)-1));

        return STD_ERR(ACL,FAIL,0);
    }

    f.handle = handle;
    f._write_function = nas_acl_delete_nh_acl_entry_action;

    rc = cps_api_register(&f);
    if (rc != cps_api_ret_code_OK) {
        NAS_ACL_LOG_ERR ("NAS ACL CLEAR NH CPS object Register failed");
        return STD_ERR(ACL,FAIL,rc);
    }

    memset (&f, 0, sizeof(f));

    f.handle             = handle;
    f._read_function     = nas_acl_profile_cps_api_read;
    f._write_function    = nas_acl_profile_cps_api_write;
    f._rollback_function = nas_acl_profile_cps_api_rollback;

    /*
     * Register all ACL profile objects
     */
    if (!cps_api_key_from_attr_with_qual(&f.key,BASE_ACL_SWITCHING_ENTITY_APP_GROUP,
                                         cps_api_qualifier_TARGET)) {
        NAS_ACL_LOG_ERR ("Could not translate %d to key %s",
                        (int)(BASE_ACL_SWITCHING_ENTITY_APP_GROUP),
                        cps_api_key_print(&f.key,buff,sizeof(buff)-1));

        return STD_ERR(ACL,FAIL,0);
    }

    rc = cps_api_register (&f);
    if (rc != cps_api_ret_code_OK) {
        NAS_ACL_LOG_ERR ("NAS ACL Profile CPS object Register failed");
        return STD_ERR(ACL, FAIL, rc);
    }

    memset (&f, 0, sizeof(f));

    f.handle             = handle;
    f._read_function     = nas_acl_profile_cps_api_read;

    /*
     * Register all ACL profile objects observed qualifier
     */
    if (!cps_api_key_from_attr_with_qual(&f.key,BASE_ACL_SWITCHING_ENTITY_APP_GROUP,
                                         cps_api_qualifier_OBSERVED)) {
        NAS_ACL_LOG_ERR ("Could not translate %d to key %s with observed qualifier",
                        (int)(BASE_ACL_SWITCHING_ENTITY_APP_GROUP),
                        cps_api_key_print(&f.key,buff,sizeof(buff)-1));

        return STD_ERR(ACL,FAIL,0);
    }

    rc = cps_api_register (&f);
    if (rc != cps_api_ret_code_OK) {
        NAS_ACL_LOG_ERR ("NAS ACL Profile CPS object Register failed for observed qualifier");
        return STD_ERR(ACL, FAIL, rc);
    }

    memset (&f, 0, sizeof(f));

    f.handle             = handle;
    f._read_function     = nas_acl_pool_info_cps_api_read;

    /*
     * Register all ACL pool info objects observed qualifier
     */
    if (!cps_api_key_from_attr_with_qual(&f.key,BASE_ACL_ACL_POOL_INFO_OBJ,
                                         cps_api_qualifier_OBSERVED)) {
        NAS_ACL_LOG_ERR ("Could not translate %d to key %s with observed qualifier",
                        (int)(BASE_ACL_ACL_POOL_INFO_OBJ),
                        cps_api_key_print(&f.key,buff,sizeof(buff)-1));

        return STD_ERR(ACL,FAIL,0);
    }

    rc = cps_api_register (&f);
    if (rc != cps_api_ret_code_OK) {
        NAS_ACL_LOG_ERR ("NAS ACL pool info CPS object Register failed for observed qualifier");
        return STD_ERR(ACL, FAIL, rc);
    }

    memset (&f, 0, sizeof(f));

    f.handle             = handle;
    f._read_function     = nas_acl_table_info_cps_api_read;

    /*
     * Register all ACL table info objects observed qualifier
     */
    if (!cps_api_key_from_attr_with_qual(&f.key,BASE_ACL_ACL_TABLE_OBJ,
                                         cps_api_qualifier_OBSERVED)) {
        NAS_ACL_LOG_ERR ("Could not translate %d to key %s with observed qualifier",
                        (int)(BASE_ACL_ACL_TABLE_OBJ),
                        cps_api_key_print(&f.key,buff,sizeof(buff)-1));

        return STD_ERR(ACL,FAIL,0);
    }

    rc = cps_api_register (&f);
    if (rc != cps_api_ret_code_OK) {
        NAS_ACL_LOG_ERR ("NAS ACL table info CPS object Register failed for observed qualifier");
        return STD_ERR(ACL, FAIL, rc);
    }

    // Register interface creation/deletion event
    cps_api_event_reg_t reg;
    cps_api_key_t key;

    memset(&reg, 0, sizeof(cps_api_event_reg_t));

    if (!cps_api_key_from_attr_with_qual(&key,
            DELL_BASE_IF_CMN_IF_INTERFACES_INTERFACE_OBJ,
            cps_api_qualifier_OBSERVED)) {
        NAS_ACL_LOG_ERR("Cannot create a key for interface event");
        return STD_ERR(ACL, FAIL, 0);
    }

    reg.objects = &key;
    reg.number_of_objects = 1;

    if (cps_api_event_thread_reg(&reg, nas_acl_if_set_handler, NULL)
            != cps_api_ret_code_OK) {
        NAS_ACL_LOG_ERR("Cannot register interface operation event");
        return STD_ERR(ACL, FAIL, 0);
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
