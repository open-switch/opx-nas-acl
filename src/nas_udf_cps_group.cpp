/*
 * Copyright (c) 2016 Dell Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may
 * not use this file except in compliance with the License. You may obtain
 * a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
 *
 * THIS CODE IS PROVIDED ON AN  *AS IS* BASIS, WITHOUT WARRANTIES OR
 * CONDITIONS OF ANY KIND, EITHER EXPRESS OR IMPLIED, INCLUDING WITHOUT
 * LIMITATION ANY IMPLIED WARRANTIES OR CONDITIONS OF TITLE, FITNESS
 * FOR A PARTICULAR PURPOSE, MERCHANTABLITY OR NON-INFRINGEMENT.
 *
 * See the Apache Version 2.0 License for specific language governing
 * permissions and limitations under the License.
 */

/*!
 * \file   nas_udf_cps_group.cpp
 * \brief  This file contains CPS related UDF Group functionality
 * \date   10-2016
 */

#include "event_log.h"
#include "std_error_codes.h"
#include "nas_acl_log.h"
#include "cps_api_object_key.h"
#include "cps_class_map.h"
#include "nas_acl_switch_list.h"
#include "nas_acl_cps_key.h"

static bool nas_fill_udf_group_attr(cps_api_object_t cps_obj,
                                    const nas_udf_group& udf_grp,
                                    bool exp_npu_list = false)
{
    if (!cps_api_object_attr_add_u32(cps_obj, BASE_UDF_UDF_GROUP_TYPE,
                                     udf_grp.type())) {
        NAS_ACL_LOG_ERR("Failed to add attribute to object");
        return false;
    }

    uint8_t length = (uint8_t)udf_grp.length();
    if (!cps_api_object_attr_add(cps_obj, BASE_UDF_UDF_GROUP_LENGTH,
                                 &length, 1)) {
        NAS_ACL_LOG_ERR("Failed to add attribute to object");
        return false;
    }

    for (auto udf_id: udf_grp.udf_ids()) {
        if (!cps_api_object_attr_add_u64(cps_obj, BASE_UDF_UDF_GROUP_UDF_ID_LIST,
                                         udf_id)) {
            NAS_ACL_LOG_ERR("Failed to add attribute to object");
            return false;
        }
    }

    if (udf_grp.following_switch_npus() && !exp_npu_list) {
        return true;
    }

    for (auto npu_id: udf_grp.npu_list()) {
        if (!cps_api_object_attr_add_u32(cps_obj, BASE_UDF_UDF_GROUP_NPU_ID_LIST,
                                         npu_id)) {
            NAS_ACL_LOG_ERR("Failed to add attribute to object");
            return false;
        }
    }

    return true;
}

static t_std_error nas_get_udf_group_info(cps_api_object_list_t& cps_obj_list,
                                          const nas_udf_group& udf_grp)
{
    cps_api_object_t cps_obj =
        cps_api_object_list_create_obj_and_append(cps_obj_list);
    if (cps_obj == nullptr) {
        NAS_ACL_LOG_ERR("Obj append failed");
        return STD_ERR(UDF, FAIL, 0);
    }

    if (!cps_api_key_from_attr_with_qual(cps_api_object_key(cps_obj),
                                         BASE_UDF_UDF_GROUP_OBJ,
                                         cps_api_qualifier_TARGET)) {
        NAS_ACL_LOG_ERR("Failed to create key from UDF Group object");
        return STD_ERR(UDF, FAIL, 0);
    }

    if (!nas_acl_cps_key_set_obj_id(cps_obj, BASE_UDF_UDF_GROUP_ID,
                                    udf_grp.group_id())) {
        NAS_ACL_LOG_ERR("Failed to set UDF Group ID in key");
        return STD_ERR(UDF, FAIL, 0);
    }

    if (!nas_fill_udf_group_attr(cps_obj, udf_grp, true)) {
        NAS_ACL_LOG_ERR("Failed to fill UDF Group attrs");
        return STD_ERR(UDF, FAIL, 0);
    }

    return STD_ERR_OK;
}

static t_std_error nas_get_udf_group_info_by_switch(cps_api_get_params_t* param,
                                                    size_t index,
                                                    const nas_acl_switch& s)
{
    for (const auto& grp_pair: s.udf_group_list()) {
        if (nas_get_udf_group_info(param->list, grp_pair.second)
                != STD_ERR_OK) {
            NAS_ACL_LOG_ERR("Failed to get UDF Group info for switch");
            return STD_ERR(UDF, FAIL, 0);
        }
    }

    return STD_ERR_OK;
}

static t_std_error nas_get_udf_group_info_all (cps_api_get_params_t *param,
                                               size_t index)
{
   for (const auto& switch_pair: nas_acl_get_switch_list ()) {
       if (nas_get_udf_group_info_by_switch (param, index, switch_pair.second)
               != STD_ERR_OK) {
           NAS_ACL_LOG_ERR("Failed to get all UDF Group info");
           return STD_ERR(UDF, FAIL, 0);
       }
   }

   return cps_api_ret_code_OK;
}

t_std_error nas_udf_get_group(cps_api_get_params_t* param, size_t index,
                              cps_api_object_t filter_obj) noexcept
{
    t_std_error  rc = cps_api_ret_code_OK;
    nas_switch_id_t        switch_id = 0;
    nas_obj_id_t           group_id = 0;

    bool switch_id_key = nas_acl_cps_key_get_switch_id (filter_obj,
                                                        NAS_ACL_SWITCH_ATTR,
                                                        &switch_id);
    bool group_id_key = nas_acl_cps_key_get_obj_id (filter_obj,
                                                    BASE_UDF_UDF_GROUP_ID,
                                                    &group_id);
    try {
        if (!switch_id_key) {
            /* No keys provided */
            rc = nas_get_udf_group_info_all (param, index);
        }
        else if (switch_id_key && !group_id_key) {
            /* Switch Id provided */
            nas_acl_switch& s = nas_acl_get_switch (switch_id);
            rc = nas_get_udf_group_info_by_switch (param, index, s);
        }
        else if (switch_id_key && group_id_key) {
            /* Switch Id and Group Id provided */
            NAS_ACL_LOG_DETAIL ("Switch Id: %d, Group Id: %ld\n",
                                switch_id, group_id);

            nas_acl_switch& s = nas_acl_get_switch (switch_id);
            nas_udf_group*  udf_grp = s.find_udf_group (group_id);
            if (udf_grp == nullptr) {
                NAS_ACL_LOG_ERR("Invalid UDF Group ID");
                return STD_ERR(UDF, FAIL, 0);
            }

            rc = nas_get_udf_group_info (param->list, *udf_grp);
        }
        else {
            NAS_ACL_LOG_ERR("Unknown key combination");
            return STD_ERR(UDF, FAIL, 0);
        }
    } catch (nas::base_exception& e) {

        NAS_ACL_LOG_ERR ("Err_code: 0x%x, fn: %s (), %s", e.err_code,
                      e.err_fn.c_str (), e.err_msg.c_str ());

        rc = e.err_code;
    }

    return (rc);
}

t_std_error nas_udf_group_create(cps_api_object_t obj,
                                 cps_api_object_t prev,
                                 bool is_rollbk) noexcept
{
    nas_switch_id_t switch_id = 0;
    nas_obj_id_t group_id = 0;
    bool is_type_present = false, is_length_present = false;
    bool id_passed_in = false;
    cps_api_attr_id_t attr_id = 0;
    cps_api_object_it_t it {};

    if (obj == nullptr) {
        NAS_ACL_LOG_ERR("NULL pointer as input");
        return STD_ERR(UDF, PARAM, 0);
    }

    if (!nas_acl_cps_key_get_switch_id(obj, NAS_ACL_SWITCH_ATTR,
                                       &switch_id)) {
        NAS_ACL_LOG_ERR("Failed to get switch id");
        return STD_ERR(UDF, FAIL, 0);
    }

    if (nas_acl_cps_key_get_obj_id(obj, BASE_UDF_UDF_GROUP_ID, &group_id)) {
        id_passed_in = true;
        NAS_ACL_LOG_BRIEF("Group ID %lu provided for Group create", group_id);
    }

    try {
        nas_acl_switch& s = nas_acl_get_switch(switch_id);
        if (id_passed_in) {
            nas_udf_group* udf_grp_p = s.find_udf_group(group_id);
            if (udf_grp_p != nullptr) {
                NAS_ACL_LOG_ERR("Group ID %lu already taken", group_id);
                return STD_ERR(UDF, FAIL, 0);
            }
        }

        nas_udf_group udf_grp(&s);

        for (cps_api_object_it_begin(obj, &it); cps_api_object_it_valid(&it);
             cps_api_object_it_next(&it)) {
            attr_id = cps_api_object_attr_id(it.attr);
            switch(attr_id) {
            case BASE_UDF_UDF_GROUP_TYPE:
            {
                if (is_type_present) {
                    NAS_ACL_LOG_ERR("Duplicate group type attribute");
                    return STD_ERR(UDF, FAIL, 0);
                }
                is_type_present = true;
                uint_t type = cps_api_object_attr_data_u32(it.attr);
                udf_grp.set_type(type);
                break;
            }
            case BASE_UDF_UDF_GROUP_LENGTH:
            {
                if (is_length_present) {
                    NAS_ACL_LOG_ERR("Duplicate group type attribute");
                    return STD_ERR(UDF, FAIL, 0);
                }
                is_length_present = true;
                uint8_t* byte_p = (uint8_t*)cps_api_object_attr_data_bin(it.attr);
                udf_grp.set_length(byte_p[0]);
                break;
            }
            default:
                NAS_ACL_LOG_DETAIL("Unknown attribute ignored %lu(%lx)",
                                   attr_id, attr_id);
                break;
            }
        }

        if (!is_type_present || !is_length_present) {
            NAS_ACL_LOG_ERR("Mandatory attributes not exist");
            return STD_ERR(UDF, FAIL, 0);
        }

        if (id_passed_in) {
            s.reserve_udf_group_id(group_id);
        } else {
            group_id = s.alloc_udf_group_id();
        }
        udf_grp.set_group_id(group_id);

        try {
            udf_grp.commit_create(is_rollbk);
        } catch (nas::base_exception& e) {
            s.release_udf_group_id(group_id);
            throw e;
        }

        // WARNING !!! CANNOT throw error or exception beyond this point
        // since UDF group is already committed to SAI

        nas_udf_group& new_grp = s.save_udf_group(std::move(udf_grp));
        group_id = new_grp.group_id();
        if (!nas_acl_cps_key_set_obj_id(obj, BASE_UDF_UDF_GROUP_ID, group_id)) {
            NAS_ACL_LOG_ERR("Failed to set Group ID as key");
        }
        if (!is_rollbk) {
            cps_api_object_set_key(prev, cps_api_object_key(obj));
            nas_acl_cps_key_set_obj_id(prev, BASE_UDF_UDF_GROUP_ID, group_id);
        }
    } catch (nas::base_exception& e) {
        NAS_ACL_LOG_ERR("Err_code: 0x%x, fn: %s (), %s", e.err_code,
                        e.err_fn.c_str(), e.err_msg.c_str());
        return e.err_code;
    } catch (std::out_of_range& e) {
        NAS_ACL_LOG_ERR("Out of range exception %s", e.what());
        return STD_ERR(UDF, FAIL, 0);
    }

    return STD_ERR_OK;
}

t_std_error nas_udf_group_delete(cps_api_object_t obj,
                                 cps_api_object_t prev,
                                 bool is_rollbk) noexcept
{
    nas_switch_id_t switch_id = 0;
    nas_obj_id_t group_id = 0;

    if (obj == nullptr) {
        NAS_ACL_LOG_ERR("NULL pointer as input");
        return STD_ERR(UDF, PARAM, 0);
    }

    if (!nas_acl_cps_key_get_switch_id(obj, NAS_ACL_SWITCH_ATTR,
                                       &switch_id)) {
        NAS_ACL_LOG_ERR("Switch ID is a mandatory key for UDF Group Delete");
        return STD_ERR(UDF, FAIL, 0);
    }
    if (!nas_acl_cps_key_get_obj_id (obj, BASE_UDF_UDF_GROUP_ID, &group_id)) {
        NAS_ACL_LOG_ERR("Group ID is a mandatory key for UDF Group Delete");
        return STD_ERR(UDF, FAIL, 0);
    }

    NAS_ACL_LOG_BRIEF("%sSwitch Id: %d Group Id %ld",
                      (is_rollbk) ? "** ROLLBACK **: " : "", switch_id, group_id);

    try {
        nas_acl_switch& s = nas_acl_get_switch (switch_id);
        nas_udf_group* group_p = s.find_udf_group(group_id);
        if (group_p == nullptr) {
            NAS_ACL_LOG_ERR("Invalid UDF Group ID %lu", group_id);
            return STD_ERR(UDF, FAIL, 0);
        }

        if (!is_rollbk) {
            cps_api_object_set_key(prev, cps_api_object_key(obj));
            nas_acl_cps_key_set_obj_id(prev, BASE_UDF_UDF_GROUP_ID, group_id);
            nas_fill_udf_group_attr(prev, *group_p);
        }

        group_p->commit_delete(is_rollbk);

        // WARNING !!! CANNOT throw error or exception beyond this point
        // since UDF group is already deleted from SAI

        s.remove_udf_group(group_id);
        s.release_udf_group_id(group_id);

    } catch (nas::base_exception& e) {

        NAS_ACL_LOG_ERR ("Err_code: 0x%x, fn: %s (), %s", e.err_code,
                         e.err_fn.c_str (), e.err_msg.c_str ());

        return e.err_code;
    } catch (std::out_of_range& e) {
        NAS_ACL_LOG_ERR ("###########  Out of Range exception %s", e.what ());
        return STD_ERR(UDF, FAIL, 0);
    }

    return STD_ERR_OK;
}
