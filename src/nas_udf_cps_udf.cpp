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
 * \file   nas_udf_cps_udf.cpp
 * \brief  This file contains CPS related UDF functionality
 * \date   10-2016
 */

#include "event_log.h"
#include "std_error_codes.h"
#include "nas_acl_log.h"
#include "cps_api_object_key.h"
#include "cps_class_map.h"
#include "nas_acl_switch_list.h"
#include "nas_acl_cps_key.h"

static bool nas_fill_udf_attr(cps_api_object_t cps_obj,
                              const nas_udf& udf,
                              bool exp_npu_list = false)
{
    if (!cps_api_object_attr_add_u64(cps_obj, BASE_UDF_UDF_OBJ_GROUP_ID,
                                     udf.udf_group_id())) {
        NAS_ACL_LOG_ERR("Failed to add attribute to object");
        return false;
    }
    if (!cps_api_object_attr_add_u64(cps_obj, BASE_UDF_UDF_OBJ_MATCH_ID,
                                     udf.udf_match_id())) {
        NAS_ACL_LOG_ERR("Failed to add attribute to object");
        return false;
    }
    if (!cps_api_object_attr_add_u32(cps_obj, BASE_UDF_UDF_OBJ_BASE,
                                     udf.base())) {
        NAS_ACL_LOG_ERR("Failed to add attribute to object");
        return false;
    }
    if (!cps_api_object_attr_add_u32(cps_obj, BASE_UDF_UDF_OBJ_OFFSET,
                                     udf.offset())) {
        NAS_ACL_LOG_ERR("Failed to add attribute to object");
        return false;
    }
    size_t byte_cnt = 0;
    udf.hash_mask(NULL, byte_cnt);
    if (byte_cnt > 0) {
        std::vector<uint8_t> byte_list(byte_cnt);
        udf.hash_mask(byte_list.data(), byte_cnt);
        for (uint8_t bval: byte_list) {
            if (!cps_api_object_attr_add(cps_obj, BASE_UDF_UDF_OBJ_HASH_MASK,
                                         &bval, 1)) {
                return false;
            }
        }
    }

    if (udf.following_switch_npus() && !exp_npu_list) {
        return true;
    }

    for (auto npu_id: udf.npu_list()) {
        if (!cps_api_object_attr_add_u32(cps_obj, BASE_UDF_UDF_OBJ_NPU_ID_LIST,
                                         npu_id)) {
            NAS_ACL_LOG_ERR("Failed to add attribute to object");
            return false;
        }
    }

    return true;
}

static t_std_error nas_get_udf_info(cps_api_object_list_t& cps_obj_list,
                                    const nas_udf& udf)
{
    cps_api_object_t cps_obj =
        cps_api_object_list_create_obj_and_append(cps_obj_list);
    if (cps_obj == nullptr) {
        NAS_ACL_LOG_ERR("Obj append failed");
        return STD_ERR(UDF, FAIL, 0);
    }

    if (!cps_api_key_from_attr_with_qual(cps_api_object_key(cps_obj),
                                         BASE_UDF_UDF_OBJ_OBJ,
                                         cps_api_qualifier_TARGET)) {
        NAS_ACL_LOG_ERR("Failed to create key from UDF object");
        return STD_ERR(UDF, FAIL, 0);
    }

    if (!nas_acl_cps_key_set_obj_id(cps_obj, BASE_UDF_UDF_OBJ_ID,
                                    udf.udf_id())) {
        NAS_ACL_LOG_ERR("Failed to set UDF ID in key");
        return STD_ERR(UDF, FAIL, 0);
    }

    if (!nas_fill_udf_attr(cps_obj, udf, true)) {
        NAS_ACL_LOG_ERR("Failed to fill UDF attrs");
        return STD_ERR(UDF, FAIL, 0);
    }

    return STD_ERR_OK;
}

static t_std_error nas_get_udf_info_by_switch(cps_api_get_params_t* param,
                                              size_t index,
                                              const nas_acl_switch& s)
{
    for (const auto& udf_pair: s.udf_obj_list()) {
        if (nas_get_udf_info(param->list, udf_pair.second)
                != STD_ERR_OK) {
            NAS_ACL_LOG_ERR("Failed to get UDF Match info for switch");
            return STD_ERR(UDF, FAIL, 0);
        }
    }

    return STD_ERR_OK;
}

static t_std_error nas_get_udf_info_all (cps_api_get_params_t *param,
                                         size_t index)
{
   for (const auto& switch_pair: nas_acl_get_switch_list ()) {
       if (nas_get_udf_info_by_switch (param, index, switch_pair.second)
               != STD_ERR_OK) {
           NAS_ACL_LOG_ERR("Failed to get all UDF Match info");
           return STD_ERR(UDF, FAIL, 0);
       }
   }

   return cps_api_ret_code_OK;
}


t_std_error nas_udf_get_udf(cps_api_get_params_t* param, size_t index,
                            cps_api_object_t filter_obj) noexcept
{
    t_std_error  rc = cps_api_ret_code_OK;
    nas_switch_id_t        switch_id;
    nas_obj_id_t           udf_id;

    bool switch_id_key = nas_acl_cps_key_get_switch_id (filter_obj,
                                                        NAS_ACL_SWITCH_ATTR,
                                                        &switch_id);
    bool udf_id_key = nas_acl_cps_key_get_obj_id (filter_obj,
                                                    BASE_UDF_UDF_OBJ_ID,
                                                    &udf_id);
    try {
        if (!switch_id_key) {
            /* No keys provided */
            rc = nas_get_udf_info_all (param, index);
        }
        else if (switch_id_key && !udf_id_key) {
            /* Switch Id provided */
            nas_acl_switch& s = nas_acl_get_switch (switch_id);
            rc = nas_get_udf_info_by_switch (param, index, s);
        }
        else if (switch_id_key && udf_id_key) {
            /* Switch Id and UDF Id provided */
            NAS_ACL_LOG_DETAIL ("Switch Id: %d, UDF Id: %ld\n",
                                switch_id, udf_id);

            nas_acl_switch& s = nas_acl_get_switch (switch_id);
            nas_udf* udf_p = s.find_udf(udf_id);
            if (udf_p == nullptr) {
                throw nas::base_exception {NAS_ACL_E_ATTR_VAL, __FUNCTION__,
                    "Invalid UDF ID"};
            }

            rc = nas_get_udf_info (param->list, *udf_p);
        }
        else {
            throw nas::base_exception {NAS_ACL_E_MISSING_KEY, __FUNCTION__,
                "Unknown Key combination "};
        }
    } catch (nas::base_exception& e) {

        NAS_ACL_LOG_ERR ("Err_code: 0x%x, fn: %s (), %s", e.err_code,
                      e.err_fn.c_str (), e.err_msg.c_str ());

        rc = e.err_code;
    }

    return (rc);
}

t_std_error nas_udf_create(cps_api_object_t obj, cps_api_object_t prev,
                           bool is_rollbk) noexcept
{
    nas_switch_id_t switch_id = 0;
    nas_obj_id_t udf_id = 0;
    bool id_passed_in = false;
    bool is_group_id_present = false, is_match_id_present = false;
    bool is_base_present = false, is_offset_present = false;
    bool is_hash_mask_present = false;
    nas_obj_id_t group_id = 0, match_id = 0;
    std::vector<uint8_t> hash_mask;
    cps_api_attr_id_t attr_id = 0;
    cps_api_object_it_t it{};

    if (obj == nullptr) {
        NAS_ACL_LOG_ERR("NULL pointer as input");
        return STD_ERR(UDF, PARAM, 0);
    }

    if (!nas_acl_cps_key_get_switch_id(obj, NAS_ACL_SWITCH_ATTR,
                                       &switch_id)) {
        NAS_ACL_LOG_ERR("Failed to get switch id");
        return STD_ERR(UDF, FAIL, 0);
    }

    if (nas_acl_cps_key_get_obj_id(obj, BASE_UDF_UDF_OBJ_ID, &udf_id)) {
        id_passed_in = true;
        NAS_ACL_LOG_BRIEF("UDF ID %lu provided for UDF create", udf_id);
    }

    try {
        nas_acl_switch& s = nas_acl_get_switch(switch_id);
        if (id_passed_in) {
            nas_udf* udf_p = s.find_udf(udf_id);
            if (udf_p != nullptr) {
                NAS_ACL_LOG_ERR("UDF ID %lu already taken", udf_id);
                return STD_ERR(UDF, FAIL, 0);
            }
        }

        nas_udf udf(&s);

        for (cps_api_object_it_begin(obj, &it); cps_api_object_it_valid(&it);
             cps_api_object_it_next(&it)) {
            attr_id = cps_api_object_attr_id(it.attr);
            switch(attr_id) {
            case BASE_UDF_UDF_OBJ_GROUP_ID:
                if (is_group_id_present) {
                    NAS_ACL_LOG_ERR("Duplicate UDF group ID attribute");
                    return STD_ERR(UDF, FAIL, 0);
                }
                is_group_id_present = true;
                udf.set_udf_group_id(group_id = cps_api_object_attr_data_u64(it.attr));
                break;
            case BASE_UDF_UDF_OBJ_MATCH_ID:
                if (is_match_id_present) {
                    NAS_ACL_LOG_ERR("Duplicate UDF match ID attribute");
                    return STD_ERR(UDF, FAIL, 0);
                }
                is_match_id_present = true;
                udf.set_udf_match_id(match_id = cps_api_object_attr_data_u64(it.attr));
                break;
            case BASE_UDF_UDF_OBJ_BASE:
                if (is_base_present) {
                    NAS_ACL_LOG_ERR("Duplicate base attribute");
                    return STD_ERR(UDF, FAIL, 0);
                }
                is_base_present = true;
                udf.set_base(cps_api_object_attr_data_u32(it.attr));
                break;
            case BASE_UDF_UDF_OBJ_OFFSET:
                if (is_offset_present) {
                    NAS_ACL_LOG_ERR("Duplicate offset attribute");
                    return STD_ERR(UDF, FAIL, 0);
                }
                is_offset_present = true;
                udf.set_offset(cps_api_object_attr_data_u32(it.attr));
                break;
            case BASE_UDF_UDF_OBJ_HASH_MASK:
                is_hash_mask_present = true;
                hash_mask.push_back(((uint8_t*)cps_api_object_attr_data_bin(it.attr))[0]);
                break;
            default:
                NAS_ACL_LOG_DETAIL("Unknown attribute ignored %lu(%lx)",
                                   attr_id, attr_id);
                break;
            }
        }

        if (!is_group_id_present || !is_match_id_present ||
            !is_base_present) {
            NAS_ACL_LOG_ERR("Mandatory attributes not exist");
            return STD_ERR(UDF, FAIL, 0);
        }

        nas_udf_group* udf_grp_p = s.find_udf_group(group_id);
        nas_udf_match* udf_match_p = s.find_udf_match(match_id);
        if (udf_grp_p == nullptr || udf_match_p == nullptr) {
            NAS_ACL_LOG_ERR("Invalid UDF group or match ID");
            return STD_ERR(UDF, FAIL, 0);
        }

        if (udf_grp_p->type() == BASE_UDF_UDF_GROUP_TYPE_HASH && is_hash_mask_present) {
            // Only set hash mask for UDF in hash group
            udf.set_hash_mask(hash_mask.data(), hash_mask.size());
        }

        if (id_passed_in) {
            s.reserve_udf_id(udf_id);
        } else {
            udf_id = s.alloc_udf_id();
        }
        udf.set_udf_id(udf_id);

        try {
            udf.commit_create(is_rollbk);
        } catch (nas::base_exception& e) {
            s.release_udf_id(udf_id);
            throw e;
        }

        // WARNING !!! CANNOT throw error or exception beyond this point
        // since UDF is already committed to SAI

        nas_udf& new_udf = s.save_udf(std::move(udf));
        udf_id = new_udf.udf_id();
        if (!nas_acl_cps_key_set_obj_id(obj, BASE_UDF_UDF_OBJ_ID, udf_id)) {
            NAS_ACL_LOG_ERR("Failed to set UDF ID as key");
        }
        if (!is_rollbk) {
            cps_api_object_set_key(prev, cps_api_object_key(obj));
            nas_acl_cps_key_set_obj_id(prev, BASE_UDF_UDF_OBJ_ID, udf_id);
        }

        try {
            udf_grp_p->add_udf_id(udf_id);
            udf_match_p->add_udf_id(udf_id);
        } catch (nas::base_exception& e) {
            NAS_ACL_LOG_ERR("Fail to add UDF ID, code: 0x%x, fn: %s (), %s",
                            e.err_code,
                            e.err_fn.c_str(), e.err_msg.c_str());
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

t_std_error nas_udf_delete(cps_api_object_t obj,
                           cps_api_object_t prev,
                           bool is_rollbk) noexcept
{
    nas_switch_id_t switch_id = 0;
    nas_obj_id_t udf_id = 0;

    if (obj == nullptr) {
        NAS_ACL_LOG_ERR("NULL pointer as input");
        return STD_ERR(UDF, PARAM, 0);
    }

    if (!nas_acl_cps_key_get_switch_id(obj, NAS_ACL_SWITCH_ATTR,
                                       &switch_id)) {
        NAS_ACL_LOG_ERR("Switch ID is a mandatory key for UDF Delete");
        return STD_ERR(UDF, FAIL, 0);
    }
    if (!nas_acl_cps_key_get_obj_id (obj, BASE_UDF_UDF_OBJ_ID, &udf_id)) {
        NAS_ACL_LOG_ERR("Match ID is a mandatory key for UDF Delete");
        return STD_ERR(UDF, FAIL, 0);
    }

    NAS_ACL_LOG_BRIEF("%sSwitch Id: %d UDF Id %ld",
                      (is_rollbk) ? "** ROLLBACK **: " : "", switch_id, udf_id);

    try {
        nas_acl_switch& s = nas_acl_get_switch (switch_id);
        nas_udf* udf_p = s.find_udf(udf_id);
        if (udf_p == nullptr) {
            NAS_ACL_LOG_ERR("UDF ID %lu not found", udf_id);
            return STD_ERR(UDF, FAIL, 0);
        }

        if (!is_rollbk) {
            cps_api_object_set_key(prev, cps_api_object_key(obj));
            nas_acl_cps_key_set_obj_id(prev, BASE_UDF_UDF_OBJ_ID, udf_id);
            nas_fill_udf_attr(prev, *udf_p);
        }

        udf_p->commit_delete(is_rollbk);

        // WARNING !!! CANNOT throw error or exception beyond this point
        // since UDF is already deleted from SAI

        s.remove_udf(udf_id);
        s.release_udf_id(udf_id);

        nas_udf_group* udf_grp_p = s.find_udf_group(udf_p->udf_group_id());
        nas_udf_match* udf_match_p = s.find_udf_match(udf_p->udf_match_id());

        try {
            if (udf_grp_p != nullptr) {
                udf_grp_p->del_udf_id(udf_id);
            }
            if (udf_match_p != nullptr) {
                udf_match_p->del_udf_id(udf_id);
            }
        } catch (nas::base_exception& e) {
            NAS_ACL_LOG_ERR("Fail to delete UDF ID, code: 0x%x, fn: %s (), %s",
                            e.err_code,
                            e.err_fn.c_str(), e.err_msg.c_str());
        }

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
