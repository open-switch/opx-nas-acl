/*
 * Copyright (c) 2017 Dell Inc.
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
 * \file   nas_acl_cps_range.cpp
 * \brief  This file contains CPS related ACL Range functionality
 * \date   05-2017
 */

#include "event_log.h"
#include "std_error_codes.h"
#include "nas_acl_log.h"
#include "cps_api_object_key.h"
#include "cps_class_map.h"
#include "nas_acl_switch_list.h"
#include "nas_acl_cps_key.h"
#include "nas_acl_cps.h"

static bool nas_fill_acl_range_attr(cps_api_object_t cps_obj,
                                    const nas_acl_range& acl_range,
                                    bool exp_npu_list = false)
{
    if (!cps_api_object_attr_add_u32(cps_obj, BASE_ACL_RANGE_TYPE,
                                     acl_range.type())) {
        NAS_ACL_LOG_ERR("Failed to add range type attribute to object");
        return false;
    }

    if (!cps_api_object_attr_add_u32(cps_obj, BASE_ACL_RANGE_LIMIT_MIN,
                                     acl_range.limit_min())) {
        NAS_ACL_LOG_ERR("Failed to add limit min attribute to object");
        return false;
    }

    if (!cps_api_object_attr_add_u32(cps_obj, BASE_ACL_RANGE_LIMIT_MAX,
                                     acl_range.limit_max())) {
        NAS_ACL_LOG_ERR("Failed to add limit max attribute to object");
        return false;
    }

    if (acl_range.following_switch_npus() && !exp_npu_list) {
        return true;
    }

    return true;
}

static t_std_error nas_get_acl_range_info(cps_api_object_list_t& cps_obj_list,
                                          const nas_acl_range& acl_range)
{
    cps_api_object_t cps_obj =
        cps_api_object_list_create_obj_and_append(cps_obj_list);
    if (cps_obj == nullptr) {
        NAS_ACL_LOG_ERR("Obj append failed");
        return STD_ERR(ACL, FAIL, 0);
    }

    if (!cps_api_key_from_attr_with_qual(cps_api_object_key(cps_obj),
                                         BASE_ACL_RANGE_OBJ,
                                         cps_api_qualifier_TARGET)) {
        NAS_ACL_LOG_ERR("Failed to create key from ACL range object");
        return STD_ERR(ACL, FAIL, 0);
    }

    if (!nas_acl_cps_key_set_obj_id(cps_obj, BASE_ACL_RANGE_ID,
                                    acl_range.range_id())) {
        NAS_ACL_LOG_ERR("Failed to set ACL Range ID in key");
        return STD_ERR(ACL, FAIL, 0);
    }

    if (!nas_fill_acl_range_attr(cps_obj, acl_range, true)) {
        NAS_ACL_LOG_ERR("Failed to fill ACL Range attrs");
        return STD_ERR(ACL, FAIL, 0);
    }

    return STD_ERR_OK;
}

static t_std_error nas_get_acl_range_info_by_switch(cps_api_get_params_t* param,
                                                    size_t index,
                                                    const nas_acl_switch& s)
{
    for (const auto& range_pair: s.range_obj_list()) {
        if (nas_get_acl_range_info(param->list, range_pair.second)
                != STD_ERR_OK) {
            NAS_ACL_LOG_ERR("Failed to get ACL Range info for switch");
            return STD_ERR(ACL, FAIL, 0);
        }
    }

    return STD_ERR_OK;
}

static t_std_error nas_get_acl_range_info_all (cps_api_get_params_t *param,
                                               size_t index)
{
   for (const auto& switch_pair: nas_acl_get_switch_list ()) {
       if (nas_get_acl_range_info_by_switch (param, index, switch_pair.second)
               != STD_ERR_OK) {
           NAS_ACL_LOG_ERR("Failed to get all ACL Range info");
           return STD_ERR(ACL, FAIL, 0);
       }
   }

   return STD_ERR_OK;
}

t_std_error nas_acl_get_range(cps_api_get_params_t* param, size_t index,
                              cps_api_object_t filter_obj) noexcept
{
    t_std_error  rc = STD_ERR_OK;
    nas_switch_id_t        switch_id = 0;
    nas_obj_id_t           range_id = 0;

    bool switch_id_key = nas_acl_cps_key_get_switch_id (filter_obj,
                                                        NAS_ACL_SWITCH_ATTR,
                                                        &switch_id);
    bool range_id_key = nas_acl_cps_key_get_obj_id (filter_obj,
                                                    BASE_ACL_RANGE_ID,
                                                    &range_id);
    try {
        if (!switch_id_key) {
            /* No keys provided */
            rc = nas_get_acl_range_info_all (param, index);
        }
        else if (switch_id_key && !range_id_key) {
            /* Switch Id provided */
            nas_acl_switch& s = nas_acl_get_switch (switch_id);
            rc = nas_get_acl_range_info_by_switch (param, index, s);
        }
        else if (switch_id_key && range_id_key) {
            /* Switch Id and Range Id provided */
            NAS_ACL_LOG_DETAIL ("Switch Id: %d, Range Id: %ld\n",
                                switch_id, range_id);

            nas_acl_switch& s = nas_acl_get_switch (switch_id);
            nas_acl_range*  acl_range = s.find_acl_range (range_id);
            if (acl_range == nullptr) {
                NAS_ACL_LOG_ERR("Invalid ACL Range ID");
                return STD_ERR(ACL, FAIL, 0);
            }

            rc = nas_get_acl_range_info (param->list, *acl_range);
        }
        else {
            NAS_ACL_LOG_ERR("Unknown key combination");
            return STD_ERR(ACL, FAIL, 0);
        }
    } catch (nas::base_exception& e) {

        NAS_ACL_LOG_ERR ("Err_code: 0x%x, fn: %s (), %s", e.err_code,
                      e.err_fn.c_str (), e.err_msg.c_str ());

        rc = e.err_code;
    }

    return (rc);
}

static
t_std_error nas_acl_range_create(cps_api_object_t obj,
                                 cps_api_object_t prev,
                                 bool is_rollbk) noexcept
{
    nas_switch_id_t switch_id = 0;
    nas_obj_id_t range_id = 0;
    bool is_type_present = false;
    bool is_limit_min_present = false, is_limit_max_present = false;
    bool id_passed_in = false;
    cps_api_attr_id_t attr_id = 0;
    cps_api_object_it_t it {};

    if (obj == nullptr) {
        NAS_ACL_LOG_ERR("NULL pointer as input");
        return STD_ERR(ACL, PARAM, 0);
    }

    if (!nas_acl_cps_key_get_switch_id(obj, NAS_ACL_SWITCH_ATTR,
                                       &switch_id)) {
        NAS_ACL_LOG_ERR("Failed to get switch id");
        return STD_ERR(ACL, FAIL, 0);
    }

    if (nas_acl_cps_key_get_obj_id(obj, BASE_ACL_RANGE_ID, &range_id)) {
        id_passed_in = true;
        NAS_ACL_LOG_BRIEF("Range ID %lu provided for ACL Range create", range_id);
    }

    try {
        nas_acl_switch& s = nas_acl_get_switch(switch_id);
        if (id_passed_in) {
            nas_acl_range* acl_range_p = s.find_acl_range(range_id);
            if (acl_range_p != nullptr) {
                NAS_ACL_LOG_ERR("Range ID %lu already taken", range_id);
                return STD_ERR(ACL, FAIL, 0);
            }
        }

        nas_acl_range acl_range(&s);

        for (cps_api_object_it_begin(obj, &it); cps_api_object_it_valid(&it);
             cps_api_object_it_next(&it)) {
            attr_id = cps_api_object_attr_id(it.attr);
            switch(attr_id) {
            case BASE_ACL_RANGE_TYPE:
            {
                if (is_type_present) {
                    NAS_ACL_LOG_ERR("Duplicate range type attribute");
                    return STD_ERR(ACL, FAIL, 0);
                }
                is_type_present = true;
                uint_t type = cps_api_object_attr_data_u32(it.attr);
                acl_range.set_type(type);
                break;
            }
            case BASE_ACL_RANGE_LIMIT_MIN:
            {
                if (is_limit_min_present) {
                    NAS_ACL_LOG_ERR("Duplicate minimum limit attribute");
                    return STD_ERR(ACL, FAIL, 0);
                }
                is_limit_min_present = true;
                uint_t limit_min = cps_api_object_attr_data_u32(it.attr);
                acl_range.set_limit_min(limit_min);
                break;
            }
            case BASE_ACL_RANGE_LIMIT_MAX:
            {
                if (is_limit_max_present) {
                    NAS_ACL_LOG_ERR("Duplicate maximum limit attribute");
                    return STD_ERR(ACL, FAIL, 0);
                }
                is_limit_max_present = true;
                uint_t limit_max = cps_api_object_attr_data_u32(it.attr);
                acl_range.set_limit_max(limit_max);
                break;
            }

            default:
                NAS_ACL_LOG_DETAIL("Unknown attribute ignored %lu(%lx)",
                                   attr_id, attr_id);
                break;
            }
        }

        if (!is_type_present || !is_limit_min_present || !is_limit_max_present) {
            NAS_ACL_LOG_ERR("Mandatory attributes not exist");
            return STD_ERR(ACL, FAIL, 0);
        }

        if (id_passed_in) {
            s.reserve_acl_range_id(range_id);
        } else {
            range_id = s.alloc_acl_range_id();
        }
        acl_range.set_range_id(range_id);

        try {
            acl_range.commit_create(is_rollbk);
        } catch (nas::base_exception& e) {
            s.release_acl_range_id(range_id);
            throw e;
        }

        // WARNING !!! CANNOT throw error or exception beyond this point
        // since ACL range is already committed to SAI

        nas_acl_range& new_range = s.save_acl_range(std::move(acl_range));
        range_id = new_range.range_id();
        if (!nas_acl_cps_key_set_obj_id(obj, BASE_ACL_RANGE_ID, range_id)) {
            NAS_ACL_LOG_ERR("Failed to set Range ID as key");
        }
        if (!is_rollbk) {
            cps_api_object_set_key(prev, cps_api_object_key(obj));
            nas_acl_cps_key_set_obj_id(prev, BASE_ACL_RANGE_ID, range_id);
        }
    } catch (nas::base_exception& e) {
        NAS_ACL_LOG_ERR("Err_code: 0x%x, fn: %s (), %s", e.err_code,
                        e.err_fn.c_str(), e.err_msg.c_str());
        return e.err_code;
    } catch (std::out_of_range& e) {
        NAS_ACL_LOG_ERR("Out of range exception %s", e.what());
        return STD_ERR(ACL, FAIL, 0);
    }

    return STD_ERR_OK;
}

static
t_std_error nas_acl_range_delete(cps_api_object_t obj,
                                 cps_api_object_t prev,
                                 bool is_rollbk) noexcept
{
    nas_switch_id_t switch_id = 0;
    nas_obj_id_t range_id = 0;

    if (obj == nullptr) {
        NAS_ACL_LOG_ERR("NULL pointer as input");
        return STD_ERR(ACL, PARAM, 0);
    }

    if (!nas_acl_cps_key_get_switch_id(obj, NAS_ACL_SWITCH_ATTR,
                                       &switch_id)) {
        NAS_ACL_LOG_ERR("Switch ID is a mandatory key for ACL Range Delete");
        return STD_ERR(ACL, FAIL, 0);
    }
    if (!nas_acl_cps_key_get_obj_id (obj, BASE_ACL_RANGE_ID, &range_id)) {
        NAS_ACL_LOG_ERR("Range ID is a mandatory key for ACL Range Delete");
        return STD_ERR(ACL, FAIL, 0);
    }

    NAS_ACL_LOG_BRIEF("%sSwitch Id: %d Range Id %ld",
                      (is_rollbk) ? "** ROLLBACK **: " : "", switch_id, range_id);

    try {
        nas_acl_switch& s = nas_acl_get_switch (switch_id);
        nas_acl_range* acl_range_p = s.find_acl_range(range_id);
        if (acl_range_p == nullptr) {
            NAS_ACL_LOG_ERR("Invalid ACL Range ID %lu", range_id);
            return STD_ERR(ACL, FAIL, 0);
        }

        if (!is_rollbk) {
            cps_api_object_set_key(prev, cps_api_object_key(obj));
            nas_acl_cps_key_set_obj_id(prev, BASE_ACL_RANGE_ID, range_id);
            nas_fill_acl_range_attr(prev, *acl_range_p);
        }

        acl_range_p->commit_delete(is_rollbk);

        // WARNING !!! CANNOT throw error or exception beyond this point
        // since ACL range is already deleted from SAI

        s.remove_acl_range(range_id);
        s.release_acl_range_id(range_id);

    } catch (nas::base_exception& e) {

        NAS_ACL_LOG_ERR ("Err_code: 0x%x, fn: %s (), %s", e.err_code,
                         e.err_fn.c_str (), e.err_msg.c_str ());

        return e.err_code;
    } catch (std::out_of_range& e) {
        NAS_ACL_LOG_ERR ("###########  Out of Range exception %s", e.what ());
        return STD_ERR(ACL, FAIL, 0);
    }

    return STD_ERR_OK;
}

static nas_acl_write_operation_map_t nas_acl_range_op_map [] = {
    {cps_api_oper_CREATE, nas_acl_range_create},
    {cps_api_oper_DELETE, nas_acl_range_delete},
};

nas_acl_write_operation_map_t *
nas_acl_get_range_operation_map (cps_api_operation_types_t op) noexcept
{
    uint32_t                  index;
    uint32_t                  count;

    count = sizeof (nas_acl_range_op_map) / sizeof (nas_acl_range_op_map [0]);

    for (index = 0; index < count; index++) {

        if (nas_acl_range_op_map [index].op == op) {

            return (&nas_acl_range_op_map [index]);
        }
    }

    return NULL;
}
