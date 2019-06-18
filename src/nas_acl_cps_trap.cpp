/*
 * Copyright (c) 2018 Dell Inc.
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
 * \file   nas_acl_cps_trap.cpp
 * \brief  NAS ACL Trap CPS routines
 * \date   10-2018
 */

#include "event_log.h"
#include "std_error_codes.h"
#include "nas_acl_log.h"
#include "cps_api_object_key.h"
#include "cps_class_map.h"
#include "nas_acl_switch_list.h"
#include "nas_acl_cps_key.h"
#include "nas_acl_cps.h"

static bool nas_fill_acl_trap_attr(cps_api_object_t cps_obj,
                                   const nas_acl_trap& acl_trap,
                                   bool exp_npu_list = false)
{
    if (!cps_api_object_attr_add_u32(cps_obj, BASE_TRAP_TRAP_TYPE,
                                     acl_trap.type())) {
        NAS_ACL_LOG_ERR("Failed to add trap type attribute to object %lld", acl_trap.trap_id());
        return false;
    }

    if ((strlen(acl_trap.name()) > 0) && 
        !cps_api_object_attr_add(cps_obj, BASE_TRAP_TRAP_NAME, (void *)acl_trap.name(), strlen(acl_trap.name()))) {
        NAS_ACL_LOG_ERR("Failed to add TRAP name attribute to object %lld", acl_trap.trap_id());
        return false;
    }

    if ((acl_trap.group() != NAS_ACL_TRAP_GRP_ID_NONE) &&
        !cps_api_object_attr_add_u64(cps_obj, BASE_TRAP_TRAP_TRAP_GROUP_ID,
                                     acl_trap.group())) {
        NAS_ACL_LOG_ERR("Failed to add trap group attribute to object %lld", acl_trap.trap_id());
        return false;
    }

    return true;
}

static t_std_error nas_get_acl_trap_info(cps_api_object_list_t& cps_obj_list,
                                         const nas_acl_trap& acl_trap)
{
    cps_api_object_t cps_obj =
        cps_api_object_list_create_obj_and_append(cps_obj_list);

    if (cps_obj == nullptr) {
        NAS_ACL_LOG_ERR("Trap Obj invalid");
        return STD_ERR(ACL, FAIL, 0);
    }

    if (!cps_api_key_from_attr_with_qual(cps_api_object_key(cps_obj),
                                         BASE_TRAP_TRAP_OBJ,
                                         cps_api_qualifier_TARGET)) {
        NAS_ACL_LOG_ERR("Failed to get key from ACL trapid object");
        return STD_ERR(ACL, FAIL, 0);
    }

    if (!nas_acl_cps_key_set_obj_id(cps_obj, BASE_TRAP_TRAP_ID,
                                    acl_trap.trap_id())) {
        NAS_ACL_LOG_ERR("Failed to set ACL Trap ID in key");
        return STD_ERR(ACL, FAIL, 0);
    }

    if (!nas_fill_acl_trap_attr(cps_obj, acl_trap, true)) {
        NAS_ACL_LOG_ERR("Failed to fill ACL Trapid attrs");
        return STD_ERR(ACL, FAIL, 0);
    }

    return STD_ERR_OK;
}

static t_std_error nas_get_acl_trap_info_by_switch(cps_api_get_params_t* param,
                                                   size_t index,
                                                   const nas_acl_switch& s)
{
    for (const auto& trap_pair: s.trap_obj_list()) {
        if (nas_get_acl_trap_info(param->list, trap_pair.second)
                != STD_ERR_OK) {
            NAS_ACL_LOG_ERR("Failed to get ACL Trapid info for switch");
            return STD_ERR(ACL, FAIL, 0);
        }
    }

    return STD_ERR_OK;
}

static t_std_error nas_get_acl_trap_info_all (cps_api_get_params_t *param,
                                              size_t index)
{
   for (const auto& switch_pair: nas_acl_get_switch_list ()) {
       if (nas_get_acl_trap_info_by_switch (param, index, switch_pair.second)
               != STD_ERR_OK) {
           NAS_ACL_LOG_ERR("Failed to get all ACL Trapid info");
           return STD_ERR(ACL, FAIL, 0);
       }
   }

   return STD_ERR_OK;
}

t_std_error nas_trap_get_trap (cps_api_get_params_t* param, size_t index,
                               cps_api_object_t filter_obj) noexcept
{
    t_std_error     rc = STD_ERR_OK;
    nas_switch_id_t switch_id = 0;
    nas_obj_id_t    trap_id = 0;

    bool switch_id_key = nas_acl_cps_key_get_switch_id (filter_obj,
                                                        NAS_ACL_SWITCH_ATTR,
                                                        &switch_id);
    bool trap_key = nas_acl_cps_key_get_obj_id (filter_obj,
                                                BASE_TRAP_TRAP_ID,
                                                &trap_id);
    try {
        if (!switch_id_key) {
            /* No keys provided */
            rc = nas_get_acl_trap_info_all (param, index);
        }
        else if (switch_id_key && !trap_key) {
            /* Switch Id provided */
            NAS_ACL_LOG_DETAIL ("Switch Id: %d No trap id\n", switch_id);
            nas_acl_switch& s = nas_acl_get_switch (switch_id);
            rc = nas_get_acl_trap_info_by_switch (param, index, s);
        }
        else if (switch_id_key && trap_key) {
            /* Switch Id and Trap Id provided */
            NAS_ACL_LOG_DETAIL ("Switch Id: %d, Trap Id: %ld\n",
                                switch_id, trap_id);

            nas_acl_switch& s = nas_acl_get_switch (switch_id);
            nas_acl_trap *acl_trap_p = s.find_acl_trap(trap_id);
            if (acl_trap_p == nullptr) {
                NAS_ACL_LOG_ERR("Invalid ACL Trap ID %lld", trap_id);
                return STD_ERR(ACL, FAIL, 0);
            }

            rc = nas_get_acl_trap_info(param->list, (*acl_trap_p));
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

static t_std_error nas_trap_create(cps_api_object_t obj,
                                   cps_api_object_t prev,
                                   bool is_rollbk) noexcept
{
    nas_switch_id_t switch_id = 0;
    nas_obj_id_t trap_id = 0, cps_grp;
    
    bool is_type_present = false;
    bool is_grp_present = false;
    cps_api_attr_id_t attr_id = 0;
    cps_api_object_it_t it {};

    if (obj == nullptr) {
        NAS_ACL_LOG_ERR("NULL Trap obj as input");
        return STD_ERR(ACL, PARAM, 0);
    }

    if (!nas_acl_cps_key_get_switch_id(obj, NAS_ACL_SWITCH_ATTR,
                                       &switch_id)) {
        NAS_ACL_LOG_ERR("Failed to get switch id for Trap");
        return STD_ERR(ACL, FAIL, 0);
    }

    if (nas_acl_cps_key_get_obj_id(obj, BASE_TRAP_TRAP_ID, &trap_id)) {
        NAS_ACL_LOG_ERR("Trap id %lu provided for ACL Trapid create failed, Trapid not expected", trap_id);
        return STD_ERR(ACL, PARAM, 0);
    }

    try {
        nas_acl_switch& s = nas_acl_get_switch(switch_id);
        nas_acl_trap acl_trap(&s);

        for (cps_api_object_it_begin(obj, &it); cps_api_object_it_valid(&it);
             cps_api_object_it_next(&it)) {
            attr_id = cps_api_object_attr_id(it.attr);
            switch(attr_id) {
            case BASE_TRAP_TRAP_TYPE:
            {
                if (is_type_present) {
                    NAS_ACL_LOG_ERR("Duplicate trap type attribute");
                    return STD_ERR(ACL, FAIL, 0);
                }
                is_type_present = true;

                BASE_TRAP_TRAP_TYPE_t cps_type = (BASE_TRAP_TRAP_TYPE_t)cps_api_object_attr_data_u32(it.attr);
                acl_trap.set_type(cps_type);
                break;
            }

            case BASE_TRAP_TRAP_TRAP_GROUP_ID:
            {
                cps_grp = (nas_obj_id_t) cps_api_object_attr_data_u64(it.attr);
                nas_acl_trapgrp* acl_trapgrp_p = s.find_acl_trapgrp(cps_grp);
                if (acl_trapgrp_p == nullptr) {
                    if (cps_grp != NAS_ACL_TRAP_GRP_ID_NONE) {
                        NAS_ACL_LOG_ERR("Create cannot find ACL Trap grp ID %lld for trap", cps_grp);
                        return STD_ERR(ACL, FAIL, 0);
                    }
                }
                is_grp_present = true;

                acl_trap.set_group(cps_grp);
                break;
            }

            case BASE_TRAP_TRAP_NAME:
            {
                cps_api_object_attr_t cps_name_attr = cps_api_object_attr_get(obj, BASE_TRAP_TRAP_NAME);
                if (cps_name_attr) {
                    const char *cps_name = (const char *)cps_api_object_attr_data_bin(cps_name_attr);
                    if (strlen(cps_name) > 0) {
                        acl_trap.set_name(cps_name);
                    }
                }
                break;
            }

            default:
                NAS_ACL_LOG_DETAIL("Unknown attribute ignored for ACL trap %lu(%lx)",
                                   attr_id, attr_id);
                break;
            }
        }

        if (!is_type_present) {
            NAS_ACL_LOG_ERR("Mandatory attribute type not exist for trap");
            return STD_ERR(ACL, FAIL, 0);
        }

        if (!is_grp_present) {
            acl_trap.set_group(acl_trap.group()); // use initialized default
        }

        try {
            acl_trap.commit_create(is_rollbk);
        } catch (nas::base_exception& e) {
            NAS_ACL_LOG_ERR("Push Create Trap failed");
            throw e;
        }


        nas_acl_trap& new_trapid = s.save_acl_trap(std::move(acl_trap));
        trap_id = new_trapid.trap_id();
        if (!nas_acl_cps_key_set_obj_id(obj, BASE_TRAP_TRAP_ID, trap_id)) {
            NAS_ACL_LOG_ERR("Failed to set Trap id as key");
        }

        if (!is_rollbk) {
            cps_api_object_set_key(prev, cps_api_object_key(obj));
            nas_acl_cps_key_set_obj_id(prev, BASE_TRAP_TRAP_ID, trap_id);
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

static t_std_error nas_trap_set (cps_api_object_t obj,
                                 cps_api_object_t prev,
                                 bool             rollback) noexcept
{
    nas_switch_id_t        switch_id;
    nas_obj_id_t           trap_id, cps_grp;
    cps_api_attr_id_t      attr_id = 0;
    cps_api_object_it_t    it {};

    if (!nas_acl_cps_key_get_switch_id (obj, NAS_ACL_SWITCH_ATTR,
                                        &switch_id)) {
        NAS_ACL_LOG_ERR ("Switch ID is a mandatory key for Trap set");
        return NAS_ACL_E_MISSING_KEY;
    }

    if (!nas_acl_cps_key_get_obj_id (obj, BASE_TRAP_TRAP_ID, &trap_id)) {
        NAS_ACL_LOG_ERR("Trap id is a mandatory key for ACL Trap Set");
        return STD_ERR(ACL, FAIL, 0);
    }

    try {
        nas_acl_switch& s = nas_acl_get_switch(switch_id);
        bool npu_update_needed = false;

        nas_acl_trap* acl_trap_p = s.find_acl_trap(trap_id);
        if (acl_trap_p == nullptr) {
            NAS_ACL_LOG_ERR("Invalid ACL Trap id %lu", trap_id);
            return STD_ERR(ACL, FAIL, 0);
        }

        nas_acl_trap local_trap(*acl_trap_p); 

        for (cps_api_object_it_begin(obj, &it); cps_api_object_it_valid(&it);
             cps_api_object_it_next(&it)) {
            attr_id = cps_api_object_attr_id(it.attr);
            switch(attr_id) {
            case BASE_TRAP_TRAP_TRAP_GROUP_ID:
            {
                cps_grp = (nas_obj_id_t) cps_api_object_attr_data_u64(it.attr);
                nas_acl_trapgrp* acl_trapgrp_p = s.find_acl_trapgrp(cps_grp);
                if (acl_trapgrp_p == nullptr) {
                    if (cps_grp != NAS_ACL_TRAP_GRP_ID_NONE) {
                        NAS_ACL_LOG_ERR("Set cannot find ACL Trap grp ID %lld for trap %lld", cps_grp, trap_id);
                        return STD_ERR(ACL, FAIL, 0);
                    }
                }

                if (cps_grp == acl_trap_p->group()) {
                    NAS_ACL_LOG_DETAIL("Set ACL Trap grp ID %lld same as before for trap %lld", cps_grp, trap_id);
                    break;
                }
                local_trap.set_group(cps_grp);
                npu_update_needed = true;

                break;
            }

            case BASE_TRAP_TRAP_TYPE:
            {
                NAS_ACL_LOG_DETAIL("Trap attribute type mod not allowed for ACL trap %lu(%lx)",
                                   attr_id, attr_id);

                break;
            }

            case BASE_TRAP_TRAP_NAME:
            {
                cps_api_object_attr_t cps_name_attr = cps_api_object_attr_get(obj, BASE_TRAP_TRAP_NAME);
                if (cps_name_attr) {
                    const char *cps_name = (const char *)cps_api_object_attr_data_bin(cps_name_attr);
                    if (strlen(cps_name) > 0) {
                         acl_trap_p->set_name(cps_name);
                         npu_update_needed = false;
                    }
                }
                break;
            }

            case BASE_TRAP_TRAP_ID:
                break;

            default:
                NAS_ACL_LOG_DETAIL("Unknown attribute ignored for ACL trap %lu(%lx)",
                                   attr_id, attr_id);
                break;
            }
        }

        if (npu_update_needed) {
            try {
                local_trap.commit_modify(*acl_trap_p, rollback);
            } catch (nas::base_exception& e) {
                NAS_ACL_LOG_ERR("Push Set Trap GRP failed on %lld", trap_id);
                return e.err_code;
            }

            *acl_trap_p = local_trap;
            NAS_ACL_LOG_DETAIL("Trap attribute grp %lld for ACL trap %lld Success", local_trap.group(), trap_id);
        }

    } catch (nas::base_exception& e) {
        NAS_ACL_LOG_ERR("Err_code: 0x%x, fn: %s (), %s", e.err_code,
                        e.err_fn.c_str(), e.err_msg.c_str());
        return e.err_code;
    } catch (std::out_of_range& e) {
        NAS_ACL_LOG_ERR("Out of range exception %s", e.what());
        return STD_ERR(ACL, FAIL, 0);
    }

    return NAS_ACL_E_NONE;
}

static t_std_error nas_trap_delete(cps_api_object_t obj,
                                   cps_api_object_t prev,
                                   bool is_rollbk) noexcept
{
    nas_switch_id_t switch_id = 0;
    nas_obj_id_t trap_id = 0;
    
    if (obj == nullptr) {
        NAS_ACL_LOG_ERR("NULL Trap as delete input");
        return STD_ERR(ACL, PARAM, 0);
    }

    if (!nas_acl_cps_key_get_switch_id(obj, NAS_ACL_SWITCH_ATTR,
                                       &switch_id)) {
        NAS_ACL_LOG_ERR("Switch ID is a mandatory key for ACL Trapid Delete");
        return STD_ERR(ACL, FAIL, 0);
    }

    if (!nas_acl_cps_key_get_obj_id (obj, BASE_TRAP_TRAP_ID, &trap_id)) {
        NAS_ACL_LOG_ERR("Trap id is a mandatory key for ACL Trapid Delete");
        return STD_ERR(ACL, FAIL, 0);
    }

    NAS_ACL_LOG_BRIEF("%sSwitch Id: %d Trap id %lld",
                      (is_rollbk) ? "** ROLLBACK **: " : "", switch_id, trap_id);

    try {
        nas_acl_switch& s = nas_acl_get_switch (switch_id);
        nas_acl_trap* acl_trap_p = s.find_acl_trap(trap_id);
        if (acl_trap_p == nullptr) {
            NAS_ACL_LOG_ERR("Invalid ACL Trap id %lu", trap_id);
            return STD_ERR(ACL, FAIL, 0);
        }


        try {
            acl_trap_p->commit_delete(is_rollbk);
        } catch (nas::base_exception& e) {
            NAS_ACL_LOG_ERR("Push Delete Trap id %lu failed", trap_id);
            throw e;
        }


        s.remove_acl_trap(trap_id);

    } catch (nas::base_exception& e) {
        NAS_ACL_LOG_ERR ("Err_code: 0x%x, fn: %s (), %s", e.err_code,
                         e.err_fn.c_str (), e.err_msg.c_str ());
        return e.err_code;
    } catch (std::out_of_range& e) {
        NAS_ACL_LOG_ERR ("Out of Range exception %s", e.what ());
        return STD_ERR(ACL, FAIL, 0);
    }

    return STD_ERR_OK;
}

static nas_acl_write_operation_map_t nas_acl_trap_write_op_map [] = {
    {cps_api_oper_CREATE, nas_trap_create},
    {cps_api_oper_SET, nas_trap_set},
    {cps_api_oper_DELETE, nas_trap_delete},
};

nas_acl_write_operation_map_t *
nas_acl_reg_trap_operation_map (cps_api_operation_types_t op) noexcept
{
    size_t index, count;

    count = sizeof(nas_acl_trap_write_op_map) / sizeof(nas_acl_trap_write_op_map[0]);

    for (index = 0; index < count; index++) {
        if (nas_acl_trap_write_op_map[index].op == op) {
            return (&nas_acl_trap_write_op_map[index]);
        }
    }

    return NULL;
}
