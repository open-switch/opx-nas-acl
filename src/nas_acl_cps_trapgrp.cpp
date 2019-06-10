/*
 * Copyright (c) 2019 Dell EMC, All rights reserved.
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
 * \file   nas_acl_cps_trapgrp.cpp
 * \brief  NAS ACL Trap Group CPS routines
 * \date   1-2019
 */

#include "event_log.h"
#include "std_error_codes.h"
#include "nas_acl_log.h"
#include "cps_api_object_key.h"
#include "cps_class_map.h"
#include "nas_acl_switch_list.h"
#include "nas_acl_cps_key.h"
#include "nas_acl_cps.h"

static bool nas_fill_acl_trapgrp_attr(cps_api_object_t cps_obj,
                                      const nas_acl_trapgrp& acl_trapgrp,
                                      bool exp_npu_list = false)
{
    uint8_t data = acl_trapgrp.admin_state();
    if (!cps_api_object_attr_add_u64(cps_obj, BASE_TRAP_TRAP_GROUP_QUEUE_ID,
                                     acl_trapgrp.queue())) {
        NAS_ACL_LOG_ERR("Failed to add trapgrp queue attribute to object %lld", acl_trapgrp.trapgrp_id());
        return false;
    }

    if ((acl_trapgrp.admin_state() != NAS_ACL_TRAPGRP_ADMIN_DEF) &&
	!cps_api_object_attr_add(cps_obj, BASE_TRAP_TRAP_GROUP_ADMIN,
                                 (void *)&data, sizeof(uint32_t))) {
        NAS_ACL_LOG_ERR("Failed to add trapgrp admin state attribute to object %lld", acl_trapgrp.trapgrp_id());
        return false;
    }

    if ((strlen(acl_trapgrp.name()) > 0) && !cps_api_object_attr_add(cps_obj, BASE_TRAP_TRAP_GROUP_NAME,
                                                (void *)acl_trapgrp.name(), strlen(acl_trapgrp.name()))) {
        NAS_ACL_LOG_ERR("Failed to add TRAPGRP name attribute to object %lld", acl_trapgrp.trapgrp_id());
        return false;
    }

    return true;
}

static t_std_error nas_get_acl_trapgrp_info(cps_api_object_list_t& cps_obj_list,
                                            const nas_acl_trapgrp& acl_trapgrp)
{
    cps_api_object_t cps_obj =
        cps_api_object_list_create_obj_and_append(cps_obj_list);

    if (cps_obj == nullptr) {
        NAS_ACL_LOG_ERR("Trapgrp Obj invalid");
        return STD_ERR(ACL, FAIL, 0);
    }

    if (!cps_api_key_from_attr_with_qual(cps_api_object_key(cps_obj),
                                         BASE_TRAP_TRAP_GROUP_OBJ,
                                         cps_api_qualifier_TARGET)) {
        NAS_ACL_LOG_ERR("Failed to create key from ACL trapgrp object");
        return STD_ERR(ACL, FAIL, 0);
    }

    if (!nas_acl_cps_key_set_obj_id(cps_obj, BASE_TRAP_TRAP_GROUP_ID,
                                    acl_trapgrp.trapgrp_id())) {
        NAS_ACL_LOG_ERR("Failed to set ACL Trapgrp ID in key");
        return STD_ERR(ACL, FAIL, 0);
    }

    if (!nas_fill_acl_trapgrp_attr(cps_obj, acl_trapgrp, true)) {
        NAS_ACL_LOG_ERR("Failed to fill ACL Trapgrp attrs");
        return STD_ERR(ACL, FAIL, 0);
    }

    return STD_ERR_OK;
}

static t_std_error nas_get_acl_trapgrp_info_by_switch(cps_api_get_params_t* param,
                                                      size_t index,
                                                      const nas_acl_switch& s)
{
    for (const auto& trapgrp_pair: s.trapgrp_obj_list()) {
        if (nas_get_acl_trapgrp_info(param->list, trapgrp_pair.second)
                != STD_ERR_OK) {
            NAS_ACL_LOG_ERR("Failed to get ACL Trapgrp info for switch");
            return STD_ERR(ACL, FAIL, 0);
        }
    }

    return STD_ERR_OK;
}

static t_std_error nas_get_acl_trapgrp_info_all (cps_api_get_params_t *param,
                                                 size_t index)
{
   for (const auto& switch_pair: nas_acl_get_switch_list ()) {
       if (nas_get_acl_trapgrp_info_by_switch (param, index, switch_pair.second)
               != STD_ERR_OK) {
           NAS_ACL_LOG_ERR("Failed to get all ACL Trapgrp info");
           return STD_ERR(ACL, FAIL, 0);
       }
   }

   return STD_ERR_OK;
}

t_std_error nas_trap_get_trapgrp (cps_api_get_params_t* param, size_t index,
                                  cps_api_object_t filter_obj) noexcept
{
    t_std_error     rc = STD_ERR_OK;
    nas_switch_id_t switch_id = 0;
    nas_obj_id_t    trapgrp_id = 0;

    bool switch_id_key = nas_acl_cps_key_get_switch_id (filter_obj,
                                                        NAS_ACL_SWITCH_ATTR,
                                                        &switch_id);
    bool trapgrp_key = nas_acl_cps_key_get_obj_id (filter_obj,
                                                   BASE_TRAP_TRAP_GROUP_ID,
                                                   &trapgrp_id);
    try {
        if (!switch_id_key) {
            /* No keys provided */
            rc = nas_get_acl_trapgrp_info_all (param, index);
        }
        else if (switch_id_key && !trapgrp_key) {
            /* Switch Id provided */
            NAS_ACL_LOG_DETAIL ("Switch Id: %d No trapgrp id\n", switch_id);
            nas_acl_switch& s = nas_acl_get_switch (switch_id);
            rc = nas_get_acl_trapgrp_info_by_switch (param, index, s);
        }
        else if (switch_id_key && trapgrp_key) {
            /* Switch Id and Trapgrp Id provided */
            NAS_ACL_LOG_DETAIL ("Switch Id: %d, Trapgrp Id: %ld\n",
                                switch_id, trapgrp_id);

            nas_acl_switch& s = nas_acl_get_switch (switch_id);
            nas_acl_trapgrp *acl_trapgrp_p = s.find_acl_trapgrp(trapgrp_id);
            if (acl_trapgrp_p == nullptr) {
                NAS_ACL_LOG_ERR("Get Cannot find ACL Trap grp ID %lld", trapgrp_id);
                return STD_ERR(ACL, FAIL, 0);
            }

            rc = nas_get_acl_trapgrp_info(param->list, (*acl_trapgrp_p));
        }
        else {
            NAS_ACL_LOG_ERR("Unknown key combination");
            return STD_ERR(ACL, FAIL, 0);
        }
    } catch (nas::base_exception& e) {
        NAS_ACL_LOG_ERR ("Get Err_code: 0x%x, fn: %s (), %s", e.err_code,
                      e.err_fn.c_str (), e.err_msg.c_str ());

        rc = e.err_code;
    }

    return (rc);
}

static t_std_error nas_trapgrp_create(cps_api_object_t obj,
                                       cps_api_object_t prev,
                                       bool is_rollbk) noexcept
{
    nas_switch_id_t switch_id = 0;
    nas_obj_id_t trapgrp_id = 0, cps_queue = 0;
    bool cps_admin_s = true;
    
    cps_api_attr_id_t attr_id = 0;
    cps_api_object_it_t it {};

    bool is_queue_present = false;
    bool is_admin_present = false;

    if (obj == nullptr) {
        NAS_ACL_LOG_ERR("NULL Trapgrp obj as input");
        return STD_ERR(ACL, PARAM, 0);
    }

    if (!nas_acl_cps_key_get_switch_id(obj, NAS_ACL_SWITCH_ATTR,
                                       &switch_id)) {
        NAS_ACL_LOG_ERR("Failed to get switch id for Trapgrp");
        return STD_ERR(ACL, FAIL, 0);
    }

    if (nas_acl_cps_key_get_obj_id(obj, BASE_TRAP_TRAP_GROUP_ID, &trapgrp_id)) {
        NAS_ACL_LOG_ERR("Trap grp %lu provided for ACL Trap Group create failed, ID not expected", trapgrp_id);
        return STD_ERR(ACL, PARAM, 0);
    }

    try {
        nas_acl_switch& s = nas_acl_get_switch(switch_id);
        nas_acl_trapgrp acl_trapgrp(&s);

        for (cps_api_object_it_begin(obj, &it); cps_api_object_it_valid(&it);
             cps_api_object_it_next(&it)) {
            attr_id = cps_api_object_attr_id(it.attr);
            switch(attr_id) {
            case BASE_TRAP_TRAP_GROUP_QUEUE_ID:
            {
                if (is_queue_present) {
                    NAS_ACL_LOG_ERR("Duplicate trapgrp queue attribute");
                    return STD_ERR(ACL, FAIL, 0);
                }
                is_queue_present = true;

                cps_queue = (nas_obj_id_t) cps_api_object_attr_data_u64(it.attr);
                acl_trapgrp.set_queue(cps_queue);
                break;
            }

            case BASE_TRAP_TRAP_GROUP_ADMIN:
            {
                uint8_t data;
                if (is_admin_present) {
                    NAS_ACL_LOG_ERR("Duplicate trapgrp admin attribute");
                    return STD_ERR(ACL, FAIL, 0);
                }
                is_admin_present = true;

                data = cps_api_object_attr_data_uint(it.attr);
                cps_admin_s = (bool) data;
                acl_trapgrp.set_admin_state(cps_admin_s);
                break;
            }

            case BASE_TRAP_TRAP_GROUP_NAME:
            {
                cps_api_object_attr_t cps_name_attr = cps_api_object_attr_get(obj, BASE_TRAP_TRAP_GROUP_NAME);
                if (cps_name_attr) {
                    const char *cps_name = (const char *)cps_api_object_attr_data_bin(cps_name_attr);
                    if (strlen(cps_name) > 0) {
                        acl_trapgrp.set_name(cps_name);
                    }
                }
                break;
            }

            default:
                NAS_ACL_LOG_DETAIL("Unknown attribute ignored for ACL trapgrp %lu(%lx)",
                                   attr_id, attr_id);
                break;
            }
        }

        if (!is_queue_present) {
            NAS_ACL_LOG_ERR("Mandatory attribute queue-id not exist for trap group");
            return STD_ERR(ACL, FAIL, 0);
        }

        if (!is_admin_present) {
            acl_trapgrp.set_admin_state(cps_admin_s);
        }


        try {
            acl_trapgrp.commit_create(is_rollbk);
        } catch (nas::base_exception& e) {
            NAS_ACL_LOG_ERR("Push Create Trapgrp failed");
            throw e;
        }


        nas_acl_trapgrp& new_trapgrpid = s.save_acl_trapgrp(std::move(acl_trapgrp));
        trapgrp_id = new_trapgrpid.trapgrp_id();
        if (!nas_acl_cps_key_set_obj_id(obj, BASE_TRAP_TRAP_GROUP_ID, trapgrp_id)) {
            NAS_ACL_LOG_ERR("Failed to set Trapgrp id as key");
        }

        if (!is_rollbk) {
            cps_api_object_set_key(prev, cps_api_object_key(obj));
            nas_acl_cps_key_set_obj_id(prev, BASE_TRAP_TRAP_GROUP_ID, trapgrp_id);
        }
    } catch (nas::base_exception& e) {
        NAS_ACL_LOG_ERR("Create Err_code: 0x%x, fn: %s (), %s", e.err_code,
                        e.err_fn.c_str(), e.err_msg.c_str());
        return e.err_code;
    } catch (std::out_of_range& e) {
        NAS_ACL_LOG_ERR("Out of range exception %s", e.what());
        return STD_ERR(ACL, FAIL, 0);
    }

    return STD_ERR_OK;
}

static t_std_error nas_trapgrp_set (cps_api_object_t obj,
                                    cps_api_object_t prev,
                                    bool             rollback) noexcept
{
    nas_switch_id_t        switch_id;
    nas_obj_id_t trapgrp_id = 0, cps_queue = 0;
    bool                   cps_admin_s = false;
    cps_api_attr_id_t      attr_id = 0;
    cps_api_object_it_t it {};

    if (!nas_acl_cps_key_get_switch_id (obj, NAS_ACL_SWITCH_ATTR,
                                        &switch_id)) {
        NAS_ACL_LOG_ERR ("Switch ID is a mandatory key for trapgrp set");
        return NAS_ACL_E_MISSING_KEY;
    }

    if (!nas_acl_cps_key_get_obj_id (obj, BASE_TRAP_TRAP_GROUP_ID, &trapgrp_id)) {
        NAS_ACL_LOG_ERR("Trapgrp id is a mandatory key for ACL Trapgrp Set");
        return STD_ERR(ACL, FAIL, 0);
    }

    try {
        nas_acl_switch& s = nas_acl_get_switch(switch_id);
        bool npu_update_needed = false;
        
        nas_acl_trapgrp* acl_trapgrp_p = s.find_acl_trapgrp(trapgrp_id);
        if (acl_trapgrp_p == nullptr) {
            NAS_ACL_LOG_ERR("Set cannot find ACL Trap grp ID %lld", trapgrp_id);
            return STD_ERR(ACL, FAIL, 0);
        }

        nas_acl_trapgrp local_trapgrp(*acl_trapgrp_p); 

        for (cps_api_object_it_begin(obj, &it); cps_api_object_it_valid(&it);
             cps_api_object_it_next(&it)) {
            attr_id = cps_api_object_attr_id(it.attr);
            switch(attr_id) {
            case BASE_TRAP_TRAP_GROUP_QUEUE_ID:
            {
                cps_queue = (nas_obj_id_t) cps_api_object_attr_data_u64(it.attr);
                if (cps_queue == acl_trapgrp_p->queue()) {
                    break;
                }

                local_trapgrp.set_queue(cps_queue);
                npu_update_needed = true;
                break;
            }

            case BASE_TRAP_TRAP_GROUP_ADMIN:
            {
                uint8_t data;
                data = cps_api_object_attr_data_uint(it.attr);
                cps_admin_s = (bool) data;
                if (cps_admin_s == acl_trapgrp_p->admin_state()) {
                    break;
                }
                local_trapgrp.set_admin_state(cps_admin_s);
                npu_update_needed = true;

                break;
            }

            case BASE_TRAP_TRAP_GROUP_NAME:
            {
                cps_api_object_attr_t cps_name_attr = cps_api_object_attr_get(obj, BASE_TRAP_TRAP_GROUP_NAME);
                if (cps_name_attr) {
                    const char *cps_name = (const char *)cps_api_object_attr_data_bin(cps_name_attr);
                    if (strlen(cps_name) > 0) {
                        acl_trapgrp_p->set_name(cps_name);
                        npu_update_needed = false;
                    }
                }
                break;
            }

            default:
                NAS_ACL_LOG_DETAIL("Set Unknown attribute ignored for ACL trapgrp %lu(%lx)",
                                   attr_id, attr_id);
                break;
            }
        }

        if (npu_update_needed) {
            try {
                local_trapgrp.commit_modify(*acl_trapgrp_p, rollback);
            } catch (nas::base_exception& e) {
                NAS_ACL_LOG_ERR("Push Set Trapgrp failed trapgrp %lld", trapgrp_id);
                return e.err_code;
            }       

            *acl_trapgrp_p = local_trapgrp;
        }
    } catch (nas::base_exception& e) {
        NAS_ACL_LOG_ERR("Set Err_code: 0x%x, fn: %s (), %s", e.err_code,
                        e.err_fn.c_str(), e.err_msg.c_str());
        return e.err_code;
    } catch (std::out_of_range& e) {
        NAS_ACL_LOG_ERR("Out of range exception %s", e.what());
        return STD_ERR(ACL, FAIL, 0);
    }

    return NAS_ACL_E_NONE;
}

static t_std_error nas_trapgrp_delete(cps_api_object_t obj,
                                       cps_api_object_t prev,
                                       bool is_rollbk) noexcept
{
    nas_switch_id_t switch_id = 0;
    nas_obj_id_t trapgrp_id = 0;
    
    if (obj == nullptr) {
        NAS_ACL_LOG_ERR("NULL Trapgrp as delete input");
        return STD_ERR(ACL, PARAM, 0);
    }

    if (!nas_acl_cps_key_get_switch_id(obj, NAS_ACL_SWITCH_ATTR,
                                       &switch_id)) {
        NAS_ACL_LOG_ERR("Switch ID is a mandatory key for ACL Trapgrp Delete");
        return STD_ERR(ACL, FAIL, 0);
    }

    if (!nas_acl_cps_key_get_obj_id (obj, BASE_TRAP_TRAP_GROUP_ID, &trapgrp_id)) {
        NAS_ACL_LOG_ERR("Trapgrp id is a mandatory key for ACL Trapgrp Delete");
        return STD_ERR(ACL, FAIL, 0);
    }

    NAS_ACL_LOG_BRIEF("%sSwitch Id: %d Trapgrp id %lld",
                      (is_rollbk) ? "** ROLLBACK **: " : "", switch_id, trapgrp_id);

    try {
        nas_acl_switch& s = nas_acl_get_switch (switch_id);
        nas_acl_trapgrp* acl_trapgrp_p = s.find_acl_trapgrp(trapgrp_id);
        if (acl_trapgrp_p == nullptr) {
            NAS_ACL_LOG_ERR("Cannot find delete ACL Trapgrp ID %lld", trapgrp_id);
            return STD_ERR(ACL, FAIL, 0);
        }

        nas_acl_trapgrp local_trapgrp(*acl_trapgrp_p); 

        try {
            local_trapgrp.commit_delete(is_rollbk);
        } catch (nas::base_exception& e) {
            NAS_ACL_LOG_ERR("Push Delete Trapgrp %lu failed", trapgrp_id);
            throw e;
        }

        *acl_trapgrp_p = local_trapgrp;

        s.remove_acl_trapgrp(trapgrp_id);

    } catch (nas::base_exception& e) {
        NAS_ACL_LOG_ERR ("Delete Err_code: 0x%x, fn: %s (), %s", e.err_code,
                         e.err_fn.c_str (), e.err_msg.c_str ());
        return e.err_code;
    } catch (std::out_of_range& e) {
        NAS_ACL_LOG_ERR ("Out of Range exception %s", e.what ());
        return STD_ERR(ACL, FAIL, 0);
    }

    return STD_ERR_OK;
}

static nas_acl_write_operation_map_t nas_acl_trapgrp_write_op_map [] = {
    {cps_api_oper_CREATE, nas_trapgrp_create},
    {cps_api_oper_SET, nas_trapgrp_set},
    {cps_api_oper_DELETE, nas_trapgrp_delete},
};

nas_acl_write_operation_map_t *
nas_acl_reg_trapgrp_operation_map (cps_api_operation_types_t op) noexcept
{
    size_t index, count;

    count = sizeof(nas_acl_trapgrp_write_op_map) / sizeof(nas_acl_trapgrp_write_op_map[0]);

    for (index = 0; index < count; index++) {
        if (nas_acl_trapgrp_write_op_map[index].op == op) {
            return (&nas_acl_trapgrp_write_op_map[index]);
        }
    }

    return NULL;
}
