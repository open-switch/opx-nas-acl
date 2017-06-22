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
 * \file   nas_udf_cps_match.cpp
 * \brief  This file contains CPS related UDF Match functionality
 * \date   10-2016
 */

#include "event_log.h"
#include "std_error_codes.h"
#include "nas_acl_log.h"
#include "cps_api_object_key.h"
#include "cps_class_map.h"
#include "nas_acl_switch_list.h"
#include "nas_acl_cps_key.h"

static bool nas_fill_udf_match_attr(cps_api_object_t cps_obj,
                                    const nas_udf_match& udf_match,
                                    bool exp_npu_list = false)
{
    uint8_t priority = (uint8_t)udf_match.priority();
    if (!cps_api_object_attr_add(cps_obj, BASE_UDF_UDF_MATCH_PRIORITY,
                                 &priority, 1)) {
        NAS_ACL_LOG_ERR("Failed to add attribute to object");
        return false;
    }

    auto match_type = udf_match.type();
    if (!cps_api_object_attr_add_u32(cps_obj, BASE_UDF_UDF_MATCH_TYPE,
                                     match_type)) {
        NAS_ACL_LOG_ERR("Failed to add attribute to object");
        return false;
    }

    if (match_type == BASE_UDF_UDF_MATCH_TYPE_NON_TUNNEL) {
        uint16_t eth_type = 0, eth_mask = 0;
        uint8_t ip_type = 0, ip_mask = 0;
        udf_match.ethertype(eth_type, eth_mask);
        udf_match.ip_protocol(ip_type, ip_mask);
        if (eth_type != 0 || eth_mask != 0) {
            if (!cps_api_object_attr_add_u16(cps_obj,
                                             BASE_UDF_UDF_MATCH_NON_TUNNEL_VALUE_L2_TYPE,
                                             eth_type)) {
                NAS_ACL_LOG_ERR("Failed to add attribute to object");
                return false;
            }
            if (!cps_api_object_attr_add_u16(cps_obj,
                                             BASE_UDF_UDF_MATCH_NON_TUNNEL_VALUE_L2_TYPE_MASK,
                                             eth_mask)) {
                NAS_ACL_LOG_ERR("Failed to add attribute to object");
                return false;
            }
        }
        if (ip_type != 0 || ip_mask != 0) {
            if (!cps_api_object_attr_add(cps_obj,
                                         BASE_UDF_UDF_MATCH_NON_TUNNEL_VALUE_L3_TYPE,
                                         &ip_type, 1)) {
                NAS_ACL_LOG_ERR("Failed to add attribute to object");
                return false;
            }
            if (!cps_api_object_attr_add(cps_obj,
                                         BASE_UDF_UDF_MATCH_NON_TUNNEL_VALUE_L3_TYPE_MASK,
                                         &ip_mask, 1)) {
                NAS_ACL_LOG_ERR("Failed to add attribute to object");
                return false;
            }
        }
    } else if (match_type == BASE_UDF_UDF_MATCH_TYPE_GRE_TUNNEL) {
        INET_IP_VERSION_t inner = INET_IP_VERSION_UNKNOWN, outer = INET_IP_VERSION_UNKNOWN;
        udf_match.gre_tunnel(inner, outer);
        if (inner != INET_IP_VERSION_UNKNOWN) {
            if (!cps_api_object_attr_add_u32(cps_obj,
                                             BASE_UDF_UDF_MATCH_GRE_TUNNEL_VALUE_INNER_TYPE,
                                             inner)) {
                NAS_ACL_LOG_ERR("Failed to add attribute to object");
                return false;
            }
        }
        if (outer != INET_IP_VERSION_UNKNOWN) {
            if (!cps_api_object_attr_add_u32(cps_obj,
                                             BASE_UDF_UDF_MATCH_GRE_TUNNEL_VALUE_OUTER_TYPE,
                                             outer)) {
                NAS_ACL_LOG_ERR("Failed to add attribute to object");
                return false;
            }
        }
    } else {
        NAS_ACL_LOG_ERR("Invalid match type: %d", match_type);
        return false;
    }

    if (udf_match.following_switch_npus() && !exp_npu_list) {
        return true;
    }

    for (auto npu_id: udf_match.npu_list()) {
        if (!cps_api_object_attr_add_u32(cps_obj, BASE_UDF_UDF_MATCH_NPU_ID_LIST,
                                         npu_id)) {
            NAS_ACL_LOG_ERR("Failed to add attribute to object");
            return false;
        }
    }

    return true;
}

static t_std_error nas_get_udf_match_info(cps_api_object_list_t& cps_obj_list,
                                          const nas_udf_match& udf_match)
{
    cps_api_object_t cps_obj =
        cps_api_object_list_create_obj_and_append(cps_obj_list);
    if (cps_obj == nullptr) {
        NAS_ACL_LOG_ERR("Obj append failed");
        return STD_ERR(UDF, FAIL, 0);
    }

    if (!cps_api_key_from_attr_with_qual(cps_api_object_key(cps_obj),
                                         BASE_UDF_UDF_MATCH_OBJ,
                                         cps_api_qualifier_TARGET)) {
        NAS_ACL_LOG_ERR("Failed to create key from UDF Match object");
        return STD_ERR(UDF, FAIL, 0);
    }

    if (!nas_acl_cps_key_set_obj_id(cps_obj, BASE_UDF_UDF_MATCH_ID,
                                    udf_match.match_id())) {
        NAS_ACL_LOG_ERR("Failed to set UDF Match ID in key");
        return STD_ERR(UDF, FAIL, 0);
    }

    if (!nas_fill_udf_match_attr(cps_obj, udf_match, true)) {
        NAS_ACL_LOG_ERR("Failed to fill UDF Match attrs");
        return STD_ERR(UDF, FAIL, 0);
    }

    return STD_ERR_OK;
}

static t_std_error nas_get_udf_match_info_by_switch(cps_api_get_params_t* param,
                                                    size_t index,
                                                    const nas_acl_switch& s)
{
    for (const auto& match_pair: s.udf_match_list()) {
        if (nas_get_udf_match_info(param->list, match_pair.second)
                != STD_ERR_OK) {
            NAS_ACL_LOG_ERR("Failed to get UDF Match info for switch");
            return STD_ERR(UDF, FAIL, 0);
        }
    }

    return STD_ERR_OK;
}

static t_std_error nas_get_udf_match_info_all (cps_api_get_params_t *param,
                                               size_t index)
{
   for (const auto& switch_pair: nas_acl_get_switch_list ()) {
       if (nas_get_udf_match_info_by_switch (param, index, switch_pair.second)
               != STD_ERR_OK) {
           NAS_ACL_LOG_ERR("Failed to get all UDF Match info");
           return STD_ERR(UDF, FAIL, 0);
       }
   }

   return STD_ERR_OK;
}

t_std_error nas_udf_get_match(cps_api_get_params_t* param, size_t index,
                              cps_api_object_t filter_obj) noexcept
{
    t_std_error  rc = cps_api_ret_code_OK;
    nas_switch_id_t        switch_id = 0;
    nas_obj_id_t           match_id = 0;

    bool switch_id_key = nas_acl_cps_key_get_switch_id (filter_obj,
                                                        NAS_ACL_SWITCH_ATTR,
                                                        &switch_id);
    bool match_id_key = nas_acl_cps_key_get_obj_id (filter_obj,
                                                    BASE_UDF_UDF_MATCH_ID,
                                                    &match_id);
    try {
        if (!switch_id_key) {
            /* No keys provided */
            rc = nas_get_udf_match_info_all (param, index);
        }
        else if (switch_id_key && !match_id_key) {
            /* Switch Id provided */
            nas_acl_switch& s = nas_acl_get_switch (switch_id);
            rc = nas_get_udf_match_info_by_switch (param, index, s);
        }
        else if (switch_id_key && match_id_key) {
            /* Switch Id and Match Id provided */
            NAS_ACL_LOG_DETAIL ("Switch Id: %d, Match Id: %ld\n",
                                switch_id, match_id);

            nas_acl_switch& s = nas_acl_get_switch (switch_id);
            nas_udf_match*  udf_match = s.find_udf_match (match_id);
            if (udf_match == nullptr) {
                throw nas::base_exception {NAS_ACL_E_ATTR_VAL, __FUNCTION__,
                    "Invalid UDF Match ID"};
            }

            rc = nas_get_udf_match_info (param->list, *udf_match);
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

t_std_error nas_udf_match_create(cps_api_object_t obj,
                                 cps_api_object_t prev,
                                 bool is_rollbk) noexcept
{
    nas_switch_id_t switch_id = 0;
    nas_obj_id_t match_id = 0;
    bool is_prio_present = false, is_type_present = false;
    bool id_passed_in = false;
    bool is_l2_present = false, is_l2_mask_present = false;
    bool is_l3_present = false, is_l3_mask_present = false;
    bool is_inner_present = false, is_outer_present = false;
    uint16_t l2_type = 0, l2_mask = 0;
    uint8_t l3_type = 0, l3_mask = 0;
    uint_t inner_type = 0, outer_type = 0;
    cps_api_attr_id_t attr_id = 0;
    cps_api_object_it_t it{};

    if (!nas_acl_cps_key_get_switch_id(obj, NAS_ACL_SWITCH_ATTR,
                                       &switch_id)) {
        NAS_ACL_LOG_ERR("Failed to get switch id");
        return STD_ERR(UDF, FAIL, 0);
    }

    if (nas_acl_cps_key_get_obj_id(obj, BASE_UDF_UDF_MATCH_ID, &match_id)) {
        id_passed_in = true;
        NAS_ACL_LOG_BRIEF("Match ID %lu provided for Match create", match_id);
    }

    try {
        nas_acl_switch& s = nas_acl_get_switch(switch_id);
        if (id_passed_in) {
            nas_udf_match* match_p = s.find_udf_match(match_id);
            if (match_p != nullptr) {
                NAS_ACL_LOG_ERR("Match ID %lu already taken", match_id);
                return STD_ERR(UDF, FAIL, 0);
            }
        }

        nas_udf_match udf_match(&s);

        for (cps_api_object_it_begin(obj, &it); cps_api_object_it_valid(&it);
             cps_api_object_it_next(&it)) {
            attr_id = cps_api_object_attr_id(it.attr);
            switch(attr_id) {
            case BASE_UDF_UDF_MATCH_PRIORITY:
            {
                if (is_prio_present) {
                    NAS_ACL_LOG_ERR("Duplicate match priority attribute");
                    return STD_ERR(UDF, FAIL, 0);
                }
                is_prio_present = true;
                uint8_t* byte_p = (uint8_t*)cps_api_object_attr_data_bin(it.attr);
                udf_match.set_priority(byte_p[0]);
                break;
            }
            case BASE_UDF_UDF_MATCH_TYPE:
            {
                if (is_type_present) {
                    NAS_ACL_LOG_ERR("Duplicate match type attribute");
                    return STD_ERR(UDF, FAIL, 0);
                }
                is_type_present = true;
                uint_t type = cps_api_object_attr_data_u32(it.attr);
                udf_match.set_type(type);
                break;
            }
            case BASE_UDF_UDF_MATCH_NON_TUNNEL_VALUE_L2_TYPE:
                if (is_l2_present) {
                    NAS_ACL_LOG_ERR("Duplicate L2 type attribute");
                    return STD_ERR(UDF, FAIL, 0);
                }
                is_l2_present = true;
                l2_type = cps_api_object_attr_data_u16(it.attr);
                break;
            case BASE_UDF_UDF_MATCH_NON_TUNNEL_VALUE_L2_TYPE_MASK:
                if (is_l2_mask_present) {
                    NAS_ACL_LOG_ERR("Duplicate L2 type mask attribute");
                    return STD_ERR(UDF, FAIL, 0);
                }
                is_l2_mask_present = true;
                l2_mask = cps_api_object_attr_data_u16(it.attr);
                break;
            case BASE_UDF_UDF_MATCH_NON_TUNNEL_VALUE_L3_TYPE:
                if (is_l3_present) {
                    NAS_ACL_LOG_ERR("Duplicate L3 type attribute");
                    return STD_ERR(UDF, FAIL, 0);
                }
                is_l3_present = true;
                l3_type = ((uint8_t*)cps_api_object_attr_data_bin(it.attr))[0];
                break;
            case BASE_UDF_UDF_MATCH_NON_TUNNEL_VALUE_L3_TYPE_MASK:
                if (is_l3_mask_present) {
                    NAS_ACL_LOG_ERR("Duplicate L3 type mask attribute");
                    return STD_ERR(UDF, FAIL, 0);
                }
                is_l3_mask_present = true;
                l3_mask = ((uint8_t*)cps_api_object_attr_data_bin(it.attr))[0];
                break;
            case BASE_UDF_UDF_MATCH_GRE_TUNNEL_VALUE_INNER_TYPE:
                if (is_inner_present) {
                    NAS_ACL_LOG_ERR("Duplicate inner ip type attribute");
                    return STD_ERR(UDF, FAIL, 0);
                }
                is_inner_present = true;
                inner_type = cps_api_object_attr_data_u32(it.attr);
                break;
            case BASE_UDF_UDF_MATCH_GRE_TUNNEL_VALUE_OUTER_TYPE:
                if (is_outer_present) {
                    NAS_ACL_LOG_ERR("Duplicate outer ip type attribute");
                    return STD_ERR(UDF, FAIL, 0);
                }
                is_outer_present = true;
                outer_type = cps_api_object_attr_data_u32(it.attr);
                break;
            default:
                NAS_ACL_LOG_DETAIL("Unknown attribute ignored %lu(%lx)",
                                   attr_id, attr_id);
                break;
            }
        }

        if (!is_type_present || !is_prio_present) {
            NAS_ACL_LOG_ERR("Mandatory attributes not exist");
            return STD_ERR(UDF, FAIL, 0);
        }

        BASE_UDF_UDF_MATCH_TYPE_t type = udf_match.type();
        if (type == BASE_UDF_UDF_MATCH_TYPE_NON_TUNNEL) {
            if (is_l2_present) {
                if (is_l2_mask_present) {
                    udf_match.set_ethertype(l2_type, l2_mask);
                } else {
                    udf_match.set_ethertype(l2_type);
                }
            }
            if (is_l3_present) {
                if (is_l3_mask_present) {
                    udf_match.set_ip_protocol(l3_type, l3_mask);
                } else {
                    udf_match.set_ip_protocol(l3_type);
                }
            }
        } else if (type == BASE_UDF_UDF_MATCH_TYPE_GRE_TUNNEL) {
            if (!is_inner_present) {
                NAS_ACL_LOG_ERR("Mandatory attributes of GRE tunnel not exist");
                return STD_ERR(UDF, FAIL, 0);
            }
            if (is_outer_present) {
                udf_match.set_gre_tunnel(inner_type, outer_type);
            } else {
                udf_match.set_gre_tunnel(inner_type);
            }
        } else {
            NAS_ACL_LOG_ERR("Invalid UDF match type");
            return STD_ERR(UDF, FAIL, 0);
        }

        if (id_passed_in) {
            s.reserve_udf_match_id(match_id);
        } else {
            match_id = s.alloc_udf_match_id();
        }
        udf_match.set_match_id(match_id);

        try {
            udf_match.commit_create(is_rollbk);
        } catch (nas::base_exception& e) {
            s.release_udf_match_id(match_id);
            throw e;
        }

        // WARNING !!! CANNOT throw error or exception beyond this point
        // since UDF match is already committed to SAI

        nas_udf_match& new_match = s.save_udf_match(std::move(udf_match));
        match_id = new_match.match_id();
        if (!nas_acl_cps_key_set_obj_id(obj, BASE_UDF_UDF_MATCH_ID, match_id)) {
            NAS_ACL_LOG_ERR("Failed to set Match ID as key");
        }
        if (!is_rollbk) {
            cps_api_object_set_key(prev, cps_api_object_key(obj));
            nas_acl_cps_key_set_obj_id(prev, BASE_UDF_UDF_MATCH_ID, match_id);
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

t_std_error nas_udf_match_delete(cps_api_object_t obj,
                                 cps_api_object_t prev,
                                 bool is_rollbk) noexcept
{
    nas_switch_id_t switch_id = 0;
    nas_obj_id_t match_id = 0;

    if (!nas_acl_cps_key_get_switch_id(obj, NAS_ACL_SWITCH_ATTR,
                                       &switch_id)) {
        NAS_ACL_LOG_ERR("Switch ID is a mandatory key for UDF Match Delete");
        return STD_ERR(UDF, FAIL, 0);
    }
    if (!nas_acl_cps_key_get_obj_id (obj, BASE_UDF_UDF_MATCH_ID, &match_id)) {
        NAS_ACL_LOG_ERR("Match ID is a mandatory key for Match Delete");
        return STD_ERR(UDF, FAIL, 0);
    }

    NAS_ACL_LOG_BRIEF("%sSwitch Id: %d Match Id %ld",
                      (is_rollbk) ? "** ROLLBACK **: " : "", switch_id, match_id);

    try {
        nas_acl_switch& s = nas_acl_get_switch (switch_id);
        nas_udf_match* match_p = s.find_udf_match(match_id);
        if (match_p == nullptr) {
            NAS_ACL_LOG_ERR("Invalid UDF Match ID %lu", match_id);
            return STD_ERR(UDF, FAIL, 0);
        }

        if (!is_rollbk) {
            cps_api_object_set_key(prev, cps_api_object_key(obj));
            nas_acl_cps_key_set_obj_id(prev, BASE_UDF_UDF_MATCH_ID, match_id);
            nas_fill_udf_match_attr(prev, *match_p);
        }

        match_p->commit_delete(is_rollbk);

        // WARNING !!! CANNOT throw error or exception beyond this point
        // since UDF match is already deleted from SAI

        s.remove_udf_match(match_id);
        s.release_udf_match_id(match_id);

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
