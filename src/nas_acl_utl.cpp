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

/*
 * filename: nas_acl_utl.cpp
 */


/**
 * \file nas_acl_utl.cpp
 * \brief NAS ACL Utilities
 **/

#include "nas_acl_utl.h"
#include "nas_base_utils.h"
#include "nas_acl_switch.h"

static bool _get_ifinfo (hal_ifindex_t ifindex, interface_ctrl_t *intf_ctrl_p)
{
    intf_ctrl_p->q_type = HAL_INTF_INFO_FROM_IF;
    intf_ctrl_p->if_index = ifindex;

    return (dn_hal_get_interface_info(intf_ctrl_p) == STD_ERR_OK);
}

void nas_acl_utl_ifidx_to_ndi_port (hal_ifindex_t ifindex, interface_ctrl_t *intf_ctrl_p)
{
    if (!_get_ifinfo (ifindex, intf_ctrl_p)) {
        throw nas::base_exception {NAS_ACL_E_ATTR_VAL, __PRETTY_FUNCTION__,
                                   std::string {"Invalid IfIndex "} +
                                       std::to_string (ifindex)};
    }
    if (intf_ctrl_p->int_type != nas_int_type_PORT &&
        intf_ctrl_p->int_type != nas_int_type_FC) {
        throw nas::base_exception {NAS_ACL_E_ATTR_VAL, __PRETTY_FUNCTION__,
                                   std::string {"Invalid IfIndex type"} +
                                       std::to_string (ifindex)};
    }
}

bool nas_acl_utl_is_ifidx_type_lag (hal_ifindex_t ifindex)
{
    interface_ctrl_t  intf_ctrl = {};
    if (!_get_ifinfo (ifindex, &intf_ctrl)) {
        throw nas::base_exception {NAS_ACL_E_ATTR_VAL, __PRETTY_FUNCTION__,
                                   std::string {"Invalid IfIndex "} +
                                       std::to_string (ifindex)};
    }
    return (intf_ctrl.int_type == nas_int_type_LAG);
}

nas_obj_id_t nas_acl_id_guard_t::alloc_guarded_id ()
{
    switch (_obj_type) {
        case BASE_ACL_TABLE_OBJ:
            _guarded_id = _sw_p->alloc_table_id ();
            break;
        case BASE_ACL_ENTRY_OBJ:
            _guarded_id = _sw_p->alloc_entry_id_in_table (_table_id);
            break;
        case BASE_ACL_COUNTER_OBJ:
            _guarded_id = _sw_p->alloc_counter_id_in_table (_table_id);
            break;
        default:
            throw nas::base_exception {NAS_ACL_E_FAIL, __PRETTY_FUNCTION__,
                                       std::string ("Unknown Object type ") +
                                       std::to_string (_obj_type)};
    }
    _guarding = true;
    return _guarded_id;
}

bool nas_acl_id_guard_t::reserve_guarded_id (nas_obj_id_t id)
{
    bool unused = true;
    switch (_obj_type) {
        case BASE_ACL_TABLE_OBJ:
            unused = _sw_p->reserve_table_id (id);
            break;
        case BASE_ACL_ENTRY_OBJ:
            unused = _sw_p->reserve_entry_id_in_table (_table_id, id);
            break;
        case BASE_ACL_COUNTER_OBJ:
            unused = _sw_p->reserve_counter_id_in_table (_table_id, id);
            break;
        default:
            throw nas::base_exception {NAS_ACL_E_FAIL, __PRETTY_FUNCTION__,
                                       std::string ("Unknown Object type ") +
                                       std::to_string (_obj_type)};
    }
    if (!unused) return false;
    _guarding = true;_guarded_id=id;
    return true;
};

nas_acl_id_guard_t::~nas_acl_id_guard_t () noexcept
{
    if (!_guarding) return;

    switch (_obj_type) {
        case BASE_ACL_TABLE_OBJ:
            _sw_p->release_table_id (_guarded_id);
            break;
        case BASE_ACL_ENTRY_OBJ:
            _sw_p->release_entry_id_in_table (_table_id, _guarded_id);
            break;
        case BASE_ACL_COUNTER_OBJ:
            _sw_p->release_counter_id_in_table (_table_id, _guarded_id);
            break;
        default:
            break;
    }
}
