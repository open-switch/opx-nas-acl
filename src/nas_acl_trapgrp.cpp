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
 * \file   nas_acl_trapgrp.cpp
 * \brief  NAS ACL Trapgrp class
 * \date   1-2019
 */

#include "std_utils.h"
#include "nas_acl_trap.h"
#include "nas_acl_trapgrp.h"
#include "nas_acl_switch.h"
#include "nas_ndi_acl.h"
#include "nas_ndi_trap.h"

nas_acl_trapgrp::nas_acl_trapgrp(nas_acl_switch* switch_p)
    : nas::base_obj_t(switch_p)
{
    _admin_state = NAS_ACL_TRAPGRP_ADMIN_DEF;
    _queue_id = NAS_ACL_TRAPGRP_QUEUE_ID_DEF;
}

nas_acl_switch& nas_acl_trapgrp::get_switch() const noexcept
{
    return static_cast<nas_acl_switch&>(nas::base_obj_t::get_switch());
}

ndi_obj_id_t nas_acl_trapgrp::get_ndi_obj_id (npu_id_t npu_id) const
{
    try {
        return _ndi_obj_ids.at(npu_id);
    } catch (...) {
        throw nas::base_exception {NAS_ACL_E_FAIL, __PRETTY_FUNCTION__,
                       std::string {"Cannot find NDI ID for ACL Trap Group in NPU "}
                       + std::to_string (npu_id)};
    }
}

void nas_acl_trapgrp::set_name(const char *name)
{
    size_t n_len = strlen(name);

    if (n_len > sizeof(_name)) n_len = sizeof(_name);

    safestrncpy(_name, name, n_len);

    mark_attr_dirty(BASE_TRAP_TRAP_GROUP_NAME);
}

void nas_acl_trapgrp::commit_create(bool rolling_back)
{
    if (!is_attr_dirty ( BASE_TRAP_TRAP_GROUP_QUEUE_ID )) {
        throw nas::base_exception {NAS_ACL_E_CREATE_ONLY, __PRETTY_FUNCTION__,
            "Mandatory attribute Trap Group Queue not present"};
    }

    nas::base_obj_t::commit_create(rolling_back);
}

nas::attr_set_t nas_acl_trapgrp::commit_modify (base_obj_t& entry_orig, bool rolling_back)
{
    if (!is_attr_dirty ( BASE_TRAP_TRAP_GROUP_QUEUE_ID ) &&
        !is_attr_dirty ( BASE_TRAP_TRAP_GROUP_ADMIN )) {
        throw nas::base_exception {NAS_ACL_E_UNSUPPORTED, __PRETTY_FUNCTION__,
            "No allowed Trap Group attribute to modify"};
    }

    return nas::base_obj_t::commit_modify(entry_orig, rolling_back);
}

void nas_acl_trapgrp::commit_delete(bool rolling_back)
{
    if (is_acl_ref()) {
        throw nas::base_exception {NAS_ACL_E_INCONSISTENT,
                                   __PRETTY_FUNCTION__,
                                   "Cannot delete ACL Trap Group when referenced"};
    }

    nas::base_obj_t::commit_delete(rolling_back);
}

bool nas_acl_trapgrp::push_create_obj_to_npu(npu_id_t npu_id, void *ndi_obj)
{
    ndi_obj_id_t ndi_trapgrp_id = NAS_ACL_TRAP_GRP_ID_NONE;
    t_std_error rc;
    size_t count = NAS_ACL_TRAP_PARAM_L;
    nas_acl_trap_attr_t *trapgrp_attr = new nas_acl_trap_attr_t[count];

    count = 0;
    
    trapgrp_attr[count].attr_id = BASE_TRAP_TRAP_GROUP_QUEUE_ID;
    trapgrp_attr[count].val.oid = queue();
    trapgrp_attr[count].vlen = sizeof(trapgrp_attr[count].val.oid);
    count++;

    if (admin_state() != NAS_ACL_TRAPGRP_ADMIN_DEF) {
        trapgrp_attr[count].attr_id = BASE_TRAP_TRAP_GROUP_ADMIN;
        trapgrp_attr[count].val.u32 = admin_state();
        trapgrp_attr[count].vlen = sizeof(trapgrp_attr[count].val.u32);
        count++;
    }
    
    rc = ndi_acl_trapgrp_create(npu_id, trapgrp_attr, count, &ndi_trapgrp_id);
    if (rc != STD_ERR_OK) {
        throw nas::base_exception {rc, __PRETTY_FUNCTION__,
            std::string("NDI Fail: ACL Trapgrpid Create Failed for NPU ")
            + std::to_string(npu_id)};
    } else {
        set_trapgrp_id(ndi_trapgrp_id);
        _ndi_obj_ids[npu_id] = ndi_trapgrp_id;

        NAS_ACL_LOG_DETAIL("ACL Trap Group Create Success %lu", ndi_trapgrp_id);
    }
    
    delete[] trapgrp_attr;

    return true;
}

bool nas_acl_trapgrp::push_delete_obj_to_npu(npu_id_t npu_id)
{
    t_std_error rc;

    rc = ndi_acl_trapgrp_delete(npu_id, trapgrp_id());
    if (rc != STD_ERR_OK) {
        throw nas::base_exception {rc, __PRETTY_FUNCTION__,
                                  std::string {"NDI Fail: ACL Trapgrp "}
                                  +    std::to_string (trapgrp_id()) +
                                  std::string {" Delete Failed for NPU "}
                                  +    std::to_string (npu_id)};
    }

    _ndi_obj_ids.erase(npu_id);

    return true;
}

bool nas_acl_trapgrp::push_leaf_attr_to_npu (nas_attr_id_t nas_attr_id, npu_id_t npu_id)
{
    t_std_error rc;
    nas_acl_trap_attr_t trapgrp_attr;
    size_t count = 0;

    switch (nas_attr_id) {
    case BASE_TRAP_TRAP_GROUP_QUEUE_ID:
        trapgrp_attr.attr_id = BASE_TRAP_TRAP_GROUP_QUEUE_ID;
        trapgrp_attr.val.oid = queue();
        trapgrp_attr.vlen = sizeof(trapgrp_attr.val.oid);
        count = 1;
        break;

    case BASE_TRAP_TRAP_GROUP_ADMIN:
        trapgrp_attr.attr_id = BASE_TRAP_TRAP_GROUP_ADMIN;
        trapgrp_attr.val.u32 = admin_state();
        trapgrp_attr.vlen = sizeof(trapgrp_attr.val.u32);
        count = 1;

        break;

    default:
        return STD_ERR(ACL, PARAM, 0);
    }
    
    rc = ndi_acl_trapgrp_set(npu_id, &trapgrp_attr, count, trapgrp_id());
    if (rc != STD_ERR_OK) {
        throw nas::base_exception {rc, __PRETTY_FUNCTION__,
            std::string("NDI Fail: ACL Trap Group Set Failed for NPU ")
            + std::to_string(npu_id) + std::string(" attr ") + std::to_string(nas_attr_id)};
    } else {
        NAS_ACL_LOG_DETAIL("ACL Trap Group Set Success %lu", trapgrp_id());
    }

    return true;
}
