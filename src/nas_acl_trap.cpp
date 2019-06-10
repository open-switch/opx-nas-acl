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
 * \file   nas_acl_trap.cpp
 * \brief  NAS ACL Trap class
 * \date   10-2018
 */

#include "std_utils.h"
#include "nas_acl_trap.h"
#include "nas_acl_switch.h"
#include "nas_ndi_acl.h"
#include "nas_ndi_trap.h"

nas_acl_trap::nas_acl_trap(nas_acl_switch* switch_p)
    : nas::base_obj_t(switch_p)
{
    _type = NAS_ACL_TRAP_TYPE_DEF;
    _group_id = NAS_ACL_TRAP_GRP_ID_NONE;
}

nas_acl_switch& nas_acl_trap::get_switch() const noexcept
{
    return static_cast<nas_acl_switch&>(nas::base_obj_t::get_switch());
}

ndi_obj_id_t nas_acl_trap::get_ndi_obj_id (npu_id_t npu_id) const
{
    try {
        return _ndi_obj_ids.at(npu_id);
    } catch (...) {
        throw nas::base_exception {NAS_ACL_E_FAIL, __PRETTY_FUNCTION__,
                       std::string {"Cannot find NDI ID for ACL Trap in NPU "}
                       + std::to_string (npu_id)};
    }
}

void nas_acl_trap::set_name(const char *name)
{
    size_t n_len = strlen(name);

    if (n_len > sizeof(_name)) n_len = sizeof(_name);

    safestrncpy(_name, name, n_len);

    mark_attr_dirty(BASE_TRAP_TRAP_NAME);
}

void nas_acl_trap::commit_create(bool rolling_back)
{
    if (!is_attr_dirty ( BASE_TRAP_TRAP_TYPE )) {
        throw nas::base_exception {NAS_ACL_E_CREATE_ONLY, __PRETTY_FUNCTION__,
            "Mandatory attribute Trap Type not present"};
    }

    nas::base_obj_t::commit_create(rolling_back);
}

nas::attr_set_t nas_acl_trap::commit_modify (base_obj_t& entry_orig, bool rolling_back)
{
    // Currently only group id set is supported
    if (!is_attr_dirty ( BASE_TRAP_TRAP_TRAP_GROUP_ID )) {
        throw nas::base_exception {NAS_ACL_E_UNSUPPORTED, __PRETTY_FUNCTION__,
            "No allowed Trap attribute to modify"};
    }

    return nas::base_obj_t::commit_modify(entry_orig, rolling_back);
}

void nas_acl_trap::commit_delete(bool rolling_back)
{
    if (is_acl_ref()) {
        throw nas::base_exception {NAS_ACL_E_INCONSISTENT,
                                   __PRETTY_FUNCTION__,
                                   "Cannot delete ACL Trap when it is referenced"};
    }

    nas::base_obj_t::commit_delete(rolling_back);
}

bool nas_acl_trap::push_create_obj_to_npu(npu_id_t npu_id, void *ndi_obj)
{
    ndi_obj_id_t ndi_trap_id = 0;
    t_std_error rc;
    size_t count = NAS_ACL_TRAP_PARAM_L;
    nas_acl_trap_attr_t *trap_attr = new nas_acl_trap_attr_t[count];
    if (!trap_attr)
        return STD_ERR(ACL, PARAM, 0);

    count = 0;

    trap_attr[count].attr_id = BASE_TRAP_TRAP_TYPE;
    trap_attr[count].val.u32 = type();
    trap_attr[count].vlen = sizeof(trap_attr[count].val.u32);
    count ++;
    
    if (group() != NAS_ACL_TRAP_GRP_ID_NONE) {
        trap_attr[count].attr_id = BASE_TRAP_TRAP_TRAP_GROUP_ID;
        trap_attr[count].val.oid = group();
        trap_attr[count].vlen = sizeof(trap_attr[count].val.oid);
        count++;
    }
    

    rc = ndi_acl_trapid_create(npu_id, trap_attr, count, &ndi_trap_id);
    if (rc != STD_ERR_OK) {
        throw nas::base_exception {rc, __PRETTY_FUNCTION__,
            std::string("NDI Fail: ACL Trapid Create Failed for NPU ")
            + std::to_string(npu_id)};
    } else {
        set_trap_id(ndi_trap_id);
        _ndi_obj_ids[npu_id] = ndi_trap_id;
    }


    delete[] trap_attr;

    return true;
}


bool nas_acl_trap::push_delete_obj_to_npu(npu_id_t npu_id)
{
    t_std_error rc;

    nas_acl_trap_attr_t trap_attr;
    trap_attr.attr_id = BASE_TRAP_TRAP_TYPE;
    trap_attr.val.u32 = type();
    trap_attr.vlen = sizeof(trap_attr.val.u32);

    rc = ndi_acl_trapid_delete(npu_id, &trap_attr, trap_id());
    if (rc != STD_ERR_OK) {
        throw nas::base_exception {rc, __PRETTY_FUNCTION__,
                                  std::string {"NDI Fail: ACL Trapid "}
                                  +    std::to_string (trap_id()) +
                                  std::string {" Delete Failed for NPU "}
                                  +    std::to_string (npu_id)};
    }

    _ndi_obj_ids.erase (npu_id);
    return true;
}


bool nas_acl_trap::push_leaf_attr_to_npu (nas_attr_id_t nas_attr_id, npu_id_t npu_id)
{
    t_std_error rc = STD_ERR_OK;
    size_t count = NAS_ACL_TRAP_PARAM_L;
    nas_acl_trap_attr_t *trap_attr = new nas_acl_trap_attr_t[count];
    bool ret = true;
    
    if (!trap_attr) {
        throw nas::base_exception {rc, __PRETTY_FUNCTION__,
            std::string("NDI Fail: ACL Trap Set GRP ID Alloc Failed for NPU ")
            + std::to_string(npu_id)};
        return false;
    }

    {
        count = 0;

        trap_attr[count].attr_id = BASE_TRAP_TRAP_TYPE;
        trap_attr[count].val.u32 = type();
        trap_attr[count].vlen = sizeof(trap_attr[count].val.u32);
        count ++;

        trap_attr[count].attr_id = nas_attr_id;
        trap_attr[count].val.oid = group();
        trap_attr[count].vlen = sizeof(trap_attr[count].val.oid);
        count ++;
    

        rc = ndi_acl_trapid_set(npu_id, trap_attr, count, trap_id());
        if (rc != STD_ERR_OK) {
            throw nas::base_exception {rc, __PRETTY_FUNCTION__,
                std::string("NDI Fail: ACL Trap Set GRP ID Failed for NPU ")
                + std::to_string(npu_id)};
        }   
    }

    delete[] trap_attr;

    return ret;
}
