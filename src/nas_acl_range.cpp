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
 * \file   nas_acl_range.cpp
 * \brief  NAS ACL Range Object
 * \date   05-2017
 */

#include "nas_acl_range.h"
#include "nas_acl_switch.h"
#include "nas_ndi_acl.h"

nas_acl_range::nas_acl_range(nas_acl_switch* switch_p)
    : nas::base_obj_t(switch_p)
{
}

nas_acl_switch& nas_acl_range::get_switch() const noexcept
{
    return static_cast<nas_acl_switch&>(nas::base_obj_t::get_switch());
}

ndi_obj_id_t nas_acl_range::get_ndi_obj_id (npu_id_t npu_id) const
{
    try {
        return _ndi_obj_ids.at(npu_id);
    } catch (...) {
        throw nas::base_exception {NAS_ACL_E_FAIL, __PRETTY_FUNCTION__,
                       std::string {"Cannot find NDI ID for ACL Range in NPU "}
                       + std::to_string (npu_id)};
    }
}

void nas_acl_range::set_type(uint_t type)
{
    if (is_created_in_ndi()) {
        throw nas::base_exception {NAS_ACL_E_CREATE_ONLY, __PRETTY_FUNCTION__,
                                   "Cannot modify Type for ACL Range"};
    }

    _type = static_cast<BASE_ACL_RANGE_TYPE_t>(type);
    if (_type != BASE_ACL_RANGE_TYPE_L4_SRC_PORT &&
        _type != BASE_ACL_RANGE_TYPE_L4_DST_PORT &&
        _type != BASE_ACL_RANGE_TYPE_OUTER_VLAN &&
        _type != BASE_ACL_RANGE_TYPE_INNER_VLAN &&
        _type != BASE_ACL_RANGE_TYPE_PACKET_LENGTH) {
        throw nas::base_exception {NAS_ACL_E_ATTR_VAL, __PRETTY_FUNCTION__,
                                   "Invalid Type value"};
    }

    mark_attr_dirty(BASE_ACL_RANGE_TYPE);
}

void nas_acl_range::set_limit_min(uint_t limit_min)
{
    if (is_created_in_ndi()) {
        throw nas::base_exception {NAS_ACL_E_CREATE_ONLY, __PRETTY_FUNCTION__,
                                   "Cannot modify minimum limit for ACL Range"};
    }

    _limit_min = limit_min;

    mark_attr_dirty(BASE_ACL_RANGE_LIMIT_MIN);
}

void nas_acl_range::set_limit_max(uint_t limit_max)
{
    if (is_created_in_ndi()) {
        throw nas::base_exception {NAS_ACL_E_CREATE_ONLY, __PRETTY_FUNCTION__,
                                   "Cannot modify maximum limit for ACL Range"};
    }

    _limit_max = limit_max;

    mark_attr_dirty(BASE_ACL_RANGE_LIMIT_MAX);
}

void nas_acl_range::commit_create(bool rolling_back)
{
    if (!is_attr_dirty (BASE_ACL_RANGE_TYPE)) {
        throw nas::base_exception {NAS_ACL_E_CREATE_ONLY, __PRETTY_FUNCTION__,
            "Mandatory attribute Type not present"};
    }

    if (!is_attr_dirty (BASE_ACL_RANGE_LIMIT_MIN)) {
        throw nas::base_exception {NAS_ACL_E_CREATE_ONLY, __PRETTY_FUNCTION__,
            "Mandatory attribute Length not present"};
    }

    if (!is_attr_dirty (BASE_ACL_RANGE_LIMIT_MAX)) {
        throw nas::base_exception {NAS_ACL_E_CREATE_ONLY, __PRETTY_FUNCTION__,
            "Mandatory attribute Length not present"};
    }

    nas::base_obj_t::commit_create(rolling_back);
}

void nas_acl_range::commit_delete(bool rolling_back)
{
    if (is_acl_ref()) {
        throw nas::base_exception {NAS_ACL_E_INCONSISTENT,
                                   __PRETTY_FUNCTION__,
                                   "Cannot delete ACL Range when it is referenced by ACL table"};
    }

    nas::base_obj_t::commit_delete(rolling_back);
}

void* nas_acl_range::alloc_fill_ndi_obj(nas::mem_alloc_helper_t& mem_trakr)
{
    ndi_acl_range_t* ndi_range_p = mem_trakr.alloc<ndi_acl_range_t>(1);
    switch(type()) {
    case BASE_ACL_RANGE_TYPE_L4_SRC_PORT:
        ndi_range_p->type = NDI_ACL_RANGE_L4_SRC_PORT;
        break;
    case BASE_ACL_RANGE_TYPE_L4_DST_PORT:
        ndi_range_p->type = NDI_ACL_RANGE_L4_DST_PORT;
        break;
    case BASE_ACL_RANGE_TYPE_OUTER_VLAN:
        ndi_range_p->type = NDI_ACL_RANGE_OUTER_VLAN;
        break;
    case BASE_ACL_RANGE_TYPE_INNER_VLAN:
        ndi_range_p->type = NDI_ACL_RANGE_INNER_VLAN;
        break;
    case BASE_ACL_RANGE_TYPE_PACKET_LENGTH:
        ndi_range_p->type = NDI_ACL_RANGE_PACKET_LENGTH;
        break;
    default:
        throw nas::base_exception {NAS_ACL_E_ATTR_VAL, __PRETTY_FUNCTION__,
            "Invalid ACL range type"};
    }
    ndi_range_p->min = limit_min();
    ndi_range_p->max = limit_max();

    return ndi_range_p;
}

bool nas_acl_range::push_create_obj_to_npu(npu_id_t npu_id, void* ndi_obj)
{
    ndi_obj_id_t ndi_range_id = 0;
    t_std_error rc;

    auto ndi_range_p = static_cast<ndi_acl_range_t*>(ndi_obj);

    rc = ndi_acl_range_create(npu_id, ndi_range_p, &ndi_range_id);
    if (rc != STD_ERR_OK) {
        throw nas::base_exception {rc, __PRETTY_FUNCTION__,
                        std::string {"NDI Fail: ACL Range Create Failed for NPU "}
                        + std::to_string(npu_id)};
    }

    _ndi_obj_ids[npu_id] = ndi_range_id;

    return true;
}

bool nas_acl_range::push_delete_obj_to_npu(npu_id_t npu_id)
{
    t_std_error rc;

    rc = ndi_acl_range_delete(npu_id, _ndi_obj_ids.at (npu_id));
    if (rc != STD_ERR_OK) {
        throw nas::base_exception {rc, __PRETTY_FUNCTION__,
                                  std::string {"NDI Fail: ACL Range "}
                                  +    std::to_string (range_id()) +
                                  std::string {" Delete Failed for NPU "}
                                  +    std::to_string (npu_id)};
    }

    _ndi_obj_ids.erase (npu_id);
    return true;
}

bool nas_acl_range::push_leaf_attr_to_npu(nas_attr_id_t attr_id, npu_id_t npu_id)
{
    return true;
}
