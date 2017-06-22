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
 * \file   nas_udf_group.cpp
 * \brief  NAS UDF Group Object
 * \date   10-2016
 */

#include "nas_udf_group.h"
#include "nas_acl_switch.h"
#include "nas_ndi_udf.h"
#include "nas_acl_log.h"

nas_udf_group::nas_udf_group(nas_acl_switch* switch_p)
    : nas::base_obj_t(switch_p)
{
}

nas_acl_switch& nas_udf_group::get_switch() const noexcept
{
    return static_cast<nas_acl_switch&>(nas::base_obj_t::get_switch());
}

ndi_obj_id_t nas_udf_group::get_ndi_obj_id (npu_id_t npu_id) const
{
    try {
        return _ndi_obj_ids.at(npu_id);
    } catch (...) {
        throw nas::base_exception {NAS_ACL_E_FAIL, __PRETTY_FUNCTION__,
                       std::string {"Cannot find NDI ID for Group in NPU "}
                       + std::to_string (npu_id)};
    }
}

void nas_udf_group::set_type(uint_t type)
{
    if (is_created_in_ndi()) {
        throw nas::base_exception {NAS_ACL_E_CREATE_ONLY, __PRETTY_FUNCTION__,
                                   "Cannot modify Type for UDF Group"};
    }

    _type = static_cast<BASE_UDF_UDF_GROUP_TYPE_t>(type);
    if (_type != BASE_UDF_UDF_GROUP_TYPE_GENERIC &&
        _type != BASE_UDF_UDF_GROUP_TYPE_HASH) {
        throw nas::base_exception {NAS_ACL_E_ATTR_VAL, __PRETTY_FUNCTION__,
                                   "Invalid Type value"};
    }

    mark_attr_dirty(BASE_UDF_UDF_GROUP_TYPE);
}

void nas_udf_group::set_length(uint8_t length)
{
    if (is_created_in_ndi()) {
        throw nas::base_exception {NAS_ACL_E_CREATE_ONLY, __PRETTY_FUNCTION__,
                                   "Cannot modify Length for UDF Group"};
    }

    _length = static_cast<size_t>(length);

    mark_attr_dirty(BASE_UDF_UDF_GROUP_LENGTH);
}

void nas_udf_group::add_udf_id(nas_obj_id_t udf_id)
{
    if (!is_created_in_ndi()) {
        throw nas::base_exception {NAS_ACL_E_FAIL, __PRETTY_FUNCTION__,
                                   "Cannot add UDF ID to non-created Group object"};
    }

    auto rc = _udf_ids.find(udf_id);
    if (rc != _udf_ids.end()) {
        throw nas::base_exception {NAS_ACL_E_FAIL, __PRETTY_FUNCTION__,
                                   "UDF ID was already added to Group object"};
    }

    _udf_ids.insert(udf_id);
}

void nas_udf_group::del_udf_id(nas_obj_id_t udf_id)
{
    if (!is_created_in_ndi()) {
        throw nas::base_exception {NAS_ACL_E_FAIL, __PRETTY_FUNCTION__,
                                   "Cannot delete UDF ID from non-created Group object"};
    }

    auto rc = _udf_ids.find(udf_id);
    if (rc == _udf_ids.end()) {
        throw nas::base_exception {NAS_ACL_E_FAIL, __PRETTY_FUNCTION__,
                                   "UDF ID has not been added to Group object"};
    }

    _udf_ids.erase(udf_id);
}

bool nas_udf_group::check_udf_id(nas_obj_id_t udf_id) const noexcept
{
    auto rc = _udf_ids.find(udf_id);
    return !(rc == _udf_ids.end());
}

size_t nas_udf_group::get_udf_id_count() const noexcept
{
    return _udf_ids.size();
}

void nas_udf_group::commit_create(bool rolling_back)
{
    if (!is_attr_dirty (BASE_UDF_UDF_GROUP_TYPE)) {
        throw nas::base_exception {NAS_ACL_E_CREATE_ONLY, __PRETTY_FUNCTION__,
            "Mandatory attribute Type not present"};
    }

    if (!is_attr_dirty (BASE_UDF_UDF_GROUP_LENGTH)) {
        throw nas::base_exception {NAS_ACL_E_CREATE_ONLY, __PRETTY_FUNCTION__,
            "Mandatory attribute Length not present"};
    }

    nas::base_obj_t::commit_create(rolling_back);
}

void nas_udf_group::commit_delete(bool rolling_back)
{
    if (get_udf_id_count() != 0) {
        throw nas::base_exception {NAS_ACL_E_INCONSISTENT,
                                   __PRETTY_FUNCTION__,
                                   "Cannot delete UDF Group when it has UDFs"};
    }

    if (is_acl_ref()) {
        throw nas::base_exception {NAS_ACL_E_INCONSISTENT,
                                   __PRETTY_FUNCTION__,
                                   "Cannot delete UDF Group when it is referenced by ACL table"};
    }

    nas::base_obj_t::commit_delete(rolling_back);
}

void* nas_udf_group::alloc_fill_ndi_obj(nas::mem_alloc_helper_t& mem_trakr)
{
    ndi_udf_grp_t* ndi_grp_p = mem_trakr.alloc<ndi_udf_grp_t>(1);
    if (type() == BASE_UDF_UDF_GROUP_TYPE_GENERIC) {
        ndi_grp_p->group_type = NAS_NDI_UDF_GROUP_GENERIC;
    } else {
        ndi_grp_p->group_type = NAS_NDI_UDF_GROUP_HASH;
    }
    ndi_grp_p->length = length();

    return ndi_grp_p;
}

bool nas_udf_group::push_create_obj_to_npu(npu_id_t npu_id, void* ndi_obj)
{
    ndi_obj_id_t ndi_grp_id = 0;
    t_std_error rc;

    auto ndi_grp_p = static_cast<ndi_udf_grp_t*>(ndi_obj);

    rc = ndi_udf_group_create(npu_id, ndi_grp_p, &ndi_grp_id);
    if (rc != STD_ERR_OK) {
        throw nas::base_exception {rc, __PRETTY_FUNCTION__,
                        std::string {"NDI Fail: UDF Group Create Failed for NPU "}
                        + std::to_string(npu_id)};
    }

    _ndi_obj_ids[npu_id] = ndi_grp_id;

    return true;
}

bool nas_udf_group::push_delete_obj_to_npu(npu_id_t npu_id)
{
    t_std_error rc;

    rc = ndi_udf_group_delete(npu_id, _ndi_obj_ids.at (npu_id));
    if (rc != STD_ERR_OK) {
        throw nas::base_exception {rc, __PRETTY_FUNCTION__,
                                  std::string {"NDI Fail: UDF Group "}
                                  +    std::to_string (group_id()) +
                                  std::string {" Delete Failed for NPU "}
                                  +    std::to_string (npu_id)};
    }

    _ndi_obj_ids.erase (npu_id);
    return true;
}

bool nas_udf_group::push_leaf_attr_to_npu(nas_attr_id_t attr_id, npu_id_t npu_id)
{
    return true;
}
