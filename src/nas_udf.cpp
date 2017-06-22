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
 * \file   nas_udf.cpp
 * \brief  NAS UDF Object
 * \date   10-2016
 */

#include "nas_udf.h"
#include "nas_acl_switch.h"
#include "nas_ndi_udf.h"
#include "nas_acl_log.h"

nas_udf::nas_udf(nas_acl_switch* switch_p)
    : nas::base_obj_t(switch_p)
{
}

nas_acl_switch& nas_udf::get_switch() const noexcept
{
    return static_cast<nas_acl_switch&>(nas::base_obj_t::get_switch());
}

void nas_udf::hash_mask(uint8_t* byte_list, size_t& byte_cnt) const noexcept
{
    if (byte_list == NULL) {
        byte_cnt = _hash_mask.size();
        return;
    }

    size_t copy_cnt = byte_cnt;
    if (copy_cnt > _hash_mask.size()) {
        copy_cnt = _hash_mask.size();
    }
    memcpy(byte_list, _hash_mask.data(), copy_cnt);
    byte_cnt = _hash_mask.size();
}

void nas_udf::set_base(uint_t base)
{
    if (is_created_in_ndi()) {
        throw nas::base_exception {NAS_ACL_E_CREATE_ONLY, __PRETTY_FUNCTION__,
                                   "Cannot modify Base for UDF Object"};
    }

    _base = static_cast<BASE_UDF_UDF_BASE_TYPE_t>(base);
    if (_base != BASE_UDF_UDF_BASE_TYPE_L2 &&
        _base != BASE_UDF_UDF_BASE_TYPE_L3 &&
        _base != BASE_UDF_UDF_BASE_TYPE_L4) {
        throw nas::base_exception {NAS_ACL_E_ATTR_VAL, __PRETTY_FUNCTION__,
                                   "Invalid Base value"};
    }

    mark_attr_dirty(BASE_UDF_UDF_OBJ_BASE);
}

void nas_udf::set_offset(size_t offset)
{
    if (is_created_in_ndi()) {
        throw nas::base_exception {NAS_ACL_E_CREATE_ONLY, __PRETTY_FUNCTION__,
                                   "Cannot modify Offset for UDF Object"};
    }

    _offset = offset;

    mark_attr_dirty(BASE_UDF_UDF_OBJ_OFFSET);
}

void nas_udf::set_hash_mask(uint8_t* byte_list, size_t byte_cnt)
{
    if (byte_list == NULL || byte_cnt == 0) {
        return;
    }
    _hash_mask.clear();
    copy(byte_list, byte_list + byte_cnt, back_inserter(_hash_mask));

    mark_attr_dirty(BASE_UDF_UDF_OBJ_HASH_MASK);
}

void nas_udf::commit_create(bool rolling_back)
{
    if (!is_attr_dirty (BASE_UDF_UDF_OBJ_GROUP_ID)) {
        throw nas::base_exception {NAS_ACL_E_CREATE_ONLY, __PRETTY_FUNCTION__,
            "Mandatory attribute UDF Group ID not present"};
    }

    if (!is_attr_dirty (BASE_UDF_UDF_OBJ_MATCH_ID)) {
        throw nas::base_exception {NAS_ACL_E_CREATE_ONLY, __PRETTY_FUNCTION__,
            "Mandatory attribute UDF Match ID not present"};
    }

    if (!is_attr_dirty (BASE_UDF_UDF_OBJ_BASE)) {
        throw nas::base_exception {NAS_ACL_E_CREATE_ONLY, __PRETTY_FUNCTION__,
            "Mandatory attribute Base not present"};
    }

    nas::base_obj_t::commit_create(rolling_back);
}

void* nas_udf::alloc_fill_ndi_obj(nas::mem_alloc_helper_t& mem_trakr)
{
    ndi_udf_t* ndi_udf_p = mem_trakr.alloc<ndi_udf_t>(1);

    switch(_base) {
    case BASE_UDF_UDF_BASE_TYPE_L2:
        ndi_udf_p->udf_base = NAS_NDI_UDF_BASE_L2;
        break;
    case BASE_UDF_UDF_BASE_TYPE_L3:
        ndi_udf_p->udf_base = NAS_NDI_UDF_BASE_L3;
        break;
    case BASE_UDF_UDF_BASE_TYPE_L4:
        ndi_udf_p->udf_base = NAS_NDI_UDF_BASE_L4;
        break;
    default:
        throw nas::base_exception {NAS_ACL_E_ATTR_VAL, __PRETTY_FUNCTION__,
            "Invalid UDF base type"};
    }
    ndi_udf_p->udf_offset = _offset;
    if (_hash_mask.size() > 0) {
        ndi_udf_p->udf_hash_mask = mem_trakr.alloc<uint8_t>(_hash_mask.size());
        ndi_udf_p->hash_mask_count = _hash_mask.size();
        size_t idx = 0;
        for (auto mask_byte: _hash_mask) {
            ndi_udf_p->udf_hash_mask[idx] = mask_byte;
            idx ++;
        }
    }

    return ndi_udf_p;
}

bool nas_udf::push_create_obj_to_npu(npu_id_t npu_id, void* ndi_obj)
{
    if (ndi_obj == nullptr) {
        return false;
    }

    auto ndi_udf_p = static_cast<ndi_udf_t*>(ndi_obj);

    nas_udf_group* udf_grp_p = get_switch().find_udf_group(_udf_group_id);
    if (udf_grp_p == NULL) {
        throw nas::base_exception {NAS_ACL_E_KEY_VAL, __PRETTY_FUNCTION__,
                                   std::string {"Could not find UDF Group for ID "} +
                                   std::to_string(_udf_group_id)};
    }
    ndi_udf_p->udf_group_id = udf_grp_p->get_ndi_obj_id(npu_id);
    nas_udf_match* udf_match_p = get_switch().find_udf_match(_udf_match_id);
    if (udf_match_p == NULL) {
        throw nas::base_exception {NAS_ACL_E_KEY_VAL, __PRETTY_FUNCTION__,
                                   std::string {"Could not find UDF Match for ID "} +
                                   std::to_string(_udf_group_id)};
    }
    ndi_udf_p->udf_match_id = udf_match_p->get_ndi_obj_id(npu_id);
    ndi_obj_id_t ndi_udf_id = 0;
    t_std_error rc = ndi_udf_create(npu_id, ndi_udf_p, &ndi_udf_id);
    if (rc != STD_ERR_OK) {
        throw nas::base_exception {rc, __PRETTY_FUNCTION__,
                        std::string {"NDI Fail: UDF Object Create Failed for NPU "}
                        + std::to_string(npu_id)};
    }

    _ndi_obj_ids[npu_id] = ndi_udf_id;

    return true;
}

bool nas_udf::push_delete_obj_to_npu(npu_id_t npu_id)
{
    t_std_error rc;

    rc = ndi_udf_delete(npu_id, _ndi_obj_ids.at (npu_id));
    if (rc != STD_ERR_OK) {
        throw nas::base_exception {rc, __PRETTY_FUNCTION__,
                                  std::string {"NDI Fail: UDF Match "}
                                  +    std::to_string (udf_id()) +
                                  std::string {" Delete Failed for NPU "}
                                  +    std::to_string (npu_id)};
    }

    _ndi_obj_ids.erase (npu_id);
    return true;
}

bool nas_udf::is_leaf_attr(nas_attr_id_t attr_id)
{
    if (attr_id == BASE_UDF_UDF_OBJ_HASH_MASK) {
        return true;
    }

    return false;
}

bool nas_udf::push_leaf_attr_to_npu(nas_attr_id_t attr_id, npu_id_t npu_id)
{
    if (attr_id != BASE_UDF_UDF_OBJ_HASH_MASK) {
        return false;
    }
    t_std_error rc = ndi_udf_set_hash_mask(npu_id, _ndi_obj_ids.at(npu_id),
                                           _hash_mask.data(),
                                           _hash_mask.size());
    if (rc != STD_ERR_OK) {
        throw nas::base_exception {rc, __PRETTY_FUNCTION__,
                                   std::string {"NDI Fail: UDF "} +
                                   std::to_string(udf_id()) +
                                   std::string {" Hash Mask set failed for NPU "} +
                                   std::to_string(npu_id)};
    }

    return true;
}
