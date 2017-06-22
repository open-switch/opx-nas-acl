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
 * \file   nas_udf_match.cpp
 * \brief  NAS UDF Match Object
 * \date   10-2016
 */

#include "nas_udf_match.h"
#include "nas_acl_switch.h"
#include "nas_ndi_udf.h"
#include "nas_acl_log.h"

nas_udf_match::nas_udf_match(nas_acl_switch* switch_p)
    : nas::base_obj_t(switch_p)
{
}

nas_acl_switch& nas_udf_match::get_switch() const noexcept
{
    return static_cast<nas_acl_switch&>(nas::base_obj_t::get_switch());
}

ndi_obj_id_t nas_udf_match::get_ndi_obj_id (npu_id_t npu_id) const
{
    try {
        return _ndi_obj_ids.at(npu_id);
    } catch (...) {
        throw nas::base_exception {NAS_ACL_E_FAIL, __PRETTY_FUNCTION__,
                       std::string {"Cannot find NDI ID for Match in NPU "}
                       + std::to_string (npu_id)};
    }
}

void nas_udf_match::set_priority(uint8_t prio)
{
    if (is_created_in_ndi()) {
        throw nas::base_exception {NAS_ACL_E_CREATE_ONLY, __PRETTY_FUNCTION__,
                                   "Cannot modify Priority for UDF Match"};
    }

    _priority = prio;

    mark_attr_dirty(BASE_UDF_UDF_MATCH_PRIORITY);
}

void nas_udf_match::set_type(uint_t type)
{
    if (is_created_in_ndi()) {
        throw nas::base_exception {NAS_ACL_E_CREATE_ONLY, __PRETTY_FUNCTION__,
                                   "Cannot modify Type for UDF Match"};
    }

    _type = static_cast<BASE_UDF_UDF_MATCH_TYPE_t>(type);
    if (_type != BASE_UDF_UDF_MATCH_TYPE_NON_TUNNEL &&
        _type != BASE_UDF_UDF_MATCH_TYPE_GRE_TUNNEL) {
        throw nas::base_exception {NAS_ACL_E_ATTR_VAL, __PRETTY_FUNCTION__,
                                   "Invalid Type value"};
    }

    mark_attr_dirty(BASE_UDF_UDF_MATCH_TYPE);
}

void nas_udf_match::set_ethertype(uint16_t type, uint16_t mask)
{
    if (is_created_in_ndi()) {
        throw nas::base_exception {NAS_ACL_E_CREATE_ONLY, __PRETTY_FUNCTION__,
                                   "Cannot modify Length for UDF Match"};
    }

    _l2_type = type;
    _l2_type_mask = mask;

    mark_attr_dirty(BASE_UDF_UDF_MATCH_NON_TUNNEL_VALUE_L2_TYPE);
    mark_attr_dirty(BASE_UDF_UDF_MATCH_NON_TUNNEL_VALUE_L2_TYPE_MASK);
}

void nas_udf_match::set_ip_protocol(uint8_t type, uint8_t mask)
{
    if (is_created_in_ndi()) {
        throw nas::base_exception {NAS_ACL_E_CREATE_ONLY, __PRETTY_FUNCTION__,
                                   "Cannot modify Length for UDF Match"};
    }

    _l3_type = type;
    _l3_type_mask = mask;

    mark_attr_dirty(BASE_UDF_UDF_MATCH_NON_TUNNEL_VALUE_L3_TYPE);
    mark_attr_dirty(BASE_UDF_UDF_MATCH_NON_TUNNEL_VALUE_L3_TYPE_MASK);
}

void nas_udf_match::set_gre_tunnel(uint_t inner_type, uint_t outer_type)
{
    if (is_created_in_ndi()) {
        throw nas::base_exception {NAS_ACL_E_CREATE_ONLY, __PRETTY_FUNCTION__,
                                   "Cannot modify Length for UDF Match"};
    }

    _inner_ip_type = static_cast<INET_IP_VERSION_t>(inner_type);
    _outer_ip_type = static_cast<INET_IP_VERSION_t>(outer_type);

    mark_attr_dirty(BASE_UDF_UDF_MATCH_GRE_TUNNEL_VALUE_INNER_TYPE);
    mark_attr_dirty(BASE_UDF_UDF_MATCH_GRE_TUNNEL_VALUE_OUTER_TYPE);
}

void nas_udf_match::add_udf_id(nas_obj_id_t udf_id)
{
    if (!is_created_in_ndi()) {
        throw nas::base_exception {NAS_ACL_E_FAIL, __PRETTY_FUNCTION__,
                                   "Cannot add UDF ID to non-created Match object"};
    }

    auto rc = _udf_ids.find(udf_id);
    if (rc != _udf_ids.end()) {
        throw nas::base_exception {NAS_ACL_E_FAIL, __PRETTY_FUNCTION__,
                                   "UDF ID was already added to Match object"};
    }

    _udf_ids.insert(udf_id);
}

void nas_udf_match::del_udf_id(nas_obj_id_t udf_id)
{
    if (!is_created_in_ndi()) {
        throw nas::base_exception {NAS_ACL_E_FAIL, __PRETTY_FUNCTION__,
                                   "Cannot delete UDF ID from non-created Match object"};
    }

    auto rc = _udf_ids.find(udf_id);
    if (rc == _udf_ids.end()) {
        throw nas::base_exception {NAS_ACL_E_FAIL, __PRETTY_FUNCTION__,
                                   "UDF ID has not been added to Match object"};
    }

    _udf_ids.erase(udf_id);
}

bool nas_udf_match::check_udf_id(nas_obj_id_t udf_id) const noexcept
{
    auto rc = _udf_ids.find(udf_id);
    return !(rc == _udf_ids.end());
}

size_t nas_udf_match::get_udf_id_count() const noexcept
{
    return _udf_ids.size();
}

void nas_udf_match::commit_create(bool rolling_back)
{
    if (!is_attr_dirty (BASE_UDF_UDF_MATCH_TYPE)) {
        throw nas::base_exception {NAS_ACL_E_CREATE_ONLY, __PRETTY_FUNCTION__,
            "Mandatory attribute Type not present"};
    }

    if (_type == BASE_UDF_UDF_MATCH_TYPE_GRE_TUNNEL) {
        if (!is_attr_dirty (BASE_UDF_UDF_MATCH_GRE_TUNNEL_VALUE_INNER_TYPE)) {
            throw nas::base_exception {NAS_ACL_E_CREATE_ONLY, __PRETTY_FUNCTION__,
                "Mandatory attribute Length not present"};
        }

        INET_IP_VERSION_t in_type = INET_IP_VERSION_UNKNOWN,
                          out_type = INET_IP_VERSION_UNKNOWN;
        gre_tunnel(in_type, out_type);

        if (in_type == INET_IP_VERSION_UNKNOWN) {
            throw nas::base_exception {NAS_ACL_E_INCONSISTENT, __PRETTY_FUNCTION__,
                "Mandatory attribute Inner tunnel type not present"};
        }

        if (in_type != INET_IP_VERSION_IPV4 && in_type != INET_IP_VERSION_IPV6) {
            throw nas::base_exception {NAS_ACL_E_INCONSISTENT, __PRETTY_FUNCTION__,
                "Invalid Innter tunnel type"};
        }

        if (out_type != INET_IP_VERSION_UNKNOWN &&
            out_type != INET_IP_VERSION_IPV4 && out_type != INET_IP_VERSION_IPV6) {
            throw nas::base_exception {NAS_ACL_E_INCONSISTENT, __PRETTY_FUNCTION__,
                "Invalid Outer tunnel type"};
        }
    }

    nas::base_obj_t::commit_create(rolling_back);
}

void nas_udf_match::commit_delete(bool rolling_back)
{
    if (get_udf_id_count() != 0)
    {
        throw nas::base_exception {NAS_ACL_E_INCONSISTENT,
                                   __PRETTY_FUNCTION__,
                                   "Cannot delete UDF Match when it has UDFs"};
    }

    nas::base_obj_t::commit_delete(rolling_back);
}

void* nas_udf_match::alloc_fill_ndi_obj(nas::mem_alloc_helper_t& mem_trakr)
{
    ndi_udf_match_t* ndi_match_p = mem_trakr.alloc<ndi_udf_match_t>(1);
    if (type() == BASE_UDF_UDF_MATCH_TYPE_NON_TUNNEL) {
        ndi_match_p->type = NAS_NDI_UDF_MATCH_NON_TUNNEL;
        ethertype(ndi_match_p->non_tunnel.l2_type, ndi_match_p->non_tunnel.l2_type_mask);
        ip_protocol(ndi_match_p->non_tunnel.l3_type, ndi_match_p->non_tunnel.l3_type_mask);
    } else {
        INET_IP_VERSION_t in_type = INET_IP_VERSION_UNKNOWN,
                          out_type = INET_IP_VERSION_UNKNOWN;
        gre_tunnel(in_type, out_type);
        if (in_type == INET_IP_VERSION_IPV4) {
            ndi_match_p->gre_tunnel.inner_ip_type = NAS_NDI_IP_TYPE_IPV4;
        } else {
            ndi_match_p->gre_tunnel.inner_ip_type = NAS_NDI_IP_TYPE_IPV6;
        }
        if (out_type != INET_IP_VERSION_UNKNOWN) {
            if (out_type == INET_IP_VERSION_IPV4) {
                ndi_match_p->gre_tunnel.outer_ip_type = NAS_NDI_IP_TYPE_IPV4;
            } else {
                ndi_match_p->gre_tunnel.outer_ip_type = NAS_NDI_IP_TYPE_IPV6;
            }
        }
    }

    return ndi_match_p;
}

bool nas_udf_match::push_create_obj_to_npu(npu_id_t npu_id, void* ndi_obj)
{
    ndi_obj_id_t ndi_match_id = 0;
    t_std_error rc;

    auto ndi_match_p = static_cast<ndi_udf_match_t*>(ndi_obj);

    rc = ndi_udf_match_create(npu_id, ndi_match_p, &ndi_match_id);
    if (rc != STD_ERR_OK) {
        throw nas::base_exception {rc, __PRETTY_FUNCTION__,
                        std::string {"NDI Fail: UDF Match Create Failed for NPU "}
                        + std::to_string(npu_id)};
    }

    _ndi_obj_ids[npu_id] = ndi_match_id;

    return true;
}

bool nas_udf_match::push_delete_obj_to_npu(npu_id_t npu_id)
{
    t_std_error rc;

    rc = ndi_udf_match_delete(npu_id, _ndi_obj_ids.at (npu_id));
    if (rc != STD_ERR_OK) {
        throw nas::base_exception {rc, __PRETTY_FUNCTION__,
                                  std::string {"NDI Fail: UDF Match "}
                                  +    std::to_string (match_id()) +
                                  std::string {" Delete Failed for NPU "}
                                  +    std::to_string (npu_id)};
    }

    _ndi_obj_ids.erase (npu_id);
    return true;
}

bool nas_udf_match::push_leaf_attr_to_npu(nas_attr_id_t attr_id, npu_id_t npu_id)
{
    return true;
}
