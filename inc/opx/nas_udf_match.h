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
 * \file   nas_udf_match.h
 * \brief  NAS UDF Match object
 * \date   10-2016
 */

#ifndef _NAS_UDF_MATCH_H_
#define _NAS_UDF_MATCH_H_

#include "dell-base-udf.h"
#include "ietf-inet-types.h"
#include "nas_ndi_obj_id_table.h"
#include "nas_base_obj.h"
#include "nas_ndi_udf.h"
#include <set>

class nas_acl_switch;

/**
* @class NAS UDF Match
* @brief UDF Match class derived from Base Object
*
* This Class and its methods are designed to be used from CPS request
* handler routines.
* Member functions of this class will throw the
* base_exception or the base_ndi_exception.
*
* Hence the creation, and all member access/calls to objects of this class
* should be wrapped in a try-catch block
*
*/

class nas_udf_match final : public nas::base_obj_t
{
public:
    nas_udf_match(nas_acl_switch* switch_p);

    nas_acl_switch& get_switch() const noexcept;
    nas_obj_id_t match_id() const noexcept {return _match_id;}
    uint8_t priority() const noexcept {return _priority;}
    BASE_UDF_UDF_MATCH_TYPE_t type() const noexcept {return _type;}
    void ethertype(uint16_t& type, uint16_t& mask) const noexcept
    {type = _l2_type; mask = _l2_type_mask;}
    void ip_protocol(uint8_t& type, uint8_t& mask) const noexcept
    {type = _l3_type; mask = _l3_type_mask;}
    void gre_tunnel(INET_IP_VERSION_t& inner, INET_IP_VERSION_t& outer)
        const noexcept
    {inner = _inner_ip_type; outer = _outer_ip_type;}

    ndi_obj_id_t get_ndi_obj_id(npu_id_t npu_id) const;

    // Modifiers
    void set_match_id(nas_obj_id_t id);
    void set_priority(uint8_t prio);
    void set_type(uint_t type);
    void set_ethertype(uint16_t type, uint16_t mask = 0xffff);
    void set_ip_protocol(uint8_t type, uint8_t mask = 0xf);
    void set_gre_tunnel(uint_t inner_type,
                        uint_t outer_type = INET_IP_VERSION_UNKNOWN);
    void add_udf_id(nas_obj_id_t udf_id);
    void del_udf_id(nas_obj_id_t udf_id);
    bool check_udf_id(nas_obj_id_t udf_id) const noexcept;
    size_t get_udf_id_count() const noexcept;

    void commit_create(bool rolling_back) override;
    void commit_delete(bool rolling_back) override;

    const char* name() const override {return "UDF match";}
    e_event_log_types_enums ev_log_mod_id() const override
    {return ev_log_t_ACL;}
    const char* ev_log_mod_name() const override {return "NAS-UDF";}

    void *alloc_fill_ndi_obj(nas::mem_alloc_helper_t& m) override;
    bool push_create_obj_to_npu(npu_id_t npu_id, void* ndi_obj) override;
    bool push_delete_obj_to_npu(npu_id_t npu_id) override;
    bool push_leaf_attr_to_npu(nas_attr_id_t attr_id, npu_id_t npu_id) override;

private:
    nas_obj_id_t _match_id = 0;

    // Create-only attributes
    BASE_UDF_UDF_MATCH_TYPE_t _type = BASE_UDF_UDF_MATCH_TYPE_NON_TUNNEL;
    uint8_t _priority = 0;
    uint16_t _l2_type = 0;
    uint16_t _l2_type_mask = 0;
    uint8_t _l3_type = 0;
    uint8_t _l3_type_mask = 0;
    INET_IP_VERSION_t _inner_ip_type = INET_IP_VERSION_UNKNOWN;
    INET_IP_VERSION_t _outer_ip_type = INET_IP_VERSION_UNKNOWN;

    // Read-write attributes
    std::set<nas_obj_id_t> _udf_ids;

    // List of mapped NDI IDs one for each NPU
    // managed by this NAS component
    nas::ndi_obj_id_table_t   _ndi_obj_ids;
};

inline void nas_udf_match::set_match_id(nas_obj_id_t id)
{
    _match_id = id;
}

#endif
