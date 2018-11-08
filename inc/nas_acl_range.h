/*
 * Copyright (c) 2017 Dell Inc.
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
 * \file   nas_acl_range.h
 * \brief  NAS ACL Range object
 * \date   05-2017
 */

#ifndef _NAS_ACL_RANGE_H_
#define _NAS_ACL_RANGE_H_

#include "dell-base-acl.h"
#include "nas_ndi_obj_id_table.h"
#include "nas_base_obj.h"
#include "nas_ndi_acl.h"

class nas_acl_switch;

/**
* @class NAS ACL Range
* @brief ACL Range class derived from Base Object
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

class nas_acl_range final : public nas::base_obj_t
{
public:
    nas_acl_range(nas_acl_switch* switch_p);

    nas_acl_switch& get_switch() const noexcept;
    nas_obj_id_t range_id() const noexcept {return _range_id;}
    BASE_ACL_RANGE_TYPE_t type() const noexcept {return _type;}
    uint_t limit_min() const noexcept {return _limit_min;}
    uint_t limit_max() const noexcept {return _limit_max;}

    ndi_obj_id_t get_ndi_obj_id(npu_id_t npu_id) const;

    // Modifiers
    void set_range_id(nas_obj_id_t id);
    void set_type(uint_t type);
    void set_limit_min(uint_t limit_min);
    void set_limit_max(uint_t limit_max);
    void inc_acl_ref_count() {_acl_ref_cnt ++;}
    void dec_acl_ref_count() {if (_acl_ref_cnt > 0) _acl_ref_cnt --;}
    bool is_acl_ref() const noexcept {return _acl_ref_cnt > 0;}

    void commit_create(bool rolling_back) override;
    void commit_delete(bool rolling_back) override;

    const char* name() const override {return "ACL range";}
    e_event_log_types_enums ev_log_mod_id() const override
    {return ev_log_t_ACL;}
    const char* ev_log_mod_name() const override {return "NAS-ACL";}

    void *alloc_fill_ndi_obj(nas::mem_alloc_helper_t& m) override;
    bool push_create_obj_to_npu(npu_id_t npu_id, void* ndi_obj) override;
    bool push_delete_obj_to_npu(npu_id_t npu_id) override;
    bool push_leaf_attr_to_npu(nas_attr_id_t attr_id, npu_id_t npu_id) override;

private:
    nas_obj_id_t _range_id = 0;

    // Create-only attributes
    BASE_ACL_RANGE_TYPE_t _type = BASE_ACL_RANGE_TYPE_PACKET_LENGTH;
    uint_t _limit_min = 0;
    uint_t _limit_max = 0;

    // Read-write attributes
    size_t _acl_ref_cnt = 0;

    // List of mapped NDI IDs one for each NPU
    // managed by this NAS component
    nas::ndi_obj_id_table_t   _ndi_obj_ids;
};

inline void nas_acl_range::set_range_id(nas_obj_id_t id)
{
    _range_id = id;
}

#endif
