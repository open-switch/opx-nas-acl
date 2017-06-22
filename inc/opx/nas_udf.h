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
 * \file   nas_udf.h
 * \brief  NAS UDF object
 * \date   10-2016
 */

#ifndef _NAS_UDF_OBJ_H_
#define _NAS_UDF_OBJ_H_

#include "dell-base-udf.h"
#include "ietf-inet-types.h"
#include "nas_ndi_obj_id_table.h"
#include "nas_base_obj.h"
#include "nas_ndi_udf.h"
#include <set>

class nas_acl_switch;

/**
* @class NAS UDF
* @brief UDF class derived from Base Object
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

class nas_udf final : public nas::base_obj_t
{
public:
    nas_udf(nas_acl_switch* switch_p);

    nas_acl_switch& get_switch() const noexcept;
    nas_obj_id_t udf_id() const noexcept {return _udf_id;}
    nas_obj_id_t udf_group_id() const noexcept {return _udf_group_id;}
    nas_obj_id_t udf_match_id() const noexcept {return _udf_match_id;}
    BASE_UDF_UDF_BASE_TYPE_t base() const noexcept {return _base;}
    size_t offset() const noexcept {return _offset;}
    void hash_mask(uint8_t* byte_list, size_t& byte_cnt) const noexcept;

    ndi_obj_id_t get_ndi_obj_id(npu_id_t npu_id) const;

    // Modifiers
    void set_udf_id(nas_obj_id_t id);
    void set_udf_group_id(nas_obj_id_t id);
    void set_udf_match_id(nas_obj_id_t id);
    void set_base(uint_t base);
    void set_offset(size_t offset);
    void set_hash_mask(uint8_t* byte_list, size_t byte_cnt);

    void commit_create(bool rolling_back) override;

    const char* name() const override {return "UDF";}
    e_event_log_types_enums ev_log_mod_id() const override
    {return ev_log_t_ACL;}
    const char* ev_log_mod_name() const override {return "NAS-UDF";}

    void *alloc_fill_ndi_obj(nas::mem_alloc_helper_t& m) override;
    bool push_create_obj_to_npu(npu_id_t npu_id, void* ndi_obj) override;
    bool push_delete_obj_to_npu(npu_id_t npu_id) override;
    bool is_leaf_attr(nas_attr_id_t attr_id) override;
    bool push_leaf_attr_to_npu(nas_attr_id_t attr_id, npu_id_t npu_id) override;

private:
    nas_obj_id_t _udf_id = 0;

    // Create-only attributes
    nas_obj_id_t _udf_group_id = 0;
    nas_obj_id_t _udf_match_id = 0;
    BASE_UDF_UDF_BASE_TYPE_t _base = BASE_UDF_UDF_BASE_TYPE_L2;
    size_t _offset = 0;
    std::vector<uint8_t> _hash_mask;

    // List of mapped NDI IDs one for each NPU
    // managed by this NAS component
    nas::ndi_obj_id_table_t   _ndi_obj_ids;
};

inline void nas_udf::set_udf_id(nas_obj_id_t id)
{
    _udf_id = id;
}

inline void nas_udf::set_udf_match_id(nas_obj_id_t match_id)
{
    _udf_match_id = match_id;
    mark_attr_dirty(BASE_UDF_UDF_OBJ_MATCH_ID);
}

inline void nas_udf::set_udf_group_id(nas_obj_id_t group_id)
{
    _udf_group_id = group_id;
    mark_attr_dirty(BASE_UDF_UDF_OBJ_GROUP_ID);
}

#endif
