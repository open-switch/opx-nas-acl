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
 * \file   nas_udf_group.h
 * \brief  NAS UDF Group object
 * \date   10-2016
 */

#ifndef _NAS_UDF_GROUP_H_
#define _NAS_UDF_GROUP_H_

#include "dell-base-udf.h"
#include "nas_ndi_obj_id_table.h"
#include "nas_base_obj.h"
#include "nas_ndi_udf.h"
#include <set>

class nas_acl_switch;

/**
* @class NAS UDF Group
* @brief UDF Group class derived from Base Object
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

class nas_udf_group final : public nas::base_obj_t
{
public:
    typedef std::set<nas_obj_id_t> udf_set_t;

    nas_udf_group(nas_acl_switch* switch_p);

    nas_acl_switch& get_switch() const noexcept;
    nas_obj_id_t group_id() const noexcept {return _group_id;}
    BASE_UDF_UDF_GROUP_TYPE_t type() const noexcept {return _type;}
    size_t length() const noexcept {return _length;}
    const udf_set_t& udf_ids() const noexcept {return _udf_ids;}

    ndi_obj_id_t get_ndi_obj_id(npu_id_t npu_id) const;

    // Modifiers
    void set_group_id(nas_obj_id_t id);
    void set_type(uint_t type);
    void set_length(uint8_t length);
    void add_udf_id(nas_obj_id_t udf_id);
    void del_udf_id(nas_obj_id_t udf_id);
    bool check_udf_id(nas_obj_id_t udf_id) const noexcept;
    size_t get_udf_id_count() const noexcept;
    void inc_acl_ref_count() {_acl_ref_cnt ++;}
    void dec_acl_ref_count() {if (_acl_ref_cnt > 0) _acl_ref_cnt --;}
    bool is_acl_ref() const noexcept {return _acl_ref_cnt > 0;}

    void commit_create(bool rolling_back) override;
    void commit_delete(bool rolling_back) override;

    const char* name() const override {return "UDF group";}
    e_event_log_types_enums ev_log_mod_id() const override
    {return ev_log_t_ACL;}
    const char* ev_log_mod_name() const override {return "NAS-UDF";}

    void *alloc_fill_ndi_obj(nas::mem_alloc_helper_t& m) override;
    bool push_create_obj_to_npu(npu_id_t npu_id, void* ndi_obj) override;
    bool push_delete_obj_to_npu(npu_id_t npu_id) override;
    bool push_leaf_attr_to_npu(nas_attr_id_t attr_id, npu_id_t npu_id) override;

private:
    nas_obj_id_t _group_id = 0;

    // Create-only attributes
    BASE_UDF_UDF_GROUP_TYPE_t _type = BASE_UDF_UDF_GROUP_TYPE_GENERIC;
    size_t _length = 0;

    // Read-write attributes
    udf_set_t _udf_ids;
    size_t _acl_ref_cnt = 0;

    // List of mapped NDI IDs one for each NPU
    // managed by this NAS component
    nas::ndi_obj_id_table_t   _ndi_obj_ids;
};

inline void nas_udf_group::set_group_id(nas_obj_id_t id)
{
    _group_id = id;
}

#endif
