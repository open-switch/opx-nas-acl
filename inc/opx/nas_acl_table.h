/*
 * Copyright (c) 2016 Dell Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may
 * not use this file except in compliance with the License. You may obtain
 * a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
 *
 * THIS CODE IS PROVIDED ON AN *AS IS* BASIS, WITHOUT WARRANTIES OR
 * CONDITIONS OF ANY KIND, EITHER EXPRESS OR IMPLIED, INCLUDING WITHOUT
 * LIMITATION ANY IMPLIED WARRANTIES OR CONDITIONS OF TITLE, FITNESS
 * FOR A PARTICULAR PURPOSE, MERCHANTABLITY OR NON-INFRINGEMENT.
 *
 * See the Apache Version 2.0 License for specific language governing
 * permissions and limitations under the License.
 */

/*!
 * \file   nas_acl_table.h
 * \brief  NAS ACL Table object
 * \date   02-2015
 */

#ifndef _NAS_ACL_TABLE_H_
#define _NAS_ACL_TABLE_H_

#include "dell-base-acl.h"
#include "nas_base_utils.h"
#include "nas_ndi_obj_id_table.h"
#include "nas_base_obj.h"
#include "nas_ndi_acl.h"
#include <set>

class nas_acl_switch;

/**
* @class NAS ACL Table
* @brief ACL Table class derived from Base Object
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

class nas_acl_table final : public nas::base_obj_t
{
    public:
        typedef std::set<BASE_ACL_MATCH_TYPE_t> filter_set_t;
        typedef std::vector<nas_obj_id_t> udf_group_list_t;

        ////// Constructor/Destructor /////
        nas_acl_table (nas_acl_switch* switch_p);

        /////// Accessors ////////
        nas_acl_switch&       get_switch() const noexcept;
        nas_obj_id_t          table_id() const noexcept {return _table_id;}
        ndi_acl_priority_t    priority() const noexcept {return _priority;}
        BASE_ACL_STAGE_t      stage() const noexcept {return _stage;}
        uint_t                table_size() const noexcept {return _size;}

        bool        is_filter_allowed (BASE_ACL_MATCH_TYPE_t filter_id) const noexcept;
        size_t      allowed_filters_count () const noexcept;
        const filter_set_t& allowed_filters () const noexcept {return _allowed_filters;}
                   // Copy filter-set to c style array
        void       allowed_filters_c_cpy (size_t filter_count,
                                          BASE_ACL_MATCH_TYPE_t* filter_list) const noexcept;
        bool         is_udf_group_in_list(nas_obj_id_t udf_grp_id) const noexcept;
        size_t       udf_group_list_count() const noexcept {return _udf_group_list.size();}
        const udf_group_list_t& udf_group_list() const noexcept {return _udf_group_list;}
        ndi_obj_id_t  get_ndi_obj_id (npu_id_t  npu_id) const;

        //////// Modifiers ////////
        void set_table_id (nas_obj_id_t id);
        void set_stage (uint_t stage);
        void set_table_size(uint_t size);
        void set_priority (ndi_acl_priority_t p);
        void set_allowed_filter (uint_t filter_id);
        void set_udf_group_id (nas_obj_id_t udf_grp_id);

        // Override all base class routines that handle NPU change request
        // to disallow change when table has entries
        void add_npu (npu_id_t npu_id, bool reset=true) override;
        void reset_npus () override;

        /// Overriding base object virtual functions
        void commit_create (bool rolling_back) override;
        void commit_delete (bool rolling_back) override;

        const char* name () const override {return "ACL Table";}
        e_event_log_types_enums ev_log_mod_id () const override
        {return ev_log_t_ACL;}
        const char* ev_log_mod_name () const override {return "NAS-ACL";}

        void* alloc_fill_ndi_obj (nas::mem_alloc_helper_t& m) override;
        bool push_create_obj_to_npu (npu_id_t npu_id, void* ndi_obj) override;

        bool push_delete_obj_to_npu (npu_id_t npu_id) override;

        bool is_leaf_attr (nas_attr_id_t attr_id) override;
        bool push_leaf_attr_to_npu (nas_attr_id_t attr_id,
                                    npu_id_t npu_id) override;

    private:
        nas_obj_id_t          _table_id = 0;

        // Create-only attributes
        BASE_ACL_STAGE_t   _stage = BASE_ACL_STAGE_INGRESS;
        filter_set_t       _allowed_filters;
        uint_t             _size = 0;
        udf_group_list_t   _udf_group_list;

        // Read-write attributes
        ndi_acl_priority_t    _priority = 0;

        // List of mapped NDI IDs one for each NPU
        // managed by this NAS component
        nas::ndi_obj_id_table_t   _ndi_obj_ids;
};

inline void nas_acl_table::set_table_id (nas_obj_id_t id)
{
    STD_ASSERT (_table_id == 0); // Something wrong .. Table already has a ID
    _table_id = id;
}

inline size_t nas_acl_table::allowed_filters_count () const noexcept
{
    return _allowed_filters.size();
}

#endif
