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
 * \file   nas_acl_table.cpp
 * \brief  NAS ACL Table Object
 * \date   02-2015
 */

#include "nas_acl_table.h"
#include "nas_acl_switch.h"
#include "nas_acl_filter.h"
#include "nas_ndi_acl.h"
#include "nas_acl_log.h"
#include <inttypes.h>

nas_acl_table::nas_acl_table (nas_acl_switch* switch_p)
           : nas::base_obj_t (switch_p)
{
}

nas_acl_switch& nas_acl_table::get_switch() const noexcept
{
    return static_cast<nas_acl_switch&>
        (nas::base_obj_t::get_switch());
}

bool nas_acl_table::is_filter_allowed (BASE_ACL_MATCH_TYPE_t filter_id) const noexcept
{
    return (_allowed_filters.find(filter_id) != _allowed_filters.end());
}

static inline void _validate_table_npu_change (nas_acl_table& table)
{
    const auto tbl_id = table.table_id();

    if (table.is_created_in_ndi () &&
        !table.get_switch().entry_list(tbl_id).empty())
    {
        throw nas::base_exception {NAS_ACL_E_CREATE_ONLY,
                                   __PRETTY_FUNCTION__,
                                   "Cannot modify NPU list when table has entries"};
    }
}

// Override all base class routines that handle NPU change request
// to disallow change when table has entries
void nas_acl_table::add_npu (npu_id_t npu_id, bool reset)
{
    _validate_table_npu_change (*this);
    nas::base_obj_t::add_npu (npu_id, reset);
}
void nas_acl_table::reset_npus ()
{
    _validate_table_npu_change (*this);
    nas::base_obj_t::reset_npus ();
}

void nas_acl_table::commit_create (bool rolling_back)
{
    if (!is_attr_dirty (BASE_ACL_TABLE_STAGE)) {
        throw nas::base_exception {NAS_ACL_E_CREATE_ONLY, __PRETTY_FUNCTION__,
            "Mandatory attribute Stage not present"};
    }

    if (!is_attr_dirty (BASE_ACL_TABLE_ALLOWED_MATCH_FIELDS)) {
        throw nas::base_exception {NAS_ACL_E_CREATE_ONLY, __PRETTY_FUNCTION__,
            "Mandatory attribute Allowed Match Fields not present"};
    }

    nas::base_obj_t::commit_create(rolling_back);

    if (is_attr_dirty(BASE_ACL_TABLE_UDF_GROUP_LIST)) {
        for (auto grp_id: _udf_group_list) {
            nas_udf_group* grp_p = get_switch().find_udf_group(grp_id);
            if (grp_p != nullptr) {
                grp_p->inc_acl_ref_count();
            }
        }
    }
}

void nas_acl_table::commit_delete (bool rolling_back)
{
    if (get_switch().entry_list(table_id()).size() != 0)
    {
        throw nas::base_exception {NAS_ACL_E_INCONSISTENT,
                                   __PRETTY_FUNCTION__,
                                   "Cannot delete table when it has entries"};
    }

    if (get_switch().counter_list(table_id()).size() != 0)
    {
        throw nas::base_exception {NAS_ACL_E_INCONSISTENT,
                                   __PRETTY_FUNCTION__,
                                   "Cannot delete table when it has counters"};
    }

    nas::base_obj_t::commit_delete(rolling_back);

    if (_udf_group_list.size() > 0) {
        for (auto grp_id: _udf_group_list) {
            nas_udf_group* grp_p = get_switch().find_udf_group(grp_id);
            if (grp_p != nullptr) {
                grp_p->dec_acl_ref_count();
            }
        }
    }
}

void nas_acl_table::set_priority (uint_t p)
{
    if (is_created_in_ndi()) {
        // Create-Only attribute
        throw nas::base_exception {NAS_ACL_E_CREATE_ONLY, __PRETTY_FUNCTION__,
                                "Cannot modify Priority for Table"};
    }

    if (p != _priority) {
        _priority = p;
        mark_attr_dirty (BASE_ACL_TABLE_PRIORITY);
    }
}

void nas_acl_table::set_table_size (uint_t size)
{
    if (is_created_in_ndi()) {
        // Create-Only attribute
        throw nas::base_exception {NAS_ACL_E_CREATE_ONLY, __PRETTY_FUNCTION__,
                                "Cannot modify Size for Table"};
    }

    if (size != _size) {
        _size = size;
        mark_attr_dirty (BASE_ACL_TABLE_SIZE);
    }
}


void nas_acl_table::set_stage (uint_t stage)
{
    if (is_created_in_ndi()) {
        // Create-Only attribute
        throw nas::base_exception {NAS_ACL_E_CREATE_ONLY, __PRETTY_FUNCTION__,
                                "Cannot modify Stage for Table"};
    }

    _stage = static_cast<BASE_ACL_STAGE_t> (stage);
    switch (_stage) {
        case BASE_ACL_STAGE_INGRESS:
        case BASE_ACL_STAGE_EGRESS:
            break;
        default:
            throw nas::base_exception {NAS_ACL_E_ATTR_VAL, __PRETTY_FUNCTION__,
                                     "Bad value for Stage"};
    }

    mark_attr_dirty (BASE_ACL_TABLE_STAGE);
}

void nas_acl_table::set_allowed_filter (uint_t filter_id)
{
    if (is_created_in_ndi()) {
        // Create-Only attribute
        throw nas::base_exception {NAS_ACL_E_CREATE_ONLY, __PRETTY_FUNCTION__,
                                "Cannot modify Filter-Set for Table"};
    }

    BASE_ACL_MATCH_TYPE_t f = static_cast <BASE_ACL_MATCH_TYPE_t> (filter_id);

    if (!nas_acl_filter_t::is_type_valid (f)) {
        throw nas::base_exception {NAS_ACL_E_ATTR_VAL, __PRETTY_FUNCTION__,
            std::string {"Unknown Table Match Field type "}
            + std::to_string (f)};
    }

    if (!is_attr_dirty (BASE_ACL_TABLE_ALLOWED_MATCH_FIELDS)) {
        mark_attr_dirty (BASE_ACL_TABLE_ALLOWED_MATCH_FIELDS);
        _allowed_filters.clear ();
    }

    _allowed_filters.insert(f);
}

void nas_acl_table::allowed_filters_c_cpy (size_t filter_count,
                                           BASE_ACL_MATCH_TYPE_t* filter_list) const noexcept
{
    size_t count = 0;

    for (auto filter: _allowed_filters) {
        filter_list[count] = filter;
        count++;
    }
    STD_ASSERT (count <= filter_count);
}

bool nas_acl_table::is_udf_group_in_list(nas_obj_id_t udf_grp_id) const noexcept
{
    for (auto id: _udf_group_list) {
        if (id == udf_grp_id) {
            return true;
        }
    }

    return false;
}

void nas_acl_table::set_udf_group_id(nas_obj_id_t udf_grp_id)
{
    if (is_created_in_ndi()) {
        // Create-Only attribute
        throw nas::base_exception {NAS_ACL_E_CREATE_ONLY, __PRETTY_FUNCTION__,
                                   "Cannot modify UDF Group list for Table"};
    }

    if (!is_attr_dirty(BASE_ACL_TABLE_UDF_GROUP_LIST)) {
        mark_attr_dirty(BASE_ACL_TABLE_UDF_GROUP_LIST);
        _udf_group_list.clear();
    }

    if (!is_udf_group_in_list(udf_grp_id)) {
        _udf_group_list.push_back(udf_grp_id);
    }
}

void* nas_acl_table::alloc_fill_ndi_obj (nas::mem_alloc_helper_t& mem_trakr)
{
    ndi_acl_table_t* ndi_tbl_p = mem_trakr.alloc<ndi_acl_table_t> (1);

    ndi_tbl_p->filter_count = allowed_filters_count ();

    ndi_tbl_p->filter_list = mem_trakr.alloc<BASE_ACL_MATCH_TYPE_t> (ndi_tbl_p->filter_count);

    ndi_tbl_p->stage = stage();
    ndi_tbl_p->priority = priority();
    ndi_tbl_p->size = table_size();

    allowed_filters_c_cpy (ndi_tbl_p->filter_count, ndi_tbl_p->filter_list);

    return ndi_tbl_p;
}

bool nas_acl_table::push_create_obj_to_npu (npu_id_t npu_id,
                                            void* ndi_obj)
{
    ndi_obj_id_t ndi_tbl_id;
    t_std_error rc;

    auto ndi_tbl_p = static_cast<ndi_acl_table_t*> (ndi_obj);

    std::vector<ndi_obj_id_t> npu_grp_id_list;
    if (_udf_group_list.size() > 0) {
        ndi_tbl_p->udf_grp_count = _udf_group_list.size();
        for (auto grp_id: _udf_group_list) {
            nas_udf_group* udf_grp_p = get_switch().find_udf_group(grp_id);
            if (udf_grp_p == nullptr) {
                throw nas::base_exception {NAS_ACL_E_ATTR_VAL, __PRETTY_FUNCTION__,
                                std::string{"Invalid UDF Group ID "} +
                                std::to_string(grp_id)};
            }
            ndi_obj_id_t npu_grp_id = udf_grp_p->get_ndi_obj_id(npu_id);
            npu_grp_id_list.push_back(npu_grp_id);
        }
        ndi_tbl_p->udf_grp_id_list = npu_grp_id_list.data();
    }

    if ((rc = ndi_acl_table_create (npu_id, ndi_tbl_p, &ndi_tbl_id))
            != STD_ERR_OK)
    {
        throw nas::base_exception {rc, __PRETTY_FUNCTION__,
                       std::string {"NDI Fail: Table Create Failed for NPU "}
                       + std::to_string (npu_id)};
    }
    // Cache the new Table ID generated by NDI
    _ndi_obj_ids[npu_id] = ndi_tbl_id;

    NAS_ACL_LOG_DETAIL ("Switch %d: Created ACL table in NPU %d; NDI ID 0x%" PRIx64,
                        get_switch().id(), npu_id, ndi_tbl_id);

    return true;
}

ndi_obj_id_t  nas_acl_table::get_ndi_obj_id (npu_id_t  npu_id) const
{
    try {
        return _ndi_obj_ids.at(npu_id);
    } catch (...) {
        throw nas::base_exception {NAS_ACL_E_FAIL, __PRETTY_FUNCTION__,
                       std::string {"Cannot find NDI ID for Table in NPU "}
                       + std::to_string (npu_id)};
    }
}

bool nas_acl_table::push_delete_obj_to_npu (npu_id_t npu_id)
{
    t_std_error rc;

    if ((rc = ndi_acl_table_delete (npu_id, _ndi_obj_ids.at (npu_id)))
        != STD_ERR_OK)
    {
        throw nas::base_exception {rc, __PRETTY_FUNCTION__,
                                  std::string {"NDI Fail: Table "}
                                  +    std::to_string (table_id()) +
                                  std::string {" Delete Failed for NPU "}
                                  +    std::to_string (npu_id)};
    }

    NAS_ACL_LOG_DETAIL ("Switch %d: Deleted ACL table %ld in NPU %d NDI-ID 0x%" PRIx64,
                        get_switch().id(), table_id(), npu_id, _ndi_obj_ids.at (npu_id));

    _ndi_obj_ids.erase (npu_id);

    return true;
}

bool nas_acl_table::is_leaf_attr (nas_attr_id_t attr_id)
{
    static const std::unordered_map <BASE_ACL_TABLE_t,
                                     bool,
                                     std::hash<int>>
        _leaf_attr_map =
    {
        // Only table priority can be modified
        {BASE_ACL_TABLE_ALLOWED_MATCH_FIELDS, false},
        {BASE_ACL_TABLE_STAGE,                true},
        {BASE_ACL_TABLE_PRIORITY,             true},
        //The NPU ID list attribute is handled by the base object itself.
    };

    return (_leaf_attr_map.at(static_cast<BASE_ACL_TABLE_t>(attr_id)));
}

bool nas_acl_table::push_leaf_attr_to_npu (nas_attr_id_t attr_id,
                                           npu_id_t npu_id)
{
    t_std_error rc = STD_ERR_OK;

    switch (attr_id)
    {
        case BASE_ACL_TABLE_PRIORITY:
            if ((rc = ndi_acl_table_set_priority (npu_id, _ndi_obj_ids.at(npu_id),
                                                    priority()))
                != STD_ERR_OK)
            {
                throw nas::base_exception {rc, __PRETTY_FUNCTION__,
                                          std::string {"NDI Fail: Table "}
                                         + std::to_string (table_id())
                                         + std::string {" Priority Set Failed for NPU "}
                                         + std::to_string (npu_id)};
            }
            NAS_ACL_LOG_DETAIL ("Switch %d: Modified ACL table %ld Priority in NPU %d",
                                get_switch().id(), table_id(), npu_id);
            break;
        default:
            STD_ASSERT (0);
    }

    return true;
}

