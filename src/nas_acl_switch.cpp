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
 * \file   nas_acl_switch.cpp
 * \brief  NAS ACL Switch Object
 * \date   02-2015
 */

#include "nas_base_utils.h"
#include "nas_acl_switch.h"
#include "event_log.h"
#include <string>

nas_acl_table& nas_acl_switch::get_table (nas_obj_id_t tbl_id)
{
    try {
        return _tables.at (tbl_id);
    } catch (std::out_of_range& ) {
        throw nas::base_exception {NAS_ACL_E_KEY_VAL, __PRETTY_FUNCTION__,
                              std::string {"Invalid Table ID "} +
                                  std::to_string(tbl_id)};
    }
}

nas_acl_table* nas_acl_switch::find_table (nas_obj_id_t tbl_id) noexcept
{
    auto it_tbl = _tables.find (tbl_id);
    if (it_tbl == _tables.end ()) return nullptr;

    return &it_tbl->second;
}

const nas_acl_switch::entry_list_t&
nas_acl_switch::entry_list (nas_obj_id_t table_id) const
{
    try {
        return _table_containers.at(table_id)._acl_entries;
    } catch (std::out_of_range& ) {
        throw nas::base_exception {NAS_ACL_E_KEY_VAL, __PRETTY_FUNCTION__,
                              std::string {"Invalid Table ID "} +
                                  std::to_string(table_id)};
    }
}

const nas_acl_switch::counter_list_t&
nas_acl_switch::counter_list (nas_obj_id_t table_id) const
{
    try {
        return _table_containers.at(table_id)._acl_counters;
    } catch (std::out_of_range& ) {
        throw nas::base_exception {NAS_ACL_E_KEY_VAL, __PRETTY_FUNCTION__,
                              std::string {"Invalid Table ID "} +
                                  std::to_string(table_id)};
    }
}

nas_acl_entry& nas_acl_switch::get_entry (nas_obj_id_t tbl_id,
                                          nas_obj_id_t entry_id)
{
    try {
        return _table_containers.at (tbl_id)._acl_entries.at (entry_id);
    } catch (std::out_of_range& ) {
        throw nas::base_exception {NAS_ACL_E_KEY_VAL, __PRETTY_FUNCTION__,
                              std::string {"Invalid Table ID "} +
                                  std::to_string(tbl_id) +
                              std::string {" or Entry ID "} +
                                  std::to_string(entry_id)};
    }
}

nas_acl_entry* nas_acl_switch::find_entry (nas_obj_id_t tbl_id,
                                           nas_obj_id_t entry_id) noexcept
{
    auto it_tbl = _table_containers.find (tbl_id);
    if (it_tbl == _table_containers.end ()) return nullptr;

    auto& entry_list = it_tbl->second._acl_entries;
    auto it_entry = entry_list.find (entry_id);
    if (it_entry == entry_list.end()) return nullptr;

    return &it_entry->second;
}

nas_acl_counter_t& nas_acl_switch::get_counter (nas_obj_id_t tbl_id,
                                                nas_obj_id_t counter_id)
{
    auto it_tbl = _table_containers.find (tbl_id);
    if (it_tbl == _table_containers.end ()) {
        throw nas::base_exception {NAS_ACL_E_KEY_VAL, __PRETTY_FUNCTION__,
                              std::string {"Invalid Table ID "} +
                                  std::to_string(tbl_id)};
    }
    auto& counter_list = it_tbl->second._acl_counters;
    auto it_cntr = counter_list.find (counter_id);
    if (it_cntr == counter_list.end()) {
        throw nas::base_exception {NAS_ACL_E_KEY_VAL, __PRETTY_FUNCTION__,
                              std::string {"Invalid Counter ID "} +
                                  std::to_string(counter_id)};
    }

    return it_cntr->second;
}

nas_acl_counter_t* nas_acl_switch::find_counter (nas_obj_id_t tbl_id,
                                                nas_obj_id_t counter_id) noexcept
{
    auto it_tbl = _table_containers.find (tbl_id);
    if (it_tbl == _table_containers.end ()) return nullptr;

    auto& counter_list = it_tbl->second._acl_counters;
    auto it_cntr = counter_list.find (counter_id);
    if (it_cntr == counter_list.end()) return nullptr;

    return &it_cntr->second;
}

nas_acl_table& nas_acl_switch::save_table (nas_acl_table&& t) noexcept
{
    /* Save is declared noexcept since it cannot fail.
     * This update is already committed to NDI and we are beyond
     * the point of roll-back.
     * Fatal exceptions like memory allocation failure are not
     * considered above - such fatal exceptions will terminate NAS.
     */
    auto it = _tables.find (t.table_id());

    if (it == _tables.end()) {
        ///// Adding a New table to list /////
        // Allocate a new container for the entries in the table
        _table_containers.insert (std::make_pair (t.table_id(),
                                                  acl_table_container_t {}));

        // Insert new Table into cache,
        // by moving contents from the argument passed in.
        // Return newly inserted Table
        auto p = _tables.insert (std::make_pair (t.table_id(), std::move (t)));
        return (p.first->second);
    }

    // Update existing table if present
    return (it->second = std::move(t));
}

void nas_acl_switch::remove_table (nas_obj_id_t table_id) noexcept
{
    // Remove all entries in this table
    _table_containers.erase(table_id);
    // Remove the table itself
    _tables.erase (table_id);
    _tableid_gen.release_id (table_id);
}

void nas_acl_switch::remove_entry_from_table (nas_obj_id_t table_id,
                                              nas_obj_id_t entry_id) noexcept
{
    // This is an internal function - Table ID cannot be invalid
    auto& container = _table_containers.at(table_id);
    auto& e_del = container._acl_entries.at (entry_id);
    auto new_counter_p = e_del.get_counter ();
    if (new_counter_p != nullptr) {
        new_counter_p->del_ref (e_del.entry_id());
    }
    container._acl_entries.erase (entry_id);
    container._entry_id_gen.release_id (entry_id);
}

nas_obj_id_t nas_acl_switch::alloc_entry_id_in_table (nas_obj_id_t table_id)
{
    // This is an internal function - Table ID cannot be invalid
    return _table_containers.at (table_id)._entry_id_gen.alloc_id ();
}

bool nas_acl_switch::reserve_table_id (nas_obj_id_t id)
{
    if (id > NAS_ACL_TABLE_ID_MAX) {
        throw nas::base_exception {NAS_ACL_E_FAIL, __PRETTY_FUNCTION__,
        std::string {"Invalid Table ID "} + std::to_string (id)};
    }
    return _tableid_gen.reserve_id (id);
}
bool nas_acl_switch::reserve_entry_id_in_table (nas_obj_id_t table_id,
                                                nas_obj_id_t id)
{
    // This is an internal function - Table ID cannot be invalid
    if (id > NAS_ACL_ENTRY_ID_MAX) {
        throw nas::base_exception {NAS_ACL_E_FAIL, __PRETTY_FUNCTION__,
        std::string {"Invalid Entry ID "} + std::to_string (id)};
    }
    return _table_containers.at (table_id)._entry_id_gen.reserve_id (id);
}

void nas_acl_switch::release_entry_id_in_table (nas_obj_id_t table_id,
                                                nas_obj_id_t entry_id) noexcept
{
    _table_containers.at (table_id)._entry_id_gen.release_id (entry_id);
}

nas_acl_entry& nas_acl_switch::save_entry (nas_acl_entry&& e_temp) noexcept
{
    /* Save is declared noexcept since it cannot fail.
     * This update is already committed to NDI and we are beyond
     * the point of roll-back.
     * Fatal exceptions like memory allocation failure are not
     * considered above - such fatal exceptions will terminate NAS.
     */
    nas_obj_id_t  table_id = e_temp.table_id();
    auto& entry_list = _table_containers.at (table_id)._acl_entries;

    auto it = entry_list.find (e_temp.entry_id());
    if (it == entry_list.end()) {
        ///// Adding a New Entry to list /////
        // Insert new Entry into cache,
        // by moving contents from the argument passed in.
        // Return newly inserted Entry
        auto p = entry_list.insert (std::make_pair (e_temp.entry_id(), std::move(e_temp)));
        auto& new_entry = p.first->second;
        auto new_counter_p = new_entry.get_counter ();
        if (new_counter_p != nullptr) {
            new_counter_p->add_ref (new_entry.entry_id());
        }
        return (new_entry);
    }

    auto& e_orig = it->second;
    if (e_orig.counter_id() != e_temp.counter_id()) {
        auto old_counter_p = e_orig.get_counter();
        if (old_counter_p != NULL) {
            old_counter_p->del_ref (e_orig.entry_id());
        }
        auto new_counter_p = e_temp.get_counter ();
        if (new_counter_p != NULL) {
            new_counter_p->add_ref (e_temp.entry_id());
        }
    }
    return (e_orig = std::move(e_temp));
}

void nas_acl_switch::remove_counter_from_table (nas_obj_id_t table_id,
                                              nas_obj_id_t counter_id) noexcept
{
    // This is an internal function - Table ID cannot be invalid
    auto& container = _table_containers.at(table_id);
    container._acl_counters.erase (counter_id);
    container._counter_id_gen.release_id (counter_id);
}

nas_obj_id_t nas_acl_switch::alloc_counter_id_in_table (nas_obj_id_t table_id)
{
    // This is an internal function - Table ID cannot be invalid
    return _table_containers.at (table_id)._counter_id_gen.alloc_id ();
}

bool nas_acl_switch::reserve_counter_id_in_table (nas_obj_id_t table_id,
                                                  nas_obj_id_t id)
{
    if (id > NAS_ACL_ENTRY_ID_MAX) {
        throw nas::base_exception {NAS_ACL_E_FAIL, __PRETTY_FUNCTION__,
        std::string {"Invalid Counter ID "} + std::to_string (id)};
    }
    // This is an internal function - Table ID cannot be invalid
    return _table_containers.at (table_id)._counter_id_gen.reserve_id (id);
}

void nas_acl_switch::release_counter_id_in_table (nas_obj_id_t table_id,
                                                 nas_obj_id_t counter_id) noexcept
{
    _table_containers.at (table_id)._counter_id_gen.release_id (counter_id);
}

nas_acl_counter_t&  nas_acl_switch::save_counter (nas_acl_counter_t&& tmp_cntr) noexcept
{
    /* Save is declared noexcept since it cannot fail.
     * This update is already committed to NDI and we are beyond
     * the point of roll-back.
     * Fatal exceptions like memory allocation failure are not
     * considered above - such fatal exceptions will terminate NAS.
     */
    nas_obj_id_t  table_id = tmp_cntr.table_id();
    auto& counter_list = _table_containers.at (table_id)._acl_counters;

    auto it = counter_list.find (tmp_cntr.counter_id());
    if (it == counter_list.end()) {
        ///// Adding a New Entry to list /////
        // Insert new Entry into cache,
        // by moving contents from the argument passed in.
        // Return newly inserted Entry
        auto p = counter_list.insert (std::make_pair (tmp_cntr.counter_id(),
                                                      std::move(tmp_cntr)));

        return (p.first->second);
    }

    return (it->second = std::move(tmp_cntr));
}

nas_udf_group* nas_acl_switch::find_udf_group (nas_obj_id_t udf_grp_id) noexcept
{
    auto udf_grp = _udf_groups.find (udf_grp_id);
    if (udf_grp == _udf_groups.end ()) {
        return nullptr;
    }

    return &udf_grp->second;
}

nas_udf_match* nas_acl_switch::find_udf_match (nas_obj_id_t udf_match_id) noexcept
{
    auto udf_match = _udf_matches.find (udf_match_id);
    if (udf_match == _udf_matches.end ()) {
        return nullptr;
    }

    return &udf_match->second;
}

nas_udf* nas_acl_switch::find_udf (nas_obj_id_t udf_id) noexcept
{
    auto udf_itr = _udf_objs.find (udf_id);
    if (udf_itr == _udf_objs.end ()) {
        return nullptr;
    }

    return &udf_itr->second;
}

nas_udf_group& nas_acl_switch::save_udf_group(nas_udf_group&& udf_grp) noexcept
{
    auto it = _udf_groups.find(udf_grp.group_id());

    if (it == _udf_groups.end()) {
        auto p = _udf_groups.insert(std::make_pair(udf_grp.group_id(), std::move(udf_grp)));
        return (p.first->second);
    }

    // Update existing UDF group if present
    return (it->second = std::move(udf_grp));
}

void nas_acl_switch::remove_udf_group(nas_obj_id_t group_id) noexcept
{
    _udf_groups.erase(group_id);
}

nas_udf_match& nas_acl_switch::save_udf_match(nas_udf_match&& udf_match) noexcept
{
    auto it = _udf_matches.find(udf_match.match_id());

    if (it == _udf_matches.end()) {
        auto p = _udf_matches.insert(std::make_pair(udf_match.match_id(), std::move(udf_match)));
        return (p.first->second);
    }

    // Update existing UDF match if present
    return (it->second = std::move(udf_match));
}

void nas_acl_switch::remove_udf_match(nas_obj_id_t match_id) noexcept
{
    _udf_matches.erase(match_id);
}

nas_udf& nas_acl_switch::save_udf(nas_udf&& udf) noexcept
{
    auto it = _udf_objs.find(udf.udf_id());

    if (it == _udf_objs.end()) {
        auto p = _udf_objs.insert(std::make_pair(udf.udf_id(), std::move(udf)));
        return (p.first->second);
    }

    // Update existing UDF if present
    return (it->second = std::move(udf));
}

void nas_acl_switch::remove_udf(nas_obj_id_t udf_id) noexcept
{
    _udf_objs.erase(udf_id);
}
