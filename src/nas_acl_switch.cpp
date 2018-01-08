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

nas_acl_table* nas_acl_switch::find_table_by_name (const char* tbl_name) noexcept
{
    for (auto& tbl_item: _tables) {
        const char* chk_name = tbl_item.second.table_name();
        if (chk_name != nullptr && strcmp(chk_name, tbl_name) == 0) {
            return &tbl_item.second;
        }
    }

    return nullptr;
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

nas_acl_entry* nas_acl_switch::find_entry_by_name (nas_obj_id_t tbl_id,
                                                   const char* entry_name) noexcept
{
    auto it_tbl = _table_containers.find (tbl_id);
    if (it_tbl == _table_containers.end ()) return nullptr;

    for (auto& ent_item: it_tbl->second._acl_entries) {
        const char* chk_name = ent_item.second.entry_name();
        if (chk_name != nullptr && strcmp(chk_name, entry_name) == 0) {
            return &ent_item.second;
        }
    }

    return nullptr;
}

void nas_acl_switch::delete_pbr_action_by_nh_obj (ndi_obj_id_t nh_obj_id) noexcept
{
    std::vector<nas_acl_entry *> entry_list;

    for (auto & pbr_entry_id: _cached_pbr_entries) {
        try {
            nas_acl_entry *acl_entry = find_entry(pbr_entry_id.tbl_id, pbr_entry_id.entry_id);

            if (acl_entry == nullptr) {
                continue;
            }

            nas_acl_action_t acl_entry_action =
                acl_entry->get_action(BASE_ACL_ACTION_TYPE_REDIRECT_IP_NEXTHOP);

            if (acl_entry_action.match_opaque_data_by_nexthop_id(nh_obj_id)) {
                // find a matching nh obj reference; collect the entry for deletion
                entry_list.push_back(acl_entry);
            }

        } catch (...) {
        }
    }

    for (auto entry: entry_list) {
        nas_acl_entry new_entry(*entry);

        new_entry.remove_action(BASE_ACL_ACTION_TYPE_REDIRECT_IP_NEXTHOP);

        new_entry.commit_modify(*entry, false);

        entry->get_table().get_switch().save_entry(std::move(new_entry));

    }

    return;
}

void nas_acl_switch::add_pbr_entry_to_cache(nas_obj_id_t tbl_id, nas_obj_id_t entry_id)
{
    bool found = false;

    for( auto iter = _cached_pbr_entries.begin();
            iter != _cached_pbr_entries.end();
            ++iter )
    {
        if( iter->tbl_id == tbl_id &&
            iter->entry_id == entry_id)
        {
            found = true;
            break;
        }
    }

    if (!found) {
        pbr_entry_id_t pbr_entry;
        pbr_entry.tbl_id = tbl_id;
        pbr_entry.entry_id = entry_id;
        _cached_pbr_entries.push_back(pbr_entry);
        NAS_ACL_LOG_BRIEF("Adding PBR entry tbl_id %d, entry_id %d to cache",
                   tbl_id, entry_id);

    }
}

void nas_acl_switch::del_pbr_entry_from_cache(nas_obj_id_t tbl_id, nas_obj_id_t entry_id)
{
    for( auto iter = _cached_pbr_entries.begin();
            iter != _cached_pbr_entries.end();
            ++iter )
    {
        if( iter->tbl_id == tbl_id &&
            iter->entry_id == entry_id)
        {
            NAS_ACL_LOG_BRIEF("Deleting PBR entry tbl_id %d, entry_id %d from cache",
                       tbl_id, entry_id);
            _cached_pbr_entries.erase( iter );
            break;
        }
    }
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

nas_acl_counter_t* nas_acl_switch::find_counter_by_name (nas_obj_id_t tbl_id,
                                                         const char* counter_name) noexcept
{
    auto it_tbl = _table_containers.find (tbl_id);
    if (it_tbl == _table_containers.end ()) return nullptr;

    for (auto& cnt_item: it_tbl->second._acl_counters) {
        const char* chk_name = cnt_item.second.counter_name();
        if (chk_name != nullptr && strcmp(chk_name, counter_name) == 0) {
            return &cnt_item.second;
        }
    }

    return nullptr;
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

// Return pointer to ACl range object of given range id. Return NULL if no range
// object found
nas_acl_range* nas_acl_switch::find_acl_range (nas_obj_id_t range_id) noexcept
{
    auto range_itr = _range_objs.find (range_id);
    if (range_itr == _range_objs.end ()) {
        return nullptr;
    }

    return &range_itr->second;
}

nas_acl_range& nas_acl_switch::save_acl_range(nas_acl_range&& acl_range) noexcept
{
    auto it = _range_objs.find(acl_range.range_id());

    if (it == _range_objs.end()) {
        auto p = _range_objs.insert(std::make_pair(acl_range.range_id(), std::move(acl_range)));
        return (p.first->second);
    }

    // Update existing ACL Range if present
    return (it->second = std::move(acl_range));
}

void nas_acl_switch::remove_acl_range(nas_obj_id_t range_id) noexcept
{
    _range_objs.erase(range_id);
}
