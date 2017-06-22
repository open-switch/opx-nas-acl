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
 * \file   nas_acl_entry.cpp
 * \brief  NAS ACL Entry Class implementation
 * \date   02-2015
 */

#include "dell-base-acl.h"
#include "nas_base_utils.h"
#include "nas_acl_log.h"
#include "nas_acl_entry.h"
#include "nas_acl_table.h"
#include "nas_acl_switch.h"
#include "nas_ndi_acl.h"
#include "nas_acl_log.h"
#include <inttypes.h>

static void _utl_push_disable_action_to_npu (nas_acl_entry& acl_entry,
                                             BASE_ACL_ACTION_TYPE_t a_type,
                                             npu_id_t  npu_id,
                                             bool remove_counter=false);

nas_acl_entry::nas_acl_entry (const nas_acl_table* table_p)
    :nas::base_obj_t (&(table_p->get_switch())), _table_p (table_p)
{
}

nas_obj_id_t  nas_acl_entry::table_id() const noexcept
{
    return _table_p->table_id();
}

// Override base npu_list routine to return a more restrictive
// NPU list in case the ACL entry is qualified with in ports or out ports
const nas::npu_set_t&  nas_acl_entry::npu_list () const
{
    if (_filter_npus.size () != 0) {
        return _filter_npus;
    }
    return nas::base_obj_t::npu_list();
}

void nas_acl_entry::set_priority (ndi_acl_priority_t p)
{
    _priority = p;
    mark_attr_dirty (BASE_ACL_ENTRY_PRIORITY);
}

void nas_acl_entry::copy_table_npus ()
{
    // Reset to the table NPU list
    set_npu_list (get_table().npu_list());
    _following_table_npus = true;
}

void nas_acl_entry::add_npu (npu_id_t npu_id, bool reset)
{
    _following_table_npus = false;
    nas::base_obj_t::add_npu (npu_id, reset);
}

bool nas_acl_entry::is_npu_set (npu_id_t npu_id) const noexcept
{
    if (!_following_table_npus) {
        return nas::base_obj_t::npu_list().contains (npu_id);
    }
    return _filter_npus.contains (npu_id);
}

/*
 * reset=True indicates that this Entry is being created or modified in overwrite mode
 * reset=False indicates that a single Filter is being added/modified/deleted
 */
void nas_acl_entry::add_filter (nas_acl_filter_t& filter, bool reset)
{
    if (!get_table().is_filter_allowed (filter.filter_type())) {
        throw nas::base_exception {NAS_ACL_E_INCONSISTENT, __PRETTY_FUNCTION__,
                              std::string {"Table does not allow matching on Filter "}
                              + std::string (filter.name())};
    }

    if (reset && !is_attr_dirty (BASE_ACL_ENTRY_MATCH)) {

        _flist.clear ();
        _filter_npus.clear();
    }

    if (filter.is_npu_specific ()) {
        // Ensure that the entry has no other NPU specific filters.
        if (!_filter_npus.empty() &&
             _flist.find({filter.filter_type(), filter.filter_offset()}) == _flist.end()) {
            throw nas::base_exception {NAS_ACL_E_INCONSISTENT, __PRETTY_FUNCTION__,
                                       "Cannot have Port and Port-list Match filter in the same Entry."};
        }
        _filter_npus = filter.get_npu_list ();

        // Assuming the NPUs required by the filter have changed ensure that
        // the entry's ACL table is installed on the new set of NPUs.
        for (auto npu_id : _filter_npus) {
            if (!get_table().npu_list().contains (npu_id))
            {
                throw nas::base_exception {NAS_ACL_E_INCONSISTENT, __PRETTY_FUNCTION__,
                    std::string {"Table's NPU list does not contain NPU "} +
                    std::to_string (npu_id) + " needed by Filter " + filter.name() };
            }
        }
    }

    mark_attr_dirty (BASE_ACL_ENTRY_MATCH);
    if (_flist.find ({filter.filter_type(), filter.filter_offset()}) != _flist.end()) {
        _flist.at ({filter.filter_type(), filter.filter_offset()}) = filter;
    } else {
        nas_acl_filter_key_t filter_key = {filter.filter_type(), filter.filter_offset()};
        _flist.insert (std::make_pair (filter_key, filter));
    }
}

void nas_acl_entry::remove_filter (BASE_ACL_MATCH_TYPE_t ftype, size_t offset)
{
    if (nas_acl_filter_t::is_npu_specific (ftype))
        _filter_npus.clear();
    _flist.erase ({ftype, offset});
    mark_attr_dirty (BASE_ACL_ENTRY_MATCH);
}

void nas_acl_entry::remove_action (BASE_ACL_ACTION_TYPE_t atype)
{
    _alist.erase (atype);
    mark_attr_dirty (BASE_ACL_ENTRY_ACTION);
}

void nas_acl_entry::reset_filter ()
{
    _flist.clear ();
    _filter_npus.clear();
    mark_attr_dirty (BASE_ACL_ENTRY_MATCH);
}

void nas_acl_entry::reset_action ()
{
    _alist.clear ();
    mark_attr_dirty (BASE_ACL_ENTRY_ACTION);
}

const nas_acl_counter_t* nas_acl_entry::get_counter () const
{
    auto& sw = get_table().get_switch();

    return (is_counter_enabled ()) ?
        &sw.get_counter (table_id(), counter_id()): NULL;
}

nas_acl_counter_t* nas_acl_entry::get_counter ()
{
    auto& sw = get_table().get_switch();

    return (is_counter_enabled ()) ?
        &sw.get_counter (table_id(), counter_id()): NULL;
}

/*
 * reset=True indicates that this Entry is being created or modified in overwrite mode
 * reset=False indicates that a single Action is being added/modified/deleted
 */
void nas_acl_entry::add_action (nas_acl_action_t& action, bool reset)
{
    if (reset && !is_attr_dirty (BASE_ACL_ENTRY_ACTION)) {
        _alist.clear ();
    }

    mark_attr_dirty (BASE_ACL_ENTRY_ACTION);
    if (_alist.find (action.action_type()) != _alist.end()) {
        _alist.at (action.action_type()) = action;
    } else {
        _alist.insert (std::make_pair (action.action_type(), action));
    }

    if (action.action_type () == BASE_ACL_ACTION_TYPE_SET_COUNTER) {

        auto counter_p = get_table().get_switch().find_counter(table_id(), counter_id());
        if (counter_p == NULL) {
            throw nas::base_exception {NAS_ACL_E_ATTR_VAL, __PRETTY_FUNCTION__,
                                       std::string {"No such Counter "} +
                                       std::to_string (counter_id())};
        }
        if (counter_p->table_id() != this->table_id()) {
            throw nas::base_exception {NAS_ACL_E_INCONSISTENT, __PRETTY_FUNCTION__,
                                       std::string {"Counter does not belong to entry's table "} +
                                       std::to_string (this->table_id())};
        }
    }
}

void nas_acl_entry::commit_create (bool rolling_back)
{
    if (_following_table_npus) {
        // A New Entry starts with _following_table_npus flag set
        // This flag is reset when the entry's NPUlist attribute is set
        // If no NPUs are set then copy all NPUs from table
        // In this case the Filter NPUs would have been already
        // validated to be a subset of the Table's NPUs
        copy_table_npus();
    } else {
        // Entry's NPUlist attribute was set - ensure that this is a
        // super set of all the NPUs required by its filters
        for (auto npu_id: _filter_npus) {
            if (!npu_list().contains (npu_id)) {
                throw nas::base_exception {NAS_ACL_E_INCONSISTENT, __PRETTY_FUNCTION__,
                        std::string {"NPU list for Entry "} + std::to_string (entry_id())
                        + " is missing NPU " + std::to_string (npu_id)};
            }
        }
    }

    if (is_counter_enabled ()) { _validate_counter_npus (); }

    nas::base_obj_t::commit_create (rolling_back);
}

void nas_acl_entry::_validate_counter_npus () const
{
    for (auto npu_id: npu_list()) {
        if (!get_counter()->is_obj_in_npu (npu_id)) {
            throw nas::base_exception {NAS_ACL_E_INCONSISTENT, __PRETTY_FUNCTION__,
                std::string {"NPU list for Counter "} +
                    std::to_string (counter_id()) +
                    " is missing NPU " + std::to_string (npu_id)};
        }
    }
}

nas::attr_set_t nas_acl_entry::commit_modify (base_obj_t& entry_orig,
                                              bool rolling_back)
{
    if (!_following_table_npus &&
        nas::base_obj_t::npu_list().empty()) {
        // If all NPUs have been removed then copy all NPUs from table
        copy_table_npus();
    }
    else if (!_following_table_npus) {
        // Entry has its own set of NPUs - ensure that this is a super set
        // of all the NPUs needed by its filters
        for (auto npu_id: _filter_npus) {
            if (!nas::base_obj_t::npu_list().contains (npu_id)) {
                throw nas::base_exception {NAS_ACL_E_INCONSISTENT, __PRETTY_FUNCTION__,
                        std::string {"NPU list for Entry "} +
                        std::to_string (entry_id()) +
                        " is missing NPU " + std::to_string (npu_id)};
            }
        }
    }

    if (is_counter_enabled ()) { _validate_counter_npus (); }

    return nas::base_obj_t::commit_modify (entry_orig, rolling_back);
}

const nas_acl_filter_t& nas_acl_entry::get_filter (BASE_ACL_MATCH_TYPE_t ftype,
                                                   size_t offset) const
{
    try {
        return _flist.at ({ftype, offset});
    } catch (std::out_of_range& ) {
        throw nas::base_exception {NAS_ACL_E_KEY_VAL, __PRETTY_FUNCTION__,
                              std::string {"ACL Entry has no Filter field "} +
                              nas_acl_filter_t::type_name (ftype)};
    }
}

const nas_acl_action_t& nas_acl_entry::get_action (BASE_ACL_ACTION_TYPE_t
                                                   atype) const
{
    try {
        return _alist.at (atype);
    } catch (std::out_of_range& ) {
        throw nas::base_exception {NAS_ACL_E_KEY_VAL, __PRETTY_FUNCTION__,
                              std::string {"ACL Entry has no Action "} +
                              nas_acl_action_t::type_name (atype)};
    }
}


bool nas_acl_entry::_copy_all_filters_ndi (ndi_acl_entry_t &ndi_acl_entry,
                                           npu_id_t npu_id,
                                           nas::mem_alloc_helper_t& mem_trakr) const
{
    int i = 0;
    for (const_filter_iter_t itr = _flist.begin();
         itr != _flist.end(); ++itr,++i) {

        auto& f = nas_acl_entry::get_filter_from_itr (itr);
        if (!f.copy_filter_ndi (&ndi_acl_entry.filter_list[i],
                                npu_id, mem_trakr)) {
            // NPU specific filter is not needed for
            return false;
        }
    }
    return true;
}

static void _copy_ndi_counter_id (const nas_acl_entry& entry,
                                  ndi_acl_entry_action_t& ndi_action,
                                  npu_id_t  npu_id) noexcept
{
    auto counter_p = entry.get_counter();
    ndi_action.values.ndi_obj_ref = counter_p->ndi_obj_id (npu_id);
    NAS_ACL_LOG_DETAIL ("NPU ID: %d, NDI Counter Id: %" PRIx64,
                        npu_id, ndi_action.values.ndi_obj_ref);
}

ndi_acl_action_list_t nas_acl_entry::_copy_all_actions_ndi (npu_id_t npu_id,
                                                            nas::mem_alloc_helper_t& mem_trakr) const
{
    ndi_acl_action_list_t ndi_alist;

    bool found_trap_id_action = false;
    for (const_action_iter_t itr = _alist.begin(); itr != _alist.end(); ++itr) {

        auto& action = nas_acl_entry::get_action_from_itr (itr);
        if (action.action_type() == BASE_ACL_ACTION_TYPE_SET_USER_TRAP_ID) {
            found_trap_id_action = true;
            continue;
        }
        action.copy_action_ndi (ndi_alist, npu_id, mem_trakr);

        if (action.is_counter()) {
            _copy_ndi_counter_id (*this, ndi_alist.back(), npu_id);
        }
    }

    if (found_trap_id_action) {
        auto& action = _alist.at(BASE_ACL_ACTION_TYPE_SET_USER_TRAP_ID);
        action.copy_action_ndi (ndi_alist, npu_id, mem_trakr);
    }

    return ndi_alist;
}

bool nas_acl_entry::push_create_obj_to_npu (npu_id_t npu_id,
                                            void* ndi_obj)
{
    t_std_error rc = STD_ERR_OK;
    nas::mem_alloc_helper_t mem_trakr;
    ndi_acl_entry_t ndi_acl_entry = {};

    ///// Populate the NDI ACL Entry structure
    //
    ndi_acl_entry.table_id = get_table().get_ndi_obj_id(npu_id);
    ndi_acl_entry.priority = priority();

    /////// Populate the filters
    ndi_acl_entry.filter_count = _flist.size();
    ndi_acl_entry.filter_list = mem_trakr.alloc<ndi_acl_entry_filter_t> (_flist.size());

    if (!_copy_all_filters_ndi (ndi_acl_entry, npu_id, mem_trakr)) {
        return false;
    }

    ///// Populate the actions
    auto ndi_alist = _copy_all_actions_ndi (npu_id, mem_trakr);

    ndi_acl_entry.action_count = ndi_alist.size();
    ndi_acl_entry.action_list = ndi_alist.data();

    ndi_obj_id_t ndi_entry_id;

    if ((rc = ndi_acl_entry_create (npu_id, &ndi_acl_entry,
            &ndi_entry_id)) != STD_ERR_OK) {
        throw nas::base_exception {rc, __PRETTY_FUNCTION__,
            std::string {"NDI ACL Entry Create failed for NPU "} +
            std::to_string (npu_id)};
    }

    ndi_entry_ids[npu_id] = ndi_entry_id;

    NAS_ACL_LOG_DETAIL ("Switch %d Table %ld: Created ACL Entry in NPU %d "
            "NDI-ID 0x%" PRIx64,
            switch_id(), table_id(), npu_id, ndi_entry_id);

    return true;
}

bool nas_acl_entry::push_delete_obj_to_npu (npu_id_t npu_id)
{
    t_std_error rc = STD_ERR_OK;
    auto it_ndi_eid = ndi_entry_ids.find (npu_id);

    if (it_ndi_eid == ndi_entry_ids.end()) {
        NAS_ACL_LOG_BRIEF ("Switch %d Table %ld: Entry %ld: Not found in NPU %d",
                           get_switch().id(), get_table().table_id(),
                           entry_id(), npu_id);
        return false;
    }

    if ((rc = ndi_acl_entry_delete (npu_id, it_ndi_eid->second))
         != STD_ERR_OK) {
        throw nas::base_exception {rc, __PRETTY_FUNCTION__,
                                   std::string {"NDI ACL Entry "} +
                                   std::to_string (ndi_entry_ids.at (npu_id)) +
                                   " Delete failed for NPU " + std::to_string (npu_id)};
    }

    NAS_ACL_LOG_DETAIL ("Switch %d Table %ld: Deleted ACL Entry %ld in NPU %d "
                        "NDI-ID 0x%" PRIx64,
                        switch_id(), table_id(), entry_id(), npu_id,
                        ndi_entry_ids.at (npu_id));

    ndi_entry_ids.erase (npu_id);

    return true;
}

bool nas_acl_entry::is_leaf_attr (nas_attr_id_t attr_id)
{
    static const std::unordered_map <BASE_ACL_ENTRY_t,
                                     bool,
                                     std::hash<int>>
        _leaf_attr_map =
    {
        {BASE_ACL_ENTRY_PRIORITY,        true},
        {BASE_ACL_ENTRY_MATCH,           false},
        {BASE_ACL_ENTRY_ACTION,          false},
        //The NPU ID list attribute is handled by the base object itself.
    };

    return (_leaf_attr_map.at(static_cast<BASE_ACL_ENTRY_t>(attr_id)));
}

bool nas_acl_entry::push_leaf_attr_to_npu (nas_attr_id_t attr_id,
                                            npu_id_t npu_id)
{
    t_std_error rc = STD_ERR_OK;

    switch (attr_id)
    {
        case BASE_ACL_ENTRY_PRIORITY:
            if ((rc = ndi_acl_entry_set_priority (npu_id, ndi_entry_ids.at(npu_id),
                                                  priority()))
                != STD_ERR_OK)
            {
                throw nas::base_exception {rc, __PRETTY_FUNCTION__,
                                   std::string {"NDI Entry Priority Set Failed for NPU "} +
                                   std::to_string (npu_id)};
            }

            NAS_ACL_LOG_DETAIL ("Switch %d Table %ld Entry %ld: Modified Priority in NPU %d",
                                switch_id(), table_id(), entry_id(), npu_id);
            break;
        default:
            throw nas::base_exception {NAS_ACL_E_FAIL, __PRETTY_FUNCTION__,
                                       "Unknown leaf attribute type in ACL entry"};
    }

    return true;
}


static void _utl_flist_compare (const nas_acl_entry::filter_list_t& lhs_flist,
                                const nas_acl_entry::filter_list_t& rhs_flist,
                                nas_acl_entry::filter_list_t& deleted,
                                nas_acl_entry::filter_list_t& add_or_mod)
{

    for (nas_acl_entry::const_filter_iter_t itr_old = rhs_flist.begin();
         itr_old != rhs_flist.end(); ++itr_old) {

        const nas_acl_filter_t& f_old = nas_acl_entry::get_filter_from_itr (itr_old);
        auto itr_new = lhs_flist.find ({f_old.filter_type(), f_old.filter_offset()});

        if (itr_new == lhs_flist.end()) {
            nas_acl_filter_key_t filter_key = {f_old.filter_type(), f_old.filter_offset()};
            deleted.insert (std::make_pair (filter_key, f_old));
        } else {
            const nas_acl_filter_t& f_new = nas_acl_entry::get_filter_from_itr (itr_new);
            if (f_old != f_new) {
                nas_acl_filter_key_t filter_key = {f_new.filter_type(), f_new.filter_offset()};
                add_or_mod.insert (std::make_pair (filter_key, f_new));
            }
        }
    }

    for (nas_acl_entry::const_filter_iter_t itr_new = lhs_flist.begin();
         itr_new != lhs_flist.end(); ++itr_new) {

        const nas_acl_filter_t& f_new = nas_acl_entry::get_filter_from_itr (itr_new);
        auto itr_old = rhs_flist.find ({f_new.filter_type(), f_new.filter_offset()});

        if (itr_old == rhs_flist.end()) {
            nas_acl_filter_key_t filter_key = {f_new.filter_type(), f_new.filter_offset()};
            add_or_mod.insert (std::make_pair (filter_key, f_new));
        }
    }
}

static void _utl_push_disable_filter_to_npu (nas_acl_entry& acl_entry,
                                             BASE_ACL_MATCH_TYPE_t f_type,
                                             npu_id_t  npu_id)
{
    t_std_error rc;

    if ((rc = ndi_acl_entry_disable_filter (npu_id, acl_entry.ndi_entry_ids.at (npu_id),
                                            f_type)) != STD_ERR_OK) {
        throw nas::base_exception {rc, __PRETTY_FUNCTION__,
                                   std::string {"NDI Filter Disable failed for "} +
                                   nas_acl_filter_t::type_name (f_type) +
                                   " for NPU " + std::to_string (npu_id)};
    }

    NAS_ACL_LOG_DETAIL ("ACL Entry NDI: Disabled Filter %s in NPU %d",
                        nas_acl_filter_t::type_name (f_type), npu_id);
}

static void _utl_push_filter_to_npu (nas_acl_entry& acl_entry,
                                     const nas_acl_filter_t& f_add,
                                     npu_id_t  npu_id)
{
    ndi_acl_entry_filter_t  ndi_filter {};
    nas::mem_alloc_helper_t  mem_trakr;

    if (!f_add.copy_filter_ndi (&ndi_filter, npu_id, mem_trakr)) {
        // This filter and hence this ACL entry is NPU specific
        // and is not needed in this NPU
        return;
    }

    t_std_error rc;

    if ((rc = ndi_acl_entry_set_filter (npu_id, acl_entry.ndi_entry_ids.at (npu_id),
                                        &ndi_filter)) != STD_ERR_OK) {
        throw nas::base_exception {rc, __PRETTY_FUNCTION__,
                                   std::string {"NDI Filter set failed for "} +
                                   f_add.name() + " for NPU " + std::to_string (npu_id)};
    }

    NAS_ACL_LOG_DETAIL ("ACL Entry NDI: Set Filter %s in NPU %d",
                        f_add.name(), npu_id);
}

static void _utl_modify_flist_npulist_ndi (nas_acl_entry&   entry_new,
                                           nas::base_obj_t&   obj_old,
                                           nas::npu_set_t  npu_list,
                                           nas::rollback_trakr_t& r_trakr,
                                           bool rolling_back)
{
    nas_acl_entry& entry_old = dynamic_cast <nas_acl_entry&> (obj_old);

    nas_acl_entry::filter_list_t  deleted_flist, add_or_mod_flist;

    _utl_flist_compare (entry_new.get_filter_list(), entry_old.get_filter_list(),
                        deleted_flist, add_or_mod_flist);

    for (auto npu_id: npu_list) {

        for (nas_acl_entry::const_filter_iter_t itr_del = deleted_flist.begin();
             itr_del != deleted_flist.end(); ++itr_del) {

            const nas_acl_filter_t& f_del = nas_acl_entry::get_filter_from_itr (itr_del);

            try {
                _utl_push_disable_filter_to_npu (entry_new, f_del.filter_type(),
                                                 npu_id);

            } catch (nas::base_exception& e) {
                if (rolling_back) {
                    // Error when rolling back - Log and continue with next filter
                    NAS_ACL_LOG_ERR ("Rollback failed: NPU %d: %s ErrCode: %d \n",
                                     npu_id, e.err_msg.c_str(), e.err_code);
                } else {
                    throw;
                }
            }

            if (!rolling_back) {
                // Upon successful NDI create, start tracking this for rollback
                nas::rollbk_elem_t r_elem {nas::ROLLBK_DELETE_ATTR, npu_id,
                    {BASE_ACL_ENTRY_MATCH, f_del.filter_type()}};
                r_trakr.push_back (r_elem);
            }
        }

        for (nas_acl_entry::const_filter_iter_t itr_add = add_or_mod_flist.begin();
             itr_add != add_or_mod_flist.end(); ++itr_add) {

            const nas_acl_filter_t& f_add = nas_acl_entry::get_filter_from_itr (itr_add);

            try {
                _utl_push_filter_to_npu (entry_new, f_add, npu_id);

            } catch (nas::base_exception& e) {
                if (rolling_back) {
                    // Error when rolling back - Log and continue with next filter
                    NAS_ACL_LOG_ERR ("Rollback failed: NPU %d: %s ErrCode: %d \n",
                                     npu_id, e.err_msg.c_str(), e.err_code);
                } else {
                    throw;
                }
            }

            if (!rolling_back) {
                // Upon successful NDI create, start tracking this for rollback
                nas::rollbk_elem_t r_elem {nas::ROLLBK_CREATE_ATTR, npu_id,
                    {BASE_ACL_ENTRY_MATCH, f_add.filter_type()}};
                r_trakr.push_back (r_elem);
            }
        }
    }
}

// Compare the new and old list of actions to identify what has changed
static void _utl_alist_compare (const nas_acl_entry::action_list_t& lhs_alist,
                                const nas_acl_entry::action_list_t& rhs_alist,
                                nas_acl_entry::action_list_t& deleted,
                                nas_acl_entry::action_list_t& add_or_mod)
{

    for (nas_acl_entry::const_action_iter_t itr_old = rhs_alist.begin();
         itr_old != rhs_alist.end(); ++itr_old) {

        const nas_acl_action_t& a_old = nas_acl_entry::get_action_from_itr (itr_old);
        auto itr_new = lhs_alist.find (a_old.action_type());

        if (itr_new == lhs_alist.end()) {
            deleted.insert (std::make_pair (a_old.action_type(), a_old));
        } else {
            const nas_acl_action_t& a_new = nas_acl_entry::get_action_from_itr (itr_new);
            if (a_old != a_new) {
                add_or_mod.insert (std::make_pair (a_new.action_type(), a_new));
            }
        }
    }

    for (nas_acl_entry::const_action_iter_t itr_new = lhs_alist.begin();
         itr_new != lhs_alist.end(); ++itr_new) {

        const nas_acl_action_t& a_new = nas_acl_entry::get_action_from_itr (itr_new);
        auto itr_old = rhs_alist.find (a_new.action_type());

        if (itr_old == rhs_alist.end()) {
            add_or_mod.insert (std::make_pair (a_new.action_type(), a_new));
        }
    }
}

// Handle deleted action in entry change request
static void _utl_push_disable_action_to_npu (nas_acl_entry& acl_entry,
                                             BASE_ACL_ACTION_TYPE_t a_type,
                                             npu_id_t  npu_id,
                                             bool remove_counter)
{
    t_std_error rc;
    if ((rc = ndi_acl_entry_disable_action (npu_id,
                                            acl_entry.ndi_entry_ids.at (npu_id),
                                            a_type)) != STD_ERR_OK) {
        throw nas::base_exception {rc, __PRETTY_FUNCTION__,
            std::string {"NDI Action Disable failed for "} +
            nas_acl_action_t::type_name (a_type) +
            " for NPU " + std::to_string (npu_id)};
    }

    NAS_ACL_LOG_DETAIL ("ACL Entry NDI: Disabled Action %s in NPU %d",
                        nas_acl_action_t::type_name (a_type), npu_id);
}

// Handle new or modified action in entry change request
static void _utl_push_action_to_npu (nas_acl_entry& acl_entry,
                                     const nas_acl_action_t& a_add,
                                     npu_id_t  npu_id)
{
    nas::mem_alloc_helper_t  mem_trakr;
    t_std_error rc;
    ndi_acl_action_list_t ndi_alist;

    if (!a_add.copy_action_ndi (ndi_alist, npu_id, mem_trakr)) {
        // This action and hence this ACL entry is NPU specific
        // and is not needed in this NPU
        return;
    }

    if (a_add.is_counter()) {
        _copy_ndi_counter_id (acl_entry, ndi_alist.back(), npu_id);
    }

    for (auto& ndi_action: ndi_alist) {
        if ((rc = ndi_acl_entry_set_action (npu_id,
                acl_entry.ndi_entry_ids.at (npu_id),
                &ndi_action)) != STD_ERR_OK) {

            throw nas::base_exception {rc, __PRETTY_FUNCTION__,
                std::string {"NDI Action Set failed for "} +
                a_add.name() + " for NPU " + std::to_string (npu_id)};
        }
    }

    NAS_ACL_LOG_DETAIL ("ACL Entry NDI: Set Action %s in NPU %d",
                        a_add.name(), npu_id);
}

// Identify change in action list and push change to each NPU for the ACL entry
static void _utl_modify_alist_npulist_ndi (nas_acl_entry&   entry_new,
                                           nas::base_obj_t&   obj_old,
                                           nas::npu_set_t  npu_list,
                                           nas::rollback_trakr_t& r_trakr,
                                           bool rolling_back)
{
    nas_acl_entry& entry_old = dynamic_cast <nas_acl_entry&> (obj_old);

    nas_acl_entry::action_list_t  deleted_alist, add_or_mod_alist;

    _utl_alist_compare (entry_new.get_action_list(), entry_old.get_action_list(),
                        deleted_alist, add_or_mod_alist);

    for (auto npu_id: npu_list) {
        // Walk through the list of deleted actions and disable them in NDI
        for (nas_acl_entry::const_action_iter_t itr_del = deleted_alist.begin();
             itr_del != deleted_alist.end(); ++itr_del) {

            const nas_acl_action_t& a_del = nas_acl_entry::get_action_from_itr (itr_del);
            NAS_ACL_LOG_DETAIL ("Push Disable %s to NPU %d",
                                nas_acl_action_t::type_name(a_del.action_type()),
                                npu_id);
            try {
                _utl_push_disable_action_to_npu (entry_new, a_del.action_type(),
                                                 npu_id);
            } catch (nas::base_exception& e) {
                if (rolling_back) {
                    // Error when rolling back - Log and continue with next action
                    NAS_ACL_LOG_ERR ("Rollback failed: NPU %d: %s ErrCode: %d \n",
                                     npu_id, e.err_msg.c_str(), e.err_code);
                } else {
                    throw;
                }
            }

            if (!rolling_back) {
                // Upon successful NDI create, start tracking this for rollback
                nas::rollbk_elem_t r_elem {nas::ROLLBK_DELETE_ATTR, npu_id,
                    {BASE_ACL_ENTRY_ACTION, a_del.action_type()}};
                r_trakr.push_back (r_elem);
            }
        }

        // Walk through the list of updated actions and add or modify them in NDI
        for (nas_acl_entry::const_action_iter_t itr_add = add_or_mod_alist.begin();
             itr_add != add_or_mod_alist.end(); ++itr_add) {

            const nas_acl_action_t& a_add = nas_acl_entry::get_action_from_itr (itr_add);
            NAS_ACL_LOG_DETAIL ("Push Enable %s to NPU %d",
                                nas_acl_action_t::type_name(a_add.action_type()),
                                npu_id);
            try {
                _utl_push_action_to_npu (entry_new, a_add, npu_id);

            } catch (nas::base_exception& e) {
                if (rolling_back) {
                    // Error when rolling back - Log and continue with next action
                    NAS_ACL_LOG_ERR ("Rollback failed: NPU %d: %s ErrCode: %d \n",
                                     npu_id, e.err_msg.c_str(), e.err_code);
                } else {
                    throw;
                }
            }

            if (!rolling_back) {
                // Upon successful NDI create, start tracking this for rollback
                nas::rollbk_elem_t r_elem {nas::ROLLBK_CREATE_ATTR, npu_id,
                    {BASE_ACL_ENTRY_ACTION, a_add.action_type()}};
                r_trakr.push_back (r_elem);
            }
        }
    }
}

void nas_acl_entry::push_non_leaf_attr_ndi (nas_attr_id_t   non_leaf_attr_id,
                                            nas::base_obj_t&   obj_old,
                                            nas::npu_set_t  npu_list,
                                            nas::rollback_trakr_t& r_trakr,
                                            bool rolling_back)
{
    switch (static_cast<BASE_ACL_ENTRY_t>(non_leaf_attr_id))
    {
        case BASE_ACL_ENTRY_MATCH:
            _utl_modify_flist_npulist_ndi (*this, obj_old, npu_list, r_trakr, rolling_back);
            break;
        case BASE_ACL_ENTRY_ACTION:
            _utl_modify_alist_npulist_ndi (*this, obj_old, npu_list, r_trakr, rolling_back);
            break;
        default:
            throw nas::base_exception {NAS_ACL_E_FAIL, __PRETTY_FUNCTION__,
                                       "Unknown non-leaf attribute type in ACL entry"};
    }
}

void nas_acl_entry::rollback_create_attr_in_npu (const nas::attr_list_t&
                                                 attr_hierarchy,
                                                 npu_id_t npu_id)
{
    // This is an internal routine called only for non-leaf attributes
    // There is no way the attribute hierarchy can have less than 2 elements
    // Extra assert just incase something wacky
    // Called from - nas_base_ndi_utl.cpp, _rollback_modify_obj_ndi()
    STD_ASSERT (attr_hierarchy.size() > 1);

    switch (attr_hierarchy[0])
    {
        case BASE_ACL_ENTRY_MATCH:
            try {
                auto f_type = static_cast <BASE_ACL_MATCH_TYPE_t>
                    (attr_hierarchy[1]);

                _utl_push_disable_filter_to_npu (*this, f_type, npu_id);

            } catch (nas::base_exception& e) {
                NAS_ACL_LOG_ERR ("Rollback failed: NPU %d: %s ErrCode: %d \n",
                                 npu_id, e.err_msg.c_str(), e.err_code);
            }
            break;

        case BASE_ACL_ENTRY_ACTION:
            try {
                auto a_type = static_cast <BASE_ACL_ACTION_TYPE_t>
                    (attr_hierarchy[1]);

                _utl_push_disable_action_to_npu (*this, a_type, npu_id);

            } catch (nas::base_exception& e) {
                NAS_ACL_LOG_ERR ("Rollback failed: NPU %d: %s ErrCode: %d \n",
                                 npu_id, e.err_msg.c_str(), e.err_code);
            }
            break;

        default:
            throw nas::base_exception {NAS_ACL_E_FAIL, __PRETTY_FUNCTION__,
                                       "Unknown non-leaf attribute type in ACL entry"};
    }
}

void nas_acl_entry::rollback_delete_attr_in_npu (const nas::attr_list_t&
                                                 attr_hierarchy,
                                                 npu_id_t npu_id)
{
    // This is an internal routine called only for non-leaf attributes
    // There is no way the attribute hierarchy can have less than 2 elements
    // Extra assert just incase something wacky
    // Called from - nas_base_ndi_utl.cpp, _rollback_modify_obj_ndi()
    STD_ASSERT (attr_hierarchy.size() > 1);

    switch (attr_hierarchy[0])
    {
        case BASE_ACL_ENTRY_MATCH:
            try {
                auto f_type = static_cast <BASE_ACL_MATCH_TYPE_t>
                    (attr_hierarchy[1]);

                if (f_type == BASE_ACL_MATCH_TYPE_UDF) {
                    for (auto& f: _flist) {
                        if (f.first.match_type == f_type) {
                            _utl_push_filter_to_npu(*this, f.second, npu_id);
                        }
                    }
                } else {
                    const nas_acl_filter_t& f = get_filter (f_type, 0);
                    _utl_push_filter_to_npu (*this, f, npu_id);
                }

            } catch (nas::base_exception& e) {
                NAS_ACL_LOG_ERR ("Rollback failed: NPU %d: %s ErrCode: %d \n",
                                 npu_id, e.err_msg.c_str(), e.err_code);
            }
            break;

        case BASE_ACL_ENTRY_ACTION:
            try {
                auto a_type = static_cast <BASE_ACL_ACTION_TYPE_t>
                    (attr_hierarchy[1]);

                const nas_acl_action_t& a = get_action (a_type);
                _utl_push_action_to_npu (*this, a, npu_id);

            } catch (nas::base_exception& e) {
                NAS_ACL_LOG_ERR ("Rollback failed: NPU %d: %s ErrCode: %d \n",
                                 npu_id, e.err_msg.c_str(), e.err_code);
            }
            break;

        default:
            throw nas::base_exception {NAS_ACL_E_FAIL, __PRETTY_FUNCTION__,
                "Unknown non-leaf attribute type in ACL entry"};
    }
}

void nas_acl_entry::dbg_dump () const
{
    NAS_ACL_LOG_DUMP ("NAS ACL Entry dump");
    NAS_ACL_LOG_DUMP ("------------------");
    NAS_ACL_LOG_DUMP ("Switch ID: %d", switch_id());
    NAS_ACL_LOG_DUMP ("Table ID: %ld", table_id());
    NAS_ACL_LOG_DUMP ("Entry ID: %ld", entry_id());
    NAS_ACL_LOG_DUMP ("Priority: %d", priority());
    NAS_ACL_LOG_DUMP ("NPU List: ");
    for (auto npu_id: npu_list()) {
        NAS_ACL_LOG_DUMP ("%d, ", npu_id);
    }
    NAS_ACL_LOG_DUMP ("");
    NAS_ACL_LOG_DUMP ("NDI Entry IDs: ");
    for (auto ndi_entry_map: ndi_entry_ids) {
        NAS_ACL_LOG_DUMP ("(NPU %d, %ld) ", ndi_entry_map.first, ndi_entry_map.second );
    }
    NAS_ACL_LOG_DUMP ("");
    NAS_ACL_LOG_DUMP ("Num Filters: %ld", get_filter_list().size());
    for (auto& f_kv: get_filter_list()) {
        const nas_acl_filter_t& filter = f_kv.second;
        NAS_ACL_LOG_DUMP ("  Filter %s", filter.name());
        filter.dbg_dump ();
    }
    NAS_ACL_LOG_DUMP ("Num Actions: %ld", get_action_list().size());
    for (auto& a_kv: get_action_list()) {
        const nas_acl_action_t& action = a_kv.second;
        NAS_ACL_LOG_DUMP ("  Action %s", action.name());
        action.dbg_dump ();
    }
}
