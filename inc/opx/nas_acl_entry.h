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
 * \file   nas_acl_entry.h
 * \brief  NAS ACL Entry Class Definition
 * \date   02-2015
 */

#ifndef _NAS_ACL_ENTRY_H_
#define _NAS_ACL_ENTRY_H_

#include "std_assert.h"
#include "nas_base_utils.h"
#include "nas_acl_filter.h"
#include "nas_acl_action.h"
#include "nas_acl_counter.h"
#include "nas_base_utils.h"
#include "nas_ndi_obj_id_table.h"
#include "nas_base_obj.h"
#include "nas_ndi_acl.h"
#include <unordered_map>

class nas_acl_switch;
class nas_acl_table;

typedef struct _nas_acl_filter_key_t
{
    BASE_ACL_MATCH_TYPE_t match_type;
    size_t offset;
} nas_acl_filter_key_t;

struct _filter_key_hash
{
    size_t operator()(const nas_acl_filter_key_t&key) const {
        size_t hash;
        if (key.match_type == BASE_ACL_MATCH_TYPE_UDF) {
            hash = std::hash<int>()(key.match_type);
            hash ^= (std::hash<int>()(key.offset) << 1);
        } else {
            hash = std::hash<int>()(key.match_type);
        }
        return hash;
    }
};

struct _filter_key_equal
{
    bool operator()(const nas_acl_filter_key_t& k1, const nas_acl_filter_key_t& k2) const
    {
        if (k1.match_type != k2.match_type) {
            return false;
        }
        if (k1.match_type == BASE_ACL_MATCH_TYPE_UDF &&
            k1.offset != k2.offset) {
            return false;
        }

        return true;
    }
};

static inline bool operator==(const nas_acl_filter_key_t& k1, const nas_acl_filter_key_t& k2)
{
    return _filter_key_equal()(k1, k2);
}

class nas_acl_entry final : public nas::base_obj_t
{
    public:
        typedef std::unordered_map<nas_acl_filter_key_t, nas_acl_filter_t, _filter_key_hash, _filter_key_equal>
            filter_list_t;
        typedef filter_list_t::iterator  filter_iter_t;
        typedef filter_list_t::const_iterator  const_filter_iter_t;

        typedef std::unordered_map<BASE_ACL_ACTION_TYPE_t, nas_acl_action_t, std::hash<int>> action_list_t;
        typedef action_list_t::iterator  action_iter_t;
        typedef action_list_t::const_iterator  const_action_iter_t;

        nas::ndi_obj_id_table_t ndi_entry_ids;

        ////// Constructor /////
        nas_acl_entry (const nas_acl_table* table_p);

        /////// Accessors ////////
        const nas_acl_table&     get_table() const noexcept {return *_table_p;}
        nas_obj_id_t             table_id() const noexcept;
        nas_obj_id_t             entry_id() const  noexcept {return _entry_id;}
        ndi_acl_priority_t       priority() const  noexcept {return _priority;}

        const nas_acl_filter_t&   get_filter (BASE_ACL_MATCH_TYPE_t ftype, size_t offset) const;
        const filter_list_t&      get_filter_list () const noexcept {return _flist;}
        const nas_acl_action_t&   get_action (BASE_ACL_ACTION_TYPE_t atype) const;
        const action_list_t&      get_action_list () const noexcept {return _alist;}
        static const nas_acl_filter_t&   get_filter_from_itr (const_filter_iter_t itr) noexcept;
        static nas_acl_filter_t&         get_filter_from_itr (filter_iter_t itr_old) noexcept;
        static const nas_acl_action_t&   get_action_from_itr (const_action_iter_t itr) noexcept;
        static nas_acl_action_t&         get_action_from_itr (action_iter_t itr_old) noexcept;

        bool is_counter_enabled () const noexcept;
        nas_obj_id_t counter_id () const noexcept;
        const nas_acl_counter_t* get_counter () const;
        nas_acl_counter_t* get_counter ();

        bool is_npu_set (npu_id_t npu_id) const noexcept;
        bool following_table_npus  () const noexcept {return _following_table_npus;}
        void dbg_dump () const;

        //////// Modifiers ////////
        void set_entry_id (nas_obj_id_t id);
        void set_priority (ndi_acl_priority_t p);
        void add_filter (nas_acl_filter_t& filter, bool reset=true);
        void add_action (nas_acl_action_t& action, bool reset=true);
        void remove_filter (BASE_ACL_MATCH_TYPE_t ftype, size_t offset);
        void remove_action (BASE_ACL_ACTION_TYPE_t atype);
        void reset_filter ();
        void reset_action ();
        void copy_table_npus ();

        /// Overriding base object virtual functions
        const nas::npu_set_t&         npu_list () const override;
        void add_npu (npu_id_t npu_id, bool reset=true) override;

        const char* name () const override {return "ACL Entry";}
        e_event_log_types_enums ev_log_mod_id () const
            override {return ev_log_t_ACL;}
        const char* ev_log_mod_name () const override {return "NAS-ACL";}

        void* alloc_fill_ndi_obj (nas::mem_alloc_helper_t& m) override
        {return NULL;}

        void commit_create (bool rolling_back) override;
        nas::attr_set_t commit_modify (base_obj_t& entry_orig,
                                       bool rolling_back) override;

        bool push_create_obj_to_npu (npu_id_t npu_id, void* ndi_obj) override;

        bool push_delete_obj_to_npu (npu_id_t npu_id) override;

        bool is_leaf_attr (nas_attr_id_t attr_id);
        bool push_leaf_attr_to_npu (nas_attr_id_t attr_id,
                                    npu_id_t npu_id) override;

        void push_non_leaf_attr_ndi (nas_attr_id_t   non_leaf_attr_id,
                                     nas::base_obj_t&   obj_new,
                                     nas::npu_set_t  npu_list,
                                     nas::rollback_trakr_t& r_trakr,
                                     bool rolling_back) override;

        void rollback_create_attr_in_npu (const nas::attr_list_t&
                                          attr_hierarchy,
                                          npu_id_t npu_id) override;
        void rollback_delete_attr_in_npu (const nas::attr_list_t&
                                          attr_hierarchy,
                                          npu_id_t npu_id) override;

    private:
        nas_obj_id_t                 _entry_id = 0;
        const nas_acl_table*         _table_p; // Back pointer to table
        ndi_acl_priority_t           _priority = 0;

        nas::npu_set_t               _filter_npus;
        bool                         _following_table_npus = true;

        filter_list_t                _flist;
        action_list_t                _alist;

        nas_obj_id_t                 _counter_id = 0;
        bool                         _enable_counter = false;

        void _validate_counter_npus () const;
        bool _copy_all_filters_ndi (ndi_acl_entry_t &ndi_acl_entry,
                                    npu_id_t npu_id,
                                    nas::mem_alloc_helper_t& mem_trakr) const;

        ndi_acl_action_list_t _copy_all_actions_ndi (npu_id_t npu_id,
                                                     nas::mem_alloc_helper_t& mem_trakr) const;

        void _modify_flist_npulist_ndi (nas::base_obj_t&   obj_old,
                                        nas::npu_set_t  npu_list,
                                        nas::rollback_trakr_t& r_trakr,
                                        bool rolling_back);

        void _flist_compare (const filter_list_t& second_flist,
                             filter_list_t& deleted,
                             filter_list_t& add_or_mod);

        void _push_disable_filter_to_npu (BASE_ACL_MATCH_TYPE_t f_type,
                                          npu_id_t  npu_id,
                                          bool rolling_back);

        void _push_filter_to_npu (const nas_acl_filter_t& f_add,
                                  npu_id_t  npu_id,
                                  bool rolling_back);

};

inline const nas_acl_filter_t&
nas_acl_entry::get_filter_from_itr (const_filter_iter_t itr_old) noexcept
{
    return itr_old->second;
}

inline nas_acl_filter_t&
nas_acl_entry::get_filter_from_itr (filter_iter_t itr_old) noexcept
{
    return itr_old->second;
}

inline const nas_acl_action_t&
nas_acl_entry::get_action_from_itr (const_action_iter_t itr_old) noexcept
{
    return itr_old->second;
}

inline nas_acl_action_t&
nas_acl_entry::get_action_from_itr (action_iter_t itr_old) noexcept
{
    return itr_old->second;
}

inline void nas_acl_entry::set_entry_id (nas_obj_id_t id)
{
    STD_ASSERT (_entry_id == 0); // Something wrong .. Entry already has a ID
    _entry_id = id;
}

inline nas_obj_id_t nas_acl_entry::counter_id () const noexcept
{
    auto it = _alist.find(BASE_ACL_ACTION_TYPE_SET_COUNTER);
    if (it != _alist.end()) {
        return it->second.counter_id();
    }
    return 0;
}

inline bool nas_acl_entry::is_counter_enabled () const noexcept
{
    return (_alist.find(BASE_ACL_ACTION_TYPE_SET_COUNTER) != _alist.end());
}

#endif
