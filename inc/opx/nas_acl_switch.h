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
 * \file   nas_acl_switch.h
 * \brief  NAS ACL Switch Object
 * \date   02-2015
 */

#ifndef _NAS_ACL_SWITCH_H_
#define _NAS_ACL_SWITCH_H_

#include "nas_base_utils.h"
#include "nas_base_obj.h"
#include "nas_acl_counter.h"
#include "nas_acl_entry.h"
#include "nas_acl_table.h"
#include "nas_acl_range.h"
#include "nas_udf_group.h"
#include "nas_udf_match.h"
#include "nas_udf.h"
#include "std_mutex_lock.h"
#include <map>
#include <unordered_map>
#include <vector>

struct acl_pool_id_t
{
    npu_id_t     npu_id;
    nas_obj_id_t pool_id;
};

struct pbr_entry_id_t
{
    nas_obj_id_t tbl_id;
    nas_obj_id_t entry_id;

};
#include <list>

class nas_acl_switch : public nas::base_switch_t
{
    public:
        // Generated ACL Table IDs will wrap around after this max
        static const size_t NAS_ACL_TABLE_ID_MAX = 500;
        // Generated ACL Entry IDs will wrap around after this max
        static const size_t NAS_ACL_ENTRY_ID_MAX  = 65536;

        static const size_t NAS_UDF_GROUP_ID_MAX = 16;
        static const size_t NAS_UDF_MATCH_ID_MAX = 1024;
        static const size_t NAS_UDF_ID_MAX = 1024;

        static const size_t NAS_ACL_RANGE_ID_MAX = 65536;

        ///// Typedefs ///////
        typedef std::map<nas_obj_id_t, nas_acl_table> table_list_t;
        typedef table_list_t::iterator table_iter_t;
        typedef table_list_t::const_iterator const_table_iter_t;

        typedef std::map<nas_obj_id_t, nas_acl_entry> entry_list_t;
        typedef entry_list_t::iterator entry_iter_t;
        typedef entry_list_t::const_iterator const_entry_iter_t;

        typedef std::map<nas_obj_id_t, nas_acl_counter_t> counter_list_t;

        typedef std::map<nas_obj_id_t, nas_udf_group> udf_group_list_t;
        typedef std::map<nas_obj_id_t, nas_udf_match> udf_match_list_t;
        typedef std::map<nas_obj_id_t, nas_udf> udf_list_t;

        typedef std::map<nas_obj_id_t, nas_acl_range> range_list_t;

        typedef std::vector<acl_pool_id_t> acl_pool_list_t;

        ///// Constructor ////
        nas_acl_switch (nas_obj_id_t id): nas::base_switch_t (id) {};

        ///////// Accessors ///////
        // ACL Table Get
        nas_acl_table&        get_table (nas_obj_id_t tbl_id);
        nas_acl_table*        find_table (nas_obj_id_t tbl_id) noexcept;
        nas_acl_table*        find_table_by_name(const char* tbl_name) noexcept;
        const table_list_t&   table_list () const noexcept {return _tables;}

        // ACL Entry Get
        nas_acl_entry&        get_entry (nas_obj_id_t tbl_id,
                                         nas_obj_id_t entry_id);
        nas_acl_entry*        find_entry (nas_obj_id_t tbl_id,
                                          nas_obj_id_t entry_id) noexcept;
        nas_acl_entry*        find_entry_by_name (nas_obj_id_t tbl_id,
                                                  const char* entry_name) noexcept;
        const entry_list_t&   entry_list (nas_obj_id_t tbl_id) const;

        nas_acl_counter_t&    get_counter (nas_obj_id_t tbl_id,
                                           nas_obj_id_t counter_id);
        nas_acl_counter_t*    find_counter (nas_obj_id_t tbl_id,
                                            nas_obj_id_t counter_id) noexcept;
        nas_acl_counter_t*    find_counter_by_name (nas_obj_id_t tbl_id,
                                                    const char* counter_name) noexcept;
        const counter_list_t& counter_list (nas_obj_id_t tbl_id) const;

        nas_udf_group*        find_udf_group(nas_obj_id_t udf_grp_id) noexcept;
        nas_udf_match*        find_udf_match(nas_obj_id_t udf_match_id) noexcept;
        nas_udf*              find_udf(nas_obj_id_t udf_id) noexcept;
        const udf_group_list_t& udf_group_list() const noexcept {return _udf_groups;}
        const udf_match_list_t& udf_match_list() const noexcept {return _udf_matches;}
        const udf_list_t& udf_obj_list() const noexcept {return _udf_objs;}

        nas_acl_range*        find_acl_range(nas_obj_id_t range_id) noexcept;
        const range_list_t& range_obj_list() const noexcept {return _range_objs;}

        acl_pool_id_t*         find_acl_pool(npu_id_t npu_id, nas_obj_id_t id) noexcept;
        const acl_pool_list_t& acl_pool_obj_list() const noexcept {return _cached_acl_pool_entries;}
        void                   mark_acl_pool_cache_init_done () noexcept {_nas_acl_pool_cache_init_done = true;}
        bool                   is_acl_pool_cache_init_done () const noexcept {return _nas_acl_pool_cache_init_done;}

        ///////// Modifiers //////////
        ///// ACL Table list
        nas_acl_table& save_table (nas_acl_table&& tbl_temp) noexcept;
        void remove_table (nas_obj_id_t id) noexcept;
        nas_obj_id_t alloc_table_id () {return _tableid_gen.alloc_id ();}
        bool reserve_table_id (nas_obj_id_t id);
        void release_table_id (nas_obj_id_t table_id) noexcept
        { _tableid_gen.release_id (table_id); }

        ///// ACL entry  list
        nas_acl_entry&  save_entry (nas_acl_entry&& entry_temp) noexcept;
        void remove_entry_from_table (nas_obj_id_t table_id,
                                      nas_obj_id_t entry_id) noexcept;
        nas_obj_id_t alloc_entry_id_in_table (nas_obj_id_t table_id);
        bool reserve_entry_id_in_table (nas_obj_id_t table_id, nas_obj_id_t id);
        void release_entry_id_in_table (nas_obj_id_t table_id,
                                        nas_obj_id_t entry_id) noexcept;

        ///// ACL counter  list
        nas_acl_counter_t&  save_counter (nas_acl_counter_t&& counter_temp) noexcept;
        void remove_counter_from_table (nas_obj_id_t table_id,
                                        nas_obj_id_t counter_id) noexcept;
        nas_obj_id_t alloc_counter_id_in_table (nas_obj_id_t table_id);
        bool reserve_counter_id_in_table (nas_obj_id_t table_id, nas_obj_id_t id);
        void release_counter_id_in_table (nas_obj_id_t table_id,
                                          nas_obj_id_t counter_id) noexcept;

        nas_obj_id_t alloc_udf_group_id() {return _udf_group_id_gen.alloc_id();}
        bool reserve_udf_group_id(nas_obj_id_t id) noexcept
        {return _udf_group_id_gen.reserve_id(id);}
        void release_udf_group_id(nas_obj_id_t group_id) noexcept
        {_udf_group_id_gen.release_id(group_id);}

        nas_obj_id_t alloc_udf_match_id() {return _udf_match_id_gen.alloc_id();}
        bool reserve_udf_match_id(nas_obj_id_t id) noexcept
        {return _udf_match_id_gen.reserve_id(id);}
        void release_udf_match_id(nas_obj_id_t match_id) noexcept
        {_udf_match_id_gen.release_id(match_id);}

        nas_obj_id_t alloc_udf_id() {return _udf_id_gen.alloc_id();}
        bool reserve_udf_id(nas_obj_id_t id) noexcept
        {return _udf_match_id_gen.reserve_id(id);}
        void release_udf_id(nas_obj_id_t udf_id) noexcept
        {_udf_id_gen.release_id(udf_id);}

        nas_udf_group& save_udf_group(nas_udf_group&& udf_grp) noexcept;
        void remove_udf_group(nas_obj_id_t id) noexcept;

        nas_udf_match& save_udf_match(nas_udf_match&& udf_match) noexcept;
        void remove_udf_match(nas_obj_id_t id) noexcept;

        nas_udf& save_udf(nas_udf&& udf) noexcept;
        void remove_udf(nas_obj_id_t id) noexcept;

        nas_obj_id_t alloc_acl_range_id() {return _range_id_gen.alloc_id();}
        bool reserve_acl_range_id(nas_obj_id_t id) noexcept
        {return _range_id_gen.reserve_id(id);}
        void release_acl_range_id(nas_obj_id_t range_id) noexcept
        {_range_id_gen.release_id(range_id);}

        nas_acl_range& save_acl_range(nas_acl_range&& acl_range) noexcept;
        void remove_acl_range(nas_obj_id_t id) noexcept;

        bool save_acl_pool(npu_id_t npu_id, nas_obj_id_t id) noexcept;
        void remove_acl_pool(npu_id_t npu_id, nas_obj_id_t id) noexcept;

        void delete_pbr_action_by_nh_obj (ndi_obj_id_t nh_obj_id) noexcept;
        void add_pbr_entry_to_cache(nas_obj_id_t tbl_id, nas_obj_id_t entry_id);
        void del_pbr_entry_from_cache(nas_obj_id_t tbl_id, nas_obj_id_t entry_id);

        void process_intf_acl_bind(hal_ifindex_t ifindex,
                                   npu_id_t npu_id, npu_port_t npu_port);
        void update_intf_match_bind(const nas_acl_entry& entry,
                                    const nas_acl_filter_t* old_match,
                                    const nas_acl_filter_t* new_match) noexcept;
        void update_intf_action_bind(const nas_acl_entry& entry,
                                     const nas_acl_action_t* old_action,
                                     const nas_acl_action_t* new_action) noexcept;

        void dump_rule_intf_bind(void) const noexcept;
    private:

        struct acl_table_container_t
        {
            nas::id_generator_t  _entry_id_gen {NAS_ACL_ENTRY_ID_MAX};
            entry_list_t     _acl_entries;
            nas::id_generator_t  _counter_id_gen {NAS_ACL_ENTRY_ID_MAX};
            counter_list_t     _acl_counters;
        };

        typedef std::unordered_map<nas_obj_id_t, acl_table_container_t>
                table_container_list_t;

        table_list_t            _tables;
        table_container_list_t  _table_containers;

        nas::id_generator_t          _tableid_gen {NAS_ACL_TABLE_ID_MAX};

        udf_group_list_t        _udf_groups;
        udf_match_list_t        _udf_matches;
        udf_list_t              _udf_objs;

        nas::id_generator_t     _udf_group_id_gen {NAS_UDF_GROUP_ID_MAX};
        nas::id_generator_t     _udf_match_id_gen {NAS_UDF_MATCH_ID_MAX};
        nas::id_generator_t     _udf_id_gen {NAS_UDF_ID_MAX};

        range_list_t            _range_objs;

        nas::id_generator_t     _range_id_gen {NAS_ACL_RANGE_ID_MAX};

        acl_pool_list_t         _cached_acl_pool_entries;
        bool                    _nas_acl_pool_cache_init_done = false;

        // cache content: <table-id, entry-id>
        std::vector<pbr_entry_id_t> _cached_pbr_entries;

        struct acl_rule_item_info_t {
            nas_obj_id_t table_id;
            nas_obj_id_t entry_id;
            bool is_match;
            union {
                BASE_ACL_MATCH_TYPE_t match_type;
                BASE_ACL_ACTION_TYPE_t action_type;
            };

            bool operator== (const acl_rule_item_info_t& item)
            {
                if (table_id != item.table_id || entry_id != item.entry_id ||
                    (is_match && !item.is_match) || (!is_match && item.is_match)) {
                    return false;
                }

                return is_match ? (match_type == item.match_type) :
                                  (action_type == item.action_type);
            }
        };

        using intf_acl_bind_map_t = std::unordered_map<hal_ifindex_t, std::list<acl_rule_item_info_t>>;

        intf_acl_bind_map_t     _intf_acl_bind_map;

        void add_intf_acl_bind(hal_ifindex_t ifindex, const acl_rule_item_info_t& rule_item);
        void del_intf_acl_bind(hal_ifindex_t ifindex, const acl_rule_item_info_t& rule_item);

        void compare_ifindex_list(const nas::ifindex_list_t& old_list,
                                  const nas::ifindex_list_t& new_list,
                                  nas::ifindex_list_t& del_list,
                                  nas::ifindex_list_t& add_list)
        {
            add_list = new_list;
            for (auto ifidx: old_list) {
                bool found = false;
                for (auto itor = add_list.begin(); itor != add_list.end();)
                {
                    if (ifidx == *itor) {
                        itor = add_list.erase(itor);
                        found = true;
                        break;
                    } else {
                        ++ itor;
                    }
                }
                if (!found) {
                    del_list.push_back(ifidx);
                }
            }
        }
};

std_mutex_type_t& nas_acl_intf_bind_mutex() noexcept;

#endif
