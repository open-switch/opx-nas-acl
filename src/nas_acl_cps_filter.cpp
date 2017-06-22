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
 * \file   nas_acl_cps_entry.cpp
 * \brief  This file contains CPS related ACL Entry functionality
 * \date   03-2015
 * \author Mukesh MV & Ravikumar Sivasankar
 */
#include "event_log.h"
#include "std_error_codes.h"
#include "nas_acl_log.h"
#include "nas_acl_cps.h"
#include "nas_base_utils.h"
#include <netinet/in.h>

// Common function called for both Full ACL Entry update and Incremental update
// In the case of Full ACL Entry update the parent_list will already have
//   - MATCH-List-Attr . Match-ListIndex
// In the case of Incremental update the parent_list will be empty
//
// This function will add the Match-Value-Attr to the parent_list hieraerchy.
//
void nas_acl_set_match_attr (const cps_api_object_t     obj,
                             nas_acl_entry&             entry,
                             BASE_ACL_MATCH_TYPE_t      match_type_val,
                             nas::attr_list_t           parent_attr_id_list,
                             bool                       reset)
{

    auto map_kv = nas_acl_get_filter_map().find (match_type_val);

    if (map_kv == nas_acl_get_filter_map().end ()) {
        throw nas::base_exception {NAS_ACL_E_ATTR_VAL, __PRETTY_FUNCTION__,
                                   std::string {"Could not find filter ("} +
                                   nas_acl_filter_t::type_name (match_type_val)
                                    + " ) "+ std::to_string(match_type_val) };
    }

    const nas_acl_filter_info_t& map_info = map_kv->second;
    nas_acl_filter_t filter {&entry.get_table(), match_type_val};

    if (map_info.val.data_type != NAS_ACL_DATA_NONE) {

        parent_attr_id_list.push_back (map_info.val.attr_id);

        auto common_data_list =
            nas_acl_copy_data_from_obj (obj, parent_attr_id_list, map_info.val,
                                        map_info.child_list, map_info.name);

        (filter.*(map_info.set_fn)) (common_data_list);
    }
    entry.add_filter (filter, reset);
}

void nas_acl_set_match_list (const cps_api_object_t     obj,
                             const cps_api_object_it_t& it,
                             nas_acl_entry&             entry)
{
    /*
     * Encoding of ACL Entry Match parameters, with the following
     * sample match parameters:
     *   1. Source IPv4 Address
     *   2. In Port List
     *
     * ------------------------------------------------------------------------
     * | Type : BASE_ACL_ENTRY_MATCH (MATCH-List-Attr)                        |
     * | Len  : Length of Val                                                 |
     * | Val  ----------------------------------------------------------------|
     * |      | Type : 'list_index' = 0                                       |
     * |      | Len  : Length of Val                                          |
     * |      | Val  ---------------------------------------------------------|
     * |      |      | Type : BASE_ACL_ENTRY_MATCH_TYPE                       |
     * |      |      | Len  : Length of Val                                   |
     * |      |      | Val  : BASE_ACL_ENTRY_MATCH_SRC_IP    <----            |
     * |      |      |                                           |            |
     * |      |      |                                  -------------------   |
     * |      |      |                                  |'match_type_val' |   |
     * |      |      |                                  -------------------   |
     * |      |      |--------------------------------------------------------|
     * |      |      | Type : BASE_ACL_ENTRY_MATCH_SRC_IP_VALUE <---          |
     * |      |      |                                             |          |
     * |      |      |                              ------------------------- |
     * |      |      |                             |'filter_map.val.attr_id'| |
     * |      |      | Len  : Length of Val         ------------------------- |
     * |      |      | Val  --------------------------------------------------|
     * |      |      |      | Type : BASE_ACL_ENTRY_MATCH_SRC_IP_VALUE_ADDR   |
     * |      |      |      | Len  : Length of Val                            |
     * |      |      |      | Val  : <ipv4-addr>                              |
     * |      |      |      |                                                 |
     * |      |      |      | Type : BASE_ACL_ENTRY_MATCH_SRC_IP_VALUE_MASK   |
     * |      |      |      | Len  : Length of Val                            |
     * |      |      |      | Val  : <ipv4-addr>                              |
     * |      |      |      --------------------------------------------------|
     * |      |      |                                                        |
     * |      |      ---------------------------------------------------------|
     * |      |                                                               |
     * |      ----------------------------------------------------------------|
     * |      |                           ...                                 |
     * |      ----------------------------------------------------------------|
     * |      | Type : 'list_index' = N                                       |
     * |      | Len  : Length of Val                                          |
     * |      | Val  ---------------------------------------------------------|
     * |      |      | Type : BASE_ACL_ENTRY_MATCH_TYPE                       |
     * |      |      | Len  : Length of Val                                   |
     * |      |      | Val  : BASE_ACL_ENTRY_MATCH_IN_PORTS  <----            |
     * |      |      |                                           |            |
     * |      |      |                                  -------------------   |
     * |      |      |                                  |'match_type_val' |   |
     * |      |      |                                  -------------------   |
     * |      |      |--------------------------------------------------------|
     * |      |      | Type : BASE_ACL_ENTRY_MATCH_IN_PORTS_VALUE <--         |
     * |      |      |                                              |         |
     * |      |      |                              ------------------------- |
     * |      |      |                             |'filter_map.val.attr_id'| |
     * |      |      | Len  : Length of Val         ------------------------- |
     * |      |      | Val  : <if-index>                                      |
     * |      |      |--------------------------------------------------------|
     * |      |      |                         ...                            |
     * |      |      |--------------------------------------------------------|
     * |      |      | Type : BASE_ACL_ENTRY_MATCH_IN_PORTS_VALUE             |
     * |      |      | Len  : Length of Val                                   |
     * |      |      | Val  : <if-index>                                      |
     * |      |      ---------------------------------------------------------|
     * |      |                                                               |
     * |      ----------------------------------------------------------------|
     * |                                                                      |
     * ------------------------------------------------------------------------
     */

    BASE_ACL_MATCH_TYPE_t      match_type_val;
    cps_api_object_it_t        it_match_list = it;
    cps_api_attr_id_t          list_index = 0;
    nas::attr_list_t           parent_attr_id_list;

    // Parent attr list to build attr hierarchy
    //  - MATCH-List-Attr . Match-ListIndex . Match-Value-Attr . Match-Value-Child-Attr
    parent_attr_id_list.reserve (NAS_ACL_MAX_ATTR_DEPTH);

    //  Of this the following hierarchy is filled in this function
    //  - MATCH-List-Attr . Match-ListIndex

    for (cps_api_object_it_inside (&it_match_list);
         cps_api_object_it_valid (&it_match_list);
         cps_api_object_it_next (&it_match_list)) {

        parent_attr_id_list.clear ();
        parent_attr_id_list.push_back (BASE_ACL_ENTRY_MATCH);

        list_index = cps_api_object_attr_id (it_match_list.attr);

        parent_attr_id_list.push_back (list_index);

        cps_api_object_it_t it_match_attr = it_match_list;
        cps_api_object_it_inside (&it_match_attr);
        if (!cps_api_object_it_valid (&it_match_attr)) {
            throw nas::base_exception {NAS_ACL_E_MISSING_ATTR, __PRETTY_FUNCTION__,
                                       "Missing list container for MATCH in object"};
        }

        bool is_dupl;
        auto attr_match_type = nas_acl_get_attr (it_match_attr,
                                                 BASE_ACL_ENTRY_MATCH_TYPE, &is_dupl);

        if (attr_match_type == NULL) {
            throw nas::base_exception {NAS_ACL_E_MISSING_ATTR, __PRETTY_FUNCTION__,
                                       "Missing MATCH_TYPE attribute"};
        }
        if (is_dupl) {
            throw nas::base_exception {NAS_ACL_E_DUPLICATE, __PRETTY_FUNCTION__,
                                       "Duplicate MATCH_TYPE attribute"};
        }

        match_type_val = (BASE_ACL_MATCH_TYPE_t)
            cps_api_object_attr_data_u32 (attr_match_type);

        NAS_ACL_LOG_DETAIL ("match_type_val: %d (%s)", match_type_val,
                            nas_acl_filter_t::type_name (match_type_val));

        nas_acl_set_match_attr (obj, entry, match_type_val,
                                parent_attr_id_list, true);
    }
}

bool nas_acl_fill_match_attr (cps_api_object_t obj,
                              const nas_acl_filter_t& filter,
                              BASE_ACL_MATCH_TYPE_t      match_type_val,
                              nas::attr_list_t           parent_attr_id_list)
{
    nas_acl_common_data_list_t common_data_list;

    auto map_kv = nas_acl_get_filter_map().find (match_type_val);

    if (map_kv == nas_acl_get_filter_map().end ()) {
        return false;
    }

    const nas_acl_filter_info_t& map_info = map_kv->second;

    if (map_info.val.data_type != NAS_ACL_DATA_NONE) {
        (filter.*(map_info.get_fn)) (common_data_list);

        parent_attr_id_list.push_back (map_info.val.attr_id);

        if (!nas_acl_copy_data_to_obj (obj, parent_attr_id_list, map_info.val,
                                       map_info.child_list, common_data_list)) {
            NAS_ACL_LOG_ERR ("nas_acl_copy_data_to_obj() failed for Match type %d (%s)",
                              match_type_val, nas_acl_filter_t::type_name (match_type_val));
            return false;
        }
    }

    return true;
}

bool
nas_acl_fill_match_attr_list (cps_api_object_t obj, const nas_acl_entry& entry)
{
    nas::attr_list_t           parent_attr_id_list;
    cps_api_attr_id_t          list_index = 0;
    BASE_ACL_MATCH_TYPE_t      match_type_val;
    nas_acl_common_data_list_t common_data_list;

    // Parent attr list to build attr hierarchy
    //  - MATCH-List-Attr . Match-ListIndex . Match-Value-Attr . Match-Value-Child-Attr
    parent_attr_id_list.reserve (NAS_ACL_MAX_ATTR_DEPTH);

    //  Of this the following hierarchy is filled in this function
    //  - MATCH-List-Attr . Match-ListIndex

    for (const auto& filter_kv: entry.get_filter_list ()) {

        match_type_val = filter_kv.second.filter_type ();

        parent_attr_id_list.clear ();

        parent_attr_id_list.push_back (BASE_ACL_ENTRY_MATCH);
        parent_attr_id_list.push_back (list_index);
        parent_attr_id_list.push_back (BASE_ACL_ENTRY_MATCH_TYPE);

        if (!cps_api_object_e_add (obj,
                                   parent_attr_id_list.data (),
                                   parent_attr_id_list.size (),
                                   cps_api_object_ATTR_T_U32,
                                   &match_type_val,
                                   sizeof (uint32_t))) {
            NAS_ACL_LOG_ERR ("cps_api_object_e_add failed for Match type %d (%s)",
                             match_type_val, nas_acl_filter_t::type_name (match_type_val));
            return false;
        }
        parent_attr_id_list.pop_back ();

        if (!nas_acl_fill_match_attr (obj, filter_kv.second,
                                      match_type_val, parent_attr_id_list))
        {
            NAS_ACL_LOG_ERR ("nas_acl_copy_data_to_obj() failed for Match type %d (%s)",
                             match_type_val, nas_acl_filter_t::type_name (match_type_val));
            return false;
        }

        list_index++;
    }

    return true;
}
