/*
 * Copyright (c) 2018 Dell Inc.
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
 * \brief  This file contains CPS related ACL Entry Action functionality
 * \date   03-2015
 * \author Mukesh MV & Ravikumar Sivasankar
 */

#include "event_log.h"
#include "std_error_codes.h"
#include "nas_acl_log.h"
#include "nas_acl_cps.h"
#include "nas_base_utils.h"

// Common function called for both Full ACL Entry update and Incremental update
// In the case of Full ACL Entry update the parent_list will already have
//   - ACTION-List-Attr . Action-ListIndex
// In the case of Incremental update the parent_list will be empty
//
// This function will add the Action-Value-Attr to the parent_list hieraerchy.
//
void nas_acl_set_action_attr (const cps_api_object_t     obj,
                              nas_acl_entry&             entry,
                              BASE_ACL_ACTION_TYPE_t     action_type_val,
                              nas::attr_list_t&          parent_attr_id_list,
                              bool                       reset)
{
    nas_acl_common_data_list_t common_data_list;

    auto map_kv = nas_acl_get_action_map().find (action_type_val);

    if (map_kv == nas_acl_get_action_map().end ()) {
        throw nas::base_exception {NAS_ACL_E_FAIL, __PRETTY_FUNCTION__,
                                   std::string {"Could not find action ("} +
                                   nas_acl_action_t::type_name (action_type_val)
                                    + " )"+ std::to_string(action_type_val) };
    }

    const nas_acl_action_info_t& map_info = map_kv->second;
    nas_acl_action_t action {action_type_val};

    if (map_info.val.data_type != NAS_ACL_DATA_NONE) {

        parent_attr_id_list.push_back (map_info.val.attr_id);
        common_data_list.clear ();

        auto common_data_list =
            nas_acl_copy_data_from_obj (obj, parent_attr_id_list, map_info.val,
                                        map_info.child_list, map_info.name);

        (action.*(map_info.set_fn)) (common_data_list);
    }

    entry.add_action (action, reset);
}

void nas_acl_set_action_list (const cps_api_object_t     obj,
                              const cps_api_object_it_t& it,
                              nas_acl_entry&             entry)
{
    /*
     * Encoding of ACL Entry Action parameters, with the following
     * sample action parameters:
     *   1. Ingress Mirroring
     *   2. Redirect Port
     *   3. Forward
     *
     * ------------------------------------------------------------------------
     * | Type : BASE_ACL_ENTRY_ACTION  (ACTION-List-Attr)                     |
     * | Len  : Length of Val                                                 |
     * | Val  ----------------------------------------------------------------|
     * |      | Type : 'list_index' = 0                                       |
     * |      | Len  : Length of Val                                          |
     * |      | Val  ---------------------------------------------------------|
     * |      |      | Type : BASE_ACL_ENTRY_ACTION_TYPE                      |
     * |      |      | Len  : Length of Val                                   |
     * |      |      | Val  : BASE_ACL_ACTION_TYPE_SET_POLICER     <--        |
     * |      |      |                                               |        |
     * |      |      |                                  --------------------  |
     * |      |      |                                  |'action_type_val' |  |
     * |      |      |                                  --------------------  |
     * |      |      |--------------------------------------------------------|
     * |      |      | Type : BASE_ACL_ENTRY_ACTION_POLICER_VALUE  <--        |
     * |      |      |                                               |        |
     * |      |      |                             -------------------------- |
     * |      |      |                             |'action_map.val.attr_id'| |
     * |      |      |                             -------------------------- |
     * |      |      | Len  : Length of Val                                   |
     * |      |      | Val  --------------------------------------------------|
     * |      |      |      | Type : BASE_ACL_ENTRY_ACTION_POLICER_VALUE_INDEX|
     * |      |      |      | Len  : Length of Val                            |
     * |      |      |      | Val  : <mirror-id>                              |
     * |      |      |      |                                                 |
     * |      |      |      | Type : BASE_ACL_ENTRY_ACTION_POLICER_VALUE_DATA |
     * |      |      |      | Len  : Length of Val                            |
     * |      |      |      | Val  : <mirror-blob-data>                       |
     * |      |      |      --------------------------------------------------|
     * |      |      |                                                        |
     * |      |      ---------------------------------------------------------|
     * |      |                                                               |
     * |      ----------------------------------------------------------------|
     * |      | Type : 'list_index' = 1                                       |
     * |      | Len  : Length of Val                                          |
     * |      | Val  ---------------------------------------------------------|
     * |      |      | Type : BASE_ACL_ENTRY_ACTION_TYPE                      |
     * |      |      | Len  : Length of Val                                   |
     * |      |      | Val  : BASE_ACL_ACTION_TYPE_FORWARD   <----            |
     * |      |      |                                           |            |
     * |      |      |                                  -------------------   |
     * |      |      |                                 |'action_type_val' |   |
     * |      |      |                                  -------------------   |
     * |      |      |     NOTE: There is no further data for this action.    |
     * |      |      ---------------------------------------------------------|
     * |      |                                                               |
     * |      ----------------------------------------------------------------|
     * |      |                                                               |
     * |      |                           ...                                 |
     * |      |                                                               |
     * |      ----------------------------------------------------------------|
     * |      | Type : 'list_index' = N                                       |
     * |      | Len  : Length of Val                                          |
     * |      | Val  ---------------------------------------------------------|
     * |      |      | Type : BASE_ACL_ENTRY_ACTION_TYPE                      |
     * |      |      | Len  : Length of Val                                   |
     * |      |      | Val  : BASE_ACL_ACTION_TYPE_REDIRECT_PORT      <--     |
     * |      |      |                                                  |     |
     * |      |      |                                 --------------------   |
     * |      |      |                                 |'action_type_val' |   |
     * |      |      |                                 --------------------   |
     * |      |      |--------------------------------------------------------|
     * |      |      | Type : BASE_ACL_ENTRY_ACTION_REDIRECT_PORT_VALUE       |
     * |      |      |                                              ^         |
     * |      |      |                                              |         |
     * |      |      |                             -------------------------- |
     * |      |      |                             |'action_map.val.attr_id'| |
     * |      |      |                             -------------------------- |
     * |      |      | Len  : Length of Val                                   |
     * |      |      | Val  : <if-index>                                      |
     * |      |      ---------------------------------------------------------|
     * |      |                                                               |
     * |      ----------------------------------------------------------------|
     * |                                                                      |
     * ------------------------------------------------------------------------
     */

    BASE_ACL_ACTION_TYPE_t     action_type_val;
    cps_api_object_it_t        it_action_list = it;
    cps_api_attr_id_t          list_index = 0;
    nas::attr_list_t           parent_attr_id_list;
    nas_acl_common_data_list_t common_data_list;

    // Parent attr list to build attr hierarchy
    //  - ACTION-List-Attr . Action-ListIndex . Action-Value-Attr . Action-Value-Child-Attr
    parent_attr_id_list.reserve(NAS_ACL_MAX_ATTR_DEPTH);

    //  Of this the following hierarchy is filled in this function
    //  - ACTION-List-Attr . Action-ListIndex

    for (cps_api_object_it_inside (&it_action_list);
         cps_api_object_it_valid (&it_action_list);
         cps_api_object_it_next (&it_action_list)) {

        parent_attr_id_list.clear ();
        parent_attr_id_list.push_back (BASE_ACL_ENTRY_ACTION);

        list_index = cps_api_object_attr_id (it_action_list.attr);

        parent_attr_id_list.push_back (list_index);

        cps_api_object_it_t it_action_attr = it_action_list;
        cps_api_object_it_inside (&it_action_attr);
        if (!cps_api_object_it_valid (&it_action_attr)) {
            throw nas::base_exception {NAS_ACL_E_MISSING_ATTR, __PRETTY_FUNCTION__,
                                       "Missing list container for ACTION in object"};
        }

        bool is_dupl;
        auto attr_action_type = nas_acl_get_attr (it_action_attr,
                                                 BASE_ACL_ENTRY_ACTION_TYPE, &is_dupl);

        if (attr_action_type == NULL) {
            throw nas::base_exception {NAS_ACL_E_MISSING_ATTR, __PRETTY_FUNCTION__,
                                       "Missing ACTION_TYPE attribute"};
        }
        if (is_dupl) {
            throw nas::base_exception {NAS_ACL_E_DUPLICATE, __PRETTY_FUNCTION__,
                                       "Duplicate ACTION_TYPE attribute"};
        }

        action_type_val = (BASE_ACL_ACTION_TYPE_t)
            cps_api_object_attr_data_u32 (attr_action_type);

        NAS_ACL_LOG_DETAIL ("action_type_val: %d (%s)", action_type_val,
                            nas_acl_action_t::type_name (action_type_val));

        nas_acl_set_action_attr (obj, entry, action_type_val,
                                 parent_attr_id_list, true);
    }
}

bool nas_acl_fill_action_attr (cps_api_object_t obj,
                               const nas_acl_action_t& action,
                               BASE_ACL_ACTION_TYPE_t  action_type_val,
                               nas::attr_list_t        parent_attr_id_list)
{
    nas_acl_common_data_list_t common_data_list;

    auto map_kv = nas_acl_get_action_map().find (action_type_val);

    if (map_kv == nas_acl_get_action_map().end ()) {
        return false;
    }

    const nas_acl_action_info_t& map_info = map_kv->second;

    if (map_info.val.data_type != NAS_ACL_DATA_NONE) {
        (action.*(map_info.get_fn)) (common_data_list);

        parent_attr_id_list.push_back (map_info.val.attr_id);

        if (!nas_acl_copy_data_to_obj (obj, parent_attr_id_list, map_info.val,
                                       map_info.child_list, common_data_list)) {
            NAS_ACL_LOG_ERR ("nas_acl_copy_data_to_obj() failed for Match type %d (%s)",
                              action_type_val, nas_acl_action_t::type_name (action_type_val));
            return false;
        }
    }

    return true;
}

bool
nas_acl_fill_action_attr_list (cps_api_object_t obj, const nas_acl_entry& entry)
{
    nas::attr_list_t           parent_attr_id_list;
    cps_api_attr_id_t          list_index = 0;
    BASE_ACL_ACTION_TYPE_t     action_type_val;
    nas_acl_common_data_list_t common_data_list;

    // Parent attr list to build attr hierarchy
    //  - ACTION-List-Attr . Action-ListIndex . Action-Value-Attr . Action-Value-Child-Attr
    parent_attr_id_list.reserve(NAS_ACL_MAX_ATTR_DEPTH);

    //  Of this the following hierarchy is filled in this function
    //  - ACTION-List-Attr . Action-ListIndex

    for (const auto& action_kv: entry.get_action_list ()) {

        action_type_val = action_kv.second.action_type ();

        auto map_kv = nas_acl_get_action_map().find (action_type_val);

        if (map_kv == nas_acl_get_action_map().end ()) {
            return false;
        }

        const nas_acl_action_info_t& map_info = map_kv->second;

        parent_attr_id_list.clear ();

        parent_attr_id_list.push_back (BASE_ACL_ENTRY_ACTION);
        parent_attr_id_list.push_back (list_index);
        parent_attr_id_list.push_back (BASE_ACL_ENTRY_ACTION_TYPE);

        if (!cps_api_object_e_add (obj,
                                   parent_attr_id_list.data (),
                                   parent_attr_id_list.size (),
                                   cps_api_object_ATTR_T_U32,
                                   &action_type_val,
                                   sizeof (uint32_t))) {
            return false;
        }
        parent_attr_id_list.pop_back ();

        if (map_info.val.data_type != NAS_ACL_DATA_NONE) {
           if (!nas_acl_fill_action_attr (obj, action_kv.second,
                                             action_type_val, parent_attr_id_list))
           {
               NAS_ACL_LOG_ERR ("nas_acl_copy_data_to_obj() failed for Match type %d (%s)",
                                action_type_val, nas_acl_action_t::type_name (action_type_val));
               return false;
           }
        }

        list_index++;
    }

    return true;
}
