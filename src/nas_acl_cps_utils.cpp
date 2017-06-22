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
 * \brief  This file contains CPS related utility functions
 * \date   05-2015
 * \author Mukesh MV & Ravikumar Sivasankar
 */

#include "event_log.h"
#include "std_error_codes.h"
#include "nas_acl_log.h"
#include "nas_acl_cps.h"
#include "nas_ndi_obj_id_table.h"
#include "nas_vlan_consts.h"
#include "nas_qos_consts.h"
#include "nas_acl_utl.h"

static bool _add_data_to_obj (cps_api_object_t       obj,
                              nas::attr_list_t&      attr_list,
                              nas_acl_common_data_t& in_common_data,
                              size_t                 expected_size,
                              NAS_ACL_DATA_TYPE_t    obj_data_type)
{
    cps_api_object_ATTR_TYPE_t  cps_attr_type;
    void                       *p_data;
    size_t                      size;

    if (obj_data_type == NAS_ACL_DATA_OPAQUE) {
        return nas::ndi_obj_id_table_cps_serialize (in_common_data.ndi_obj_id_table,
                                                    obj, attr_list.data(),
                                                    attr_list.size());
    }

    switch (obj_data_type) {

        case NAS_ACL_DATA_U8:
            p_data        = &in_common_data.u8;
            size          = sizeof (uint8_t);
            cps_attr_type = cps_api_object_ATTR_T_BIN;
            break;

        case NAS_ACL_DATA_U16:
            p_data        = &in_common_data.u16;
            size          = sizeof (uint16_t);
            cps_attr_type = cps_api_object_ATTR_T_U16;
            break;

        case NAS_ACL_DATA_U32:
            p_data        = &in_common_data.u32;
            size          = sizeof (uint32_t);
            cps_attr_type = cps_api_object_ATTR_T_U32;
            break;

        case NAS_ACL_DATA_U64:
            p_data        = &in_common_data.u64;
            size          = sizeof (uint64_t);
            cps_attr_type = cps_api_object_ATTR_T_U64;
            break;

        case NAS_ACL_DATA_OBJ_ID:
            static_assert (sizeof (nas_obj_id_t) == sizeof (uint64_t),
                           "NAS Object ID is not 64 bit");
            p_data        = &in_common_data.obj_id;
            size          = sizeof (nas_obj_id_t);
            cps_attr_type = cps_api_object_ATTR_T_U64;
            break;

        case NAS_ACL_DATA_IFINDEX:
            p_data        = &in_common_data.ifindex;
            size          = sizeof (uint32_t);
            cps_attr_type = cps_api_object_ATTR_T_U32;
            break;

        case NAS_ACL_DATA_IFNAME:
        {
            char if_name[HAL_IF_NAME_SZ];
            if (cps_api_interface_if_index_to_name(in_common_data.ifindex,
                        if_name, sizeof(if_name)) == NULL) {
                NAS_ACL_LOG_ERR ("Invalid interface index %d",
                        in_common_data.ifindex);
                return false;
            }
            auto& bytes = in_common_data.bytes;
            bytes.insert(bytes.begin(), if_name, if_name + strlen(if_name));
            p_data = bytes.data();
            size = bytes.size();
            cps_attr_type = cps_api_object_ATTR_T_BIN;
            break;
        }

        case NAS_ACL_DATA_BIN:
            p_data        = in_common_data.bytes.data();
            size          = in_common_data.bytes.size();
            cps_attr_type = cps_api_object_ATTR_T_BIN;
            break;

        default:
            NAS_ACL_LOG_ERR ("Unknown data type %d", obj_data_type);
            return false;
    }

    if (size == 0) {
        // size equal to 0 means data is optional and should not be
        // added to object
        return true;
    }

    if ((expected_size != 0) && (expected_size < size)) {
        NAS_ACL_LOG_ERR ("Size mismatch. expected_size: %ld, filled size: %ld",
                         expected_size, size);

        return false;
    }

    if (cps_api_object_e_add (obj, attr_list.data(), attr_list.size(),
                              cps_attr_type, p_data, size) != true) {
        NAS_ACL_LOG_ERR ("CPS Add failed");
        return false;
    }

    return true;
}

static bool _add_child_attrs_to_obj (cps_api_object_t               obj,
                                     nas::attr_list_t&              parent_list,
                                     const nas_acl_map_data_list_t& child_list,
                                     nas_acl_common_data_list_t&    common_data_list,
                                     uint_t                         start_index)
{
    for (auto data_info: child_list) {

        parent_list.push_back (data_info.attr_id);

        if (!_add_data_to_obj (obj, parent_list, common_data_list.at (start_index),
                               data_info.data_len, data_info.data_type)) {
            return false;
        }

        /* Remove the processed child attr id */
        parent_list.pop_back ();
        start_index++;
    }
    return true;
}

static bool _add_child_list_to_obj (cps_api_object_t               obj,
                                    nas::attr_list_t&              parent_list,
                                    const nas_acl_map_data_list_t& child_list,
                                    nas_acl_common_data_list_t&    common_data_list)
{
    const uint_t elem_per_obj = child_list.size();
    uint_t num_objs = common_data_list.size()/elem_per_obj;

    if (num_objs == 0) {
        NAS_ACL_LOG_ERR ("Expected multiple of %d items but got %ld items",
                         elem_per_obj, common_data_list.size());
        return false;
    }

    for (uint_t iter_obj=0; iter_obj<num_objs; iter_obj++) {
        auto elem_num = iter_obj * elem_per_obj;

        // Inner List index
        parent_list.push_back (iter_obj);
        if (!_add_child_attrs_to_obj (obj, parent_list, child_list,
                                 common_data_list, elem_num)) {
            return false;
        }
        parent_list.pop_back ();
    }
    return true;
}

static bool
_copy_non_iflist_data_to_obj (cps_api_object_t               obj,
                              nas::attr_list_t&              parent_list,
                              const nas_acl_map_data_t&      val_info,
                              const nas_acl_map_data_list_t& child_list,
                              nas_acl_common_data_list_t&    common_data_list)
{
    // Full ACL Entry Get -
    // Packing list of Filter/Action value into a CPS obj would require the
    //  following attr hierarchy
    //  - MATCH/ACTION-List-Attr . ListIndex . Match/Action-Value-Attr . Match/Action-Value-Child-Attr
    //
    // Of this the following is already filled by caller in parent_list
    //  - MATCH/ACTION-List-Attr . ListIndex . Match/Action-Value-Attr

    // Specific Filter or Action Get -
    // Packing single Filter/Action value into a CPS obj would require the
    //  following attr hierarchy
    //      - Match/Action-Value-Attr . Match/Action-Value-Child-Attr
    //
    // Of this the following is already filled by caller in parent_list
    //  - Match/Action-Value-Attr

    // In either case this function is ONLY responsible for the child attributes
    // within a particular Match or Action Value

    if (val_info.data_type == NAS_ACL_DATA_EMBEDDED_LIST) {
        return _add_child_list_to_obj (obj, parent_list, child_list, common_data_list);
    }

    if (val_info.data_type == NAS_ACL_DATA_EMBEDDED) {

        if (common_data_list.size () != child_list.size ()) {
            NAS_ACL_LOG_ERR ("Expected %ld items but got %ld items",
                             child_list.size(), common_data_list.size());
            return false;
        }

        return _add_child_attrs_to_obj (obj, parent_list, child_list,
                                        common_data_list, 0);
    }

    constexpr int non_embedded_data_list_size = 1;

    if (common_data_list.size () < non_embedded_data_list_size) {
        NAS_ACL_LOG_ERR ("Expected %d items but got %ld items",
                         non_embedded_data_list_size, common_data_list.size());
        return false;
    }

    if (!_add_data_to_obj (obj, parent_list, common_data_list.at (0),
                           val_info.data_len, val_info.data_type)) {
        return false;
    }

    return true;
}

static bool
_copy_iflist_data_to_obj (cps_api_object_t            obj,
                          nas::attr_list_t&           parent_list,
                          nas_acl_common_data_list_t& common_data_list,
                          bool                        use_ifname)
{
    static const int  common_data_list_size = 1;
    char intf_name[HAL_IF_NAME_SZ + 1];
    const void *attr_data;
    size_t attr_len;

    if (common_data_list.size () != common_data_list_size) {
        return false;
    }

    for (auto if_index: common_data_list.at(0).ifindex_list) {

        if (use_ifname) {
            if(cps_api_interface_if_index_to_name(if_index, intf_name,
                    sizeof(intf_name)) == NULL) {
                NAS_ACL_LOG_ERR ("Invalid interface index %d", if_index);
                continue;
            }
            attr_data = intf_name;
            attr_len = strlen(intf_name) + 1;
        } else {
            attr_data = &if_index;
            attr_len = sizeof(uint32_t);
        }

        if (!cps_api_object_e_add (obj,
                                   parent_list.data (),
                                   parent_list.size (),
                                   use_ifname ? cps_api_object_ATTR_T_BIN :
                                                cps_api_object_ATTR_T_U32,
                                   attr_data, attr_len)) {
            return false;
        }
    }

    return true;
}

static nas_acl_common_data_t _cps_wr_attr_data  (cps_api_object_attr_t  attr_val,
                                                 NAS_ACL_DATA_TYPE_t    obj_data_type,
                                                 size_t                 attr_len,
                                                 const std::string&     sub_obj_name)
{
    nas_acl_common_data_t  out_common_data {};

    switch (obj_data_type) {

        case NAS_ACL_DATA_U8:
            out_common_data.u8 = *((uint8_t *) cps_api_object_attr_data_bin (attr_val));
            break;

        case NAS_ACL_DATA_U16:
            out_common_data.u16 = cps_api_object_attr_data_u16 (attr_val);
            break;

        case NAS_ACL_DATA_U32:
            out_common_data.u32 = cps_api_object_attr_data_u32 (attr_val);
            break;

        case NAS_ACL_DATA_U64:
            out_common_data.u64 = cps_api_object_attr_data_u64 (attr_val);
            break;

        case NAS_ACL_DATA_OBJ_ID:
            static_assert (sizeof (nas_obj_id_t) == sizeof (uint64_t),
                            "NAS Object ID is not 64 bit");
            out_common_data.obj_id = cps_api_object_attr_data_u64 (attr_val);
            break;

        case NAS_ACL_DATA_IFINDEX:
            out_common_data.ifindex = cps_api_object_attr_data_u32 (attr_val);
            break;

        case NAS_ACL_DATA_IFNAME:
        {
            char *if_name = (char *) cps_api_object_attr_data_bin (attr_val);
            int ifindex = cps_api_interface_name_to_if_index(if_name);
            if (ifindex == 0) {
                throw nas::base_exception {NAS_ACL_E_ATTR_VAL, __PRETTY_FUNCTION__,
                                           "Invalid interface name"};
            }
            out_common_data.ifindex = ifindex;
            break;
        }

        case NAS_ACL_DATA_BIN:
        {
            auto data_p = (uint8_t *) cps_api_object_attr_data_bin (attr_val);
            auto& bytes = out_common_data.bytes;
            bytes.insert (bytes.begin(), data_p, data_p+attr_len);
            break;
        }

        case NAS_ACL_DATA_NONE:
            break;

        default:
            throw nas::base_exception { NAS_ACL_E_FAIL, __PRETTY_FUNCTION__,
                    std::string {"Failed to extract "} + sub_obj_name
                    + "Invalid data type " + std::to_string (obj_data_type)};
    }

    return out_common_data;
}

// Fill Optional mask if not provided by setting all bits to 1
static nas_acl_common_data_t _fill_optional_attr (const nas_acl_map_data_t&  val_info,
                                                  const std::string& sub_obj_name)
{
    nas_acl_common_data_t     out_common_data {};

    switch (val_info.data_type) {

        case NAS_ACL_DATA_U8:
            if (val_info.range.max != 0) {
                out_common_data.u8 = val_info.range.max;
            } else {
                out_common_data.u8 = UINT8_MAX;
            }
            break;

        case NAS_ACL_DATA_U16:
            if (val_info.range.max != 0) {
                out_common_data.u16 = val_info.range.max;
            } else {
                out_common_data.u16 = UINT16_MAX;
            }
            break;

        case NAS_ACL_DATA_U32:
            if (val_info.range.max != 0) {
                out_common_data.u32 = val_info.range.max;
            } else {
                out_common_data.u32 = UINT32_MAX;
            }
            break;

        case NAS_ACL_DATA_U64:
            out_common_data.u64 = UINT64_MAX;
            break;

        case NAS_ACL_DATA_BIN:
        {
            auto& bytes = out_common_data.bytes;
            bytes.insert (bytes.begin(), val_info.data_len, 0xff);
            break;
        }
        default:
            throw nas::base_exception { NAS_ACL_E_FAIL, __PRETTY_FUNCTION__,
                std::string {"Failed to extract "} + sub_obj_name
                + ": Optional Attribute " + std::to_string (val_info.attr_id)
                + ": Unsupported type " + nas_acl_obj_data_type_to_str (val_info.data_type)
            };
    }

    return out_common_data;
}

static bool _validate_range (const nas_acl_map_data_t&  val_info,
                             const nas_acl_common_data_t&   out_common_data)
{
    if (val_info.range.max == 0) {
        // No range specified
        return true;
    }

    switch (val_info.data_type) {

        case NAS_ACL_DATA_U8:
            if (out_common_data.u8 > val_info.range.max ||
                out_common_data.u8 < val_info.range.min)
                return false;
            break;

        case NAS_ACL_DATA_U16:
            if (out_common_data.u16 > val_info.range.max ||
                out_common_data.u16 < val_info.range.min)
                return false;
            break;

        case NAS_ACL_DATA_U32:
            if (out_common_data.u32 > val_info.range.max ||
                out_common_data.u32 < val_info.range.min)
                return false;
            break;

        default:
            throw nas::base_exception { NAS_ACL_E_FAIL, __PRETTY_FUNCTION__,
                + ": Attribute " + std::to_string (val_info.attr_id)
                + ": Unsupported range validation type " +
                nas_acl_obj_data_type_to_str (val_info.data_type)
            };
    }

    return true;
}

static nas_acl_common_data_t _get_data_from_obj (cps_api_object_t           obj,
                                                 nas::attr_list_t&          attr_list,
                                                 const nas_acl_map_data_t&  data_info,
                                                 const std::string&         sub_obj_name)
{
    auto obj_data_type   = data_info.data_type;

    if (obj_data_type == NAS_ACL_DATA_OPAQUE) {
        nas_acl_common_data_t  common_data {};

        if (nas::ndi_obj_id_table_cps_unserialize (common_data.ndi_obj_id_table,
                                                   obj, attr_list.data(),
                                                   attr_list.size())) {
            return common_data;
        } else {
            throw nas::base_exception { NAS_ACL_E_MISSING_ATTR, __PRETTY_FUNCTION__,
                std::string {"Failed to extract "} + sub_obj_name
                + ": Missing Opaque Attribute " + std::to_string (data_info.attr_id) };
        }
    }

    auto attr_val = cps_api_object_e_get (obj, attr_list.data (), attr_list.size ());

    if (attr_val == NULL) {

        if (data_info.mode == NAS_ACL_ATTR_MODE_MANDATORY) {
            std::string attr_str;
            for (auto attr_elem: attr_list) {
                attr_str += std::to_string (attr_elem) + ".";
            }
            throw nas::base_exception { NAS_ACL_E_MISSING_ATTR, __PRETTY_FUNCTION__,
                                        std::string {"Failed to extract "} + sub_obj_name
                                        + ": No such attribute - " + attr_str};
        }

        return _fill_optional_attr (data_info, sub_obj_name);
    }

    auto attr_len = cps_api_object_attr_len (attr_val);
    auto expected_size   = data_info.data_len;

    if ((expected_size != 0) && (expected_size < attr_len)) {
        throw nas::base_exception { NAS_ACL_E_ATTR_LEN, __PRETTY_FUNCTION__,
                std::string {"Failed to extract "} + sub_obj_name
                + ": Size mismatch for attribute " + std::to_string (data_info.attr_id)
                + " data type " + nas_acl_obj_data_type_to_str (obj_data_type) +
                + " - expected: " + std::to_string (expected_size)
                + " received: " + std::to_string (attr_len) };
    }

    auto common_data = _cps_wr_attr_data (attr_val, obj_data_type, attr_len, sub_obj_name);

    if (!_validate_range (data_info, common_data)) {
        throw nas::base_exception { NAS_ACL_E_ATTR_VAL, __PRETTY_FUNCTION__,
                std::string {"Failed to extract "} + sub_obj_name
                + ": Invalid value for Attribute " + std::to_string (data_info.attr_id)
                + ": Received " + std::to_string (common_data.u32)
                + " Allowed range " + std::to_string (data_info.range.min)
                + " - " +  std::to_string (data_info.range.max)};
    }

    return common_data;
}

static void _get_child_attrs_from_obj (cps_api_object_t               obj,
                                       nas::attr_list_t&              parent_list,
                                       const nas_acl_map_data_list_t& child_list,
                                       const std::string&             subobj_name,
                                       nas_acl_common_data_list_t&    common_data_list)
{
    for (auto data_info: child_list) {
        parent_list.push_back (data_info.attr_id);

        auto common_data =_get_data_from_obj (obj, parent_list, data_info,
                                              subobj_name);
        common_data_list.push_back (std::move (common_data));

        /* Remove the processed child attr id */
        parent_list.pop_back ();
    }
}

static nas_acl_common_data_list_t _get_child_list_from_obj (cps_api_object_t               obj,
                                                            nas::attr_list_t&              parent_list,
                                                            const nas_acl_map_data_t&      val_info,
                                                            const nas_acl_map_data_list_t& child_list,
                                                            const std::string&             subobj_name)
{
    nas_acl_common_data_list_t    common_data_list;
    cps_api_object_it_t           it_value_list;

    cps_api_object_it (obj, parent_list.data (), parent_list.size (), &it_value_list);

    if (!cps_api_object_it_valid (&it_value_list)) {
        if (val_info.mode == NAS_ACL_ATTR_MODE_MANDATORY) {
            throw nas::base_exception { NAS_ACL_E_MISSING_ATTR, __PRETTY_FUNCTION__,
                std::string {"Failed to extract "} + subobj_name
                + ": Missing Attribute " + std::to_string (val_info.attr_id) };
        }
    }

    for (cps_api_object_it_inside (&it_value_list);
         cps_api_object_it_valid (&it_value_list);
         cps_api_object_it_next (&it_value_list)) {

        auto list_index = cps_api_object_attr_id (it_value_list.attr);
        parent_list.push_back (list_index);
        _get_child_attrs_from_obj (obj, parent_list, child_list, subobj_name, common_data_list);
        parent_list.pop_back ();
    }
    return common_data_list;
}

static nas_acl_common_data_list_t
_copy_non_iflist_data_from_obj (cps_api_object_t               obj,
                                nas::attr_list_t&              parent_list,
                                const nas_acl_map_data_t&      val_info,
                                const nas_acl_map_data_list_t& child_list,
                                const std::string&             subobj_name)
{
    // Full ACL Entry update -
    // Unpacking Filter/Action value from CPS obj with list of Filters or Actions
    // would require the following attr hierarchy
    //  - MATCH/ACTION-List-Attr . ListIndex . Match/Action-Value-Attr . Match/Action-Value-Child-Attr
    //
    // Of this the following is already filled by caller in parent_list
    //  - MATCH/ACTION-List-Attr . ListIndex . Match/Action-Value-Attr

    // Incremental ACL Entry update -
    // Unpacking Filter/Action value from a CPS obj with single Filter or Action
    //   (incremental update - the Match/Action Type is part of the obj key)
    // would require the following attr hierarchy
    //      - Match/Action-Value-Attr . Match/Action-Value-Child-Attr
    //
    // Of this the following is already filled by caller in parent_list
    //  - Match/Action-Value-Attr

    // In either case this function is ONLY responsible for the child attributes
    // within a particular Match or Action Value

    if (val_info.data_type == NAS_ACL_DATA_EMBEDDED_LIST) {
        return _get_child_list_from_obj (obj, parent_list, val_info, child_list, subobj_name);
    }

    nas_acl_common_data_list_t    common_data_list;

    if (val_info.data_type == NAS_ACL_DATA_EMBEDDED) {
        _get_child_attrs_from_obj (obj, parent_list, child_list, subobj_name, common_data_list);
        return common_data_list;
    }

    auto common_data = _get_data_from_obj (obj, parent_list, val_info, subobj_name);
    common_data_list.push_back (std::move (common_data));
    return common_data_list;
}

static nas_acl_common_data_list_t _copy_iflist_data_from_obj (cps_api_object_t   obj,
                                                              nas::attr_list_t&  parent_list,
                                                              const std::string& sub_obj_name,
                                                              bool use_ifname)
{
    auto ifval_attr_id = parent_list.back();
    parent_list.pop_back ();

    cps_api_object_it_t   it_if_list;
    if (parent_list.empty()) {
        // Incremental update -
        // For unpacking IfList from CPS object containing a single Filter,
        //   the parent_list input param will have just 1 element
        //    - IF-VAL
        // IF-VAL refers to attributes like IN_PORTS_VALUE or OUT_PORTS_VALUE etc.
        //
        // And the ACL Entry Obj CPS TLV will have a flat structure as follows
        //
        // Entry-Obj{
        //  Keys: SWITCH-ID, TABLE-ID, ENTRY-ID, MATCH/ACTION-TYPE
        //  Attrs:
        //      IF-VAL, IF-VAL, ..., IF-VAL
        //        ^
        //      (Get iterator to this level)
        // }
        //
        // Get the object iterator using the parent_list with the final attribute removed
        cps_api_object_it_begin (obj, &it_if_list);

    } else {
        // Full ACL Entry update -
        // For unpacking IfList from CPS object containing a list of Filters
        //    the parent_list will have the following attribute IDs
        // MATCH/ACTION-LIST Attr . <list-id> . IF-VAL
        //
        // IF-VAL refers to attributes like IN_PORTS_VALUE or OUT_PORTS_VALUE etc.
        //
        // Since the Iflist is defined as a leaf-list in the Yang,
        // the Match data would be arranged as follows in the CPS TLV for the
        // ACL Entry Obj
        //
        // Entry-Obj{
        //   Keys: SWITCH-ID, TABLE-ID, ENTRY-ID, MATCH-TYPE
        //   Attrs:
        //      MATCH/ACTION-LIST Attribute:
        //           {<list-id> :
        //                { MATCH/ACTION-TYPE, IF-VAL, IF-VAL, ..., IF-VAL}
        //                    ^
        //                  (Get iterator to this level)
        //           }
        //      Other attributes ...
        // }

        // Get the iterator to the match list entry (at <list-id> level)
        // using the parent_list with the final attribute removed
        if (!cps_api_object_it (obj, parent_list.data(), parent_list.size(),
                                &it_if_list)) {
            throw nas::base_exception { NAS_ACL_E_MISSING_ATTR, __PRETTY_FUNCTION__,
                std::string {"Failed to extract "} + sub_obj_name
                + ": Missing Iflist Attribute " + std::to_string (ifval_attr_id) };
        }

        // Then move inside to reach the level of the IF-VAL attributes
        cps_api_object_it_inside (&it_if_list);
    }

    // Scan for the IF-VAL attribute
    nas_acl_common_data_t common_data {};
    for (; cps_api_object_it_valid (&it_if_list); cps_api_object_it_next (&it_if_list)) {

        if (cps_api_object_attr_id (it_if_list.attr) == ifval_attr_id) {
            hal_ifindex_t ifindex;
            if (use_ifname) {
                char *intf_name = (char *)cps_api_object_attr_data_bin(it_if_list.attr);
                ifindex = cps_api_interface_name_to_if_index(intf_name);
                if (ifindex == 0) {
                    NAS_ACL_LOG_ERR("Invalid interface name %s", intf_name);
                    continue;
                }
            } else {
                ifindex = cps_api_object_attr_data_u32 (it_if_list.attr);
            }
            common_data.ifindex_list.push_back (ifindex);
            NAS_ACL_LOG_DETAIL ("match ifindex: %d (0x%x)", ifindex, ifindex);
        }
    }

    return nas_acl_common_data_list_t (1, std::move (common_data));
}

bool
nas_acl_copy_data_to_obj (cps_api_object_t               obj,
                          nas::attr_list_t&              parent_list,
                          const nas_acl_map_data_t&      val_info,
                          const nas_acl_map_data_list_t& child_list,
                          nas_acl_common_data_list_t&    common_data_list)
{
    bool rc;

    switch (val_info.data_type) {

        case NAS_ACL_DATA_NONE:
            rc = true;
            break;

        case NAS_ACL_DATA_U8:
        case NAS_ACL_DATA_U16:
        case NAS_ACL_DATA_U32:
        case NAS_ACL_DATA_U64:
        case NAS_ACL_DATA_OBJ_ID:
        case NAS_ACL_DATA_BIN:
        case NAS_ACL_DATA_EMBEDDED:
        case NAS_ACL_DATA_EMBEDDED_LIST:
        case NAS_ACL_DATA_IFINDEX:
        case NAS_ACL_DATA_IFNAME:
            rc = _copy_non_iflist_data_to_obj(obj, parent_list, val_info,
                                              child_list, common_data_list);
            break;

        case NAS_ACL_DATA_IFINDEX_LIST:
            rc = _copy_iflist_data_to_obj (obj, parent_list, common_data_list, false);
            break;

        case NAS_ACL_DATA_IFNAME_LIST:
            rc = _copy_iflist_data_to_obj (obj, parent_list, common_data_list, true);
            break;

        default:
            rc = false;
            break;
    }

    return rc;
}

nas_acl_common_data_list_t
nas_acl_copy_data_from_obj (cps_api_object_t                obj,
                            nas::attr_list_t&               parent_list,
                            const nas_acl_map_data_t&       val_info,
                            const nas_acl_map_data_list_t&  child_list,
                            const std::string&              sub_obj_name)
{
    switch (val_info.data_type) {

        case NAS_ACL_DATA_IFINDEX_LIST:
            return _copy_iflist_data_from_obj(obj, parent_list, sub_obj_name, false);
        case NAS_ACL_DATA_IFNAME_LIST:
            return _copy_iflist_data_from_obj(obj, parent_list, sub_obj_name, true);
        default:
            break;
    }
    return _copy_non_iflist_data_from_obj (obj, parent_list, val_info,
                                           child_list, sub_obj_name);
}

const char* nas_acl_obj_data_type_to_str (NAS_ACL_DATA_TYPE_t obj_data_type)
{
    static const std::unordered_map
        <NAS_ACL_DATA_TYPE_t, const char*, std::hash<int>>
        _obj_data_type_to_str_map = {
            {NAS_ACL_DATA_NONE,     "NONE"},
            {NAS_ACL_DATA_U8,       "U8"},
            {NAS_ACL_DATA_U16,      "U16"},
            {NAS_ACL_DATA_U32,      "U32"},
            {NAS_ACL_DATA_U64,      "U64"},
            {NAS_ACL_DATA_OBJ_ID,   "OBJ-ID"},
            {NAS_ACL_DATA_BIN,      "BIN"},
            {NAS_ACL_DATA_IFINDEX_LIST, "IFINDEX-LIST"},
            {NAS_ACL_DATA_IFNAME_LIST,  "IFNAME-LIST"},
            {NAS_ACL_DATA_EMBEDDED, "EMBEDDED"},
            {NAS_ACL_DATA_OPAQUE,   "OPAQUE"},
            {NAS_ACL_DATA_IFINDEX,  "IFINDEX"},
            {NAS_ACL_DATA_IFNAME,   "IFNAME"},
        };

    const auto& map_kv = _obj_data_type_to_str_map.find (obj_data_type);

    if (map_kv == _obj_data_type_to_str_map.end ()) {
        return "INVALID";
    }

    return map_kv->second;
}
