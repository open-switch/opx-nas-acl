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

#include <net/if.h>
#include <stdarg.h>
#include <arpa/inet.h>
#include "nas_acl_cps_ut.h"
#include "cps_api_object_key.h"
#include "cps_class_map.h"
#include "std_ip_utils.h"
#include "iana-if-type.h"
#include "dell-interface.h"
#include "dell-base-if.h"
#include "dell-base-routing.h"
#include "nas_ndi_route.h"

#define UT_ARR_DATA_LEN 128

#define SYSTEM(arg) if (system(arg)) return false;

typedef enum {
    _NO_OP,
    _MODIFY,
    _DELETE,
    _ADD_LATER,
    _SKIP,
} ut_field_op_t;

typedef struct _ut_filter_info_t {
    BASE_ACL_MATCH_TYPE_t type;
    uint64_t              val1;
    uint64_t              val2;
    ut_field_op_t         mod;
    uint64_t              new_val1;  /* Used for entry modify test */
    uint64_t              new_val2;  /* Used for entry modify test */
} ut_filter_info_t;

typedef struct _ut_action_info_t {
    BASE_ACL_ACTION_TYPE_t type;
    uint64_t               val1;
    uint64_t               val2;
    ut_field_op_t          mod;
    uint64_t               new_val1;  /* Used for entry modify test */
    uint64_t               new_val2;  /* Used for entry modify test */
} ut_action_info_t;

typedef std::vector<ut_filter_info_t> ut_filter_info_list_t;
typedef std::vector<ut_action_info_t> ut_action_info_list_t;

typedef struct _ut_entry_info_t {
    uint32_t              priority;
    ut_field_op_t         mod_priority;
    uint32_t              new_priority;
    ut_filter_info_list_t filter_info_list;
    ut_action_info_list_t action_info_list;
    ut_npu_list_t         npu_list;
    ut_field_op_t         mod_npu_list;
    ut_npu_list_t         new_npu_list;
} ut_entry_info_t;

std::vector<nas_obj_id_t> g_entry_id_list;
std::vector<ut_entry_t> g_validate_entry_list;
std::vector<ut_entry_t> g_validate_old_entry_list;

#define _ALL_FIELDS_ENTRY             99
#define _ALL_FIELDS_ENTRY_DEF_VAL1    79
#define _ALL_FIELDS_ENTRY_DEF_VAL2    89

struct entry_input_comp {
    bool operator() (uint32_t lhs, uint32_t rhs) {
        return (lhs < rhs);
    }
};

static std::set<uint32_t> _optional_filter_type = {
    BASE_ACL_MATCH_TYPE_SRC_IPV6,
    BASE_ACL_MATCH_TYPE_DST_IPV6,
    BASE_ACL_MATCH_TYPE_SRC_MAC,
    BASE_ACL_MATCH_TYPE_DST_MAC,
    BASE_ACL_MATCH_TYPE_SRC_IP,
    BASE_ACL_MATCH_TYPE_DST_IP,
    BASE_ACL_MATCH_TYPE_OUTER_VLAN_ID,
    BASE_ACL_MATCH_TYPE_OUTER_VLAN_PRI,
    BASE_ACL_MATCH_TYPE_INNER_VLAN_ID,
    BASE_ACL_MATCH_TYPE_INNER_VLAN_PRI,
    BASE_ACL_MATCH_TYPE_L4_SRC_PORT,
    BASE_ACL_MATCH_TYPE_L4_DST_PORT,
    BASE_ACL_MATCH_TYPE_ETHER_TYPE,
    BASE_ACL_MATCH_TYPE_IP_PROTOCOL,
    BASE_ACL_MATCH_TYPE_DSCP,
    BASE_ACL_MATCH_TYPE_TTL,
    BASE_ACL_MATCH_TYPE_TOS,
    BASE_ACL_MATCH_TYPE_IP_FLAGS,
    BASE_ACL_MATCH_TYPE_TCP_FLAGS,
    BASE_ACL_MATCH_TYPE_IPV6_FLOW_LABEL,
    BASE_ACL_MATCH_TYPE_TC,
    BASE_ACL_MATCH_TYPE_ECN,
    BASE_ACL_MATCH_TYPE_ICMP_TYPE,
    BASE_ACL_MATCH_TYPE_ICMP_CODE
};

static std::map <uint32_t, ut_entry_info_t, entry_input_comp>
_entry_map_input =
{
    {1,
        {1, _MODIFY, 11,
            {
                {BASE_ACL_MATCH_TYPE_SRC_IP,  4,  5, _MODIFY,  6,  7},
                {BASE_ACL_MATCH_TYPE_DST_IP, 14, 15, _DELETE,  0,  0},
                {BASE_ACL_MATCH_TYPE_IP_PROTOCOL, 4, 1, _MODIFY,  3, 3},
                {BASE_ACL_MATCH_TYPE_L4_DST_PORT, 500, 0xfff, _NO_OP,  0, 0},
            },
            {
                {BASE_ACL_ACTION_TYPE_PACKET_ACTION, BASE_ACL_PACKET_ACTION_TYPE_DROP, 0, _NO_OP, 0, 0},
                {BASE_ACL_ACTION_TYPE_SET_OUTER_VLAN_PRI, 7, 0, _MODIFY, 5, 0},
                {BASE_ACL_ACTION_TYPE_FLOOD, 0, 0, _ADD_LATER, 0, 0},
            },
            {}, _NO_OP, {},
        }
    },

    {_ALL_FIELDS_ENTRY,
        {100, _MODIFY, 101,
            {},
            {},
            {}, _NO_OP, {},
        }
    }
};

static ut_entry_t *ut_get_entry_by_entry_id (nas_acl_ut_table_t* table,
                                             nas_obj_id_t        entry_id)
{
    for (auto& map_kv: table->entries) {
        if (map_kv.second.entry_id == entry_id) {
            return &map_kv.second;
        }
    }

    return NULL;
}

void ut_dump_ndi_obj_id_table (nas::ndi_obj_id_table_t& ndi_obj_id_table)
{
    size_t count = 0;

    ut_printf ("[%s()-%d] Printing ndi_obj_id_table \r\n",
               __FUNCTION__, __LINE__);

    for (const auto& kvp: ndi_obj_id_table) {
        ut_printf ("%ld: Npu: %d, objId: %ld\r\n",
                   count, (int)kvp.first, kvp.second);
        count++;
    }
}

static inline void ut_init_all_verified_flags (nas_acl_ut_table_t& table)
{
    for (auto& map_kv: table.entries) {
        map_kv.second.to_be_verified = true;
        map_kv.second.verified       = false;
    }
}

static inline void ut_clear_all_verified_flags (nas_acl_ut_table_t& table)
{
    for (auto& map_kv: table.entries) {
        map_kv.second.to_be_verified = false;
        map_kv.second.verified       = false;
    }
}

static inline bool ut_validate_verified_flags ()
{
    uint32_t index;

    for (index = 0; index < NAS_ACL_UT_MAX_TABLES; index++) {

        nas_acl_ut_table_t& table = g_nas_acl_ut_tables [index];

        for (auto& map_kv: table.entries) {

            ut_entry_t& entry = map_kv.second;

            if ((entry.to_be_verified == true) && (entry.verified == false)) {

                ut_printf ("%s(): Entry NOT verified. Switch: %d, Table: %ld, "
                           "Entry Id: %ld, Entry Index: %d\r\n", __FUNCTION__,
                           entry.switch_id, entry.table_id, entry.entry_id,
                           entry.index);
                return false;
            }
        }
    }

    return true;
}

static uint8_t ip_buf[sizeof(dn_ipv4_addr_t) + 1];
static uint8_t mask_buf[sizeof(dn_ipv4_addr_t) + 1];

static inline void ut_fill_all_fields_filter_val (ut_filter_t& filter, bool modify)
{
    uint32_t val1;
    uint32_t val2;
    uint32_t increment;

    increment = (modify == true) ? 1 : 0;

    switch (filter.type) {

        case BASE_ACL_MATCH_TYPE_IN_PORTS:
        case BASE_ACL_MATCH_TYPE_OUT_PORTS:
        case BASE_ACL_MATCH_TYPE_IN_PORT:
        case BASE_ACL_MATCH_TYPE_OUT_PORT:
        case BASE_ACL_MATCH_TYPE_IN_INTFS:
        case BASE_ACL_MATCH_TYPE_OUT_INTFS:
        case BASE_ACL_MATCH_TYPE_IN_INTF:
        case BASE_ACL_MATCH_TYPE_OUT_INTF:
            val1 = NAS_ACL_UT_MAX_NPUS; /*
                                         * No of ports. Using Max NPUs here,
                                         * since want to have one port picked
                                         * from each NPU.
                                         */

            val2 = 1 + increment;       /* Start Port */
            break;

        case BASE_ACL_MATCH_TYPE_OUTER_VLAN_PRI:
        case BASE_ACL_MATCH_TYPE_INNER_VLAN_PRI:
            val1 = 5 + increment;
            val2 = 5 + increment;
            break;

        case BASE_ACL_MATCH_TYPE_IP_FLAGS:
            val1 = 3 + increment;
            val2 = 0x7;
            break;

        case BASE_ACL_MATCH_TYPE_ECN:
            val1 = 1 + increment;
            val2 = 0x3;
            break;

        case BASE_ACL_MATCH_TYPE_TCP_FLAGS:
            val1 = 54 + increment;
            val2 = 0x3f;
            break;

        case BASE_ACL_MATCH_TYPE_IP_TYPE:
            val1 = BASE_ACL_MATCH_IP_TYPE_ARP_REPLY;
            val2 = val1;
            break;

        case BASE_ACL_MATCH_TYPE_IP_FRAG:
            val1 = BASE_ACL_MATCH_IP_FRAG_NON_HEAD;
            val2 = val1;
            break;

        case BASE_ACL_MATCH_TYPE_OUTER_VLAN_CFI:
        case BASE_ACL_MATCH_TYPE_INNER_VLAN_CFI:
            val1 = 0 + increment;
            val2 = 0 + increment;
            break;

        case BASE_ACL_MATCH_TYPE_DSCP:
            val1 = 50 + increment;
            val2 = 50 + increment;
            break;

        case BASE_ACL_MATCH_TYPE_L4_SRC_PORT:
        case BASE_ACL_MATCH_TYPE_L4_DST_PORT:
            val1 = 500 + increment;
            val2= val1;
            break;

        case BASE_ACL_MATCH_TYPE_SRC_IP:
        case BASE_ACL_MATCH_TYPE_DST_IP:
            ip_buf[0] = (uint8_t)sizeof(dn_ipv4_addr_t);
            mask_buf[0] = (uint8_t)sizeof(dn_ipv4_addr_t);
            val1 = (uint64_t)ip_buf;
            memset(&ip_buf[1], 0x1, sizeof(dn_ipv4_addr_t));
            memset(&mask_buf[1], 0xff, sizeof(dn_ipv4_addr_t));
            val2 = (uint64_t)mask_buf;
            break;

        default:
            val1 = _ALL_FIELDS_ENTRY_DEF_VAL1 + increment;
            val2 = _ALL_FIELDS_ENTRY_DEF_VAL2 + increment;
    }

    filter.val_list.clear ();
    filter.val_list.push_back (val1);
    filter.val_list.push_back (val2);
}

static inline void ut_fill_all_fields_action_val (ut_action_t& action, bool modify)
{
    uint32_t val1;
    uint32_t val2;
    uint32_t increment;

    increment = (modify == true) ? 1 : 0;

    switch (action.type) {

        case BASE_ACL_ACTION_TYPE_REDIRECT_PORT:
            val1 = 1;
            val2 = 7 + increment;
            break;

        case BASE_ACL_ACTION_TYPE_REDIRECT_IP_NEXTHOP:
        case BASE_ACL_ACTION_TYPE_MIRROR_INGRESS:
        case BASE_ACL_ACTION_TYPE_MIRROR_EGRESS:
        case BASE_ACL_ACTION_TYPE_SET_POLICER:
        case BASE_ACL_ACTION_TYPE_SET_CPU_QUEUE:
            val1 = 10 + increment;
            val2 = 100 + increment;
            break;

        case BASE_ACL_ACTION_TYPE_SET_INNER_VLAN_PRI:
            val1 = 3 + increment;
            val2 = val1;
            break;

        case BASE_ACL_ACTION_TYPE_SET_OUTER_VLAN_PRI:
            val1 = 4 + increment;
            val2 = val1;
            break;

        case BASE_ACL_ACTION_TYPE_SET_DSCP:
            val1 = 23 + increment;
            val2 = val1;
            break;

        case BASE_ACL_ACTION_TYPE_PACKET_ACTION:
            val1 = BASE_ACL_PACKET_ACTION_TYPE_DROP + increment;
            val2 = val1;
            break;

        default:
            val1 = _ALL_FIELDS_ENTRY_DEF_VAL1 + increment;
            val2 = _ALL_FIELDS_ENTRY_DEF_VAL2 + increment;
    }

    action.val_list.clear ();
    action.val_list.push_back (val1);
    action.val_list.push_back (val2);
}

void ut_add_all_filter (ut_entry_t& entry)
{
    ut_filter_t       filter;
    cps_api_attr_id_t filter_type;

    for (filter_type = NAS_ACL_UT_START_FILTER;
         filter_type <= NAS_ACL_UT_END_FILTER; filter_type++) {

        filter.type = (BASE_ACL_MATCH_TYPE_t) filter_type;

        if (!nas_acl_filter_is_type_valid (filter.type)) {
            continue;
        }

        if (filter.type == BASE_ACL_MATCH_TYPE_IN_PORT) {
            continue;
        }

        ut_fill_all_fields_filter_val (filter, true);

        entry.filter_list.insert (filter);
    }
}

void ut_add_all_action (ut_entry_t& entry)
{
    ut_action_t       action;
    cps_api_attr_id_t action_type;

    for (action_type = NAS_ACL_UT_START_ACTION;
         action_type <= NAS_ACL_UT_END_ACTION; action_type++) {

        action.type = (BASE_ACL_ACTION_TYPE_t) action_type;

        if (!nas_acl_action_is_type_valid (action.type)) {
            continue;
        }

        if ((action.type == BASE_ACL_ACTION_TYPE_MIRROR_EGRESS) ||
            (action.type == BASE_ACL_ACTION_TYPE_MIRROR_INGRESS) ||
            (action.type == BASE_ACL_ACTION_TYPE_SET_COUNTER)) {
            continue;
        }

        ut_fill_all_fields_action_val (action, false);

        entry.action_list.insert (action);
    }
}

void ut_modify_all_filter (ut_entry_t& entry)
{
    for (auto filter: entry.filter_list) {
        ut_fill_all_fields_filter_val (filter, false);
    }
}

void ut_modify_all_action (ut_entry_t& entry)
{
    for (auto action: entry.action_list) {
        ut_fill_all_fields_action_val (action, false);
    }
}

static bool ut_add_opaque_data_to_obj (cps_api_object_t   obj,
                                       ut_attr_id_list_t& attr_list,
                                       uint64_t           in_u64)
{
    int32_t                 npu_id;
    nas::ndi_obj_id_table_t obj_id_table;

    ut_printf ("[%s()-%d] in_u64: %ld\r\n", __FUNCTION__, __LINE__, in_u64);

    for (npu_id = 0; npu_id < NAS_ACL_UT_MAX_NPUS; npu_id++) {
        obj_id_table [npu_id] = (ndi_obj_id_t) (in_u64);
    }

    ut_dump_ndi_obj_id_table (obj_id_table);

    return nas::ndi_obj_id_table_cps_serialize (obj_id_table, obj,
                                                attr_list.data (),
                                                attr_list.size ());
}

static bool ut_validate_opaque_obj_data (cps_api_object_t      obj,
                                         ut_attr_id_list_t&    attr_list,
                                         uint64_t              in_u64)
{
    nas::ndi_obj_id_table_t ndi_obj_id_table;
    uint32_t                count = 0;
    bool                    rc;

    ut_printf ("%s() in_u64: %ld\r\n", __FUNCTION__, in_u64);

    rc = nas::ndi_obj_id_table_cps_unserialize (ndi_obj_id_table, obj,
                                                attr_list.data (),
                                                attr_list.size ());

    if (rc == false) {
        ut_printf ("[%s()-%d] ndi_obj_id_table_cps_unserialize failed. "
                   "in_u64: %ld\r\n", __FUNCTION__, __LINE__, in_u64);
        return false;
    }

    ut_dump_ndi_obj_id_table (ndi_obj_id_table);

    if (ndi_obj_id_table.size () != NAS_ACL_UT_MAX_NPUS) {
        ut_printf ("[%s()-%d] ndi_obj_id_table size mismatch. "
                   "Size: %ld, NAS_ACL_UT_MAX_NPUS: %ld\r\n",
                   __FUNCTION__, __LINE__, ndi_obj_id_table.size (), in_u64);
        return false;
    }

    for (auto elem: ndi_obj_id_table) {

        auto npu_id = elem.first;
        auto obj_id = elem.second;

        if ((nas_obj_id_t) (in_u64) != obj_id) {
            ut_printf ("[%s()-%d] Obj Id mismatch. Expected: %ld, Actual: %d.\r\n",
                       __FUNCTION__, __LINE__, obj_id, npu_id);
            return false;
        }

        if ((npu_id < 0) || (npu_id >= (int32_t) NAS_ACL_UT_MAX_NPUS)) {
            ut_printf ("[%s()-%d] Invalid Npu. npu_id: %d, in_u64: %ld\r\n",
                       __FUNCTION__, __LINE__, npu_id, in_u64);
            return false;
        }

        count++;
    }

    if (count != NAS_ACL_UT_MAX_NPUS) {
        ut_printf ("[%s()-%d] size mismatch. count: %d, expected count: %d\r\n",
                   __FUNCTION__, __LINE__, count, NAS_ACL_UT_MAX_NPUS);
        return false;
    }

    return true;
}

static bool ut_validate_sub_data (cps_api_object_t      obj,
                                  ut_attr_id_list_t&    attr_list,
                                  uint64_t              in_u64,
                                  NAS_ACL_DATA_TYPE_t   obj_data_type,
                                  size_t                obj_data_size)
{
    cps_api_object_attr_t  attr_val;
    uint8_t               *p_u8;

    if (obj_data_type == NAS_ACL_DATA_OPAQUE) {
        return (ut_validate_opaque_obj_data (obj, attr_list, in_u64));
    }

    attr_val = cps_api_object_e_get (obj, attr_list.data(), attr_list.size());

    if (attr_val == NULL) {
        ut_printf ("[%s()-%d] cps_api_object_e_get failed.\r\n",
                   __FUNCTION__, __LINE__);
        return false;
    }

    switch (obj_data_type) {
        case NAS_ACL_DATA_NONE:
            return true;
            break;

        case NAS_ACL_DATA_U8:
            p_u8 = (uint8_t *) cps_api_object_attr_data_bin (attr_val);
            if (*p_u8 != (uint8_t) in_u64) {
                ut_printf ("[%s()-%d] Invalid U8 data (%d). \r\n",
                           __FUNCTION__, __LINE__, *p_u8);
                return false;
            }
            break;

        case NAS_ACL_DATA_U16:
            if (cps_api_object_attr_data_u16 (attr_val) != (uint16_t) in_u64) {
                ut_printf ("[%s()-%d] Invalid U16 data (%d).\r\n",
                           __FUNCTION__, __LINE__,
                           cps_api_object_attr_data_u16 (attr_val));
                return false;
            }
            break;

        case NAS_ACL_DATA_U32:
        case NAS_ACL_DATA_IFINDEX:
             if (cps_api_object_attr_data_u32 (attr_val) != (uint32_t)in_u64) {
                ut_printf ("[%s()-%d] cps_api_object_e_get failed.\r\n",
                           __FUNCTION__, __LINE__);
                 return false;
             }
             break;

        case NAS_ACL_DATA_U64:
        case NAS_ACL_DATA_OBJ_ID:
            if (cps_api_object_attr_data_u64 (attr_val) != in_u64) {
                ut_printf ("[%s()-%d] cps_api_object_e_get failed.\r\n",
                           __FUNCTION__, __LINE__);
                return false;
            }
            break;

        case NAS_ACL_DATA_BIN:
        {
            //Always return true because static buffer is used to store all bin data
            return true;

        }

        default:
                ut_printf ("[%s()-%d] cps_api_object_e_get failed.\r\n",
                           __FUNCTION__, __LINE__);
            return false;
            break;
    }

    return true;
}

bool ut_validate_non_iflist_data (ut_attr_id_list_t&             parent_list,
                                  const nas_acl_map_data_list_t& child_list,
                                  cps_api_object_t               obj,
                                  NAS_ACL_DATA_TYPE_t            obj_data_type,
                                  size_t                         obj_data_size,
                                  bool                           optional,
                                  const ut_val_list_t&           val_list)
{
    uint32_t index = 0;
    uint64_t flag;

    if (obj_data_type != NAS_ACL_DATA_EMBEDDED) {

        if (optional) {
            flag = val_list.at(index++);
            if (flag == 0) {
                return true;
            }
        }
        if (!ut_validate_sub_data (obj, parent_list, val_list.at (index),
                                   obj_data_type, obj_data_size)) {

            ut_printf ("[%s()-%d] ut_validate_sub_data() failed. "
                       "Data Type: %s\r\n", __FUNCTION__, __LINE__,
                       nas_acl_obj_data_type_to_str (obj_data_type));
            return false;
        }

        return true;
    }

    for (auto data: child_list) {
        if (data.mode == NAS_ACL_ATTR_MODE_OPTIONAL) {
            flag = val_list.at(index++);
            if (flag == 0) {
                continue;
            }
        }
        parent_list.push_back (data.attr_id);

        if (!ut_validate_sub_data (obj, parent_list, val_list.at (index),
                                   data.data_type, data.data_len)) {
            ut_printf ("[%s()-%d] ut_validate_sub_data() failed. "
                       "Data Type: %s, Index: %d\r\n", __FUNCTION__, __LINE__,
                       nas_acl_obj_data_type_to_str (obj_data_type), index);
            return false;
        }

        parent_list.pop_back ();
        index++;
    }

    return true;
}

bool ut_validate_iflist_data (ut_attr_id_list_t&   list,
                              cps_api_object_t     obj,
                              const ut_val_list_t& val_list)
{
    cps_api_object_it_t   it;
    cps_api_object_it_t   it_if_list;
    hal_ifindex_t         ifindex;
    hal_ifindex_t         num_ifindex;
    int                   index;
    ut_val_list_t         if_list_tmp;
    size_t                position;
    bool                  found;

    if (!cps_api_object_it (obj, list.data(), list.size(), &it)) {
        ut_printf ("[%s()-%d] cps_api_object_it() failed. \r\n",
                   __FUNCTION__, __LINE__);
        return false;
    }

    num_ifindex = val_list.at (0);
    ifindex     = val_list.at (1);

    for (index = 0; index < num_ifindex; index++) {
        if_list_tmp.push_back (ifindex);
        ifindex += NAS_ACL_UT_NUM_PORTS_PER_NPU;
    }

    for (it_if_list = it;
         cps_api_object_it_valid (&it_if_list);
         cps_api_object_it_next (&it_if_list)) {

        ifindex = cps_api_object_attr_data_u32 (it_if_list.attr);

        position = 0;
        found    = false;

        for (auto ifindex_tmp: if_list_tmp) {
            if (ifindex == (int) ifindex_tmp) {
                if_list_tmp.erase (if_list_tmp.begin () + position);
                found = true;

                break;
            }

            position++;
        }

        if (found == false) {
            ut_printf ("[%s()-%d] ifIndex NOT found. \r\n",
                       __FUNCTION__, __LINE__);
            return false;
        }
    }

    if (if_list_tmp.size () != 0) {
        ut_printf ("[%s()-%d] Could not match all ifindexes \r\n", __FUNCTION__, __LINE__);
        return false;
    }

    return true;
}

bool ut_validate_data (ut_attr_id_list_t&             parent_list,
                       const nas_acl_map_data_list_t& child_list,
                       cps_api_object_t               obj,
                       NAS_ACL_DATA_TYPE_t            data_type,
                       size_t                         data_size,
                       bool                           optional,
                       const ut_val_list_t&           val_list)
{
    bool rc;

    switch (data_type) {

        case NAS_ACL_DATA_NONE:
            rc = true;
            break;

        case NAS_ACL_DATA_U8:
        case NAS_ACL_DATA_U16:
        case NAS_ACL_DATA_U32:
        case NAS_ACL_DATA_IFINDEX:
        case NAS_ACL_DATA_U64:
        case NAS_ACL_DATA_BIN:
        case NAS_ACL_DATA_OBJ_ID:
        case NAS_ACL_DATA_EMBEDDED:
            rc = ut_validate_non_iflist_data (parent_list, child_list, obj,
                                              data_type, data_size, optional, val_list);
            break;

        case NAS_ACL_DATA_IFINDEX_LIST:
            rc = ut_validate_iflist_data (parent_list, obj, val_list);
            break;

        default:
            ut_printf ("%s(): Unknown Data type (%d)\r\n",
                       __FUNCTION__, data_type);
            rc = false;
            break;
    }

    return rc;
}

static bool ut_add_data_to_obj (cps_api_object_t       obj,
                                ut_attr_id_list_t&     attr_list,
                                uint64_t               in_u64,
                                NAS_ACL_DATA_TYPE_t    obj_data_type,
                                size_t                 obj_data_size)
{
    cps_api_object_ATTR_TYPE_t  cps_attr_type;
    nas::ndi_obj_id_table_t     obj_id_table;
    uint8_t                     u8;
    uint16_t                    u16;
    uint32_t                    u32;
    void                       *p_data;
    size_t                      size;
    ut_printf ("[%s()-%d] in_u64: %ld, obj_data_type: %s(%d), "
               "obj_data_size: %ld\r\n", __FUNCTION__, __LINE__, in_u64,
               nas_acl_obj_data_type_to_str (obj_data_type), obj_data_type, obj_data_size);

    if (obj_data_type == NAS_ACL_DATA_OPAQUE) {
        return (ut_add_opaque_data_to_obj (obj, attr_list, in_u64));
    }

    switch (obj_data_type) {

        case NAS_ACL_DATA_U8:
            u8            = (uint8_t) in_u64;
            p_data        = &u8;
            size          = sizeof (uint8_t);
            cps_attr_type = cps_api_object_ATTR_T_BIN;
            break;

        case NAS_ACL_DATA_U16:
            u16           = (uint16_t) in_u64;
            p_data        = &u16;
            size          = sizeof (uint16_t);
            cps_attr_type = cps_api_object_ATTR_T_U16;
            break;

        case NAS_ACL_DATA_U32:
        case NAS_ACL_DATA_IFINDEX:
            u32           = (uint32_t)in_u64;
            p_data        = &u32;
            size          = sizeof (uint32_t);
            cps_attr_type = cps_api_object_ATTR_T_U32;
            break;

        case NAS_ACL_DATA_U64:
            p_data        = &in_u64;
            size          = sizeof (uint64_t);
            cps_attr_type = cps_api_object_ATTR_T_U64;
            break;

        case NAS_ACL_DATA_OBJ_ID:
            p_data        = &in_u64;
            size          = sizeof (nas_obj_id_t);
            cps_attr_type = cps_api_object_ATTR_T_U64;
            break;

        case NAS_ACL_DATA_BIN:

            p_data        = (void *)in_u64;
            size = (size_t)*((uint8_t *)p_data);
            p_data = &((uint8_t *)p_data)[1];
            cps_attr_type = cps_api_object_ATTR_T_BIN;
            break;

        default:
            ut_printf ("%s(): DEFAULT case. \r\n", __FUNCTION__);
            return false;
            break;
    }

    if (obj_data_size != size) {

        ut_printf ("%s(): Size mismatch. \r\n", __FUNCTION__);
        return false;
    }

    if (cps_api_object_e_add (obj, attr_list.data(), attr_list.size(),
                              cps_attr_type, p_data, size) != true) {
        ut_printf ("%s(): cps_api_object_e_add () failed.\r\n", __FUNCTION__);
        return false;
    }

    return true;
}

static bool
ut_action_copy_non_iflist_data_to_obj (cps_api_object_t               obj,
                                       ut_attr_id_list_t&             parent_list,
                                       const nas_acl_map_data_list_t& child_list,
                                       NAS_ACL_DATA_TYPE_t            obj_data_type,
                                       size_t                         obj_data_size,
                                       bool                           optional,
                                       const ut_val_list_t&           val_list)
{
    size_t index = 0;
    uint64_t flag;

    ut_printf ("%s(), obj_data_type: %s, obj_data_size: %ld \r\n",
                __FUNCTION__, nas_acl_obj_data_type_to_str (obj_data_type),
                obj_data_size);

    if (obj_data_type != NAS_ACL_DATA_EMBEDDED) {
        if (optional) {
            flag = val_list.at(index);
            if (flag == 0) {
                return true;
            }
            index ++;
        }
        if (!ut_add_data_to_obj (obj, parent_list, val_list.at (index),
                                 obj_data_type, obj_data_size)) {
            ut_printf ("%s(): %d, ut_add_data_to_obj () failed. \r\n",
                        __FUNCTION__, __LINE__);

            return false;
        }

        return true;
    }

    for (auto data: child_list) {
        if (data.mode == NAS_ACL_ATTR_MODE_OPTIONAL) {
            flag = val_list.at(index ++);
            if (flag == 0) {
                continue;
            }
        }

        parent_list.push_back (data.attr_id);

        if (!ut_add_data_to_obj (obj, parent_list, val_list.at (index),
                                 data.data_type, data.data_len)) {
            ut_printf ("%s(): %d, ut_add_data_to_obj () failed. \r\n",
                        __FUNCTION__, __LINE__);
            return false;
        }

        /* Remove the processed child attr id */
        parent_list.pop_back ();
        index++;
    }

    return true;
}

static bool
ut_action_copy_iflist_data_to_obj (cps_api_object_t     obj,
                                   ut_attr_id_list_t&   parent_list,
                                   bool optional,
                                   const ut_val_list_t& val_list)
{
    uint32_t          num_ifindex;
    uint32_t          if_index;
    uint32_t          index;

    int idx = 0;
    if (optional) {
        uint64_t flag = val_list.at(idx);
        if (flag == 0) {
            return true;
        }
        idx ++;
    }
    num_ifindex  = val_list.at (idx);
    if_index     = val_list.at (idx + 1);

    ut_printf ("[%s()-%d] num_ifindex: %d, if_index: %d\r\n",
               __FUNCTION__, __LINE__, num_ifindex, if_index);

    for (index = 0; index < num_ifindex; index++) {

        if (!cps_api_object_e_add (obj,
                                   parent_list.data (),
                                   parent_list.size (),
                                   cps_api_object_ATTR_T_U32,
                                   &if_index,
                                   sizeof (uint32_t))) {
            ut_printf ("[%s()-%d] cps_api_object_e_add failed\r\n",
                       __FUNCTION__, __LINE__);
            return false;
        }

        if_index += NAS_ACL_UT_NUM_PORTS_PER_NPU;
    }

    return true;
}

bool ut_copy_data_to_obj (ut_attr_id_list_t&             parent_list,
                          const nas_acl_map_data_list_t& child_list,
                          cps_api_object_t               obj,
                          NAS_ACL_DATA_TYPE_t            obj_data_type,
                          size_t                         obj_data_size,
                          bool                           optional,
                          const ut_val_list_t&           val_list)
{
    bool rc;

    switch (obj_data_type) {

        case NAS_ACL_DATA_NONE:
            rc = true;
            break;

        case NAS_ACL_DATA_U8:
        case NAS_ACL_DATA_U16:
        case NAS_ACL_DATA_U32:
        case NAS_ACL_DATA_IFINDEX:
        case NAS_ACL_DATA_U64:
        case NAS_ACL_DATA_OBJ_ID:
        case NAS_ACL_DATA_BIN:
        case NAS_ACL_DATA_EMBEDDED:
            rc = ut_action_copy_non_iflist_data_to_obj (obj,
                                                        parent_list,
                                                        child_list,
                                                        obj_data_type,
                                                        obj_data_size,
                                                        optional,
                                                        val_list);
            break;

        case NAS_ACL_DATA_IFINDEX_LIST:
            rc = ut_action_copy_iflist_data_to_obj (obj, parent_list, optional, val_list);
            break;

        default:
            rc = false;
            break;
    }

    return rc;
}

static inline void set_all_update_flags (ut_entry_t& entry)
{
    entry.update_priority = true;

    if (!entry.filter_list.empty ()) {
        entry.update_filter = true;
    }

    if (!entry.action_list.empty ()) {
        entry.update_action = true;
    }

    if (!entry.npu_list.empty ()) {
        entry.update_npu = true;
    }
}

static inline void clear_all_update_flags (ut_entry_t& entry)
{
    entry.update_priority = false;
    entry.update_filter   = false;
    entry.update_action   = false;
    entry.update_npu      = false;
}

bool ut_clear_action (ut_entry_t&                   entry,
                      BASE_ACL_ACTION_TYPE_t        type,
                      nas::attr_list_t&             parent_attr_id_list,
                      const nas_acl_action_info_t&  map_info,
                      cps_api_object_t              obj,
                      bool                         *p_out_found)
{
    *p_out_found = false;

    for (auto& action: entry.action_list) {

        if (action.type == type) {

            *p_out_found = true;

            if (!ut_validate_data (parent_attr_id_list,
                                   map_info.child_list,
                                   obj,
                                   map_info.val.data_type,
                                   map_info.val.data_len,
                                   map_info.val.mode == NAS_ACL_ATTR_MODE_OPTIONAL,
                                   action.val_list)) {
                return false;
            }

            entry.action_list.erase (action);
            break;
        }
    }

    return true;
}

bool ut_validate_entry_filter_list (const cps_api_object_t     obj,
                                    const cps_api_object_it_t& it,
                                    ut_entry_t&                entry)
{
    BASE_ACL_MATCH_TYPE_t  match_type_val;
    BASE_ACL_ENTRY_MATCH_t match_val_attr_id;
    cps_api_object_it_t    it_lvl_1 = it;
    cps_api_attr_id_t      attr_id;
    cps_api_attr_id_t      list_index = 0;
    nas::attr_list_t       parent_attr_id_list;
    bool                   filter_found;

    for (cps_api_object_it_inside (&it_lvl_1);
         cps_api_object_it_valid (&it_lvl_1);
         cps_api_object_it_next (&it_lvl_1)) {

        parent_attr_id_list.clear ();
        parent_attr_id_list.push_back (BASE_ACL_ENTRY_MATCH);

        list_index = cps_api_object_attr_id (it_lvl_1.attr);

        parent_attr_id_list.push_back (list_index);

        cps_api_object_it_t it_lvl_2 = it_lvl_1;

        cps_api_object_it_inside (&it_lvl_2);

        if (!cps_api_object_it_valid (&it_lvl_2)) {

            return false;
        }

        attr_id = cps_api_object_attr_id (it_lvl_2.attr);

        /*
         * TODO: Need to figure out how emptying of match parameters
         * is to be handled.
         */
        if (attr_id != BASE_ACL_ENTRY_MATCH_TYPE) {
            ut_printf ("%s(): BASE_ACL_ENTRY_MATCH_TYPE not present.\r\n",
                       __FUNCTION__);
            return false;
        }

        match_type_val = (BASE_ACL_MATCH_TYPE_t)
            cps_api_object_attr_data_u32 (it_lvl_2.attr);

        cps_api_object_it_next (&it_lvl_2);

        if (!cps_api_object_it_valid (&it_lvl_2)) {
            return false;
        }

        match_val_attr_id = (BASE_ACL_ENTRY_MATCH_t)
            cps_api_object_attr_id (it_lvl_2.attr);

        parent_attr_id_list.push_back (match_val_attr_id);

        const auto& map_kv = nas_acl_get_filter_map().find (match_type_val);

        if (map_kv == nas_acl_get_filter_map().end ()) {
            ut_printf ("%s(): Unknown Filter (%d).\r\n",
                       __FUNCTION__, match_type_val);
            return false;
        }

        const nas_acl_filter_info_t& map_info = map_kv->second;
        filter_found = false;

        for (auto& filter: entry.filter_list) {

            if (filter.type == match_type_val) {

                filter_found = true;
                if (!ut_validate_data (parent_attr_id_list,
                                       map_info.child_list,
                                       obj,
                                       map_info.val.data_type,
                                       map_info.val.data_len,
                                       map_info.val.mode == NAS_ACL_ATTR_MODE_OPTIONAL,
                                       filter.val_list)) {
                    return false;
                }

                entry.filter_list.erase (filter);

                break;
            }
        }

        if (filter_found == false) {
            ut_printf ("%s(): Filter (%d) NOT found\r\n",
                       __FUNCTION__, match_type_val);
            return false;
        }
    }

    if (entry.filter_list.size () != 0) {
        ut_printf ("%s(): Unvalidated filters present\r\n", __FUNCTION__);
        return false;
    }

    return true;
}

bool ut_validate_entry_action_list (const cps_api_object_t     obj,
                                    const cps_api_object_it_t& it,
                                    ut_entry_t&                entry)
{
    BASE_ACL_ACTION_TYPE_t  action_type_val;
    BASE_ACL_ENTRY_ACTION_t action_val_attr_id;
    cps_api_object_it_t     it_lvl_1 = it;
    cps_api_attr_id_t       attr_id;
    cps_api_attr_id_t       list_index = 0;
    nas::attr_list_t        parent_attr_id_list;
    bool                    action_found;

    for (cps_api_object_it_inside (&it_lvl_1);
         cps_api_object_it_valid (&it_lvl_1);
         cps_api_object_it_next (&it_lvl_1)) {

        parent_attr_id_list.clear ();
        parent_attr_id_list.push_back (BASE_ACL_ENTRY_ACTION);

        list_index = cps_api_object_attr_id (it_lvl_1.attr);

        parent_attr_id_list.push_back (list_index);

        cps_api_object_it_t it_lvl_2 = it_lvl_1;

        cps_api_object_it_inside (&it_lvl_2);

        if (!cps_api_object_it_valid (&it_lvl_2)) {
            return false;
        }

        attr_id = cps_api_object_attr_id (it_lvl_2.attr);

        if (attr_id != BASE_ACL_ENTRY_ACTION_TYPE) {
            return false;
        }

        action_type_val = (BASE_ACL_ACTION_TYPE_t)
            cps_api_object_attr_data_u32 (it_lvl_2.attr);

        const auto& map_kv = nas_acl_get_action_map().find (action_type_val);

        if (map_kv == nas_acl_get_action_map().end ()) {
            ut_printf ("%s failed at %d for %d\r\n", __FUNCTION__, __LINE__, action_type_val);
            return false;
        }

        const nas_acl_action_info_t& map_info = map_kv->second;

        cps_api_object_it_next (&it_lvl_2);

        action_found = false;

        if (map_info.val.data_type == NAS_ACL_DATA_NONE) {

            if (cps_api_object_it_valid (&it_lvl_2)) {
                ut_printf ("%s failed at %d for %d\r\n", __FUNCTION__, __LINE__, action_type_val);
                return false;
            }

            if (!ut_clear_action (entry, action_type_val, parent_attr_id_list,
                                  map_info, obj, &action_found)) {
                ut_printf ("%s failed at %d for %d\r\n", __FUNCTION__, __LINE__, action_type_val);
                return false;
            }
        }
        else {

            if (!cps_api_object_it_valid (&it_lvl_2)) {
                ut_printf ("%s failed at %d for %d\r\n", __FUNCTION__, __LINE__, action_type_val);
                return false;
            }

            action_val_attr_id = (BASE_ACL_ENTRY_ACTION_t)
                cps_api_object_attr_id (it_lvl_2.attr);

            if (map_info.val.attr_id != action_val_attr_id) {
                ut_printf ("%s failed at %d for %d\r\n", __FUNCTION__, __LINE__, action_type_val);
                return false;
            }

            parent_attr_id_list.push_back (action_val_attr_id);

            if (!ut_clear_action (entry, action_type_val, parent_attr_id_list,
                                  map_info, obj, &action_found)) {
                ut_printf ("%s failed at %d for %d\r\n", __FUNCTION__, __LINE__, action_type_val);
                return false;
            }
        }

        if (action_found == false) {
            ut_printf ("%s(): Action (%d) NOT found\r\n",
                       __FUNCTION__, action_type_val);
            return false;
        }
    }

    if (entry.action_list.size () != 0) {
        ut_printf ("%s(): Missing Actions present.\r\n", __FUNCTION__);
        return false;
    }

    return true;
}

bool ut_fill_entry_match (cps_api_object_t obj, const ut_entry_t& entry)
{
    ut_attr_id_list_t parent_list;
    cps_api_attr_id_t list_index = 0;

    for (const auto& filter: entry.filter_list) {

        const auto& map_kv = nas_acl_get_filter_map().find (filter.type);

        if (map_kv == nas_acl_get_filter_map().end ()) {
            ut_printf ("FAILED: Could not Find filter type %d\r\n", filter.type);
            return false;
        }

        const nas_acl_filter_info_t& map_info = map_kv->second;

        parent_list.clear ();

        parent_list.push_back (BASE_ACL_ENTRY_MATCH);
        parent_list.push_back (list_index);
        parent_list.push_back (BASE_ACL_ENTRY_MATCH_TYPE);

        if (!cps_api_object_e_add (obj,
                                   parent_list.data (),
                                   parent_list.size (),
                                   cps_api_object_ATTR_T_U32,
                                   &filter.type,
                                   sizeof (uint32_t))) {
            return false;
        }

        parent_list.pop_back ();
        parent_list.push_back (map_info.val.attr_id);

        if (!ut_copy_data_to_obj (parent_list,
                                  map_info.child_list,
                                  obj,
                                  map_info.val.data_type,
                                  map_info.val.data_len,
                                  map_info.val.mode == NAS_ACL_ATTR_MODE_OPTIONAL,
                                  filter.val_list)) {
            ut_printf ("Failed filter %s", nas_acl_filter_type_name (filter.type));
            return false;
        }

        list_index++;
    }

    return true;
}

bool ut_fill_entry_action (cps_api_object_t obj, const ut_entry_t& entry)
{
    ut_attr_id_list_t parent_list;
    cps_api_attr_id_t list_index = 0;

    for (const auto& action: entry.action_list) {

        const auto& map_kv = nas_acl_get_action_map ().find (action.type);

        if (map_kv == nas_acl_get_action_map().end ()) {
            ut_printf ("FAILED: Could not Find action type %d\r\n", action.type);
            return false;
        }

        const nas_acl_action_info_t& map_info = map_kv->second;

        parent_list.clear ();

        parent_list.push_back (BASE_ACL_ENTRY_ACTION);
        parent_list.push_back (list_index);
        parent_list.push_back (BASE_ACL_ENTRY_ACTION_TYPE);

        if (!cps_api_object_e_add (obj,
                                   parent_list.data (),
                                   parent_list.size (),
                                   cps_api_object_ATTR_T_U32,
                                   &action.type,
                                   sizeof (uint32_t))) {
            return false;
        }

        if (map_info.val.data_type != NAS_ACL_DATA_NONE) {

            parent_list.pop_back ();
            parent_list.push_back (map_info.val.attr_id);

            if (!ut_copy_data_to_obj (parent_list,
                                      map_info.child_list,
                                      obj,
                                      map_info.val.data_type,
                                      map_info.val.data_len,
                                      map_info.val.mode == NAS_ACL_ATTR_MODE_OPTIONAL,
                                      action.val_list)) {
                ut_printf ("Failed filter %s", nas_acl_action_type_name (action.type));
                return false;
            }
        }

        list_index++;
    }

    return true;
}

void nas_acl_ut_extract_entry_keys (cps_api_object_t  obj,
                                    nas_switch_id_t  *p_out_switch_id,
                                    nas_obj_id_t     *p_out_table_id,
                                    nas_obj_id_t     *p_out_entry_id,
                                    uint_t           *p_out_count)
{
    cps_api_object_attr_t table_id_attr = cps_api_get_key_data (obj,
                                                                BASE_ACL_ENTRY_TABLE_ID);
    cps_api_object_attr_t entry_id_attr = cps_api_get_key_data (obj,
                                                                BASE_ACL_ENTRY_ID);

    *p_out_count = 0;

    if (table_id_attr) {
        (*p_out_count) ++;
        *p_out_table_id = cps_api_object_attr_data_u64 (table_id_attr);
        ut_printf ("%s(): Table Id: %ld \r\n", __FUNCTION__, *p_out_table_id);
    }
    if (entry_id_attr) {
        (*p_out_count) ++;
        *p_out_entry_id = cps_api_object_attr_data_u64 (entry_id_attr);
        ut_printf ("%s(): Entry Id: %ld \r\n", __FUNCTION__, *p_out_entry_id);
    }
}


bool ut_fill_entry_create_req (cps_api_transaction_params_t *params,
                               ut_entry_t&                   entry)
{
    cps_api_return_code_t rc;
    cps_api_object_t      obj;

    obj = cps_api_object_create ();

    if (obj == NULL) {
        ut_printf ("cps_api_object_create () failed. \r\n");
        return (false);
    }

    cps_api_object_guard obj_guard (obj);

    cps_api_key_from_attr_with_qual (cps_api_object_key (obj), BASE_ACL_ENTRY_OBJ,
                                     cps_api_qualifier_TARGET);
    cps_api_set_key_data (obj, BASE_ACL_ENTRY_TABLE_ID, cps_api_object_ATTR_T_U64,
                          &entry.table_id, sizeof (uint64_t));

    cps_api_object_attr_add_u32 (obj, BASE_ACL_ENTRY_PRIORITY, entry.priority);

    for (auto npu: entry.npu_list) {
        cps_api_object_attr_add_u32(obj, BASE_ACL_ENTRY_NPU_ID_LIST, npu);
    }

    if (ut_fill_entry_match (obj, entry) == false) {
        ut_printf ("ut_fill_entry_match () failed. \r\n");
        return (false);
    }

    if (ut_fill_entry_action (obj, entry) == false) {
        ut_printf ("ut_fill_entry_action () failed. \r\n");
        return (false);
    }

    rc = cps_api_create (params, obj);

    if (rc != cps_api_ret_code_OK) {
        ut_printf ("cps_api_create () failed. \r\n");
        return (false);
    }

    obj_guard.release ();
    return (true);
}

bool ut_fill_entry_modify_req (cps_api_transaction_params_t *params,
                               ut_entry_t&                   entry)
{
    cps_api_return_code_t rc;
    cps_api_object_t      obj;

    obj = cps_api_object_create ();

    if (obj == NULL) {
        ut_printf ("cps_api_object_create () failed. \r\n");
        return (false);
    }

    cps_api_key_from_attr_with_qual (cps_api_object_key (obj), BASE_ACL_ENTRY_OBJ,
                                     cps_api_qualifier_TARGET);
    cps_api_set_key_data (obj, BASE_ACL_ENTRY_TABLE_ID, cps_api_object_ATTR_T_U64,
                          &entry.table_id, sizeof (uint64_t));
    cps_api_set_key_data (obj, BASE_ACL_ENTRY_ID, cps_api_object_ATTR_T_U64,
                          &entry.entry_id, sizeof (uint64_t));

    if (entry.update_priority == true) {
        cps_api_object_attr_add_u32 (obj,
                                     BASE_ACL_ENTRY_PRIORITY, entry.priority);
    }

    if (entry.update_npu == true) {
        for (auto npu: entry.npu_list) {
            cps_api_object_attr_add_u32(obj, BASE_ACL_ENTRY_NPU_ID_LIST, npu);
        }
    }

    if (entry.update_filter == true) {
        if (ut_fill_entry_match (obj, entry) == false) {
            cps_api_object_delete (obj);
            ut_printf ("ut_fill_entry_match () failed. \r\n");
            return (false);
        }
    }

    if (entry.update_action == true) {
        if (ut_fill_entry_action (obj, entry) == false) {
            cps_api_object_delete (obj);
            ut_printf ("ut_fill_entry_action () failed. \r\n");
            return (false);
        }
    }

    rc = cps_api_set (params, obj);

    if (rc != cps_api_ret_code_OK) {
        cps_api_object_delete (obj);
        ut_printf ("cps_api_set () failed. \r\n");
        return (false);
    }

    return (true);
}

bool ut_fill_entry_delete_req (cps_api_transaction_params_t *params,
                               ut_entry_t&                   entry)
{
    cps_api_return_code_t rc;
    cps_api_object_t      obj;

    obj = cps_api_object_create ();

    if (obj == NULL) {
        ut_printf ("cps_api_object_create () failed. \r\n");
        return (false);
    }

    cps_api_key_from_attr_with_qual (cps_api_object_key (obj), BASE_ACL_ENTRY_OBJ, cps_api_qualifier_TARGET);
    cps_api_set_key_data (obj, BASE_ACL_ENTRY_TABLE_ID, cps_api_object_ATTR_T_U64,
                          &entry.table_id, sizeof (uint64_t));
    cps_api_set_key_data (obj, BASE_ACL_ENTRY_ID, cps_api_object_ATTR_T_U64,
                          &entry.entry_id, sizeof (uint64_t));

    rc = cps_api_delete (params, obj);

    if (rc != cps_api_ret_code_OK) {
        cps_api_object_delete (obj);
        ut_printf ("cps_api_delete () failed. \r\n");
        return (false);
    }

    return (true);
}

bool validate_entry_obj (cps_api_object_t obj, ut_entry_t& entry)
{
    cps_api_object_it_t    it;
    cps_api_attr_id_t      attr_id;
    nas_switch_id_t        switch_id;
    uint32_t               npu;
    nas_obj_id_t           table_id;
    nas_obj_id_t           entry_id;
    uint_t                 priority;
    bool                   update_priority;
    bool                   update_filter;
    bool                   update_action;
    bool                   update_npu;
    bool                   priority_validated = false;
    bool                   filter_validated = false;;
    bool                   action_validated = false;
    static const int       num_allowed_keys = 2;
    uint_t                 count;

    nas_acl_ut_extract_entry_keys (obj, &switch_id, &table_id, &entry_id, &count);

    if (count != num_allowed_keys) {
        ut_printf ("%s(): FAILED. Key Count: %d\r\n", __FUNCTION__, count);
        return false;
    }

    update_priority = entry.update_priority;
    update_filter   = entry.update_filter;
    update_action   = entry.update_action;
    update_npu      = entry.update_npu;

    clear_all_update_flags (entry);

    ut_printf ("%s(): Switch Id: %d, Table Id: %ld, Entry Id: %ld\r\n",
               __FUNCTION__, switch_id, table_id, entry_id);

    for (cps_api_object_it_begin (obj, &it);
         cps_api_object_it_valid (&it); cps_api_object_it_next (&it)) {

        attr_id = cps_api_object_attr_id (it.attr);

        switch (attr_id) {

            case BASE_ACL_ENTRY_TABLE_ID:
                ut_printf ("%s(): Table Id NOT allowed as an attribute \r\n",
                           __FUNCTION__);
                return false;
                break;

            case BASE_ACL_ENTRY_ID:
                ut_printf ("%s(): Entry Id NOT allowed as an attribute \r\n",
                           __FUNCTION__);
                return false;
                break;

            case BASE_ACL_ENTRY_PRIORITY:
                priority = cps_api_object_attr_data_u32 (it.attr);

                if ((update_priority == true) && (entry.priority != priority)) {

                    ut_printf ("%s(): Entry Priority mismatch. "
                               "Entry Priority: %d, In Priority: %d\r\n",
                               __FUNCTION__, entry.priority, priority);
                    return false;
                }
                priority_validated = true;
                break;

            case BASE_ACL_ENTRY_MATCH:
                if (update_filter == true) {
                    if (ut_validate_entry_filter_list (obj, it, entry) != true) {
                        ut_printf ("%s(): Filter validation failed.\r\n",
                                   __FUNCTION__);
                        return false;
                    }
                }
                filter_validated = true;
                break;

            case BASE_ACL_ENTRY_ACTION:
                if (update_action == true) {
                    if (ut_validate_entry_action_list (obj, it, entry) != true) {
                        ut_printf ("%s(): Action validation failed.\r\n",
                                   __FUNCTION__);
                        return false;
                    }
                }
                action_validated = true;
                break;

            case BASE_ACL_ENTRY_NPU_ID_LIST:
                if (update_npu == true) {
                    npu = cps_api_object_attr_data_u32 (it.attr);

                    const_ut_npu_list_iter_t npu_it = entry.npu_list.find(npu);

                    if (npu_it == entry.npu_list.end ()) {
                        return false;
                    }

                    entry.npu_list.erase (npu);
                }
                break;

            default:
                // Unknown attribute. Ignore silently.
                ut_printf ("%s(): DEFAULT Case \r\n", __FUNCTION__);
                break;
        }
    }

    if ((update_priority == true) && (priority_validated != true)) {
        ut_printf ("%s(): Priority check failed.\r\n", __FUNCTION__);
        return false;
    }

    if ((update_filter == true) && (filter_validated != true)) {
        ut_printf ("%s(): Filter check failed.\r\n", __FUNCTION__);
        return false;
    }

    if ((update_action == true) && (action_validated != true)) {
        ut_printf ("%s(): Action check failed.\r\n", __FUNCTION__);
        return false;
    }

    if ((update_npu == true) && (entry.npu_list.size () != 0)) {
        ut_printf ("%s(): NPU check failed.\r\n", __FUNCTION__);
        return false;
    }

    return true;
}

bool
validate_entry_cps_resp(uint_t op, ut_entry_t& entry, cps_api_object_t prev_obj)
{
    nas_switch_id_t switch_id;
    nas_obj_id_t    table_id;
    nas_obj_id_t    entry_id;
    uint_t          count;

    ut_printf ("Starting validation\r\n");
    fflush (stdout);

    nas_acl_ut_extract_entry_keys (prev_obj, &switch_id, &table_id, &entry_id, &count);

    if (count != 2) {
        ut_printf ("%s(): Invalid key count: %d.\r\n", __FUNCTION__, count);
        return false;
    }

    ut_printf ("%s(): switch_id: %d, table_id: %ld, entry_id: %ld.\r\n",
               __FUNCTION__, switch_id, table_id, entry_id);
    fflush (stdout);

    if (op == NAS_ACL_UT_CREATE) {
        entry.entry_id = entry_id;
    }

    if ((entry.table_id  != table_id)  &&
        (entry.entry_id  != entry_id)) {
        ut_printf ("%s(): Key mismatch.\r\n", __FUNCTION__);
        return false;
    }

    if (op == NAS_ACL_UT_CREATE) {
        return true;
    }

    if (op != NAS_ACL_UT_CREATE) {
        if (validate_entry_obj (prev_obj, entry) != true) {
            ut_printf ("%s(): validate_entry_obj failed.\r\n", __FUNCTION__);
            return false;
        }
    }

    return true;
}

bool nas_acl_ut_entry_get (uint_t op, ut_entry_t& entry)
{
    cps_api_get_params_t   params;
    cps_api_object_t       obj;
    cps_api_return_code_t  rc;

    ut_printf ("%s()\r\n", __FUNCTION__);

    if (cps_api_get_request_init (&params) != cps_api_ret_code_OK) {
        ut_printf ("cps_api_get_request_init () failed. \r\n");
        return (false);
    }

    ut_printf ("%s(): Switch Id: %d, Table Id : %ld, Entry Id: %ld \r\n",
               __FUNCTION__, entry.switch_id, entry.table_id, entry.entry_id);

    obj = cps_api_object_list_create_obj_and_append (params.filters);

    cps_api_key_from_attr_with_qual (cps_api_object_key (obj), BASE_ACL_ENTRY_OBJ,
                                     cps_api_qualifier_TARGET);
    cps_api_set_key_data (obj, BASE_ACL_ENTRY_TABLE_ID, cps_api_object_ATTR_T_U64,
                          &entry.table_id, sizeof (uint64_t));
    cps_api_set_key_data (obj, BASE_ACL_ENTRY_ID, cps_api_object_ATTR_T_U64,
                          &entry.entry_id, sizeof (uint64_t));

    rc = nas_acl_ut_cps_api_get (&params, 0);

    if (op == NAS_ACL_UT_DELETE) {
        if (rc != cps_api_ret_code_OK) {
            return true;
        }

        return false;
    }

    if (rc != cps_api_ret_code_OK) {

        ut_printf ("cps_api_get () failed. \r\n");
        return (false);
    }

    obj = cps_api_object_list_get (params.list, 0);

    if (obj == NULL) {
        ut_printf ("%s(): Get resp object NOT present.\r\n",
                   __FUNCTION__);
        return (false);
    }

    if (validate_entry_obj (obj, entry) == false) {
        return (false);
    }

    if (cps_api_get_request_close (&params) != cps_api_ret_code_OK) {
        ut_printf ("cps_api_request_close () failed. \r\n");
        return (false);
    }

    ut_printf ("********** ACL Entry Get TEST PASSED ********** .\r\n\n");
    return (true);
}

bool
validate_entry_commit_create (cps_api_transaction_params_t *params)
{
    ut_entry_t       tmp_entry;
    cps_api_object_t obj;
    size_t           index;
    size_t           count;

    count = cps_api_object_list_size (params->prev);

    if (g_validate_entry_list.size () != count) {
        return false;
    }

    for (index = 0; index < count; index++) {

        ut_entry_t& entry = g_validate_entry_list.at (index);

        obj = cps_api_object_list_get (params->prev, index);

        if (obj == NULL) {
            return false;
        }

        tmp_entry = entry;
        if (validate_entry_cps_resp (NAS_ACL_UT_CREATE, tmp_entry, obj)
            != true) {
            ut_printf ("Failed\r\n"); fflush (stdout);
            return false;
        }

        entry.entry_id = tmp_entry.entry_id;
        g_entry_id_list.push_back (entry.entry_id);

        set_all_update_flags (entry);

        if (nas_acl_ut_entry_get (NAS_ACL_UT_CREATE, entry) != true) {
            return false;
        }
    }

    return true;
}

bool
validate_entry_commit_modify (cps_api_transaction_params_t *params)
{
    cps_api_object_t obj;
    size_t           index;
    size_t           count;

    count = cps_api_object_list_size (params->prev);

    if ((g_validate_entry_list.size () != count) &&
        (g_validate_old_entry_list.size () != count)) {
        ut_printf ("%s(): Size mismatch. \r\n", __FUNCTION__);
        return false;
    }

    for (index = 0; index < count; index++) {

        ut_entry_t& old_entry = g_validate_old_entry_list.at (index);
        ut_entry_t& new_entry = g_validate_entry_list.at (index);

        obj = cps_api_object_list_get (params->prev, index);

        if (obj == NULL) {
            ut_printf ("%s(): cps_api_object_list_get failed.\r\n",
                       __FUNCTION__);
            return false;
        }

        ut_entry_t tmp_entry = old_entry;
        if (validate_entry_cps_resp (NAS_ACL_UT_MODIFY, tmp_entry, obj)
            != true) {
            ut_printf ("%s(): validate_entry_cps_resp failed.\r\n",
                       __FUNCTION__);
            return false;
        }

        set_all_update_flags (new_entry);
        tmp_entry = new_entry;

        if (nas_acl_ut_entry_get (NAS_ACL_UT_MODIFY, tmp_entry) != true) {
            ut_printf ("%s(): nas_acl_ut_entry_get failed.\r\n",
                       __FUNCTION__);
            return false;
        }
    }

    return true;
}

bool
validate_entry_commit_delete (cps_api_transaction_params_t *params)
{
    cps_api_object_t obj;
    uint32_t         index;
    uint32_t         count;

    count = cps_api_object_list_size (params->prev);

    if (g_validate_entry_list.size () != count) {
        return false;
    }

    for (index = 0; index < count; index++) {

        ut_entry_t& entry = g_validate_entry_list.at (index);

        obj = cps_api_object_list_get (params->prev, index);

        if (obj == NULL) {
            return false;
        }

        set_all_update_flags (entry);
        ut_entry_t tmp_entry = entry;

        if (validate_entry_cps_resp (NAS_ACL_UT_DELETE, tmp_entry, obj)
            != true) {
            return false;
        }

        entry.entry_id = tmp_entry.entry_id;

        if (nas_acl_ut_entry_get (NAS_ACL_UT_DELETE, entry) != true) {
            return false;
        }
    }

    return true;
}

bool entry_commit_create (cps_api_transaction_params_t *params,
                          ut_entry_t&                   entry,
                          uint32_t                      index,
                          bool                          force_commit,
                          bool                          rollback)
{
    if (index == 0) {
        if (cps_api_transaction_init (params) != cps_api_ret_code_OK) {
            return cps_api_ret_code_ERR;
        }

        g_validate_entry_list.clear ();
    }

    if (ut_fill_entry_create_req (params, entry) == false) {
        return false;
    }

    g_validate_entry_list.push_back (entry);

    if (force_commit == true) {

        if (nas_acl_ut_cps_api_commit (params,
                                       rollback) != cps_api_ret_code_OK) {
            return false;
        }

        if (validate_entry_commit_create (params) != true) {
            return false;
        }

        if (cps_api_transaction_close (params) != cps_api_ret_code_OK) {
            return false;
        }
    }

    return true;
}

bool entry_commit_modify (cps_api_transaction_params_t *params,
                          ut_entry_t&                   old_entry,
                          ut_entry_t&                   new_entry,
                          uint32_t                      index,
                          bool                          force_commit,
                          bool                          rollback)
{
    if (index == 0) {
        if (cps_api_transaction_init (params) != cps_api_ret_code_OK) {
            ut_printf ("%s(): cps_api_transaction_init failed \r\n",
                       __FUNCTION__);
            return cps_api_ret_code_ERR;
        }

        g_validate_entry_list.clear ();
        g_validate_old_entry_list.clear ();
    }

    if (ut_fill_entry_modify_req (params, new_entry) != true) {
        ut_printf ("%s(): ut_fill_entry_modify_req failed \r\n",
                   __FUNCTION__);
        return false;
    }

    g_validate_entry_list.push_back (new_entry);
    g_validate_old_entry_list.push_back (old_entry);

    if (force_commit == true) {

        if (nas_acl_ut_cps_api_commit (params,
                                       rollback) != cps_api_ret_code_OK) {
            ut_printf ("%s(): nas_acl_ut_cps_api_commit failed \r\n",
                       __FUNCTION__);
            return false;
        }

        if (validate_entry_commit_modify (params) != true) {
            return false;
        }

        if (cps_api_transaction_close (params) != cps_api_ret_code_OK) {
            return false;
        }
    }

    return true;
}

bool entry_commit_delete (cps_api_transaction_params_t *params,
                          ut_entry_t&                   entry,
                          uint32_t                      index,
                          bool                          force_commit,
                          bool                          rollback,
                          bool                          validate)
{
    if (index == 0) {
        if (cps_api_transaction_init (params) != cps_api_ret_code_OK) {
            return cps_api_ret_code_ERR;
        }

        g_validate_entry_list.clear ();
    }

    if (ut_fill_entry_delete_req (params, entry) == false) {
        return false;
    }

    g_validate_entry_list.push_back (entry);

    if (force_commit == true) {

        if (nas_acl_ut_cps_api_commit (params,
                                       rollback) != cps_api_ret_code_OK) {
            return false;
        }

        if (validate && validate_entry_commit_delete (params) != true) {
            return false;
        }

        if (cps_api_transaction_close (params) != cps_api_ret_code_OK) {
            return false;
        }
    }

    return true;
}

static inline void ut_add_filter_int (ut_entry_t& entry, ut_filter_t& filter,
                                      uint64_t val1, bool val1_optional, bool val1_null,
                                      uint64_t val2, bool val2_optional, bool val2_null)
{
    filter.val_list.clear ();
    if (val1_optional) {
        if (val1_null) {
            filter.val_list.push_back(0);
        } else {
            filter.val_list.push_back(1);
        }
    }
    if (!val1_optional || !val1_null) {
        filter.val_list.push_back (val1);
    }
    if (val2_optional) {
        if (val1_null) {
            filter.val_list.push_back(0);
        } else {
            filter.val_list.push_back(1);
        }
    }
    if (!val2_optional || !val2_null) {
        filter.val_list.push_back (val2);
    }

    entry.filter_list.insert (filter);
}

static inline void ut_add_filter (ut_entry_t& entry, ut_filter_t& filter,
                                  uint64_t val1, uint64_t val2)
{
    auto it = _optional_filter_type.find(filter.type);
    ut_add_filter_int(entry, filter, val1, false, false,
                      val2, it == _optional_filter_type.end() ? false : true, false);
}

static inline void ut_add_action_int (ut_entry_t& entry, ut_action_t& action,
                                      uint64_t val1, bool val1_optional, bool val1_null,
                                      uint64_t val2, bool val2_optional, bool val2_null)
{
    action.val_list.clear ();
    if (val1_optional) {
        if (val1_null) {
            action.val_list.push_back(1);
        } else {
            action.val_list.push_back(0);
        }
    }
    if (!val1_optional || !val1_null) {
        action.val_list.push_back (val1);
    }
    if (val2_optional) {
        if (val1_null) {
            action.val_list.push_back(1);
        } else {
            action.val_list.push_back(0);
        }
    }
    if (!val2_optional || !val2_null) {
        action.val_list.push_back (val2);
    }

    entry.action_list.insert (action);
}

static inline void ut_add_action (ut_entry_t& entry, ut_action_t& action,
                                  uint64_t val1, uint64_t val2)
{
    ut_add_action_int(entry, action, val1, false, false, val2, false, false);
}

static bool ut_add_filter_ip_mask_val(ut_entry_t& entry, ut_filter_t& filter,
                                      uint32_t ip_val, uint32_t mask_val)
{
    ip_buf[0] = (uint8_t)sizeof(dn_ipv4_addr_t);
    memcpy(&ip_buf[1], &ip_val, sizeof(dn_ipv4_addr_t));

    mask_buf[0] = (uint8_t)sizeof(dn_ipv4_addr_t);
    memcpy(&mask_buf[1], &mask_val, sizeof(dn_ipv4_addr_t));
    ut_add_filter_int(entry, filter, (uint64_t)ip_buf, false, false,
                      (uint64_t)mask_buf, true, false);

    return true;
}

static bool ut_add_filter_ip_mask(ut_entry_t& entry, ut_filter_t& filter,
                                  const char *ip, const char *mask)
{
    std_ip_addr_t ip_addr_holder;
    if (std_str_to_ip(ip, &ip_addr_holder) == false) {
        return false;
    }
    uint32_t ip_val = (uint32_t)ip_addr_holder.u.ipv4.s_addr;
    if (std_str_to_ip(mask, &ip_addr_holder) == false) {
        return false;
    }
    uint32_t mask_val = (uint32_t)ip_addr_holder.u.ipv4.s_addr;

    return ut_add_filter_ip_mask_val(entry, filter, ip_val, mask_val);
}

static bool nas_acl_ut_entry_create (nas_acl_ut_table_t& table)
{
    cps_api_transaction_params_t params;
    ut_entry_t                   entry;
    ut_filter_t                  filter;
    ut_action_t                  action;
    uint32_t                     index;

    ut_printf ("---------- ACL Entry Creation TEST STARTED ------------\r\n");

    for (const auto& map_kv: _entry_map_input) {

        index = map_kv.first;

        /* entry.entry_id will be filled once the create response is received */
        entry.switch_id = table.switch_id;
        entry.table_id  = table.table_id;
        entry.priority  = map_kv.second.priority;

        clear_all_update_flags (entry);

        if (index == _ALL_FIELDS_ENTRY) {

            if (nas_acl_ut_is_on_target ()) {
                continue;
            }
            else {
                ut_add_all_filter (entry);
                ut_add_all_action (entry);
            }
        }
        else {
            for (auto& filter_info: map_kv.second.filter_info_list) {

                if (filter_info.mod == _ADD_LATER) continue;
                filter.type = filter_info.type;
                if (filter.type == BASE_ACL_MATCH_TYPE_SRC_IP ||
                    filter.type == BASE_ACL_MATCH_TYPE_DST_IP) {
                    ut_add_filter_ip_mask_val(entry, filter,
                                              filter_info.val1, filter_info.val2);
                } else {
                    ut_add_filter(entry, filter, filter_info.val1, filter_info.val2);
                }
            }

            for (auto& action_info: map_kv.second.action_info_list) {
                if (action_info.mod == _ADD_LATER) continue;
                action.type = action_info.type;
                ut_add_action (entry, action,
                               action_info.val1, action_info.val2);
            }
        }

        for (auto npu: map_kv.second.npu_list) {
            entry.npu_list.insert (npu);
        }

        if (entry_commit_create (&params, entry, 0, true, false) == false) {
            return false;
        }

        entry.index    = index;
        entry.entry_id = g_entry_id_list.at(0);
        table.entries.insert (std::make_pair (index, std::move (entry)));

        g_entry_id_list.clear ();
    }

    ut_printf ("********** ACL Entry Creation TEST PASSED ************\r\n\n");
    return true;
}

static bool nas_acl_ut_entry_modify (nas_acl_ut_table_t& table)
{
    cps_api_transaction_params_t params;
    ut_filter_t                  filter;
    ut_action_t                  action;
    uint32_t                     index;

    ut_printf ("---------- ACL Entry Modify TEST STARTED ------------\r\n");

    for (const auto& map_kv: _entry_map_input) {

        index = map_kv.first;
        const ut_entry_info_t& entry_info = map_kv.second;

        if (index == _ALL_FIELDS_ENTRY) {
            if (nas_acl_ut_is_on_target ()) {
                continue;
            }
        }

        auto entry_kv = table.entries.find (index);
        if (entry_kv == table.entries.end ()) {
            return false;
        }

        ut_entry_t& old_entry = entry_kv->second;
        ut_entry_t  new_entry = old_entry;

        clear_all_update_flags (old_entry);
        clear_all_update_flags (new_entry);

        if (entry_info.mod_priority == _MODIFY) {
            new_entry.priority = entry_info.new_priority;
            new_entry.update_priority = true;
            old_entry.update_priority = true;
        }

        if (index == _ALL_FIELDS_ENTRY) {

            if (nas_acl_ut_is_on_target ()) {
                continue;
            }
            else {
                ut_modify_all_filter (new_entry);
                ut_modify_all_action (new_entry);
            }
        }
        else {
            for (auto& filter_info: entry_info.filter_info_list) {

                if ((filter_info.mod == _NO_OP) || (filter_info.mod == _MODIFY)) {
                    filter.type = filter_info.type;
                    if (filter.type == BASE_ACL_MATCH_TYPE_SRC_IP ||
                        filter.type == BASE_ACL_MATCH_TYPE_DST_IP) {
                        ut_add_filter_ip_mask_val(new_entry, filter, filter_info.val1, filter_info.val2);
                    } else {
                        ut_add_filter(new_entry, filter, filter_info.val1, filter_info.val2);
                    }
                    new_entry.update_filter = true;
                    old_entry.update_filter = true;
                }
            }

            for (auto& action_info: entry_info.action_info_list) {

                if ((action_info.mod == _NO_OP) || (action_info.mod == _MODIFY)) {
                    action.type = action_info.type;

                    action.val_list.clear ();
                    action.val_list.push_back (action_info.val1);
                    action.val_list.push_back (action_info.val2);

                    new_entry.action_list.insert (action);
                    new_entry.update_action = true;
                    old_entry.update_action = true;
                }
            }
        }

        if ((entry_info.mod_npu_list == _MODIFY) ||
            (entry_info.mod_npu_list == _DELETE)) {

            for (auto npu: map_kv.second.npu_list) {
                new_entry.npu_list.insert (npu);
            }

            new_entry.update_npu = true;
            old_entry.update_npu = true;
        }

        if (entry_commit_modify (&params, old_entry,
                                 new_entry, 0, true, false) == false) {
            return false;
        }

        table.entries.at (index) = std::move (new_entry);
    }

    ut_printf ("********** ACL Entry Modify TEST PASSED ************\r\n\n");
    return true;
}

static bool nas_acl_ut_entry_delete (nas_acl_ut_table_t& table, bool validate)
{
    cps_api_transaction_params_t params;
    ut_filter_t                  filter;
    uint32_t                     index;

    ut_printf ("---------- ACL Entry Delete TEST STARTED ------------\r\n");

    for (const auto& map_kv: _entry_map_input) {
        index = map_kv.first;

        if (index == _ALL_FIELDS_ENTRY) {
            if (nas_acl_ut_is_on_target ()) {
                continue;
            }
        }

        const auto& entry_kv = table.entries.find (index);

        if (entry_kv == table.entries.end ()) {
            return false;
        }

        if (entry_commit_delete (&params, entry_kv->second, 0, true, false, validate)
            == false) {

            return false;
        }

        table.entries.erase (index);
    }

    ut_printf ("********** ACL Entry Delete TEST PASSED ************\r\n\n");
    return true;
}

bool nas_acl_ut_entry_create_test (nas_acl_ut_table_t& table)
{
    if (!nas_acl_ut_entry_create (table)) {
        return false;
    }

    return true;
}

bool nas_acl_ut_entry_modify_test (nas_acl_ut_table_t& table)
{
    if (!nas_acl_ut_entry_modify (table)) {
        return false;
    }

    return true;
}

bool nas_acl_ut_entry_delete_test (nas_acl_ut_table_t& table, bool validate)
{
    if (!nas_acl_ut_entry_delete (table, validate)) {
        return false;
    }

    return true;
}

bool ut_entry_get_bulk (cps_api_object_t obj)
{
    static const int       num_allowed_keys = 2;
    nas_acl_ut_table_t    *p_table;
    ut_entry_t            *p_entry;
    cps_api_get_params_t   params;
    cps_api_return_code_t  rc;
    size_t                 size;
    uint_t                 index;
    uint_t                 resp_key_count;
    nas_switch_id_t        switch_id;
    nas_obj_id_t           table_id;
    nas_obj_id_t           entry_id;

    ut_printf ("%s()\r\n", __FUNCTION__);

    if (cps_api_get_request_init (&params) != cps_api_ret_code_OK) {
        ut_printf ("cps_api_get_request_init () failed. \r\n");
        return (false);
    }

    if (!cps_api_object_list_append (params.filters, obj)) {

        ut_printf ("%s() Obj append failed.\n", __FUNCTION__);
        cps_api_object_delete (obj);
        return false;
    }

    rc = nas_acl_ut_cps_api_get (&params, 0);

    if (rc != cps_api_ret_code_OK) {

        ut_printf ("%s(): cps_api_get () failed. \r\n", __FUNCTION__);
        return (false);
    }

    size = cps_api_object_list_size (params.list);

    for (index = 0; index < size; index++) {

        obj = cps_api_object_list_get (params.list, index);

        if (obj == NULL) {
            ut_printf ("%s(): Get resp object NOT present.\r\n",
                       __FUNCTION__);
            return (false);
        }

        nas_acl_ut_extract_entry_keys (obj, &switch_id, &table_id,
                                       &entry_id, &resp_key_count);

        p_table = find_table (table_id);

        if (p_table == NULL) {
            continue;
        }

        if (resp_key_count != num_allowed_keys) {
            ut_printf ("%s(): Invalid Key Count. Expected: %d, Received: %d\r\n",
                       __FUNCTION__, num_allowed_keys, resp_key_count);
            return false;
        }

        ut_printf ("%s(): switch_id: %d, table_id: %ld, entry_id: %ld.\r\n",
                   __FUNCTION__, switch_id, table_id, entry_id);

        p_entry = ut_get_entry_by_entry_id (p_table, entry_id);

        if (p_entry == NULL) {
            ut_printf ("%s(): Entry (%ld) NOT present.\r\n",
                       __FUNCTION__, entry_id);
            return false;
        }

        if (p_entry->to_be_verified == false) {
            ut_printf ("%s(): to_be_verified NOT set\r\n", __FUNCTION__);
            return false;
        }

        if (validate_entry_obj (obj, *p_entry) == false) {
            return (false);
        }

        p_entry->verified = true;
    }

    if (cps_api_get_request_close (&params) != cps_api_ret_code_OK) {
        ut_printf ("cps_api_request_close () failed. \r\n");
        return (false);
    }

    return (true);
}

bool nas_acl_ut_entry_get_by_table_test (nas_acl_ut_table_t& table)
{
    cps_api_object_t obj;

    ut_init_all_verified_flags (table);

    obj = cps_api_object_create ();

    if (obj == NULL) {
        ut_printf ("%s() Obj creation failed. Switch Id: %d, Table Id: %ld\n",
                   __FUNCTION__, table.switch_id, table.table_id);
        return false;
    }

    cps_api_key_from_attr_with_qual (cps_api_object_key (obj),
                                     BASE_ACL_ENTRY_OBJ,
                                     cps_api_qualifier_TARGET);
    cps_api_set_key_data (obj, BASE_ACL_ENTRY_TABLE_ID,
                          cps_api_object_ATTR_T_U64,
                          &table.table_id, sizeof (uint64_t));

    if (!ut_entry_get_bulk (obj)) {
        ut_printf ("%s() ut_entry_get_bulk(). Switch Id: %d, Table Id: %ld\n",
                   __FUNCTION__, table.switch_id, table.table_id);
        return false;
    }

    if (!ut_validate_verified_flags ()) {
        ut_printf ("%s() ut_validate_verified_flags(). Switch Id: %d, "
                   "Table Id: %ld\n",
                   __FUNCTION__, table.switch_id, table.table_id);
        return false;
    }

    ut_clear_all_verified_flags (table);

    return true;
}

bool nas_acl_ut_entry_get_by_switch_test (nas_switch_id_t switch_id)
{
    cps_api_object_t obj;
    uint32_t         index;

    for (index = 0; index < NAS_ACL_UT_MAX_TABLES; index++) {
        if (g_nas_acl_ut_tables [index].switch_id == switch_id) {
            ut_init_all_verified_flags (g_nas_acl_ut_tables [index]);
        }
    }

    obj = cps_api_object_create ();

    if (obj == NULL) {
        ut_printf ("%s() Obj creation failed. Switch Id: %d\n",
                   __FUNCTION__, switch_id);
        return false;
    }

    cps_api_key_from_attr_with_qual (cps_api_object_key (obj),
                                     BASE_ACL_ENTRY_OBJ,
                                     cps_api_qualifier_TARGET);

    if (!ut_entry_get_bulk (obj)) {
        ut_printf ("%s() ut_entry_get_bulk () failed. Switch Id: %d\n",
                   __FUNCTION__, switch_id);
        return false;
    }

    if (!ut_validate_verified_flags ()) {
        ut_printf ("%s() ut_validate_verified_flags () failed. Switch Id: %d\n",
                   __FUNCTION__, switch_id);
        return false;
    }

    for (index = 0; index < NAS_ACL_UT_MAX_TABLES; index++) {
        if (g_nas_acl_ut_tables [index].switch_id == switch_id) {
            ut_clear_all_verified_flags (g_nas_acl_ut_tables [index]);
        }
    }

    return true;
}

bool nas_acl_ut_entry_get_all_test ()
{
    cps_api_object_t obj;
    uint32_t         index;

    for (index = 0; index < NAS_ACL_UT_MAX_TABLES; index++) {
        ut_init_all_verified_flags (g_nas_acl_ut_tables [index]);
    }

    obj = cps_api_object_create ();

    if (obj == NULL) {
        ut_printf ("%s() Obj creation failed.\n", __FUNCTION__);
        return false;
    }

    cps_api_key_from_attr_with_qual (cps_api_object_key (obj),
                                     BASE_ACL_ENTRY_OBJ,
                                     cps_api_qualifier_TARGET);

    if (!ut_entry_get_bulk (obj)) {
        ut_printf ("%s() ut_entry_get_bulk () failed.\n", __FUNCTION__);
        return false;
    }

    if (!ut_validate_verified_flags ()) {
        ut_printf ("%s() ut_validate_verified_flags() failed.\n", __FUNCTION__);
        return false;
    }

    for (index = 0; index < NAS_ACL_UT_MAX_TABLES; index++) {
        ut_clear_all_verified_flags (g_nas_acl_ut_tables [index]);
    }

    return true;
}

static void _cps_fill_entry_key (cps_api_object_t obj, const ut_entry_t& entry)
{
    cps_api_set_key_data (obj, BASE_ACL_ENTRY_TABLE_ID, cps_api_object_ATTR_T_U64,
            &entry.table_id, sizeof (uint64_t));
    cps_api_set_key_data (obj, BASE_ACL_ENTRY_ID, cps_api_object_ATTR_T_U64,
            &entry.entry_id, sizeof (uint64_t));
}

static void _cps_fill_filter_upd_key (cps_api_object_t obj, const ut_entry_t& entry,
        const ut_filter_info_t& filter_info)
{
    cps_api_key_from_attr_with_qual (cps_api_object_key (obj), BASE_ACL_ENTRY_MATCH,
            cps_api_qualifier_TARGET);
    _cps_fill_entry_key (obj, entry);
    cps_api_set_key_data (obj, BASE_ACL_ENTRY_MATCH_TYPE, cps_api_object_ATTR_T_U32,
            &filter_info.type, sizeof (uint32_t));
}

static void _cps_fill_action_upd_key (cps_api_object_t obj, const ut_entry_t& entry,
        const ut_action_info_t& action_info)
{
    cps_api_key_from_attr_with_qual (cps_api_object_key (obj), BASE_ACL_ENTRY_ACTION,
            cps_api_qualifier_TARGET);
    _cps_fill_entry_key (obj, entry);
    cps_api_set_key_data (obj, BASE_ACL_ENTRY_ACTION_TYPE, cps_api_object_ATTR_T_U32,
            &action_info.type, sizeof (uint32_t));
}

static bool _cps_fill_filter_upd (cps_api_object_t obj, const ut_entry_t& entry,
        const ut_filter_info_t& filter)
{
    const auto& map_kv = nas_acl_get_filter_map().find (filter.type);
    uint64_t val1, val2;

    if (map_kv == nas_acl_get_filter_map().end ()) {
        ut_printf ("FAILED: Could not Find filter type %d\r\n", filter.type);
        return false;
    }

    const nas_acl_filter_info_t& map_info = map_kv->second;
    ut_attr_id_list_t             parent_list;

    parent_list.push_back (map_info.val.attr_id);
    ut_val_list_t val_list;
    if (filter.type == BASE_ACL_MATCH_TYPE_SRC_IP ||
        filter.type == BASE_ACL_MATCH_TYPE_DST_IP) {
        ip_buf[0] = (uint8_t)sizeof(dn_ipv4_addr_t);
        memcpy(&ip_buf[1], &filter.new_val1, sizeof(dn_ipv4_addr_t));
        mask_buf[0] = (uint8_t)sizeof(dn_ipv4_addr_t);
        memcpy(&mask_buf[1], &filter.new_val2, sizeof(dn_ipv4_addr_t));
        val1 = (uint64_t)ip_buf;
        val2 = (uint64_t)mask_buf;
    } else {
        val1 = filter.new_val1;
        val2 = filter.new_val2;
    }
    val_list.push_back(val1);
    auto it = _optional_filter_type.find(filter.type);
    if (it != _optional_filter_type.end()) {
        val_list.push_back(1);
    }
    val_list.push_back(val2);

    if (!ut_copy_data_to_obj (parent_list, map_info.child_list,
                              obj, map_info.val.data_type,
                              map_info.val.data_len,
                              map_info.val.mode == NAS_ACL_ATTR_MODE_OPTIONAL,
                              val_list)) {
        ut_printf ("Failed incr modify filter %s", nas_acl_filter_type_name (filter.type));
        return false;
    }

    return true;
}

static bool _cps_fill_action_upd (cps_api_object_t obj, const ut_entry_t& entry,
        const ut_action_info_t& action)
{
    const auto& map_kv = nas_acl_get_action_map().find (action.type);

    if (map_kv == nas_acl_get_action_map().end ()) {
        ut_printf ("FAILED: Could not Find filter type %d\r\n", action.type);
        return false;
    }

    const nas_acl_action_info_t& map_info = map_kv->second;
    ut_attr_id_list_t             parent_list;

    parent_list.push_back (map_info.val.attr_id);
    ut_val_list_t val_list {action.new_val1, action.new_val2};

    if (!ut_copy_data_to_obj (parent_list, map_info.child_list,
                              obj, map_info.val.data_type,
                              map_info.val.data_len,
                              map_info.val.mode == NAS_ACL_ATTR_MODE_OPTIONAL,
                              val_list)) {
        ut_printf ("Failed incr modify action %s", nas_acl_action_type_name (action.type));
        return false;
    }

    return true;
}

bool nas_acl_ut_entry_incr_modify_test (nas_acl_ut_table_t& table)
{

    uint32_t                     index;

    ut_printf ("---------- ACL Entry Incremental Modify TEST STARTED ------------\r\n");

    for (const auto& map_kv: _entry_map_input) {

        index = map_kv.first;
        const ut_entry_info_t& entry_info = map_kv.second;
        if (index == _ALL_FIELDS_ENTRY) continue;

        auto entry_kv = table.entries.find (index);
        if (entry_kv == table.entries.end ()) {
            return false;
        }

        ut_entry_t& entry = entry_kv->second;
        cps_api_transaction_params_t  params;

        if (cps_api_transaction_init (&params) != cps_api_ret_code_OK) {
            return cps_api_ret_code_ERR;
        }

        for (auto& filter_info: entry_info.filter_info_list) {

            if (filter_info.mod == _NO_OP) continue;

            cps_api_object_t obj = cps_api_object_create ();
            if (obj == NULL) {
                ut_printf ("cps_api_object_create () failed. \r\n");
                return (false);
            }
            cps_api_object_guard g(obj);

            _cps_fill_filter_upd_key (obj, entry, filter_info);
            if (filter_info.mod == _ADD_LATER) {
                _cps_fill_filter_upd (obj, entry, filter_info);
                cps_api_create (&params, obj);
            }
            if (filter_info.mod == _MODIFY) {
                _cps_fill_filter_upd (obj, entry, filter_info);
                cps_api_set (&params, obj);
            }
            if (filter_info.mod == _DELETE) {
                cps_api_delete (&params, obj);
            }
            g.release();
        }

        for (auto& action_info: entry_info.action_info_list) {

            if (action_info.mod == _NO_OP) continue;

            cps_api_object_t obj = cps_api_object_create ();
            if (obj == NULL) {
                ut_printf ("cps_api_object_create () failed. \r\n");
                return (false);
            }
            cps_api_object_guard g(obj);

            _cps_fill_action_upd_key (obj, entry, action_info);
            if (action_info.mod == _ADD_LATER) {
                _cps_fill_action_upd (obj, entry, action_info);
                cps_api_create (&params, obj);
            } else if (action_info.mod == _MODIFY) {
                _cps_fill_action_upd (obj, entry, action_info);
                cps_api_set (&params, obj);
            } else if (action_info.mod == _DELETE) {
                cps_api_delete (&params, obj);
            }
            g.release();
        }
        auto rc = nas_acl_ut_cps_api_commit (&params, false);
        if (rc != cps_api_ret_code_OK) {
            ut_printf ("%s(): nas_acl_ut_cps_api_commit failed 0x%x\r\n",
                    __FUNCTION__, rc);
            return false;
        }

        if (cps_api_transaction_close (&params) != cps_api_ret_code_OK) {
            return false;
        }
    }
    ut_printf ("********** ACL Entry Incremental Modify TEST PASSED ************\r\n\n");
    return true;
}

bool nas_acl_ut_lag_create(const char *lag_name, int sub_if_num, ...)
{
    va_list ap;
    cps_api_object_t obj = cps_api_object_create();

    ut_printf("--- Create LAG interface %s ---\n", lag_name);

    cps_api_key_from_attr_with_qual(cps_api_object_key(obj),
               DELL_BASE_IF_CMN_IF_INTERFACES_INTERFACE_OBJ, cps_api_qualifier_TARGET);
    cps_api_object_attr_add(obj,IF_INTERFACES_INTERFACE_TYPE,
           (const char *)IF_INTERFACE_TYPE_IANAIFT_IANA_INTERFACE_TYPE_IANAIFT_IEEE8023ADLAG,
           strlen(IF_INTERFACE_TYPE_IANAIFT_IANA_INTERFACE_TYPE_IANAIFT_IEEE8023ADLAG) + 1);
    cps_api_object_attr_add(obj,IF_INTERFACES_INTERFACE_NAME,lag_name, strlen(lag_name) + 1);
    cps_api_object_attr_add_u32(obj, IF_INTERFACES_INTERFACE_ENABLED, 1);

    va_start(ap, sub_if_num);
    const char *sub_ifname;

    cps_api_attr_id_t ids[3] = {DELL_IF_IF_INTERFACES_INTERFACE_MEMBER_PORTS,0,
                                DELL_IF_IF_INTERFACES_INTERFACE_MEMBER_PORTS_NAME };
    const int ids_len = sizeof(ids)/sizeof(ids[0]);
    while(sub_if_num > 0) {
        sub_ifname = va_arg(ap, const char *);
        if (!sub_ifname) {
            break;
        }
        cps_api_object_e_add(obj, ids, ids_len, cps_api_object_ATTR_T_BIN,
                             sub_ifname, strlen(sub_ifname) + 1);
        ids[1] ++;
        sub_if_num --;
    }
    va_end(ap);

    cps_api_transaction_params_t tr;
    bool rc = false;
    do {
        if (cps_api_transaction_init(&tr) != cps_api_ret_code_OK) {
            break;
        }
        cps_api_create(&tr, obj);
        if (cps_api_commit(&tr) != cps_api_ret_code_OK) {
            break;
        }
        rc = true;
    } while(0);

    if (rc) {
        ut_printf("*** Create LAG interface done ***\n");
    } else {
        ut_printf("*** Failed to create LAG ***\n");
    }
    cps_api_transaction_close(&tr);
    return rc;
}

bool nas_acl_ut_lag_delete(const char *lag_name)
{
    cps_api_object_t obj = cps_api_object_create();

    ut_printf("--- Delete LAG interface name %s ---\n", lag_name);
    cps_api_key_from_attr_with_qual(cps_api_object_key(obj),
                                    DELL_BASE_IF_CMN_IF_INTERFACES_INTERFACE_OBJ,
                                    cps_api_qualifier_TARGET);
    cps_api_object_attr_add(obj, IF_INTERFACES_INTERFACE_NAME,
                            lag_name, strlen(lag_name) + 1);

    cps_api_transaction_params_t tr;
    bool rc = false;
    do {
        if (cps_api_transaction_init(&tr) != cps_api_ret_code_OK) {
            break;
        }
        cps_api_delete(&tr, obj);
        if (cps_api_commit(&tr) != cps_api_ret_code_OK) {
            break;
        }
        rc = true;
    } while(0);

    if (rc) {
        ut_printf("*** Delete LAG interface done ***\n");
    } else {
        ut_printf("*** Failed to delete LAG ***\n");
    }
    cps_api_transaction_close(&tr);
    return rc;
}

bool nas_acl_ut_src_port_entry_create(nas_acl_ut_table_t& table,
                                      int priority, const char *intf_name)
{
    ut_entry_t entry;
    ut_filter_t filter;
    ut_action_t action;
    cps_api_transaction_params_t params;
    const char *src_ip = "1.2.3.4";
    const char *ip_mask = "255.255.255.0";

    ut_printf("--- Create entry to test port filtering ---\n");

    entry.switch_id = table.switch_id;
    entry.table_id = table.table_id;
    entry.priority = priority;

    filter.type = BASE_ACL_MATCH_TYPE_SRC_IP;
    if (!ut_add_filter_ip_mask(entry, filter, src_ip, ip_mask)) {
        return false;
    }

    filter.type = BASE_ACL_MATCH_TYPE_IP_PROTOCOL;
    ut_add_filter(entry, filter, 17, 0xff);

    filter.type = BASE_ACL_MATCH_TYPE_SRC_PORT;
    uint32_t if_index = if_nametoindex(intf_name);
    if (if_index == 0) {
        return false;
    }
    ut_add_filter(entry, filter, if_index, 0);

    action.type = BASE_ACL_ACTION_TYPE_PACKET_ACTION;
    ut_add_action(entry, action, BASE_ACL_PACKET_ACTION_TYPE_DROP, 0);

    if (cps_api_transaction_init(&params) != cps_api_ret_code_OK) {
        return false;
    }

    bool rc = false;
    do {
        if (ut_fill_entry_create_req(&params, entry) == false) {
            break;
        }

        if (nas_acl_ut_cps_api_commit(&params, false) != cps_api_ret_code_OK) {
            break;
        }
        rc = true;
    } while(0);

    if (rc) {
        size_t count = cps_api_object_list_size(params.prev);
        if (count > 0) {
            cps_api_object_t obj = cps_api_object_list_get(params.prev, 0);
            cps_api_object_attr_t attr = cps_api_get_key_data(obj, BASE_ACL_ENTRY_ID);
            entry.entry_id = cps_api_object_attr_data_u64(attr);
            entry.index = table.entries.size();
            table.entries.insert(std::make_pair(entry.index, std::move(entry)));
        }
    }

    if (cps_api_transaction_close(&params) != cps_api_ret_code_OK) {
        return false;
    }

    ut_printf("*** Entry create done ***\n");

    return rc;
}

bool nas_acl_ut_nbr_dst_hit_entry_create(nas_acl_ut_table_t& table,
                                         int priority)
{
    ut_entry_t entry;
    ut_filter_t filter;
    ut_action_t action;
    cps_api_transaction_params_t params;
    const char *dst_ip = "192.168.100.1";
    const char *ip_mask = "255.255.255.0";

    ut_printf("--- Create entry to test neighbor destination hit filtering ---\n");

    entry.switch_id = table.switch_id;
    entry.table_id = table.table_id;
    entry.priority = priority;

    filter.type = BASE_ACL_MATCH_TYPE_DST_IP;
    if (!ut_add_filter_ip_mask(entry, filter, dst_ip, ip_mask)) {
        return false;
    }

    filter.type = BASE_ACL_MATCH_TYPE_NEIGHBOR_DST_HIT;
    ut_add_filter(entry, filter, 0, 0);

    action.type = BASE_ACL_ACTION_TYPE_PACKET_ACTION;
    ut_add_action(entry, action, BASE_ACL_PACKET_ACTION_TYPE_DROP, 0);

    if (cps_api_transaction_init(&params) != cps_api_ret_code_OK) {
        return false;
    }

    bool rc = false;
    do {
        if (ut_fill_entry_create_req(&params, entry) == false) {
            break;
        }

        if (nas_acl_ut_cps_api_commit(&params, false) != cps_api_ret_code_OK) {
            break;
        }
        rc = true;
    } while(0);

    if (rc) {
        size_t count = cps_api_object_list_size(params.prev);
        if (count > 0) {
            cps_api_object_t obj = cps_api_object_list_get(params.prev, 0);
            cps_api_object_attr_t attr = cps_api_get_key_data(obj, BASE_ACL_ENTRY_ID);
            entry.entry_id = cps_api_object_attr_data_u64(attr);
            entry.index = table.entries.size();
            table.entries.insert(std::make_pair(entry.index, std::move(entry)));
        }
    }

    if (cps_api_transaction_close(&params) != cps_api_ret_code_OK) {
        return false;
    }

    ut_printf("*** Entry create done ***\n");

    return rc;
}

bool nas_acl_ut_route_dst_hit_entry_create(nas_acl_ut_table_t& table,
                                           int priority)
{
    ut_entry_t entry;
    ut_filter_t filter;
    ut_action_t action;
    cps_api_transaction_params_t params;
    const char *dst_ip = "192.168.100.2";
    const char *ip_mask = "255.255.255.0";


    ut_printf("--- Create entry to test routing destination hit filtering ---\n");

    entry.switch_id = table.switch_id;
    entry.table_id = table.table_id;
    entry.priority = priority;

    filter.type = BASE_ACL_MATCH_TYPE_DST_IP;
    if (!ut_add_filter_ip_mask(entry, filter, dst_ip, ip_mask)) {
        return false;
    }
    filter.type = BASE_ACL_MATCH_TYPE_ROUTE_DST_HIT;
    ut_add_filter(entry, filter, 0, 0);

    action.type = BASE_ACL_ACTION_TYPE_PACKET_ACTION;
    ut_add_action(entry, action, BASE_ACL_PACKET_ACTION_TYPE_DROP, 0);

    if (cps_api_transaction_init(&params) != cps_api_ret_code_OK) {
        return false;
    }

    bool rc = false;
    do {
        if (ut_fill_entry_create_req(&params, entry) == false) {
            break;
        }

        if (nas_acl_ut_cps_api_commit(&params, false) != cps_api_ret_code_OK) {
            break;
        }
        rc = true;
    } while(0);

    if (rc) {
        size_t count = cps_api_object_list_size(params.prev);
        if (count > 0) {
            cps_api_object_t obj = cps_api_object_list_get(params.prev, 0);
            cps_api_object_attr_t attr = cps_api_get_key_data(obj, BASE_ACL_ENTRY_ID);
            entry.entry_id = cps_api_object_attr_data_u64(attr);
            entry.index = table.entries.size();
            table.entries.insert(std::make_pair(entry.index, std::move(entry)));
        }
    }

    if (cps_api_transaction_close(&params) != cps_api_ret_code_OK) {
        return false;
    }

    ut_printf("*** Entry create done ***\n");

    return rc;
}

static bool nht_add_del(void *nht_dest, uint32_t af_family, bool is_add)
{
    uint32_t ip;
    cps_api_transaction_params_t tr;

    cps_api_object_t obj = cps_api_object_create();
    cps_api_key_from_attr_with_qual(cps_api_object_key(obj),
                                    BASE_ROUTE_NH_TRACK_OBJ,cps_api_qualifier_TARGET);

    cps_api_object_attr_add_u32(obj,BASE_ROUTE_NH_TRACK_VRF_ID,0);
    cps_api_object_attr_add_u32(obj,BASE_ROUTE_NH_TRACK_AF,af_family);
    if (af_family == AF_INET6) {
        cps_api_object_attr_add(obj,BASE_ROUTE_NH_TRACK_DEST_ADDR,(struct in6_addr *) nht_dest,
                                sizeof(struct in6_addr));
    } else {
        cps_api_object_attr_add_u32(obj,BASE_ROUTE_NH_TRACK_AF,AF_INET);
        ip=((struct in_addr *) nht_dest)->s_addr;
        cps_api_object_attr_add(obj,BASE_ROUTE_NH_TRACK_DEST_ADDR,&ip,sizeof(ip));
    }

    if (cps_api_transaction_init(&tr)!=cps_api_ret_code_OK) {
        return false;
    }
    if (is_add) {
        cps_api_create(&tr,obj);
    } else {
        cps_api_delete(&tr,obj);
    }
    if (cps_api_commit(&tr)!=cps_api_ret_code_OK) {
        return false;
    }
    cps_api_transaction_close(&tr);

    return true;
}

static bool nht_config(const char *ip_str, uint32_t af_family, bool is_add)
{
    struct in_addr a;
    struct in6_addr a6;

    if (af_family == AF_INET6) {
        inet_pton(AF_INET6, ip_str, &a6);
        return nht_add_del ((void *) &a6, af_family, is_add);
    } else {
        inet_aton(ip_str,&a);
        return nht_add_del ((void *) &a, af_family, is_add);
    }
}

static bool nht_get_specific(const char *ip_str, uint32_t af_family,
                             nas::ndi_obj_id_table_t& nh_id_table)
{
    struct in_addr a;
    uint32_t ip;
    cps_api_get_params_t gp;
    if (cps_api_get_request_init(&gp) != cps_api_ret_code_OK)
        return false;

    inet_aton(ip_str, &a);

    cps_api_object_t obj = cps_api_object_list_create_obj_and_append(gp.filters);
    cps_api_key_from_attr_with_qual(cps_api_object_key(obj),BASE_ROUTE_NH_TRACK_OBJ,
                                        cps_api_qualifier_TARGET);


    cps_api_object_attr_add_u32(obj,BASE_ROUTE_NH_TRACK_AF,AF_INET);

    ip=a.s_addr;
    cps_api_object_attr_add(obj,BASE_ROUTE_NH_TRACK_DEST_ADDR,&ip,sizeof(ip));

    if (cps_api_get(&gp)!=cps_api_ret_code_OK) {
        ut_printf("%s: failed to get nh-track\n", __FUNCTION__);
        return false;
    }
    if(cps_api_object_list_size(gp.list) == 0) {
        ut_printf("%s: no nh-track object found\n", __FUNCTION__);
        return false;
    }

    obj = cps_api_object_list_get(gp.list, 0);
    if (obj == NULL) {
        return false;
    }
    cps_api_object_attr_t attr;
    attr = cps_api_object_attr_get(obj, BASE_ROUTE_NH_TRACK_NH_COUNT);
    if (attr == NULL) {
        ut_printf("%s: no nh_count attribute found\n", __FUNCTION__);
        return false;
    }
    uint32_t nh_cnt = cps_api_object_attr_data_u32(attr);
    if (nh_cnt == 0) {
        ut_printf("%s: nh_count is 0\n", __FUNCTION__);
        return false;
    }
    cps_api_attr_id_t attr_id_list[] = {BASE_ROUTE_NH_TRACK_DATA};
    if (!nas::ndi_obj_id_table_cps_unserialize(nh_id_table, obj, attr_id_list,
            sizeof(attr_id_list) / sizeof(attr_id_list[0]))) {
        ut_printf("%s: Failed to parse opaque data\n", __FUNCTION__);
        return false;
    }

    if (cps_api_get_request_close(&gp) != cps_api_ret_code_OK)
        return false;

    return true;
}

static inline void ut_add_nh_action(ut_entry_t& entry, ut_action_t& action,
                                    uint32_t vrf_id, uint32_t af,
                                    const char *dest_ip,
                                    next_hop_id_t nh_id)
{
    static uint8_t nh_dest_buf[64];
    std_ip_addr_t ip_addr_holder;
    if (std_str_to_ip(dest_ip, &ip_addr_holder) == false) {
        return;
    }
    uint32_t ip_val = (uint32_t)ip_addr_holder.u.ipv4.s_addr;
    uint8_t addr_len = sizeof(dn_ipv4_addr_t);
    nh_dest_buf[0] = addr_len;
    memcpy(&nh_dest_buf[1], &ip_val, addr_len);
    action.val_list.clear();
    action.val_list.push_back(vrf_id);
    action.val_list.push_back(af);
    action.val_list.push_back(1);
    action.val_list.push_back((uint64_t)nh_dest_buf);
    action.val_list.push_back(0);
    action.val_list.push_back((uint64_t)nh_id);

    entry.action_list.insert(action);
}

const char *nh_dest_ip = "30.0.0.5";
const char *nh_mac_addr = "01:02:03:04:05:06";
const char *local_if_name = "e101-028-0";
const char *local_ip_addr = "30.0.0.1";
const char *route_dest_net = "40.0.0.0";
const char *route_dest_mask = "255.255.255.0";

bool nas_acl_ut_nh_redir_entry_create(nas_acl_ut_table_t& table,
                                      int priority)
{
    ut_entry_t entry;
    ut_filter_t filter;
    ut_action_t action;
    cps_api_transaction_params_t params;
    const char *dst_ip = "192.168.100.1";
    const char *ip_mask = "255.255.255.0";
    char cmdbuf[512];

    ut_printf("--- Create entry to test nexthop redirect action ---\n");

    entry.switch_id = table.switch_id;
    entry.table_id = table.table_id;
    entry.priority = priority;

    filter.type = BASE_ACL_MATCH_TYPE_DST_IP;
    if (!ut_add_filter_ip_mask(entry, filter, dst_ip, ip_mask)) {
        return false;
    }

    snprintf(cmdbuf, sizeof(cmdbuf), "ifconfig %s %s/24 up", local_if_name, local_ip_addr);
    SYSTEM(cmdbuf);
    snprintf(cmdbuf, sizeof(cmdbuf), "arp -s %s %s", nh_dest_ip, nh_mac_addr);
    SYSTEM(cmdbuf);
    snprintf(cmdbuf, sizeof(cmdbuf), "route add -net %s netmask %s gw %s", route_dest_net,
            route_dest_mask, nh_dest_ip);
    SYSTEM(cmdbuf);

    if (!nht_config(nh_dest_ip, AF_INET, true)) {
        return false;
    }
    nas::ndi_obj_id_table_t nh_id_table;
    int wait_cnt = 0;
    while (!nht_get_specific(nh_dest_ip, AF_INET, nh_id_table)) {
        wait_cnt ++;
        if (wait_cnt > 20) {
            ut_printf("Failed to create nexthop tracking object\n");
            return false;
        }
        sleep(1);
    }

    next_hop_id_t npu_nh_id = 0;
    for (auto& id_map: nh_id_table) {
        npu_nh_id = id_map.second;
        break;
    }
    action.type = BASE_ACL_ACTION_TYPE_REDIRECT_IP_NEXTHOP;
    ut_add_nh_action(entry, action, 0, AF_INET, nh_dest_ip, npu_nh_id);

    if (cps_api_transaction_init(&params) != cps_api_ret_code_OK) {
        return false;
    }

    bool rc = false;
    do {
        if (ut_fill_entry_create_req(&params, entry) == false) {
            break;
        }

        if (nas_acl_ut_cps_api_commit(&params, false) != cps_api_ret_code_OK) {
            break;
        }
        rc = true;
    } while(0);

    if (rc) {
        size_t count = cps_api_object_list_size(params.prev);
        if (count > 0) {
            cps_api_object_t obj = cps_api_object_list_get(params.prev, 0);
            cps_api_object_attr_t attr = cps_api_get_key_data(obj, BASE_ACL_ENTRY_ID);
            entry.entry_id = cps_api_object_attr_data_u64(attr);
            entry.index = table.entries.size();
            table.entries.insert(std::make_pair(entry.index, std::move(entry)));
        }
    }

    if (cps_api_transaction_close(&params) != cps_api_ret_code_OK) {
        return false;
    }

    ut_printf("*** Entry create done ***\n");

    return rc;
}

bool nas_acl_ut_table_entry_delete(nas_acl_ut_table_t& table)
{
    cps_api_object_t obj;
    cps_api_transaction_params_t params;

    ut_printf("--- Delete all entries from table %s ---\n", table.name);

    for (auto& item: table.entries) {
        if (cps_api_transaction_init(&params) != cps_api_ret_code_OK) {
            return false;
        }
        ut_entry_t& entry = item.second;
        obj = cps_api_object_create();
        cps_api_key_from_attr_with_qual(cps_api_object_key(obj), BASE_ACL_ENTRY_OBJ,
                                        cps_api_qualifier_TARGET);
        cps_api_set_key_data(obj, BASE_ACL_ENTRY_TABLE_ID, cps_api_object_ATTR_T_U64,
                             &entry.table_id, sizeof(uint64_t));
        cps_api_set_key_data(obj, BASE_ACL_ENTRY_ID, cps_api_object_ATTR_T_U64,
                             &entry.entry_id, sizeof(uint64_t));
        cps_api_delete(&params, obj);
        if (cps_api_commit(&params) != cps_api_ret_code_OK) {
            ut_printf("Failed to delete entry %d\n", item.first);
            cps_api_transaction_close(&params);
            return false;
        }
        cps_api_transaction_close(&params);
    }
    table.entries.clear();

    ut_printf("*** Table entries delete done ***\n");

    return true;
}

bool nas_acl_ut_nh_redir_entry_delete(nas_acl_ut_table_t& table)
{
    char cmdbuf[512];

    if (!nas_acl_ut_table_entry_delete(table)) {
        return true;
    }

    snprintf(cmdbuf, sizeof(cmdbuf), "route del -net %s netmask %s gw %s", route_dest_net,
            route_dest_mask, nh_dest_ip);
    SYSTEM(cmdbuf);
    snprintf(cmdbuf, sizeof(cmdbuf), "arp -d %s", nh_dest_ip);
    SYSTEM(cmdbuf);
    snprintf(cmdbuf, sizeof(cmdbuf), "ifconfig %s 0.0.0.0", local_if_name);
    SYSTEM(cmdbuf);
    snprintf(cmdbuf, sizeof(cmdbuf), "ifconfig %s down", local_if_name);
    SYSTEM(cmdbuf);

    return true;
}
