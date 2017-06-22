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
 * \file   nas_acl_cps_action_map.cpp
 * \brief  This file contains ACL Entry Action Map table initiazation
 * \date   05-2015
 * \author Mukesh MV & Ravikumar Sivasankar
 */
#include "nas_acl_cps.h"
#include "nas_vlan_consts.h"
#include "nas_qos_consts.h"
#include "nas_acl_common.h"

/*
    nas_acl_map_data_t          val;
    nas_acl_map_data_list_t     child_list;
    nas_acl_action_get_fn_ptr_t get_fn;
    nas_acl_action_set_fn_ptr_t set_fn;
 */
static const nas_acl_action_map_t _action_map =
{
    {BASE_ACL_ACTION_TYPE_PACKET_ACTION,
        {
            "ACTION_TYPE_PACKET_ACTION",
            {
                BASE_ACL_ENTRY_ACTION_PACKET_ACTION_VALUE,
                NAS_ACL_DATA_U32,
                sizeof (uint32_t),
                NAS_ACL_ATTR_MODE_MANDATORY,
                {},
            },
            {
                {},
            },
            &nas_acl_action_t::get_pkt_action_val,
            &nas_acl_action_t::set_pkt_action_val,
        },
    },

    {BASE_ACL_ACTION_TYPE_REDIRECT_PORT,
        {
            "ACTION_TYPE_REDIRECT_PORT",
            {
                BASE_ACL_ENTRY_ACTION_REDIRECT_PORT_VALUE,
                NAS_ACL_DATA_IFINDEX,
                sizeof(uint32_t),
                NAS_ACL_ATTR_MODE_MANDATORY,
                {},
            },
            {
                {},
            },
            &nas_acl_action_t::get_action_ifindex,
            &nas_acl_action_t::set_action_ifindex,
        },
    },

    {BASE_ACL_ACTION_TYPE_REDIRECT_IP_NEXTHOP,
        {
            "ACTION_TYPE_REDIRECT_IP_NEXTHOP",
            {
                BASE_ACL_ENTRY_ACTION_IP_NEXTHOP_GROUP_VALUE,
                NAS_ACL_DATA_EMBEDDED,
                {},
            },
            {
                {
                    BASE_ACL_ENTRY_ACTION_IP_NEXTHOP_GROUP_VALUE_VRF_ID,
                    NAS_ACL_DATA_U32,
                    sizeof (uint32_t),
                    NAS_ACL_ATTR_MODE_MANDATORY,
                    {},
                },
                {
                    BASE_ACL_ENTRY_ACTION_IP_NEXTHOP_GROUP_VALUE_AF,
                    NAS_ACL_DATA_U32,
                    sizeof (uint32_t),
                    NAS_ACL_ATTR_MODE_MANDATORY,
                    {},
                },
                {
                    BASE_ACL_ENTRY_ACTION_IP_NEXTHOP_GROUP_VALUE_DEST_ADDR_BASE_CMN_IPV4_ADDRESS,
                    NAS_ACL_DATA_BIN,
                    sizeof(dn_ipv4_addr_t),
                    NAS_ACL_ATTR_MODE_OPTIONAL,
                    {},
                },
                {
                    BASE_ACL_ENTRY_ACTION_IP_NEXTHOP_GROUP_VALUE_DEST_ADDR_BASE_CMN_IPV6_ADDRESS,
                    NAS_ACL_DATA_BIN,
                    sizeof(dn_ipv6_addr_t),
                    NAS_ACL_ATTR_MODE_OPTIONAL,
                    {},
                },
                {
                    BASE_ACL_ENTRY_ACTION_IP_NEXTHOP_GROUP_VALUE_DATA,
                    NAS_ACL_DATA_OPAQUE,
                    0,
                    NAS_ACL_ATTR_MODE_MANDATORY,
                    {},
                },
            },
            &nas_acl_action_t::get_opaque_data_nexthop_val,
            &nas_acl_action_t::set_opaque_data_nexthop_val,
        },
    },

    {BASE_ACL_ACTION_TYPE_FLOOD,
        {
            "ACTION_TYPE_FLOOD",
            {
                0, NAS_ACL_DATA_NONE, {},
            },
            {},
            NULL,
            NULL,
        },
    },

    {BASE_ACL_ACTION_TYPE_MIRROR_INGRESS,
        {
            "ACTION_TYPE_MIRROR_INGRESS",
            {
                BASE_ACL_ENTRY_ACTION_MIRROR_INGRESS_VALUE,
                NAS_ACL_DATA_EMBEDDED_LIST,
                {},
            },
            {
                {
                    BASE_ACL_ENTRY_ACTION_MIRROR_INGRESS_VALUE_INDEX,
                    NAS_ACL_DATA_OBJ_ID,
                    sizeof (nas_obj_id_t),
                    NAS_ACL_ATTR_MODE_MANDATORY,
                    {},
                },
                {
                    BASE_ACL_ENTRY_ACTION_MIRROR_INGRESS_VALUE_DATA,
                    NAS_ACL_DATA_OPAQUE,
                    0,
                    NAS_ACL_ATTR_MODE_MANDATORY,
                    {},
                },
            },
            &nas_acl_action_t::get_opaque_data_action_val,
            &nas_acl_action_t::set_opaque_data_list_action_val,
        },
    },

    {BASE_ACL_ACTION_TYPE_MIRROR_EGRESS,
        {
            "ACTION_TYPE_MIRROR_EGRESS",
            {
                BASE_ACL_ENTRY_ACTION_MIRROR_EGRESS_VALUE,
                NAS_ACL_DATA_EMBEDDED_LIST,
                {},
            },
            {
                {
                    BASE_ACL_ENTRY_ACTION_MIRROR_EGRESS_VALUE_INDEX,
                    NAS_ACL_DATA_OBJ_ID,
                    sizeof (nas_obj_id_t),
                    NAS_ACL_ATTR_MODE_MANDATORY,
                    {},
                },
                {
                    BASE_ACL_ENTRY_ACTION_MIRROR_EGRESS_VALUE_DATA,
                    NAS_ACL_DATA_OPAQUE,
                    0,
                    NAS_ACL_ATTR_MODE_MANDATORY,
                    {},
                },
            },
            &nas_acl_action_t::get_opaque_data_action_val,
            &nas_acl_action_t::set_opaque_data_list_action_val,
        },
    },

    {BASE_ACL_ACTION_TYPE_SET_COUNTER,
        {
            "ACTION_TYPE_SET_COUNTER",
            {
                BASE_ACL_ENTRY_ACTION_COUNTER_VALUE,
                NAS_ACL_DATA_OBJ_ID,
                sizeof (nas_obj_id_t),
                NAS_ACL_ATTR_MODE_MANDATORY,
                {},
            },
            {},
            &nas_acl_action_t::get_obj_id_action_val,
            &nas_acl_action_t::set_obj_id_action_val,
        },
    },

    {BASE_ACL_ACTION_TYPE_SET_POLICER,
        {
            "ACTION_TYPE_SET_POLICER",
            {
                BASE_ACL_ENTRY_ACTION_POLICER_VALUE,
                NAS_ACL_DATA_EMBEDDED,
                {},
            },
            {
                {
                    BASE_ACL_ENTRY_ACTION_POLICER_VALUE_INDEX,
                    NAS_ACL_DATA_OBJ_ID,
                    sizeof (nas_obj_id_t),
                    NAS_ACL_ATTR_MODE_MANDATORY,
                    {},
                },
                {
                    BASE_ACL_ENTRY_ACTION_POLICER_VALUE_DATA,
                    NAS_ACL_DATA_OPAQUE,
                    0,
                    NAS_ACL_ATTR_MODE_MANDATORY,
                    {},
                },
            },
            &nas_acl_action_t::get_opaque_data_action_val,
            &nas_acl_action_t::set_opaque_data_action_val,
        },
    },

    {BASE_ACL_ACTION_TYPE_DECREMENT_TTL,
        {
            "ACTION_TYPE_DECREMENT_TTL",
            {
                0, NAS_ACL_DATA_NONE, {},
            },
            {},
            NULL,
            NULL,
        },
    },

    {BASE_ACL_ACTION_TYPE_SET_TC,
        {
            "ACTION_TYPE_SET_TC",
            {
                BASE_ACL_ENTRY_ACTION_NEW_TC_VALUE,
                NAS_ACL_DATA_U8,
                sizeof (uint8_t),
                NAS_ACL_ATTR_MODE_MANDATORY,
                {},
            },
            {},
            &nas_acl_action_t::get_u8_action_val,
            &nas_acl_action_t::set_u8_action_val,
        },
    },

    {BASE_ACL_ACTION_TYPE_SET_INNER_VLAN_ID,
        {
            "ACTION_TYPE_SET_INNER_VLAN_ID",
            {
                BASE_ACL_ENTRY_ACTION_NEW_INNER_VLAN_ID_VALUE,
                NAS_ACL_DATA_U16,
                sizeof (uint16_t),
                NAS_ACL_ATTR_MODE_MANDATORY,
                {1, NAS_MAX_VLAN_ID},
            },
            {},
            &nas_acl_action_t::get_u16_action_val,
            &nas_acl_action_t::set_u16_action_val,
        },
    },

    {BASE_ACL_ACTION_TYPE_SET_INNER_VLAN_PRI,
        {
            "ACTION_TYPE_SET_INNER_VLAN_PRI",
            {
                BASE_ACL_ENTRY_ACTION_NEW_INNER_VLAN_PRI_VALUE,
                NAS_ACL_DATA_U8,
                sizeof (uint8_t),
                NAS_ACL_ATTR_MODE_MANDATORY,
                {0, NAS_MAX_DOT1P},
            },
            {},
            &nas_acl_action_t::get_u8_action_val,
            &nas_acl_action_t::set_u8_action_val,
        },
    },

    {BASE_ACL_ACTION_TYPE_SET_OUTER_VLAN_ID,
        {
            "ACTION_TYPE_SET_OUTER_VLAN_ID",
            {
                BASE_ACL_ENTRY_ACTION_NEW_OUTER_VLAN_ID_VALUE,
                NAS_ACL_DATA_U16,
                sizeof (uint16_t),
                NAS_ACL_ATTR_MODE_MANDATORY,
                {1, NAS_MAX_VLAN_ID},
            },
            {},
            &nas_acl_action_t::get_u16_action_val,
            &nas_acl_action_t::set_u16_action_val,
        },
    },

    {BASE_ACL_ACTION_TYPE_SET_OUTER_VLAN_PRI,
        {
            "ACTION_TYPE_SET_OUTER_VLAN_PRI",
            {
                BASE_ACL_ENTRY_ACTION_NEW_OUTER_VLAN_PRI_VALUE,
                NAS_ACL_DATA_U8,
                sizeof (uint8_t),
                NAS_ACL_ATTR_MODE_MANDATORY,
                {0, NAS_MAX_DOT1P},
            },
            {},
            &nas_acl_action_t::get_u8_action_val,
            &nas_acl_action_t::set_u8_action_val,
        },
    },

    {BASE_ACL_ACTION_TYPE_SET_SRC_MAC,
        {
            "ACTION_TYPE_SET_SRC_MAC",
            {
                BASE_ACL_ENTRY_ACTION_NEW_SRC_MAC_VALUE,
                NAS_ACL_DATA_BIN,
                HAL_MAC_ADDR_LEN,
                NAS_ACL_ATTR_MODE_MANDATORY,
                {},
            },
            {},
            &nas_acl_action_t::get_mac_action_val,
            &nas_acl_action_t::set_mac_action_val,
        },
    },

    {BASE_ACL_ACTION_TYPE_SET_DST_MAC,
        {
            "ACTION_TYPE_SET_DST_MAC",
            {
                BASE_ACL_ENTRY_ACTION_NEW_DST_MAC_VALUE,
                NAS_ACL_DATA_BIN,
                HAL_MAC_ADDR_LEN,
                NAS_ACL_ATTR_MODE_MANDATORY,
                {},
            },
            {},
            &nas_acl_action_t::get_mac_action_val,
            &nas_acl_action_t::set_mac_action_val,
        },
    },

    {BASE_ACL_ACTION_TYPE_SET_SRC_IP,
        {
            "ACTION_TYPE_SET_SRC_IP",
            {
                BASE_ACL_ENTRY_ACTION_NEW_SRC_IP_VALUE,
                NAS_ACL_DATA_BIN,
                sizeof (dn_ipv4_addr_t),
                NAS_ACL_ATTR_MODE_MANDATORY,
                {},
            },
            {},
            &nas_acl_action_t::get_ipv4_action_val,
            &nas_acl_action_t::set_ipv4_action_val,
        },
    },

    {BASE_ACL_ACTION_TYPE_SET_DST_IP,
        {
            "ACTION_TYPE_SET_DST_IP",
            {
                BASE_ACL_ENTRY_ACTION_NEW_DST_IP_VALUE,
                NAS_ACL_DATA_BIN,
                sizeof (dn_ipv4_addr_t),
                NAS_ACL_ATTR_MODE_MANDATORY,
                {},
            },
            {},
            &nas_acl_action_t::get_ipv4_action_val,
            &nas_acl_action_t::set_ipv4_action_val,
        },
    },

    {BASE_ACL_ACTION_TYPE_SET_SRC_IPV6,
        {
            "ACTION_TYPE_SET_SRC_IPV6",
            {
                BASE_ACL_ENTRY_ACTION_NEW_SRC_IPV6_VALUE,
                NAS_ACL_DATA_BIN,
                sizeof (dn_ipv6_addr_t),
                NAS_ACL_ATTR_MODE_MANDATORY,
                {},
            },
            {},
            &nas_acl_action_t::get_ipv6_action_val,
            &nas_acl_action_t::set_ipv6_action_val,
        },
    },

    {BASE_ACL_ACTION_TYPE_SET_DST_IPV6,
        {
            "ACTION_TYPE_SET_DST_IPV6",
            {
                BASE_ACL_ENTRY_ACTION_NEW_DST_IPV6_VALUE,
                NAS_ACL_DATA_BIN,
                sizeof (dn_ipv6_addr_t),
                NAS_ACL_ATTR_MODE_MANDATORY,
                {},
            },
            {},
            &nas_acl_action_t::get_ipv6_action_val,
            &nas_acl_action_t::set_ipv6_action_val,
        },
    },

    {BASE_ACL_ACTION_TYPE_SET_DSCP,
        {
            "ACTION_TYPE_SET_DSCP",
            {
                BASE_ACL_ENTRY_ACTION_NEW_DSCP_VALUE,
                NAS_ACL_DATA_U8,
                sizeof (uint8_t),
                NAS_ACL_ATTR_MODE_MANDATORY,
                {0, NAS_MAX_DSCP},
            },
            {},
            &nas_acl_action_t::get_u8_action_val,
            &nas_acl_action_t::set_u8_action_val,
        },
    },

    {BASE_ACL_ACTION_TYPE_SET_L4_SRC_PORT,
        {
            "ACTION_TYPE_SET_L4_SRC_PORT",
            {
                BASE_ACL_ENTRY_ACTION_NEW_L4_SRC_PORT_VALUE,
                NAS_ACL_DATA_U16,
                sizeof (uint16_t),
                NAS_ACL_ATTR_MODE_MANDATORY,
                {},
            },
            {},
            &nas_acl_action_t::get_u16_action_val,
            &nas_acl_action_t::set_u16_action_val,
        },
    },

    {BASE_ACL_ACTION_TYPE_SET_L4_DST_PORT,
        {
            "ACTION_TYPE_SET_L4_DST_PORT",
            {
                BASE_ACL_ENTRY_ACTION_NEW_L4_DST_PORT_VALUE,
                NAS_ACL_DATA_U16,
                sizeof (uint16_t),
                NAS_ACL_ATTR_MODE_MANDATORY,
                {},
            },
            {},
            &nas_acl_action_t::get_u16_action_val,
            &nas_acl_action_t::set_u16_action_val,
        },
    },

    {BASE_ACL_ACTION_TYPE_SET_CPU_QUEUE,
        {
            "ACTION_TYPE_SET_CPU_QUEUE",
            {
                BASE_ACL_ENTRY_ACTION_CPU_QUEUE_VALUE,
                NAS_ACL_DATA_EMBEDDED,
                {},
            },
            {
                {
                    BASE_ACL_ENTRY_ACTION_CPU_QUEUE_VALUE_INDEX,
                    NAS_ACL_DATA_OBJ_ID,
                    sizeof (nas_obj_id_t),
                    NAS_ACL_ATTR_MODE_MANDATORY,
                    {},
                },
                {
                    BASE_ACL_ENTRY_ACTION_CPU_QUEUE_VALUE_DATA,
                    NAS_ACL_DATA_OPAQUE,
                    0,
                    NAS_ACL_ATTR_MODE_MANDATORY,
                    {},
                },
            },
            &nas_acl_action_t::get_opaque_data_action_val,
            &nas_acl_action_t::set_opaque_data_action_val,
        },
    },
    {BASE_ACL_ACTION_TYPE_EGRESS_MASK,
        {
            "ACTION_TYPE_EGRESS_MASK",
            {
                BASE_ACL_ENTRY_ACTION_EGRESS_MASK_VALUE,
                NAS_ACL_DATA_IFINDEX_LIST,
                {},
            },
            {
                {},
            },
            &nas_acl_action_t::get_action_ifindex_list,
            &nas_acl_action_t::set_action_ifindex_list,
        },
    },
    {BASE_ACL_ACTION_TYPE_REDIRECT_PORT_LIST,
        {
            "ACTION_TYPE_REDIRECT_PORT_LIST",
            {
                BASE_ACL_ENTRY_ACTION_REDIRECT_PORT_LIST_VALUE,
                NAS_ACL_DATA_IFINDEX_LIST,
                {},
            },
            {
                {},
            },
            &nas_acl_action_t::get_action_ifindex_list,
            &nas_acl_action_t::set_action_ifindex_list,
        },
    },
    {BASE_ACL_ACTION_TYPE_REDIRECT_INTF,
        {
            "ACTION_TYPE_REDIRECT_INTF",
            {
                BASE_ACL_ENTRY_ACTION_REDIRECT_INTF_VALUE,
                NAS_ACL_DATA_IFNAME,
                HAL_IF_NAME_SZ,
                NAS_ACL_ATTR_MODE_MANDATORY,
                {},
            },
            {
                {},
            },
            &nas_acl_action_t::get_action_ifindex,
            &nas_acl_action_t::set_action_ifindex,
        },
    },
    {BASE_ACL_ACTION_TYPE_EGRESS_INTF_MASK,
        {
            "ACTION_TYPE_EGRESS_INTF_MASK",
            {
                BASE_ACL_ENTRY_ACTION_EGRESS_INTF_MASK_VALUE,
                NAS_ACL_DATA_IFNAME_LIST,
                {},
            },
            {
                {},
            },
            &nas_acl_action_t::get_action_ifindex_list,
            &nas_acl_action_t::set_action_ifindex_list,
        },
    },
    {BASE_ACL_ACTION_TYPE_REDIRECT_INTF_LIST,
        {
            "ACTION_TYPE_REDIRECT_INTF_LIST",
            {
                BASE_ACL_ENTRY_ACTION_REDIRECT_INTF_LIST_VALUE,
                NAS_ACL_DATA_IFNAME_LIST,
                {},
            },
            {
                {},
            },
            &nas_acl_action_t::get_action_ifindex_list,
            &nas_acl_action_t::set_action_ifindex_list,
        },
    },

    {BASE_ACL_ACTION_TYPE_SET_USER_TRAP_ID,
        {
            "ACTION_TYPE_SET_USER_TRAP_ID",
            {
                BASE_ACL_ENTRY_ACTION_SET_USER_TRAP_ID_VALUE,
                NAS_ACL_DATA_U32,
                sizeof (uint32_t),
                NAS_ACL_ATTR_MODE_MANDATORY,
                {},
            },
            {},
            &nas_acl_action_t::get_u32_action_val,
            &nas_acl_action_t::set_u32_action_val,
        },
    },
};

const char* nas_acl_action_type_name (BASE_ACL_ACTION_TYPE_t type) noexcept
{
    auto it = _action_map.find (type);
    if (it == _action_map.end()) {
        return "Invalid Action Type";
    }
    return it->second.name.c_str();
}

bool nas_acl_action_is_type_valid (BASE_ACL_ACTION_TYPE_t a_type) noexcept
{
    if (_action_map.find (a_type) == _action_map.end()) {
        return false;
    }

    return true;
}

nas_acl_action_map_t& nas_acl_get_action_map () noexcept
{
    return (_action_map);
}

