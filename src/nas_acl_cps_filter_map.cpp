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
 * \file   nas_acl_cps_filter_map.cpp
 * \brief  This file contains ACL Entry Filter Map table initiazation
 * \date   05-2015
 * \author Mukesh MV & Ravikumar Sivasankar
 */
#include "nas_acl_cps.h"
#include "nas_vlan_consts.h"
#include "nas_qos_consts.h"
#include "nas_acl_common.h"
#include "nas_acl_udf.h"

static const nas_acl_filter_map_t _filter_map =
{
    {BASE_ACL_MATCH_TYPE_SRC_IPV6,
        {
            "MATCH_TYPE_SRC_IPV6",
            {
                BASE_ACL_ENTRY_MATCH_SRC_IPV6_VALUE,
                NAS_ACL_DATA_EMBEDDED,
                {},
            },
            {
                {
                    BASE_ACL_ENTRY_MATCH_SRC_IPV6_VALUE_ADDR,
                    NAS_ACL_DATA_BIN,
                    sizeof (dn_ipv6_addr_t),
                    NAS_ACL_ATTR_MODE_MANDATORY,
                    {},
                },
                {
                    BASE_ACL_ENTRY_MATCH_SRC_IPV6_VALUE_MASK,
                    NAS_ACL_DATA_BIN,
                    sizeof (dn_ipv6_addr_t),
                    NAS_ACL_ATTR_MODE_OPTIONAL,
                    {},
                },
            },
            &nas_acl_filter_t::get_ipv6_filter_val,
            &nas_acl_filter_t::set_ipv6_filter_val,
        },
    },

    {BASE_ACL_MATCH_TYPE_DST_IPV6,
        {
            "MATCH_TYPE_DST_IPV6",
            {
                BASE_ACL_ENTRY_MATCH_DST_IPV6_VALUE,
                NAS_ACL_DATA_EMBEDDED,
                {},
            },
            {
                {
                    BASE_ACL_ENTRY_MATCH_DST_IPV6_VALUE_ADDR,
                    NAS_ACL_DATA_BIN,
                    sizeof (dn_ipv6_addr_t),
                    NAS_ACL_ATTR_MODE_MANDATORY,
                    {},
                },
                {
                    BASE_ACL_ENTRY_MATCH_DST_IPV6_VALUE_MASK,
                    NAS_ACL_DATA_BIN,
                    sizeof (dn_ipv6_addr_t),
                    NAS_ACL_ATTR_MODE_OPTIONAL,
                    {},
                },
            },
            &nas_acl_filter_t::get_ipv6_filter_val,
            &nas_acl_filter_t::set_ipv6_filter_val,
        },
    },

    {BASE_ACL_MATCH_TYPE_SRC_MAC,
        {
            "MATCH_TYPE_SRC_MAC",
            {
                BASE_ACL_ENTRY_MATCH_SRC_MAC_VALUE,
                NAS_ACL_DATA_EMBEDDED,
                {},
            },
            {
                {
                    BASE_ACL_ENTRY_MATCH_SRC_MAC_VALUE_ADDR,
                    NAS_ACL_DATA_BIN,
                    HAL_MAC_ADDR_LEN,
                    NAS_ACL_ATTR_MODE_MANDATORY,
                    {},
                },
                {
                    BASE_ACL_ENTRY_MATCH_SRC_MAC_VALUE_MASK,
                    NAS_ACL_DATA_BIN,
                    HAL_MAC_ADDR_LEN,
                    NAS_ACL_ATTR_MODE_OPTIONAL,
                    {},
                },
            },
            &nas_acl_filter_t::get_mac_filter_val,
            &nas_acl_filter_t::set_mac_filter_val,
        },
    },

    {BASE_ACL_MATCH_TYPE_DST_MAC,
        {
            "MATCH_TYPE_DST_MAC",
            {
                BASE_ACL_ENTRY_MATCH_DST_MAC_VALUE,
                NAS_ACL_DATA_EMBEDDED,
                {},
            },
            {
                {
                    BASE_ACL_ENTRY_MATCH_DST_MAC_VALUE_ADDR,
                    NAS_ACL_DATA_BIN,
                    HAL_MAC_ADDR_LEN,
                    NAS_ACL_ATTR_MODE_MANDATORY,
                    {},
                },
                {
                    BASE_ACL_ENTRY_MATCH_DST_MAC_VALUE_MASK,
                    NAS_ACL_DATA_BIN,
                    HAL_MAC_ADDR_LEN,
                    NAS_ACL_ATTR_MODE_OPTIONAL,
                    {},
                },
            },
            &nas_acl_filter_t::get_mac_filter_val,
            &nas_acl_filter_t::set_mac_filter_val,
        },
    },

    {BASE_ACL_MATCH_TYPE_SRC_IP,
        {
            "MATCH_TYPE_SRC_IP",
            {
                BASE_ACL_ENTRY_MATCH_SRC_IP_VALUE,
                NAS_ACL_DATA_EMBEDDED,
                {},
            },
            {
                {
                    BASE_ACL_ENTRY_MATCH_SRC_IP_VALUE_ADDR,
                    NAS_ACL_DATA_BIN,
                    sizeof (dn_ipv4_addr_t),
                    NAS_ACL_ATTR_MODE_MANDATORY,
                    {},
                },
                {
                    BASE_ACL_ENTRY_MATCH_SRC_IP_VALUE_MASK,
                    NAS_ACL_DATA_BIN,
                    sizeof (dn_ipv4_addr_t),
                    NAS_ACL_ATTR_MODE_OPTIONAL,
                    {},
                },
            },
            &nas_acl_filter_t::get_ipv4_filter_val,
            &nas_acl_filter_t::set_ipv4_filter_val,
        },
    },

    {BASE_ACL_MATCH_TYPE_DST_IP,
        {
            "MATCH_TYPE_DST_IP",
            {
                BASE_ACL_ENTRY_MATCH_DST_IP_VALUE,
                NAS_ACL_DATA_EMBEDDED,
                {},
            },
            {
                {
                    BASE_ACL_ENTRY_MATCH_DST_IP_VALUE_ADDR,
                    NAS_ACL_DATA_BIN,
                    sizeof (dn_ipv4_addr_t),
                    NAS_ACL_ATTR_MODE_MANDATORY,
                    {},
                },
                {
                    BASE_ACL_ENTRY_MATCH_DST_IP_VALUE_MASK,
                    NAS_ACL_DATA_BIN,
                    sizeof (dn_ipv4_addr_t),
                    NAS_ACL_ATTR_MODE_OPTIONAL,
                    {},
                },
            },
            &nas_acl_filter_t::get_ipv4_filter_val,
            &nas_acl_filter_t::set_ipv4_filter_val,
        },
    },

    {BASE_ACL_MATCH_TYPE_IN_PORTS,
        {
            "MATCH_TYPE_IN_PORTS",
            {
                BASE_ACL_ENTRY_MATCH_IN_PORTS_VALUE,
                NAS_ACL_DATA_IFINDEX_LIST,
                {},
            },
            {},
            &nas_acl_filter_t::get_filter_ifindex_list,
            &nas_acl_filter_t::set_filter_ifindex_list,
        },
    },

    {BASE_ACL_MATCH_TYPE_OUT_PORTS,
        {
            "MATCH_TYPE_OUT_PORTS",
            {
                BASE_ACL_ENTRY_MATCH_OUT_PORTS_VALUE,
                NAS_ACL_DATA_IFINDEX_LIST,
                {},
            },
            {},
            &nas_acl_filter_t::get_filter_ifindex_list,
            &nas_acl_filter_t::set_filter_ifindex_list,
        },
    },

    {BASE_ACL_MATCH_TYPE_IN_PORT,
        {
            "MATCH_TYPE_IN_PORT",
            {
                BASE_ACL_ENTRY_MATCH_IN_PORT_VALUE,
                NAS_ACL_DATA_IFINDEX,
                sizeof (uint32_t),
                NAS_ACL_ATTR_MODE_MANDATORY,
                {},
            },
            {},
            &nas_acl_filter_t::get_filter_ifindex,
            &nas_acl_filter_t::set_filter_ifindex,
        },
    },

    {BASE_ACL_MATCH_TYPE_OUT_PORT,
        {
            "MATCH_TYPE_OUT_PORT",
            {
                BASE_ACL_ENTRY_MATCH_OUT_PORT_VALUE,
                NAS_ACL_DATA_IFINDEX,
                sizeof (uint32_t),
                NAS_ACL_ATTR_MODE_MANDATORY,
                {},
            },
            {},
            &nas_acl_filter_t::get_filter_ifindex,
            &nas_acl_filter_t::set_filter_ifindex,
        },
    },

    {BASE_ACL_MATCH_TYPE_OUTER_VLAN_ID,
        {
            "MATCH_TYPE_OUTER_VLAN_ID",
            {
                BASE_ACL_ENTRY_MATCH_OUTER_VLAN_ID_VALUE,
                NAS_ACL_DATA_EMBEDDED,
                {},
            },
            {
                {
                    BASE_ACL_ENTRY_MATCH_OUTER_VLAN_ID_VALUE_DATA,
                    NAS_ACL_DATA_U16,
                    sizeof (uint16_t),
                    NAS_ACL_ATTR_MODE_MANDATORY,
                    {1, NAS_MAX_VLAN_ID},
                },
                {
                    BASE_ACL_ENTRY_MATCH_OUTER_VLAN_ID_VALUE_MASK,
                    NAS_ACL_DATA_U16,
                    sizeof (uint16_t),
                    NAS_ACL_ATTR_MODE_OPTIONAL,
                    {0, NAS_MAX_VLAN_ID},
                },
            },
            &nas_acl_filter_t::get_u16_filter_val,
            &nas_acl_filter_t::set_u16_filter_val,
        },
    },

    {BASE_ACL_MATCH_TYPE_OUTER_VLAN_PRI,
        {
            "MATCH_TYPE_OUTER_VLAN_PRI",
            {
                BASE_ACL_ENTRY_MATCH_OUTER_VLAN_PRI_VALUE,
                NAS_ACL_DATA_EMBEDDED,
                {},
            },
            {
                {
                    BASE_ACL_ENTRY_MATCH_OUTER_VLAN_PRI_VALUE_DATA,
                    NAS_ACL_DATA_U8,
                    sizeof (uint8_t),
                    NAS_ACL_ATTR_MODE_MANDATORY,
                    {0, NAS_MAX_DOT1P}
                },
                {
                    BASE_ACL_ENTRY_MATCH_OUTER_VLAN_PRI_VALUE_MASK,
                    NAS_ACL_DATA_U8,
                    sizeof (uint8_t),
                    NAS_ACL_ATTR_MODE_OPTIONAL,
                    {0, NAS_MAX_DOT1P}
                },
            },
            &nas_acl_filter_t::get_u8_filter_val,
            &nas_acl_filter_t::set_u8_filter_val,
        },
    },

    {BASE_ACL_MATCH_TYPE_OUTER_VLAN_CFI,
        {
            "MATCH_TYPE_OUTER_VLAN_CFI",
            {
                BASE_ACL_ENTRY_MATCH_OUTER_VLAN_CFI_VALUE,
                NAS_ACL_DATA_U8,
                sizeof (uint8_t),
                NAS_ACL_ATTR_MODE_MANDATORY,
                {0, NAS_ACL_MAX_CFI}
            },
            {},
            &nas_acl_filter_t::get_u8_filter_val,
            &nas_acl_filter_t::set_u8_filter_val,
        },
    },

    {BASE_ACL_MATCH_TYPE_INNER_VLAN_ID,
        {
            "MATCH_TYPE_INNER_VLAN_ID",
            {
                BASE_ACL_ENTRY_MATCH_INNER_VLAN_ID_VALUE,
                NAS_ACL_DATA_EMBEDDED,
                {},
            },
            {
                {
                    BASE_ACL_ENTRY_MATCH_INNER_VLAN_ID_VALUE_DATA,
                    NAS_ACL_DATA_U16,
                    sizeof (uint16_t),
                    NAS_ACL_ATTR_MODE_MANDATORY,
                    {1, NAS_MAX_VLAN_ID},
                },
                {
                    BASE_ACL_ENTRY_MATCH_INNER_VLAN_ID_VALUE_MASK,
                    NAS_ACL_DATA_U16,
                    sizeof (uint16_t),
                    NAS_ACL_ATTR_MODE_OPTIONAL,
                    {0, NAS_MAX_VLAN_ID},
                },
            },
            &nas_acl_filter_t::get_u16_filter_val,
            &nas_acl_filter_t::set_u16_filter_val,
        },
    },

    {BASE_ACL_MATCH_TYPE_INNER_VLAN_PRI,
        {
            "MATCH_TYPE_INNER_VLAN_PRI",
            {
                BASE_ACL_ENTRY_MATCH_INNER_VLAN_PRI_VALUE,
                NAS_ACL_DATA_EMBEDDED,
                {},
            },
            {
                {
                    BASE_ACL_ENTRY_MATCH_INNER_VLAN_PRI_VALUE_DATA,
                    NAS_ACL_DATA_U8,
                    sizeof (uint8_t),
                    NAS_ACL_ATTR_MODE_MANDATORY,
                    {0, NAS_MAX_DOT1P},
                },
                {
                    BASE_ACL_ENTRY_MATCH_INNER_VLAN_PRI_VALUE_MASK,
                    NAS_ACL_DATA_U8,
                    sizeof (uint8_t),
                    NAS_ACL_ATTR_MODE_OPTIONAL,
                    {0, NAS_MAX_DOT1P},
                },
            },
            &nas_acl_filter_t::get_u8_filter_val,
            &nas_acl_filter_t::set_u8_filter_val,
        },
    },

    {BASE_ACL_MATCH_TYPE_INNER_VLAN_CFI,
        {
            "MATCH_TYPE_INNER_VLAN_CFI",
            {
                BASE_ACL_ENTRY_MATCH_INNER_VLAN_CFI_VALUE,
                NAS_ACL_DATA_U8,
                sizeof (uint8_t),
                NAS_ACL_ATTR_MODE_MANDATORY,
                {0, NAS_ACL_MAX_CFI},
            },
            {},
            &nas_acl_filter_t::get_u8_filter_val,
            &nas_acl_filter_t::set_u8_filter_val,
        },
    },

    {BASE_ACL_MATCH_TYPE_L4_SRC_PORT,
        {
            "MATCH_TYPE_L4_SRC_PORT",
            {
                BASE_ACL_ENTRY_MATCH_L4_SRC_PORT_VALUE,
                NAS_ACL_DATA_EMBEDDED,
                {},
            },
            {
                {
                    BASE_ACL_ENTRY_MATCH_L4_SRC_PORT_VALUE_DATA,
                    NAS_ACL_DATA_U16,
                    sizeof (uint16_t),
                    NAS_ACL_ATTR_MODE_MANDATORY,
                    {},
                },
                {
                    BASE_ACL_ENTRY_MATCH_L4_SRC_PORT_VALUE_MASK,
                    NAS_ACL_DATA_U16,
                    sizeof (uint16_t),
                    NAS_ACL_ATTR_MODE_OPTIONAL,
                    {},
                },
            },
            &nas_acl_filter_t::get_u16_filter_val,
            &nas_acl_filter_t::set_u16_filter_val,
        },
    },

    {BASE_ACL_MATCH_TYPE_L4_DST_PORT,
        {
            "MATCH_TYPE_L4_DST_PORT",
            {
                BASE_ACL_ENTRY_MATCH_L4_DST_PORT_VALUE,
                NAS_ACL_DATA_EMBEDDED,
                {},
            },
            {
                {
                    BASE_ACL_ENTRY_MATCH_L4_DST_PORT_VALUE_DATA,
                    NAS_ACL_DATA_U16,
                    sizeof (uint16_t),
                    NAS_ACL_ATTR_MODE_MANDATORY,
                    {},
                },
                {
                    BASE_ACL_ENTRY_MATCH_L4_DST_PORT_VALUE_MASK,
                    NAS_ACL_DATA_U16,
                    sizeof (uint16_t),
                    NAS_ACL_ATTR_MODE_OPTIONAL,
                    {},
                },
            },
            &nas_acl_filter_t::get_u16_filter_val,
            &nas_acl_filter_t::set_u16_filter_val,
        },
    },

    {BASE_ACL_MATCH_TYPE_ETHER_TYPE,
        {
            "MATCH_TYPE_ETHER_TYPE",
            {
                BASE_ACL_ENTRY_MATCH_ETHER_TYPE_VALUE,
                NAS_ACL_DATA_EMBEDDED,
                {},
            },
            {
                {
                    BASE_ACL_ENTRY_MATCH_ETHER_TYPE_VALUE_DATA,
                    NAS_ACL_DATA_U16,
                    sizeof (uint16_t),
                    NAS_ACL_ATTR_MODE_MANDATORY,
                    {},
                },
                {
                    BASE_ACL_ENTRY_MATCH_ETHER_TYPE_VALUE_MASK,
                    NAS_ACL_DATA_U16,
                    sizeof (uint16_t),
                    NAS_ACL_ATTR_MODE_OPTIONAL,
                    {},
                },
            },
            &nas_acl_filter_t::get_u16_filter_val,
            &nas_acl_filter_t::set_u16_filter_val,
        },
    },

    {BASE_ACL_MATCH_TYPE_IP_PROTOCOL,
        {
            "MATCH_TYPE_IP_PROTOCOL",
            {
                BASE_ACL_ENTRY_MATCH_IP_PROTOCOL_VALUE,
                NAS_ACL_DATA_EMBEDDED,
                {},
            },
            {
                {
                    BASE_ACL_ENTRY_MATCH_IP_PROTOCOL_VALUE_DATA,
                    NAS_ACL_DATA_U8,
                    sizeof (uint8_t),
                    NAS_ACL_ATTR_MODE_MANDATORY,
                    {},
                },
                {
                    BASE_ACL_ENTRY_MATCH_IP_PROTOCOL_VALUE_MASK,
                    NAS_ACL_DATA_U8,
                    sizeof (uint8_t),
                    NAS_ACL_ATTR_MODE_OPTIONAL,
                    {},
                },
            },
            &nas_acl_filter_t::get_u8_filter_val,
            &nas_acl_filter_t::set_u8_filter_val,
        },
    },

    {BASE_ACL_MATCH_TYPE_DSCP,
        {
            "MATCH_TYPE_DSCP",
            {
                BASE_ACL_ENTRY_MATCH_DSCP_VALUE,
                NAS_ACL_DATA_EMBEDDED,
                {},
            },
            {
                {
                    BASE_ACL_ENTRY_MATCH_DSCP_VALUE_DATA,
                    NAS_ACL_DATA_U8,
                    sizeof (uint8_t),
                    NAS_ACL_ATTR_MODE_MANDATORY,
                    {0, NAS_MAX_DSCP},
                },
                {
                    BASE_ACL_ENTRY_MATCH_DSCP_VALUE_MASK,
                    NAS_ACL_DATA_U8,
                    sizeof (uint8_t),
                    NAS_ACL_ATTR_MODE_OPTIONAL,
                    {0, NAS_MAX_DSCP},
                },
            },
            &nas_acl_filter_t::get_u8_filter_val,
            &nas_acl_filter_t::set_u8_filter_val,
        },
    },

    {BASE_ACL_MATCH_TYPE_TTL,
        {
            "MATCH_TYPE_TTL",
            {
                BASE_ACL_ENTRY_MATCH_TTL_VALUE,
                NAS_ACL_DATA_EMBEDDED,
                {},
            },
            {
                {
                    BASE_ACL_ENTRY_MATCH_TTL_VALUE_DATA,
                    NAS_ACL_DATA_U8,
                    sizeof (uint8_t),
                    NAS_ACL_ATTR_MODE_MANDATORY,
                    {},
                },
                {
                    BASE_ACL_ENTRY_MATCH_TTL_VALUE_MASK,
                    NAS_ACL_DATA_U8,
                    sizeof (uint8_t),
                    NAS_ACL_ATTR_MODE_OPTIONAL,
                    {},
                },
            },
            &nas_acl_filter_t::get_u8_filter_val,
            &nas_acl_filter_t::set_u8_filter_val,
        },
    },

    {BASE_ACL_MATCH_TYPE_TOS,
        {
            "MATCH_TYPE_TOS",
            {
                BASE_ACL_ENTRY_MATCH_TOS_VALUE,
                NAS_ACL_DATA_EMBEDDED,
                {},
            },
            {
                {
                    BASE_ACL_ENTRY_MATCH_TOS_VALUE_DATA,
                    NAS_ACL_DATA_U8,
                    sizeof (uint8_t),
                    NAS_ACL_ATTR_MODE_MANDATORY,
                    {},
                },
                {
                    BASE_ACL_ENTRY_MATCH_TOS_VALUE_MASK,
                    NAS_ACL_DATA_U8,
                    sizeof (uint8_t),
                    NAS_ACL_ATTR_MODE_OPTIONAL,
                    {},
                },
            },
            &nas_acl_filter_t::get_u8_filter_val,
            &nas_acl_filter_t::set_u8_filter_val,
        },
    },

    {BASE_ACL_MATCH_TYPE_IP_FLAGS,
        {
            "MATCH_TYPE_IP_FLAGS",
            {
                BASE_ACL_ENTRY_MATCH_IP_FLAGS_VALUE,
                NAS_ACL_DATA_EMBEDDED,
                {},
            },
            {
                {
                    BASE_ACL_ENTRY_MATCH_IP_FLAGS_VALUE_DATA,
                    NAS_ACL_DATA_U8,
                    sizeof (uint8_t),
                    NAS_ACL_ATTR_MODE_MANDATORY,
                    {0, NAS_ACL_MAX_IP_FLAGS},
                },
                {
                    BASE_ACL_ENTRY_MATCH_IP_FLAGS_VALUE_MASK,
                    NAS_ACL_DATA_U8,
                    sizeof (uint8_t),
                    NAS_ACL_ATTR_MODE_OPTIONAL,
                    {0, NAS_ACL_MAX_IP_FLAGS},
                },
            },
            &nas_acl_filter_t::get_u8_filter_val,
            &nas_acl_filter_t::set_u8_filter_val,
        },
    },

    {BASE_ACL_MATCH_TYPE_TCP_FLAGS,
        {
            "MATCH_TYPE_TCP_FLAGS",
            {
                BASE_ACL_ENTRY_MATCH_TCP_FLAGS_VALUE,
                NAS_ACL_DATA_EMBEDDED,
                {},
            },
            {
                {
                    BASE_ACL_ENTRY_MATCH_TCP_FLAGS_VALUE_DATA,
                    NAS_ACL_DATA_U8,
                    sizeof (uint8_t),
                    NAS_ACL_ATTR_MODE_MANDATORY,
                    {},
                },
                {
                    BASE_ACL_ENTRY_MATCH_TCP_FLAGS_VALUE_MASK,
                    NAS_ACL_DATA_U8,
                    sizeof (uint8_t),
                    NAS_ACL_ATTR_MODE_OPTIONAL,
                    {},
                },
            },
            &nas_acl_filter_t::get_u8_filter_val,
            &nas_acl_filter_t::set_u8_filter_val,
        },
    },

    {BASE_ACL_MATCH_TYPE_IP_TYPE,
        {
            "MATCH_TYPE_IP_TYPE",
            {
                BASE_ACL_ENTRY_MATCH_IP_TYPE_VALUE,
                NAS_ACL_DATA_U32,
                sizeof (uint32_t),
                NAS_ACL_ATTR_MODE_MANDATORY,
                {},
            },
            {},
            &nas_acl_filter_t::get_ip_type_filter_val,
            &nas_acl_filter_t::set_ip_type_filter_val,
        },
    },

    {BASE_ACL_MATCH_TYPE_IP_FRAG,
        {
            "MATCH_TYPE_IP_FRAG",
            {
                BASE_ACL_ENTRY_MATCH_IP_FRAG_VALUE,
                NAS_ACL_DATA_U32,
                sizeof (uint32_t),
                NAS_ACL_ATTR_MODE_MANDATORY,
                {},
            },
            {},
            &nas_acl_filter_t::get_ip_frag_filter_val,
            &nas_acl_filter_t::set_ip_frag_filter_val,
        },
    },

    {BASE_ACL_MATCH_TYPE_IPV6_FLOW_LABEL,
        {
            "MATCH_TYPE_IPV6_FLOW_LABEL",
            {
                BASE_ACL_ENTRY_MATCH_IPV6_FLOW_LABEL_VALUE,
                NAS_ACL_DATA_EMBEDDED,
                {},
            },
            {
                {
                    BASE_ACL_ENTRY_MATCH_IPV6_FLOW_LABEL_VALUE_DATA,
                    NAS_ACL_DATA_U32,
                    sizeof (uint32_t),
                    NAS_ACL_ATTR_MODE_MANDATORY,
                    {0, NAS_ACL_MAX_IPV6_FLOW_LABEL},
                },
                {
                    BASE_ACL_ENTRY_MATCH_IPV6_FLOW_LABEL_VALUE_MASK,
                    NAS_ACL_DATA_U32,
                    sizeof (uint32_t),
                    NAS_ACL_ATTR_MODE_OPTIONAL,
                    {0, NAS_ACL_MAX_IPV6_FLOW_LABEL},
                },
            },
            &nas_acl_filter_t::get_u32_filter_val,
            &nas_acl_filter_t::set_u32_filter_val,
        },
    },

    {BASE_ACL_MATCH_TYPE_TC,
        {
            "MATCH_TYPE_TC",
            {
                BASE_ACL_ENTRY_MATCH_TC_VALUE,
                NAS_ACL_DATA_EMBEDDED,
                {},
            },
            {
                {
                    BASE_ACL_ENTRY_MATCH_TC_VALUE_DATA,
                    NAS_ACL_DATA_U8,
                    sizeof (uint8_t),
                    NAS_ACL_ATTR_MODE_MANDATORY,
                    {},
                },
                {
                    BASE_ACL_ENTRY_MATCH_TC_VALUE_MASK,
                    NAS_ACL_DATA_U8,
                    sizeof (uint8_t),
                    NAS_ACL_ATTR_MODE_OPTIONAL,
                    {},
                },
            },
            &nas_acl_filter_t::get_u8_filter_val,
            &nas_acl_filter_t::set_u8_filter_val,
        },
    },

    {BASE_ACL_MATCH_TYPE_ECN,
        {
            "MATCH_TYPE_ECN",
            {
                BASE_ACL_ENTRY_MATCH_ECN_VALUE,
                NAS_ACL_DATA_EMBEDDED,
                {},
            },
            {
                {
                    BASE_ACL_ENTRY_MATCH_ECN_VALUE_DATA,
                    NAS_ACL_DATA_U8,
                    sizeof (uint8_t),
                    NAS_ACL_ATTR_MODE_MANDATORY,
                    {0, NAS_ACL_MAX_ECN},
                },
                {
                    BASE_ACL_ENTRY_MATCH_ECN_VALUE_MASK,
                    NAS_ACL_DATA_U8,
                    sizeof (uint8_t),
                    NAS_ACL_ATTR_MODE_OPTIONAL,
                    {0, NAS_ACL_MAX_ECN},
                },
            },
            &nas_acl_filter_t::get_u8_filter_val,
            &nas_acl_filter_t::set_u8_filter_val,
        },
    },

    {BASE_ACL_MATCH_TYPE_ICMP_TYPE,
        {
            "MATCH_TYPE_ICMP_TYPE",
            {
                BASE_ACL_ENTRY_MATCH_ICMP_TYPE_VALUE,
                NAS_ACL_DATA_EMBEDDED,
                {},
            },
            {
                {
                    BASE_ACL_ENTRY_MATCH_ICMP_TYPE_VALUE_DATA,
                    NAS_ACL_DATA_U8,
                    sizeof (uint8_t),
                    NAS_ACL_ATTR_MODE_MANDATORY,
                    {},
                },
                {
                    BASE_ACL_ENTRY_MATCH_ICMP_TYPE_VALUE_MASK,
                    NAS_ACL_DATA_U8,
                    sizeof (uint8_t),
                    NAS_ACL_ATTR_MODE_OPTIONAL,
                    {},
                },
            },
            &nas_acl_filter_t::get_u8_filter_val,
            &nas_acl_filter_t::set_u8_filter_val,
        },
    },

    {BASE_ACL_MATCH_TYPE_ICMP_CODE,
        {
            "MATCH_TYPE_ICMP_CODE",
            {
                BASE_ACL_ENTRY_MATCH_ICMP_CODE_VALUE,
                NAS_ACL_DATA_EMBEDDED,
                {},
            },
            {
                {
                    BASE_ACL_ENTRY_MATCH_ICMP_CODE_VALUE_DATA,
                    NAS_ACL_DATA_U8,
                    sizeof (uint8_t),
                    NAS_ACL_ATTR_MODE_MANDATORY,
                    {},
                },
                {
                    BASE_ACL_ENTRY_MATCH_ICMP_CODE_VALUE_MASK,
                    NAS_ACL_DATA_U8,
                    sizeof (uint8_t),
                    NAS_ACL_ATTR_MODE_OPTIONAL,
                    {},
                },
            },
            &nas_acl_filter_t::get_u8_filter_val,
            &nas_acl_filter_t::set_u8_filter_val,
        },
    },

    {BASE_ACL_MATCH_TYPE_SRC_PORT,
        {
            "MATCH_TYPE_SRC_PORT",
            {
                BASE_ACL_ENTRY_MATCH_SRC_PORT_VALUE,
                NAS_ACL_DATA_IFINDEX,
                sizeof (uint32_t),
                NAS_ACL_ATTR_MODE_MANDATORY,
                {},
            },
            {},
            &nas_acl_filter_t::get_filter_ifindex,
            &nas_acl_filter_t::set_filter_ifindex,
        },
    },

    {BASE_ACL_MATCH_TYPE_NEIGHBOR_DST_HIT,
        {
            "MATCH_TYPE_NEIGHBOR_DST_HIT",
            {
                0,
                NAS_ACL_DATA_NONE,
                0,
                NAS_ACL_ATTR_MODE_MANDATORY,
                {},
            },
            {},
            NULL,
            NULL,
        },
    },

    {BASE_ACL_MATCH_TYPE_ROUTE_DST_HIT,
        {
            "MATCH_TYPE_ROUTE_DST_HIT",
            {
                0,
                NAS_ACL_DATA_NONE,
                0,
                NAS_ACL_ATTR_MODE_MANDATORY,
                {},
            },
            {},
            NULL,
            NULL,
        },
    },

    {BASE_ACL_MATCH_TYPE_IN_INTFS,
        {
            "MATCH_TYPE_IN_INTFS",
            {
                BASE_ACL_ENTRY_MATCH_IN_INTFS_VALUE,
                NAS_ACL_DATA_IFNAME_LIST,
                {},
            },
            {},
            &nas_acl_filter_t::get_filter_ifindex_list,
            &nas_acl_filter_t::set_filter_ifindex_list,
        },
    },

    {BASE_ACL_MATCH_TYPE_OUT_INTFS,
        {
            "MATCH_TYPE_OUT_INTFS",
            {
                BASE_ACL_ENTRY_MATCH_OUT_INTFS_VALUE,
                NAS_ACL_DATA_IFNAME_LIST,
                {},
            },
            {},
            &nas_acl_filter_t::get_filter_ifindex_list,
            &nas_acl_filter_t::set_filter_ifindex_list,
        },
    },

    {BASE_ACL_MATCH_TYPE_IN_INTF,
        {
            "MATCH_TYPE_IN_INTF",
            {
                BASE_ACL_ENTRY_MATCH_IN_INTF_VALUE,
                NAS_ACL_DATA_IFNAME,
                HAL_IF_NAME_SZ,
                NAS_ACL_ATTR_MODE_MANDATORY,
                {},
            },
            {},
            &nas_acl_filter_t::get_filter_ifindex,
            &nas_acl_filter_t::set_filter_ifindex,
        },
    },

    {BASE_ACL_MATCH_TYPE_OUT_INTF,
        {
            "MATCH_TYPE_OUT_INTF",
            {
                BASE_ACL_ENTRY_MATCH_OUT_INTF_VALUE,
                NAS_ACL_DATA_IFNAME,
                HAL_IF_NAME_SZ,
                NAS_ACL_ATTR_MODE_MANDATORY,
                {},
            },
            {},
            &nas_acl_filter_t::get_filter_ifindex,
            &nas_acl_filter_t::set_filter_ifindex,
        },
    },

    {BASE_ACL_MATCH_TYPE_SRC_INTF,
        {
            "MATCH_TYPE_SRC_INTF",
            {
                BASE_ACL_ENTRY_MATCH_SRC_INTF_VALUE,
                NAS_ACL_DATA_IFNAME,
                HAL_IF_NAME_SZ,
                NAS_ACL_ATTR_MODE_MANDATORY,
                {},
            },
            {},
            &nas_acl_filter_t::get_filter_ifindex,
            &nas_acl_filter_t::set_filter_ifindex,
        },
    },

    {BASE_ACL_MATCH_TYPE_UDF,
        {
            "MATCH_TYPE_UDF",
            {
                BASE_ACL_ENTRY_MATCH_UDF_VALUE,
                NAS_ACL_DATA_EMBEDDED,
                {},
            },
            {
                {
                    BASE_ACL_ENTRY_MATCH_UDF_VALUE_UDF_GROUP_ID,
                    NAS_ACL_DATA_OBJ_ID,
                    sizeof(nas_obj_id_t),
                    NAS_ACL_ATTR_MODE_MANDATORY,
                    {},
                },
                {
                    BASE_ACL_ENTRY_MATCH_UDF_VALUE_MATCH_DATA,
                    NAS_ACL_DATA_BIN,
                    MAX_UDF_BYTE_ARRAY_LENGTH,
                    NAS_ACL_ATTR_MODE_MANDATORY,
                    {},
                },
                {
                    BASE_ACL_ENTRY_MATCH_UDF_VALUE_MATCH_MASK,
                    NAS_ACL_DATA_BIN,
                    MAX_UDF_BYTE_ARRAY_LENGTH,
                    NAS_ACL_ATTR_MODE_OPTIONAL,
                    {},
                },
            },
            &nas_acl_filter_t::get_udf_filter_val,
            &nas_acl_filter_t::set_udf_filter_val,
        },
    },
};

const char* nas_acl_filter_type_name (BASE_ACL_MATCH_TYPE_t type) noexcept
{
    auto it = _filter_map.find (type);
    if (it == _filter_map.end()) {
        return "Invalid Filter Type";
    }
    return it->second.name.c_str();
}

bool nas_acl_filter_is_type_valid (BASE_ACL_MATCH_TYPE_t f_type) noexcept
{
    if (_filter_map.find (f_type) == _filter_map.end()) {
        return false;
    }
    return true;
}

nas_acl_filter_map_t& nas_acl_get_filter_map () noexcept
{
    return (_filter_map);
}

