#!/usr/bin/python
# Copyright (c) 2015 Dell Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
#
# THIS CODE IS PROVIDED ON AN *AS IS* BASIS, WITHOUT WARRANTIES OR
# CONDITIONS OF ANY KIND, EITHER EXPRESS OR IMPLIED, INCLUDING WITHOUT
# LIMITATION ANY IMPLIED WARRANTIES OR CONDITIONS OF TITLE, FITNESS
# FOR A PARTICULAR PURPOSE, MERCHANTABLITY OR NON-INFRINGEMENT.
#
# See the Apache Version 2.0 License for specific language governing
# permissions and limitations under the License.

table_attr_map = {
    'switch-id': ('leaf', 'uint32_t'),
    'id': ('leaf', 'uint64_t'),
    'size': ('leaf', 'uint32_t'),
    'stage': ('leaf', 'enum', 'base-acl:stage:'),
    'priority': ('leaf', 'uint32_t'),
    'allowed-match-fields': ('leaflist', 'enum', 'base-acl:match-type:'),
    'npu-id-list': ('leaflist', 'uint32_t'),
}


def get_table_attr_map():
    return table_attr_map

filter_name2val_map = {
    'SRC_IP': 'SRC_IP_VALUE',
    'ETHER_TYPE': 'ETHER_TYPE_VALUE',
    'SRC_IPV6': 'SRC_IPV6_VALUE',
    'DST_IPV6': 'DST_IPV6_VALUE',
    'SRC_MAC': 'SRC_MAC_VALUE',
    'DST_MAC': 'DST_MAC_VALUE',
    'SRC_IP': 'SRC_IP_VALUE',
    'DST_IP': 'DST_IP_VALUE',
    'IN_PORTS': 'IN_PORTS_VALUE',
    'OUT_PORTS': 'OUT_PORTS_VALUE',
    'IN_PORT': 'IN_PORT_VALUE',
    'OUT_PORT': 'OUT_PORT_VALUE',
    'OUTER_VLAN_ID': 'OUTER_VLAN_ID_VALUE',
    'INNER_VLAN_ID': 'INNER_VLAN_ID_VALUE',
    'OUTER_VLAN_PRI': 'OUTER_VLAN_PRI_VALUE',
    'INNER_VLAN_PRI': 'INNER_VLAN_PRI_VALUE',
    'OUTER_VLAN_CFI': 'OUTER_VLAN_CFI_VALUE',
    'INNER_VLAN_CFI': 'INNER_VLAN_CFI_VALUE',
    'L4_SRC_PORT': 'L4_SRC_PORT_VALUE',
    'L4_DST_PORT': 'L4_DST_PORT_VALUE',
    'ETHER_TYPE': 'ETHER_TYPE_VALUE',
    'IP_PROTOCOL': 'IP_PROTOCOL_VALUE',
    'DSCP': 'DSCP_VALUE',
    'TTL': 'TTL_VALUE',
    'TOS': 'TOS_VALUE',
    'IP_FLAGS': 'IP_FLAGS_VALUE',
    'TCP_FLAGS': 'TCP_FLAGS_VALUE',
    'IP_TYPE': 'IP_TYPE_VALUE',
    'IP_FRAG': 'IP_FRAG_VALUE',
    'IPV6_FLOW_LABEL': 'IPV6_FLOW_LABEL_VALUE',
    'TC': 'TC_VALUE',
    'ECN': 'ECN_VALUE',
    'ICMP_TYPE': 'ICMP_TYPE_VALUE',
    'ICMP_CODE': 'ICMP_CODE_VALUE',
    'SRC_PORT': 'SRC_PORT_VALUE',
    'DST_PORT': 'DST_PORT_VALUE',
}

action_name2val_map = {
    'PACKET_ACTION': 'PACKET_ACTION_VALUE',
    'SET_SRC_MAC': 'NEW_SRC_MAC_VALUE',
    'REDIRECT_PORT': 'REDIRECT_PORT_VALUE',
    'REDIRECT_IP_NEXTHOP': 'IP_NEXTHOP_GROUP_VALUE',
    'MIRROR_INGRESS': 'MIRROR_INGRESS_VALUE',
    'MIRROR_EGRESS': 'MIRROR_EGRESS_VALUE',
    'SET_COUNTER': 'COUNTER_VALUE',
    'SET_POLICER': 'POLICER_VALUE',
    'SET_TC': 'NEW_TC_VALUE',
    'SET_INNER_VLAN_ID': 'NEW_INNER_VLAN_ID_VALUE',
    'SET_OUTER_VLAN_ID': 'NEW_OUTER_VLAN_ID_VALUE',
    'SET_INNER_VLAN_PRI': 'NEW_INNER_VLAN_PRI_VALUE',
    'SET_OUTER_VLAN_PRI': 'NEW_OUTER_VLAN_PRI_VALUE',
    'SET_SRC_MAC': 'NEW_SRC_MAC_VALUE',
    'SET_DST_MAC': 'NEW_DST_MAC_VALUE',
    'SET_SRC_IP': 'NEW_SRC_IP_VALUE',
    'SET_DST_IP': 'NEW_DST_IP_VALUE',
    'SET_SRC_IPV6': 'NEW_SRC_IPV6_VALUE',
    'SET_DST_IPV6': 'NEW_DST_IPV6_VALUE',
    'SET_DSCP': 'NEW_DSCP_VALUE',
    'SET_L4_SRC_PORT': 'NEW_L4_SRC_PORT_VALUE',
    'SET_L4_DST_PORT': 'NEW_L4_DST_PORT_VALUE',
    'SET_CPU_QUEUE': 'CPU_QUEUE_VALUE',
    'EGRESS_MASK': 'EGRESS_MASK_VALUE',
    'REDIRECT_PORT_LIST': 'REDIRECT_PORT_LIST_VALUE',
}

entry_attr_map = {
    'switch-id': ('leaf', 'uint32_t'),
    'table-id': ('leaf', 'uint64_t'),
    'id': ('leaf', 'uint64_t'),
    'priority': ('leaf', 'uint32_t'),
    'match': ('list',),
    'action': ('list',),
    'npu-id-list': ('leaflist', 'uint32_t'),
    'match/type': ('leaf', 'enum', 'base-acl:match-type:'),
    'action/type': ('leaf', 'enum', 'base-acl:action-type:'),

    'match/SRC_IPV6_VALUE':
    ('container', 'addr'),  # Type, default leaf attribute
    'match/SRC_IPV6_VALUE/addr': ('leaf', 'ipv6'),
    'match/SRC_IPV6_VALUE/mask': ('leaf', 'ipv6'),
    'match/DST_IPV6_VALUE': ('container', 'addr'),
    'match/DST_IPV6_VALUE/addr': ('leaf', 'ipv6'),
    'match/DST_IPV6_VALUE/mask': ('leaf', 'ipv6'),

    'match/SRC_IP_VALUE': ('container', 'addr'),
    'match/SRC_IP_VALUE/addr': ('leaf', 'ipv4'),
    'match/SRC_IP_VALUE/mask': ('leaf', 'ipv4'),
    'match/DST_IP_VALUE': ('container', 'addr'),
    'match/DST_IP_VALUE/addr': ('leaf', 'ipv4'),
    'match/DST_IP_VALUE/mask': ('leaf', 'ipv4'),

    'match/SRC_MAC_VALUE': ('container', 'addr'),
    'match/SRC_MAC_VALUE/addr': ('leaf', 'mac'),
    'match/SRC_MAC_VALUE/mask': ('leaf', 'mac'),
    'match/DST_MAC_VALUE': ('container', 'addr'),
    'match/DST_MAC_VALUE/addr': ('leaf', 'mac'),
    'match/DST_MAC_VALUE/mask': ('leaf', 'mac'),

    'match/IN_PORTS_VALUE': ('leaflist', 'intf'),
    'match/OUT_PORTS_VALUE': ('leaflist', 'intf'),

    'match/IN_PORT_VALUE': ('leaf', 'intf'),
    'match/OUT_PORT_VALUE': ('leaf', 'intf'),

    'match/OUTER_VLAN_ID_VALUE': ('container', 'data'),
    'match/OUTER_VLAN_ID_VALUE/data': ('leaf', 'uint16_t'),
    'match/OUTER_VLAN_ID_VALUE/mask': ('leaf', 'uint16_t'),

    'match/INNER_VLAN_ID_VALUE': ('container', 'data'),
    'match/INNER_VLAN_ID_VALUE/data': ('leaf', 'uint16_t'),
    'match/INNER_VLAN_ID_VALUE/mask': ('leaf', 'uint16_t'),

    'match/OUTER_VLAN_PRI_VALUE': ('container', 'data'),
    'match/OUTER_VLAN_PRI_VALUE/data': ('leaf', 'uint8_t'),
    'match/OUTER_VLAN_PRI_VALUE/mask': ('leaf', 'uint8_t'),

    'match/INNER_VLAN_PRI_VALUE': ('container', 'data'),
    'match/INNER_VLAN_PRI_VALUE/data': ('leaf', 'uint8_t'),
    'match/INNER_VLAN_PRI_VALUE/mask': ('leaf', 'uint8_t'),

    'match/OUTER_VLAN_CFI_VALUE': ('leaf', 'uint8_t'),
    'match/INNER_VLAN_CFI_VALUE': ('leaf', 'uint8_t'),

    'match/L4_SRC_PORT_VALUE': ('container', 'data'),
    'match/L4_SRC_PORT_VALUE/data': ('leaf', 'uint16_t'),
    'match/L4_SRC_PORT_VALUE/mask': ('leaf', 'uint16_t'),

    'match/L4_DST_PORT_VALUE': ('container', 'data'),
    'match/L4_DST_PORT_VALUE/data': ('leaf', 'uint16_t'),
    'match/L4_DST_PORT_VALUE/mask': ('leaf', 'uint16_t'),

    'match/ETHER_TYPE_VALUE': ('container', 'data'),
    'match/ETHER_TYPE_VALUE/data': ('leaf', 'uint16_t'),
    'match/ETHER_TYPE_VALUE/mask': ('leaf', 'uint16_t'),

    'match/IP_PROTOCOL_VALUE': ('container', 'data'),
    'match/IP_PROTOCOL_VALUE/data': ('leaf', 'uint8_t'),
    'match/IP_PROTOCOL_VALUE/mask': ('leaf', 'uint8_t'),

    'match/DSCP_VALUE': ('container', 'data'),
    'match/DSCP_VALUE/data': ('leaf', 'uint8_t'),
    'match/DSCP_VALUE/mask': ('leaf', 'uint8_t'),

    'match/TTL_VALUE': ('container', 'data'),
    'match/TTL_VALUE/data': ('leaf', 'uint8_t'),
    'match/TTL_VALUE/mask': ('leaf', 'uint8_t'),

    'match/TOS_VALUE': ('container', 'data'),
    'match/TOS_VALUE/data': ('leaf', 'uint8_t'),
    'match/TOS_VALUE/mask': ('leaf', 'uint8_t'),

    'match/IP_FLAGS_VALUE': ('container', 'data'),
    'match/IP_FLAGS_VALUE/data': ('leaf', 'uint8_t'),
    'match/IP_FLAGS_VALUE/mask': ('leaf', 'uint8_t'),

    'match/TCP_FLAGS_VALUE': ('container', 'data'),
    'match/TCP_FLAGS_VALUE/data': ('leaf', 'uint8_t'),
    'match/TCP_FLAGS_VALUE/mask': ('leaf', 'uint8_t'),

    'match/IP_TYPE_VALUE': ('leaf', 'enum', 'base-acl:match-ip-type:'),
    'match/IP_FRAG_VALUE': ('leaf', 'enum', 'base-acl:match-ip-frag:'),

    'match/IPV6_FLOW_LABEL_VALUE': ('container', 'data'),
    'match/IPV6_FLOW_LABEL_VALUE/data': ('leaf', 'uint32_t'),
    'match/IPV6_FLOW_LABEL_VALUE/mask': ('leaf', 'uint32_t'),

    'match/TC_VALUE': ('container', 'data'),
    'match/TC_VALUE/data': ('leaf', 'uint8_t'),
    'match/TC_VALUE/mask': ('leaf', 'uint8_t'),

    'match/ECN_VALUE': ('container', 'data'),
    'match/ECN_VALUE/data': ('leaf', 'uint8_t'),
    'match/ECN_VALUE/mask': ('leaf', 'uint8_t'),

    'match/ICMP_TYPE_VALUE': ('container', 'data'),
    'match/ICMP_TYPE_VALUE/data': ('leaf', 'uint8_t'),
    'match/ICMP_TYPE_VALUE/mask': ('leaf', 'uint8_t'),

    'match/ICMP_CODE_VALUE': ('container', 'data'),
    'match/ICMP_CODE_VALUE/data': ('leaf', 'uint8_t'),
    'match/ICMP_CODE_VALUE/mask': ('leaf', 'uint8_t'),

    'match/SRC_PORT_VALUE': ('leaf', 'intf'),
    'match/DST_PORT_VALUE': ('leaf', 'intf'),

    'action/PACKET_ACTION_VALUE':
    ('leaf', 'enum', 'base-acl:packet-action-type:'),
    'action/REDIRECT_PORT_VALUE': ('leaf', 'intf'),

    'action/IP_NEXTHOP_GROUP_VALUE': ('container',),
    'action/IP_NEXTHOP_GROUP_VALUE/id': ('leaf', 'uint64_t'),
    'action/IP_NEXTHOP_GROUP_VALUE/data': ('leaf', 'opaque'),

    'action/MIRROR_INGRESS_VALUE': ('list',),
    'action/MIRROR_INGRESS_VALUE/index': ('leaf', 'uint64_t'),
    'action/MIRROR_INGRESS_VALUE/data': ('leaf', 'opaque'),

    'action/MIRROR_EGRESS_VALUE': ('list',),
    'action/MIRROR_EGRESS_VALUE/index': ('leaf', 'uint64_t'),
    'action/MIRROR_EGRESS_VALUE/data': ('leaf', 'opaque'),

    'action/COUNTER_VALUE': ('leaf', 'uint64_t'),

    'action/POLICER_VALUE': ('container',),
    'action/POLICER_VALUE/index': ('leaf', 'uint64_t'),
    'action/POLICER_VALUE/data': ('leaf', 'opaque'),

    'action/NEW_TC_VALUE': ('leaf', 'uint8_t'),
    'action/NEW_INNER_VLAN_ID_VALUE': ('leaf', 'uint16_t'),
    'action/NEW_OUTER_VLAN_ID_VALUE': ('leaf', 'uint16_t'),
    'action/NEW_INNER_VLAN_PRI_VALUE': ('leaf', 'uint8_t'),
    'action/NEW_OUTER_VLAN_PRI_VALUE': ('leaf', 'uint8_t'),
    'action/NEW_SRC_MAC_VALUE': ('leaf', 'mac'),
    'action/NEW_DST_MAC_VALUE': ('leaf', 'mac'),
    'action/NEW_SRC_IP_VALUE': ('leaf', 'ipv4'),
    'action/NEW_DST_IP_VALUE': ('leaf', 'ipv4'),
    'action/NEW_SRC_IPV6_VALUE': ('leaf', 'ipv6'),
    'action/NEW_DST_IPV6_VALUE': ('leaf', 'ipv6'),
    'action/NEW_DSCP_VALUE': ('leaf', 'uint8_t'),
    'action/NEW_L4_SRC_PORT_VALUE': ('leaf', 'uint16_t'),
    'action/NEW_L4_DST_PORT_VALUE': ('leaf', 'uint16_t'),

    'action/CPU_QUEUE_VALUE': ('container',),
    'action/CPU_QUEUE_VALUE/index': ('leaf', 'uint64_t'),
    'action/CPU_QUEUE_VALUE/data': ('leaf', 'opaque'),
}


def get_entry_attr_map():
    return entry_attr_map


def get_filter_name2val_map():
    return filter_name2val_map


def get_action_name2val_map():
    return action_name2val_map


enum_map = {
    'base-acl:stage:INGRESS': 1,
    'base-acl:stage:EGRESS': 2,

    'base-acl:counter-type:PACKET': 1,
    'base-acl:counter-type:BYTE': 2,

    'base-acl:action-type:REDIRECT_PORT': 1,
    'base-acl:action-type:REDIRECT_IP_NEXTHOP': 2,
    'base-acl:action-type:PACKET_ACTION': 3,
    'base-acl:action-type:FLOOD': 4,
    'base-acl:action-type:MIRROR_INGRESS': 5,
    'base-acl:action-type:MIRROR_EGRESS': 6,
    'base-acl:action-type:SET_COUNTER': 7,
    'base-acl:action-type:SET_POLICER': 8,
    'base-acl:action-type:DECREMENT_TTL': 9,
    'base-acl:action-type:SET_TC': 10,
    'base-acl:action-type:SET_INNER_VLAN_ID': 11,
    'base-acl:action-type:SET_INNER_VLAN_PRI': 12,
    'base-acl:action-type:SET_OUTER_VLAN_ID': 13,
    'base-acl:action-type:SET_OUTER_VLAN_PRI': 14,
    'base-acl:action-type:SET_SRC_MAC': 15,
    'base-acl:action-type:SET_DST_MAC': 16,
    'base-acl:action-type:SET_SRC_IP': 17,
    'base-acl:action-type:SET_DST_IP': 18,
    'base-acl:action-type:SET_SRC_IPV6': 19,
    'base-acl:action-type:SET_DST_IPV6': 20,
    'base-acl:action-type:SET_DSCP': 21,
    'base-acl:action-type:SET_L4_SRC_PORT': 22,
    'base-acl:action-type:SET_L4_DST_PORT': 23,
    'base-acl:action-type:SET_CPU_QUEUE': 24,
    'base-acl:action-type:EGRESS_MASK': 25,
    'base-acl:action-type:REDIRECT_PORT_LIST': 26,

    'base-acl:match-type:SRC_IPV6': 1,
    'base-acl:match-type:DST_IPV6': 2,
    'base-acl:match-type:SRC_MAC': 3,
    'base-acl:match-type:DST_MAC': 4,
    'base-acl:match-type:SRC_IP': 5,
    'base-acl:match-type:DST_IP': 6,
    'base-acl:match-type:IN_PORTS': 7,
    'base-acl:match-type:OUT_PORTS': 8,
    'base-acl:match-type:IN_PORT': 9,
    'base-acl:match-type:OUT_PORT': 10,
    'base-acl:match-type:OUTER_VLAN_ID': 11,
    'base-acl:match-type:OUTER_VLAN_PRI': 12,
    'base-acl:match-type:OUTER_VLAN_CFI': 13,
    'base-acl:match-type:INNER_VLAN_ID': 14,
    'base-acl:match-type:INNER_VLAN_PRI': 15,
    'base-acl:match-type:INNER_VLAN_CFI': 16,
    'base-acl:match-type:L4_SRC_PORT': 17,
    'base-acl:match-type:L4_DST_PORT': 18,
    'base-acl:match-type:ETHER_TYPE': 19,
    'base-acl:match-type:IP_PROTOCOL': 20,
    'base-acl:match-type:DSCP': 21,
    'base-acl:match-type:TTL': 22,
    'base-acl:match-type:TOS': 23,
    'base-acl:match-type:IP_FLAGS': 24,
    'base-acl:match-type:TCP_FLAGS': 25,
    'base-acl:match-type:IP_TYPE': 26,
    'base-acl:match-type:IP_FRAG': 27,
    'base-acl:match-type:IPV6_FLOW_LABEL': 28,
    'base-acl:match-type:TC': 29,
    'base-acl:match-type:ECN': 30,
    'base-acl:match-type:ICMP_TYPE': 31,
    'base-acl:match-type:ICMP_CODE': 32,
    'base-acl:match-type:SRC_PORT': 33,
    'base-acl:match-type:DST_PORT': 34,
    'base-acl:match-type:NEIGHBOR_DST_HIT': 35,
    'base-acl:match-type:ROUTE_DST_HIT': 36,

    'base-acl:packet-action-type:DROP': 1,
    'base-acl:packet-action-type:FORWARD': 2,
    'base-acl:packet-action-type:COPY_TO_CPU': 3,
    'base-acl:packet-action-type:COPY_TO_CPU_CANCEL': 4,
    'base-acl:packet-action-type:TRAP_TO_CPU': 5,
    'base-acl:packet-action-type:COPY_TO_CPU_AND_FORWARD': 6,
    'base-acl:packet-action-type:COPY_TO_CPU_CANCEL_AND_DROP': 7,
    'base-acl:packet-action-type:COPY_TO_CPU_CANCEL_AND_FORWARD': 8,

    'base-acl:match-ip-type:ANY': 1,
    'base-acl:match-ip-type:IP': 2,
    'base-acl:match-ip-type:NON_IP': 3,
    'base-acl:match-ip-type:IPV4ANY': 4,
    'base-acl:match-ip-type:NON_IPv4': 5,
    'base-acl:match-ip-type:IPV6ANY': 6,
    'base-acl:match-ip-type:NON_IPV6': 7,
    'base-acl:match-ip-type:ARP': 8,
    'base-acl:match-ip-type:ARP_REQUEST': 9,
    'base-acl:match-ip-type:ARP_REPLY': 10,

    'base-acl:match-ip-frag:ANY': 1,
    'base-acl:match-ip-frag:NON_FRAG': 2,
    'base-acl:match-ip-frag:NON_FRAG_OR_HEAD': 3,
    'base-acl:match-ip-frag:HEAD': 4,
    'base-acl:match-ip-frag:NON_HEAD': 5,
}


def get_enums():
    return enum_map
