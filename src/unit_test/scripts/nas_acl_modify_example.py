#!/usr/bin/python
# Copyright (c) 2018 Dell Inc.
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

"""
A more extensive example of the NAS ACL wrapper utility module to
show all possible CPS CRUD operations available with this module
"""

import nas_acl
import sys
import nas_acl_utils as a_utl

if len(sys.argv) <= 1:
    print "Usage ./nas_acl_example.py <table-priority> <entry-priority>"
    sys.exit(0)

# Create ACL Table with a list of allowed filters
tid = nas_acl.create_table(stage='INGRESS', prio=sys.argv[1],
                           allow_filters=[
                           'SRC_IP', 'SRC_MAC', 'DST_MAC', 'DST_IP', 'IP_TYPE',
                           'TCP_FLAGS', 'ECN', 'IPV6_FLOW_LABEL', 'IN_PORT'])

if len(sys.argv) < 3:
    sys.exit(0)

# Create ACL counter for this Table
counter_id = nas_acl.create_counter(table_id=tid)

# Create Mirroring sessions
mirr_id_1, mirr_opq_1 = a_utl.mirror_create(15)
mirr_id_2, mirr_opq_2 = a_utl.mirror_create(16)


#
# Example shows how various filters and actions can be specified for ACL entry create
#

filters = {
    'SRC_MAC': '01:80:c2:00:00:05',
    # Auto apply default mask
    'IPV6_FLOW_LABEL': '34456',

    'SRC_IP': {'addr': '23.0.0.1', 'mask': '255.0.0.255'},
    # Specify mask explicitly
    'TCP_FLAGS': {'data': '0x17', 'mask': '0x3f'},
    'ECN': {'data': '0x2', 'mask': '0x2'},

    'IP_TYPE': 'IP',
    # Filters where Mask is N/A
    'IN_PORT':
    a_utl.get_if_name(3),                     # Takes name or ifindex
}

actions = {
    'SET_SRC_MAC': '01:00:79:08:78:BC',
    'REDIRECT_PORT': a_utl.get_if_name(6),              # Takes name or ifindex
    'PACKET_ACTION': 'COPY_TO_CPU',
    'SET_COUNTER': counter_id,
    # Attach internal object to
                                                        # ACL action
    'MIRROR_INGRESS':
    {'index': mirr_id_1, 'data': mirr_opq_1}  # Attaching external obj
    # to ACL action
}

# Create an ACL entry with above filters and actions
eid = nas_acl.create_entry(
    table_id=tid,
    prio=sys.argv[2],
    filter_map=filters,
    action_map=actions)
nas_acl.print_entry(tid, eid)

try:
    # Add another filter to the ACL entry
    nas_acl.append_entry_filter(
        table_id=tid,
        entry_id=eid,
        filter_type='DST_IP',
        filter_val={
            'addr': '23.0.0.1',
            'mask': '255.0.0.255'})
    print "Added new DST IP filter"
    nas_acl.print_entry(tid, eid)

    # Or change value of existing filter
    nas_acl.mod_entry_filter(
        table_id=tid,
        entry_id=eid,
        filter_type='IPV6_FLOW_LABEL',
        filter_val=12345)
    print "Changed existing IPv6 Flow Label filter"
    nas_acl.print_entry(tid, eid)

    # Remove a filter from the ACL entry
    nas_acl.remove_entry_filter(
        table_id=tid,
        entry_id=eid,
        filter_type='SRC_IP')
    print "Removed SRC IP filter"
    nas_acl.print_entry(tid, eid)

    # Add another action to the ACL entry
    nas_acl.append_entry_action(
        table_id=tid,
        entry_id=eid,
        action_type='SET_TC',
        action_val=6)
    print "Added new SET TC action"
    nas_acl.print_entry(tid, eid)

    # Remove an action from the ACL entry
    nas_acl.remove_entry_action(
        table_id=tid,
        entry_id=eid,
        action_type='MIRROR_INGRESS')
    print "Removed Mirror Ingress action"
    nas_acl.print_entry(tid, eid)

    # Completely overwrite the filter list with another set of filters
    filters = {
        'DST_MAC': '00:70:a2:00:00:01',
        # Auto apply default mask
        'IP_TYPE': 'IP',
        # Filters where Mask is N/A
        'IN_PORT':
        a_utl.get_if_name(6),                     # Takes name or ifindex
    }
    print "Replaced filter list - new filters - Dst MAC, IP Type and In port"
    nas_acl.replace_entry_filter_list(
        table_id=tid,
        entry_id=eid,
        filter_map=filters)
    nas_acl.print_entry(tid, eid)

    # Completely overwrite the action list with another set of actions
    print "Replaced action list - new action - Mirror egress"
    actions = {
        'MIRROR_EGRESS':
        {'index': mirr_id_2, 'data': mirr_opq_2}  # Attaching external obj
        # to ACL
        # action
    }
    nas_acl.replace_entry_action_list(
        table_id=tid,
        entry_id=eid,
        action_map=actions)
    nas_acl.print_entry(tid, eid)

except RuntimeError as r:
    print r

# Clean up
nas_acl.delete_entry(tid, eid)
nas_acl.delete_counter(tid, counter_id)

a_utl.mirror_delete(mirr_id_1)
a_utl.mirror_delete(mirr_id_2)
nas_acl.delete_table(tid)
print "Clean up Successful"
