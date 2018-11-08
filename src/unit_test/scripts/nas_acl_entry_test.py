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

import sys
import nas_acl
import cps
import pytest

def test_check_entry():
    ret_tlist = []
    tid=1
    eid="ospfv3-all-dr"
    filt = nas_acl.TableCPSObj(table_id=tid)
    if not cps.get([filt.data()], ret_tlist):
        print "Error in Table Get"
        exit()

    print ""
    print "Finding Entry in Table "
    filt = nas_acl.EntryCPSObj(table_id=tid, entry_id=eid)
    ret_elist = []
    if not cps.get([filt.data()], ret_elist):
        print "Error in Entry Get"
    for entry in ret_elist:
        e = nas_acl.EntryCPSObj(cps_data=entry)
        cps_data=e.data()
        print "The Entry ID is:"+ str(e.extract_attr(cps_data,'id'))
        assert e.extract_attr(cps_data,'match/IP_PROTOCOL_VALUE/data') == 89

def test_update_entry_action():
    print 'Creating ACL table'
    table_id = nas_acl.create_table('INGRESS', 100, ['IN_INTF'])
    print 'Table ID: %d' % table_id
    print 'Creating ACL entry'
    entry_id = nas_acl.create_entry(table_id, 1, {'IN_INTF': 'e101-001-0'},
                                    {'PACKET_ACTION': 'DROP'})
    print 'Entry ID: %d' % entry_id
    print 'Trying to set user trap ID with drop action (expected fail)'
    with pytest.raises(RuntimeError):
        nas_acl.replace_entry_action_list(table_id, entry_id,
                                          {'PACKET_ACTION': 'DROP', 'SET_USER_TRAP_ID': 2})
    nas_acl.print_entry(table_id, entry_id)
    print 'Trying to set user trap ID with trap to CPU action'
    try:
        nas_acl.replace_entry_action_list(table_id, entry_id,
                                          {'PACKET_ACTION': 'TRAP_TO_CPU', 'SET_USER_TRAP_ID': 2})
    except RuntimeError:
        assert False
    nas_acl.print_entry(table_id, entry_id)
    print 'Restoring ACL entry actions'
    try:
        nas_acl.replace_entry_action_list(table_id, entry_id,
                                          {'PACKET_ACTION': 'DROP'})
    except RuntimeError:
        assert False
    nas_acl.print_entry(table_id, entry_id)
    print 'Deleting ACL entry'
    nas_acl.delete_entry(table_id, entry_id)
    print 'Deleting ACL table'
    nas_acl.delete_table(table_id)

def test_vlan_id_filter():
    print 'Creating ACL table'
    table_id = nas_acl.create_table('INGRESS', 100, ['OUTER_VLAN_ID', 'INNER_VLAN_ID'])
    print 'Table ID: %d' % table_id
    print 'Creating ACL entry'
    entry_id_1 = nas_acl.create_entry(table_id, 1,
                                {'OUTER_VLAN_ID': {'data': 0}, 'INNER_VLAN_ID': {'data': 0}},
                                {'PACKET_ACTION': 'DROP'})
    print 'Entry ID: %d' % entry_id_1
    entry_id_2 = nas_acl.create_entry(table_id, 2,
                                {'OUTER_VLAN_ID': {'data': 100}, 'INNER_VLAN_ID': {'data': 200}},
                                {'PACKET_ACTION': 'DROP'})
    print 'Entry ID: %d' % entry_id_2

    nas_acl.print_entry(table_id)

    print 'Deleting ACL entry'
    nas_acl.delete_entry(table_id, entry_id_1)
    nas_acl.delete_entry(table_id, entry_id_2)
    print 'Deleting ACL table'
    nas_acl.delete_table(table_id)

def test_bridge_type_filter():
    print 'Createing Ingress ACL table'
    ing_table_id = nas_acl.create_table('INGRESS', 101, ['BRIDGE_TYPE'])
    print 'Table ID: %d' % ing_table_id
    print 'Creating Ingress ACL entry'
    entry_id_1 = nas_acl.create_entry(ing_table_id, 1,
                                {'BRIDGE_TYPE': 'BRIDGE_1Q'}, {'PACKET_ACTION': 'DROP'})
    print 'Entry ID: %d' % entry_id_1
    entry_id_2 = nas_acl.create_entry(ing_table_id, 2,
                                {'BRIDGE_TYPE': 'BRIDGE_1D'}, {'PACKET_ACTION': 'DROP'})
    print 'Entry ID: %d' % entry_id_2

    nas_acl.print_entry(ing_table_id)

    print 'Createing Egress ACL table'
    eg_table_id = nas_acl.create_table('EGRESS', 101, ['BRIDGE_TYPE'])
    print 'Table ID: %d' % eg_table_id
    print 'Creating Egress ACL entry'
    entry_id_3 = nas_acl.create_entry(eg_table_id, 1,
                                {'BRIDGE_TYPE': 'BRIDGE_1Q'}, {'PACKET_ACTION': 'DROP'})
    print 'Entry ID: %d' % entry_id_3
    entry_id_4 = nas_acl.create_entry(eg_table_id, 2,
                                {'BRIDGE_TYPE': 'BRIDGE_1D'}, {'PACKET_ACTION': 'DROP'})
    print 'Entry ID: %d' % entry_id_4

    nas_acl.print_entry(eg_table_id)

    print 'Deleting ACL entry'
    nas_acl.delete_entry(ing_table_id, entry_id_1)
    nas_acl.delete_entry(ing_table_id, entry_id_2)
    nas_acl.delete_entry(eg_table_id, entry_id_3)
    nas_acl.delete_entry(eg_table_id, entry_id_4)
    print 'Deleting ACL table'
    nas_acl.delete_table(ing_table_id)
    nas_acl.delete_table(eg_table_id)
