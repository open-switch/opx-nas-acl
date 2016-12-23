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

"""
Simple Base ACL CPS config using the NAS ACL Python module - an ACL specific
wrapper over the generic CPS Python module.

ACL Entry 1 -
    Drop all packets received on specific port from specific range of Src MACs
ACL Entry 2 -
    Assign traffic-class to all packets that are destined to specific IP
    and contain a specific range of DSCP marking values.

Compare with the steps in nas_acl_generic_cps_example.py
"""

import nas_acl

#
# ACL Table to hold the ACL Entries.
#
tid = nas_acl.create_table(stage='INGRESS',
                           prio=99,
                           allow_filters=['DST_IP', 'SRC_MAC',
                                          'IN_PORT', 'DSCP'])

#
# ACL Entry to drop all packets received from MAC 50:10:6e:xx:xx:xx on port 23
#
# ACL counter to count number of dropped packets
counter_mac = nas_acl.create_counter(table_id=tid, types=['PACKET'])
# CPS Create the ACL entry
eid_mac = nas_acl.create_entry(table_id=tid,
                               prio=512,
                               filter_map={'SRC_MAC': {'addr':'50:10:6e:00:00:00',
                                                       'mask':'ff:ff:ff:00:00:00'},
                                           'IN_PORT': 23},
                               action_map={'PACKET_ACTION': 'DROP',
                                           'SET_COUNTER': counter_mac})
#
# ACL Entry to set traffic class for packets destined to IP 23.0.0.1
# with a DSCP range 8-15
#
# ACL counter to count number of dropped packets
counter_ip = nas_acl.create_counter(table_id=tid, types=['PACKET'])
# CPS Create the ACL entry
eid_ip = nas_acl.create_entry(table_id=tid,
                              prio=511,
                              filter_map={'DST_IP': '23.0.0.1',
                                          'DSCP': {'data':0x08, 'mask':0x38}},
                              action_map={'SET_TC': 4,
                                          'SET_COUNTER': counter_ip})

# Print both entries in ACL table
nas_acl.print_entry(tid)

raw_input("Press Enter to clean up the ACL entries and table ...")

# Print the ACL stats object
nas_acl.print_stats(tid, counter_ip)
nas_acl.print_stats(tid, counter_mac)

# Clean up
nas_acl.delete_entry(tid, eid_ip)
nas_acl.delete_entry(tid, eid_mac)
nas_acl.delete_counter(tid, counter_ip)
nas_acl.delete_counter(tid, counter_mac)
nas_acl.delete_table(tid)
print "Clean up Successful"
