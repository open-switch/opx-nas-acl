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
Simple Base ACL CPS config using the generic CPS Python module and utilities.

ACL Entry 1 -
    Drop all packets received on specific port from specific range of Src MACs
ACL Entry 2 -
    Assign traffic-class to all packets that are destined to specific IP
    and contain a specific range of DSCP marking values.
"""

import cps_utils

# Yang Enum name to number map
e_stg = {'INGRESS': 1, 'EGRESS': 2}
e_ftype = {'SRC_MAC': 3, 'DST_MAC': 4, 'SRC_IP': 5, 'DST_IP': 6,
           'IN_PORT': 9, 'DSCP': 21}
e_atype = {'PACKET_ACTION': 3, 'SET_TC': 10}
e_ptype = {'DROP': 1}

# Teach Attr Types
type_map = {
    'base-acl/entry/DST_IP_VALUE/addr': 'ipv4',
    'base-acl/entry/SRC_MAC_VALUE/addr': 'mac',
    'base-acl/entry/SRC_MAC_VALUE/mask': 'mac',
    'base-acl/entry/DSCP_VALUE/data': 'uint8_t',
    'base-acl/entry/DSCP_VALUE/mask': 'uint8_t',
    'base-acl/entry/NEW_TC_VALUE': 'uint8_t'
}
for key,val in type_map.items():
    cps_utils.cps_attr_types_map.add_type(key, val)


# ACL Table
# Container to hold ACL entries
obj = cps_utils.CPSObject(module='base-acl/table',
                          data={'stage': e_stg['INGRESS'],
                                'priority': 99})
obj.add_list ('allowed-match-fields', [e_ftype['SRC_MAC'],
                                       e_ftype['DST_IP'],
                                       e_ftype['DSCP'],
                                       e_ftype['IN_PORT']])
# CPS Transaction
upd = ('create', obj.get())
r = cps_utils.CPSTransaction([upd]).commit()
if not r:
    raise RuntimeError ("Error creating ACL Table")
ret = cps_utils.CPSObject (module='base-acl/table', obj=r[0]['change'])
tbl_id = ret.get_attr_data ('id')
print "Successfully created ACL Table " + str(tbl_id)


# ACL entry 1
# Drop all packets received on specific port from specific range of MACs
obj = cps_utils.CPSObject(module='base-acl/entry',
                          data={'table-id': tbl_id,
                                'priority': 512})
# Match Filter 0 - Src MAC Range
obj.add_embed_attr (['match','0','type'], e_ftype['SRC_MAC'])
# Last 2 attrs (SRC_MAC_VALUE,addr) used to identify attr type
obj.add_embed_attr (['match','0','SRC_MAC_VALUE','addr'],
                    '50:10:6e:00:00:00', 2)
obj.add_embed_attr (['match','0','SRC_MAC_VALUE','mask'],
                          'ff:ff:ff:00:00:00', 2)
# Match Filter 1 - Rx Port
obj.add_embed_attr (['match','1','type'], e_ftype['IN_PORT'])
obj.add_embed_attr (['match','1','IN_PORT_VALUE'], 23)
# Action 0 - Drop
obj.add_embed_attr (['action','0','type'], e_atype['PACKET_ACTION'])
obj.add_embed_attr (['action','0','PACKET_ACTION_VALUE'], e_ptype['DROP'])
# CPS Transaction
upd = ('create', obj.get())
r = cps_utils.CPSTransaction([upd]).commit()
if not r:
    raise RuntimeError ("Error creating MAC ACL Entry")
ret = cps_utils.CPSObject (module='base-acl/entry', obj=r[0]['change'])
mac_eid = ret.get_attr_data ('id')
print "Successfully created MAC ACL Entry " + str(mac_eid)


# ACL entry 2
# Assign traffic class to all packets with DSCP range 8-15
# and destined to specific IP
obj = cps_utils.CPSObject(module='base-acl/entry',
                          data={'table-id': tbl_id,
                                'priority': 511})
# Match Filter 0 - IP
obj.add_embed_attr (['match','0','type'], e_ftype['DST_IP'])
obj.add_embed_attr (['match','0','DST_IP_VALUE','addr'], '23.0.0.1', 2)
# Match Filter 1 - DSCP Range
obj.add_embed_attr (['match','1','type'], e_ftype['DSCP'])
obj.add_embed_attr (['match','1','DSCP_VALUE','data'], 0x08, 2)
obj.add_embed_attr (['match','1','DSCP_VALUE','mask'], 0x38, 2)
# Action 0 - Traffic Class
obj.add_embed_attr (['action','0','type'], e_atype['SET_TC'])
obj.add_embed_attr (['action','0','NEW_TC_VALUE'], 4)
# CPS Transaction
upd = ('create', obj.get())
r = cps_utils.CPSTransaction([upd]).commit()
if not r:
    raise RuntimeError ("Error creating IP ACL Entry")
ret = cps_utils.CPSObject (module='base-acl/entry', obj=r[0]['change'])
ip_eid = ret.get_attr_data ('id')
print "Successfully created IP ACL Entry " + str(ip_eid)
