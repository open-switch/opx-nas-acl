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



