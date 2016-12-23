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

tid = None
eid = None
ret_tlist = []

if len(sys.argv) > 1:
    tid = sys.argv[1]
if len(sys.argv) > 2:
    eid = sys.argv[2]

filt = nas_acl.TableCPSObj(table_id=tid)
if not cps.get([filt.data()], ret_tlist):
    print "Error in Table Get"
    exit()

for table in ret_tlist:
    t = nas_acl.TableCPSObj(cps_data=table)
    print ""
    print "TABLE "
    t.print_obj()

    print ""
    print "Entries in Table "
    filt = nas_acl.EntryCPSObj(table_id=t.extract_id(), entry_id=eid)
    ret_elist = []
    if not cps.get([filt.data()], ret_elist):
        print "Error in Entry Get"
        continue

    for entry in ret_elist:
        e = nas_acl.EntryCPSObj(cps_data=entry)
        e.print_obj()
