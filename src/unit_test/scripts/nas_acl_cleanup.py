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
import sys
import nas_acl
import cps
import cps_utils


def cps_delete(cps_obj):
    cps_upd = ('delete', cps_obj.data())
    if not cps_utils.CPSTransaction([cps_upd]).commit():
        print "Deletion failed"
        return False
    return True


tid = None
eid = None
out_entry = []
out_table = []
out_counter = []

if len(sys.argv) > 1:
    tid = sys.argv[1]
if len(sys.argv) > 2:
    eid = sys.argv[2]

if eid is None:
    filt = nas_acl.EntryCPSObj(table_id=tid)
    if cps.get([filt.data()], out_entry):
        for e_cps in out_entry:
            e = nas_acl.EntryCPSObj(cps_data=e_cps)
            eid = e.extract_id()
            print "Deleting entry ", eid, "in table ", e.extract('table-id')
            e1 = nas_acl.EntryCPSObj(e.extract('table-id'), eid)
            cps_delete(e1)
    else:
        print "No entries in table"

    filt = nas_acl.CounterCPSObj(table_id=tid)
    if cps.get([filt.data()], out_counter):
        for e_cps in out_counter:
            e = nas_acl.CounterCPSObj(cps_data=e_cps)
            eid = e.extract_id()
            print "Deleting counter ", eid, "in table ", e.extract('table-id')
            e1 = nas_acl.CounterCPSObj(e.extract('table-id'), eid)
            cps_delete(e1)
    else:
        print "No counters in table"

    if tid is None:
        filt = nas_acl.TableCPSObj()
        if not cps.get([filt.data()], out_table):
            print "Table Get failed"
            exit()
        for t_cps in out_table:
            t = nas_acl.TableCPSObj(cps_data=t_cps)
            tid = t.extract_id()
            print "Deleting table ", tid
            t1 = nas_acl.TableCPSObj(tid)
            cps_delete(t1)
    else:
        t = nas_acl.TableCPSObj(table_id=tid)
        print "Deleting table ", tid
        cps_delete(t)


else:
    e = nas_acl.EntryCPSObj(table_id=tid, entry_id=eid)
    print "Deleting entry ", eid, "in table ", tid
    cps_delete(e)
