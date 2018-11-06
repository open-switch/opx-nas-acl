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
import cps
import nas_acl
import cps_utils
import nas_acl_utils as a_utl

meter_id = 0
mirror_id_1 = 0
mir_opq_1 = 0
mirror_id_2 = 0
mir_opq_2 = 0
passed = []
total = []
ifs = []


def acl_ut_table_create(prio=None):
    global total, passed
    total.append(sys._getframe().f_code.co_name)
    try:
        tid = nas_acl.create_table(stage='INGRESS', prio=prio,
                                   allow_filters=[
                                   'SRC_IP', 'SRC_MAC', 'DST_IP', 'IP_TYPE',
                                   'TCP_FLAGS', 'DSCP', 'ECN', 'IPV6_FLOW_LABEL',
                                   'IN_PORTS', 'IN_PORT'], allow_actions=['PACKET_ACTION','SET_CPU_QUEUE'])
    except RuntimeError as r:
        print (sys._getframe().f_code.co_name + ": Error creating Table")
        return None

    print (sys._getframe().f_code.co_name + " - Created Table " + str(tid))
    passed.append(sys._getframe().f_code.co_name)
    return tid


def acl_ut_table_get(table_id=None):
    global total, passed
    total.append(sys._getframe().f_code.co_name)
    try:
        print '#### Table Show ####'
        nas_acl.print_table(table_id)
        passed.append(sys._getframe().f_code.co_name)
    except RuntimeError:
        print (sys._getframe().f_code.co_name + ": Error in Get")


def acl_ut_counter_create(table_id, types=[]):
    global total, passed
    total.append(sys._getframe().f_code.co_name)
    try:
        cid = nas_acl.create_counter(table_id=table_id, types=types)
    except RuntimeError:
        print (sys._getframe().f_code.co_name + " - Error creating Counter")
        return None

    print (sys._getframe().f_code.co_name + " - Created Counter " + str(cid))
    passed.append(sys._getframe().f_code.co_name)
    return cid


def acl_ut_counter_get(table_id=None, counter_id=None):
    global total, passed
    total.append(sys._getframe().f_code.co_name)
    try:
        print '#### Counter Show ####'
        nas_acl.print_counter(table_id, counter_id)
        passed.append(sys._getframe().f_code.co_name)
    except RuntimeError:
        print (sys._getframe().f_code.co_name + " - Error in Get")


def acl_ut_entry_create(table_id, prio=None, counter_id=None):
    global total, passed
    total.append(sys._getframe().f_code.co_name)
    filters = {
        'SRC_IP': {'addr': '23.0.0.1', 'mask': '255.0.0.255'},
        'SRC_MAC': '01:80:c2:00:00:05',
        'IPV6_FLOW_LABEL': 34456,
        'TCP_FLAGS': {'data': '0x17', 'mask': '0x3f'},
        'ECN': {'data': '0x2', 'mask': '0x2'},
        'IP_TYPE': 'IP',
        'IN_PORTS': [a_utl.get_if_name(2), a_utl.get_if_name(3)],
    }

    actions = {
        'SET_SRC_MAC': '01:00:79:08:78:BC',
        'PACKET_ACTION': 'COPY_TO_CPU',
        'REDIRECT_PORT': a_utl.get_if_name(4),
    }
    if (counter_id):
        actions['SET_COUNTER'] = counter_id

    global meter_id
    try:
        meter_id, meter_opaque = a_utl.qos_meter_create(
            m_type='BYTE', cir=300000,
            cbs=800000, pbs=900000)
    except:
        print "Meter install Failed"
        return

    actions['SET_POLICER'] = {'index': meter_id, 'data': meter_opaque}

    global mirror_id_1, mir_opq_1
    global mirror_id_2, mir_opq_2
    try:
        mirror_id_1, mir_opq_1 = a_utl.mirror_create(13)
        mirror_id_2, mir_opq_2 = a_utl.mirror_create(16)
    except:
        print "Mirror Create Failed"
        return

    actions['MIRROR_INGRESS'] = [{'index': mirror_id_1, 'data': mir_opq_1},
                                 {'index': mirror_id_2, 'data': mir_opq_2}]

    try:
        entry_id = nas_acl.create_entry(table_id=table_id, prio=prio,
                                        filter_map=filters, action_map=actions)
    except RuntimeError:
        print (sys._getframe().f_code.co_name + " - Error creating Entry")
        return None

    print (sys._getframe().f_code.co_name +
           " - Created Entry " + str(entry_id))
    raw_input("Check entry is created and Press Enter to continue...")
    passed.append(sys._getframe().f_code.co_name)
    return entry_id


def acl_ut_entry_modify1(table_id, entry_id):
    global total, passed
    total.append(sys._getframe().f_code.co_name)
    e = nas_acl.EntryCPSObj(table_id=table_id, entry_id=entry_id)
    filters = {
        'DST_IP': '56.0.0.1',
        'IPV6_FLOW_LABEL': {'data': '34456', 'mask': '0xff'},
        'TCP_FLAGS': {'data': '0x17', 'mask': '0x3f'},
        'ECN': {'data': '0x2', 'mask': '0x2'},
        'IP_TYPE': 'IP',
        'IN_PORTS': [a_utl.get_if_name(3)],
    }
    actions = {
        'SET_DST_MAC': '01:00:79:08:78:BC',
        'MIRROR_INGRESS': {'index': mirror_id_1, 'data': mir_opq_1},
    }

    try:
        nas_acl.replace_entry_filter_list(
            table_id=table_id, entry_id=entry_id,
            filter_map=filters)
        nas_acl.replace_entry_action_list(
            table_id=table_id, entry_id=entry_id,
            action_map=actions)
    except RuntimeError:
        print (sys._getframe().f_code.co_name + " - Error Modifying Entry")
        return None

    print (sys._getframe().f_code.co_name +
           " - Modified Entry " + str(entry_id))
    raw_input(
        "Check entry is modified (Del SRCIP,SRCMAC,Redirect port. Changed IPv6Flowlabel mask,IN PORTS,Packet Action. Add DSTIP, DST-MAC action. Press Enter to continue...")
    passed.append(sys._getframe().f_code.co_name)
    return entry_id


def acl_ut_entry_modify2(table_id, entry_id, counter_id):
    global total, passed
    total.append(sys._getframe().f_code.co_name)

    # Using the internal CPS Obj instead of the convenience wrapper

    e = nas_acl.EntryCPSObj(table_id=table_id, entry_id=entry_id)
    e.add_match_filter(
        filter_type='SRC_IP',
        filter_val={
            'addr': '23.0.0.1',
            'mask': '255.0.0.255'})
    e.add_match_filter(
        filter_type='SRC_MAC',
        filter_val={'addr': '01:80:c2:00:00:05'})
    e.add_match_filter(
        filter_type='IPV6_FLOW_LABEL',
        filter_val={'data': '34456'})
    e.add_match_filter(
        filter_type='TCP_FLAGS',
        filter_val={
            'data': '0x17',
            'mask': '0x3f'})
    e.add_match_filter(
        filter_type='ECN',
        filter_val={
            'data': '0x2',
            'mask': '0x2'})
    e.add_match_filter(filter_type='IP_TYPE', filter_val='IP')
    e.add_match_filter(
        filter_type='IN_PORTS',
        filter_val=a_utl.get_if_name(2))
    e.add_action(action_type='SET_SRC_MAC', action_val='01:00:79:08:78:BC')
    e.add_action(action_type='PACKET_ACTION', action_val='COPY_TO_CPU')
    e.add_action(
        action_type='REDIRECT_PORT',
        action_val=a_utl.get_if_name(4))
    if (counter_id):
        e.add_action(action_type='SET_COUNTER', action_val=counter_id)

    global meter_id
    meter_opaque = a_utl.qos_meter_get_opaque_data(meter_id)
    if meter_opaque is None:
        return

    e.add_action(action_type='SET_POLICER',
                 action_val={'index': meter_id, 'data': meter_opaque})

    print e.data()
    upd = ('set', e.data())
    r = cps_utils.CPSTransaction([upd]).commit()

    if r == False:
        print (sys._getframe().f_code.co_name + " - Error modifying Entry")
        return None

    e = nas_acl.EntryCPSObj(cps_data=r[0])
    entry_id = e.extract_id()
    print (sys._getframe().f_code.co_name +
           " - Modified Entry " + str(entry_id))
    raw_input(
        "Check entry is modified (Add SRCIP,SRCMAC,Redirect port. Changed IPv6Flowlabel mask,IN PORTS,Packet Action. Del DSTIP, DST-MAC action. Press Enter to continue...")
    passed.append(sys._getframe().f_code.co_name)
    return entry_id


def acl_ut_entry_modify_rollback(table_id, entry_id):
    global total, passed
    total.append(sys._getframe().f_code.co_name)

    e = nas_acl.EntryCPSObj(table_id=table_id, entry_id=entry_id)
    e.add_match_filter(
        filter_type='ECN',
        filter_val={
            'data': '0x3',
            'mask': '0x3'})
    e.add_match_filter(filter_type='IP_TYPE', filter_val='IPV6ANY')
    e.add_match_filter(
        filter_type='IN_PORTS',
        filter_val=[a_utl.get_if_name(1),
                    a_utl.get_if_name(5)])
    e.add_action(action_type='SET_DST_MAC', action_val='01:00:79:08:78:BC')
    e.add_action(
        action_type='REDIRECT_PORT',
        action_val=a_utl.get_if_name(6))

    upd = []
    upd.append(('set', e.data()))

    e = nas_acl.EntryCPSObj(table_id=table_id, entry_id=entry_id)
    e.add_match_filter(
        filter_type='IN_PORTS',
        filter_val=[a_utl.get_if_name(1),
                    a_utl.get_if_name(5)])
    e.add_match_filter(
        filter_type='IN_PORT',
        filter_val=a_utl.get_if_name(1))
    upd.append(('set', e.data()))

    r = cps_utils.CPSTransaction(upd).commit()

    if r:
        print (sys._getframe().f_code.co_name + " - NO Error Modifying Entry")
        return None

    print (sys._getframe().f_code.co_name +
           " - Rolled back Entry " + str(entry_id))
    raw_input("Check entry is reverted back. Press Enter to continue...")
    passed.append(sys._getframe().f_code.co_name)
    return entry_id


def acl_ut_entry_incr_modify(table_id, entry_id):
    global total, passed
    total.append(sys._getframe().f_code.co_name)

    # Transaction with multiple updates
    upd = []
    # First add DSCP filter
    e = nas_acl.EntryCPSObj(
        table_id=table_id,
        entry_id=entry_id,
        filter_type='DSCP')
    e.set_filter_val({'data': '0x37'})
    upd.append(('create', e.data()))

    # Modify counter - use another counter object
    new_counter_id = acl_ut_counter_create(table_id, ['BYTE'])
    e = nas_acl.EntryCPSObj(
        table_id=table_id,
        entry_id=entry_id,
        action_type='SET_COUNTER')
    e.set_action_val(new_counter_id)
    upd.append(('set', e.data()))

    # Delete IP Type filter
    e = nas_acl.EntryCPSObj(
        table_id=table_id,
        entry_id=entry_id,
        filter_type='IP_TYPE')
    upd.append(('delete', e.data()))

    # Add mirror action
    e = nas_acl.EntryCPSObj(
        table_id=table_id,
        entry_id=entry_id,
        action_type='MIRROR_INGRESS')
    e.set_action_val(
        [{'index': mirror_id_1,
          'data': mir_opq_1},
         {'index': mirror_id_2,
          'data': mir_opq_2}])
    upd.append(('create', e.data()))

    # Change meter
    try:
        new_meter_id, meter_opaque = a_utl.qos_meter_create(
            m_type='BYTE', pir=40000,
            cir=35000, cbs=85000, pbs=95000)
    except:
        print "Meter install Failed"
        return

    e = nas_acl.EntryCPSObj(
        table_id=table_id,
        entry_id=entry_id,
        action_type='SET_POLICER')
    e.set_action_val({'index': new_meter_id, 'data': meter_opaque})
    upd.append(('set', e.data()))

    print upd
    r = cps_utils.CPSTransaction(upd).commit()
    if r == False:
        print sys._getframe().f_code.co_name + " - Error modifying Entry"
        return None

    global meter_id
    a_utl.qos_meter_delete(meter_id)
    meter_id = new_meter_id

    raw_input(
        "Check entry is modified (New DSCP, Changed Policer,Counter and Removed IPType - Press Enter to continue...")
    passed.append(sys._getframe().f_code.co_name)
    return new_counter_id


def acl_ut_entry_incr_rollback(table_id, entry_id):
    global total, passed
    total.append(sys._getframe().f_code.co_name)

    # Transaction with multiple updates
    upd = []
    # Modify inports
    e = nas_acl.EntryCPSObj(
        table_id=table_id,
        entry_id=entry_id,
        filter_type='IN_PORTS')
    e.set_filter_val([a_utl.get_if_name(4), a_utl.get_if_name(8)])
    upd.append(('set', e.data()))

    # Delete Counter action
    e = nas_acl.EntryCPSObj(
        table_id=table_id,
        entry_id=entry_id,
        action_type='SET_COUNTER')
    upd.append(('delete', e.data()))

    # Modify mirror action
    e = nas_acl.EntryCPSObj(
        table_id=table_id,
        entry_id=entry_id,
        action_type='MIRROR_INGRESS')
    e.set_action_val(
        [{'index': mirror_id_2,
          'data': mir_opq_2},
         {'index': mirror_id_1,
          'data': mir_opq_1}])
    upd.append(('set', e.data()))

    # Delete Meter
    e = nas_acl.EntryCPSObj(
        table_id=table_id,
        entry_id=entry_id,
        action_type='SET_POLICER')
    upd.append(('delete', e.data()))

    # Introduce error - Add IN_PORT filter even though IN_PORTS is already
    # present
    e = nas_acl.EntryCPSObj(
        table_id=table_id,
        entry_id=entry_id,
        filter_type='IN_PORT')
    e.set_filter_val(a_utl.get_if_name(1))
    upd.append(('create', e.data()))

    print upd
    r = cps_utils.CPSTransaction(upd).commit()
    if r == False:
        print "Error adding inport filter (Expected) - Should have rolled back previous updates in transaction"
        raw_input("Check entry is Rolled back and Press Enter to continue...")
        passed.append(sys._getframe().f_code.co_name)
    else:
        print "#### Failed - Adding Inport filter did not give error"


def acl_ut_entry_delete_rollback(table_id, entry_id, counter_id):
    global total, passed
    total.append(sys._getframe().f_code.co_name)

    # Transaction with multiple updates
    upd = []
    # Delete entry
    e = nas_acl.EntryCPSObj(table_id=table_id, entry_id=entry_id)
    upd.append(('delete', e.data()))

    # Delete counter
    e = nas_acl.CounterCPSObj(table_id=table_id, counter_id=counter_id)
    upd.append(('delete', e.data()))

    # Delete table
    e = nas_acl.TableCPSObj(table_id=table_id)
    upd.append(('delete', e.data()))

    # Delete entry again - should fail
    e = nas_acl.EntryCPSObj(table_id=table_id, entry_id=entry_id)
    upd.append(('delete', e.data()))

    print upd
    r = cps_utils.CPSTransaction(upd).commit()
    if r == False:
        print "Error deleting entry twice (Expected) - Should have rolled back to create table, counter and entry again"
        raw_input(
            "Check table and entry is Roll back recreated and Press Enter to continue...")
        passed.append(sys._getframe().f_code.co_name)
    else:
        print "#### Failed - Deleting twice did not give error"


def acl_ut_entry_get(table_id=None, entry_id=None):
    global total, passed
    total.append(sys._getframe().f_code.co_name)
    try:
        print '#### Entry Show ####'
        nas_acl.print_entry(table_id, entry_id)
        passed.append(sys._getframe().f_code.co_name)
    except RuntimeError:
        print (sys._getframe().f_code.co_name + ": Error in Get")


def acl_ut_stats_get(table_id=None, counter_id=None):
    global total, passed
    total.append(sys._getframe().f_code.co_name)
    try:
        print '#### Stats Show ####'
        nas_acl.print_stats(table_id, entry_id)
        passed.append(sys._getframe().f_code.co_name)
    except RuntimeError:
        print (sys._getframe().f_code.co_name + ": Error in Get")


def acl_ut_entry_delete(table_id, entry_id):
    global total, passed
    total.append(sys._getframe().f_code.co_name)
    try:
        nas_acl.delete_entry(table_id, entry_id)
        print "Entry ", str(entry_id), " deleted sucessfully"
        passed.append(sys._getframe().f_code.co_name)
    except RuntimeError:
        print "Failed to delete Entry"


def acl_ut_counter_delete(table_id, counter_id):
    global total, passed
    total.append(sys._getframe().f_code.co_name)
    try:
        nas_acl.delete_counter(table_id, counter_id)
        print "Counter ", str(counter_id), " deleted sucessfully"
        passed.append(sys._getframe().f_code.co_name)
    except RuntimeError:
        print "Failed to delete counter"
        return


def acl_ut_table_delete(table_id):
    global total, passed
    total.append(sys._getframe().f_code.co_name)
    try:
        nas_acl.delete_table(table_id)
    except RuntimeError:
        print "Failed to delete table"
        return

    print "Table ", str(entry_id), " deleted sucessfully"
    passed.append(sys._getframe().f_code.co_name)

if __name__ == '__main__':

    table_id = None
    entry_id = None

    if len(sys.argv) <= 1:
        print "Usage ./nas_acl_ut.py <table-priority> <entry-priority>"
        exit()

    try:
        table_id = acl_ut_table_create(sys.argv[1])
        if table_id is not None:
            acl_ut_table_get(table_id)

        if table_id and len(sys.argv) > 2:
            counter_id = acl_ut_counter_create(table_id, ['PACKET', 'BYTE'])
            acl_ut_counter_get(table_id, counter_id)

            entry_id = acl_ut_entry_create(table_id, prio=sys.argv[2],
                                           counter_id=counter_id)
            if entry_id is None:
                exit()
            acl_ut_entry_get(table_id, entry_id)

            acl_ut_entry_modify1(table_id, entry_id)
            acl_ut_entry_modify2(table_id, entry_id, counter_id)
            acl_ut_entry_modify_rollback(table_id, entry_id)

            new_counter_id = acl_ut_entry_incr_modify(table_id, entry_id)
            acl_ut_entry_get(table_id, entry_id)

            acl_ut_entry_incr_rollback(table_id, entry_id)
            acl_ut_entry_get(table_id, entry_id)

            acl_ut_entry_delete_rollback(table_id, entry_id, new_counter_id)
            acl_ut_entry_get(table_id, entry_id)

            acl_ut_stats_get(table_id, counter_id)
            acl_ut_counter_delete(table_id, counter_id)
            acl_ut_entry_delete(table_id, entry_id)
            acl_ut_counter_delete(table_id, new_counter_id)
            acl_ut_table_delete(table_id)
            a_utl.mirror_delete(mirror_id_1)
            a_utl.mirror_delete(mirror_id_2)

    except RuntimeError as r:
        print r

    print "======================"
    p = 0
    f = 0
    for i in total:
        if i in passed:
            print (i + " passed")
            p = p + 1
        else:
            print (">>>>  " + i + " FAILED")
            f = f + 1
    print (str(p + f) + " tests. " + str(p)
           + " passed." + str(f) + " failed.")
