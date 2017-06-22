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

import cps_utils
import cps
import sys
import nas_os_if_utils
import nas_qos

base_cpu_intf_type = 'base-if:cpu'


def mirror_create(dst_intf):
    cfg_mo = cps_utils.CPSObject('base-mirror/entry')
    cfg_mo.add_attr('type', 1)  # Local SPAN
    cfg_mo.add_attr('dst-intf', dst_intf)

    print cfg_mo.get()
    r = cps_utils.CPSTransaction([('create', cfg_mo.get())]).commit()
    if r == False:
        raise RuntimeError(
            "Mirror creation failed on interface " + str(dst_intf))

    ret_obj = r[0]['change']
    mirr_wr_obj = cps_utils.CPSObject('base-mirror/entry', obj=ret_obj)

    mirr_id = mirr_wr_obj.get_attr_data('id')
    print "Successfully installed Mirror Id = ", mirr_id
    print "Opaque data = " + mirr_wr_obj.get_attr_data('opaque-data')

    return mirr_id, ret_obj['data']['base-mirror/entry/opaque-data']


def mirror_delete(mirr_id):
    cfg_mo = cps_utils.CPSObject('base-mirror/entry')
    cfg_mo.add_attr('id', mirr_id)

    r = cps_utils.CPSTransaction([('delete', cfg_mo.get())]).commit()
    if r == False:
        print ("Error deleting mirror" + str(mirr_id))
    else:
        print ("Successfully deleted mirror" + str(mirr_id))


def mirror_show():
    filt = cps_utils.CPSObject('base-mirror/entry')
    ret = []
    r = cps.get([filt.get()], ret)
    for obj in ret:
        cps_utils.print_obj(obj)

ifs = []


def get_if_name(index=0):
    global ifs

    if not ifs:
        ifs = nas_os_if_utils.nas_os_if_list()
        while not ifs:
            ifs = nas_os_if_utils.nas_os_if_list()
            time.sleep(1)

    if not ifs:
        raise RuntimeError("No interfaces found")

    if index < len(ifs):
        if_wr_obj = cps_utils.CPSObject(obj=ifs[index])
    else:
        if_wr_obj = cps_utils.CPSObject(obj=ifs[0])

    return if_wr_obj.get_attr_data('if/interfaces/interface/name')


def qos_meter_create(m_type='BYTE', cir=None, pir=None, cbs=None, pbs=None):
    m = nas_qos.MeterCPSObj(
        meter_type=m_type,
        pir=pir,
        cir=cir,
        cbs=cbs,
        pbs=pbs)
    m.set_attr('red-packet-action', 'DROP')

    upd = ('create', m.data())
    r = cps_utils.CPSTransaction([upd]).commit()
    if r == False:
        raise RuntimeError("Meter creation failed")

    m = nas_qos.MeterCPSObj(cps_data=r[0])
    meter_id = m.extract_id()
    meter_opq = m.extract_opaque_data()

    print "Successfully installed Meter Id = ", meter_id
    return meter_id, meter_opq


def qos_meter_delete(meter_id):
    m = nas_qos.MeterCPSObj(meter_id=meter_id)
    upd = ('delete', m.data())
    r = cps_utils.CPSTransaction([upd]).commit()
    if r == False:
        print ("Error deleting meter" + str(meter_id))
    else:
        print ("Successfully deleted meter" + str(meter_id))


def qos_meter_get_opaque_data(meter_id):
    flt = nas_qos.MeterCPSObj(meter_id=meter_id)
    ret = []
    r = cps.get([flt.data()], ret)
    if r == False:
        raise RuntimeError("Meter Get failed")

    m = nas_qos.MeterCPSObj(cps_data=ret[0])
    return m.extract_opaque_data()


def qos_queue_get(ifidx, q_num, q_type):
    attr_list = {
        'type': q_type,
        'queue-number': q_num,
        'port-id': ifidx,
    }
    flt = nas_qos.QueueCPSObj(map_of_attr = attr_list)
    ret = []
    r = cps.get([flt.data()], ret)
    if r == False:
        raise RuntimeError("Queue Get failed")

    q = nas_qos.QueueCPSObj(cps_data=ret[0])

    return q.extract_id(), q.extract_opaque_data()


def get_cpu_port():
    ifs = nas_os_if_utils.nas_os_cpu_if()
    cpu_ifs = []
    cpu_ifnames = []
    for intf in ifs:
        obj = cps_utils.CPSObject(obj=intf)
        try:
            iftype = obj.get_attr_data('if/interfaces/interface/type')
        except ValueError:
            continue
        if iftype != base_cpu_intf_type:
            continue
        cpu_ifnames.append(obj.get_attr_data('if/interfaces/interface/name'))
        cpu_ifs.append(obj.get_attr_data('dell-base-if-cmn/if/interfaces/interface/if-index'))
    return cpu_ifs, cpu_ifnames
