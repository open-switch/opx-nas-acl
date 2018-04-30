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

import os
import nas_acl
import xml.etree.ElementTree as ET
import cps
import cps_utils
import time
import nas_acl_utils as a_utl
import binascii
import sys

dbg_on = False
target_cfg_path = '/etc/opx/acl'


def get_master_cfg():
    return acl_cfg_path + '/nas_master_list.xml'


def get_detail_cfg():
    return acl_cfg_path + '/nas_detail_list.xml'


def xml_getroot(xml_file):
    tree = ET.parse(xml_file)
    return tree.getroot()


def load_detail_list():
    detail_list = xml_getroot(get_detail_cfg())

    table_detail_map = {}
    entry_detail_map = {}

    for obj_detail in detail_list:
        if obj_detail.tag == 'table':
            table_detail_map[obj_detail.attrib['tag']] = obj_detail
        elif obj_detail.tag == 'entry':
            entry_detail_map[obj_detail.attrib['tag']] = obj_detail
        else:
            print 'Invalid type of object in ', get_detail_cfg()

    return table_detail_map, entry_detail_map


def load_master_list(table_detail_map, entry_detail_map):
    master_list = xml_getroot(get_master_cfg())

    for stage in master_list:
        print ("Inside ", stage.tag)
        for table in stage:
            load_master_list_table(
                stage.tag,
                table,
                table_detail_map,
                entry_detail_map)


def load_master_list_table(stage, table, table_detail_map, entry_detail_map):
    table_name = table.attrib['tag']
    prio = table.attrib['priority']
    if table_name not in table_detail_map:
        raise RuntimeError(
            "ACL INIT - Unable to find table " +
            table_name +
            " in detail list")

    table_id = apply_table_cfg(table_detail_map[table_name], stage, prio)

    entry_prio = 512
    for entry in table:
        load_master_list_entry(
            entry_prio,
            table_id,
            entry,
            entry_detail_map,
            table_name)
        entry_prio -= 1


def load_master_list_entry(
        entry_prio, table_id, entry, entry_detail_map, table_name):
    if 'priority' not in entry.attrib:
        prio = entry_prio
    else:
        prio = entry.attrib['priority']

    entry_name = entry.attrib['tag']
    if entry_name not in entry_detail_map:
        raise RuntimeError(
            "ACL INIT - Unable to find Entry " +
            entry_name +
            " in detail list")
    apply_entry_cfg(
        entry,
        entry_detail_map[entry_name],
        table_id,
        prio,
        table_name)


def apply_table_cfg(etree_table, stage, prio):
    table_name = etree_table.attrib['tag']

    dbg_print("Creating table stage = ", stage, "prio = ", prio)
    t = nas_acl.TableCPSObj(table_id=table_name, stage=stage, priority=int(prio))
    for field in etree_table.findall('allow-match'):
        dbg_print("Add allow filter ", field.text)
        t.add_allow_filter(field.text)
    for field in etree_table.findall('allow-action'):
        dbg_print("Add allow action ", field.text)
        t.add_allow_action(field.text)

    dbg_print(t.data())
    cps_upd = ('create', t.data())
    ret = cps_utils.CPSTransaction([cps_upd]).commit()

    if ret == False:
        raise RuntimeError("ACL INIT - Table creation failed: " + table_name)

    t = nas_acl.TableCPSObj(cps_data=ret[0])
    table_id = t.extract_id()
    dbg_print("Created Table " + table_name + "-" + str(table_id))
    return table_id

cpu_q_data = {}
cpu_ifs = []
cpu_q_type = ''

def get_cpu_q(q_num):
    global cpu_q_data, cpu_ifs, cpu_q_type

    if q_num in cpu_q_data:
        return cpu_q_data[q_num]

    if not cpu_ifs:
        cpu_ifs, cpu_ifnames = a_utl.get_cpu_port()
        print "CPU IFIndex, IfName = " + str(zip(cpu_ifs, cpu_ifnames))

    qid = None
    q_opq = None
    if cpu_q_type == '':
        for q_type in ['MULTICAST', 'NONE']:
            try:
                cpu_q_type = q_type
                qid, q_opq = a_utl.qos_queue_get(cpu_ifs[0], q_num, cpu_q_type)
                break
            except RuntimeError as r:
                continue
    else:
        qid, q_opq = a_utl.qos_queue_get(cpu_ifs[0], q_num, cpu_q_type)

    return qid, q_opq

def apply_entry_cfg(
        master_etree_entry, etree_entry, table_id, prio, table_name):

    entry_name = etree_entry.attrib['tag']

    dbg_print("Creating entry ", entry_name, " in table_name = ", table_name)
    dbg_print(" ... table_id = ", table_id, "prio = ", prio)

    e = nas_acl.EntryCPSObj(table_id=table_id, entry_id=entry_name, priority=int(prio))

    for match in etree_entry.findall('match'):
        elem_type, elem_val = get_entry_elem(match)
        e.add_match_filter(filter_type=elem_type, filter_val=elem_val)

    for action in etree_entry.findall('action'):
        elem_type, elem_val = get_entry_elem(action)
        e.add_action(action_type=elem_type, action_val=elem_val)

    if 'cpu-q' in master_etree_entry.attrib:
        cpu_q = master_etree_entry.attrib['cpu-q']
        qid, q_opq = get_cpu_q(cpu_q)
        dbg_print("cpu q num = " + str(cpu_q))
        dbg_print("nas cpu q id = " + str(qid))
        dbg_print("q opq data = " + str(binascii.hexlify(q_opq)))

        e.add_action(
            action_type='SET_CPU_QUEUE',
            action_val={'index': qid,
                        'data': q_opq})
        if 'action' in master_etree_entry.attrib:
            e.add_action(
                action_type='PACKET_ACTION',
                action_val=master_etree_entry.attrib['action'])
        try:
            counter_id = counter_create(table_id, types=['PACKET'])
        except:
            raise RuntimeError(
                "ACL INIT - Counter creation failed for " +
                entry_name +
                " in table: " +
                table_name)
        e.add_action(action_type='SET_COUNTER', action_val=counter_id)

    dbg_print(e.data())
    cps_upd = ('create', e.data())
    ret = cps_utils.CPSTransaction([cps_upd]).commit()

    if ret == False:
        raise RuntimeError(
            "ACL INIT - Entry creation failed: " +
            entry_name +
            " in table: " +
            table_name)

    e = nas_acl.EntryCPSObj(cps_data=ret[0])
    entry_id = e.extract_id()
    print ("Created Entry " + entry_name + "-" + str(entry_id))
    return entry_id


def counter_create(table_id, types=[]):
    c = nas_acl.CounterCPSObj(table_id=table_id, types=types)
    upd = ('create', c.data())
    r = cps_utils.CPSTransaction([upd]).commit()

    if r == False:
        raise RuntimeError

    c = nas_acl.CounterCPSObj(cps_data=r[0])
    counter_id = c.extract_id()
    print "Created Counter " + str(counter_id)
    return counter_id


def get_entry_elem(elem):
    elem_type = elem.attrib['type']
    value = elem.find('value')
    if value == None:
        elem_val = None
    elif len(value) == 0:
        elem_val = value.text
    else:
        elem_val = {}
        for child in value:
            elem_val[child.tag] = child.text

    dbg_print("Add type ", elem_type, "val = ", elem_val)
    return elem_type, elem_val


def dbg_print(*args):
    if dbg_on:
        print (args)

if __name__ == '__main__':

    if 'DN_ACL_CFG_PATH' in os.environ.keys():
        acl_cfg_path = os.environ['DN_ACL_CFG_PATH']
    else:
        acl_cfg_path = target_cfg_path

    t = nas_acl.TableCPSObj()
    r = []
    while cps.get([t.data()], r) == False:
        time.sleep(1)

    try:
        table_detail_map, entry_detail_map = load_detail_list()
        load_master_list(table_detail_map, entry_detail_map)
    except RuntimeError as r:
        print "Runtime Error: " + str(r)
        sys.exit(1)
