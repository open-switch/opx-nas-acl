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

import cps
import cps_object
import cps_utils
import nas_acl

def get_cps_object(module_name, attr_list = {}, qual='target'):
    cps_obj = cps_object.CPSObject(module = module_name, qual = qual, data = attr_list)
    ret_list = []
    if cps.get([cps_obj.get()], ret_list)  == False:
        return False
    for ret_obj in ret_list:
        cps_utils.print_obj(ret_obj)
    return True

def set_cps_object(module_name, attr_list = {}, op = 'set'):
    cps_obj = cps_object.CPSObject(module = module_name, data = attr_list)
    upd = (op, cps_obj.get())
    ret_cps_data = cps_utils.CPSTransaction([upd]).commit()
    if ret_cps_data == False:
        return False
    cps_utils.print_obj(ret_cps_data[0])
    return True

def create_interface(if_name, fp_port = None, sub_port = 0):
    module_name = 'dell-base-if-cmn/set-interface'
    attr_list = {'dell-base-if-cmn/set-interface/input/operation': 1,
                 'if/interfaces/interface/name': if_name,
                 'if/interfaces/interface/type': 'ianaift:ethernetCsmacd'}
    if fp_port is not None:
        attr_list['base-if-phy/hardware-port/front-panel-port'] = fp_port
        attr_list['base-if-phy/hardware-port/subport-id'] = sub_port
    return set_cps_object(module_name, attr_list, 'rpc')

def delete_interface(if_name):
    module_name = 'dell-base-if-cmn/set-interface'
    attr_list = {'dell-base-if-cmn/set-interface/input/operation': 2,
                 'if/interfaces/interface/name': if_name}
    return set_cps_object(module_name, attr_list, 'rpc')

def update_intf_conn_status(if_name, conn, fp_port = None, sub_port = 0):
    module_name = 'dell-base-if-cmn/set-interface'
    attr_list = {'dell-base-if-cmn/set-interface/input/operation': 3,
                 'if/interfaces/interface/name': if_name}
    if conn:
        if fp_port is None:
            print 'No front-panel-port specified for connecting operation'
            return False
        attr_list['base-if-phy/hardware-port/front-panel-port'] = fp_port
        attr_list['base-if-phy/hardware-port/subport-id'] = sub_port
    else:
        attr_list['base-if-phy/hardware-port/front-panel-port'] = None
    return set_cps_object(module_name, attr_list, 'rpc')

def dump_interface(if_name):
    module_name = 'dell-base-if-cmn/if/interfaces/interface'
    attr_list = {'if/interfaces/interface/type': 'ianaift:ethernetCsmacd',
                 'if/interfaces/interface/name': if_name}
    return get_cps_object(module_name, attr_list)

virt_if_name = 'test_virt_if'
phy_if_name = 'e101-003-0'
test_fp_port = 3
test_table_name = 'test_table'
test_entry_name = 'test_entry'
test_table_prio = 200

def test_virt_if_rule():
    try:
        test_table_id = nas_acl.create_table('INGRESS', test_table_prio, ['IN_INTF'], name = test_table_name)
    except RuntimeError:
        assert False
    print '\nTable was created: ID = %d' % test_table_id
    assert create_interface(virt_if_name)
    try:
        test_entry_id = nas_acl.create_entry(test_table_id, 10,
                                    {'IN_INTF': virt_if_name}, {'PACKET_ACTION': 'DROP'}, name = test_entry_name)
        nas_acl.print_entry(test_table_id, test_entry_id)
    except RuntimeError:
        assert False
    print '\nEntry was created: ID = %d' % test_entry_id

    print '\nUn-map physical interface %s' % phy_if_name
    assert update_intf_conn_status(phy_if_name, False)
    assert dump_interface(phy_if_name)
    print 'Map virtual interface %s to front panel port %d' % (virt_if_name, test_fp_port)
    assert update_intf_conn_status(virt_if_name, True, test_fp_port)
    assert dump_interface(virt_if_name)

def test_cleanup():
    print '\nRestore physical interface mapping'
    assert update_intf_conn_status(virt_if_name, False)
    assert dump_interface(virt_if_name)
    assert update_intf_conn_status(phy_if_name, True, test_fp_port)
    assert dump_interface(phy_if_name)

    print '\nCleanup test environment'
    try:
        nas_acl.delete_entry(test_table_name, test_entry_name)
        nas_acl.delete_table(test_table_name)
    except RuntimeError:
        assert False
    assert delete_interface(virt_if_name)
