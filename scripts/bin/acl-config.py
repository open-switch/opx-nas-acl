#!/usr/bin/python
#
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
#

import nas_acl


import cps
import cps_object
import cps_utils

import random
import time
import signal
import sys
import argparse

_KEY='acl-config/entry'

_key_for_status = cps.key_from_name('observed',_KEY)
_key_for_cfg = cps.key_from_name('target',_KEY)

_key_for_reload = cps.key_from_name('target','acl-config/reload')


_valid_match_fields_in=['SRC_IP','DST_IP','IN_PORT','OUT_PORT','L4_SRC_PORT','L4_DST_PORT','SRC_MAC','DST_MAC']

_valid_match_fields_eg=['SRC_IP','DST_IP','IN_PORT','OUT_PORT','L4_SRC_PORT','L4_DST_PORT','SRC_MAC','DST_MAC']

_default_table_prio = 110
_default_entry_prio = 30
#Service Data
__event_handle = None
__table_in = None
__table_out = None

def __get_table(type,fields):
    _table_id = nas_acl.create_table(stage=type,\
        prio=_default_table_prio, allow_filters=fields,only_if_not_exist=True)

    out = []
    if cps.get ([nas_acl.TableCPSObj (table_id=_table_id).data()], out) == True:
        if len(out) > 0:
            return nas_acl.TableCPSObj(cps_data=out[0])
    return None

def __validate_table():
    global __table_in, __table_out
    __table_in = __get_table('INGRESS',_valid_match_fields_in)
    __table_out = __get_table('EGRESS',_valid_match_fields_eg)

    if not __table_in or not __table_out:
        print('Unable to initialize the default tables', __table_in, __table_out)
        return False

    return True

def __load_file(name):
    l=[]
    with open(name,'r') as _file:
        _process = False
        while True:
            _line = _file.readline()
            if not _line: break
            if _line.find('ACL Entries:')==0:
               _process=True
               continue

            if not _process:
               continue

            if _line.find('#') != -1:
                _line = _line[:_ln.find('#')+1]

            _ln = _line.strip().split(' ')

            if _ln[0] == '-':
                    _ln = _ln[1:]
            _name = _ln[0]
            _ln = _ln[1:]
            _ln = ' '.join(_ln)
            _obj = cps_object.CPSObject(module=_KEY,qual='target')
            _obj.add_attr('name',_name)
            _obj.add_attr('rule',_ln)
            l.append(_obj.get())
            cps_utils.print_obj(_obj.get())

    return l

def __get_acl_entries(table_id=None,entry_id=None):
    e = nas_acl.EntryCPSObj(table_id=table_id, entry_id=entry_id)
    r = []
    if not cps.get([e.data()], r):
        print 'Failed to get acl entries' + str(entry_id)
        return []
    return r


def __acl_cfg_to_acl_entry(obj, create_if_not_there=False):
    obj = cps_object.CPSObject(obj=obj)

    _name = obj.get_attr_data('name')
    _rule = obj.get_attr_data('rule')
    try:
        _entry_id = obj.get_attr_data('base-acl/entry/id')
        _table_id = obj.get_attr_data('base-acl/table/id')
        _lst = __get_acl_entries(_table_id,_entry_id)
        if len(_lst) > 0:
            return obj.get()
        print('Invalid ACL entry details - %d and %d' % (_table_id,_entry_id))
    except:
        print('Not created yet...')
        _entry_id = None
        _table_id = None

    l = _rule.strip().split(' ')
    _parser = argparse.ArgumentParser('Process ACL rules')

    _parser.add_argument('-prio','--priority',help='The rule priority',action='store',required=False)
    _parser.add_argument('-i','--in-interface',help='The incoming interface name',action='append',required=False)
    _parser.add_argument('-o','--out-interface',help='The outgoing interface name (same as the -i option) at this point',action='append',required=False)
    _parser.add_argument('-j', '--jump',help='The action assocaiated with the rule ACCEPT or DROP',choices=['DROP','ACCEPT','ACCEPT-TRAP','TRAP'],action='store',required=True)
    _parser.add_argument('-I','-A',help='The INPUT or OUTPUT chain which maps to the INGRESS or EGRESS tables',choices=['INPUT','OUTPUT'],required=True)
    _parser.add_argument('-p', '--protocol',help='The IP protocol type (TCP/UDP/ICMP)',action='store')
    _parser.add_argument('-d', '--destination',help='Specify the destination IPv4/IPv6 address',action='store')
    _parser.add_argument('--dport',help='Specify the destination port number',action='store')
    _parser.add_argument('--sport',help='Specify the source port number',action='store')
    _parser.add_argument('-s', '--source',help='Specify the source IPv4/IPv6 address',action='store')
    _parser.add_argument('--mac-source',help='The source MAC address',action='store')
    _parser.add_argument('--mac-destination',help='The destination MAC address',action='store')
    _parser.add_argument('-m',help='Module loading (depreciated at this point but ignored)',action='store')

    _args = vars(_parser.parse_args(l))
    print "***"
    print _args
    if 'A' in _args:
        _args['I'] = _args['A']
    _table = None
    if 'I' in _args:
        if _args['I'] == 'INPUT':
            _table = __table_in
        else:
            _table = __table_out
    if _table is None:
        print('Invalid table specified.')
        raise Exception('Failed to create table - no table specified (in/out)')

    _filters={}
    if _args['source']!=None:
        if '.' in _args['source']:
            _addrs = _args['source'].split('/')
            _mask = '255.255.255.255'
            if len(_addrs) == 1:
                _addrs.append(_mask)
            _filters['SRC_IP']={
                'addr' : _addrs[0],
                'mask' : _addrs[1]
            }
    if _args['destination']!=None:
        if '.' in _args['destination']:
            _addrs = _args['destination'].split('/')
            _mask = '255.255.255.255'
            if len(_addrs) == 1:
                _addrs.append(_mask)
            _filters['DST_IP']={
                'addr' : _addrs[0],
                'mask' : _addrs[1]
            }

    if _args['mac_source']!=None:
        _addrs = _args['mac_source'].split('/')
        _mask = 'ff:ff:ff:ff:ff:ff'
        if len(_addrs) == 1:
            _addrs.append(_mask)
        _filters['SRC_MAC']={
            'addr' : _addrs[0],
            'mask' : _addrs[1]
        }

    if _args['mac_destination']!=None:
        _addrs = _args['mac_destination'].split('/')
        _mask = 'ff:ff:ff:ff:ff:ff'
        if len(_addrs) == 1:
            _addrs.append(_mask)
        _filters['DST_MAC']={
            'addr' : _addrs[0],
            'mask' : _addrs[1]
        }

    if _args['sport']!=None:
        _filters['L4_SRC_PORT']=_args['sport']

    if _args['dport']!=None:
        _filters['L4_DST_PORT'] = _args['dport']

    _actions = {}
    if _args['jump']!=None and _args['jump'] == 'DROP':
        _actions['PACKET_ACTION'] = 'DROP'
    if _args['jump']!=None and _args['jump'] == 'ACCEPT':
        _actions['PACKET_ACTION'] = 'FORWARD'
    if _args['jump']!=None and _args['jump'] == 'ACCEPT-TRAP':
        _actions['PACKET_ACTION'] = 'COPY_TO_CPU_AND_FORWARD'
    if _args['jump']!=None and _args['jump'] == 'TRAP':
        _actions['PACKET_ACTION'] = 'COPY_TO_CPU'

    _prio = None
    if _args['priority']:
        _prio = int(_args['priority'])
    else:
        _prio = _default_entry_prio

    print('Attempting to local ACL entry')
    _entry = nas_acl.find_entry(table_id=_table.extract_id(),priority=_prio,\
                filter_map=_filters,action_map=_actions)
    if _entry != None:
        _obj = cps_object.CPSObject(obj=_entry.data())
        #_entry_id = _obj.get_attr_data('base-acl/entry/id')
        #_table_id = _obj.get_attr_data('base-acl/table/id')
        obj.add_attr('base-acl/entry/id',_obj.get_attr_data('base-acl/entry/id'))
        obj.add_attr('base-acl/table/id',_table.extract_id())

        _obj = obj.get()
        _obj['operation'] = 'set'
        cps.db_commit(_obj,None,True)
        return _obj

    if _entry == None and create_if_not_there:
        _entry_id = None
        try :
            _entry_id = nas_acl.create_entry(table_id=_table.extract_id(),prio=_prio,filter_map=_filters,action_map=_actions)
            obj.add_attr('base-acl/entry/id',_entry_id)
            obj.add_attr('base-acl/table/id',_table.extract_id())
            _obj = obj.get()
            _obj['operation'] = 'set'
            cps.db_commit(_obj,None,True)
            return _obj
        except Exception as err:
            print(err)
            print('Failed to create acl entry')
            return None

    return None

def __sync_from_db():
    _obj = cps_object.CPSObject(module=_KEY,qual='target')
    _l=[]
    cps.db_get(_obj.get(),_l)
    for i in _l:
        if not __create_acl_entry(i):
            print('Failed to create ACL entry for ', i)

def __mark_dirty(obj):
    obj['dirty'] = True

def __clean(obj):
    del obj['dirty']

def __is_dirty(obj):
    if 'dirty' in obj: return obj['dirty'] == True
    return False

def __array_to_map(lst):
    _d = {}
    for i in lst:
        _obj = cps_object.CPSObject(obj=i)
        _name =  _obj.get_attr_data('name')
        _d[_name] = _obj
    return _d

def __find_entry(obj):
    return  __acl_cfg_to_acl_entry(obj,False)


def __get_db_objs():
    #load the DB entry list
    _db_objs=[]
    if cps.db_get(cps_object.CPSObject(module=_KEY,qual='target').get(),_db_objs) != 0:
        print('DB - Can\'t get list of acl config db entries')

    return _db_objs

def __sync_file_to_db(filename):
    __objs = __load_file(filename)
    _objs = __array_to_map(__objs)

    _db = __get_db_objs()

    _db_map = {}

    for _i in _db:
        _o = cps_object.CPSObject(obj=_i)
        _name = _o.get_attr_data('name')
        _rule = _o.get_attr_data('rule')

        if _name in _objs:
            if _rule == _objs[_name].get_attr_data('rule'):
                #print(_objs[_name].get(), "And ", _i, "Are the same")
                _db_map[_name] = _i
                continue
            #print('Entries are different ' , _i,_objs[_name].get())
        #print('Existing DB entry targeted to be removed ' , _i)
        __mark_dirty(_i)

    for _i in _db:
        #_entry = __find_entry(_i)
        if __is_dirty(_i):
            _i['operation']='delete'
            cps.db_commit(_i,None,True)

    for _i in __objs:
        _i['operation']='create'
        _o = cps_object.CPSObject(obj=_i)
        _name = _o.get_attr_data('name')
        if _name in _db_map:
            continue
        cps.db_commit(_i,None,True)

def __resync():

    _db = __get_db_objs()

    _entries = __get_acl_entries( __table_in.extract_id()) + \
        __get_acl_entries( __table_out.extract_id())

    _m = {}

    for _i in _entries:
        print (_i)
        _o = cps_object.CPSObject(obj=_i)
        _acl = _o.get_attr_data('base-acl/entry/id')
        _table = _o.get_attr_data('base-acl/entry/table-id')
        __mark_dirty(_o.get())
        _m[(_table,_acl)] = _i

    for _i in _db:
        _entry = cps_object.CPSObject(obj=__acl_cfg_to_acl_entry(_i,True))
        if _entry == None:
            print('Error creating ACL entries.  Consult the logs for more details.')

        _table = _entry.get_attr_data('base-acl/table/id')
        _entry = _entry.get_attr_data('base-acl/entry/id')
        _i['operation']='set'
        cps.db_commit(_i,None,True)

        if (_table,_entry) in _m:
            del _m[(_table,_entry)]

    for (table,entry) in _m.keys():
        nas_acl.delete_entry(table,entry)



# CPS Get handler
def get_status_cb(methods, params):
    print params
    key = params['filter']['key']

    _db = __get_db_objs()
    print _db
    for _i in _db:
        params['list'].append(_i)

    return True


# CPS Transaction handler
def set_cfg_cb(methods, params):
    # print "Trans...", params
    op = params['operation']

    #change object
    _change = params['change']

    print('Handling change - '+op+' and obj ',_change)

    if op == 'rpc':
        _o = cps_object.CPSObject(obj=_change)
        _filename = _o.get_attr_data('acl-config/reload/input/filename')
        print('Loading data from '+_filename)
        try:
            __sync_file_to_db(_filename)
        except:
            pass
        #handle two stage sync - allow failures and still cause a re-sunc to the back end
        try:
            __resync()
        except:
            pass

        return True

    if not op == 'set':
        return False

    return True


__event_handle = cps.event_connect()
cps_handle = cps.obj_init()

while True:
    if not cps.enabled(cps.key_from_name('target','base-acl/entry')):
        time.sleep(1)
        continue
    break

#load ACL tables
if not __validate_table():
    print('Unable to create required ACL table for ACL model')
    sys.exit(1)

print ('INPUT - Table ID %d' % __table_in.extract_id())
print ('OUTPUT - Table ID %d' % __table_out.extract_id())

__sync_file_to_db('acl-config.yaml')
__resync()


# Register for CPS
reg = dict()

reg['get'] = get_status_cb
cps.obj_register(cps_handle, _key_for_status, reg)

reg={}
reg['get'] = get_status_cb
cps.obj_register(cps_handle, _key_for_cfg, reg)

reg={}
reg['transaction'] = set_cfg_cb
cps.obj_register(cps_handle, _key_for_reload, reg)


# Wait for responses
while True:
    signal.pause()
