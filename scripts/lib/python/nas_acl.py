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
The NAS ACL Python module is a user-friendly wrapper over the generic CPS Python
module for configuring the Base ACL.

Advatntages over generic CPS module and its utilities -

 - Knows types for all attributes in the Base ACL Yang model - types need not
   be taught explicitly
 - Knows the value attributes for all the ACL Filter and Action types - allows
   filters and actions to be specified as simple python dict type-value pairs
 - Knows the ACL yang model enum name to number mapping - allows Filter and
   Action names from the yang model to be used directly.
 - Hides CPS object creation/population, attachment to CPS Transaction
   internally behind single function call.

Checkout the nas_acl_simple_example.py for a simple usage
Refer the nas_acl_crud_example.py for a more extensive usage
"""

from nas_acl_table import *
from nas_acl_entry import *
from nas_acl_counter import *
from nas_acl_stats import *
import cps
import cps_utils

def find_table(table_id=None,priority=None,matchfields=None,table_stage=None):
    t = TableCPSObj(table_id=table_id)
    r = []
    if not cps.get([t.data()], r):
        print 'CPS Get failed for ACL Table'
        return
    for t_cps in r:
        _valid = True
        t = TableCPSObj(cps_data=t_cps)
        if priority!=None:
           try:
                _val = t.extract('priority')
                if _val!=priority:
                    continue
           except:
                continue

        if matchfields!=None:
            _val = t.extract('allowed-match-fields')
            for i in matchfields:
                if i in _val: continue
                _valid=False
                break
        if not _valid:
            continue

        if table_stage!=None:
            _val = t.extract('stage')
            if _val!=table_stage:
                continue
        return t
    return None

def __extract_attr(e,name):
    try:
        _val = e.extract(name)
        return _val
    except:
        pass
    return None

def find_entry(table_id=None, entry_id=None,priority=None,filter_map={},\
    action_map={}):
    """
    Find the entry based on the parameters in the actions/filters and other parameters.
    """

    e = EntryCPSObj(table_id=table_id, priority=priority)

    for ftype, fval in filter_map.items():
        e.add_match_filter(filter_type=ftype, filter_val=fval)

    for atype, aval in action_map.items():
        e.add_action(action_type=atype, action_val=aval)

    _ent_data = e.data()

    r = []
    if not cps.get([e.data()], r):
        print 'CPS Get failed for ACL Entry' + str(entry_id)
        return
    for e_cps in r:
        def __cmp_maps(to_o, from_o):
            for _ent in from_o.keys():
                _rhs_data = from_o[_ent]
                if _ent not in to_o:
                    if 'cps/key_data' in to_o and _ent in to_o['cps/key_data']:
                        _lhs_data = to_o['cps/key_data'][_ent]
                    else:
                        return False
                else:
                    _lhs_data = to_o[_ent]

                if type(_lhs_data) != type(_rhs_data): return False
                if type(_lhs_data) is dict:
                    if not __cmp_maps(_lhs_data,_rhs_data):
                        return False

                if type(_lhs_data) is list:
                    if len(_lhs_data)!=len(_rhs_data): return False
                    for _ix in range(0,len(_lhs_data)):
                         #first item
                        _a = _lhs_data[ix]
                        _b = _rhs_data[ix]
                        if _a != _b: return False
            return True

        # remember that we can't use all keys - since there are other things in the object that shouldn't be there
        if not __cmp_maps(e_cps['data'],_ent_data['data']):
            print('Not the same',e_cps['data'], 'and',_ent_data['data'])
            continue

        return e_cps
    return None


def create_table(stage, prio, allow_filters, allow_actions=None, name=None, size=None, switch_id=0,
                 udf_groups=None, only_if_not_exist=False):
    if only_if_not_exist:
        _table = find_table(priority=prio,matchfields=allow_filters,\
                table_stage=stage)
        if _table!=None:
            return _table.extract_id()

    t = TableCPSObj(stage=stage, priority=prio, table_id=name, size=size, switch_id=switch_id)

    for f in allow_filters:
        t.add_allow_filter(f)

    if allow_actions is not None:
        for a in allow_actions:
            t.add_allow_action(a)

    if udf_groups != None:
        for grp_id in udf_groups:
            t.add_udf_group(grp_id)

    upd = ('create', t.data())
    r = cps_utils.CPSTransaction([upd]).commit()

    if r == False:
        raise RuntimeError("Table create failed")

    t = TableCPSObj(cps_data=r[0])
    table_id = t.extract_id()
    return table_id


def create_entry(table_id, prio, filter_map, action_map, name=None, switch_id=0):
    e = EntryCPSObj(table_id=table_id, priority=prio, entry_id=name,
                    switch_id=switch_id)
    for ftype, fval in filter_map.items():
        e.add_match_filter(filter_type=ftype, filter_val=fval)

    for atype, aval in action_map.items():
        e.add_action(action_type=atype, action_val=aval)
    upd = ('create', e.data())
    r = cps_utils.CPSTransaction([upd]).commit()
    if r == False:
        raise RuntimeError("Entry create failed")

    e = EntryCPSObj(cps_data=r[0])
    entry_id = e.extract_id()
    return entry_id


def create_counter(table_id, types=['BYTE'], name=None, switch_id=0):
    c = CounterCPSObj(table_id=table_id, types=types, counter_id=name,
                      switch_id=switch_id)
    upd = ('create', c.data())
    r = cps_utils.CPSTransaction([upd]).commit()

    if r == False:
        raise RuntimeError("Counter create failed")

    c = CounterCPSObj(cps_data=r[0])
    counter_id = c.extract_id()
    print "Created Counter " + str(counter_id)
    return counter_id

# Add another filter to the ACL entry


def append_entry_filter(table_id, entry_id, filter_type, filter_val):
    e = EntryCPSObj(
        table_id=table_id,
        entry_id=entry_id,
        filter_type=filter_type)
    e.set_filter_val(filter_val)
    upd = ('create', e.data())
    r = cps_utils.CPSTransaction([upd]).commit()

    if r == False:
        raise RuntimeError("Entry filter append failed")
# Change existing filter value in the ACL entry


def mod_entry_filter(table_id, entry_id, filter_type, filter_val):
    e = EntryCPSObj(
        table_id=table_id,
        entry_id=entry_id,
        filter_type=filter_type)
    e.set_filter_val(filter_val)
    upd = ('set', e.data())
    r = cps_utils.CPSTransaction([upd]).commit()

    if r == False:
        raise RuntimeError("Entry filter mod failed")


# Remove a filter from the ACL entry
def remove_entry_filter(table_id, entry_id, filter_type):
    e = EntryCPSObj(
        table_id=table_id,
        entry_id=entry_id,
        filter_type=filter_type)
    upd = ('delete', e.data())
    r = cps_utils.CPSTransaction([upd]).commit()

    if r == False:
        raise RuntimeError("Entry filter remove failed")


# Add another action to the ACL entry
def append_entry_action(table_id, entry_id, action_type, action_val):
    e = EntryCPSObj(
        table_id=table_id,
        entry_id=entry_id,
        action_type=action_type)
    e.set_action_val(action_val)
    upd = ('create', e.data())
    r = cps_utils.CPSTransaction([upd]).commit()

    if r == False:
        raise RuntimeError("Entry action append failed")
    else:
        print "Appended the action %s with value %d to %d and %d" %(action_type,action_val,table_id,entry_id)


# Change existing action value in the ACL entry
def mod_entry_action(table_id, entry_id, action_type, action_val):
    e = EntryCPSObj(
        table_id=table_id,
        entry_id=entry_id,
        action_type=action_type)
    e.set_action_val(action_val)
    upd = ('set', e.data())
    r = cps_utils.CPSTransaction([upd]).commit()

    if r == False:
        raise RuntimeError("Entry action mod failed")


# Remove an action from the ACL entry
def remove_entry_action(table_id, entry_id, action_type):
    e = EntryCPSObj(
        table_id=table_id,
        entry_id=entry_id,
        action_type=action_type)
    upd = ('delete', e.data())
    r = cps_utils.CPSTransaction([upd]).commit()

    if r == False:
        raise RuntimeError("Entry action remove failed")


# Completely overwrite the filter list with another set of filters
def replace_entry_filter_list(table_id, entry_id, filter_map):
    e = EntryCPSObj(table_id=table_id, entry_id=entry_id)

    for ftype, fval in filter_map.items():
        e.add_match_filter(filter_type=ftype, filter_val=fval)

    upd = ('set', e.data())
    r = cps_utils.CPSTransaction([upd]).commit()

    if r == False:
        raise RuntimeError("Entry filter-list replace failed")

# Completely overwrite the action list with another set of actions


def replace_entry_action_list(table_id, entry_id, action_map):
    e = EntryCPSObj(table_id=table_id, entry_id=entry_id)

    for atype, aval in action_map.items():
        e.add_action(action_type=atype, action_val=aval)

    upd = ('set', e.data())
    r = cps_utils.CPSTransaction([upd]).commit()

    if r == False:
        raise RuntimeError("Entry action-list replace failed")


def print_table(table_id=None):
    t = TableCPSObj(table_id=table_id)
    r = []
    if not cps.get([t.data()], r):
        print 'CPS Get failed for ACL Table' + str(table_id)
        return
    for t_cps in r:
        t = TableCPSObj(cps_data=t_cps)
        t.print_obj()


def print_entry(table_id=None, entry_id=None):
    e = EntryCPSObj(table_id=table_id, entry_id=entry_id)
    r = []
    if not cps.get([e.data()], r):
        print 'CPS Get failed for ACL Entry' + str(entry_id)
        return
    for e_cps in r:
        e = EntryCPSObj(cps_data=e_cps)
        e.print_obj()


def print_counter(table_id=None, counter_id=None):
    c = CounterCPSObj(table_id=table_id, counter_id=counter_id)
    r = []
    if not cps.get([c.data()], r):
        print 'CPS Get failed for ACL Counter' + str(counter_id)
        return
    for c_cps in r:
        c = CounterCPSObj(cps_data=c_cps)
        c.print_obj()


def print_stats(table_id=None, counter_id=None):
    c = StatsCPSObj(table_id=table_id, counter_id=counter_id)
    r = []
    if not cps.get([c.data()], r):
        print 'CPS Get failed for ACL Counter Stats' + str(counter_id)
        return
    for c_cps in r:
        c = StatsCPSObj(cps_data=c_cps)
        c.print_obj()


# Clean up
def delete_entry(table_id, entry_id):
    e = EntryCPSObj(table_id=table_id, entry_id=entry_id)

    upd = ('delete', e.data())
    r = cps_utils.CPSTransaction([upd]).commit()

    if r == False:
        raise RuntimeError("Entry delete failed")


def delete_counter(table_id, counter_id):
    c = CounterCPSObj(table_id=table_id, counter_id=counter_id)

    upd = ('delete', c.data())
    r = cps_utils.CPSTransaction([upd]).commit()

    if r == False:
        raise RuntimeError("Counter delete failed")
    else:
        print "Successfully Deleted the counter for table_id %d and counter_id %d" %(table_id,counter_id)


def delete_table(table_id):
    t = TableCPSObj(table_id=table_id)

    upd = ('delete', t.data())
    r = cps_utils.CPSTransaction([upd]).commit()

    if r == False:
        raise RuntimeError("Table delete failed")
