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

import nas_acl_base as nab
import nas_acl_map


class EntryCPSObj(nab.AclCPSObj):

    """
    Utility class to build a CPS Object based on the ACL Entry Yang model
    with attributes populated from the values passed as inputs.
    The resulting CPS Object representation, obtained by calling data() method,
    can be plugged into a CPS Transaction (by adding create,delete or set op)
    or directly into a CPS Get request.

    Utility class to create a Python dict representation of the
    ACL Entry CPS object based on the values of the attributes passed
    as inputs.
    This internal dict object, obtained by calling the data() method,
    can then be plugged into a CPS Transaction (by adding a operation)
    or directly into a CPS Get request as a Filter.
    eg:
        e = nas_acl.EntryCPSObj (table_id=9, priority=prio)
        e.add_match_filter (filter_type='SRC_IP',
                            filter_val={'addr':'23.0.0.1','mask':'255.0.0.255'})
        e.add_match_filter (filter_type='IP_TYPE', filter_val='IP')
        e.add_action (action_type='SET_SRC_MAC', action_val='01:00:79:08:78:BC')

        upd = ('create', e.data())
        ret = cps_utils.CPSTransaction ([upd]).commit ()

    An instance of this class can also act as a wrapper over the CPS object
    dictionary returned by CPS Create or Get on ACL Entry Yang model and
    provides methods to extract various attributes from it.

    eg:
        filt_obj = nas_acl.EntryCPSObj (table_id=table_id, entry_id=entry_id)
        out = []
        if cps.get ([filt_obj.data()], out) == True:
            for e_cps in out:
                e = nas_acl.EntryCPSObj (cps_data = e_cps)
                e.print_obj ()
    """

    obj_name = nab.obj_root + '/entry'

    @classmethod
    def get_attr_map(cls):
        return nas_acl_map.get_entry_attr_map()

    def __init__(
        self, table_id=None, entry_id=None, priority=None, switch_id=0, cps_data=None,
            filter_type=None, action_type=None, npu_id_list=[]):
        """
        Initialize the Entry CPS object Python dictionary with the input parameters.
        @table_id, @entry_id, @priority, @switch_id - form the CPS object with the
                                                      corresponding attributes
        @cps_data - form the CPS object from CPS data returned from a Create or Set.
        """

        if cps_data is not None:
            self.cps_data = cps_data
            return

        self.cps_data = None
        self.obj_dict = {}
        self.filters = []
        self.actions = []
        self.inner_obj = False
        self.ftype = filter_type
        self.atype = action_type

        if priority is not None:
            self.add_attr(self.obj_dict, 'priority', priority)
        if entry_id is not None:
            if type(entry_id) is int:
                self.add_attr(self.obj_dict, 'id', entry_id)
            elif type(entry_id) is str:
                self.add_attr(self.obj_dict, 'name', entry_id)
        if table_id is not None:
            if type(table_id) is int:
                self.add_attr(self.obj_dict, 'table-id', table_id)
            elif type(table_id) is str:
                self.add_attr(self.obj_dict, 'table-name', table_id)
        if npu_id_list:
            self.add_attr(self.obj_dict, 'npu-id-list', npu_id_list)

        if filter_type:
            self.add_attr(self.obj_dict, 'match/type', filter_type)
            self.cps_obj = self.create_cps_obj(
                module=self.obj_name + '/match',
                data=self.obj_dict)
            self.inner_obj = True
        if action_type:
            self.add_attr(self.obj_dict, 'action/type', action_type)
            self.cps_obj = self.create_cps_obj(
                module=self.obj_name + '/action',
                data=self.obj_dict)
            self.inner_obj = True
        else:
            self.cps_obj = self.create_cps_obj(
                module=self.obj_name,
                data=self.obj_dict)

    def set_filter_val(self, filter_val=None):
        if not self.ftype:
            raise RuntimeError("Not a filter object")
        self.__make_subobj_val(
            self.ftype,
            "match/",
            filter_val,
            self.filter_name2val_map(),
            self.obj_dict)

    def set_action_val(self, action_val=None):
        if not self.atype:
            raise RuntimeError("Not a action object")
        self.__make_subobj_val(
            self.atype,
            "action/",
            action_val,
            self.action_name2val_map(),
            self.obj_dict)

    def add_match_filter(self, filter_type, filter_val=None):
        """
        Add match criteria filters to this Entry

        @filter_type - yang enum name of the match field ('SRC_IPV6')
        @filter_val - a dictionary if the value for this filter type is a container in the yang model
                      or a direct value if the value is a leaf
                      If container then the keys of the dictionary should match the yang leaf attributes
                      of the container
        """
        match_data = {'type_str': filter_type, 'val': filter_val}
        self.filters.append(match_data)

    def add_action(self, action_type, action_val=None):
        """
        Add actions to this Entry

        @action_type - yang enum name of the action ('SET_DSCP')
        @action_val - a dictionary if the value for this filter type is a container in the yang model
                      or a direct value if the value is a leaf
                      If container then the keys of the dictionary should match the yang leaf attributes
                      of the container
        """
        action_data = {'type_str': action_type, 'val': action_val}
        self.actions.append(action_data)

    def data(self):
        """
        Get the CPS object created for the ACL Entry.
        This CPS object can then be plugged into a CPS Transaction or CPS Get request.
        """

        if self.cps_data is not None:
            return self.cps_data

        if self.inner_obj:
            return self.cps_obj

        match_dict = self.__make_match_subobj()
        action_dict = self.__make_action_subobj()

        self.add_attr(self.obj_dict, 'match', match_dict)
        self.add_attr(self.obj_dict, 'action', action_dict)
        return self.cps_obj

    @classmethod
    def filter_name2val_map(cls):
        return nas_acl_map.get_filter_name2val_map()

    @classmethod
    def action_name2val_map(cls):
        return nas_acl_map.get_action_name2val_map()

    def __make_match_subobj(self):
        i = 0
        subobj_dict = {}
        for data in self.filters:
            subobj_dict[str(i)] = self.__make_subobj(
                'match/', data, self.filter_name2val_map())
            i += 1
        return subobj_dict

    def __make_action_subobj(self):
        i = 0
        subobj_dict = {}
        for data in self.actions:
            subobj_dict[str(i)] = self.__make_subobj(
                'action/', data, self.action_name2val_map())
            i += 1
        return subobj_dict

    @classmethod
    def __make_subobj(cls, key_prefix, input_subobj, val_name_map):
        out_subobj = {}
        key_path = key_prefix + 'type'
        elem_type = input_subobj['type_str']
        cls.add_attr(out_subobj, key_path, elem_type)
        if val_name_map[elem_type] != None:
            cls.__make_subobj_val(
                elem_type,
                key_prefix,
                input_subobj['val'],
                val_name_map,
                out_subobj)
        return out_subobj

    @classmethod
    def __make_inner_obj(cls, input_val, key_path):
        inner_obj = {}
        t = type(input_val)
        if t is not dict:
            input_val = {cls.get_container_default(key_path): input_val}

        for inner_key in input_val:
            inner_key_path = key_path + '/' + inner_key
            nab.dbg_print('input_val = ', input_val)
            nab.dbg_print('inner_key_path = ', inner_key_path)
            cls.add_attr(inner_obj, inner_key_path, input_val[inner_key])

        return inner_obj

    @classmethod
    def __make_subobj_val(
            self, elem_type, key_prefix, input_val, val_name_map, out_subobj):
        if input_val is None or elem_type not in val_name_map:
            # No data for this element
            return out_subobj

        key_path = key_prefix + val_name_map[elem_type]
        nab.dbg_print(
            'key_path= ',
            key_path,
            ' ',
            self.get_attr_map()[key_path])
        if self.is_attr_leaf (key_path) or \
           self.is_attr_leaflist(key_path):
            # Leaf value - Input val is a direct value
            self.add_attr(out_subobj, key_path, input_val)
            return out_subobj

        # Non-leaf - Filter or Action Value is a Container or a List of
        # containers
        if self.is_attr_list(key_path):
            # List of containers
            inner_obj = {}
            t = type(input_val)
            if t is list:
                ilist = 0
                for inp in input_val:
                    inner_obj[str(ilist)] = self.__make_inner_obj(
                        inp, key_path)
                    ilist = ilist + 1
            else:
                inner_obj[str(0)] = self.__make_inner_obj(input_val, key_path)
            nab.dbg_print('List inner_obj = ', inner_obj)
        else:
            # Container
            inner_obj = self.__make_inner_obj(input_val, key_path)
            nab.dbg_print('inner_obj = ', inner_obj)

        self.add_attr(out_subobj, key_path, inner_obj)
        return out_subobj

    def extract_id(self):
        """
        Get Table ID from the CPS data returned by Create or Get

        @cps_data - CPS data returned by Create or Get
        """
        cps_data = self.data()

        return self.extract_attr(cps_data, 'id')

    def extract(self, name, obj=None):
        if obj:
            cps_data = obj
        else:
            cps_data = self.data()

        return self.extract_attr(cps_data, name)
