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


import cps
import cps_utils
import bytearray_utils
import nas_os_if_utils as if_utl
import os
import re
import nas_acl_map
import binascii

obj_root = 'base-acl'
dbg_on = False


def dbg_print(*args):
    if dbg_on:
        print args


class AclCPSObj:

    """
    Base class for the ACL Table and Entry classes
    """

    @classmethod
    def create_cps_obj(cls, module, data={}, qual='target'):
        cps_obj = {
            'key': cps.key_from_name(qual, module),
            'data': data
        }
        return cps_obj

    @classmethod
    def to_cps_val(cls, name, val):
        if cls.is_attr_enum(name):
            der_val = nas_acl_utils.enum_get(
                cls.attr_enum_prefix(name) + val)
            der_val = bytearray_utils.type_to_ba[
                'uint32_t']('uint32_t', der_val)
        elif cls.is_attr_intf(name):
            if isinstance(val, str) and not val.isdigit():
                ifindex = if_utl.name_to_ifindex(val)
                if ifindex is None:
                    raise ValueError("Unknown interface name" + val)
                der_val = bytearray_utils.type_to_ba[
                    'uint32_t']('uint32_t', ifindex)
            else:
                der_val = bytearray_utils.type_to_ba[
                    'uint32_t']('uint32_t', val)
        else:
            attr_type = cls.attr_type(name)
            if attr_type == 'opaque':
                return val
            if attr_type in ['uint8_t', 'uint16_t', 'uint32_t', 'uint64_t']:
                if isinstance(val, str):
                    val = int(val, 0)
                else:
                    val = int(val)
            der_val = bytearray_utils.type_to_ba[attr_type](attr_type, val)
        return der_val

    @classmethod
    def attr_enum_prefix(cls, name):
        return cls.get_attr_map()[name][2]

    @classmethod
    def is_attr_enum(cls, name):
        return cls.get_attr_map()[name][1] == 'enum'

    @classmethod
    def is_attr_intf(cls, name):
        return cls.get_attr_map()[name][1] == 'intf'

    @classmethod
    def is_attr_leaf(cls, name):
        return cls.get_attr_map()[name][0] == 'leaf'

    @classmethod
    def is_attr_leaflist(cls, name):
        return cls.get_attr_map()[name][0] == 'leaflist'

    @classmethod
    def is_attr_container(cls, name):
        return cls.get_attr_map()[name][0] == 'container'

    @classmethod
    def get_container_default(cls, name):
        return cls.get_attr_map()[name][1]

    @classmethod
    def is_attr_list(cls, name):
        return cls.get_attr_map()[name][0] == 'list'

    @classmethod
    def from_cps_val(cls, name, val):

        if cls.is_attr_enum(name):
            der_val = bytearray_utils.ba_to_value('uint32_t', val)
            der_val = nas_acl_utils.enum_reverse_get(
                der_val, cls.attr_enum_prefix(name))
        elif cls.is_attr_intf(name):
            ifidx = bytearray_utils.ba_to_value('uint32_t', val)
            der_val = if_utl.ifindex_to_name (ifidx)
        else:
            der_val = bytearray_utils.ba_to_value(
                cls.attr_type(name), str(val))
        return der_val

    @classmethod
    def attr_type(cls, name):
        if name in cls.get_attr_map():
            return cls.get_attr_map()[name][1]
        return None

    @classmethod
    def add_attr(cls, obj_dict, name, val):

        if cls.is_attr_leaf(name):
            der_val = cls.to_cps_val(name, val)
            obj_dict[cls.to_path(name)] = der_val

        elif cls.is_attr_leaflist(name):
            if cls.to_path(name) in obj_dict:
                leaflist = obj_dict[cls.to_path(name)]
            else:
                leaflist = []
                obj_dict[cls.to_path(name)] = leaflist

            if isinstance(val, list):
                for i in val:
                    der_val = cls.to_cps_val(name, i)
                    leaflist.append(der_val)
            else:
                der_val = cls.to_cps_val(name, val)
                leaflist.append(der_val)

        else:
            obj_dict[cls.to_path(name)] = val

    @classmethod
    def extract_obj(cls, cps_data):
        if 'change' in cps_data:
            return cps_data['change']['data']
        if 'data' in cps_data:
            return cps_data['data']
        return cps_data

    @classmethod
    def find_container(cls, obj, full_name):
        if full_name in obj:
            return obj
        for attr, val in obj.items():
            if isinstance(val, dict):
                ret_obj = cls.find_container(val, full_name)
                if ret_obj is not None:
                    return ret_obj
        return None

    @classmethod
    def extract_attr(cls, cps_data, name):

        obj = cls.extract_obj(cps_data)

        if 'cps/key_data' in obj and \
                cls.to_path(name) in obj['cps/key_data']:
            return cls.extract_attr(obj['cps/key_data'], name)

        full_attr_name = cls.to_path(name)

        if cls.is_attr_leaf(name):
            container = cls.find_container(obj, full_attr_name)
            val = container[full_attr_name]
            return cls.from_cps_val(name, val)

        elif cls.is_attr_leaflist(name):
            container = cls.find_container(obj, full_attr_name)
            l = []
            for val in obj[full_attr_name]:
                l.append(cls.from_cps_val(name, val))
            return l
        else:
            return obj[full_attr_name]

    @classmethod
    def to_path(cls, attr_name):
        return cls.obj_name + '/' + attr_name

    def __print_attrs(self, obj):
        for attr, val in obj.items():
            if isinstance(val, dict):
                if attr != 'cps/key_data':
                    self.__print_attrs(val)
            else:
                cut_name = attr.replace(self.obj_name + '/', '')
                try:
                    val_str = self.extract(cut_name, obj)
                    if self.attr_type(cut_name) == 'opaque':
                        val_str = binascii.hexlify(val_str)
                    print '  ' + cut_name + '   : ' + str(val_str)
                except:
                    print '  ' + cut_name + '   : ' + "E: Could not extract value"

    def print_obj(self):
        """
        Print the contents in a user friendly format
        """
        print '-' * 40
        cps_data = self.data()
        if 'cps/key_data' in cps_data:
            print "### Key ###"
            self.__print_attrs(cps_data['cps/key_data'])
        if 'data' in cps_data:
            if 'cps/key_data' in cps_data['data']:
                print "### Key ###"
                self.__print_attrs(cps_data['data']['cps/key_data'])
            print "### Data ###"
            self.__print_attrs(cps_data['data'])
        print '-' * 40


class nas_acl_utils:

    @staticmethod
    def form_enum_name(enum_str):
        return '_'.join([e_comp.upper() for e_comp in enum_str.split(':')])

    @staticmethod
    def enum_map_get():
        return nas_acl_map.get_enums()

    @staticmethod
    def enum_reverse_get(val, enum_type):
        for key in nas_acl_utils.enum_map_get():
            if key.split(':')[:2] == enum_type.split(':')[:2]:
                if nas_acl_utils.enum_get(key) == val:
                    return key.split(':')[2]

    @staticmethod
    def enum_get(enum_str):
        return nas_acl_utils.enum_map_get()[enum_str]

    @staticmethod
    def enum_read(enum_str):
        e_name = nas_acl_utils.form_enum_name(enum_str)
        e_name = e_name.replace('-', '_')
        print e_name
        fname = os.environ['ARINC'] + '/dell-base-acl.h'
        print fname
        with open(fname, 'r') as searchfile:
            for line in searchfile:
                if re.search(e_name, line):
                    print line
                    return int(line.split()[2].rstrip(','))
