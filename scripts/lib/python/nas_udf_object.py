#!/usr/bin/python
# Copyright (c) 2017 Dell Inc.
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

from cps_object import *
import cps
import cps_utils
import StringIO
import sys
import traceback

udf_grp_type_name_to_value = {'GENERIC': 1, 'HASH': 2}
udf_match_type_name_to_value = {'NON_TUNNEL': 1, 'GRE_TUNNEL': 2}
udf_ip_version_name_to_value = {'IPV4': 1, 'IPV6': 2}
udf_base_name_to_value = {'L2': 1, 'L3': 2, 'L4': 3}

def get_enum_value(name_to_value_map, in_val):
    if type(in_val) != str:
        return  in_val
    in_val = in_val.upper()
    if in_val not in name_to_value_map:
        return None
    return name_to_value_map[in_val]

def get_enum_name(name_to_value_map, enum_val):
    for key in name_to_value_map:
        if name_to_value_map[key] == enum_val:
            return key
    return None

class UdfCommonObj(CPSObject):

    def __init__(self, module = '', raw_obj = None):
        if raw_obj is not None:
            CPSObject.__init__(self, obj = raw_obj)
        else:
            CPSObject.__init__(self, 'base-udf/' + module)
            self.cr_mand_attrs = []
        self.obj_title = ''
        self.obj_attrs = []

    def fixup_attr_name(self, attr_name):
        idx = attr_name.find('/')
        if idx >= 0:
            attr_name = self.generate_path(attr_name[:idx]) + attr_name[idx:]
        return attr_name

    def get_attr_data(self, attr):
       return CPSObject.get_attr_data(self, self.fixup_attr_name(attr))

    def add_attr(self, attr, val):
        CPSObject.add_attr(self, self.fixup_attr_name(attr), val)

    def init_attr(self, params):
        for attr_info in self.obj_attrs:
            arg_name = attr_info[0]
            if arg_name not in params:
                continue
            arg_val = params[arg_name]
            if arg_val is None:
                continue
            if len(attr_info) > 4:
                enum_val = get_enum_value(attr_info[4], arg_val)
                if enum_val is None:
                    raise ValueError('Invalid value %s for argument %s' % (arg_val, arg_name))
                arg_val = enum_val
            self.add_attr(attr_info[1], arg_val)

    def create(self):
        obj_id = None
        try:
            obj_id = self.get_attr_data('id')
        except ValueError:
            pass
        if obj_id is not None:
            raise RuntimeError('Object with id could not be created')
        for attr_id in self.cr_mand_attrs:
            attr_val = None
            try:
                attr_val = self.get_attr_data(attr_id)
            except ValueError:
                pass
            if attr_val is None:
                raise RuntimeError('Mandatory attribute %s not found' % attr_id)
        upd = ('create', self.get())
        r = cps_utils.CPSTransaction([upd]).commit()
        if r == False:
            raise RuntimeError('Object create failed')
        if len(r) == 0:
            raise RuntimeError('No returned object')
        ret_obj = r[0]
        if 'change' in ret_obj:
            ret_obj = ret_obj['change']
        obj = CPSObject(obj = ret_obj)
        id_attr = self.generate_path('id')
        self.add_attr('id', obj.get_attr_data(id_attr))

        return self

    def delete(self):
        obj_id = None
        try:
            obj_id = self.get_attr_data('id')
        except ValueError:
            pass
        if obj_id is None:
            raise RuntimeError('Object ID not found')
        upd = ('delete', self.get())
        r = cps_utils.CPSTransaction([upd]).commit()
        if r == False:
            raise RuntimeError('Object delete failed')

    def get_obj(self):
        ret_objs = []
        cps.get([self.get()], ret_objs)
        out_objs = []
        for ret_obj in ret_objs:
            out_objs.append(self.__class__(raw_obj = ret_obj))
        return out_objs

    def __str__(self):
        saved_stdout = sys.stdout
        output = StringIO.StringIO()
        sys.stdout = output
        fst_col_width = 8
        for attr_info in self.obj_attrs:
            width = len(attr_info[2]) + 1
            if fst_col_width < width:
                fst_col_width = width
        print '-' * (2 * fst_col_width + 5)
        print ' %s' % self.obj_title
        print '-' * (2 * fst_col_width + 5)
        for attr_info in self.obj_attrs:
            try:
                attr_val = self.get_attr_data(attr_info[1])
            except ValueError:
                attr_val = None

            if attr_val is not None and len(attr_info) > 4:
                attr_val = get_enum_name(attr_info[4], attr_val)
            if attr_val is None and len(attr_info) > 3 and attr_info[3]:
                attr_val = '-'
            if attr_val is not None:
                sys.stdout.write('%s%s: %s\n' % (attr_info[2],
                                                ' ' * (fst_col_width - len(attr_info[2])),
                                                attr_val))
        sys.stdout = saved_stdout
        ret_val = output.getvalue()
        output.close()
        return ret_val

class UdfGroupObj(UdfCommonObj):

    def __init__(self, raw_obj = None, **params):
        UdfCommonObj.__init__(self, 'udf-group', raw_obj)
        self.obj_title += 'UDF Group'
        self.obj_attrs += [('group_id', 'id', 'ID', True),
                           ('group_type', 'type', 'Type', True, udf_grp_type_name_to_value),
                           ('length', 'length', 'Length', True)]
        if raw_obj is None:
            self.cr_mand_attrs += ['type', 'length']
            self.init_attr(params)

    def delete(self):
        obj_id = self.get_attr_data('id')
        udf_flt = UdfObj()
        ret_objs = udf_flt.get_obj()
        for obj in ret_objs:
            udf_id = obj.get_attr_data('id')
            grp_id = obj.get_attr_data('group-id')
            if obj_id == grp_id:
                raise ValueError('UDF group is used by UDF with id %d' % udf_id)
        UdfCommonObj.delete(self)

class UdfMatchObj(UdfCommonObj):

    def __init__(self, raw_obj = None, **params):
        UdfCommonObj.__init__(self, 'udf-match', raw_obj)
        self.obj_title += 'UDF Match'
        self.obj_attrs += [('match_id', 'id', 'ID', True),
                           ('match_type', 'type', 'Type', True, udf_match_type_name_to_value),
                           ('priority', 'priority', 'Priority', True),
                           ('l2_type', 'NON_TUNNEL_VALUE/l2-type', 'L2 Type'),
                           ('l2_type_mask', 'NON_TUNNEL_VALUE/l2-type-mask', 'L2 Mask'),
                           ('l3_type', 'NON_TUNNEL_VALUE/l3-type', 'L3 Type'),
                           ('l3_type_mask', 'NON_TUNNEL_VALUE/l3-type-mask', 'L3 Mask'),
                           ('inner_type', 'GRE_TUNNEL_VALUE/inner-type', 'Inner Type', False,
                            udf_ip_version_name_to_value),
                           ('outer_type', 'GRE_TUNNEL_VALUE/outer-type', 'Outer Type', False,
                            udf_ip_version_name_to_value)]
        if raw_obj is None:
            self.cr_mand_attrs += ['type', 'priority']
            self.init_attr(params)

    def delete(self):
        obj_id = self.get_attr_data('id')
        udf_flt = UdfObj()
        ret_objs = udf_flt.get_obj()
        for obj in ret_objs:
            udf_id = obj.get_attr_data('id')
            match_id = obj.get_attr_data('match-id')
            if obj_id == match_id:
                raise ValueError('UDF match is used by UDF with id %d' % udf_id)
        UdfCommonObj.delete(self)


class UdfObj(UdfCommonObj):

    def __init__(self, raw_obj = None, **params):
        UdfCommonObj.__init__(self, 'udf-obj', raw_obj)
        self.obj_title += 'UDF Object'
        self.obj_attrs += [('udf_id', 'id', 'ID', True),
                           ('group_id', 'group-id', 'Group ID', True),
                           ('match_id', 'match-id', 'Match ID', True),
                           ('base_type', 'base', 'Base', True, udf_base_name_to_value),
                           ('offset', 'offset', 'Offset'),
                           ('hash_mask', 'hash-mask', 'HASH Mask')]
        if raw_obj is None:
            self.cr_mand_attrs += ['group-id', 'match-id', 'base']
            self.init_attr(params)

    def create(self):
        grp_id = self.get_attr_data('group-id')
        flt_obj = UdfGroupObj(group_id = grp_id)
        ret_objs = flt_obj.get_obj()
        if len(ret_objs) == 0:
            raise ValueError('UDF group with ID %d not found' % grp_id)
        match_id = self.get_attr_data('match-id')
        flt_obj = UdfMatchObj(match_id = match_id)
        ret_objs = flt_obj.get_obj()
        if len(ret_objs) == 0:
            raise ValueError('UDF match with ID %d not found' % match_id)
        return UdfCommonObj.create(self)

if __name__ == '__main__':

    delete = True
    if len(sys.argv) > 1 and sys.argv[1] == 'no-delete':
        delete = False

    failed = False
    try:
        print '*** Create UDF group ***'
        obj = UdfGroupObj(group_type = 'generic', length = 10)
        obj.create()
        grp_id = obj.get_attr_data('id')
        print obj
        print '*** Create UDF match ***'
        obj = UdfMatchObj(match_type = 'non_tunnel', priority = 1)
        obj.create()
        match_id = obj.get_attr_data('id')
        print obj
        obj = UdfMatchObj(match_type = 'non_tunnel', priority = 2,
                          l2_type = 0x800, l2_type_mask = 0xfff,
                          l3_type = 1, l3_type_mask = 0xf)
        obj.create()
        print obj
        obj = UdfMatchObj(match_type = 'gre_tunnel', priority = 3, inner_type = 'ipv4')
        obj.create()
        print obj
        print '*** Create UDF ***'
        obj = UdfObj(group_id = grp_id, match_id = match_id, base_type = 'L2')
        obj.create()
        print obj
    except StandardError:
        print 'Failed to create UDF objects'
        traceback.print_exc()
        failed = True

    grp_flt_obj = UdfGroupObj()
    grp_list = grp_flt_obj.get_obj()
    match_flt_obj = UdfMatchObj()
    match_list = match_flt_obj.get_obj()
    udf_flt_obj = UdfObj()
    udf_list = udf_flt_obj.get_obj()
    if not failed:
        print '*** List of all UDF objects ***'
        for o in grp_list:
            print o
        for o in match_list:
            print o
        for o in udf_list:
            print o
    if delete:
        print '*** Delete all UDF objects ***'
        for o in udf_list:
            o.delete()
        for o in match_list:
            o.delete()
        for o in grp_list:
            o.delete()
