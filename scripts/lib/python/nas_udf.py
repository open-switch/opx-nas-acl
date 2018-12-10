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

from nas_udf_object import *

def create_udf_group(group_type, length):
    try:
        grp_obj = UdfGroupObj(group_type = group_type, length = length)
        grp_obj.create()
        grp_id = grp_obj.get_attr_data('id')
    except Exception as err:
        print 'Failed to create UDF group: %s' % err
        return None
    print 'Created UDF Group %d' % grp_id
    return grp_id

def create_udf_non_tunnel_match(priority, l2_type = None, l2_type_mask = None,
                                l3_type = None, l3_type_mask = None):
    try:
        match_obj = UdfMatchObj(match_type = 'NON_TUNNEL', priority = priority,
                                l2_type = l2_type, l2_type_mask = l2_type_mask,
                                l3_type = l3_type, l3_type_mask = l3_type_mask)
        match_obj.create()
        match_id = match_obj.get_attr_data('id')
    except Exception as err:
        print 'Failed to create UDF match: %s' % err
        return None
    print 'Created UDF Match %d' % match_id
    return match_id

def create_udf_gre_tunnel_match(priority, inner_type, outer_type = None):
    try:
        match_obj = UdfMatchObj(match_type = 'GRE_TUNNEL', priority = priority,
                                inner_type = inner_type, outer_type = outer_type)
        match_obj.create()
        match_id = match_obj.get_attr_data('id')
    except Exception as err:
        print 'Failed to create UDF match: %s'  % err
        return None
    print 'Created UDF Match %d' % match_id
    return match_id

def create_udf(group_id, match_id, base, offset = 0):
    try:
        udf_obj = UdfObj(group_id = group_id, match_id = match_id,
                         base_type = base, offset = offset)
        udf_obj.create()
        udf_id = udf_obj.get_attr_data('id')
    except Exception as err:
        print 'Failed to create UDF: %s' % err
        return None
    print 'Created UDF %d' % udf_id
    return udf_id

def print_udf_group(group_id = None):
    try:
        flt_obj = UdfGroupObj(group_id = group_id)
        ret_objs = flt_obj.get_obj()
        for obj in ret_objs:
            print obj
    except Exception as err:
        print err

def print_udf_match(match_id = None):
    try:
        flt_obj = UdfMatchObj(match_id = match_id)
        ret_objs = flt_obj.get_obj()
        for obj in ret_objs:
            print obj
    except Exception as err:
        print err

def print_udf(udf_id = None):
    try:
        flt_obj = UdfObj(udf_id = udf_id)
        ret_objs = flt_obj.get_obj()
        for obj in ret_objs:
            print obj
    except Exception as err:
        print err

def delete_udf_group(group_id):
    try:
        grp_obj = UdfGroupObj(group_id = group_id)
        grp_obj.delete()
    except Exception as err:
        print err

def delete_udf_match(match_id):
    try:
        match_obj = UdfMatchObj(match_id = match_id)
        match_obj.delete()
    except Exception as err:
        print err

def delete_udf(udf_id):
    try:
        udf_obj = UdfObj(udf_id = udf_id)
        udf_obj.delete()
    except Exception as err:
        print err
