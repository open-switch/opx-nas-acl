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

import nas_acl_base as nab
import nas_acl_map


class CounterCPSObj(nab.AclCPSObj):

    """
    Utility class to build a CPS Object based on the ACL Counter Yang model
    with attributes populated from the values passed as inputs.
    The resulting CPS Object representation, obtained by calling data() method,
    can be plugged into a CPS Transaction (by adding create,delete or set op)
    or directly into a CPS Get request.

    eg:
        c = nas_acl.CounterCPSObj (table_id=9, types=['PACKET','BYTE'])

        upd = ('create', c.data())
        ret = cps_utils.CPSTransaction ([upd]).commit ()

    An instance of this class can also act as a wrapper over the CPS object
    dictionary returned by CPS Create or Get on ACL Table Yang model and
    provides methods to extract various attributes from it.

    eg:
    filt_obj = nas_acl.CounterCPSObj (table_id=table_id, counter_id=id)
    out = []
    if cps.get ([filt_obj.data()], out) == True:
        for c_cps in out:
            c = nas_acl.CounterCPSObj (cps_data = c_cps)
            c.print_obj ()
    """

    obj_name = nab.obj_root + '/counter'

    attr_map = {
        'switch-id': ('leaf', 'uint32_t'),
        'table-id': ('leaf', 'uint64_t'),
        'id': ('leaf', 'uint64_t'),
        'types':
        ('leaflist', 'enum', 'base-acl:counter-type:'),
        'npu-id-list': ('leaflist', 'uint32_t'),
        'name': ('leaf', 'string'),
        'table-name': ('leaf', 'string'),
    }

    def __init__(
        self, table_id=None, counter_id=None, types=[], switch_id=0, cps_data=None,
            npu_id_list=[]):
        """
        Initialize the CPS object Python dictionary with the input parameters.
        @table_id, @counter_id, @types, @switch_id - form the CPS object with the
                                                   corresponding attributes
        @cps_data - form the CPS object from CPS data returned from a Create or Set.
        """

        if cps_data is not None:
            self.cps_data = cps_data
            return

        self.cps_data = None
        self.obj_dict = {}

        if counter_id is not None:
            if type(counter_id) is int:
                self.add_attr(self.obj_dict, 'id', counter_id)
            elif type(counter_id) is str:
                self.add_attr(self.obj_dict, 'name', counter_id)
        if table_id is not None:
            if type(table_id) is int:
                self.add_attr(self.obj_dict, 'table-id', table_id)
            elif type(table_id) is str:
                self.add_attr(self.obj_dict, 'table-name', table_id)
        if npu_id_list:
            self.add_attr(self.obj_dict, 'npu-id-list', npu_id_list)
        for t in types:
            self.add_attr(self.obj_dict, 'types', t)

        self.cps_obj = self.create_cps_obj(
            module=self.obj_name,
            data=self.obj_dict)

    @classmethod
    def get_attr_map(cls):
        return cls.attr_map

    def data(self):
        """
        Get the CPS object created for the ACL Table.
        This CPS object can then be plugged into a CPS Transaction or CPS Get request.
        """
        if self.cps_data is not None:
            return self.cps_data
        return self.cps_obj

    def extract_id(self):
        """
        Get Counter ID from the CPS data returned by Create or Get

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
