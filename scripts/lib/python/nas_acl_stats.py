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


class StatsCPSObj(nab.AclCPSObj):
    obj_name = nab.obj_root + '/stats'

    attr_map = {
        'switch-id': ('leaf', 'uint32_t'),
        'table-id': ('leaf', 'uint64_t'),
        'counter-id': ('leaf', 'uint64_t'),
        'matched-packets': ('leaf', 'uint64_t'),
        'matched-bytes': ('leaf', 'uint64_t'),
        'npu-id-list': ('leaflist', 'uint32_t'),
        'table-name': ('leaf', 'string'),
        'counter-name': ('leaf', 'string'),
    }

    def __init__(self, table_id=None, counter_id=None,
                 pkt_count=None, byte_count=None, switch_id=0, cps_data=None):
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
                self.add_attr(self.obj_dict, 'counter-id', counter_id)
            elif type(counter_id) is str:
                self.add_attr(self.obj_dict, 'counter-name', counter_id)
        if table_id is not None:
            if type(table_id) is int:
                self.add_attr(self.obj_dict, 'table-id', table_id)
            elif type(table_id) is str:
                self.add_attr(self.obj_dict, 'table-name', table_id)
        if pkt_count is not None:
            self.add_attr(self.obj_dict, 'matched-packets', pkt_count)
        if byte_count is not None:
            self.add_attr(self.obj_dict, 'matched-bytes', byte_count)

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

    def extract(self, name, obj=None):
        if obj:
            cps_data = obj
        else:
            cps_data = self.data()

        return self.extract_attr(cps_data, name)
