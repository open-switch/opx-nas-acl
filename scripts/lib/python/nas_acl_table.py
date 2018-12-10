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


class TableCPSObj(nab.AclCPSObj):

    """
    Utility class to build a CPS Object based on the ACL Table Yang model
    with attributes populated from the values passed as inputs.
    The resulting CPS Object representation, obtained by calling data() method,
    can be plugged into a CPS Transaction (by adding create,delete or set op)
    or directly into a CPS Get request.

    eg:
        t = nas_acl.TableCPSObj (stage='INGRESS', priority=prio)
        t.add_allow_filter('SRC_IP')
        t.add_allow_filter('IP_TYPE')
        t.add_allow_action('PACKET_ACTION')

        upd = ('create', t.data())
        ret = cps_utils.CPSTransaction ([upd]).commit ()

    An instance of this class can also act as a wrapper over the CPS object
    dictionary returned by CPS Create or Get on ACL Table Yang model and
    provides methods to extract various attributes from it.

    eg:
    filt_obj = nas_acl.TableCPSObj (table_id=table_id)
    out = []
    if cps.get ([filt_obj.data()], out) == True:
        for t_cps in out:
            t = nas_acl.TableCPSObj (cps_data = t_cps)
            t.print_obj ()
    """

    obj_name = nab.obj_root + '/table'

    def __init__(self, table_id=None, stage=None,
                 priority=None, size=None, switch_id=0, cps_data=None,
                 npu_id_list=[]):
        """
        Initialize the CPS object Python dictionary with the input parameters.
        @table_id, @stage, @priority, @name, @size, @switch_id - form the CPS object with the
                                                                 corresponding attributes
        @cps_data - form the CPS object from CPS data returned from a Create or Set.
        """

        if cps_data is not None:
            self.cps_data = cps_data
            return

        self.cps_data = None
        self.obj_dict = {}

        if priority is not None:
            self.add_attr(self.obj_dict, 'priority', priority)
        if stage is not None:
            self.add_attr(self.obj_dict, 'stage', stage)
        if size is not None:
            self.add_attr(self.obj_dict, 'size', size)
        if table_id is not None:
            if type(table_id) is int:
                self.add_attr(self.obj_dict, 'id', table_id)
            elif type(table_id) is str:
                self.add_attr(self.obj_dict, 'name', table_id)
        if npu_id_list:
            self.add_attr(self.obj_dict, 'npu-id-list', npu_id_list)

        self.cps_obj = self.create_cps_obj(
            module=self.obj_name,
            data=self.obj_dict)

    @classmethod
    def get_attr_map(cls):
        return nas_acl_map.get_table_attr_map()

    def add_allow_filter(self, filter_type):
        """
        Add allowed fields to this Table

        @filter_type - yang enum name of the match field ('SRC_IPV6')
        """
        self.add_attr(self.obj_dict, 'allowed-match-fields', filter_type)

    def add_allow_action(self, action_type):
        """
        Add allowed action to this Table

        @filter_type - yang enum name of the action type ('PACKET_ACTION')
        """
        self.add_attr(self.obj_dict, 'allowed-actions', action_type)

    def add_udf_group(self, group_id):
        """
        Add UDF group to this Table

        @group_id - UDF Group ID
        """
        self.add_attr(self.obj_dict, 'udf-group-list', group_id)

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
