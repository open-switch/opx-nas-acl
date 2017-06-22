/*
 * Copyright (c) 2016 Dell Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may
 * not use this file except in compliance with the License. You may obtain
 * a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
 *
 * THIS CODE IS PROVIDED ON AN *AS IS* BASIS, WITHOUT WARRANTIES OR
 * CONDITIONS OF ANY KIND, EITHER EXPRESS OR IMPLIED, INCLUDING WITHOUT
 * LIMITATION ANY IMPLIED WARRANTIES OR CONDITIONS OF TITLE, FITNESS
 * FOR A PARTICULAR PURPOSE, MERCHANTABLITY OR NON-INFRINGEMENT.
 *
 * See the Apache Version 2.0 License for specific language governing
 * permissions and limitations under the License.
 */


#include "ds_common_types.h"
#include "hal_if_mapping.h"
#include "nas_ndi_acl.h"
#include "nas_ndi_udf.h"
#include "std_error_codes.h"
#include "nas_acl_cps_ut.h"
#include "nas_acl_db_ut.h"
#include <stdio.h>
#include <netinet/in.h>
#include <string>

int& ut_simulate_ndi_entry_create_error ()
{
    static int _ut_simulate_ndi_entry_create_error = UT_RESET_NPU;
    return _ut_simulate_ndi_entry_create_error;
}
int& ut_simulate_ndi_entry_delete_error ()
{
    static int _ut_simulate_ndi_entry_delete_error = UT_RESET_NPU;
    return _ut_simulate_ndi_entry_delete_error;
}
int& ut_simulate_ndi_entry_priority_error ()
{
    static int _ut_simulate_ndi_entry_priority_error= UT_RESET_NPU;
    return _ut_simulate_ndi_entry_priority_error;
}
int& ut_simulate_ndi_entry_filter_error_npu ()
{
    static int _ut_simulate_ndi_entry_filter_error_npu = UT_RESET_NPU;
    return _ut_simulate_ndi_entry_filter_error_npu;
}
int& ut_simulate_ndi_entry_filter_error_ftype ()
{
    static int _ut_simulate_ndi_entry_filter_error_ftype = UT_RESET_FTYPE;
    return _ut_simulate_ndi_entry_filter_error_ftype;
}
int& ut_simulate_ndi_entry_action_error_npu ()
{
    static int _ut_simulate_ndi_entry_action_error_npu = UT_RESET_NPU;
    return _ut_simulate_ndi_entry_action_error_npu;
}
int& ut_simulate_ndi_entry_action_error_atype ()
{
    static int _ut_simulate_ndi_entry_action_error_atype = UT_RESET_ATYPE;
    return _ut_simulate_ndi_entry_action_error_atype;
}

t_std_error ndi_acl_table_create (npu_id_t npu, const ndi_acl_table_t* t,
                                  ndi_obj_id_t* id)
{
    static int count = 0;
    count ++;
    ut_printf ("%s: npu %d, filter count %ld table prio %d returned id %d\n", __FUNCTION__,
           npu, t->filter_count, t->priority, count);
    *id = count;
    return STD_ERR_OK;
}
t_std_error ndi_acl_table_delete (npu_id_t npu, ndi_obj_id_t id)
{
    ut_printf ("%s: npu %d, table id %ld\n", __FUNCTION__, npu, id);
    return STD_ERR_OK;
}
t_std_error ndi_acl_table_set_priority (npu_id_t npu,
                                        ndi_obj_id_t id,
                                        uint_t prio)
{
    ut_printf ("%s: npu %d, table id %ld prio %d\n", __FUNCTION__, npu, id, prio);
    if (npu == 4 && id == 12) {
        ut_printf (" >>> Simulate NDI Error\n");
        return 1;
    }
    return STD_ERR_OK;
}

t_std_error ndi_acl_entry_create (npu_id_t npu, const ndi_acl_entry_t* e,
                                  ndi_obj_id_t* id)
{
    static int count = 0;
    count ++;
    if (ut_simulate_ndi_entry_create_error() == npu) {
        ut_printf (" >>> Simulate Entry Create NDI failure for NPU %d\r\n", npu);
        ut_simulate_ndi_entry_create_error() = UT_RESET_NPU;
        return STD_ERR (NPU, FAIL, 0);
    }
    ut_printf ("%s: npu %d, filter count %ld entry prio %d return id %d\n", __FUNCTION__,
            npu, e->filter_count, e->priority, count);
    *id = count;
    return STD_ERR_OK;
}

t_std_error ndi_acl_entry_delete (npu_id_t npu, ndi_obj_id_t id)
{
    if (ut_simulate_ndi_entry_delete_error() == npu) {
        ut_printf (" >>> Simulate Entry Delete NDI failure for NPU %d\r\n", npu);
        ut_simulate_ndi_entry_delete_error() = UT_RESET_NPU;
        return STD_ERR (NPU, FAIL, 0);
    }
    ut_printf ("%s: npu %d, entry id %ld\n", __FUNCTION__, npu, id);
    return STD_ERR_OK;
}
t_std_error ndi_acl_entry_set_priority (npu_id_t npu,
                                        ndi_obj_id_t id,
                                        uint_t prio)
{
    if (ut_simulate_ndi_entry_priority_error() == npu) {
        ut_printf (" >>> Simulate Entry Priority set NDI failure for NPU %d\r\n", npu);
        ut_simulate_ndi_entry_priority_error() = UT_RESET_NPU;
        return STD_ERR (NPU, FAIL, 0);
    }
    ut_printf ("%s: npu %d, entry id %ld prio %d\n", __FUNCTION__, npu, id, prio);
    return STD_ERR_OK;
}

t_std_error ndi_acl_entry_set_filter (npu_id_t npu,
                                      ndi_obj_id_t id,
                                      ndi_acl_entry_filter_t *filter_p)
{
    if (ut_simulate_ndi_entry_filter_error_npu() == npu &&
        ut_simulate_ndi_entry_filter_error_ftype() == filter_p->filter_type)
    {
        ut_printf (" >>> Simulate Entry Filter set NDI failure for NPU %d Filter %s\r\n",
                npu, nas_acl_filter_type_name (filter_p->filter_type));
        ut_simulate_ndi_entry_filter_error_npu() = UT_RESET_NPU;
        ut_simulate_ndi_entry_filter_error_ftype() = 0;
        return STD_ERR (NPU, FAIL, 0);
    }
    ut_printf ("%s: npu %d, entry id %ld filter %s\n", __FUNCTION__, npu, id,
               nas_acl_filter_type_name (filter_p->filter_type));

    if (npu == 3 && id == 18 && filter_p->filter_type==7) {
        ut_printf (" >>> Simulate NDI Error\n");
        return 1;
    }
    return STD_ERR_OK;
}

t_std_error ndi_acl_entry_disable_filter (npu_id_t npu,
                                          ndi_obj_id_t id,
                                          BASE_ACL_MATCH_TYPE_t filter_id)
{
    if (ut_simulate_ndi_entry_filter_error_npu() == npu &&
        ut_simulate_ndi_entry_filter_error_ftype() == filter_id)
    {
        ut_printf (" >>> Simulate Entry Filter disable NDI failure for NPU %d Filter %s\r\n",
                   npu, nas_acl_filter_type_name (filter_id));
        ut_simulate_ndi_entry_filter_error_npu() = UT_RESET_NPU;
        ut_simulate_ndi_entry_filter_error_ftype() = 0;
        return STD_ERR (NPU, FAIL, 0);
    }
    ut_printf ("%s: npu %d, entry id %ld filter %s\n", __FUNCTION__, npu, id,
               nas_acl_filter_type_name (filter_id));
    return STD_ERR_OK;
}


t_std_error ndi_acl_entry_set_action (npu_id_t npu_id,
                                      ndi_obj_id_t ndi_entry_id,
                                      ndi_acl_entry_action_t *action_p)
{
    if (ut_simulate_ndi_entry_action_error_npu() == npu_id &&
        ut_simulate_ndi_entry_action_error_atype() == action_p->action_type)
    {
        ut_printf (" >>> Simulate Entry Action enable NDI failure for NPU %d Action %s\r\n",
                npu_id, nas_acl_action_type_name (action_p->action_type));
        ut_simulate_ndi_entry_action_error_npu() = UT_RESET_NPU;
        ut_simulate_ndi_entry_action_error_atype() = 0;
        return STD_ERR (NPU, FAIL, 0);
    }
    ut_printf ("%s: npu %d, entry id %ld action %s\n", __FUNCTION__, npu_id, ndi_entry_id,
               nas_acl_action_type_name (action_p->action_type));
    return STD_ERR_OK;
}

t_std_error ndi_acl_counter_enable_pkt_count (npu_id_t npu_id,
                                              ndi_obj_id_t ndi_counter_id,
                                              bool enable)
{
    ut_printf ("%s: npu %d, counter id %ld enable %d\n", __FUNCTION__, npu_id, ndi_counter_id,
            enable);
    return STD_ERR_OK;
}

t_std_error ndi_acl_counter_enable_byte_count (npu_id_t npu_id,
                                               ndi_obj_id_t ndi_counter_id,
                                               bool enable)
{
    ut_printf ("%s: npu %d, counter id %ld enable %d\n", __FUNCTION__, npu_id, ndi_counter_id,
            enable);
    return STD_ERR_OK;
}

t_std_error ndi_acl_entry_disable_action (npu_id_t npu_id,
                                          ndi_obj_id_t ndi_entry_id,
                                          BASE_ACL_ACTION_TYPE_t action_id)
{
    ut_printf ("%s: npu %d, entry id %ld action %s\n", __FUNCTION__, npu_id, ndi_entry_id,
               nas_acl_action_type_name (action_id));
    return STD_ERR_OK;
}

t_std_error ndi_acl_counter_create (npu_id_t npu_id,
                                    const ndi_acl_counter_t* ndi_counter_p,
                                    ndi_obj_id_t* ndi_counter_id_p)
{
    static size_t counter_count = 0;
    *ndi_counter_id_p = ++counter_count;
    ut_printf ("%s: npu %d, pkt count %d byte count %d id %ld\n", __FUNCTION__,
            npu_id, ndi_counter_p->enable_pkt_count,
                    ndi_counter_p->enable_byte_count,
                    counter_count);
    return STD_ERR_OK;
}
t_std_error ndi_acl_counter_delete (npu_id_t npu_id,
                                    ndi_obj_id_t ndi_counter_id)
{
    ut_printf ("%s: npu %d, id %ld\n", __FUNCTION__,
            npu_id, ndi_counter_id);
    return STD_ERR_OK;
}

t_std_error ndi_acl_counter_get_pkt_count (npu_id_t npu_id,
                                           ndi_obj_id_t ndi_counter_id,
                                           uint64_t* pkt_count_p)
{
    static uint64_t count = 0;
    ut_printf ("%s: npu %d, id %ld\n", __FUNCTION__, npu_id, ndi_counter_id);
    count += 2000;
    *pkt_count_p = count;
    return STD_ERR_OK;
}
t_std_error ndi_acl_counter_get_byte_count (npu_id_t npu_id,
                                            ndi_obj_id_t ndi_counter_id,
                                            uint64_t* byte_count_p)
{
    static uint64_t count = 0;
    ut_printf ("%s: npu %d, id %ld\n", __FUNCTION__, npu_id, ndi_counter_id);
    count += 2000;
    *byte_count_p = count;
    return STD_ERR_OK;
}

t_std_error ndi_acl_counter_set_pkt_count (npu_id_t npu_id,
                                           ndi_obj_id_t ndi_counter_id,
                                           uint64_t pkt_count)
{
    ut_printf ("%s: npu %d, id %ld val %ld\n", __FUNCTION__, npu_id,
            ndi_counter_id, pkt_count);
    return STD_ERR_OK;
}
t_std_error ndi_acl_counter_set_byte_count (npu_id_t npu_id,
                                            ndi_obj_id_t ndi_counter_id,
                                            uint64_t byte_count)
{
    ut_printf ("%s: npu %d, id %ld val %ld\n", __FUNCTION__, npu_id,
            ndi_counter_id, byte_count);
    return STD_ERR_OK;
}

void intf_init (npu_id_t num_npus, npu_port_t num_ports)
{
    for (npu_id_t npu = 0; npu < num_npus; npu ++) {
        for (npu_port_t port = 1; port <= num_ports; port ++) {
            interface_ctrl_t detail {};
            detail.npu_id = npu;    //! the npu id
            detail.port_id = port;    //! the port id
            detail.if_index = (npu*8)+port;    //!if index under the VRF
            std::string name = std::string {"If "} + std::to_string (detail.if_index);
            memcpy (detail.if_name, name.c_str(), HAL_IF_NAME_SZ);
            dn_hal_if_register(HAL_INTF_OP_REG, &detail);
        }
    }
    dn_hal_dump_interface_mapping ();
}

t_std_error ndi_udf_group_create(npu_id_t npu_id, const ndi_udf_grp_t *udf_grp_p,
                                 ndi_obj_id_t *udf_grp_id_p)
{
    return STD_ERR_OK;
}

t_std_error ndi_udf_group_delete(npu_id_t npu_id, ndi_obj_id_t udf_grp_id)
{
    return STD_ERR_OK;
}

t_std_error ndi_udf_match_create(npu_id_t npu_id, const ndi_udf_match_t *udf_match_p,
                                 ndi_obj_id_t *udf_match_id_p)
{
    return STD_ERR_OK;
}

t_std_error ndi_udf_match_delete(npu_id_t npu_id, ndi_obj_id_t udf_match_id)
{
    return STD_ERR_OK;
}

t_std_error ndi_udf_create(npu_id_t npu_id, const ndi_udf_t *udf_p,
                           ndi_obj_id_t *udf_id_p)
{
    return STD_ERR_OK;
}

t_std_error ndi_udf_delete(npu_id_t npu_id, ndi_obj_id_t udf_id)
{
    return STD_ERR_OK;
}

t_std_error ndi_udf_set_hash_mask(npu_id_t npu_id, ndi_obj_id_t udf_id,
                                  uint8_t *hash_mask_list, size_t hash_mask_count)
{
    return STD_ERR_OK;
}
