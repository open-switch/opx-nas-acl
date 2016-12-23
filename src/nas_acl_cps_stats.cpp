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

/*!
 * \file   nas_acl_cps_stats.cpp
 * \brief  This file contains CPS related ACL Counter stats functionality
 * \date   03-2015
 */
#include "event_log.h"
#include "std_error_codes.h"
#include "cps_api_operation.h"
#include "nas_acl_log.h"
#include "nas_acl_switch_list.h"
#include "nas_acl_cps.h"
#include "nas_base_utils.h"
#include "cps_api_object_key.h"
#include "cps_class_map.h"
#include "nas_acl_cps_key.h"

static t_std_error nas_acl_stats_set (cps_api_object_t obj,
                                      cps_api_object_t prev,
                                      bool             rollback) noexcept;

static nas_acl_write_operation_map_t nas_acl_stats_op_map [] = {
    {cps_api_oper_SET, nas_acl_stats_set},
};

nas_acl_write_operation_map_t *
nas_acl_get_stats_op_map (cps_api_operation_types_t op) noexcept
{
    return (op == cps_api_oper_SET) ? &nas_acl_stats_op_map[0]: NULL;
}

enum class nas_acl_stats_op_type {
    GET,
    SET,
};

static bool nas_acl_stats_cps_key_init (cps_api_object_t obj,
                                        const nas_acl_counter_t& counter) noexcept
{
    if (!cps_api_key_from_attr_with_qual (cps_api_object_key (obj),
                                          BASE_ACL_STATS_OBJ,
                                          cps_api_qualifier_TARGET)) {
        NAS_ACL_LOG_ERR ("Failed to create Key from Stats Object");
        return false;
    }

    if (!nas_acl_cps_key_set_obj_id (obj, BASE_ACL_STATS_TABLE_ID, counter.table_id())) {
        NAS_ACL_LOG_ERR ("Failed to set Table ID in Key");
        return false;
    }
    if (!nas_acl_cps_key_set_obj_id (obj, BASE_ACL_STATS_COUNTER_ID, counter.counter_id())) {
        NAS_ACL_LOG_ERR ("Failed to set Counter ID in Key");
        return false;
    }

    return true;
}

// In addition to extracting attributes from the Counter Stats object
// this utility function performs the following validation
//   a) If called for a SET operation then either the Pkt count or
//      the Byte count attribute MUST be present.
static bool _extract_stats_attrs (cps_api_object_t obj,
                                 nas_acl_stats_op_type op_type,
                                 nas::npu_set_t *npu_list_p,
                                 bool* is_pkt_count_set_p,
                                 bool* is_byte_count_set_p,
                                 uint64_t  *pkt_count_p = NULL,
                                 uint64_t  *byte_count_p = NULL) noexcept
{
    cps_api_object_it_t  it;
    bool pkt_count_set = false, byte_count_set=false;

    for (cps_api_object_it_begin (obj, &it);
         cps_api_object_it_valid (&it); cps_api_object_it_next (&it)) {

        switch (cps_api_object_attr_id (it.attr)) {

            case BASE_ACL_STATS_NPU_ID_LIST:
                npu_list_p->add (cps_api_object_attr_data_u32 (it.attr));
                break;

            case BASE_ACL_STATS_MATCHED_PACKETS:
                if (pkt_count_p) *pkt_count_p = cps_api_object_attr_data_u64 (it.attr);
                pkt_count_set = true;
                break;

            case BASE_ACL_STATS_MATCHED_BYTES:
                if (byte_count_p) *byte_count_p = cps_api_object_attr_data_u64 (it.attr);
                byte_count_set = true;
                break;
        }
    }

    if (op_type == nas_acl_stats_op_type::SET) {
        if (!pkt_count_set && !byte_count_set) return false;
    }
    if (is_byte_count_set_p) *is_byte_count_set_p = byte_count_set;
    if (is_pkt_count_set_p) *is_pkt_count_set_p = pkt_count_set;

    return true;
}

t_std_error nas_acl_stats_info_get (cps_api_get_params_t *param,
                                    size_t                index,
                                    const nas_acl_counter_t&  counter) noexcept
{
    cps_api_object_t obj;
    nas::npu_set_t  filtr_npu_list;
    bool            filtr_pkt_count = false;
    bool            filtr_byte_count = false;
    uint64_t        total_pkt_count = 0;
    uint64_t        total_byte_count = 0;

    NAS_ACL_LOG_BRIEF ("Switch Id: %d, Table Id: %ld, Counter Id: %ld, GET Stats",
                       counter.switch_id(), counter.get_table().table_id(),
                       counter.counter_id());

    auto filtr_obj = cps_api_object_list_get (param->filters, index);

    if (filtr_obj != NULL) {
        _extract_stats_attrs (filtr_obj, nas_acl_stats_op_type::GET,
                              &filtr_npu_list, &filtr_pkt_count, &filtr_byte_count);
    }

    bool filtr_count_mode = (filtr_pkt_count || filtr_byte_count);

    obj = cps_api_object_create ();

    if (obj == NULL) {
        return NAS_ACL_E_MEM;
    }

    cps_api_object_guard obj_guard (obj);

    const nas::npu_set_t& loop_npu = (filtr_npu_list.empty()) ? counter.npu_list():
                                                                filtr_npu_list;

    uint64_t  count;
    for (auto npu_id: loop_npu) {

        if ((!filtr_count_mode || filtr_pkt_count) &&
            (counter.get_pkt_count_ndi(npu_id,  &count) == NAS_ACL_E_NONE)) {
            total_pkt_count += count;
        }
        if ((!filtr_count_mode || filtr_byte_count) &&
            (counter.get_byte_count_ndi(npu_id,  &count) == NAS_ACL_E_NONE)) {
            total_byte_count += count;
        }
        if (!cps_api_object_attr_add_u32 (obj,
                                          BASE_ACL_STATS_NPU_ID_LIST, npu_id)) {
            NAS_ACL_LOG_ERR ("Attr add failed. Index: %ld", index);
            return NAS_ACL_E_MEM;
        }
    }

    if ((!filtr_count_mode || filtr_pkt_count) &&
        !cps_api_object_attr_add_u64 (obj,
                                      BASE_ACL_STATS_MATCHED_PACKETS,
                                      total_pkt_count)) {
        NAS_ACL_LOG_ERR ("Attr add failed. Index: %ld", index);
        return NAS_ACL_E_MEM;
    }

    if ((!filtr_count_mode || filtr_byte_count) &&
        !cps_api_object_attr_add_u64 (obj,
                                      BASE_ACL_STATS_MATCHED_BYTES,
                                      total_byte_count)) {
        NAS_ACL_LOG_ERR ("Attr add failed. Index: %ld", index);
        return NAS_ACL_E_MEM;
    }

    if (!nas_acl_stats_cps_key_init (obj, counter)) return NAS_ACL_E_MEM;

    if (!cps_api_object_list_append (param->list, obj)) {
        NAS_ACL_LOG_ERR ("Obj Append failed. Index: %ld", index);

        return NAS_ACL_E_MEM;
    }

    obj_guard.release ();
    return NAS_ACL_E_NONE;
}

static t_std_error nas_acl_stats_set (cps_api_object_t obj,
                                     cps_api_object_t prev,
                                     bool             rollback) noexcept
{
    nas_switch_id_t        switch_id;
    nas_obj_id_t           table_id;
    nas_obj_id_t           counter_id;
    nas::npu_set_t         filt_npu_list;
    uint64_t               pkt_count = 0, byte_count = 0;
    bool                   is_pkt_count_set = false;
    bool                   is_byte_count_set = false;

    if (!nas_acl_cps_key_get_switch_id (obj, NAS_ACL_SWITCH_ATTR,
                                        &switch_id)) {
        NAS_ACL_LOG_ERR ("Switch ID is a mandatory key for Counter Stats Modify ");
        return NAS_ACL_E_MISSING_KEY;
    }
    if (!nas_acl_cps_key_get_obj_id (obj, BASE_ACL_STATS_TABLE_ID,
                                     &table_id)) {
        NAS_ACL_LOG_ERR ("Table ID is a mandatory key for Counter Stats Modify ");
        return NAS_ACL_E_MISSING_KEY;
    }
    if (!nas_acl_cps_key_get_obj_id (obj, BASE_ACL_STATS_COUNTER_ID, &counter_id)) {
        NAS_ACL_LOG_ERR ("Counter ID is a mandatory key for Counter Stats Modify");
        return NAS_ACL_E_MISSING_KEY;
    }

    NAS_ACL_LOG_BRIEF ("Switch Id: %d, Table Id: %ld, Counter Id: %ld, SET Stats",
                       switch_id, table_id, counter_id);

    if (!_extract_stats_attrs (obj, nas_acl_stats_op_type::SET,
                              &filt_npu_list, &is_pkt_count_set,
                              &is_byte_count_set, &pkt_count, &byte_count)) {
        return NAS_ACL_E_MISSING_ATTR;
    }

    try {
        auto& counter = nas_acl_get_switch(switch_id).get_counter(table_id, counter_id);

        const nas::npu_set_t& loop_npu = (filt_npu_list.empty()) ? counter.npu_list(): filt_npu_list;

        for (auto npu_id: loop_npu) {

            if (is_pkt_count_set) {
                counter.set_pkt_count_ndi(npu_id,  pkt_count);
            }
            if (is_byte_count_set) {
                counter.set_byte_count_ndi(npu_id, byte_count);
            }
        }

    } catch (nas::base_exception& e) {

        NAS_ACL_LOG_ERR ("Err_code: 0x%x, fn: %s (), %s", e.err_code,
                         e.err_fn.c_str (), e.err_msg.c_str ());
        return e.err_code;
    }

    // No rollback for Stats - hence no need to fill prev obj

    NAS_ACL_LOG_BRIEF ("Successful ");
    return NAS_ACL_E_NONE;
}

