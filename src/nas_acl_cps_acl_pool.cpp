/*
 * Copyright (c) 2018 Dell Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may
 * not use this file except in compliance with the License. You may obtain
 * a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
 *
 * THIS CODE IS PROVIDED ON AN  *AS IS* BASIS, WITHOUT WARRANTIES OR
 * CONDITIONS OF ANY KIND, EITHER EXPRESS OR IMPLIED, INCLUDING WITHOUT
 * LIMITATION ANY IMPLIED WARRANTIES OR CONDITIONS OF TITLE, FITNESS
 * FOR A PARTICULAR PURPOSE, MERCHANTABLITY OR NON-INFRINGEMENT.
 *
 * See the Apache Version 2.0 License for specific language governing
 * permissions and limitations under the License.
 */

/*!
 * \file   nas_acl_cps_acl_pool.cpp
 * \brief  This file contains CPS functions related to ACL profile functionality
 * \date   08-2018
 */

#include "nas_base_utils.h"
#include "nas_types.h"
#include "nas_switch.h"
#include "nas_acl_switch.h"
#include "nas_acl_switch_list.h"
#include "hal_if_mapping.h"
#include "event_log.h"
#include "std_error_codes.h"
#include "cps_api_object_key.h"
#include "cps_class_map.h"
#include "nas_acl_cps.h"
#include "nas_acl_cps_key.h"
#include "nas_ndi_switch.h"
#include "nas_ndi_acl.h"
#include <string>
#include <inttypes.h>

//This is used to indicate if the acl pool cache is populated or not.
static bool nas_acl_pool_cache_init_done = false;

static t_std_error
nas_acl_populate_acl_pool_cache (const nas_acl_switch& acl_switch)
{
    size_t                  list_sz = 16;
    t_std_error             ret;
    nas_ndi_switch_param_t  param;
    std::vector<ndi_obj_id_t> ndi_obj_list(list_sz);

    if (nas_acl_pool_cache_init_done == false) {
        const nas_switches_t   *switches = nas_switch_inventory();

        for (size_t ix = 0; ix < switches->number_of_switches; ++ix) {

            nas_acl_switch& s = nas_acl_get_switch (ix);

            const nas_switch_detail_t * sd = nas_switch((nas_switch_id_t) ix);
            if (sd == NULL) {
                NAS_ACL_LOG_ERR("Switch(%d) Details Configuraiton file is erroneous", ix);
                return STD_ERR(ACL, FAIL, 0);
            }

            for (size_t sd_ix = 0; sd_ix < sd->number_of_npus; ++sd_ix) {

                memset (&param, 0, sizeof (param));

                /* start with an arbitrary number for list size and resize it as required */
                param.obj_list.len = list_sz;
                param.obj_list.vals = &(ndi_obj_list[0]);

                ret = ndi_switch_get_slice_list((npu_id_t) sd_ix, &param);

                if (ret != STD_ERR_OK) {
                    NAS_ACL_LOG_ERR("Switch ACL pool list get failed for npu:%d", (int) sd_ix);
                    return STD_ERR(ACL, FAIL, 0);
                }

                // if returned list length is more than the passed list length,
                // then retrieve the list by resizing for required length.
                if (param.obj_list.len > list_sz) {

                    ndi_obj_list.resize(param.obj_list.len);
                    param.obj_list.vals = &(ndi_obj_list[0]);

                    ret = ndi_switch_get_slice_list((npu_id_t) sd_ix, &param);

                    if (ret != STD_ERR_OK) {
                        NAS_ACL_LOG_ERR("Switch ACL pool list get with resized list failed for npu:%d", (int) sd_ix);
                        return STD_ERR(ACL, FAIL, 0);
                    }
                }

                if (param.obj_list.len != 0) {

                    for (size_t pool_ix = 0; pool_ix < param.obj_list.len; pool_ix++) {
                        bool acl_pool_saved = s.save_acl_pool(sd_ix, param.obj_list.vals[pool_ix]);

                        if (!acl_pool_saved)
                            NAS_ACL_LOG_ERR("Switch ACL pool save to cache failed "
                                            "npu:%d pool_id:0x%lx",
                                            sd_ix, param.obj_list.vals[pool_ix]);
                    }
                } else {
                    NAS_ACL_LOG_BRIEF ("Switch ACL pool list get returned no entries "
                                       "for npu:%d", (int) sd_ix);
                }
            }
        }

        nas_acl_pool_cache_init_done = true;
    }

    return STD_ERR_OK;
}

// get ACL table NDI object id from NAS object id
static t_std_error
nas_acl_table_get_ndi_obj_id_from_nas_obj_id (npu_id_t npu_id,
                                              nas_obj_id_t nas_acl_tbl_id,
                                              ndi_obj_id_t *p_ndi_acl_tbl_id,
                                              nas_acl_switch& s)
{
    t_std_error  rc = STD_ERR(ACL,FAIL,0);

    try {
        nas_acl_table &tbl = s.get_table(nas_acl_tbl_id);

        ndi_obj_id_t ndi_obj_id = tbl.get_ndi_obj_id(npu_id);

        *p_ndi_acl_tbl_id = ndi_obj_id;

        rc = STD_ERR_OK;
    } catch (std::exception& ex) {
        NAS_ACL_LOG_ERR("ACL table NDI object id get failed for NAS object id:0x%lx", nas_acl_tbl_id);
    } catch (...) {
        throw nas::base_exception {NAS_ACL_E_FAIL, __PRETTY_FUNCTION__,
                       std::string {"Cannot find NDI ID for ACL table in NPU "}
                       + std::to_string (npu_id)};
    }

    return rc;
}

// get ACL table NAS object id from NDI object id
static t_std_error
nas_acl_table_get_nas_obj_id_from_ndi_obj_id (npu_id_t npu_id,
                                              ndi_obj_id_t ndi_acl_tbl_id,
                                              nas_obj_id_t *p_acl_tbl_id,
                                              nas_acl_switch& s)
{
    t_std_error  rc = STD_ERR(ACL, FAIL, 0);

    for (const auto& tbl_kvp: s.table_list ()) {
        if (tbl_kvp.second.get_ndi_obj_id(npu_id) == ndi_acl_tbl_id) {
            *p_acl_tbl_id = tbl_kvp.second.table_id();
            rc = STD_ERR_OK;
            break;
        }
    }

    return rc;
}


static bool
nas_fill_acl_pool_attr(cps_api_object_t cps_obj, npu_id_t npu_id,
                       nas_obj_id_t acl_pool_id, nas_acl_switch& s)
{
    size_t                 list_sz = 16;
    t_std_error            ret;
    nas_obj_id_t           acl_table_id;
    ndi_acl_slice_attr_t   slice_attr;
    std::vector<ndi_obj_id_t> acl_table_list(list_sz);

    memset (&slice_attr, 0, sizeof (slice_attr));

    slice_attr.acl_table_count = list_sz;
    slice_attr.acl_table_list = &(acl_table_list[0]);

    ret = ndi_acl_get_slice_attribute (npu_id, (ndi_obj_id_t) acl_pool_id, &slice_attr);
    if (ret != STD_ERR_OK) {
        NAS_ACL_LOG_ERR("ACL Pool attribute get failed in NDI for ID:0x%x", acl_pool_id);
        return false;
    }
    if (slice_attr.acl_table_count > list_sz) {

        // if returned list length is more than the passed list length,
        // then retrieve the list by resizing for required length.
        acl_table_list.resize(slice_attr.acl_table_count);
        slice_attr.acl_table_list = &(acl_table_list[0]);

        ret = ndi_acl_get_slice_attribute (npu_id, (ndi_obj_id_t) acl_pool_id, &slice_attr);
        if (ret != STD_ERR_OK) {
            NAS_ACL_LOG_ERR("ACL Pool attribute get with resized list (sz:%d) failed in NDI for ID:0x%x",
                            slice_attr.acl_table_count, acl_pool_id);
            return false;
        }
    }
    if (!cps_api_object_attr_add_u32(cps_obj, BASE_ACL_ACL_POOL_INFO_INDEX,
                                     slice_attr.slice_index)) {
        NAS_ACL_LOG_ERR("ACL Pool attribute get failed to add pool-index to object");
        return false;
    }

    if (!cps_api_object_attr_add_u32(cps_obj, BASE_ACL_ACL_POOL_INFO_PIPELINE_ID,
                                     slice_attr.pipeline_index)) {
        NAS_ACL_LOG_ERR("ACL Pool attribute get failed to add pipeline-id to object");
        return false;
    }

    if (!cps_api_object_attr_add_u32(cps_obj, BASE_ACL_ACL_POOL_INFO_STAGE,
                                     slice_attr.stage)) {
        NAS_ACL_LOG_ERR("ACL Pool attribute get failed to add stage to object");
        return false;
    }

    if (!cps_api_object_attr_add_u32(cps_obj, BASE_ACL_ACL_POOL_INFO_USED_COUNT,
                                     slice_attr.used_count)) {
        NAS_ACL_LOG_ERR("ACL Pool attribute get failed to add used count to object");
        return false;
    }

    if (!cps_api_object_attr_add_u32(cps_obj, BASE_ACL_ACL_POOL_INFO_AVAIL_COUNT,
                                     slice_attr.avail_count)) {
        NAS_ACL_LOG_ERR("ACL Pool attribute get failed to add avail count to object");
        return false;
    }

    if (!cps_api_object_attr_add_u32(cps_obj, BASE_ACL_ACL_POOL_INFO_DEPTH,
                                     (slice_attr.used_count + slice_attr.avail_count))) {
        NAS_ACL_LOG_ERR("ACL Pool attribute get failed to add depth to object");
        return false;
    }

    for (size_t ix = 0; ix < slice_attr.acl_table_count; ix++) {

        ret = nas_acl_table_get_nas_obj_id_from_ndi_obj_id (npu_id,
                    slice_attr.acl_table_list[ix], &acl_table_id, s);

        if (ret != STD_ERR_OK)
        {
            NAS_ACL_LOG_ERR("ACL Pool attribute get failed in NPU:%d in retrieval of "
                            "NAS object id from NPU object id, NDI object id:0x%lx",
                            npu_id, slice_attr.acl_table_list[ix]);
            return false;
        }
        if (!cps_api_object_attr_add_u64(cps_obj, BASE_ACL_ACL_POOL_INFO_ACL_TABLE,
                    acl_table_id)) {
            NAS_ACL_LOG_ERR("ACL Pool attribute get failed to add ACL table id(0x%x) to object",
                            acl_table_id);
            return false;
        }
    }

    return true;
}

static t_std_error
nas_get_acl_pool_info(cps_api_object_list_t& cps_obj_list,
                      npu_id_t npu_id, nas_obj_id_t acl_pool_id,
                      nas_acl_switch& s)
{
    cps_api_object_t cps_obj =
        cps_api_object_list_create_obj_and_append(cps_obj_list);

    if (cps_obj == nullptr) {
        NAS_ACL_LOG_ERR("Obj append failed");
        return STD_ERR(ACL, FAIL, 0);
    }

    if (!cps_api_key_from_attr_with_qual(cps_api_object_key(cps_obj),
                                         BASE_ACL_ACL_POOL_INFO_OBJ,
                                         cps_api_qualifier_OBSERVED)) {
        NAS_ACL_LOG_ERR("ACL Pool attribute get failed to create key from ACL Pool object");
        return STD_ERR(ACL, FAIL, 0);
    }

    if (!nas_acl_cps_key_set_u32(cps_obj, BASE_ACL_ACL_POOL_INFO_NPU_ID,
                                 npu_id)) {
        NAS_ACL_LOG_ERR("ACL Pool attribute get failed to set NPU ID in key");
        return STD_ERR(ACL, FAIL, 0);
    }

    if (!nas_acl_cps_key_set_obj_id(cps_obj, BASE_ACL_ACL_POOL_INFO_POOL_ID,
                                    acl_pool_id)) {
        NAS_ACL_LOG_ERR("ACL Pool attribute get failed to set ACL Pool ID in key");
        return STD_ERR(ACL, FAIL, 0);
    }

    if (!nas_fill_acl_pool_attr(cps_obj, npu_id, acl_pool_id, s)) {
        NAS_ACL_LOG_ERR("ACL Pool attribute get failed to fill ACL Pool attrs");
        return STD_ERR(ACL, FAIL, 0);
    }

    return STD_ERR_OK;
}

static t_std_error
nas_get_acl_pool_info_by_npu (cps_api_get_params_t* param,
                              size_t index, npu_id_t npu_id,
                              nas_acl_switch& s)
{
    for (const auto& acl_pool_id: s.acl_pool_obj_list()) {
        if (acl_pool_id.npu_id == npu_id) {
            if (nas_get_acl_pool_info(param->list, npu_id, acl_pool_id.pool_id, s)
                    != STD_ERR_OK) {
                NAS_ACL_LOG_ERR("ACL Pool info get failed for npu:%d, pool-id:0x%lx",
                                npu_id, acl_pool_id.pool_id);
                return STD_ERR(ACL, FAIL, 0);
            }
        }
    }

    return STD_ERR_OK;
}

static t_std_error
nas_get_acl_pool_info_by_switch(cps_api_get_params_t* param,
                                size_t index,
                                nas_acl_switch& s)
{
    for (const auto& acl_pool_id: s.acl_pool_obj_list()) {
        if (nas_get_acl_pool_info(param->list, acl_pool_id.npu_id, acl_pool_id.pool_id, s)
                != STD_ERR_OK) {
            NAS_ACL_LOG_ERR("ACL Pool info get failed for switch");
            return STD_ERR(ACL, FAIL, 0);
        }
    }

    return STD_ERR_OK;
}

static bool
nas_fill_acl_table_attr (cps_api_object_t cps_obj, npu_id_t npu_id,
                         nas_obj_id_t acl_table_id, nas_acl_switch& s)
{
    size_t                 list_sz = 16;
    t_std_error            ret;
    ndi_obj_id_t           ndi_acl_table_id;
    ndi_acl_table_attr_t   table_attr;

    std::vector<uint32_t> acl_table_used_entry_count(list_sz);
    std::vector<uint32_t> acl_table_avail_entry_count(list_sz);

    memset (&table_attr, 0, sizeof (table_attr));

    ret = nas_acl_table_get_ndi_obj_id_from_nas_obj_id (npu_id,
                 acl_table_id, &ndi_acl_table_id, s);

    if (ret != STD_ERR_OK)
    {
        NAS_ACL_LOG_ERR("ACL table attribute get failed to retrieve NDI object ID from NAS object ID(0x%lx), NPU ID(%d)",
                        acl_table_id, npu_id);
        return false;
    }

    table_attr.acl_table_used_entry_list_count = list_sz;
    table_attr.acl_table_used_entry_list = &(acl_table_used_entry_count[0]);
    table_attr.acl_table_avail_entry_list_count = list_sz;
    table_attr.acl_table_avail_entry_list = &(acl_table_avail_entry_count[0]);

    ret = ndi_acl_get_acl_table_attribute (npu_id, ndi_acl_table_id, &table_attr);

    if (ret != STD_ERR_OK) {
        NAS_ACL_LOG_ERR("ACL table attribute get failed in NDI for object id:0x%lx", ndi_acl_table_id);
        return false;
    }

    if ((table_attr.acl_table_used_entry_list_count > list_sz) ||
        (table_attr.acl_table_avail_entry_list_count > list_sz)) {

        // if returned list length is more than the passed list length,
        // then retrieve the list by resizing for required length.
        acl_table_used_entry_count.resize(table_attr.acl_table_used_entry_list_count);
        table_attr.acl_table_used_entry_list = &(acl_table_used_entry_count[0]);
        acl_table_avail_entry_count.resize(table_attr.acl_table_avail_entry_list_count);
        table_attr.acl_table_avail_entry_list = &(acl_table_avail_entry_count[0]);

        ret = ndi_acl_get_acl_table_attribute (npu_id, ndi_acl_table_id, &table_attr);

        if (ret != STD_ERR_OK) {
            NAS_ACL_LOG_ERR("ACL table attribute get with resized list failed in NDI "
                            "for object id:0x%lx list len:%d",
                            ndi_acl_table_id, table_attr.acl_table_used_entry_list_count);
            return false;
        }
    }

    cps_api_attr_id_t ids[3] = {BASE_ACL_ACL_TABLE_INFO, 0,
        BASE_ACL_ACL_TABLE_INFO_PIPELINE_ID};
    const int ids_len = sizeof(ids)/sizeof(ids[0]);

    for (size_t app_idx = 0; app_idx < table_attr.acl_table_used_entry_list_count; app_idx++) {
        ids[1] = app_idx;
        ids[2] = BASE_ACL_ACL_TABLE_INFO_PIPELINE_ID;
        cps_api_object_e_add(cps_obj,ids,ids_len,cps_api_object_ATTR_T_U32,
                &app_idx, sizeof (uint32_t));

        ids[1] = app_idx;
        ids[2] = BASE_ACL_ACL_TABLE_INFO_USED_COUNT;
        cps_api_object_e_add(cps_obj,ids,ids_len,cps_api_object_ATTR_T_U32,
                &table_attr.acl_table_used_entry_list[app_idx],
                sizeof(uint32_t));

        ids[1] = app_idx;
        ids[2] = BASE_ACL_ACL_TABLE_INFO_AVAIL_COUNT;
        cps_api_object_e_add(cps_obj,ids,ids_len,cps_api_object_ATTR_T_U32,
                &table_attr.acl_table_avail_entry_list[app_idx],
                sizeof(uint32_t));
    }

    return true;
}

static t_std_error
nas_get_acl_table_info (cps_api_object_list_t& cps_obj_list,
                        npu_id_t npu_id,
                        nas_obj_id_t acl_table_id,
                        nas_acl_switch& s)
{
    cps_api_object_t cps_obj =
        cps_api_object_list_create_obj_and_append(cps_obj_list);

    if (cps_obj == nullptr) {
        NAS_ACL_LOG_ERR("Obj append failed");
        return STD_ERR(ACL, FAIL, 0);
    }

    if (!cps_api_key_from_attr_with_qual(cps_api_object_key(cps_obj),
                                         BASE_ACL_ACL_TABLE_OBJ,
                                         cps_api_qualifier_OBSERVED)) {
        NAS_ACL_LOG_ERR("ACL table info get failed to create key from ACL table object");
        return STD_ERR(ACL, FAIL, 0);
    }

    if (!nas_acl_cps_key_set_u32(cps_obj, BASE_ACL_ACL_TABLE_NPU_ID,
                                 npu_id)) {
        NAS_ACL_LOG_ERR("ACL table info get failed to set NPU id in key");
        return STD_ERR(ACL, FAIL, 0);
    }

    if (!nas_acl_cps_key_set_obj_id(cps_obj, BASE_ACL_ACL_TABLE_ID,
                                    acl_table_id)) {
        NAS_ACL_LOG_ERR("ACL table info get failed to set Table ID:0x%lx in key",
                        acl_table_id);
        return STD_ERR(ACL, FAIL, 0);
    }

    if (!nas_fill_acl_table_attr(cps_obj, npu_id, acl_table_id, s)) {
        NAS_ACL_LOG_ERR("Failed to fill ACL Table attrs");
        NAS_ACL_LOG_ERR("ACL table info get failed to fill attrs for Table ID:0x%lx",
                        acl_table_id);
        return STD_ERR(ACL, FAIL, 0);
    }

    return STD_ERR_OK;
}

static t_std_error
nas_get_acl_table_info_by_npu (cps_api_get_params_t* param,
                              size_t index, npu_id_t npu_id,
                              nas_acl_switch& s)
{
    t_std_error  rc = STD_ERR_OK;

    for (const auto& tbl_kvp: s.table_list ()) {

        nas_obj_id_t nas_acl_table_id = tbl_kvp.second.table_id();

        if (nas_get_acl_table_info (param->list, npu_id, nas_acl_table_id, s)
                != STD_ERR_OK) {
            NAS_ACL_LOG_ERR("ACL table info get failed for npu:%d, ACL Table ID:0x%lx",
                            npu_id, nas_acl_table_id);
            rc = STD_ERR(ACL, FAIL, 0);
            break;
        }
    }

    return rc;
}

static t_std_error
nas_get_acl_table_info_by_switch (cps_api_get_params_t* param,
                                  size_t index,
                                  nas_acl_switch& s)
{
    t_std_error  rc = STD_ERR_OK;

    for (const auto& tbl_kvp: s.table_list ()) {

        nas_obj_id_t nas_acl_table_id = tbl_kvp.second.table_id();

        for (auto npu_id: tbl_kvp.second.npu_list ()) {
            if (nas_get_acl_table_info(param->list, npu_id, nas_acl_table_id, s)
                    != STD_ERR_OK) {
                NAS_ACL_LOG_ERR("ACL table info get failed for switch, "
                                "npu:%d, ACL Table ID:0x%lx",
                                npu_id, nas_acl_table_id);
                rc = STD_ERR(ACL, FAIL, 0);
                break;
            }
        }
    }

    return rc;
}


/* this function is used to retrieve the switch ACL pool information */
t_std_error
nas_acl_pool_info_get (cps_api_get_params_t *param, size_t index,
                       cps_api_object_t filter_obj) noexcept
{
    npu_id_t          npu_id = 0;
    bool              id_passed_in = false;
    bool              npu_id_passed_in = false;
    t_std_error       rc = NAS_ACL_E_NONE;
    nas_switch_id_t   switch_id = 0;
    nas_obj_id_t      nas_acl_pool_id = 0;

    if (!nas_acl_cps_key_get_switch_id(filter_obj, NAS_ACL_SWITCH_ATTR,
                                       &switch_id)) {
        NAS_ACL_LOG_ERR("ACL Pool info get failed to get switch id");
        return STD_ERR(ACL, FAIL, 0);
    }

    try {

        nas_acl_switch& s = nas_acl_get_switch(switch_id);

        if (s.is_acl_pool_cache_init_done() == false) {

            // check and populate switch ACL pool cache
            if (nas_acl_populate_acl_pool_cache (s) != STD_ERR_OK) {
                NAS_ACL_LOG_ERR("Failed to retrieve Switch ACL pool list");
                return STD_ERR(ACL, FAIL, 0);
            }
            s.mark_acl_pool_cache_init_done();
        }

        if (nas_acl_cps_key_get_u32(filter_obj, BASE_ACL_ACL_POOL_INFO_NPU_ID,
                    (uint32_t *) &npu_id)) {
            npu_id_passed_in = true;
            NAS_ACL_LOG_BRIEF("ACL Pool info get input params NPU ID %d", npu_id);
        }

        if (nas_acl_cps_key_get_obj_id(filter_obj, BASE_ACL_ACL_POOL_INFO_POOL_ID, &nas_acl_pool_id)) {
            id_passed_in = true;
            NAS_ACL_LOG_BRIEF("ACL Pool info get input params Pool ID 0x%lx ", nas_acl_pool_id);
        }

        if (npu_id_passed_in && id_passed_in) {
            acl_pool_id_t* acl_pool_id = s.find_acl_pool(npu_id, nas_acl_pool_id);

            if (acl_pool_id == nullptr) {
                NAS_ACL_LOG_ERR("ACL Pool info get failed to find pool in cache, "
                                " NPU ID %d, Pool ID 0x%lx not present",
                                npu_id, nas_acl_pool_id);
                return STD_ERR(ACL, FAIL, 0);
            }
            rc = nas_get_acl_pool_info(param->list, npu_id, nas_acl_pool_id, s);
        } else if (npu_id_passed_in) {
            nas_acl_switch& s = nas_acl_get_switch (switch_id);
            rc = nas_get_acl_pool_info_by_npu (param, index, npu_id, s);
        } else {
            nas_acl_switch& s = nas_acl_get_switch (switch_id);
            rc = nas_get_acl_pool_info_by_switch (param, index, s);
        }
    } catch (nas::base_exception& e) {
        NAS_ACL_LOG_ERR("Err_code: 0x%x, fn: %s (), %s", e.err_code,
                        e.err_fn.c_str(), e.err_msg.c_str());
        return e.err_code;
    } catch (std::out_of_range& e) {
        NAS_ACL_LOG_ERR("Out of range exception %s", e.what());
        return STD_ERR(ACL, FAIL, 0);
    }

    return (rc);
}


/* this function is used to retrieve the switch ACL table usage information */
t_std_error
nas_acl_table_info_get (cps_api_get_params_t *param, size_t index,
                        cps_api_object_t filter_obj) noexcept
{
    t_std_error       rc = NAS_ACL_E_NONE;
    nas_switch_id_t   switch_id = 0;
    npu_id_t          npu_id = 0;
    nas_obj_id_t      acl_table_id = 0;
    bool              id_passed_in = false;
    bool              npu_id_passed_in = false;

    if (!nas_acl_cps_key_get_switch_id(filter_obj, NAS_ACL_SWITCH_ATTR,
                                       &switch_id)) {
        NAS_ACL_LOG_ERR("ACL Table info get failed to get switch id");
        return STD_ERR(ACL, FAIL, 0);
    }

    try {

        nas_acl_switch& s = nas_acl_get_switch(switch_id);

        if (nas_acl_cps_key_get_u32(filter_obj, BASE_ACL_ACL_TABLE_NPU_ID,
                    (uint32_t *) &npu_id)) {
            npu_id_passed_in = true;
            NAS_ACL_LOG_BRIEF("ACL Table info get input params NPU ID %d", npu_id);
        }

        if (nas_acl_cps_key_get_obj_id(filter_obj, BASE_ACL_ACL_TABLE_ID, &acl_table_id)) {
            id_passed_in = true;
            NAS_ACL_LOG_BRIEF("ACL Table info get input params Pool ID 0x%lx ", acl_table_id);
        }

        if (npu_id_passed_in && id_passed_in) {
            rc = nas_get_acl_table_info(param->list, npu_id, acl_table_id, s);
        } else if (npu_id_passed_in) {
            rc = nas_get_acl_table_info_by_npu (param, index, npu_id, s);
        } else {
            rc = nas_get_acl_table_info_by_switch (param, index, s);
        }
    } catch (nas::base_exception& e) {
        NAS_ACL_LOG_ERR("Err_code: 0x%x, fn: %s (), %s", e.err_code,
                        e.err_fn.c_str(), e.err_msg.c_str());
        return e.err_code;
    } catch (std::out_of_range& e) {
        NAS_ACL_LOG_ERR("Out of range exception %s", e.what());
        return STD_ERR(ACL, FAIL, 0);
    }

    return (rc);
}
