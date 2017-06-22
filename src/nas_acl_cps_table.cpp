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
 * \file   nas_acl_cps_table.cpp
 * \brief  This file contains CPS related ACL Table functionality
 * \date   03-2015
 * \author Mukesh MV & Ravikumar Sivasankar
 */
#include "event_log.h"
#include "std_error_codes.h"
#include "nas_acl_log.h"
#include "nas_acl_cps.h"
#include "cps_api_object_key.h"
#include "cps_class_map.h"
#include "nas_base_utils.h"
#include "nas_acl_utl.h"
#include "nas_acl_cps_key.h"
#include "nas_acl_switch_list.h"

static t_std_error
nas_acl_table_create (cps_api_object_t obj,
                      cps_api_object_t prev,
                      bool             is_rollbk_op) noexcept;

static t_std_error
nas_acl_table_delete (cps_api_object_t obj,
                      cps_api_object_t prev,
                      bool             is_rollbk_op) noexcept;

static nas_acl_write_operation_map_t nas_acl_table_op_map [] = {
    {cps_api_oper_CREATE, nas_acl_table_create},
    {cps_api_oper_DELETE, nas_acl_table_delete},
};

nas_acl_write_operation_map_t *
nas_acl_get_table_operation_map (cps_api_operation_types_t op) noexcept
{
    uint32_t                  index;
    uint32_t                  count;

    count = sizeof (nas_acl_table_op_map) / sizeof (nas_acl_table_op_map [0]);

    for (index = 0; index < count; index++) {

        if (nas_acl_table_op_map [index].op == op) {

            return (&nas_acl_table_op_map [index]);
        }
    }

    return NULL;
}

static inline bool
nas_acl_fill_table_npu_list (cps_api_object_t obj, const nas_acl_table& table,
                             bool explicit_npu_list=false) noexcept
{
    if (table.following_switch_npus() && !explicit_npu_list) {
        // Skip NPU list attr if it has not been configured
        return true;
    }

    for (auto npu_id: table.npu_list ()) {
        if (!cps_api_object_attr_add_u32 (obj, BASE_ACL_TABLE_NPU_ID_LIST,
                                          npu_id)) {
            return false;
        }
    }

    return true;
}

static inline bool
nas_acl_fill_table_allowed_fields (cps_api_object_t obj, const nas_acl_table& table) noexcept
{
    for (auto attr_id: table.allowed_filters ()) {
        if (!cps_api_object_attr_add_u32 (obj,
                                          BASE_ACL_TABLE_ALLOWED_MATCH_FIELDS,
                                          attr_id)) {
            return false;
        }
    }

    return true;
}

static inline bool
nas_acl_fill_table_udf_group_list (cps_api_object_t obj, const nas_acl_table& table) noexcept
{
    if (obj == nullptr) {
        NAS_ACL_LOG_ERR ("Invalid input argument");
        return false;
    }

    for (auto grp_id: table.udf_group_list ()) {
        if (!cps_api_object_attr_add_u64 (obj,
                                          BASE_ACL_TABLE_UDF_GROUP_LIST,
                                          grp_id)) {
            return false;
        }
    }

    return true;
}

static bool
nas_acl_fill_table_attr_info (cps_api_object_t obj, const nas_acl_table& table,
                              bool explicit_npu_list=false) noexcept
{
    if (!cps_api_object_attr_add_u32 (obj, BASE_ACL_TABLE_STAGE,
                                      table.stage ())) {
        return false;
    }

    if (!cps_api_object_attr_add_u32 (obj, BASE_ACL_TABLE_PRIORITY,
                                      table.priority ())) {
        return false;
    }

    if (!cps_api_object_attr_add_u32 (obj, BASE_ACL_TABLE_SIZE,
                                      table.table_size ())) {
        return false;
    }

    if (!nas_acl_fill_table_allowed_fields (obj, table)) {
        return false;
    }

    if (!nas_acl_fill_table_udf_group_list(obj, table)) {
        return false;
    }

    if (!nas_acl_fill_table_npu_list (obj, table, explicit_npu_list)) {
        return false;
    }

    return true;
}

static bool _cps_key_fill (cps_api_object_t obj,
                           const nas_acl_table& table) noexcept
{
    if (!nas_acl_cps_key_set_obj_id (obj, BASE_ACL_TABLE_ID, table.table_id())) {
        NAS_ACL_LOG_ERR ("Failed to set Table ID in Key");
        return false;
    }
    return true;
}

static bool nas_acl_table_cps_key_init (cps_api_object_t obj,
                                        const nas_acl_table& table) noexcept
{
    if (!cps_api_key_from_attr_with_qual (cps_api_object_key (obj),
                                          BASE_ACL_TABLE_OBJ,
                                          cps_api_qualifier_TARGET)) {
        NAS_ACL_LOG_ERR ("Failed to create Key from Table Object");
        return false;
    }

    return _cps_key_fill (obj, table);
}

static t_std_error nas_acl_get_table_info (cps_api_get_params_t *param,
                                           size_t                index,
                                           const nas_acl_table&  table) noexcept
{
    cps_api_object_t obj = cps_api_object_list_create_obj_and_append (param->list);
    if (!obj) {
        NAS_ACL_LOG_ERR ("Obj Append failed. Index: %ld", index);
        return cps_api_ret_code_ERR;
    }

    if (!nas_acl_table_cps_key_init (obj, table)) return cps_api_ret_code_ERR;

    if (nas_acl_fill_table_attr_info (obj, table, true) == false) {
         NAS_ACL_LOG_ERR ("nas_acl_fill_table_attr_info() failed. "
                          "Index: %ld", index);
         return cps_api_ret_code_ERR;
    }

    return cps_api_ret_code_OK;
}

static t_std_error nas_acl_get_table_info_by_switch (cps_api_get_params_t  *param,
                                                     size_t                 index,
                                                     const nas_acl_switch&  s) noexcept
{
    for (const auto& table_pair: s.table_list ()) {
        nas_acl_get_table_info (param, index, table_pair.second);
    }
    return cps_api_ret_code_OK;
}

static t_std_error nas_acl_get_table_info_all (cps_api_get_params_t *param,
                                               size_t               index) noexcept
{
   for (const auto& switch_pair: nas_acl_get_switch_list ()) {
       nas_acl_get_table_info_by_switch (param, index, switch_pair.second);
   }

   return cps_api_ret_code_OK;
}

t_std_error nas_acl_get_table (cps_api_get_params_t *param, size_t index,
                               cps_api_object_t filter_obj) noexcept
{
    t_std_error  rc = cps_api_ret_code_OK;
    nas_switch_id_t        switch_id;
    nas_obj_id_t           table_id;

    bool switch_id_key = nas_acl_cps_key_get_switch_id (filter_obj,
                                                        NAS_ACL_SWITCH_ATTR,
                                                        &switch_id);
    bool table_id_key = nas_acl_cps_key_get_obj_id (filter_obj,
                                                    BASE_ACL_TABLE_ID,
                                                    &table_id);
    try {
        if (!switch_id_key) {
            /* No keys provided */
            rc = nas_acl_get_table_info_all (param, index);
        }
        else if (switch_id_key && !table_id_key) {
            /* Switch Id provided */
            nas_acl_switch& s = nas_acl_get_switch (switch_id);
            rc = nas_acl_get_table_info_by_switch (param, index, s);
        }
        else if (switch_id_key && table_id_key) {
            /* Switch Id and Table Id provided */
            NAS_ACL_LOG_DETAIL ("Switch Id: %d, Table Id: %ld\n",
                                switch_id, table_id);

            nas_acl_switch&     s = nas_acl_get_switch (switch_id);
            nas_acl_table&  table = s.get_table (table_id);

            rc = nas_acl_get_table_info (param, index, table);
        }
        else {
            throw nas::base_exception {NAS_ACL_E_MISSING_KEY, __FUNCTION__,
                "Unknown Key combination "};
        }
    } catch (nas::base_exception& e) {

        NAS_ACL_LOG_ERR ("Err_code: 0x%x, fn: %s (), %s", e.err_code,
                      e.err_fn.c_str (), e.err_msg.c_str ());

        rc = e.err_code;
    }

    return (rc);
}

static
t_std_error nas_acl_table_create (cps_api_object_t obj,
                                  cps_api_object_t prev,
                                  bool             is_rollbk_op) noexcept
{
    cps_api_object_it_t    it;
    cps_api_attr_id_t      attr_id;
    nas_switch_id_t        switch_id;
    uint32_t               npu;
    nas_obj_id_t           table_id;
    uint_t                 stage;
    uint_t                 priority;
    uint_t                 table_size;
    uint_t                 match_field;
    bool                   is_stage_present = false;
    bool                   is_priority_present = false;
    bool                   is_size_present = false;
    bool                   id_passed_in = false;

    if (!nas_acl_cps_key_get_switch_id (obj, NAS_ACL_SWITCH_ATTR,
                                        &switch_id)) {
        NAS_ACL_LOG_ERR ("Switch ID is a mandatory key for Table Create ");
        return NAS_ACL_E_MISSING_KEY;
    }
    NAS_ACL_LOG_BRIEF ("%sSwitch Id: %d",
                       (is_rollbk_op) ? "** ROLLBACK **: " : "", switch_id);

    if (nas_acl_cps_key_get_obj_id (obj, BASE_ACL_TABLE_ID, &table_id)) {
        id_passed_in = true;
        NAS_ACL_LOG_BRIEF ("Table ID %lu provided for Table Create", table_id);
    }

    try {
        nas_acl_switch& s = nas_acl_get_switch (switch_id);

        if (id_passed_in) {
            nas_acl_table* tp;
            if ((tp = s.find_table (table_id)) != NULL) {
                NAS_ACL_LOG_ERR ("Table ID %lu already taken", table_id);
                return NAS_ACL_E_KEY_VAL;
            }
        }

        nas_acl_table tmp_table (&s);

        for (cps_api_object_it_begin (obj, &it);
             cps_api_object_it_valid (&it); cps_api_object_it_next (&it)) {

            attr_id = cps_api_object_attr_id (it.attr);

            switch (attr_id) {
                case BASE_ACL_TABLE_STAGE:
                    if (is_stage_present == true) {
                        throw nas::base_exception {NAS_ACL_E_DUPLICATE,
                            __FUNCTION__, "Duplicate Stage attribute "};
                    }
                    else {
                        is_stage_present = true;
                        stage = cps_api_object_attr_data_u32 (it.attr);
                        tmp_table.set_stage (stage);
                        NAS_ACL_LOG_DETAIL ("Stage: %d", stage);
                    }
                    break;

                case BASE_ACL_TABLE_PRIORITY:
                    if (is_priority_present == true) {
                        throw nas::base_exception {NAS_ACL_E_DUPLICATE,
                            __FUNCTION__, "Duplicate Priority attribute "};
                    }
                    else {
                        is_priority_present = true;
                        priority = cps_api_object_attr_data_u32 (it.attr);
                        NAS_ACL_LOG_DETAIL ("Priority: %d", priority);
                        tmp_table.set_priority (priority);
                    }
                    break;

                case BASE_ACL_TABLE_SIZE:
                    if (is_size_present == true) {
                        throw nas::base_exception {NAS_ACL_E_DUPLICATE,
                            __FUNCTION__, "Duplicate Size attribute "};
                    }
                    else {
                        is_size_present = true;
                        table_size = cps_api_object_attr_data_u32 (it.attr);
                        NAS_ACL_LOG_DETAIL ("Size: %d", table_size);
                        tmp_table.set_table_size (table_size);
                    }
                    break;


                case BASE_ACL_TABLE_ALLOWED_MATCH_FIELDS:
                    // Must not check for duplicate attributes, since
                    // 'allowed-match-fields' is a leaf-list and it will
                    // appear multiple times, once for each element in
                    // the list.
                    match_field = cps_api_object_attr_data_u32 (it.attr);
                    NAS_ACL_LOG_DETAIL ("Match field: %d (%s)", match_field,
                                        nas_acl_filter_type_name (static_cast
                                                                  <BASE_ACL_MATCH_TYPE_t>
                                                                  (match_field)));

                    tmp_table.set_allowed_filter (match_field);
                    break;

                case BASE_ACL_TABLE_UDF_GROUP_LIST:
                {
                    nas_obj_id_t udf_grp_id = cps_api_object_attr_data_u64(it.attr);
                    NAS_ACL_LOG_DETAIL ("UDF Group ID: %lu", udf_grp_id);
                    tmp_table.set_udf_group_id(udf_grp_id);
                    break;
                }

                case BASE_ACL_TABLE_NPU_ID_LIST:
                    // Must not check for duplicate attributes, since
                    // 'npu-id-list' is a leaf-list and it will
                    // appear multiple times, once for each element in
                    // the list.
                    npu = cps_api_object_attr_data_u32 (it.attr);
                    NAS_ACL_LOG_DETAIL ("NPU Id: %d", npu);
                    tmp_table.add_npu (npu);
                    break;

                default:
                    NAS_ACL_LOG_DETAIL ("Unknown attribute ignored %lu(%lx)",
                                        attr_id, attr_id);
                    break;
            }
        }

        // Allocate a new ID for the Table beforehand
        // to avoid rolling back commit if ID allocation fails
        nas_acl_id_guard_t  idg (s, BASE_ACL_TABLE_OBJ);
        if (id_passed_in) {
            idg.reserve_guarded_id(table_id);
        } else {
            table_id = idg.alloc_guarded_id();
        }
        tmp_table.set_table_id (table_id);

        tmp_table.commit_create (is_rollbk_op);

        // WARNING !!! CANNOT throw error or exception beyond this point
        // since table is already committed to SAI

        nas_acl_table& new_table = s.save_table (std::move (tmp_table));
        idg.unguard();
        table_id = new_table.table_id ();
        NAS_ACL_LOG_BRIEF ("Table Creation successful. Switch Id: %d, "
                           "Table Id: %ld", switch_id, table_id);

        if (!nas_acl_cps_key_set_obj_id (obj, BASE_ACL_TABLE_ID, table_id)) {
            NAS_ACL_LOG_ERR ("Failed to set new Table Id Key as return value");
        }

        if (is_rollbk_op == false) {
            cps_api_object_set_key (prev, cps_api_object_key (obj));
            _cps_key_fill (prev, new_table);
        }

    } catch (nas::base_exception& e) {
        NAS_ACL_LOG_ERR ("Err_code: 0x%x, fn: %s (), %s", e.err_code,
                         e.err_fn.c_str (), e.err_msg.c_str ());

        return e.err_code;

    } catch (std::out_of_range& e) {
        NAS_ACL_LOG_ERR ("###########  Out of Range exception %s", e.what ());
        return NAS_ACL_E_FAIL;
    }

    NAS_ACL_LOG_BRIEF ("Successful ");
    return NAS_ACL_E_NONE;
}

static
t_std_error nas_acl_table_delete (cps_api_object_t obj,
                                  cps_api_object_t prev,
                                  bool             is_rollbk_op) noexcept
{
    nas_switch_id_t       switch_id;
    nas_obj_id_t          table_id;

    if (!nas_acl_cps_key_get_switch_id (obj, NAS_ACL_SWITCH_ATTR,
                                        &switch_id)) {
        NAS_ACL_LOG_ERR ("Switch ID is a mandatory key for Table Delete");
        return NAS_ACL_E_MISSING_KEY;
    }
    if (!nas_acl_cps_key_get_obj_id (obj, BASE_ACL_TABLE_ID, &table_id)) {
        NAS_ACL_LOG_ERR ("Table ID is a mandatory key for Table Delete");
        return NAS_ACL_E_MISSING_KEY;
    }

    NAS_ACL_LOG_BRIEF ("%sSwitch Id: %d Table Id %ld",
                       (is_rollbk_op) ? "** ROLLBACK **: " : "", switch_id, table_id);

    try {
        nas_acl_switch& s = nas_acl_get_switch (switch_id);

        nas_acl_table& curr_table = s.get_table (table_id);

        if (!is_rollbk_op) {
            cps_api_object_set_key (prev, cps_api_object_key (obj));
            _cps_key_fill (prev, curr_table);
            nas_acl_fill_table_attr_info (prev, curr_table);
        }

        curr_table.commit_delete (is_rollbk_op);

        // WARNING !!! CANNOT throw error or exception beyond this point
        // since table is already deleted from SAI

        s.remove_table (table_id);

    } catch (nas::base_exception& e) {

        NAS_ACL_LOG_ERR ("Err_code: 0x%x, fn: %s (), %s", e.err_code,
                         e.err_fn.c_str (), e.err_msg.c_str ());

        return e.err_code;
    } catch (std::out_of_range& e) {
        NAS_ACL_LOG_ERR ("###########  Out of Range exception %s", e.what ());
        return NAS_ACL_E_FAIL;
    }

    return NAS_ACL_E_NONE;
}

