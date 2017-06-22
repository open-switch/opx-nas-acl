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
 * \file   nas_acl_cps.cpp
 * \brief  This file contains CPS related functionality
 * \date   03-2015
 * \author Mukesh MV & Ravikumar Sivasankar
 */
#include "event_log.h"
#include "std_error_codes.h"
#include "nas_acl_log.h"
#include "nas_acl_cps.h"

static inline t_std_error
nas_acl_exec_write_op (nas_acl_write_operation_map_t *op_map,
                       cps_api_object_t               obj,
                       cps_api_object_t               prev,
                       bool                           rollback) noexcept
{
    t_std_error rc;

    nas_acl_lock ();
    rc = op_map->fn (obj, prev, rollback);
    nas_acl_unlock ();

    return rc;
}

static t_std_error
nas_acl_cps_api_write_internal (void                         *context,
                                cps_api_transaction_params_t *param,
                                cps_api_object_t              obj,
                                cps_api_operation_types_t     op,
                                bool                          rollback) noexcept
{
    nas_acl_write_operation_map_t  *p_op_map = NULL;
    bool                            save_prev = !rollback;

    if (cps_api_key_get_cat (cps_api_object_key (obj))
        != cps_api_obj_CAT_BASE_ACL) {

        NAS_ACL_LOG_BRIEF ("Invalid Category.");
        return NAS_ACL_E_UNSUPPORTED;
    }

    uint32_t sub_category = cps_api_key_get_subcat (cps_api_object_key (obj));

    switch (sub_category) {
        case BASE_ACL_TABLE_OBJ:
            p_op_map = nas_acl_get_table_operation_map (op);
            break;

        case BASE_ACL_ENTRY_OBJ:
            p_op_map = nas_acl_get_entry_operation_map (op);
            break;

        case BASE_ACL_COUNTER_OBJ:
            p_op_map = nas_acl_get_counter_operation_map (op);
            break;

        case BASE_ACL_STATS_OBJ:
            p_op_map = nas_acl_get_stats_op_map (op);
            // Stats is a stateless object.
            // So it doesn't have the concept of a rollback
            // or the need to save the prev state.
            save_prev = false;
            break;

        default:
            return NAS_ACL_E_UNSUPPORTED;
    }

    if (p_op_map == NULL) {

        NAS_ACL_LOG_ERR ("Operation %d NOT allowed on Obj", op);
        return NAS_ACL_E_UNSUPPORTED;
    }

    cps_api_object_t prev = NULL;

    if (save_prev) {
        prev = cps_api_object_list_create_obj_and_append (param->prev);
        if (prev == NULL) {
            return (NAS_ACL_E_MEM);
        }
    }

    return nas_acl_exec_write_op (p_op_map, obj, prev, rollback);
}

cps_api_return_code_t
nas_acl_cps_api_read (void                 *context,
                      cps_api_get_params_t *param,
                      size_t                index) noexcept
{
    uint32_t              sub_category;
    t_std_error rc = NAS_ACL_E_UNSUPPORTED;

    cps_api_object_t filter_obj = cps_api_object_list_get (param->filters, index);

    if (filter_obj == NULL) {
        NAS_ACL_LOG_ERR ("Missing Filter Object");
        return cps_api_ret_code_ERR;
    }

    if (cps_api_key_get_cat (cps_api_object_key (filter_obj)) != cps_api_obj_CAT_BASE_ACL) {
        NAS_ACL_LOG_ERR ("Invalid Category");
        return cps_api_ret_code_ERR;
    }

    sub_category = cps_api_key_get_subcat (cps_api_object_key (filter_obj));

    NAS_ACL_LOG_BRIEF("Sub Category: %d", sub_category);

    nas_acl_lock ();

    switch (sub_category) {

        case BASE_ACL_TABLE_OBJ:
            rc = nas_acl_get_table (param, index, filter_obj);
            break;

        case BASE_ACL_ENTRY_OBJ:
            rc = nas_acl_get_entry (param, index, filter_obj);
            break;

        case BASE_ACL_COUNTER_OBJ:
        case BASE_ACL_STATS_OBJ:
            rc = nas_acl_get_counter (param, index, filter_obj,
                                      (BASE_ACL_OBJECTS_t) sub_category);
            break;

        default:
            break;
    }

    nas_acl_unlock ();

    return static_cast <cps_api_return_code_t> (rc);
}

cps_api_return_code_t
nas_acl_cps_api_write (void                         *context,
                       cps_api_transaction_params_t *param,
                       size_t                        index) noexcept
{
    cps_api_object_t          obj;
    cps_api_operation_types_t op;

    obj = cps_api_object_list_get (param->change_list, index);

    if (obj == NULL) {
        NAS_ACL_LOG_ERR ("Missing Change Object");
        return cps_api_ret_code_ERR;
    }

    op = cps_api_object_type_operation (cps_api_object_key (obj));

    auto rc = nas_acl_cps_api_write_internal (context, param, obj, op, false);
    return static_cast<cps_api_return_code_t>(rc);
}

cps_api_return_code_t
nas_acl_cps_api_rollback (void                         *context,
                          cps_api_transaction_params_t *param,
                          size_t                        index) noexcept
{
    cps_api_object_t          obj;
    cps_api_operation_types_t op;

    obj = cps_api_object_list_get (param->prev, index);

    if (obj == NULL) {
        NAS_ACL_LOG_ERR ("Missing Previous saved Object");
        return cps_api_ret_code_ERR;
    }

    op = cps_api_object_type_operation (cps_api_object_key (obj));

    op = ((op == cps_api_oper_CREATE) ? cps_api_oper_DELETE :
          (op == cps_api_oper_DELETE) ? cps_api_oper_CREATE : op);

    auto rc = nas_acl_cps_api_write_internal (context, param, obj, op, true);
    return static_cast<cps_api_return_code_t>(rc);
}

cps_api_object_attr_t nas_acl_get_attr (const cps_api_object_it_t& it,
                                        cps_api_attr_id_t attr_id,
                                        bool* is_dupl) noexcept
{
    auto attr = cps_api_object_it_find (&it, attr_id);
    *is_dupl = false;

    if (attr == NULL) {
        return NULL;
    }

    // Move to the next attribute and try finding again to check for duplicates
    cps_api_object_it_t  it_temp;
    cps_api_object_it_from_attr (attr, &it_temp);
    cps_api_object_it_next (&it_temp);

    if (cps_api_object_it_find (&it_temp, attr_id) != NULL) {
        *is_dupl = true;
    }
    return attr;
}

cps_api_return_code_t
nas_udf_cps_api_read (void                 *context,
                      cps_api_get_params_t *param,
                      size_t                index)
{
    uint32_t              sub_category;
    t_std_error rc = NAS_ACL_E_UNSUPPORTED;

    cps_api_object_t filter_obj = cps_api_object_list_get (param->filters, index);

    if (filter_obj == NULL) {
        NAS_ACL_LOG_ERR ("Missing Filter Object");
        return cps_api_ret_code_ERR;
    }

    if (cps_api_key_get_cat (cps_api_object_key (filter_obj)) != cps_api_obj_CAT_BASE_UDF) {
        NAS_ACL_LOG_ERR ("Invalid Category");
        return cps_api_ret_code_ERR;
    }

    sub_category = cps_api_key_get_subcat (cps_api_object_key (filter_obj));

    NAS_ACL_LOG_BRIEF("Sub Category: %d", sub_category);

    nas_acl_lock ();

    switch (sub_category) {

        case BASE_UDF_UDF_GROUP_OBJ:
            rc = nas_udf_get_group (param, index, filter_obj);
            break;

        case BASE_UDF_UDF_MATCH_OBJ:
            rc = nas_udf_get_match (param, index, filter_obj);
            break;

        case BASE_UDF_UDF_OBJ_OBJ:
            rc = nas_udf_get_udf (param, index, filter_obj);
            break;

        default:
            break;
    }

    nas_acl_unlock ();

    return static_cast <cps_api_return_code_t> (rc);
}

static t_std_error
nas_udf_cps_api_write_internal (void                         *context,
                                cps_api_transaction_params_t *param,
                                cps_api_object_t             obj,
                                cps_api_operation_types_t    op,
                                bool                         rollback)
{
    if (cps_api_key_get_cat (cps_api_object_key (obj))
        != cps_api_obj_CAT_BASE_UDF) {

        NAS_ACL_LOG_BRIEF ("Invalid Category.");
        return NAS_ACL_E_UNSUPPORTED;
    }

    cps_api_object_t prev = NULL;
    if (!rollback) {
        prev = cps_api_object_list_create_obj_and_append(param->prev);
        if (prev == NULL) {
            return NAS_ACL_E_MEM;
        }
    }

    t_std_error rc = STD_ERR_OK;
    uint32_t sub_category = cps_api_key_get_subcat (cps_api_object_key (obj));

    NAS_ACL_LOG_BRIEF("Sub Category: %d", sub_category);

    nas_acl_lock ();

    switch (sub_category) {
    case BASE_UDF_UDF_GROUP_OBJ:
        switch(op) {
        case cps_api_oper_CREATE:
            rc = nas_udf_group_create(obj, prev, rollback);
            break;
        case cps_api_oper_DELETE:
            rc = nas_udf_group_delete(obj, prev, rollback);
            break;
        default:
            rc = NAS_ACL_E_UNSUPPORTED;
            break;
        }
        break;
    case BASE_UDF_UDF_MATCH_OBJ:
        switch(op) {
        case cps_api_oper_CREATE:
            rc = nas_udf_match_create(obj, prev, rollback);
            break;
        case cps_api_oper_DELETE:
            rc = nas_udf_match_delete(obj, prev, rollback);
            break;
        default:
            rc = NAS_ACL_E_UNSUPPORTED;
            break;
        }
        break;
    case BASE_UDF_UDF_OBJ_OBJ:
        switch(op) {
        case cps_api_oper_CREATE:
            rc = nas_udf_create(obj, prev, rollback);
            break;
        case cps_api_oper_DELETE:
            rc = nas_udf_delete(obj, prev, rollback);
            break;
        default:
            rc = NAS_ACL_E_UNSUPPORTED;
            break;
        }
        break;
    default:
        rc = NAS_ACL_E_UNSUPPORTED;
        break;
    }

    nas_acl_unlock ();

    return rc;
}

cps_api_return_code_t
nas_udf_cps_api_write (void                         *context,
                       cps_api_transaction_params_t *param,
                       size_t                        index)
{
    cps_api_object_t          obj;
    cps_api_operation_types_t op;

    obj = cps_api_object_list_get (param->change_list, index);

    if (obj == NULL) {
        NAS_ACL_LOG_ERR ("Missing Change Object");
        return cps_api_ret_code_ERR;
    }

    op = cps_api_object_type_operation (cps_api_object_key (obj));

    auto rc = nas_udf_cps_api_write_internal (context, param, obj, op, false);
    return static_cast<cps_api_return_code_t>(rc);
}

cps_api_return_code_t
nas_udf_cps_api_rollback (void                         *context,
                          cps_api_transaction_params_t *param,
                          size_t                        index)
{
    cps_api_object_t          obj;
    cps_api_operation_types_t op;

    obj = cps_api_object_list_get (param->prev, index);

    if (obj == NULL) {
        NAS_ACL_LOG_ERR ("Missing Previous saved Object");
        return cps_api_ret_code_ERR;
    }

    op = cps_api_object_type_operation (cps_api_object_key (obj));

    op = ((op == cps_api_oper_CREATE) ? cps_api_oper_DELETE :
          (op == cps_api_oper_DELETE) ? cps_api_oper_CREATE : op);

    auto rc = nas_udf_cps_api_write_internal (context, param, obj, op, true);
    return static_cast<cps_api_return_code_t>(rc);
}
