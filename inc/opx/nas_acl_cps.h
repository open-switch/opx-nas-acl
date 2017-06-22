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
 * \file   nas_acl_cps.h
 * \brief  NAS ACL CPS API prototypes
 * \date   02-2015
 * \author Mukesh MV & Ravikumar Sivasankar
 */

#ifndef _NAS_ACL_CPS_H_
#define _NAS_ACL_CPS_H_

#include "cps_api_events.h"
#include "cps_api_operation.h"
#include "cps_api_object_category.h"
#include "dell-base-acl.h"
#include "nas_base_utils.h"
#include "nas_acl_switch_list.h"
#include "nas_acl_common.h"
#include <pthread.h>

// Possible Longest attr hierarchy -
// ACTION-List-Attr . Action-ListIndex . Action-Value-Attr . Value-Inner-ListIndex . Action-Value-Child-Attr
#define NAS_ACL_MAX_ATTR_DEPTH 6

typedef struct _nas_acl_write_operation_map_t {
    cps_api_operation_types_t op;
    t_std_error             (*fn) (cps_api_object_t obj,
                                   cps_api_object_t prev, bool rollback);
} nas_acl_write_operation_map_t;

typedef void (nas_acl_filter_t:: *nas_acl_filter_get_fn_ptr_t)
    (nas_acl_common_data_list_t& data_list) const;

typedef void
(nas_acl_filter_t::* nas_acl_filter_set_fn_ptr_t)
    (const nas_acl_common_data_list_t&);

typedef bool
(* nas_acl_attr_validate_fn_ptr_t) (NAS_ACL_DATA_TYPE_t data_type,
                                    nas_acl_common_data_t& common_data);

typedef enum _nas_acl_attr_mode {
    NAS_ACL_ATTR_MODE_MANDATORY,
    NAS_ACL_ATTR_MODE_OPTIONAL
} nas_acl_attr_mode_t;

typedef struct _nas_acl_attr_int_range {
    uint_t min;
    uint_t max;
} nas_acl_attr_int_range_t;

/* Attribute info structure definition */
typedef struct _nas_acl_map_data_t {
    cps_api_attr_id_t               attr_id;
    NAS_ACL_DATA_TYPE_t             data_type;
    struct {
        size_t                          data_len; /* if 0, the data is variable
                                                   * length data. */
        nas_acl_attr_mode_t             mode;
        nas_acl_attr_int_range_t        range;
    };
} nas_acl_map_data_t;

typedef enum {
    NAS_ACL_ATTR_EXTRACT_NOT_FOUND,
    NAS_ACL_ATTR_EXTRACT_FAIL,
    NAS_ACL_ATTR_EXTRACT_SUCCESS,
} nas_acl_attr_extract_t;

typedef std::vector<nas_acl_map_data_t> nas_acl_map_data_list_t;

typedef struct _nas_acl_filter_info_t {
    std::string                 name;
    nas_acl_map_data_t          val;
    nas_acl_map_data_list_t     child_list;
    nas_acl_filter_get_fn_ptr_t get_fn;
    nas_acl_filter_set_fn_ptr_t set_fn;
} nas_acl_filter_info_t;

typedef void (nas_acl_action_t:: *nas_acl_action_get_fn_ptr_t)
    (nas_acl_common_data_list_t& data_list) const;

typedef void (nas_acl_action_t::* nas_acl_action_set_fn_ptr_t)
    (const nas_acl_common_data_list_t&);

typedef struct _nas_acl_action_info_t {
    std::string                 name;
    nas_acl_map_data_t          val;
    nas_acl_map_data_list_t     child_list;
    nas_acl_action_get_fn_ptr_t get_fn;
    nas_acl_action_set_fn_ptr_t set_fn;
} nas_acl_action_info_t;

typedef const std::unordered_map <BASE_ACL_MATCH_TYPE_t,
        nas_acl_filter_info_t, std::hash<int>> nas_acl_filter_map_t;

typedef const std::unordered_map <BASE_ACL_ACTION_TYPE_t,
    nas_acl_action_info_t, std::hash<int>> nas_acl_action_map_t;

nas_acl_filter_map_t& nas_acl_get_filter_map () noexcept;
nas_acl_action_map_t& nas_acl_get_action_map () noexcept;

cps_api_return_code_t nas_acl_cps_api_read (void * context,
                                            cps_api_get_params_t * param,
                                            size_t ix) noexcept;

cps_api_return_code_t nas_acl_cps_api_write (void * context,
                                             cps_api_transaction_params_t * param,
                                             size_t ix) noexcept;

cps_api_return_code_t nas_acl_cps_api_rollback (void * context,
                                                cps_api_transaction_params_t * param,
                                                size_t index_of_element_being_updated) noexcept;

cps_api_object_attr_t nas_acl_get_attr (const cps_api_object_it_t& it,
                                        cps_api_attr_id_t attr_id, bool* is_dupl) noexcept;

t_std_error           nas_acl_get_table (cps_api_get_params_t *param, size_t index,
                                         cps_api_object_t filter_obj) noexcept;

t_std_error           nas_acl_get_entry (cps_api_get_params_t *param, size_t index,
                                         cps_api_object_t filter_obj) noexcept;

t_std_error           nas_acl_get_counter (cps_api_get_params_t *param, size_t index,
                                           cps_api_object_t filter_obj,
                                           BASE_ACL_OBJECTS_t obj_type) noexcept;

t_std_error           nas_acl_stats_info_get (cps_api_get_params_t *param,
                                              size_t                index,
                                              const nas_acl_counter_t&  counter) noexcept;

nas_acl_write_operation_map_t *
nas_acl_get_table_operation_map (cps_api_operation_types_t op) noexcept;

nas_acl_write_operation_map_t *
nas_acl_get_entry_operation_map (cps_api_operation_types_t op) noexcept;

nas_acl_write_operation_map_t *
nas_acl_get_counter_operation_map (cps_api_operation_types_t op) noexcept;

nas_acl_write_operation_map_t *
nas_acl_get_stats_op_map (cps_api_operation_types_t op) noexcept;

void nas_acl_set_match_list (const cps_api_object_t     obj,
                             const cps_api_object_it_t& it,
                             nas_acl_entry&             entry);

void nas_acl_set_match_attr (const cps_api_object_t     obj,
                             nas_acl_entry&             entry,
                             BASE_ACL_MATCH_TYPE_t      match_type_val,
                             nas::attr_list_t           parent_attr_id_list,
                             bool                       reset);

bool
nas_acl_fill_match_attr_list (cps_api_object_t obj, const nas_acl_entry& entry);

bool
nas_acl_fill_match_attr (cps_api_object_t obj, const nas_acl_filter_t& filter,
                         BASE_ACL_MATCH_TYPE_t      match_type_val,
                         nas::attr_list_t           parent_attr_id_list);

bool
nas_acl_fill_action_attr (cps_api_object_t obj, const nas_acl_action_t& action,
                          BASE_ACL_ACTION_TYPE_t      action_type_val,
                          nas::attr_list_t           parent_attr_id_list);

void nas_acl_set_action_list (const cps_api_object_t     obj,
                              const cps_api_object_it_t& it,
                              nas_acl_entry&             entry);

void nas_acl_set_action_attr (const cps_api_object_t     obj,
                              nas_acl_entry&             entry,
                              BASE_ACL_ACTION_TYPE_t     match_type_val,
                              nas::attr_list_t&          parent_attr_id_list,
                              bool                       reset);

bool
nas_acl_fill_action_attr_list (cps_api_object_t obj, const nas_acl_entry& entry);

bool
nas_acl_copy_data_to_obj (cps_api_object_t               obj,
                          nas::attr_list_t&              parent_list,
                          const nas_acl_map_data_t&      val_info,
                          const nas_acl_map_data_list_t& child_list,
                          nas_acl_common_data_list_t&    common_data_list);

nas_acl_common_data_list_t
nas_acl_copy_data_from_obj (cps_api_object_t                obj,
                            nas::attr_list_t&               parent_list,
                            const nas_acl_map_data_t&       val_info,
                            const nas_acl_map_data_list_t&  child_list,
                            const std::string&              name);

int nas_acl_lock () noexcept;

int nas_acl_unlock () noexcept;

t_std_error           nas_udf_get_group (cps_api_get_params_t *param, size_t index,
                                         cps_api_object_t filter_obj) noexcept;

t_std_error           nas_udf_get_match (cps_api_get_params_t *param, size_t index,
                                         cps_api_object_t filter_obj) noexcept;

t_std_error           nas_udf_get_udf (cps_api_get_params_t *param, size_t index,
                                       cps_api_object_t filter_obj) noexcept;

t_std_error           nas_udf_group_create(cps_api_object_t obj,
                                           cps_api_object_t prev,
                                           bool is_rollbk) noexcept;

t_std_error           nas_udf_group_delete(cps_api_object_t obj,
                                           cps_api_object_t prev,
                                           bool is_rollbk) noexcept;

t_std_error           nas_udf_match_create(cps_api_object_t obj,
                                           cps_api_object_t prev,
                                           bool is_rollbk) noexcept;

t_std_error           nas_udf_match_delete(cps_api_object_t obj,
                                           cps_api_object_t prev,
                                           bool is_rollbk) noexcept;

t_std_error           nas_udf_create(cps_api_object_t obj,
                                     cps_api_object_t prev,
                                     bool is_rollbk) noexcept;

t_std_error           nas_udf_delete(cps_api_object_t obj,
                                     cps_api_object_t prev,
                                     bool is_rollbk) noexcept;

#endif
