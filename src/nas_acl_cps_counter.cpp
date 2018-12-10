/*
 * Copyright (c) 2018 Dell Inc.
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
 * \file   nas_acl_cps_counter.cpp
 * \brief  This file contains CPS related ACL Counter functionality
 * \date   03-2015
 */
#include "event_log.h"
#include "std_error_codes.h"
#include "nas_acl_log.h"
#include "nas_acl_switch_list.h"
#include "nas_acl_cps.h"
#include "nas_base_utils.h"
#include "cps_api_object_key.h"
#include "cps_class_map.h"
#include "nas_switch.h"
#include "nas_acl_cps_key.h"
#include "nas_acl_utl.h"

static t_std_error
nas_acl_counter_create (cps_api_object_t obj,
                      cps_api_object_t prev,
                      bool             is_rollbk_op) noexcept;

static t_std_error
nas_acl_counter_delete (cps_api_object_t obj,
                      cps_api_object_t prev,
                      bool             is_rollbk_op) noexcept;

enum class nas_acl_stats_op_type {
    GET,
    SET,
};

static nas_acl_write_operation_map_t nas_acl_counter_op_map [] = {
    {cps_api_oper_CREATE, nas_acl_counter_create},
    {cps_api_oper_DELETE, nas_acl_counter_delete},
};

nas_acl_write_operation_map_t *
nas_acl_get_counter_operation_map (cps_api_operation_types_t op) noexcept
{
    uint32_t                  index;
    uint32_t                  count;

    count = sizeof (nas_acl_counter_op_map) / sizeof (nas_acl_counter_op_map [0]);

    for (index = 0; index < count; index++) {

        if (nas_acl_counter_op_map [index].op == op) {

            return (&nas_acl_counter_op_map [index]);
        }
    }
    return NULL;
}

static bool
_fill_counter_npu_list (cps_api_object_t obj, const nas_acl_counter_t& counter,
                        bool explicit_npu_list) noexcept
{
    if (counter.following_table_npus() && !explicit_npu_list) {
        // Skip NPU list attr if it has not been configured
        return true;
    }
    for (auto npu_id: counter.npu_list ()) {
        if (!cps_api_object_attr_add_u32 (obj,
                                          BASE_ACL_COUNTER_NPU_ID_LIST, npu_id)) {
            return false;
        }
    }
    return true;
}

static bool
_fill_counter_attr_info (cps_api_object_t obj, const nas_acl_counter_t& counter,
                         bool explicit_npu_list) noexcept
{
    if (counter.is_pkt_count_enabled()) {
        if (!cps_api_object_attr_add_u32 (obj, BASE_ACL_COUNTER_TYPES,
                                          BASE_ACL_COUNTER_TYPE_PACKET)) {
            return false;
        }
    }

    if (counter.is_byte_count_enabled()) {
        if (!cps_api_object_attr_add_u32 (obj, BASE_ACL_COUNTER_TYPES,
                                          BASE_ACL_COUNTER_TYPE_BYTE)) {
            return false;
        }
    }

    if (counter.counter_name() != nullptr) {
        if (!cps_api_object_attr_add(obj, BASE_ACL_COUNTER_NAME, counter.counter_name(),
                                     strlen(counter.counter_name()) + 1)) {
            return false;
        }
    }

    const char* tbl_name = counter.table_name();
    if (tbl_name != nullptr) {
        if (!cps_api_object_attr_add(obj, BASE_ACL_COUNTER_TABLE_NAME, tbl_name,
                                     strlen(tbl_name) + 1)) {
            return false;
        }
    }

    if (!_fill_counter_npu_list (obj, counter, explicit_npu_list)) {
        return false;
    }

    return true;
}

static bool _cps_key_fill (cps_api_object_t obj,
                           const nas_acl_counter_t& counter) noexcept
{
    if (!nas_acl_cps_key_set_obj_id (obj, BASE_ACL_COUNTER_TABLE_ID, counter.table_id())) {
        NAS_ACL_LOG_ERR ("Failed to set Table ID in Key");
        return false;
    }
    if (!nas_acl_cps_key_set_obj_id (obj, BASE_ACL_COUNTER_ID, counter.counter_id())) {
        NAS_ACL_LOG_ERR ("Failed to set Counter ID in Key");
        return false;
    }
    return true;
}

static bool nas_acl_counter_cps_key_init (cps_api_object_t obj,
                                          const nas_acl_counter_t& counter) noexcept
{
    if (!cps_api_key_from_attr_with_qual (cps_api_object_key (obj),
                                          BASE_ACL_COUNTER_OBJ,
                                          cps_api_qualifier_TARGET)) {
        NAS_ACL_LOG_ERR ("Failed to create Key from Counter Object");
        return false;
    }

    return _cps_key_fill (obj, counter);
}

static
t_std_error nas_acl_get_counter_info (cps_api_get_params_t *param,
                                              size_t                index,
                                              const nas_acl_counter_t&  counter) noexcept
{
    cps_api_object_t obj = cps_api_object_create ();
    if (obj == NULL) {
        return NAS_ACL_E_MEM;
    }
    cps_api_object_guard g(obj);

    if (!_fill_counter_attr_info (obj, counter, true)) {
        return NAS_ACL_E_MEM;
    }

    if (!nas_acl_counter_cps_key_init (obj, counter)) {
        return NAS_ACL_E_MEM;
    }

    if (!cps_api_object_list_append (param->list, obj)) {
        NAS_ACL_LOG_ERR ("Obj Append failed. Index: %ld", index);
        return NAS_ACL_E_MEM;
    }

    g.release();
    return NAS_ACL_E_NONE;
}

static t_std_error
nas_acl_get_counter_info_by_table (cps_api_get_params_t  *param,
                                 size_t                 index,
                                 const nas_acl_table&   table,
                                 BASE_ACL_OBJECTS_t     obj_type) noexcept
{
    nas_acl_switch& s = table.get_switch ();

    for (const auto& counter_pair: s.counter_list (table.table_id())) {
        t_std_error  rc;

        switch (obj_type) {
        case BASE_ACL_COUNTER_OBJ:
            if ((rc = nas_acl_get_counter_info (param, index,
                    counter_pair.second)) != NAS_ACL_E_NONE) {
                return rc;
            }
            break;
        case BASE_ACL_STATS_OBJ:
            if ((rc = nas_acl_stats_info_get (param, index,
                    counter_pair.second)) != NAS_ACL_E_NONE) {
                return rc;
            }
            break;
        default:
            break;
        }
    }
    return NAS_ACL_E_NONE;
}

static t_std_error
nas_acl_get_counter_info_by_switch (cps_api_get_params_t  *param,
                                  size_t                 index,
                                  const nas_acl_switch&  s,
                                  BASE_ACL_OBJECTS_t     obj_type) noexcept
{
    for (const auto& tbl_kvp: s.table_list ()) {
        t_std_error  rc;

        if ((rc = nas_acl_get_counter_info_by_table (param, index, tbl_kvp.second,
                obj_type)) != NAS_ACL_E_NONE) {
            return rc;
        }
    }
    return NAS_ACL_E_NONE;
}

static
t_std_error nas_acl_get_counter_info_all (cps_api_get_params_t *param,
                                                  size_t               index,
                                                  BASE_ACL_OBJECTS_t   obj_type) noexcept
{
    for (const auto& switch_pair: nas_acl_get_switch_list ()) {
        t_std_error  rc;

        if ((rc = nas_acl_get_counter_info_by_switch (param,
                index, switch_pair.second, obj_type)) != NAS_ACL_E_NONE) {
            return rc;
        }
    }

    return NAS_ACL_E_NONE;
}

t_std_error
nas_acl_get_counter (cps_api_get_params_t *param, size_t index,
                     cps_api_object_t filter_obj, BASE_ACL_OBJECTS_t obj_type) noexcept
{
    t_std_error  rc = NAS_ACL_E_NONE;
    nas_switch_id_t        switch_id;
    nas_obj_id_t           table_id;
    nas_obj_id_t           counter_id;
    nas_attr_id_t          table_id_attr_id, table_name_attr_id;
    nas_attr_id_t          counter_id_attr_id, counter_name_attr_id;

    if (obj_type == BASE_ACL_COUNTER_OBJ) {
        table_id_attr_id  = BASE_ACL_COUNTER_TABLE_ID;
        table_name_attr_id = BASE_ACL_COUNTER_TABLE_NAME;
        counter_id_attr_id  = BASE_ACL_COUNTER_ID;
        counter_name_attr_id = BASE_ACL_COUNTER_NAME;
    }
    else {
        table_id_attr_id  = BASE_ACL_STATS_TABLE_ID;
        table_name_attr_id  = BASE_ACL_STATS_TABLE_NAME;
        counter_id_attr_id  = BASE_ACL_STATS_COUNTER_ID;
        counter_name_attr_id  = BASE_ACL_STATS_COUNTER_NAME;
    }

    bool switch_id_key = nas_acl_cps_key_get_switch_id (filter_obj,
                                                        NAS_ACL_SWITCH_ATTR,
                                                        &switch_id);
    bool table_id_key = nas_acl_cps_key_get_obj_id (filter_obj,
                                                    table_id_attr_id,
                                                    &table_id);
    if (switch_id_key && !table_id_key) {
        nas_acl_switch& sw = nas_acl_get_switch(switch_id);
        cps_api_object_attr_t name_attr = cps_api_get_key_data(filter_obj,
                                                               table_name_attr_id);
        if (name_attr != nullptr) {
            char* table_name = (char*)cps_api_object_attr_data_bin(name_attr);
            nas_acl_table* table_p = sw.find_table_by_name(table_name);
            if (table_p == nullptr) {
                NAS_ACL_LOG_ERR("ACL Table with specific name not found");
                return NAS_ACL_E_ATTR_VAL;
            }
            table_id_key = true;
            table_id = table_p->table_id();
        }
    }
    bool counter_id_key = nas_acl_cps_key_get_obj_id (filter_obj,
                                                      counter_id_attr_id,
                                                      &counter_id);
    if (switch_id_key && table_id_key && !counter_id_key) {
        nas_acl_switch& sw = nas_acl_get_switch(switch_id);
        cps_api_object_attr_t name_attr = cps_api_get_key_data(filter_obj, counter_name_attr_id);
        if (name_attr != nullptr) {
            char* counter_name = (char*)cps_api_object_attr_data_bin(name_attr);
            nas_acl_counter_t* counter_p = sw.find_counter_by_name(table_id, counter_name);
            if (counter_p == nullptr) {
                NAS_ACL_LOG_ERR("ACL Counter with specific name not found");
                return NAS_ACL_E_ATTR_VAL;
            }
            counter_id_key = true;
            counter_id = counter_p->counter_id();
        }
    }

    try {
        if (!switch_id_key) {
            /* No keys provided */
            rc = nas_acl_get_counter_info_all (param, index, obj_type);
        }
        else if (switch_id_key && !table_id_key) {
            /* Switch Id provided */
            nas_acl_switch& s = nas_acl_get_switch (switch_id);
            rc = nas_acl_get_counter_info_by_switch (param, index, s, obj_type);
        }
        else if (switch_id_key && table_id_key && !counter_id_key) {
            /* Switch Id and Table Id provided */
            nas_acl_switch& s = nas_acl_get_switch (switch_id);
            nas_acl_table&  table = s.get_table (table_id);

            rc = nas_acl_get_counter_info_by_table (param, index, table, obj_type);
        }
        else if (switch_id_key && table_id_key && counter_id_key) {
            /* Switch Id, Table Id and Counter Id provided */
            nas_acl_switch& s = nas_acl_get_switch (switch_id);
            auto& counter = s.get_counter (table_id, counter_id);

            if (obj_type == BASE_ACL_STATS_OBJ) {
                rc = nas_acl_stats_info_get (param, index, counter);
            } else {
                rc = nas_acl_get_counter_info (param, index, counter);
            }
        }
        else {
            NAS_ACL_LOG_ERR ("Invalid combination of keys");
            rc = NAS_ACL_E_MISSING_KEY;
        }
    } catch (nas::base_exception& e) {

        NAS_ACL_LOG_ERR ("Err_code: 0x%x, fn: %s (), %s", e.err_code,
                      e.err_fn.c_str (), e.err_msg.c_str ());

        rc = e.err_code;
    }

    return (rc);
}

static
t_std_error nas_acl_counter_create (cps_api_object_t obj,
                                              cps_api_object_t prev,
                                              bool             is_rollbk_op) noexcept
{
    cps_api_object_it_t    it;
    cps_api_attr_id_t      attr_id;
    nas_switch_id_t        switch_id;
    nas_obj_id_t           table_id;
    nas_obj_id_t           counter_id;
    bool                   id_passed_in = false;

    if (!nas_acl_cps_key_get_switch_id (obj, NAS_ACL_SWITCH_ATTR,
                                        &switch_id)) {
        NAS_ACL_LOG_ERR ("Switch ID is a mandatory key for Counter Create ");
        return NAS_ACL_E_MISSING_KEY;
    }

    if (nas_acl_cps_key_get_obj_id (obj, BASE_ACL_COUNTER_ID, &counter_id)) {
        id_passed_in = true;
        NAS_ACL_LOG_BRIEF ("Counter ID %lu provided for Counter Create", counter_id);
    }

    try {
        nas_acl_switch& s    = nas_acl_get_switch (switch_id);
        if (!nas_acl_cps_key_get_obj_id (obj, BASE_ACL_COUNTER_TABLE_ID,
                                         &table_id)) {
            cps_api_object_attr_t tbl_name_attr = cps_api_get_key_data(obj,
                                                    BASE_ACL_COUNTER_TABLE_NAME);
            if (tbl_name_attr == nullptr) {
                NAS_ACL_LOG_ERR ("No Table ID or Name found for Counter Create ");
                return NAS_ACL_E_MISSING_KEY;
            }
            char* tbl_name = (char*)cps_api_object_attr_data_bin(tbl_name_attr);
            nas_acl_table* table_p = s.find_table_by_name(tbl_name);
            if (table_p == nullptr) {
                NAS_ACL_LOG_ERR("No Table with name %s was found", tbl_name);
                return NAS_ACL_E_MISSING_KEY;
            }
            table_id = table_p->table_id();
        }

        NAS_ACL_LOG_BRIEF ("%sSwitch Id: %d, Table Id: %ld",
                            (is_rollbk_op) ? "** ROLLBACK **: " : "", switch_id, table_id);

        nas_acl_table& table = s.get_table (table_id);

        if (id_passed_in) {
            nas_acl_counter_t* cp;
            if ((cp = s.find_counter (table_id, counter_id)) != NULL) {
                NAS_ACL_LOG_ERR ("Counter ID %lu already taken", counter_id);
                return NAS_ACL_E_MISSING_KEY;
            }
        }
        nas_acl_counter_t tmp_counter (&table);

        for (cps_api_object_it_begin (obj, &it);
             cps_api_object_it_valid (&it); cps_api_object_it_next (&it)) {

            attr_id = cps_api_object_attr_id (it.attr);

            switch (attr_id) {

                case BASE_ACL_COUNTER_TYPES:
                {
                    auto counter_type = cps_api_object_attr_data_u32 (it.attr);
                    NAS_ACL_LOG_DETAIL ("Counter type: %d", counter_type);
                    tmp_counter.set_type (counter_type);
                    break;
                }
                case BASE_ACL_COUNTER_NAME:
                {
                    char* name = (char*)cps_api_object_attr_data_bin(it.attr);
                    nas_acl_counter_t* counter_p = s.find_counter_by_name(table_id, name);
                    if (counter_p != nullptr) {
                        NAS_ACL_LOG_ERR("Counter %s already exists", name);
                        return NAS_ACL_E_DUPLICATE;
                    }
                    NAS_ACL_LOG_DETAIL ("Counter Name: %s", name);
                    tmp_counter.set_counter_name(name);
                    break;
                }
                case BASE_ACL_COUNTER_NPU_ID_LIST:
                {
                    // Must not check for duplicate attributes, since
                    // 'npu-id-list' is a leaf-list and it will
                    // appear multiple times, once for each element in
                    // the list.
                    auto npu = cps_api_object_attr_data_u32 (it.attr);
                    NAS_ACL_LOG_DETAIL ("NPU Id: %d", npu);
                    tmp_counter.add_npu (npu);
                    break;
                }
                default:
                    NAS_ACL_LOG_DETAIL ("Unknown attribute ignored %lu(%lx)",
                                        attr_id, attr_id);
                    break;
            }
        }

        // Allocate a new ID for the counter beforehand
        // to avoid rolling back commit if ID allocation fails
        nas_acl_id_guard_t  idg (s, BASE_ACL_COUNTER_OBJ, table_id);
        if (id_passed_in) {
            idg.reserve_guarded_id(counter_id);
        } else {
            counter_id  = idg.alloc_guarded_id();
        }
        tmp_counter.set_counter_id (counter_id);

        tmp_counter.commit_create (is_rollbk_op);

        // WARNING !!! CANNOT throw error or exception beyond this point
        // since counter is already committed to SAI

        nas_acl_counter_t& new_counter = s.save_counter (std::move(tmp_counter));
        idg.unguard();
        counter_id = new_counter.counter_id ();
        NAS_ACL_LOG_BRIEF ("Counter Creation successful. Switch Id: %d, "
                           "Table Id: %ld, Counter Id: %ld",
                           switch_id, table_id, counter_id);

        if (!nas_acl_cps_key_set_obj_id (obj, BASE_ACL_COUNTER_ID, counter_id)) {
            NAS_ACL_LOG_ERR ("Failed to set Counter Id Key as return value");
        }

        if (is_rollbk_op == false) {
            cps_api_object_set_key (prev, cps_api_object_key(obj));
            _cps_key_fill (prev, new_counter);
        }

    } catch (nas::base_exception& e) {
        NAS_ACL_LOG_ERR ("Err_code: 0x%x, fn: %s (), %s", e.err_code,
                         e.err_fn.c_str (), e.err_msg.c_str ());
        return e.err_code;
    }catch (std::out_of_range& e) {
        NAS_ACL_LOG_ERR ("###########  Out of Range exception %s", e.what ());
        return NAS_ACL_E_FAIL;
    }

    NAS_ACL_LOG_BRIEF ("Successful ");
    return NAS_ACL_E_NONE;
}

static t_std_error nas_acl_counter_delete (cps_api_object_t obj,
                                           cps_api_object_t prev,
                                           bool             is_rollbk_op) noexcept
{
    nas_switch_id_t   switch_id;
    nas_obj_id_t      table_id;
    nas_obj_id_t      counter_id;

    if (!nas_acl_cps_key_get_switch_id (obj, NAS_ACL_SWITCH_ATTR,
                                        &switch_id)) {
        NAS_ACL_LOG_ERR ("Switch ID is a mandatory key for Counter Delete ");
        return NAS_ACL_E_MISSING_KEY;
    }

    try {
        nas_acl_switch& s    = nas_acl_get_switch (switch_id);

        if (!nas_acl_cps_key_get_obj_id (obj, BASE_ACL_COUNTER_TABLE_ID,
                                         &table_id)) {
            cps_api_object_attr_t tbl_name_attr = cps_api_get_key_data(obj,
                                                    BASE_ACL_COUNTER_TABLE_NAME);
            if (tbl_name_attr == nullptr) {
                NAS_ACL_LOG_ERR ("No Table ID or Name found for Counter Delete ");
                return NAS_ACL_E_MISSING_KEY;
            }
            char* tbl_name = (char*)cps_api_object_attr_data_bin(tbl_name_attr);
            nas_acl_table* table_p = s.find_table_by_name(tbl_name);
            if (table_p == nullptr) {
                NAS_ACL_LOG_ERR("No Table with name %s was found", tbl_name);
                return NAS_ACL_E_MISSING_KEY;
            }
            table_id = table_p->table_id();
        }

        if (!nas_acl_cps_key_get_obj_id (obj, BASE_ACL_COUNTER_ID, &counter_id)) {
            cps_api_object_attr_t cnt_name_attr = cps_api_get_key_data(obj,
                                                            BASE_ACL_COUNTER_NAME);
            if (cnt_name_attr == nullptr) {
                NAS_ACL_LOG_ERR ("No Counter ID of Name found for Counter Delete");
                return NAS_ACL_E_MISSING_KEY;
            }
            char* cnt_name = (char*)cps_api_object_attr_data_bin(cnt_name_attr);
            nas_acl_counter_t* counter_p = s.find_counter_by_name(table_id, cnt_name);
            if (counter_p == nullptr) {
                NAS_ACL_LOG_ERR("No Counter with name %s was found", cnt_name);
                return NAS_ACL_E_MISSING_KEY;
            }
            counter_id = counter_p->counter_id();
        }

        NAS_ACL_LOG_BRIEF ("%sSwitch Id: %d, Table Id: %ld, Counter Id: %ld",
                           (is_rollbk_op) ? "** ROLLBACK **: " : "", switch_id,
                           table_id, counter_id);


        nas_acl_counter_t& counter = s.get_counter (table_id, counter_id);

        if (is_rollbk_op == false) {
            cps_api_object_set_key (prev, cps_api_object_key(obj));
            _cps_key_fill (prev, counter);
            _fill_counter_attr_info (prev, counter, false);
        }

        counter.commit_delete (is_rollbk_op);

        // WARNING !!! CANNOT throw error or exception beyond this point
        // since counter is already deleted in SAI

        s.remove_counter_from_table (table_id, counter_id);

        NAS_ACL_LOG_BRIEF ("Counter Deletion successful. Switch Id: %d, "
                           "Table Id: %ld, Counter Id: %ld",
                           switch_id, table_id, counter_id);
    } catch (nas::base_exception& e) {

        NAS_ACL_LOG_ERR ("Err_code: 0x%x, fn: %s (), %s", e.err_code,
                         e.err_fn.c_str (), e.err_msg.c_str ());

        return e.err_code;
    }catch (std::out_of_range& e) {
        NAS_ACL_LOG_ERR ("###########  Out of Range exception %s", e.what ());
        return NAS_ACL_E_FAIL;
    }

    NAS_ACL_LOG_BRIEF ("Successful ");
    return NAS_ACL_E_NONE;
}
