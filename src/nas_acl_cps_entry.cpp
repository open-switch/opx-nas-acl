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
 * \file   nas_acl_cps_entry.cpp
 * \brief  This file contains CPS related ACL Entry functionality
 * \date   03-2015
 * \author Mukesh MV & Ravikumar Sivasankar
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
#include <utility>

static t_std_error
nas_acl_entry_create (cps_api_object_t obj,
                      cps_api_object_t prev,
                      bool             is_rollbk_op) noexcept;

static t_std_error
nas_acl_entry_modify (cps_api_object_t obj,
                      cps_api_object_t prev,
                      bool             is_rollbk_op) noexcept;
static t_std_error
nas_acl_entry_delete (cps_api_object_t obj,
                      cps_api_object_t prev,
                      bool             is_rollbk_op) noexcept;

static nas_acl_write_operation_map_t nas_acl_entry_op_map [] = {
    {cps_api_oper_CREATE, nas_acl_entry_create},
    {cps_api_oper_SET, nas_acl_entry_modify},
    {cps_api_oper_DELETE, nas_acl_entry_delete},
};

/* Used by CPS Get handler */
struct entry_key_t {
    nas_switch_id_t switch_id;
    bool has_switch_id;
    nas_obj_id_t  table_id;
    bool has_table_id;
    nas_obj_id_t  entry_id;
    bool has_entry_id;
    BASE_ACL_MATCH_TYPE_t  ftype;
    bool has_match_type;
    BASE_ACL_ACTION_TYPE_t  atype;
    bool has_action_type;
};

/* Used by CPS operation (Create/Set/Del) handlers */
struct entry_op_key_t {
    nas_acl_switch& s;
    nas_acl_table&  t;
    bool            has_eid;
    nas_obj_id_t    eid;
    bool            is_incr_upd; // incremental update to filter or action
    struct {
        bool is_match_type;
        uint32_t type;
    };
};

nas_acl_write_operation_map_t *
nas_acl_get_entry_operation_map (cps_api_operation_types_t op) noexcept
{
    uint32_t                  index;
    uint32_t                  count;

    count = sizeof (nas_acl_entry_op_map) / sizeof (nas_acl_entry_op_map [0]);

    for (index = 0; index < count; index++) {
        if (nas_acl_entry_op_map [index].op == op) {
            return (&nas_acl_entry_op_map [index]);
        }
    }
    return NULL;
}

static inline bool
nas_acl_fill_entry_npu_list (cps_api_object_t obj, const nas_acl_entry& entry,
                             bool explicit_npu_list=false)
{
    if (!explicit_npu_list && entry.following_table_npus()) {
        // Skip NPU list attr if it has not been configured
        return true;
    }
    for (auto npu_id: entry.npu_list ()) {
        if (!cps_api_object_attr_add_u32 (obj, BASE_ACL_ENTRY_NPU_ID_LIST, npu_id)) {
            return false;
        }
    }

    return true;
}

static bool
nas_acl_fill_entry_attr_info (cps_api_object_t obj, const nas_acl_entry& entry,
                              bool explicit_npu_list)
{
    if (!cps_api_object_attr_add_u32 (obj, BASE_ACL_ENTRY_PRIORITY,
                                      entry.priority ())) {
        return false;
    }

    if (!nas_acl_fill_match_attr_list (obj, entry)) {
        return false;
    }

    if (!nas_acl_fill_action_attr_list (obj, entry)) {
        return false;
    }

    if (!nas_acl_fill_entry_npu_list (obj, entry, explicit_npu_list)) {
        return false;
    }

    return true;
}

static bool _cps_key_fill (cps_api_object_t obj,
                           const nas_acl_entry& entry) noexcept
{
    if (!nas_acl_cps_key_set_obj_id (obj, BASE_ACL_ENTRY_TABLE_ID, entry.table_id())) {
        NAS_ACL_LOG_ERR ("Failed to set Table ID in Key");
        return false;
    }
    if (!nas_acl_cps_key_set_obj_id (obj, BASE_ACL_ENTRY_ID, entry.entry_id())) {
        NAS_ACL_LOG_ERR ("Failed to set Entry ID in Key");
        return false;
    }
    return true;
}

static bool _cps_filter_upd_key_fill (cps_api_object_t obj,
                                      const nas_acl_entry& entry,
                                      BASE_ACL_MATCH_TYPE_t ftype) noexcept
{
    if (!_cps_key_fill (obj, entry)) return false;

    if (!nas_acl_cps_key_set_u32 (obj, BASE_ACL_ENTRY_MATCH_TYPE, ftype)) {
        NAS_ACL_LOG_ERR ("Failed to set Match type in Key");
        return false;
    }
    return true;
}

static bool _cps_action_upd_key_fill (cps_api_object_t obj,
                                      const nas_acl_entry& entry,
                                      BASE_ACL_ACTION_TYPE_t atype) noexcept
{
    if (!_cps_key_fill (obj, entry)) return false;

    if (!nas_acl_cps_key_set_u32 (obj, BASE_ACL_ENTRY_ACTION_TYPE, atype)) {
        NAS_ACL_LOG_ERR ("Failed to set Match type in Key");
        return false;
    }
    return true;
}

static bool nas_acl_entry_cps_key_init (cps_api_object_t obj,
                                        const nas_acl_entry& entry) noexcept
{
    if (!cps_api_key_from_attr_with_qual (cps_api_object_key (obj),
                                          BASE_ACL_ENTRY_OBJ,
                                          cps_api_qualifier_TARGET)) {
        NAS_ACL_LOG_ERR ("Failed to create Key from Entry Object");
        return false;
    }
    return (_cps_key_fill (obj, entry));
}

static t_std_error nas_acl_get_entry_info (cps_api_get_params_t *param,
                                           size_t                index,
                                           const nas_acl_entry&  entry)
{
    cps_api_object_t obj = cps_api_object_create ();
    if (obj == NULL) {
        return NAS_ACL_E_MEM;
    }
    cps_api_object_guard g(obj);

    if (!nas_acl_fill_entry_attr_info (obj, entry, true)) {
        return NAS_ACL_E_MEM;
    }

    if (!nas_acl_entry_cps_key_init (obj, entry)) {
        return NAS_ACL_E_MEM;
    }

    if (!cps_api_object_list_append (param->list, obj)) {
        NAS_ACL_LOG_ERR ("Obj Append failed. Index: %ld", index);
        return NAS_ACL_E_MEM;
    }

    g.release();
    return NAS_ACL_E_NONE;
}

static t_std_error nas_acl_get_entry_info_by_table (cps_api_get_params_t  *param,
                                                    size_t                 index,
                                                    const nas_acl_table&   table)
{
    nas_acl_switch& s = table.get_switch ();
    t_std_error  rc;

    for (const auto& entry_pair: s.entry_list (table.table_id())) {

        if ((rc = nas_acl_get_entry_info (param, index, entry_pair.second))
            != NAS_ACL_E_NONE) {
            return rc;
        }
    }
    return NAS_ACL_E_NONE;
}

static t_std_error nas_acl_get_entry_info_by_switch (cps_api_get_params_t  *param,
                                                     size_t                 index,
                                                     const nas_acl_switch&  s)
{
    t_std_error  rc;
    for (const auto& tbl_kvp: s.table_list ()) {

        if ((rc = nas_acl_get_entry_info_by_table (param, index, tbl_kvp.second))
            != NAS_ACL_E_NONE) {
            return rc;
        }
    }
    return NAS_ACL_E_NONE;
}

static t_std_error nas_acl_get_entry_info_all (cps_api_get_params_t *param,
                                               size_t               index)
{
    t_std_error  rc;
    for (const auto& switch_pair: nas_acl_get_switch_list ()) {

        if ((rc = nas_acl_get_entry_info_by_switch (param, index, switch_pair.second))
                != NAS_ACL_E_NONE) {
            return rc;
        }
    }

    return NAS_ACL_E_NONE;
}

static t_std_error _cps_fill_match_info (cps_api_get_params_t *param,
                                         size_t                index,
                                         const nas_acl_entry&  entry,
                                         BASE_ACL_MATCH_TYPE_t ftype)
{
    cps_api_object_t obj = cps_api_object_create ();
    if (obj == NULL) {
        return NAS_ACL_E_MEM;
    }
    cps_api_object_guard g(obj);

    // Attr-list to build Single Filter attr hierarchy -
    //  - Match-Value-Attr . Match-Value-Child-Attr
    nas::attr_list_t  attr_id_list;
    attr_id_list.reserve (NAS_ACL_MAX_ATTR_DEPTH);

    if (!nas_acl_fill_match_attr (obj, entry.get_filter(ftype, 0),
                                  ftype, attr_id_list))
    {
        return NAS_ACL_E_MEM;
    }

    if (!cps_api_key_from_attr_with_qual (cps_api_object_key (obj),
                                          BASE_ACL_ENTRY_MATCH_TYPE,
                                          cps_api_qualifier_TARGET)) {
        NAS_ACL_LOG_ERR ("Failed to create Key from Filter Object");
        return NAS_ACL_E_FAIL;
    }

    if (!_cps_filter_upd_key_fill (obj, entry, ftype)) {
        return NAS_ACL_E_MEM;
    }

    if (!cps_api_object_list_append (param->list, obj)) {
        NAS_ACL_LOG_ERR ("Obj Append failed. Index: %ld", index);
        return NAS_ACL_E_MEM;
    }

    g.release();
    return NAS_ACL_E_NONE;
}

static t_std_error _cps_fill_action_info (cps_api_get_params_t *param,
                                          size_t                index,
                                          const nas_acl_entry&  entry,
                                          BASE_ACL_ACTION_TYPE_t atype)
{
    cps_api_object_t obj = cps_api_object_create ();
    if (obj == NULL) {
        return NAS_ACL_E_MEM;
    }
    cps_api_object_guard g(obj);

    // Attr-list to build Single Action attr hierarchy -
    //  - Action-Value-Attr [. Value-Inner-ListIndex]. Action-Value-Child-Attr
    nas::attr_list_t attr_id_list;
    attr_id_list.reserve (NAS_ACL_MAX_ATTR_DEPTH);

    if (!nas_acl_fill_action_attr (obj, entry.get_action(atype),
                                   atype, attr_id_list))
    {
        return NAS_ACL_E_MEM;
    }

    if (!cps_api_key_from_attr_with_qual (cps_api_object_key (obj),
                                          BASE_ACL_ENTRY_ACTION_TYPE,
                                          cps_api_qualifier_TARGET)) {
        NAS_ACL_LOG_ERR ("Failed to create Key from Action Object");
        return NAS_ACL_E_FAIL;
    }

    if (!_cps_action_upd_key_fill (obj, entry, atype)) {
        return NAS_ACL_E_MEM;
    }

    if (!cps_api_object_list_append (param->list, obj)) {
        NAS_ACL_LOG_ERR ("Obj Append failed. Index: %ld", index);
        return NAS_ACL_E_MEM;
    }

    g.release();
    return NAS_ACL_E_NONE;
}

static entry_key_t _cps_extract_key (cps_api_object_t obj)
{
    nas_switch_id_t switch_id;
    bool has_switch_id = nas_acl_cps_key_get_switch_id (obj, NAS_ACL_SWITCH_ATTR,
            &switch_id);

    nas_obj_id_t  table_id;
    bool has_table_id = nas_acl_cps_key_get_obj_id (obj, BASE_ACL_ENTRY_TABLE_ID,
            &table_id);

    nas_obj_id_t  entry_id;
    bool has_entry_id = nas_acl_cps_key_get_obj_id (obj, BASE_ACL_ENTRY_ID,
            &entry_id);

    BASE_ACL_MATCH_TYPE_t  ftype;
    bool has_match_type = nas_acl_cps_key_get_u32 (obj, BASE_ACL_ENTRY_MATCH_TYPE,
            (uint32_t*)&ftype);

    BASE_ACL_ACTION_TYPE_t  atype;
    bool has_action_type = nas_acl_cps_key_get_u32 (obj, BASE_ACL_ENTRY_ACTION_TYPE,
            (uint32_t*)&atype);

    return {switch_id, has_switch_id, table_id, has_table_id, entry_id, has_entry_id,
            ftype, has_match_type, atype, has_action_type};
}

t_std_error
nas_acl_get_entry (cps_api_get_params_t *param, size_t index,
                   cps_api_object_t filter_obj) noexcept
{
    t_std_error  rc = NAS_ACL_E_NONE;

    auto key = _cps_extract_key (filter_obj);

    try {
        if (!key.has_switch_id) {
            /* No keys provided */
            rc = nas_acl_get_entry_info_all (param, index);
        }
        else if (key.has_switch_id && !key.has_table_id) {
            /* Switch Id provided */
            nas_acl_switch& s = nas_acl_get_switch (key.switch_id);
            rc = nas_acl_get_entry_info_by_switch (param, index, s);
        }
        else if (key.has_switch_id && key.has_table_id && !key.has_entry_id) {
            /* Switch Id and Table Id provided */
            nas_acl_switch& s = nas_acl_get_switch (key.switch_id);
            nas_acl_table&  table = s.get_table (key.table_id);

            rc = nas_acl_get_entry_info_by_table (param, index, table);
        }
        else if (key.has_switch_id && key.has_table_id && key.has_entry_id &&
                !(key.has_match_type || key.has_action_type)) {
            /* Switch Id, Table Id and Entry Id provided */
            nas_acl_switch& s = nas_acl_get_switch (key.switch_id);
            nas_acl_entry&  entry = s.get_entry (key.table_id, key.entry_id);

            rc = nas_acl_get_entry_info (param, index, entry);
        }
        else if (key.has_switch_id && key.has_table_id && key.has_entry_id
                 && key.has_match_type) {
            /* Switch Id, Table Id, Entry Id and Match type provided */
            nas_acl_switch& s = nas_acl_get_switch (key.switch_id);
            nas_acl_entry&  entry = s.get_entry (key.table_id, key.entry_id);
            rc = _cps_fill_match_info (param, index, entry, key.ftype);

        } else if (key.has_switch_id && key.has_table_id && key.has_entry_id
                   && key.has_action_type) {
                /* Switch Id, Table Id, Entry Id and Action type provided */
            nas_acl_switch& s = nas_acl_get_switch (key.switch_id);
            nas_acl_entry&  entry = s.get_entry (key.table_id, key.entry_id);
            rc = _cps_fill_action_info (param, index, entry, key.atype);

        } else {
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

static entry_op_key_t _cps_op_key_extract (cps_api_object_t obj)
{
    auto key = _cps_extract_key (obj);

    if (!key.has_switch_id) {
        throw nas::base_exception {NAS_ACL_E_MISSING_KEY, __PRETTY_FUNCTION__,
                                   "Missing Switch ID key"};
    }
    nas_acl_switch& s    = nas_acl_get_switch (key.switch_id);

    if (!key.has_table_id) {
        throw nas::base_exception {NAS_ACL_E_MISSING_KEY, __PRETTY_FUNCTION__,
                                   "Missing Table ID key"};
    }
    nas_acl_table& t = s.get_table (key.table_id);

    if (key.has_entry_id) {
        if (key.has_match_type) {
             if (key.ftype == BASE_ACL_MATCH_TYPE_UDF) {
                 throw nas::base_exception {NAS_ACL_E_UNSUPPORTED, __PRETTY_FUNCTION__,
                                "Modification on UDF filter is not supported"};
             }
             return {s,t,true, key.entry_id, true,{true, (uint32_t)(key.ftype)}};
        }
        if (key.has_action_type) {
             return {s,t,true, key.entry_id, true,{false, (uint32_t)(key.atype)}};
        }
        return {s,t,true, key.entry_id, false,{}};
    }

    return {s,t,false,0, false,{}};
}

static void  _cps_entry_incr_upd (cps_api_object_t       obj,
                                  cps_api_object_t       prev,
                                  entry_op_key_t &       op_key,
                                  cps_api_operation_types_t op,
                                  bool                   is_rollbk_op)
{
    nas_obj_id_t      table_id = op_key.t.table_id();
    nas_acl_switch&   s = op_key.s;
    nas_acl_entry&    old_entry = s.get_entry (table_id, op_key.eid);
    nas_acl_entry     new_entry (old_entry);
    const nas_acl_filter_t* filter_p = NULL;
    const nas_acl_action_t* action_p = NULL;

    NAS_ACL_LOG_BRIEF ("%sOp %d, Switch Id: %d, Table Id: %ld, Entry Id %ld",
                       (is_rollbk_op) ? "** ROLLBACK **: " : "",
                       op, s.id(), table_id, old_entry.entry_id());

    if (op_key.is_match_type) {
        auto ftype = (BASE_ACL_MATCH_TYPE_t)op_key.type;
        NAS_ACL_LOG_BRIEF ("match_type_val: %d (%s)", ftype,
                            nas_acl_filter_t::type_name (ftype));

        if (op != cps_api_oper_CREATE) {
            filter_p = &(old_entry.get_filter (ftype, 0));
        }
        if (op == cps_api_oper_DELETE) {
            new_entry.remove_filter(ftype, filter_p->filter_offset());
        } else {
            // Attr-list to build single Filter attr hierarchy -
            //   - Match-Value-Attr . Match-Value-Child-Attr
            nas::attr_list_t  attr_list;
            attr_list.reserve (NAS_ACL_MAX_ATTR_DEPTH);
            nas_acl_set_match_attr (obj, new_entry, ftype, attr_list, false);
        }
    } else {
        auto atype = (BASE_ACL_ACTION_TYPE_t)op_key.type;
        NAS_ACL_LOG_BRIEF ("match_type_val: %d (%s)", atype,
                            nas_acl_action_t::type_name (atype));

        if (op != cps_api_oper_CREATE) {
            action_p = &(old_entry.get_action (atype));
        }
        if (op == cps_api_oper_DELETE) {
            new_entry.remove_action(atype);
        } else {
            // Attr-list to build single Action attr hierarchy -
            //  - Action-Value-Attr [. Value-Inner-ListIndex]. Action-Value-Child-Attr
            nas::attr_list_t  attr_list;
            attr_list.reserve (NAS_ACL_MAX_ATTR_DEPTH);
            nas_acl_set_action_attr (obj, new_entry, atype, attr_list, false);
        }
    }

    new_entry.commit_modify (old_entry, is_rollbk_op);

    // WARNING !!! CANNOT throw error or exception beyond this point
    // since entry is already committed to SAI

    if (!is_rollbk_op) {
        nas::attr_list_t attr_id_list;
        attr_id_list.reserve (NAS_ACL_MAX_ATTR_DEPTH);

        cps_api_object_set_key (prev, cps_api_object_key (obj));

        if (op_key.is_match_type) {
            auto ftype = (BASE_ACL_MATCH_TYPE_t)op_key.type;
            _cps_filter_upd_key_fill (prev, old_entry, ftype);
            if (op != cps_api_oper_CREATE) {
                nas_acl_fill_match_attr (prev, *filter_p,
                                         ftype, attr_id_list);
            }
        } else {
            auto atype = (BASE_ACL_ACTION_TYPE_t)op_key.type;
            _cps_action_upd_key_fill (prev, old_entry, atype);
            if (op != cps_api_oper_CREATE) {
                nas_acl_fill_action_attr (prev, *action_p,
                                          atype, attr_id_list);
            }
        }
    }

    s.save_entry (std::move (new_entry));

    NAS_ACL_LOG_BRIEF ("Entry Modification successful. Switch Id: %d, "
                       "Table Id: %ld, Entry Id: %ld",
                       s.id(), table_id, op_key.eid);
}

static bool _cps_parse_entry_obj (cps_api_object_t obj, nas_acl_entry& tmp_entry,
                                  cps_api_operation_types_t op)
{
    cps_api_object_it_t    it;
    bool npu_modified = false;

    for (cps_api_object_it_begin (obj, &it);
            cps_api_object_it_valid (&it); cps_api_object_it_next (&it)) {

        cps_api_attr_id_t attr_id = cps_api_object_attr_id (it.attr);

        switch (attr_id) {

        case BASE_ACL_ENTRY_PRIORITY:
        {
            if (tmp_entry.is_attr_dirty(BASE_ACL_ENTRY_PRIORITY) == true) {
                throw nas::base_exception {NAS_ACL_E_DUPLICATE,
                    __FUNCTION__, "Duplicate Priority attribute "};
            }
            uint32_t priority = cps_api_object_attr_data_u32 (it.attr);
            NAS_ACL_LOG_DETAIL ("Priority: %d", priority);
            tmp_entry.set_priority (priority);
            break;
        }

        case BASE_ACL_ENTRY_MATCH:
            nas_acl_set_match_list (obj, it, tmp_entry);
            break;

        case BASE_ACL_ENTRY_ACTION:
            nas_acl_set_action_list (obj, it, tmp_entry);
            break;

        case BASE_ACL_ENTRY_NPU_ID_LIST:
        {
            uint32_t npu = cps_api_object_attr_data_u32 (it.attr);
            NAS_ACL_LOG_DETAIL ("NPU Id: %d", npu);
            tmp_entry.add_npu (npu);
            npu_modified = true;
            break;
        }

        default:
            NAS_ACL_LOG_DETAIL ("Unknown attribute ignored %lu(%lx)",
                    attr_id, attr_id);
            break;
        }
    }
    return npu_modified;
}

static void _cps_pack_attrs (cps_api_object_t pack_obj, cps_api_object_t key_obj,
                             const nas_acl_entry& entry,
                             const nas::attr_set_t& attrs, bool npu_modified)
{
    cps_api_object_set_key (pack_obj, cps_api_object_key (key_obj));
    _cps_key_fill (pack_obj, entry);

    for (auto attr_id: attrs) {

        switch (attr_id) {
        case BASE_ACL_ENTRY_PRIORITY:
            cps_api_object_attr_add_u32 (pack_obj, attr_id,
                                         entry.priority ());
            break;

        case BASE_ACL_ENTRY_MATCH:
            nas_acl_fill_match_attr_list (pack_obj, entry);
            break;

        case BASE_ACL_ENTRY_ACTION:
            nas_acl_fill_action_attr_list (pack_obj, entry);
            break;

        default:
            break;
        }
    }

    if (npu_modified == true) {
        nas_acl_fill_entry_npu_list (pack_obj, entry);
    }
}

static void _cps_pack_entry (cps_api_object_t pack_obj, cps_api_object_t key_obj,
                           const nas_acl_entry& entry)
{
    return _cps_pack_attrs (pack_obj, key_obj, entry, entry.set_attr_list (), true);
}

static void _cps_pack_key (cps_api_object_t pack_obj, cps_api_object_t key_obj,
                           const nas_acl_entry& entry)
{
    nas::attr_set_t dummy;
    return _cps_pack_attrs (pack_obj, key_obj, entry, dummy, false);
}

static t_std_error nas_acl_entry_create (cps_api_object_t obj,
                                         cps_api_object_t prev,
                                         bool             is_rollbk_op) noexcept
{
    try {
        auto op_key = _cps_op_key_extract (obj);

        if (op_key.is_incr_upd) {
            // This is not a new ACL entry create.
            // Rather just Append new Match filter or Action to existing ACL entry
            if (!op_key.has_eid) {
                NAS_ACL_LOG_ERR ("Entry ID is a mandatory key for Modify operation");
                return NAS_ACL_E_MISSING_KEY;
            }
            _cps_entry_incr_upd (obj, prev, op_key, cps_api_oper_CREATE, is_rollbk_op);
            return NAS_ACL_E_NONE;
        }

        nas_acl_switch& sw    = op_key.s;
        auto table_id = op_key.t.table_id();
        auto entry_id = op_key.eid;

        NAS_ACL_LOG_BRIEF ("%sSwitch Id: %d, Table Id: %ld",
                           (is_rollbk_op) ? "** ROLLBACK **: " : "", sw.id(), table_id);

        if (op_key.has_eid) {
            if ((sw.find_entry (table_id, entry_id)) != NULL) {
                NAS_ACL_LOG_ERR ("Entry ID %lu already taken", entry_id);
                return NAS_ACL_E_KEY_VAL;
            }
            NAS_ACL_LOG_BRIEF ("Entry ID %lu provided for Entry Create", entry_id);
        }

        nas_acl_entry tmp_entry (&op_key.t);
        _cps_parse_entry_obj (obj, tmp_entry, cps_api_oper_CREATE);

        // Allocate a new ID for the entry beforehand
        // to avoid rolling back commit if ID allocation fails
        nas_acl_id_guard_t  idg (sw, BASE_ACL_ENTRY_OBJ, table_id);
        if (op_key.has_eid) {
            idg.reserve_guarded_id (entry_id);
        } else {
            entry_id  = idg.alloc_guarded_id ();
        }
        tmp_entry.set_entry_id (entry_id);

        // Apply new entry to NDI and SAI
        tmp_entry.commit_create (is_rollbk_op);

        // WARNING !!! CANNOT throw error or exception beyond this point
        // since entry is already committed to SAI

        // Now save the entry in local cache. Also track references to table/counter
        nas_acl_entry& new_entry = sw.save_entry (std::move(tmp_entry));
        idg.unguard ();
        entry_id = new_entry.entry_id ();

        NAS_ACL_LOG_BRIEF ("Entry Creation successful. Switch Id: %d, "
                           "Table Id: %ld, Entry Id: %ld",
                           sw.id(), table_id, entry_id);

        if (!nas_acl_cps_key_set_obj_id (obj, BASE_ACL_ENTRY_ID, entry_id)) {
            NAS_ACL_LOG_ERR ("Failed to set Entry Id Key as return value");
        }

        if (!is_rollbk_op) {
            _cps_pack_key (prev, obj, new_entry);
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

static t_std_error nas_acl_entry_modify (cps_api_object_t obj,
                                         cps_api_object_t prev,
                                         bool             is_rollbk_op) noexcept
{
    try {
        auto op_key = _cps_op_key_extract (obj);

        if (!op_key.has_eid) {
            NAS_ACL_LOG_ERR ("Entry ID is a mandatory key for Modify operation");
            return NAS_ACL_E_MISSING_KEY;
        }
        if (op_key.is_incr_upd) {
            // Not replacing entire filter or action list.
            // Rather just modify value of existing Match filter or Action in ACL entry
            _cps_entry_incr_upd (obj, prev, op_key, cps_api_oper_SET, is_rollbk_op);
            return NAS_ACL_E_NONE;
        }

        nas_acl_switch& sw    = op_key.s;
        auto table_id = op_key.t.table_id();
        auto entry_id = op_key.eid;

        NAS_ACL_LOG_BRIEF ("%sSwitch Id: %d, Table Id: %ld, Entry Id: %ld",
                            (is_rollbk_op) ? "** ROLLBACK **: " : "",
                            sw.id(), table_id, entry_id);

        nas_acl_entry& old_entry = sw.get_entry (table_id, entry_id);
        nas_acl_entry  new_entry (old_entry);

        bool npu_modified = _cps_parse_entry_obj (obj, new_entry, cps_api_oper_SET);

        // Apply changes to NDI and SAI
        auto mod_attrs = new_entry.commit_modify (old_entry, is_rollbk_op);

        // WARNING !!! CANNOT throw error or exception beyond this point
        // since entry is already committed to SAI

        if (!is_rollbk_op) {
            _cps_pack_attrs (prev, obj, old_entry, mod_attrs, npu_modified);
        }

        // Now save the entry in local cache. Also track references to table/counter
        sw.save_entry (std::move (new_entry));

        NAS_ACL_LOG_BRIEF ("Entry Modification successful. Switch Id: %d, "
                           "Table Id: %ld, Entry Id: %ld",
                           sw.id(), table_id, entry_id);
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

static t_std_error nas_acl_entry_delete (cps_api_object_t obj,
                                         cps_api_object_t prev,
                                         bool             is_rollbk_op) noexcept
{
    try {
        auto op_key = _cps_op_key_extract (obj);

        if (!op_key.has_eid) {
            NAS_ACL_LOG_ERR ("Entry ID is a mandatory key for Delete operation");
            return NAS_ACL_E_MISSING_KEY;
        }

        if (op_key.is_incr_upd) {
            // Not deleting complete ACL entry.
            // Rather just removing a specific Match filter or Action in the ACL entry
            _cps_entry_incr_upd (obj, prev, op_key, cps_api_oper_DELETE, is_rollbk_op);
            return NAS_ACL_E_NONE;
        }

        nas_acl_switch& sw    = op_key.s;
        auto table_id = op_key.t.table_id();
        auto entry_id = op_key.eid;
        nas_acl_entry& entry = sw.get_entry (table_id, entry_id);

        NAS_ACL_LOG_BRIEF ("%sSwitch Id: %d, Table Id: %ld, Entry Id: %ld",
                           (is_rollbk_op) ? "** ROLLBACK **: " : "",
                           sw.id(), table_id, entry_id);

        // Apply Delete to NDI and SAI
        entry.commit_delete (is_rollbk_op);

        // WARNING !!! CANNOT throw error or exception beyond this point
        // since entry is already deleted in SAI

        if (!is_rollbk_op) {
            _cps_pack_entry (prev, obj, entry);
        }

        // Now save the entry in local cache. Also remove references to table/counter
        sw.remove_entry_from_table (table_id, entry_id);

        NAS_ACL_LOG_BRIEF ("Entry Deletion successful. Switch Id: %d, "
                           "Table Id: %ld, Entry Id: %ld",
                           sw.id(), table_id, entry_id);
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
