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

#include "nas_acl_cps_ut.h"
#include "cps_api_object_key.h"
#include "cps_class_map.h"

/*** NAS ACL Main Control block ***/
nas_acl_ut_table_t g_nas_acl_ut_tables [NAS_ACL_UT_MAX_TABLES];

nas_acl_ut_table_t* find_table (nas_obj_id_t table_id)
{
    uint_t index;

    for (index = 0; index < NAS_ACL_UT_MAX_TABLES; index++) {
        if (g_nas_acl_ut_tables [index].table_id == table_id) {
            return &g_nas_acl_ut_tables [index];
        }
    }

    return NULL;
}

void nas_acl_ut_print_table (nas_acl_ut_table_t *p_table)
{
    std::set<BASE_ACL_MATCH_TYPE_t>::iterator it;
    uint_t index;
    uint_t count;

    ut_printf ("Switch: %d, Table-Name = %s, Id: %ld, Stage: %s, Priority: %d, "
               "Filter Count = %ld, NPU %ssent in Mod req\r\n",
               p_table->switch_id, p_table->name,
               p_table->table_id, NAS_ACL_UT_STAGE_TO_STR (p_table->stage),
               p_table->priority, p_table->filters.size (),
               (p_table->npu_sent_in_mod_req == true) ? "" : "NOT ");
    ut_printf ("----------------------------------------------------------------------\r\n");

    for (it = p_table->filters.begin (); it != p_table->filters.end (); ++it) {
       ut_printf ("   %2d - %s\r\n", *it, nas_acl_filter_t::type_name (*it));
    }

    index = 0;
    count = p_table->npu_list.size ();

    for (auto npu_id: p_table->npu_list) {
        ut_printf ("%s%d%s", (index == 0) ? "NPU List: " :"",
                   npu_id, (index == (count - 1)) ? "\r\n" :", ");
        index++;
    }
}

void nas_acl_ut_init_table_filters (int in_index, nas_acl_ut_table_t *p_table)
{
    BASE_ACL_MATCH_TYPE_t filter;
    int                   index;
    uint32_t              val;
    long int              count;

    p_table->filters.clear();

    if (nas_acl_ut_is_on_target ()) {

        p_table->filters.insert (BASE_ACL_MATCH_TYPE_SRC_IP);
        p_table->filters.insert (BASE_ACL_MATCH_TYPE_DST_IP);
        p_table->filters.insert (BASE_ACL_MATCH_TYPE_IP_PROTOCOL);
        p_table->filters.insert (BASE_ACL_MATCH_TYPE_L4_DST_PORT);
        if (in_index == 0 || in_index == 1) {
            p_table->filters.insert (BASE_ACL_MATCH_TYPE_IN_PORT);
        } else if (in_index == 2) {
            p_table->filters.insert (BASE_ACL_MATCH_TYPE_SRC_PORT);
            p_table->filters.insert (BASE_ACL_MATCH_TYPE_NEIGHBOR_DST_HIT);
            p_table->filters.insert (BASE_ACL_MATCH_TYPE_ROUTE_DST_HIT);
        }
    }
    else {
        if (in_index == 0) {

            for (index = NAS_ACL_UT_START_FILTER;
                 index <= NAS_ACL_UT_END_FILTER; index++) {

                filter = (BASE_ACL_MATCH_TYPE_t) index;

                if (!nas_acl_filter_is_type_valid (filter)) {
                    continue;
                }

                p_table->filters.insert (filter);
            }

            return;
        }

        count = (random () % 10) + 1;

        while (count > 0) {

            val = NAS_ACL_UT_START_FILTER + (random () % NAS_ACL_UT_NUM_FILTERS);
            filter = (BASE_ACL_MATCH_TYPE_t) val;

            if (!nas_acl_filter_is_type_valid (filter)) {
                continue;
            }

            p_table->filters.insert (filter);
            count--;
        }
    }
}

void nas_acl_ut_init_table_npu_list (nas_acl_ut_table_t *p_table)
{
    npu_id_t npu;

    p_table->npu_list.clear ();

    for (npu = 0; npu < NAS_ACL_UT_MAX_NPUS; npu++) {
        p_table->npu_list.insert (npu);
    }
}


bool nas_acl_ut_table_filter_list_find_and_clr (nas_acl_ut_table_t    *p_table,
                                                BASE_ACL_MATCH_TYPE_t  filter)
{
    std::set<BASE_ACL_MATCH_TYPE_t>::iterator it;

    it = p_table->filters.find (filter);

    if (it != p_table->filters.end ()) {
        p_table->filters.erase (it);

        return true;
    }

    return false;
}

bool nas_acl_ut_table_npu_list_find_and_clr (nas_acl_ut_table_t *p_table,
                                             uint_t              npu)
{
    std::set<npu_id_t>::iterator it;

    if (p_table->npu_list.size () == 0) {
        return true;
    }

    it = p_table->npu_list.find (npu);

    if (it != p_table->npu_list.end ()) {
        p_table->npu_list.erase (it);

        return true;
    }

    return false;
}

#define UT_TABLE_PRIORITY_BASE  100

void nas_acl_ut_init_tables ()
{
    nas_acl_ut_table_t *p_table;
    int                 index;

    for (index = 0; index < NAS_ACL_UT_MAX_TABLES; index++) {
        p_table = &g_nas_acl_ut_tables [index];

        p_table->switch_id = NAS_ACL_UT_DEF_SWITCH_ID;
        snprintf (p_table->name, sizeof (p_table->name) - 1, "Table-%d", index);
        p_table->stage = (index % 2 == 0)
            ? BASE_ACL_STAGE_INGRESS : BASE_ACL_STAGE_EGRESS;
        p_table->priority = UT_TABLE_PRIORITY_BASE + index;
        p_table->npu_sent_in_mod_req = false;

        nas_acl_ut_init_table_filters (index, p_table);
        nas_acl_ut_init_table_npu_list (p_table);
    }
}

void nas_acl_ut_extract_table_keys (cps_api_object_t  obj,
                                    nas_switch_id_t  *p_out_switch_id,
                                    nas_obj_id_t     *p_out_table_id,
                                    uint_t           *p_out_count)
{
    cps_api_object_attr_t table_id_attr = cps_api_get_key_data (obj,
                                                                BASE_ACL_TABLE_ID);

    *p_out_count = 0;

    if (table_id_attr) {
        (*p_out_count) ++;
        *p_out_table_id = cps_api_object_attr_data_u64 (table_id_attr);
        ut_printf ("%s(): Table Id: %ld \r\n", __FUNCTION__, *p_out_table_id);
    }
}

bool nas_acl_ut_fill_create_req (cps_api_transaction_params_t *params,
                                 nas_acl_ut_table_t           *p_table)
{
    cps_api_return_code_t rc;
    cps_api_object_t      obj;

    obj = cps_api_object_create ();

    if (obj == NULL) {
        ut_printf ("cps_api_object_create () failed. \r\n");
        return (false);
    }

    cps_api_key_from_attr_with_qual (cps_api_object_key (obj), BASE_ACL_TABLE_OBJ,
                                     cps_api_qualifier_TARGET);

    cps_api_object_attr_add_u32 (obj, BASE_ACL_TABLE_STAGE,
                                 p_table->stage);
    cps_api_object_attr_add_u32 (obj,
                                 BASE_ACL_TABLE_PRIORITY,
                                 p_table->priority);

    for (auto filter: p_table->filters) {
        cps_api_object_attr_add_u32 (obj,
                                     BASE_ACL_TABLE_ALLOWED_MATCH_FIELDS,
                                     filter);
    }

    for (auto npu: p_table->npu_list) {
        cps_api_object_attr_add_u32(obj, BASE_ACL_TABLE_NPU_ID_LIST, npu);
    }

    rc = cps_api_create (params, obj);

    if (rc != cps_api_ret_code_OK) {
        cps_api_object_delete (obj);
        ut_printf ("cps_api_create () failed. \r\n");
        return (false);
    }

    return (true);
}

bool nas_acl_ut_fill_modify_req (cps_api_transaction_params_t *params,
                                 nas_acl_ut_table_t           *p_table)
{
    cps_api_return_code_t rc;
    cps_api_object_t      obj;
    uint_t                npu_index;

    obj = cps_api_object_create ();

    if (obj == NULL) {
        ut_printf ("cps_api_object_create () failed. \r\n");
        return (false);
    }

    cps_api_key_from_attr_with_qual (cps_api_object_key (obj), BASE_ACL_TABLE_OBJ,
                                     cps_api_qualifier_TARGET);
    cps_api_set_key_data (obj, BASE_ACL_TABLE_ID, cps_api_object_ATTR_T_U64,
                          &p_table->table_id, sizeof (uint64_t));

    p_table->priority += 10;
    cps_api_object_attr_add_u32 (obj,
                                 BASE_ACL_TABLE_PRIORITY,
                                 p_table->priority);

    if (NAS_ACL_UT_MAX_NPUS != 1) {
        if (p_table->npu_list.size () == 0) {

            for (npu_index = 0; npu_index < NAS_ACL_UT_MAX_NPUS; npu_index++) {
                p_table->npu_list.insert (npu_index);
            }
        }
        else {
            p_table->npu_list.clear ();
        }
    }

    for (auto npu: p_table->npu_list) {
        cps_api_object_attr_add_u32(obj, BASE_ACL_TABLE_NPU_ID_LIST, npu);
        p_table->npu_sent_in_mod_req = true;
    }

    rc = cps_api_set (params, obj);

    if (rc != cps_api_ret_code_OK) {
        ut_printf ("cps_api_set () failed. \r\n");
        return (false);
    }

    return (true);
}

void nas_acl_ut_print_obj_attrs (cps_api_object_t obj, const char* function)
{
    cps_api_object_it_t it;
    cps_api_attr_id_t   attr_id;

    ut_printf ("Printing attributes in %s\r\n", function);
    for (cps_api_object_it_begin (obj, &it);
         cps_api_object_it_valid (&it); cps_api_object_it_next (&it)) {

        attr_id = cps_api_object_attr_id (it.attr);
        ut_printf ("%s(): ### Attribute %ld\r\n", __FUNCTION__, attr_id);
    }
}

bool nas_acl_ut_fill_delete_req (cps_api_transaction_params_t *params,
                                 nas_acl_ut_table_t           *p_table)
{
    cps_api_return_code_t rc;
    cps_api_object_t      obj;

    obj = cps_api_object_create ();

    if (obj == NULL) {
        ut_printf ("cps_api_object_create () failed. \r\n");
        return (false);
    }

    cps_api_key_from_attr_with_qual (cps_api_object_key (obj), BASE_ACL_TABLE_OBJ,
                                     cps_api_qualifier_TARGET);

    cps_api_set_key_data (obj, BASE_ACL_TABLE_ID, cps_api_object_ATTR_T_U64,
                          &p_table->table_id, sizeof (uint64_t));

    rc = cps_api_delete (params, obj);

    if (rc != cps_api_ret_code_OK) {
        ut_printf ("cps_api_delete () failed. \r\n");
        return (false);
    }

    return (true);
}

bool nas_acl_ut_validate_op (cps_api_object_t    obj,
                             uint_t              op,
                             nas_acl_ut_table_t *p_table)
{
    nas_acl_ut_table_t  tmp_table;
    cps_api_object_it_t it;
    cps_api_attr_id_t   attr_id;
    nas_switch_id_t     switch_id;
    nas_obj_id_t        table_id;
    uint_t              count;
    uint32_t            data32;

    ut_printf ("%s(): %s request \r\n",
               __FUNCTION__, NAS_ACL_UT_OP_TO_STR (op));

    tmp_table = *p_table;
    p_table->npu_sent_in_mod_req = false;

    nas_acl_ut_extract_table_keys (obj, &switch_id, &table_id, &count);

    if (count != 1) {
        ut_printf ("%s(): Invalid key count: %d.\r\n",
                   __FUNCTION__, count);
        return (false);
    }

    if (op == NAS_ACL_UT_CREATE) {
        p_table->table_id = table_id;

        ut_printf ("\r\n    [%s  Validation Passed. Switch Id: %d, Table Id: %ld]\r\n\n",
                   NAS_ACL_UT_OP_TO_STR (op), switch_id, table_id);
        return (true);
    }
    else {

        if ((table_id  != tmp_table.table_id)) {

            ut_printf ("%s(): NOT-CREATE: Ids mismatch. "
                       "In Switch Id: %d, Switch Id: %d., "
                       "In Table Id: %ld, Table Id: %ld.\r\n",
                       __FUNCTION__, tmp_table.switch_id,
                       switch_id, tmp_table.table_id, table_id);
            return (false);
        }
    }

    for (cps_api_object_it_begin (obj, &it);
         cps_api_object_it_valid (&it); cps_api_object_it_next (&it)) {

        attr_id = cps_api_object_attr_id (it.attr);
        data32  = cps_api_object_attr_data_u32 (it.attr);

        switch (attr_id) {

            case BASE_ACL_TABLE_STAGE:
                if (op == NAS_ACL_UT_MODIFY) {
                    ut_printf ("%s(): STAGE Attr present. Op : MODIFY \r\n",
                               __FUNCTION__);
                    return (false);
                }

                if (data32 != tmp_table.stage) {
                    ut_printf ("%s(): Invalid Stage. Old: %d, New: %d.\r\n",
                               __FUNCTION__, tmp_table.stage, data32);
                    return (false);
                }
                break;

            case BASE_ACL_TABLE_PRIORITY:
                if (data32 != tmp_table.priority) {
                    ut_printf ("%s(): Invalid Priority. Old: %d, New: %d.\r\n",
                               __FUNCTION__, tmp_table.priority, data32);
                    return (false);
                }
                break;

            case BASE_ACL_TABLE_ALLOWED_MATCH_FIELDS:
                if (op == NAS_ACL_UT_MODIFY) {
                    ut_printf ("%s(): MATCH_FIELDS Attr present. Op: MODIFY \r\n",
                               __FUNCTION__);
                    return (false);
                }

                if (nas_acl_ut_table_filter_list_find_and_clr (&tmp_table,
                                                               (BASE_ACL_MATCH_TYPE_t) data32)
                    == false)  {
                    ut_printf ("%s(): Invalid Filter: %d (%s).\r\n", __FUNCTION__,
                               data32,
                               nas_acl_filter_t::type_name (static_cast
                                                            <BASE_ACL_MATCH_TYPE_t>
                                                            (data32)));
                    return (false);
                }
                break;

            case BASE_ACL_TABLE_NPU_ID_LIST:
                if (nas_acl_ut_table_npu_list_find_and_clr (&tmp_table, data32)
                    == false)  {
                    ut_printf ("%s(): Invalid Npu: %d.\r\n", __FUNCTION__, data32);
                    return (false);
                }
                break;

            default:
                ut_printf ("%s(): Unknown attribute %ld.\r\n", __FUNCTION__, attr_id);
                break;
        }
    }

    if ((op == NAS_ACL_UT_MODIFY) && (tmp_table.npu_sent_in_mod_req == false)) {
        tmp_table.npu_list.clear ();
    }

    if (op != NAS_ACL_UT_MODIFY) {
        if (tmp_table.filters.size () != 0) {
            ut_printf ("%s(): Incomplete get. Filter Count: %ld\r\n",
                       __FUNCTION__, tmp_table.filters.size ());
            return (false);
        }
    }

    if (tmp_table.npu_list.size () != 0) {
        ut_printf ("%s(): Incomplete get. Npu Count: %ld.\r\n",
                   __FUNCTION__, tmp_table.npu_list.size ());
        return (false);
    }

    ut_printf ("\r\n    [%s  Validation Passed. Switch Id: %d, Table Id: %ld]\r\n\n",
               NAS_ACL_UT_OP_TO_STR (op), switch_id, table_id);
    return (true);
}

bool nas_acl_ut_table_create ()
{
    cps_api_transaction_params_t  params;
    cps_api_object_t              prev_obj;
    cps_api_return_code_t         rc;
    nas_acl_ut_table_t           *p_table;
    uint_t                        index;

    ut_printf ("%s()\r\n", __FUNCTION__);

    for (index = 0; index < NAS_ACL_UT_MAX_TABLES; index++) {

        p_table = &g_nas_acl_ut_tables [index];
        printf("Create table %d: name %s id %lu stage %d priority %d\n", index,
                p_table->name, p_table->table_id, p_table->stage, p_table->priority);

        if (cps_api_transaction_init (&params) != cps_api_ret_code_OK) {
            ut_printf ("cps_api_transaction_init () failed. \r\n");
            return (false);
        }

        if (nas_acl_ut_fill_create_req (&params, p_table) == false) {
            return (false);
        }

        rc = nas_acl_ut_cps_api_commit (&params, false);

        if (rc != cps_api_ret_code_OK) {
            ut_printf ("cps_api_commit () failed. \r\n");
            return (false);
        }

        prev_obj = cps_api_object_list_get (params.prev, 0);

        if (nas_acl_ut_validate_op (prev_obj,
                                    NAS_ACL_UT_CREATE, p_table) == false) {
            return (false);
        }

        rc = cps_api_transaction_close (&params);

        if (rc != cps_api_ret_code_OK) {
            ut_printf ("cps_api_transaction_close () failed. \r\n");
            return (false);
        }
    }

    ut_printf ("********** ACL Table Creation TEST PASSED ********** .\r\n\n");
    return (true);
}

bool nas_acl_ut_table_modify ()
{
    cps_api_transaction_params_t  params;
    cps_api_object_t              obj;
    cps_api_return_code_t         rc;
    nas_acl_ut_table_t            old_table;
    nas_acl_ut_table_t           *p_table;
    uint_t                        index;

    ut_printf ("%s()\r\n", __FUNCTION__);

    for (index = 0; index < NAS_ACL_UT_MAX_TABLES; index++) {

        p_table = &g_nas_acl_ut_tables [index];

        if (cps_api_transaction_init (&params) != cps_api_ret_code_OK) {
            ut_printf ("cps_api_transaction_init () failed. \r\n");
            return (false);
        }

        old_table = *p_table;
        if (nas_acl_ut_fill_modify_req (&params, p_table) == false) {
            return (false);
        }

        rc = nas_acl_ut_cps_api_commit (&params, false);

        if (rc != cps_api_ret_code_OK) {
            ut_printf ("cps_api_commit () failed. \r\n");
            return (false);
        }

        obj = cps_api_object_list_get (params.prev, 0);

        if (obj == NULL) {
            ut_printf ("%s(): Roll back object NOT present.\r\n", __FUNCTION__);
            return (false);
        }

        if (nas_acl_ut_validate_op (obj, NAS_ACL_UT_MODIFY,
                                    &old_table) == false) {
            return (false);
        }

        rc = cps_api_transaction_close (&params);

        if (rc != cps_api_ret_code_OK) {
            ut_printf ("cps_api_transaction_close () failed. \r\n");
            return (false);
        }
    }

    ut_printf ("********** ACL Table Modify TEST PASSED ********** .\r\n\n");
    return (true);
}

bool nas_acl_ut_table_delete ()
{
    cps_api_transaction_params_t  params;
    cps_api_object_t              obj;
    cps_api_return_code_t         rc;
    nas_acl_ut_table_t           *p_table;
    uint_t                        index;

    ut_printf ("%s()\r\n", __FUNCTION__);

    for (index = 0; index < NAS_ACL_UT_MAX_TABLES; index++) {

        p_table = &g_nas_acl_ut_tables [index];

        if (cps_api_transaction_init (&params) != cps_api_ret_code_OK) {
            ut_printf ("cps_api_transaction_init () failed. \r\n");
            return (false);
        }

        if (nas_acl_ut_fill_delete_req (&params, p_table) == false) {
            return (false);
        }

        rc = nas_acl_ut_cps_api_commit (&params, false);

        if (rc != cps_api_ret_code_OK) {
            ut_printf ("cps_api_commit () failed. \r\n");
            return (false);
        }

        obj = cps_api_object_list_get (params.prev, 0);
        printf ("Obtained Prev obj %p\r\n", obj);
        if (obj == NULL) {
            ut_printf ("%s(): Roll back object NOT present.\r\n", __FUNCTION__);
            return (false);
        }

        if (nas_acl_ut_validate_op (obj, NAS_ACL_UT_DELETE, p_table) == false) {
            return (false);
        }

        rc = cps_api_transaction_close (&params);

        if (rc != cps_api_ret_code_OK) {
            ut_printf ("cps_api_transaction_close () failed. \r\n");
            return (false);
        }
    }

    ut_printf ("********** ACL Table Delete TEST PASSED ********** .\r\n\n");
    return (true);
}

bool nas_acl_ut_table_get ()
{
    cps_api_get_params_t   params;
    cps_api_return_code_t  rc;
    nas_acl_ut_table_t    *p_table;
    uint_t                 index;

    ut_printf ("%s()\r\n", __FUNCTION__);

    for (index = 0; index < NAS_ACL_UT_MAX_TABLES; index++) {

        p_table = &g_nas_acl_ut_tables [index];

        if (cps_api_get_request_init (&params) != cps_api_ret_code_OK) {
            ut_printf ("cps_api_get_request_init () failed. \r\n");
            return (false);
        }

        ut_printf ("%s(): Switch Id: %d, Table Id : %ld \r\n",
                   __FUNCTION__, p_table->switch_id, p_table->table_id);

        cps_api_object_t obj = cps_api_object_list_create_obj_and_append (params.filters);

        cps_api_key_from_attr_with_qual (cps_api_object_key (obj), BASE_ACL_TABLE_OBJ,
                                         cps_api_qualifier_TARGET);
        cps_api_set_key_data (obj, BASE_ACL_TABLE_ID, cps_api_object_ATTR_T_U64,
                              &p_table->table_id, sizeof (uint64_t));

        rc = nas_acl_ut_cps_api_get (&params, 0);

        if (rc != cps_api_ret_code_OK) {
            ut_printf ("cps_api_get () failed. \r\n");
            return (false);
        }

        obj = cps_api_object_list_get (params.list, 0);

        if (obj == NULL) {
            ut_printf ("%s(): Get resp object NOT present.\r\n",
                       __FUNCTION__);
            return (false);
        }

        if (nas_acl_ut_validate_op (obj, NAS_ACL_UT_GET, p_table) == false) {
            return (false);
        }

        rc = cps_api_get_request_close (&params);

        if (rc != cps_api_ret_code_OK) {
            ut_printf ("cps_api_request_close () failed. \r\n");
            return (false);
        }
    }

    ut_printf ("********** ACL Table Get TEST PASSED ********** .\r\n\n");
    return (true);
}

