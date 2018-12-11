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

/*
 * nas_acl_cps_counter_ut.cpp
 *
 */

#include "nas_acl_cps_ut.h"
#include "cps_api_object_key.h"
#include "cps_class_map.h"

static const std::unordered_map <uint32_t, ut_npu_list_t, std::hash<int>>
_stats_map_input =
{
    {1, {0}}
};

bool nas_acl_ut_counter_delete (nas_acl_ut_table_t& table)
{
    ut_printf ("---------- ACL Counter Delete STARTED ------------\r\n");

    cps_api_transaction_params_t  params;

    if (cps_api_transaction_init (&params) != cps_api_ret_code_OK) {
        return cps_api_ret_code_ERR;
    }

    for (auto& counter_id: table.counter_ids) {
        cps_api_object_t obj = cps_api_object_create ();
        if (obj == NULL) {
            ut_printf ("cps_api_object_create () failed. \r\n");
            return (false);
        }

        cps_api_key_from_attr_with_qual (cps_api_object_key (obj), BASE_ACL_COUNTER_OBJ,
                                         cps_api_qualifier_TARGET);
        cps_api_set_key_data (obj, BASE_ACL_COUNTER_TABLE_ID, cps_api_object_ATTR_T_U64,
                              &table.table_id, sizeof (uint64_t));
        cps_api_set_key_data (obj, BASE_ACL_COUNTER_ID, cps_api_object_ATTR_T_U64,
                              &counter_id, sizeof (uint64_t));

        cps_api_delete (&params, obj);
    }

    if (nas_acl_ut_cps_api_commit (&params,
                                   false) != cps_api_ret_code_OK) {
        ut_printf ("Counter Delete commit failed. \r\n");
        return false;
    }

    ut_printf ("********** ACL Counter Delete PASSED ********** .\r\n\n");
    return true;
}

bool nas_acl_ut_create_counters (cps_api_transaction_params_t&  params,
        const ut_entry_list_t&  entry_list, bool pkt, bool byte)
{
    ut_printf ("---------- ACL Counter Create STARTED ------------\r\n");

    for (auto& ut_kv: entry_list) {
        auto& ut_entry = ut_kv.second;

        cps_api_object_t obj = cps_api_object_create ();
        if (obj == NULL) {
            ut_printf ("cps_api_object_create () failed. \r\n");
            return (false);
        }

        cps_api_key_from_attr_with_qual (cps_api_object_key (obj), BASE_ACL_COUNTER_OBJ,
                                         cps_api_qualifier_TARGET);
        cps_api_set_key_data (obj, BASE_ACL_COUNTER_TABLE_ID, cps_api_object_ATTR_T_U64,
                              &ut_entry.table_id, sizeof (uint64_t));

        if (pkt) {
            cps_api_object_attr_add_u32 (obj, BASE_ACL_COUNTER_TYPES, BASE_ACL_COUNTER_TYPE_PACKET);
        }

        if (byte) {
            cps_api_object_attr_add_u32 (obj, BASE_ACL_COUNTER_TYPES, BASE_ACL_COUNTER_TYPE_BYTE);
        }

        cps_api_create (&params, obj);
    }

    if (nas_acl_ut_cps_api_commit (&params,
                                   false) != cps_api_ret_code_OK) {
         return false;
    }

    ut_printf ("********** ACL Counter Create PASSED ********** .\r\n\n");
    return true;
}

bool nas_acl_ut_extract_counter_ids (const cps_api_transaction_params_t& params,
                                     std::vector<nas_obj_id_t>& counter_ids)
{
    for (size_t ix = 0; ix < cps_api_object_list_size (params.change_list); ix++) {
        cps_api_object_t obj = cps_api_object_list_get (params.change_list, ix);
        auto attr = cps_api_get_key_data (obj, BASE_ACL_COUNTER_ID);
        counter_ids.push_back (cps_api_object_attr_data_u64 (attr));
    }
    return true;
}

bool nas_acl_ut_entry_count_enable (nas_acl_ut_table_t& table, bool pkt, bool byte)
{
    cps_api_transaction_params_t  params;
    ut_entry_list_t&  entry_list = table.entries;

    if (cps_api_transaction_init (&params) != cps_api_ret_code_OK) {
        return cps_api_ret_code_ERR;
    }

    if (!nas_acl_ut_create_counters (params, entry_list, pkt, byte)) {
        cps_api_transaction_close (&params);
        return false;
    }

    if (!nas_acl_ut_extract_counter_ids (params, table.counter_ids)) {
        cps_api_transaction_close (&params);
        return false;
    }

    if (cps_api_transaction_close (&params) != cps_api_ret_code_OK) {
         return false;
    }

    if (cps_api_transaction_init (&params) != cps_api_ret_code_OK) {
        return cps_api_ret_code_ERR;
    }

    int i = 0;
    bool rc = true;

    ut_printf ("---------- ACL Entry Set Counter STARTED ------------\r\n");

    for (auto& ut_kv: entry_list) {
        auto& ut_entry = ut_kv.second;

        ut_action_t       action;
        action.type = BASE_ACL_ACTION_TYPE_SET_COUNTER;
        action.val_list.push_back(table.counter_ids.at (i));
        ut_entry.action_list.insert (action);

        cps_api_object_t obj = cps_api_object_create ();
        if (obj == NULL) {
            ut_printf ("cps_api_object_create () failed. \r\n");
            rc = false;
            break;
        }
        cps_api_object_guard g(obj);

        cps_api_key_from_attr_with_qual (cps_api_object_key (obj), BASE_ACL_ENTRY_OBJ,
                                         cps_api_qualifier_TARGET);
        cps_api_set_key_data (obj, BASE_ACL_ENTRY_TABLE_ID, cps_api_object_ATTR_T_U64,
                              &ut_entry.table_id, sizeof (uint64_t));
        cps_api_set_key_data (obj, BASE_ACL_ENTRY_ID, cps_api_object_ATTR_T_U64,
                              &ut_entry.entry_id, sizeof (uint64_t));

        if (ut_fill_entry_action (obj, ut_entry) == false) {
            ut_printf ("ut_fill_entry_action () failed. \r\n");
            rc = false;
            break;
        }

        cps_api_set (&params, obj);
        g.release ();
    }

    if (nas_acl_ut_cps_api_commit (&params,
                                   false) != cps_api_ret_code_OK) {
        rc = false;
    }

    if (cps_api_transaction_close (&params) != cps_api_ret_code_OK) {
        rc = false;
    }

    if (rc) ut_printf ("********** ACL Entry Counter Action Set SUCCESSFULLY ********** .\r\n\n");
    return rc;
}

void nas_acl_ut_extract_stats_keys (cps_api_object_t  obj,
                                          nas_switch_id_t  *p_out_switch_id,
                                          nas_obj_id_t     *p_out_table_id,
                                          nas_obj_id_t     *p_out_entry_id,
                                          uint_t           *p_out_count)
{
    cps_api_object_attr_t table_id_attr = cps_api_get_key_data (obj,
                                                                BASE_ACL_STATS_TABLE_ID);
    cps_api_object_attr_t entry_id_attr = cps_api_get_key_data (obj,
                                                                BASE_ACL_STATS_COUNTER_ID);

    *p_out_count = 0;

    if (table_id_attr) {
        (*p_out_count) ++;
        *p_out_table_id = cps_api_object_attr_data_u64 (table_id_attr);
        ut_printf ("%s(): Table Id: %ld \r\n", __FUNCTION__, *p_out_table_id);
    }
    if (entry_id_attr) {
        (*p_out_count) ++;
        *p_out_entry_id = cps_api_object_attr_data_u64 (entry_id_attr);
        ut_printf ("%s(): Entry Id: %ld \r\n", __FUNCTION__, *p_out_entry_id);
    }
}

static bool validate_stats_get (cps_api_object_t     obj,
                                      const ut_entry_t&    entry,
                                      const ut_npu_list_t& npu_list)
{
    cps_api_object_it_t    it;
    cps_api_attr_id_t      attr_id;
    nas_switch_id_t        switch_id;
    uint32_t               npu;
    nas_obj_id_t           table_id;
    nas_obj_id_t           entry_id;
    static const int       num_allowed_keys = 2;
    uint_t                 count;

    nas_acl_ut_extract_stats_keys (obj, &switch_id, &table_id, &entry_id, &count);

    if (count != num_allowed_keys) {
        ut_printf ("%s(): FAILED. Key Count: %d\r\n", __FUNCTION__, count);
        return false;
    }

    if ((table_id  != entry.table_id)  ||
        (entry_id  != entry.entry_id))
    {
        ut_printf ("%s(): [Invalid Keys] Switch Id: %d, Table Id: %ld, ""Entry Id: %ld\r\n",
                   __FUNCTION__, switch_id, table_id, entry_id);

        ut_printf ("%s(): [Expected Keys] Switch Id: %d, Table Id: %ld, Entry Id: %ld\r\n",
                   __FUNCTION__, entry.switch_id, entry.table_id, entry.entry_id);
        return false;
    }

    ut_printf ("%s(): Switch Id: %d, Table Id: %ld, Entry Id: %ld\r\n",
               __FUNCTION__, switch_id, table_id, entry_id);

    ut_npu_list_t rcvd_npulist;

    for (cps_api_object_it_begin (obj, &it);
         cps_api_object_it_valid (&it); cps_api_object_it_next (&it)) {

        attr_id = cps_api_object_attr_id (it.attr);

        switch (attr_id) {

            case BASE_ACL_STATS_MATCHED_BYTES:
                {
                uint64_t byte_count = cps_api_object_attr_data_u64 (it.attr);
                ut_printf ("%s(): Byte count = %ld\r\n", __FUNCTION__, byte_count);
                }
                break;

            case BASE_ACL_STATS_MATCHED_PACKETS:
                {
                uint64_t pkt_count = cps_api_object_attr_data_u64 (it.attr);
                ut_printf ("%s(): Pkt count = %ld\r\n", __FUNCTION__, pkt_count);
                }
                break;

            case BASE_ACL_STATS_NPU_ID_LIST:
                {
                    npu = cps_api_object_attr_data_u32 (it.attr);
                    rcvd_npulist.insert (npu);
                }
                break;

            default:
                // Unknown attribute. Ignore silently.
                ut_printf ("%s(): Unknown attribute %ld \r\n", __FUNCTION__, attr_id);
                break;
        }
    }
    if (npu_list.empty()) {
        ut_printf ("Received NPU List: \n   ");
        for (auto npu: rcvd_npulist) {
            ut_printf ("%d, ", npu);
        }
        ut_printf ("\n");
        if (!entry.npu_list.empty()) {
            return (rcvd_npulist != entry.npu_list);
        }
    } else {
        if (rcvd_npulist != npu_list) {
            ut_printf ("Received NPU List: \n   ");
            for (auto npu: rcvd_npulist) {
                ut_printf ("%d, ", npu);
            }
            ut_printf ("\n Expected Custom NPU List: \n   ");
            for (auto npu: npu_list) {
                ut_printf ("%d, ", npu);
            }
            ut_printf ("\n");
            return false;
        }
    }

    return true;
}

static bool nas_acl_ut_stats_get (nas_acl_ut_table_t& table,
                                  uint32_t            ut_stat_index,
                                  uint32_t            entry_index)
{
    ut_printf ("---------- ACL Stats Get TEST STARTED -----------\r\n");

    auto entry_kv = table.entries.find (entry_index);
    if (entry_kv == table.entries.end ()) {
        return false;
    }
    ut_entry_t& entry = entry_kv->second;

    ut_npu_list_t npu_list;
    auto ut_entry_stat_kv = _stats_map_input.find (ut_stat_index);

    if (ut_entry_stat_kv != _stats_map_input.end()) {
        npu_list = ut_entry_stat_kv->second;
    }

    cps_api_get_params_t   params;
    cps_api_return_code_t  rc;

    ut_printf ("%s()\r\n", __FUNCTION__);

    if (cps_api_get_request_init (&params) != cps_api_ret_code_OK) {
        ut_printf ("cps_api_get_request_init () failed. \r\n");
        return (false);
    }

    ut_printf ("%s(): Switch Id: %d, Table Id : %ld, Entry Id: %ld \r\n",
               __FUNCTION__, entry.switch_id, entry.table_id, entry.entry_id);

    cps_api_object_t  obj = cps_api_object_list_create_obj_and_append (params.filters);
    if (obj==NULL) return cps_api_ret_code_ERR;

    cps_api_key_from_attr_with_qual (cps_api_object_key (obj), BASE_ACL_STATS_OBJ,
                                     cps_api_qualifier_TARGET);
    cps_api_set_key_data (obj, BASE_ACL_STATS_TABLE_ID, cps_api_object_ATTR_T_U64,
                          &entry.table_id, sizeof (uint64_t));
    cps_api_set_key_data (obj, BASE_ACL_STATS_COUNTER_ID, cps_api_object_ATTR_T_U64,
                          &entry.entry_id, sizeof (uint64_t));

    for (auto npu: npu_list) {
        cps_api_object_attr_add_u32(obj, BASE_ACL_STATS_NPU_ID_LIST, npu);
    }

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

    if (validate_stats_get (obj, entry, npu_list) == false) {
        return (false);
    }

    if (cps_api_get_request_close (&params) != cps_api_ret_code_OK) {
        ut_printf ("cps_api_request_close () failed. \r\n");
        return (false);
    }

    ut_printf ("********** ACL Stats Get TEST PASSED ************\r\n\n");
    return (true);
}

static bool nas_acl_ut_entry_count_set (nas_acl_ut_table_t& table,
                                        uint32_t            ut_stat_index,
                                        uint32_t            entry_index,
                                        bool                pkt_count,
                                        bool                byte_count)
{
    cps_api_transaction_params_t params;
    ut_filter_t                  filter;

    ut_printf ("---------- ACL Stats Set TEST STARTED -----------\r\n");

    auto entry_kv = table.entries.find (entry_index);
    if (entry_kv == table.entries.end ()) {
        return false;
    }
    ut_entry_t& entry = entry_kv->second;

    ut_npu_list_t npu_list;
    auto ut_entry_stat_kv = _stats_map_input.find (ut_stat_index);

    if (ut_entry_stat_kv != _stats_map_input.end()) {
        npu_list = ut_entry_stat_kv->second;
    }

    if (cps_api_transaction_init (&params) != cps_api_ret_code_OK) {
        return cps_api_ret_code_ERR;
    }

    cps_api_object_t obj = cps_api_object_create ();

    if (obj == NULL) {
        ut_printf ("cps_api_object_create () failed. \r\n");
        return (false);
    }

    cps_api_key_from_attr_with_qual (cps_api_object_key (obj), BASE_ACL_STATS_OBJ,
                                     cps_api_qualifier_TARGET);
    cps_api_set_key_data (obj, BASE_ACL_STATS_TABLE_ID, cps_api_object_ATTR_T_U64,
                          &entry.table_id, sizeof (uint64_t));
    cps_api_set_key_data (obj, BASE_ACL_STATS_COUNTER_ID, cps_api_object_ATTR_T_U64,
                          &entry.entry_id, sizeof (uint64_t));

    for (auto npu: npu_list) {
        cps_api_object_attr_add_u32(obj, BASE_ACL_STATS_NPU_ID_LIST, npu);
    }

    if (pkt_count) cps_api_object_attr_add_u64(obj, BASE_ACL_STATS_MATCHED_PACKETS, 0);
    if (byte_count) cps_api_object_attr_add_u64(obj, BASE_ACL_STATS_MATCHED_BYTES, 0);

    if (cps_api_set (&params, obj) != cps_api_ret_code_OK) {
        cps_api_object_delete (obj);
        ut_printf ("cps_api_set () failed. \r\n");
        return (false);
    }

    if (nas_acl_ut_cps_api_commit (&params,
                                   false) != cps_api_ret_code_OK) {
        ut_printf ("********** ACL Stats Set TEST FAILED ********** .\r\n\n");
        return false;
    }

    if (cps_api_transaction_close (&params) != cps_api_ret_code_OK) {
        return false;
    }

    ut_printf ("********** ACL Stats Set TEST PASSED ********** .\r\n\n");
    return true;
}

bool nas_acl_ut_stats_get_test (nas_acl_ut_table_t& table)
{
    if (!nas_acl_ut_stats_get (table, 1, 1))
        return false;
    if (!nas_acl_ut_stats_get (table, 2, 1))
        return false;
    return true;
}

bool nas_acl_ut_stats_set_test (nas_acl_ut_table_t& table)
{
    ut_printf ("### Setting packet count on specific NPUs\r\n");
    if (!nas_acl_ut_entry_count_set (table, 1, 1, true, false))
        return false;
    ut_printf ("### Setting byte count on specific NPUs - Should fail\r\n");
    if (nas_acl_ut_entry_count_set (table, 1, 1, false, true))
        return false;
    ut_printf ("### Setting pkt count on all NPUs \r\n");
    if (!nas_acl_ut_entry_count_set (table, 2, 1, true, false))
        return false;

    return true;
}

bool nas_acl_ut_stats_set_test_full (nas_acl_ut_table_t& table)
{
    ut_printf ("### Setting packet count on specific NPUs\r\n");
    if (!nas_acl_ut_entry_count_set (table, 1, 1, true, false))
        return false;

    ut_printf ("### Getting byte count from all NPUs to validate\r\n");
    if (!nas_acl_ut_stats_get (table, 2, 1))
        return false;
    ut_printf ("### Setting byte count on specific NPUs - should fail \r\n");
    if (nas_acl_ut_entry_count_set (table, 1, 1, false, true))
        return false;

    ut_printf ("### Enable byte count \r\n");
    if (!nas_acl_ut_entry_count_enable (table, true, true))
        return false;
    ut_printf ("### Now Setting byte count on specific NPUs - should succeed \r\n");
    if (!nas_acl_ut_entry_count_set (table, 1, 1, false, true))
        return false;
    ut_printf ("### Setting pkt and byte count on all NPUs \r\n");
    if (!nas_acl_ut_entry_count_set (table, 2, 1, true, true))
        return false;

    return true;
}
