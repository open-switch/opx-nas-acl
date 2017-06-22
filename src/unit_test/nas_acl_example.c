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


/**
 * Create ACL entry to drop all packets received from Base IfIndex 15
 **/

#include "dell-base-acl.h"
#include "cps_api_events.h"
#include "cps_api_operation.h"
#include "cps_api_object_tools.h"
#include "cps_api_object_key.h"
#include "ds_common_types.h"
#include <stdio.h>


#define MAX_ACL_ATTRS  5

/* Commit simple Create transaction with 1 object and get its ID */
static bool _commit_and_get_id (cps_api_object_t obj, uint32_t id_tag,
                                uint64_t *p_out_id)
{
    if (cps_api_commit_one(cps_api_oper_CREATE, obj, 1, 0)!=cps_api_ret_code_OK) {
        return false;
    }
    cps_api_object_attr_t id_attr = cps_api_get_key_data (obj, id_tag);
    if (!id_attr) { return false; }
    *p_out_id = cps_api_object_attr_data_u64 (id_attr);
    return true;
}

static bool install_table (uint64_t* p_out_table_id)
{
    cps_api_object_t obj = cps_api_obj_tool_create (cps_api_qualifier_TARGET, BASE_ACL_TABLE_OBJ,
                                                    true);
    if (obj == NULL) { return false; }

    bool fail = false;
    do {
        cps_api_object_attr_add_u32 (obj, BASE_ACL_TABLE_STAGE, BASE_ACL_STAGE_INGRESS);
        cps_api_object_attr_add_u32 (obj, BASE_ACL_TABLE_PRIORITY, 9);
        cps_api_object_attr_add_u32 (obj, BASE_ACL_TABLE_ALLOWED_MATCH_FIELDS,
                                     BASE_ACL_MATCH_TYPE_IN_PORT);
        fail = !_commit_and_get_id (obj, BASE_ACL_TABLE_ID, p_out_table_id);
    } while (0);

    cps_api_object_delete (obj);

    if (!fail) {
        printf ("Successfully created table id 0x%lx\r\n", *p_out_table_id);
    }
    return !fail;
}

static bool install_entry_on_port (uint64_t table_id, hal_ifindex_t ifidx,
                                   uint64_t* p_out_entry_id)
{
    cps_api_object_t obj = cps_api_obj_tool_create (cps_api_qualifier_TARGET, BASE_ACL_ENTRY_OBJ,
                                                    true);
    if (obj == NULL) { return false; }

    bool fail = false;
    do {
        cps_api_set_key_data (obj, BASE_ACL_ENTRY_TABLE_ID, cps_api_object_ATTR_T_U64,
                              &table_id, sizeof (uint64_t));
        cps_api_object_attr_add_u32 (obj, BASE_ACL_ENTRY_PRIORITY, 100);

        cps_api_attr_id_t  attrs [MAX_ACL_ATTRS];
        uint_t attr_index = 0;
        uint_t list_index = 0;
        attrs[attr_index++] = BASE_ACL_ENTRY_MATCH;
        attrs[attr_index++] = list_index;
        attrs[attr_index] = BASE_ACL_ENTRY_MATCH_TYPE;

        uint32_t type = BASE_ACL_MATCH_TYPE_IN_PORT;
        if (!cps_api_object_e_add (obj, attrs, attr_index+1, cps_api_object_ATTR_T_U32,
                              &type, sizeof (uint32_t))) {
            fail = true;
            break;
        }
        attrs[attr_index] = BASE_ACL_ENTRY_MATCH_IN_PORT_VALUE;
        if (!cps_api_object_e_add (obj, attrs, attr_index+1, cps_api_object_ATTR_T_U32,
                              &ifidx, sizeof (uint32_t))) {
            fail = true;
            break;
        }

        attr_index = 0;
        list_index = 0;
        attrs[attr_index++] = BASE_ACL_ENTRY_ACTION;
        attrs[attr_index++] = list_index;
        attrs[attr_index] = BASE_ACL_ENTRY_ACTION_TYPE;

        type = BASE_ACL_ACTION_TYPE_PACKET_ACTION;
        if (!cps_api_object_e_add (obj, attrs, attr_index+1, cps_api_object_ATTR_T_U32,
                              &type, sizeof (uint32_t))) {
            fail = true;
            break;
        }
        attrs[attr_index] = BASE_ACL_ENTRY_ACTION_PACKET_ACTION_VALUE;
        type = BASE_ACL_PACKET_ACTION_TYPE_DROP;
        if (!cps_api_object_e_add (obj, attrs, attr_index+1, cps_api_object_ATTR_T_U32,
                              &type, sizeof (uint32_t))) {
            fail = true;
            break;
        }

        fail = !_commit_and_get_id (obj, BASE_ACL_ENTRY_ID, p_out_entry_id);

    } while (0);

    cps_api_object_delete (obj);

    if (!fail) {
        printf ("Successfully created entry id 0x%lx\r\n", *p_out_entry_id);
    }
    return !fail;
}

void main ()
{
    uint64_t table_id, entry_id;
    // First create ACL table to hold the ACL entry
    if (!install_table (&table_id)) {
        printf ("Table Creation failed\r\n");
    }
    if (!install_entry_on_port (table_id, 15, &entry_id)) {
        printf ("Entry Creation failed\r\n");
    }
}

/*
gcc src/unit_test/nas_acl_example.c -I ../workspace/debian/jessie/x86_64/sysroot/usr/include/ngos/ -L ../workspace/debian/jessie/x86_64/sysroot/opt/dell/os10/lib/ -l cps-api-common
 */
