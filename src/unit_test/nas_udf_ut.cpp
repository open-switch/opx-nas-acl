#include <iostream>
#include <vector>

#include "cps_api_operation.h"
#include "cps_api_object_key.h"
#include "cps_class_map.h"
#include "nas_types.h"
#include "dell-base-acl.h"
#include "dell-base-udf.h"
#include "ietf-inet-types.h"

#include "gtest/gtest.h"

using namespace std;
using dump_object_cb_t = void (*)(cps_api_object_t);

static nas_obj_id_t g_group_id = 0, g_group_id_1 = 0;
static nas_obj_id_t g_non_tun_match_id = 0, g_tun_match_id = 0;
static nas_obj_id_t g_udf_id = 0, g_udf_id_1 = 0;
static nas_obj_id_t g_acl_table_id = 0;
static nas_obj_id_t g_acl_entry_id = 0;
static nas_obj_id_t g_acl_counter_id = 0;
static vector<nas_obj_id_t> g_obj_id_list;

static bool nas_udf_ut_create_group(BASE_UDF_UDF_GROUP_TYPE_t type,
                                    size_t length,
                                    nas_obj_id_t* group_id)
{
    cps_api_transaction_params_t trans;
    if (cps_api_transaction_init(&trans) != cps_api_ret_code_OK) {
        return false;
    }
    cps_api_object_t obj = cps_api_object_create();
    if (obj == nullptr) {
        return false;
    }
    if (!cps_api_key_from_attr_with_qual(cps_api_object_key(obj),
                                         BASE_UDF_UDF_GROUP_OBJ,
                                         cps_api_qualifier_TARGET)) {
        return false;
    }

    cps_api_object_attr_add_u32(obj, BASE_UDF_UDF_GROUP_TYPE, type);
    uint8_t len = (uint8_t)length;
    cps_api_object_attr_add(obj, BASE_UDF_UDF_GROUP_LENGTH, &len, 1);

    if (cps_api_create(&trans, obj) != cps_api_ret_code_OK) {
        cout << "Failed to add object to transaction for creation" << endl;
        return false;
    }

    if (cps_api_commit(&trans) != cps_api_ret_code_OK) {
        cout << "Failed to commit" << endl;
        cps_api_transaction_close(&trans);
        return false;
    }

    cps_api_object_t ret_obj = cps_api_object_list_get(trans.change_list, 0);
    cps_api_object_attr_t attr = cps_api_get_key_data(ret_obj,
                                                      BASE_UDF_UDF_GROUP_ID);
    if (attr == nullptr) {
        cout << "No UDF Group ID returned" << endl;
        cps_api_transaction_close(&trans);
        return false;
    }

    if (group_id) {
        *group_id = cps_api_object_attr_data_u64(attr);
    }
    cout << "NAS returns UDF Group ID: " << *group_id << endl;
    cps_api_transaction_close(&trans);

    return true;
}

using udf_match_attr_t = union {
    struct {
        uint16_t l2_type;
        uint16_t l2_type_mask;
        uint8_t l3_type;
        uint8_t l3_type_mask;
    };
    struct {
        INET_IP_VERSION_t inner_type;
        INET_IP_VERSION_t outer_type;
    };
};

static bool nas_udf_ut_create_match(uint8_t priority,
                                    BASE_UDF_UDF_MATCH_TYPE_t type,
                                    const udf_match_attr_t* match_attr,
                                    nas_obj_id_t* match_id)
{
    cps_api_transaction_params_t trans;
    if (cps_api_transaction_init(&trans) != cps_api_ret_code_OK) {
        return false;
    }
    cps_api_object_t obj = cps_api_object_create();
    if (obj == nullptr) {
        return false;
    }
    if (!cps_api_key_from_attr_with_qual(cps_api_object_key(obj),
                                         BASE_UDF_UDF_MATCH_OBJ,
                                         cps_api_qualifier_TARGET)) {
        return false;
    }

    uint8_t prio = (uint8_t)priority;
    cps_api_object_attr_add(obj, BASE_UDF_UDF_MATCH_PRIORITY, &prio, 1);
    cps_api_object_attr_add_u32(obj, BASE_UDF_UDF_MATCH_TYPE, type);
    if (type != BASE_UDF_UDF_MATCH_TYPE_NON_TUNNEL &&
        type != BASE_UDF_UDF_MATCH_TYPE_GRE_TUNNEL) {
        cout << "Unknow UDF match type: " << type << endl;
        return false;
    }
    if (match_attr != nullptr) {
        if (type == BASE_UDF_UDF_MATCH_TYPE_NON_TUNNEL) {
            cps_api_object_attr_add_u16(obj,
                                        BASE_UDF_UDF_MATCH_NON_TUNNEL_VALUE_L2_TYPE,
                                        match_attr->l2_type);
            cps_api_object_attr_add_u16(obj,
                                        BASE_UDF_UDF_MATCH_NON_TUNNEL_VALUE_L2_TYPE_MASK,
                                        match_attr->l2_type_mask);
            cps_api_object_attr_add(obj,
                                    BASE_UDF_UDF_MATCH_NON_TUNNEL_VALUE_L3_TYPE,
                                    &match_attr->l3_type, 1);
            cps_api_object_attr_add(obj,
                                    BASE_UDF_UDF_MATCH_NON_TUNNEL_VALUE_L3_TYPE_MASK,
                                    &match_attr->l3_type_mask, 1);
        } else if (type == BASE_UDF_UDF_MATCH_TYPE_GRE_TUNNEL) {
            cps_api_object_attr_add_u32(obj,
                                        BASE_UDF_UDF_MATCH_GRE_TUNNEL_VALUE_INNER_TYPE,
                                        match_attr->inner_type);
            if (match_attr->outer_type != INET_IP_VERSION_UNKNOWN) {
                cps_api_object_attr_add_u32(obj,
                                            BASE_UDF_UDF_MATCH_GRE_TUNNEL_VALUE_OUTER_TYPE,
                                            match_attr->outer_type);
            }
       }
    }

    if (cps_api_create(&trans, obj) != cps_api_ret_code_OK) {
        cout << "Failed to add object to transaction for creation" << endl;
        return false;
    }

    if (cps_api_commit(&trans) != cps_api_ret_code_OK) {
        cout << "Failed to commit" << endl;
        cps_api_transaction_close(&trans);
        return false;
    }

    cps_api_object_t ret_obj = cps_api_object_list_get(trans.change_list, 0);
    cps_api_object_attr_t attr = cps_api_get_key_data(ret_obj,
                                                      BASE_UDF_UDF_MATCH_ID);
    if (attr == nullptr) {
        cout << "No UDF Match ID returned" << endl;
        cps_api_transaction_close(&trans);
        return false;
    }

    if (match_id) {
        *match_id = cps_api_object_attr_data_u64(attr);
    }
    cout << "NAS returns UDF Match ID: " << *match_id << endl;
    cps_api_transaction_close(&trans);

    return true;
}

static bool nas_udf_ut_create_udf(nas_obj_id_t group_id, nas_obj_id_t match_id,
                                  BASE_UDF_UDF_BASE_TYPE_t base,
                                  bool default_offset, size_t offset,
                                  const uint8_t* hash_mask, size_t mask_len,
                                  nas_obj_id_t* udf_id)
{
    cps_api_transaction_params_t trans;
    if (cps_api_transaction_init(&trans) != cps_api_ret_code_OK) {
        return false;
    }
    cps_api_object_t obj = cps_api_object_create();
    if (obj == nullptr) {
        return false;
    }
    if (!cps_api_key_from_attr_with_qual(cps_api_object_key(obj),
                                         BASE_UDF_UDF_OBJ,
                                         cps_api_qualifier_TARGET)) {
        return false;
    }

    cout << "Create UDF with Group " << group_id << " Match " << match_id << endl;
    cps_api_object_attr_add_u64(obj, BASE_UDF_UDF_OBJ_GROUP_ID, group_id);
    cps_api_object_attr_add_u64(obj, BASE_UDF_UDF_OBJ_MATCH_ID, match_id);
    cps_api_object_attr_add_u32(obj, BASE_UDF_UDF_OBJ_BASE, base);
    if (!default_offset) {
        cps_api_object_attr_add_u32(obj, BASE_UDF_UDF_OBJ_OFFSET, offset);
    }
    if (hash_mask != nullptr && mask_len > 0) {
        for (size_t idx = 0; idx < mask_len; idx ++) {
            cps_api_object_attr_add(obj, BASE_UDF_UDF_OBJ_HASH_MASK, &hash_mask[idx], 1);
        }
    }

    if (cps_api_create(&trans, obj) != cps_api_ret_code_OK) {
        cout << "Failed to add object to transaction for creation" << endl;
        return false;
    }

    if (cps_api_commit(&trans) != cps_api_ret_code_OK) {
        cout << "Failed to commit" << endl;
        cps_api_transaction_close(&trans);
        return false;
    }

    cps_api_object_t ret_obj = cps_api_object_list_get(trans.change_list, 0);
    cps_api_object_attr_t attr = cps_api_get_key_data(ret_obj,
                                                      BASE_UDF_UDF_OBJ_ID);
    if (attr == nullptr) {
        cout << "No UDF ID returned" << endl;
        cps_api_transaction_close(&trans);
        return false;
    }

    if (udf_id) {
        *udf_id = cps_api_object_attr_data_u64(attr);
    }
    cout << "NAS returns UDF ID: " << *udf_id << endl;
    cps_api_transaction_close(&trans);

    return true;
}

using match_field_list_t = vector<BASE_ACL_MATCH_TYPE_t>;
using udf_group_id_list_t = vector<nas_obj_id_t>;

static bool nas_udf_ut_create_acl_table(size_t priority,
                                        match_field_list_t& allowed_match_fields,
                                        udf_group_id_list_t& udf_group_ids,
                                        nas_obj_id_t* table_id)
{
    cps_api_transaction_params_t trans;
    if (cps_api_transaction_init(&trans) != cps_api_ret_code_OK) {
        return false;
    }
    cps_api_object_t obj = cps_api_object_create();
    if (obj == nullptr) {
        return false;
    }
    if (!cps_api_key_from_attr_with_qual(cps_api_object_key(obj),
                                         BASE_ACL_TABLE_OBJ,
                                         cps_api_qualifier_TARGET)) {
        return false;
    }
    cps_api_object_attr_add_u32(obj, BASE_ACL_TABLE_PRIORITY, priority);
    uint32_t stage = (uint32_t)BASE_ACL_STAGE_INGRESS;
    cps_api_object_attr_add_u32(obj, BASE_ACL_TABLE_STAGE, stage);
    for (auto grp_id: udf_group_ids) {
        cps_api_object_attr_add_u64(obj, BASE_ACL_TABLE_UDF_GROUP_LIST, grp_id);
    }
    for (auto allowed_field: allowed_match_fields) {
        cps_api_object_attr_add_u32(obj, BASE_ACL_TABLE_ALLOWED_MATCH_FIELDS,
                                    allowed_field);
    }

    if (cps_api_create(&trans, obj) != cps_api_ret_code_OK) {
        cout << "Failed to add object to transaction for creation" << endl;
        return false;
    }

    if (cps_api_commit(&trans) != cps_api_ret_code_OK) {
        cout << "Failed to commit" << endl;
        cps_api_transaction_close(&trans);
        return false;
    }

    cps_api_object_t ret_obj = cps_api_object_list_get(trans.change_list, 0);
    cps_api_object_attr_t attr = cps_api_get_key_data(ret_obj,
                                                      BASE_ACL_TABLE_ID);
    if (attr == nullptr) {
        cout << "No ACL Table ID returned" << endl;
        cps_api_transaction_close(&trans);
        return false;
    }

    if (table_id) {
        *table_id = cps_api_object_attr_data_u64(attr);
    }
    cout << "NAS returns ACL Table ID: " << *table_id << endl;
    cps_api_transaction_close(&trans);

    return true;
}

static bool add_match_type(cps_api_object_t obj, uint_t index,
                           BASE_ACL_MATCH_TYPE_t type)
{
    cps_api_attr_id_t ids[] = {BASE_ACL_ENTRY_MATCH, (cps_api_attr_id_t)index,
                               BASE_ACL_ENTRY_MATCH_TYPE};
    size_t id_cnt = sizeof(ids) / sizeof(ids[0]);
    return cps_api_object_e_add(obj, ids, id_cnt, cps_api_object_ATTR_T_U32,
                                &type, sizeof(uint32_t));
}

static bool add_action_type(cps_api_object_t obj, uint_t index,
                            BASE_ACL_ACTION_TYPE_t type)
{
    cps_api_attr_id_t ids[] = {BASE_ACL_ENTRY_ACTION, (cps_api_attr_id_t)index,
                               BASE_ACL_ENTRY_ACTION_TYPE};
    size_t id_cnt = sizeof(ids) / sizeof(ids[0]);
    return cps_api_object_e_add(obj, ids, id_cnt, cps_api_object_ATTR_T_U32,
                                &type, sizeof(uint32_t));
}

static bool add_string_match_int(cps_api_object_t obj, size_t index,
                                 uint32_t attr_id, const char* str)
{
    cps_api_attr_id_t ids[] = {BASE_ACL_ENTRY_MATCH, (cps_api_attr_id_t)index,
                               attr_id};
    size_t id_cnt = sizeof(ids) / sizeof(ids[0]);
    if (!cps_api_object_e_add(obj, ids, id_cnt, cps_api_object_ATTR_T_BIN,
                              str, strlen(str) + 1)) {
        return false;
    }

    return true;
}

#define ADD_STRING_MATCH(obj, index, attr_id, str) \
    add_string_match_int(obj, index, (uint32_t)attr_id, str)

static bool add_mac_match_int(cps_api_object_t obj, size_t index,
                              uint32_t parent_id, uint32_t addr_id, uint32_t mask_id,
                              hal_mac_addr_t addr, hal_mac_addr_t mask)
{
    cps_api_attr_id_t ids[] = {BASE_ACL_ENTRY_MATCH, (cps_api_attr_id_t)index,
                               parent_id, addr_id};
    size_t id_cnt = sizeof(ids) / sizeof(ids[0]);
    if (!cps_api_object_e_add(obj, ids, id_cnt, cps_api_object_ATTR_T_BIN,
                              addr, sizeof(hal_mac_addr_t))) {
        return false;
    }

    ids[id_cnt - 1] = mask_id;
    if (!cps_api_object_e_add(obj, ids, id_cnt, cps_api_object_ATTR_T_BIN,
                              mask, sizeof(hal_mac_addr_t))) {
        return false;
    }

    return true;
}

#define ADD_MAC_MATCH(obj, index, prefix, addr, mask) \
    add_mac_match_int(obj, index, (uint32_t)prefix, \
            (uint32_t)prefix##_ADDR, (uint32_t)prefix##_MASK, \
            addr, mask)

static bool add_udf_match_int(cps_api_object_t obj, size_t index, uint32_t parent_id,
                              uint32_t grp_attr_id, uint32_t data_id, uint32_t mask_id,
                              nas_obj_id_t udf_grp_id, uint8_t* bytes, uint8_t* masks,
                              size_t length)
{
    cps_api_attr_id_t ids[] = {BASE_ACL_ENTRY_MATCH, (cps_api_attr_id_t)index,
                               parent_id, grp_attr_id};
    size_t id_cnt = sizeof(ids) / sizeof(ids[0]);
    if (!cps_api_object_e_add(obj, ids, id_cnt, cps_api_object_ATTR_T_U64,
                              &udf_grp_id, sizeof(uint64_t))) {
        return false;
    }

    ids[id_cnt - 1] = data_id;
    if (!cps_api_object_e_add(obj, ids, id_cnt, cps_api_object_ATTR_T_BIN,
                              bytes, length)) {
        return false;
    }

    ids[id_cnt - 1] = mask_id;
    if (!cps_api_object_e_add(obj, ids, id_cnt, cps_api_object_ATTR_T_BIN,
                              masks, length)) {
        return false;
    }

    return true;
}

#define ADD_UDF_MATCH(obj, index, prefix, grp_id, bytes, masks, len) \
    add_udf_match_int(obj, index, (uint32_t)prefix, \
            (uint32_t)prefix##_UDF_GROUP_ID, (uint32_t)prefix##_MATCH_DATA, \
            (uint32_t)prefix##_MATCH_MASK, \
            grp_id, bytes, masks, len)

static bool add_action_value_u32_int(cps_api_object_t obj, size_t index,
                                     uint32_t attr_id, uint32_t act_value)
{
    cps_api_attr_id_t ids[] = {BASE_ACL_ENTRY_ACTION, (cps_api_attr_id_t)index,
                               attr_id};
    size_t id_cnt = sizeof(ids) / sizeof(ids[0]);
    if (!cps_api_object_e_add(obj, ids, id_cnt, cps_api_object_ATTR_T_U32,
                              &act_value, sizeof(uint32_t))) {
        return false;
    }

    return true;
}

#define ADD_ACTION_VALUE_U32(obj, index, prefix, act_val) \
    add_action_value_u32_int(obj, index, prefix, act_val)

static bool add_action_value_u64_int(cps_api_object_t obj, size_t index,
                                     uint32_t attr_id, uint64_t act_value)
{
    cps_api_attr_id_t ids[] = {BASE_ACL_ENTRY_ACTION, (cps_api_attr_id_t)index,
                               attr_id};
    size_t id_cnt = sizeof(ids) / sizeof(ids[0]);
    if (!cps_api_object_e_add(obj, ids, id_cnt, cps_api_object_ATTR_T_U64,
                              &act_value, sizeof(uint64_t))) {
        return false;
    }

    return true;
}

#define ADD_ACTION_VALUE_U64(obj, index, prefix, act_val) \
    add_action_value_u64_int(obj, index, prefix, act_val)

#define ADD_ENTRY_ITEM_VALUE(obj, index, prefix, add_func, args...) \
    add_func(obj, index, prefix, ##args)

static bool nas_acl_ut_add_acl_entry_match(cps_api_object_t obj)
{
    uint_t index = 0;

    if (!add_match_type(obj, index, BASE_ACL_MATCH_TYPE_SRC_MAC)) {
        return false;
    }
    hal_mac_addr_t mac_addr = {0x1, 0x2, 0x3, 0x4, 0x5, 0x6};
    hal_mac_addr_t addr_mask = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
    if (!ADD_ENTRY_ITEM_VALUE(obj, index, BASE_ACL_ENTRY_MATCH_SRC_MAC_VALUE,
                              ADD_MAC_MATCH, mac_addr, addr_mask)) {
        return false;
    }

    index ++;
    if (!add_match_type(obj, index, BASE_ACL_MATCH_TYPE_IN_INTF)) {
        return false;
    }
    const char *if_name = "e101-002-0";
    if (!ADD_ENTRY_ITEM_VALUE(obj, index, BASE_ACL_ENTRY_MATCH_IN_INTF_VALUE,
                              ADD_STRING_MATCH, if_name)) {
        return false;
    }

    index ++;
    if (!add_match_type(obj, index, BASE_ACL_MATCH_TYPE_UDF)) {
        return false;
    }
    uint8_t udf_bytes[] = {0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88};
    uint8_t udf_masks[] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
    if (!ADD_ENTRY_ITEM_VALUE(obj, index, BASE_ACL_ENTRY_MATCH_UDF_VALUE,
                              ADD_UDF_MATCH, g_group_id, udf_bytes, udf_masks, 8)) {
        return false;
    }

    index ++;
    if (!add_match_type(obj, index, BASE_ACL_MATCH_TYPE_UDF)) {
        return false;
    }
    if (!ADD_ENTRY_ITEM_VALUE(obj, index, BASE_ACL_ENTRY_MATCH_UDF_VALUE,
                              ADD_UDF_MATCH, g_group_id_1, udf_bytes, udf_masks, 3)) {
        return false;
    }

    return true;
}

static bool nas_acl_ut_add_acl_entry_action(cps_api_object_t obj)
{
    uint_t index = 0;

    if (!add_action_type(obj, index, BASE_ACL_ACTION_TYPE_PACKET_ACTION)) {
        return false;
    }
    if (!ADD_ENTRY_ITEM_VALUE(obj, index, BASE_ACL_ENTRY_ACTION_PACKET_ACTION_VALUE,
            ADD_ACTION_VALUE_U32, (uint32_t)BASE_ACL_PACKET_ACTION_TYPE_COPY_TO_CPU)) {
        return false;
    }

    index ++;
    if (!add_action_type(obj, index, BASE_ACL_ACTION_TYPE_SET_USER_TRAP_ID)) {
        return false;
    }
    if (!ADD_ENTRY_ITEM_VALUE(obj, index, BASE_ACL_ENTRY_ACTION_SET_USER_TRAP_ID_VALUE,
            ADD_ACTION_VALUE_U32, 0x1234)) {
        return false;
    }

    index ++;
    if (!add_action_type(obj, index, BASE_ACL_ACTION_TYPE_SET_COUNTER)) {
        return false;
    }
    if (!ADD_ENTRY_ITEM_VALUE(obj, index, BASE_ACL_ENTRY_ACTION_COUNTER_VALUE,
            ADD_ACTION_VALUE_U64, (uint64_t)g_acl_counter_id)) {
        return false;
    }

    return true;
}

static bool nas_udf_ut_create_acl_entry(nas_obj_id_t table_id, size_t priority,
                                        nas_obj_id_t* entry_id)
{
    cps_api_transaction_params_t trans;
    if (cps_api_transaction_init(&trans) != cps_api_ret_code_OK) {
        return false;
    }
    cps_api_object_t obj = cps_api_object_create();
    if (obj == nullptr) {
        return false;
    }
    if (!cps_api_key_from_attr_with_qual(cps_api_object_key(obj),
                                         BASE_ACL_ENTRY_OBJ,
                                         cps_api_qualifier_TARGET)) {
        return false;
    }
    cps_api_object_attr_add_u64(obj, BASE_ACL_ENTRY_TABLE_ID, table_id);
    cps_api_object_attr_add_u32(obj, BASE_ACL_ENTRY_PRIORITY, priority);
    if (!nas_acl_ut_add_acl_entry_match(obj)) {
        return false;
    }

    if (!nas_acl_ut_add_acl_entry_action(obj)) {
        return false;
    }

    if (cps_api_create(&trans, obj) != cps_api_ret_code_OK) {
        cout << "Failed to add object to transaction for creation" << endl;
        return false;
    }

    if (cps_api_commit(&trans) != cps_api_ret_code_OK) {
        cout << "Failed to commit" << endl;
        cps_api_transaction_close(&trans);
        return false;
    }

    cps_api_object_t ret_obj = cps_api_object_list_get(trans.change_list, 0);
    cps_api_object_attr_t attr = cps_api_get_key_data(ret_obj,
                                                      BASE_ACL_ENTRY_ID);
    if (attr == nullptr) {
        cout << "No ACL Entry ID returned" << endl;
        cps_api_transaction_close(&trans);
        return false;
    }

    if (entry_id) {
        *entry_id = cps_api_object_attr_data_u64(attr);
    }
    cout << "NAS returns ACL Entry ID: " << *entry_id << endl;
    cps_api_transaction_close(&trans);

    return true;
}

static bool nas_udf_ut_create_acl_counter(nas_obj_id_t table_id,
                                          bool byte_cntr, bool packet_cntr,
                                          nas_obj_id_t* counter_id)
{
    if (!byte_cntr && !packet_cntr) {
        return false;
    }

    cps_api_transaction_params_t trans;
    if (cps_api_transaction_init(&trans) != cps_api_ret_code_OK) {
        return false;
    }
    cps_api_object_t obj = cps_api_object_create();
    if (obj == nullptr) {
        return false;
    }
    if (!cps_api_key_from_attr_with_qual(cps_api_object_key(obj),
                                         BASE_ACL_COUNTER_OBJ,
                                         cps_api_qualifier_TARGET)) {
        return false;
    }
    cps_api_object_attr_add_u64(obj, BASE_ACL_COUNTER_TABLE_ID, table_id);
    if (byte_cntr) {
        cps_api_object_attr_add_u32(obj, BASE_ACL_COUNTER_TYPES,
                                    BASE_ACL_COUNTER_TYPE_BYTE);
    }
    if (packet_cntr) {
        cps_api_object_attr_add_u32(obj, BASE_ACL_COUNTER_TYPES,
                                    BASE_ACL_COUNTER_TYPE_PACKET);
    }

    if (cps_api_create(&trans, obj) != cps_api_ret_code_OK) {
        cout << "Failed to add object to transaction for creation" << endl;
        return false;
    }

    if (cps_api_commit(&trans) != cps_api_ret_code_OK) {
        cout << "Failed to commit" << endl;
        cps_api_transaction_close(&trans);
        return false;
    }

    cps_api_object_t ret_obj = cps_api_object_list_get(trans.change_list, 0);
    cps_api_object_attr_t attr = cps_api_get_key_data(ret_obj,
                                                      BASE_ACL_COUNTER_ID);
    if (attr == nullptr) {
        cout << "No ACL Counter ID returned" << endl;
        cps_api_transaction_close(&trans);
        return false;
    }

    if (counter_id) {
        *counter_id = cps_api_object_attr_data_u64(attr);
    }
    cout << "NAS returns ACL Counter ID: " << *counter_id << endl;
    cps_api_transaction_close(&trans);

    return true;
}

static bool nas_udf_ut_delete_object(nas_obj_id_t nas_id,
                                     cps_api_attr_id_t key_attr_id,
                                     nas_obj_id_t nas_id_1,
                                     cps_api_attr_id_t key_attr_id_1,
                                     cps_api_attr_id_t obj_attr_id)
{
    cps_api_transaction_params_t trans;
    if (cps_api_transaction_init(&trans) != cps_api_ret_code_OK) {
        return false;
    }
    cps_api_object_t obj = cps_api_object_create();
    if (obj == nullptr) {
        return false;
    }
    if (!cps_api_key_from_attr_with_qual(cps_api_object_key(obj),
                                         obj_attr_id,
                                         cps_api_qualifier_TARGET)) {
        return false;
    }
    cps_api_set_key_data(obj, key_attr_id, cps_api_object_ATTR_T_U64,
                         &nas_id, sizeof(uint64_t));
    if (nas_id_1 != 0) {
        cps_api_set_key_data(obj, key_attr_id_1, cps_api_object_ATTR_T_U64,
                             &nas_id_1, sizeof(uint64_t));
    }
    if (cps_api_delete(&trans, obj) != cps_api_ret_code_OK) {
        cout << "Failed to add object to transaction for delete" << endl;
        return false;
    }

    if (cps_api_commit(&trans) != cps_api_ret_code_OK) {
        cout << "Failed to commit" << endl;
        cps_api_transaction_close(&trans);
        return false;
    }

    cps_api_transaction_close(&trans);

    return true;
}

static bool nas_udf_ut_delete_group(nas_obj_id_t group_id)
{
    return nas_udf_ut_delete_object(group_id, BASE_UDF_UDF_GROUP_ID,
                                    0, 0,
                                    BASE_UDF_UDF_GROUP_OBJ);
}

static bool nas_udf_ut_delete_match(nas_obj_id_t match_id)
{
    return nas_udf_ut_delete_object(match_id, BASE_UDF_UDF_MATCH_ID,
                                    0, 0,
                                    BASE_UDF_UDF_MATCH_OBJ);
}

static bool nas_udf_ut_delete_udf(nas_obj_id_t udf_id)
{
    return nas_udf_ut_delete_object(udf_id, BASE_UDF_UDF_OBJ_ID,
                                    0, 0,
                                    BASE_UDF_UDF_OBJ_OBJ);
}

static bool nas_udf_ut_delete_acl_table(nas_obj_id_t table_id)
{
    return nas_udf_ut_delete_object(table_id, BASE_ACL_TABLE_ID,
                                    0, 0,
                                    BASE_ACL_TABLE_OBJ);
}

static bool nas_udf_ut_delete_acl_entry(nas_obj_id_t entry_id,
                                        nas_obj_id_t table_id)
{
    return nas_udf_ut_delete_object(entry_id, BASE_ACL_ENTRY_ID,
                                    table_id, BASE_ACL_ENTRY_TABLE_ID,
                                    BASE_ACL_ENTRY_OBJ);
}

static bool nas_udf_ut_delete_acl_counter(nas_obj_id_t counter_id,
                                          nas_obj_id_t table_id)
{
    return nas_udf_ut_delete_object(counter_id, BASE_ACL_COUNTER_ID,
                                    table_id, BASE_ACL_COUNTER_TABLE_ID,
                                    BASE_ACL_COUNTER_OBJ);
}

static bool nas_udf_ut_get_object(nas_obj_id_t nas_id,
                                  cps_api_attr_id_t key_attr_id,
                                  cps_api_attr_id_t obj_attr_id,
                                  dump_object_cb_t dump_func)
{
    cps_api_get_params_t gp;
    if (cps_api_get_request_init(&gp) != cps_api_ret_code_OK) {
        return false;
    }

    cps_api_object_t obj = cps_api_object_list_create_obj_and_append(gp.filters);
    if (obj == nullptr) {
        return false;
    }

    if (!cps_api_key_from_attr_with_qual(cps_api_object_key(obj),
                                         obj_attr_id,
                                         cps_api_qualifier_TARGET)) {
        return false;
    }

    if (nas_id != 0) {
        cps_api_set_key_data(obj, key_attr_id, cps_api_object_ATTR_T_U64,
                             &nas_id, sizeof(uint64_t));
    }

    if (cps_api_get(&gp) == cps_api_ret_code_OK) {
        size_t mx = cps_api_object_list_size(gp.list);
        for (size_t ix = 0; ix < mx; ix ++) {
            if (dump_func != nullptr) {
                cout << "Attributes of returned object " << ix << endl;
                dump_func(cps_api_object_list_get(gp.list, ix));
                cout << endl;
            }
        }
    }

    return true;
}

static void dump_udf_group_obj(cps_api_object_t cps_obj)
{
    if (cps_obj == nullptr) {
        return;
    }
    cps_api_object_attr_t attr = cps_api_get_key_data(cps_obj,
                                                      BASE_UDF_UDF_GROUP_ID);
    if (attr == nullptr) {
        cout << "No UDF Group ID attribute" << endl;
        return;
    }
    cout << " UDF Group ID     : " << cps_api_object_attr_data_u64(attr) << endl;
    attr = cps_api_object_attr_get(cps_obj, BASE_UDF_UDF_GROUP_TYPE);
    if (attr == nullptr) {
        cout << "No type attribute" << endl;
        return;
    }
    BASE_UDF_UDF_GROUP_TYPE_t type_val =
            (BASE_UDF_UDF_GROUP_TYPE_t)cps_api_object_attr_data_u32(attr);
    const char *type_name = "";
    switch(type_val) {
    case BASE_UDF_UDF_GROUP_TYPE_GENERIC:
        type_name = "GENERIC";
        break;
    case BASE_UDF_UDF_GROUP_TYPE_HASH:
        type_name = "HASH";
        break;
    default:
        cout << "Unknown type: " << type_val << endl;
        return;
    }
    cout << " UDF Group Type   : " << type_name << endl;
    attr = cps_api_object_attr_get(cps_obj, BASE_UDF_UDF_GROUP_LENGTH);
    if (attr == nullptr) {
        cout << "No length attribute" << endl;
        return;
    }
    size_t length = ((uint8_t*)cps_api_object_attr_data_bin(attr))[0];
    cout << " UDF Group Length : " << length << endl;
    vector<nas_obj_id_t> udf_id_list;
    cps_api_object_it_t it;
    for (cps_api_object_it_begin(cps_obj, &it);
         cps_api_object_it_attr_walk(&it, BASE_UDF_UDF_GROUP_UDF_ID_LIST);
         cps_api_object_it_next(&it)) {
         udf_id_list.push_back(cps_api_object_attr_data_u64(it.attr));
    }
    if (udf_id_list.size() > 0) {
        cout << " UDF ID List      : ";
        for (auto udf_id: udf_id_list) {
            cout << udf_id << " ";
        }
        cout << endl;
    }
}

static bool nas_udf_ut_get_group(nas_obj_id_t group_id)
{
    return nas_udf_ut_get_object(group_id, BASE_UDF_UDF_GROUP_ID,
                                 BASE_UDF_UDF_GROUP_OBJ,
                                 dump_udf_group_obj);
}

static const char *ip_version_name(INET_IP_VERSION_t ip_version)
{
    if (ip_version == INET_IP_VERSION_IPV4) {
        return "IPv4";
    } else if (ip_version == INET_IP_VERSION_IPV6) {
        return "IPv6";
    }

    return "N/A";
}

static void dump_udf_match_obj(cps_api_object_t cps_obj)
{
    if (cps_obj == nullptr) {
        return;
    }
    cps_api_object_attr_t attr = cps_api_get_key_data(cps_obj,
                                                      BASE_UDF_UDF_MATCH_ID);
    if (attr == nullptr) {
        cout << "No UDF Match ID attribute" << endl;
        return;
    }
    cout << " UDF Match ID     : " << cps_api_object_attr_data_u64(attr) << endl;
    attr = cps_api_object_attr_get(cps_obj, BASE_UDF_UDF_MATCH_PRIORITY);
    if (attr == nullptr) {
        cout << "No priority attribute" << endl;
        return;
    }
    uint8_t prio = ((uint8_t*)cps_api_object_attr_data_bin(attr))[0];
    cout << " Priority         : " << (uint_t)prio << endl;
    attr = cps_api_object_attr_get(cps_obj, BASE_UDF_UDF_MATCH_TYPE);
    if (attr == nullptr) {
        cout << "No type attribute" << endl;
        return;
    }
    BASE_UDF_UDF_MATCH_TYPE_t type_val =
            (BASE_UDF_UDF_MATCH_TYPE_t)cps_api_object_attr_data_u32(attr);
    switch(type_val) {
    case BASE_UDF_UDF_MATCH_TYPE_NON_TUNNEL:
    {
        cout << " Match Type       : NON_TUNNEL" << endl;
        attr = cps_api_object_attr_get(cps_obj,
                                       BASE_UDF_UDF_MATCH_NON_TUNNEL_VALUE_L2_TYPE);
        cout.setf(ios::hex, ios::basefield);
        if (attr != nullptr) {
            cout << " Ether Type       : " << "0x" << cps_api_object_attr_data_u16(attr) << endl;
        }
        attr = cps_api_object_attr_get(cps_obj,
                                       BASE_UDF_UDF_MATCH_NON_TUNNEL_VALUE_L2_TYPE_MASK);
        if (attr != nullptr) {
            cout << " Ether Type Mask  : " << "0x" << cps_api_object_attr_data_u16(attr) << endl;
        }
        uint8_t bval;
        attr = cps_api_object_attr_get(cps_obj,
                                       BASE_UDF_UDF_MATCH_NON_TUNNEL_VALUE_L3_TYPE);
        if (attr != nullptr) {
            bval = ((uint8_t*)cps_api_object_attr_data_bin(attr))[0];
            cout << " IP Protocol      : " << "0x" << (uint_t)bval << endl;
        }
        attr = cps_api_object_attr_get(cps_obj,
                                       BASE_UDF_UDF_MATCH_NON_TUNNEL_VALUE_L3_TYPE_MASK);
        if (attr != nullptr) {
            bval = ((uint8_t*)cps_api_object_attr_data_bin(attr))[0];
            cout << " IP Protocol Mask : " << "0x" << (uint_t)bval << endl;
        }
        cout.unsetf(ios::basefield);
        break;
    }
    case BASE_UDF_UDF_MATCH_TYPE_GRE_TUNNEL:
    {
        cout << " Match Type       : GRE_TUNNEL" << endl;
        INET_IP_VERSION_t ip_ver;
        attr = cps_api_object_attr_get(cps_obj,
                                       BASE_UDF_UDF_MATCH_GRE_TUNNEL_VALUE_INNER_TYPE);
        if (attr != nullptr) {
            ip_ver = (INET_IP_VERSION_t)cps_api_object_attr_data_u32(attr);
            cout << " Inner Type      : " << ip_version_name(ip_ver) << endl;
        }
        attr = cps_api_object_attr_get(cps_obj,
                                       BASE_UDF_UDF_MATCH_GRE_TUNNEL_VALUE_OUTER_TYPE);
        if (attr != nullptr) {
            ip_ver = (INET_IP_VERSION_t)cps_api_object_attr_data_u32(attr);
            cout << " Outer Type      : " << ip_version_name(ip_ver) << endl;
        }
        break;
    }
    default:
        cout << "Unknown type: " << type_val << endl;
        return;
    }

}

static bool nas_udf_ut_get_match(nas_obj_id_t match_id)
{
    return nas_udf_ut_get_object(match_id, BASE_UDF_UDF_MATCH_ID,
                                 BASE_UDF_UDF_MATCH_OBJ,
                                 dump_udf_match_obj);
}

static void dump_udf_obj(cps_api_object_t cps_obj)
{
    if (cps_obj == nullptr) {
        return;
    }
    cps_api_object_attr_t attr = cps_api_get_key_data(cps_obj,
                                                      BASE_UDF_UDF_OBJ_ID);
    if (attr == nullptr) {
        cout << "No UDF ID attribute" << endl;
        return;
    }
    cout << " UDF ID      : " << cps_api_object_attr_data_u64(attr) << endl;
    attr = cps_api_object_attr_get(cps_obj, BASE_UDF_UDF_OBJ_GROUP_ID);
    if (attr == nullptr) {
        cout << "No Group ID attribute" << endl;
        return;
    }
    cout << " Group ID    : " << cps_api_object_attr_data_u64(attr) << endl;
    attr = cps_api_object_attr_get(cps_obj, BASE_UDF_UDF_OBJ_MATCH_ID);
    if (attr == nullptr) {
        cout << "No Match ID attribute" << endl;
        return;
    }
    cout << " Match ID    : " << cps_api_object_attr_data_u64(attr) << endl;

    attr = cps_api_object_attr_get(cps_obj, BASE_UDF_UDF_OBJ_BASE);
    if (attr == nullptr) {
        cout << "No base attribute" << endl;
        return;
    }
    BASE_UDF_UDF_BASE_TYPE_t base =
            (BASE_UDF_UDF_BASE_TYPE_t)cps_api_object_attr_data_u32(attr);
    cout << " Base        : ";
    switch(base) {
    case BASE_UDF_UDF_BASE_TYPE_L2:
        cout << "L2";
        break;
    case BASE_UDF_UDF_BASE_TYPE_L3:
        cout << "L3";
        break;
    case BASE_UDF_UDF_BASE_TYPE_L4:
        cout << "L4";
        break;
    default:
        cout << "";
        break;
    }
    cout << endl;
    attr = cps_api_object_attr_get(cps_obj, BASE_UDF_UDF_OBJ_OFFSET);
    if (attr == nullptr) {
        cout << "No offset attribute" << endl;
        return;
    }
    cout << " Offset      : " << cps_api_object_attr_data_u32(attr) << endl;
    vector<uint8_t> hash_mask;
    cps_api_object_it_t it;
    for (cps_api_object_it_begin(cps_obj, &it);
         cps_api_object_it_attr_walk(&it, BASE_UDF_UDF_OBJ_HASH_MASK);
         cps_api_object_it_next(&it)) {
         hash_mask.push_back(((uint8_t*)cps_api_object_attr_data_bin(it.attr))[0]);
    }
    if (hash_mask.size() > 0) {
        cout << " Hash Mask   : ";
        cout.setf(ios::hex, ios::basefield);
        for (auto mask: hash_mask) {
            cout << "0x" << (uint_t)mask << " ";
        }
        cout << endl;
        cout.unsetf(ios::basefield);
    }
}

static bool nas_udf_ut_get_udf(nas_obj_id_t udf_id)
{
    return nas_udf_ut_get_object(udf_id, BASE_UDF_UDF_OBJ_ID,
                                 BASE_UDF_UDF_OBJ_OBJ,
                                 dump_udf_obj);
}

TEST(nas_udf_group, create_udf_group)
{
    ASSERT_TRUE(nas_udf_ut_create_group(
                            BASE_UDF_UDF_GROUP_TYPE_GENERIC, 6,
                            &g_group_id));
}

TEST(nas_udf_group, get_udf_group_all)
{
    ASSERT_TRUE(nas_udf_ut_get_group(0));
}

TEST(nas_udf_group, get_udf_group_by_id)
{
    if (g_group_id == 0) {
        ASSERT_TRUE(g_obj_id_list.size() > 0);
        g_group_id = g_obj_id_list[0];
    }
    ASSERT_TRUE(nas_udf_ut_get_group(g_group_id));
}

TEST(nas_udf_group, delete_udf_group)
{
    if (g_group_id == 0) {
        ASSERT_TRUE(g_obj_id_list.size() > 0);
        g_group_id = g_obj_id_list[0];
    }
    ASSERT_TRUE(nas_udf_ut_delete_group(g_group_id));
    g_group_id = 0;
}

TEST(nas_udf_match, create_udf_match_non_tunnel)
{
    udf_match_attr_t attr;
    attr.l2_type = 0x800;
    attr.l2_type_mask = 0xffff;
    attr.l3_type = 0x0;
    attr.l3_type_mask = 0x0;
    ASSERT_TRUE(nas_udf_ut_create_match(1, BASE_UDF_UDF_MATCH_TYPE_NON_TUNNEL,
                                        &attr, &g_non_tun_match_id));
}

TEST(nas_udf_match, create_udf_match_gre_tunnel)
{
    udf_match_attr_t attr;
    attr.inner_type = INET_IP_VERSION_IPV4;
    attr.outer_type = INET_IP_VERSION_IPV4;
    ASSERT_TRUE(nas_udf_ut_create_match(1, BASE_UDF_UDF_MATCH_TYPE_GRE_TUNNEL,
                                        &attr, &g_tun_match_id));
}

TEST(nas_udf_match, get_udf_match_all)
{
    ASSERT_TRUE(nas_udf_ut_get_match(0));
}

TEST(nas_udf_match, get_udf_match_by_id)
{
    if (g_non_tun_match_id == 0 || g_tun_match_id == 0) {
        ASSERT_TRUE(g_obj_id_list.size() > 1);
        g_non_tun_match_id = g_obj_id_list[0];
        g_tun_match_id = g_obj_id_list[1];
    }
    ASSERT_TRUE(nas_udf_ut_get_match(g_non_tun_match_id));
    ASSERT_TRUE(nas_udf_ut_get_match(g_tun_match_id));
}

TEST(nas_udf_match, delete_udf_match)
{
    if (g_non_tun_match_id == 0 || g_tun_match_id == 0) {
        ASSERT_TRUE(g_obj_id_list.size() > 1);
        g_non_tun_match_id = g_obj_id_list[0];
        g_tun_match_id = g_obj_id_list[1];
    }
    ASSERT_TRUE(nas_udf_ut_delete_match(g_non_tun_match_id));
    ASSERT_TRUE(nas_udf_ut_delete_match(g_tun_match_id));
    g_non_tun_match_id = 0;
    g_tun_match_id = 0;
}

TEST(nas_udf, create_udf)
{
    ASSERT_TRUE(nas_udf_ut_create_group(
                            BASE_UDF_UDF_GROUP_TYPE_GENERIC, 3,
                            &g_group_id));
    udf_match_attr_t attr;
    attr.l2_type = 0x800;
    attr.l2_type_mask = 0xff00;
    attr.l3_type = 0x1;
    attr.l3_type_mask = 0xf;
    ASSERT_TRUE(nas_udf_ut_create_match(1, BASE_UDF_UDF_MATCH_TYPE_NON_TUNNEL,
                                        &attr, &g_non_tun_match_id));
    ASSERT_TRUE(nas_udf_ut_create_udf(g_group_id, g_non_tun_match_id,
                                      BASE_UDF_UDF_BASE_TYPE_L3, false, 2,
                                      NULL, 0, &g_udf_id));
}

TEST(nas_udf, get_udf_all)
{
    cout << "------ All UDF Groups ------" << endl;
    ASSERT_TRUE(nas_udf_ut_get_group(0));
    cout << "------ All UDF Matches ------" << endl;
    ASSERT_TRUE(nas_udf_ut_get_match(0));
    cout << "------ All UDF Objects ------" << endl;
    ASSERT_TRUE(nas_udf_ut_get_udf(0));
}

TEST(nas_udf, get_udf_by_id)
{
    if (g_udf_id == 0) {
        ASSERT_TRUE(g_obj_id_list.size() > 0);
        g_udf_id = g_obj_id_list[0];
    }
    ASSERT_TRUE(g_udf_id != 0);
}

TEST(nas_udf, delete_udf)
{
    if (g_udf_id == 0) {
        ASSERT_TRUE(g_obj_id_list.size() > 0);
        g_udf_id = g_obj_id_list[0];
    }
    ASSERT_TRUE(nas_udf_ut_delete_udf(g_udf_id));
    g_udf_id = 0;
    if (g_group_id != 0) {
        ASSERT_TRUE(nas_udf_ut_delete_group(g_group_id));
        g_group_id = 0;
    }
    if (g_non_tun_match_id != 0) {
        ASSERT_TRUE(nas_udf_ut_delete_match(g_non_tun_match_id));
        g_non_tun_match_id = 0;
    }
}

TEST(nas_udf, create_hash_udf)
{
    ASSERT_TRUE(nas_udf_ut_create_group(
                            BASE_UDF_UDF_GROUP_TYPE_HASH, 2,
                            &g_group_id));
    ASSERT_TRUE(nas_udf_ut_create_group(
                            BASE_UDF_UDF_GROUP_TYPE_HASH, 2,
                            &g_group_id_1));
    udf_match_attr_t attr;
    attr.l2_type = 0x0;
    attr.l2_type_mask = 0x0;
    attr.l3_type = 0x0;
    attr.l3_type_mask = 0x0;
    ASSERT_TRUE(nas_udf_ut_create_match(1, BASE_UDF_UDF_MATCH_TYPE_NON_TUNNEL,
                                        &attr, &g_non_tun_match_id));
    uint8_t hash_mask[] = {0xf, 0x3f};
    uint8_t hash_mask_1[] = {0xff, 0x7};
    ASSERT_TRUE(nas_udf_ut_create_udf(g_group_id, g_non_tun_match_id,
                                      BASE_UDF_UDF_BASE_TYPE_L3, false, 0,
                                      hash_mask, sizeof(hash_mask), &g_udf_id));
    ASSERT_TRUE(nas_udf_ut_create_udf(g_group_id_1, g_non_tun_match_id,
                                      BASE_UDF_UDF_BASE_TYPE_L4, false, 4,
                                      hash_mask_1, sizeof(hash_mask_1), &g_udf_id_1));
}

TEST(nas_udf, get_hash_udf_all)
{
    cout << "------ All UDF Groups ------" << endl;
    ASSERT_TRUE(nas_udf_ut_get_group(0));
    cout << "------ All UDF Matches ------" << endl;
    ASSERT_TRUE(nas_udf_ut_get_match(0));
    cout << "------ All UDF Objects ------" << endl;
    ASSERT_TRUE(nas_udf_ut_get_udf(0));
}

TEST(nas_udf, delete_hash_udf)
{
    if (g_obj_id_list.size() >= 5) {
        g_udf_id = g_obj_id_list[0];
        g_udf_id_1 = g_obj_id_list[1];
        g_group_id = g_obj_id_list[2];
        g_group_id_1 = g_obj_id_list[3];
        g_non_tun_match_id = g_obj_id_list[4];
        cout << "Cmdline input: udf_id " << g_udf_id << " " << g_udf_id_1
             << " group_id " << g_group_id << " " << g_group_id_1
             << " match_id " << g_non_tun_match_id << endl;
    }
    if (g_udf_id != 0) {
        ASSERT_TRUE(nas_udf_ut_delete_udf(g_udf_id));
        g_udf_id = 0;
    }
    if (g_udf_id_1 != 0) {
        ASSERT_TRUE(nas_udf_ut_delete_udf(g_udf_id_1));
        g_udf_id_1 = 0;
    }
    if (g_group_id != 0) {
        ASSERT_TRUE(nas_udf_ut_delete_group(g_group_id));
        g_group_id = 0;
    }
    if (g_group_id_1 != 0) {
        ASSERT_TRUE(nas_udf_ut_delete_group(g_group_id_1));
        g_group_id_1 = 0;
    }
    if (g_non_tun_match_id != 0) {
        ASSERT_TRUE(nas_udf_ut_delete_match(g_non_tun_match_id));
        g_non_tun_match_id = 0;
    }
}

TEST(nas_udf, create_udf_with_default_attr)
{
    ASSERT_TRUE(nas_udf_ut_create_group(
                            BASE_UDF_UDF_GROUP_TYPE_GENERIC, 28,
                            &g_group_id));
    ASSERT_TRUE(nas_udf_ut_create_match(1, BASE_UDF_UDF_MATCH_TYPE_NON_TUNNEL,
                                        nullptr, &g_non_tun_match_id));
    ASSERT_TRUE(nas_udf_ut_create_udf(g_group_id, g_non_tun_match_id,
                                      BASE_UDF_UDF_BASE_TYPE_L3, true, 0,
                                      NULL, 0, &g_udf_id));
}

TEST(nas_udf, delete_udf_with_default_attr)
{
    if (g_obj_id_list.size() >= 3) {
        g_udf_id = g_obj_id_list[0];
        g_non_tun_match_id = g_obj_id_list[1];
        g_group_id = g_obj_id_list[2];
    }
    if (g_udf_id != 0) {
        ASSERT_TRUE(nas_udf_ut_delete_udf(g_udf_id));
        g_udf_id = 0;
    }
    if (g_non_tun_match_id != 0) {
        ASSERT_TRUE(nas_udf_ut_delete_match(g_non_tun_match_id));
        g_non_tun_match_id = 0;
    }
    if (g_group_id != 0) {
        ASSERT_TRUE(nas_udf_ut_delete_group(g_group_id));
        g_group_id = 0;
    }
}

TEST(nas_udf_acl, create_udf_entry)
{
    ASSERT_TRUE(nas_udf_ut_create_group(
                            BASE_UDF_UDF_GROUP_TYPE_GENERIC, 8,
                            &g_group_id));
    ASSERT_TRUE(nas_udf_ut_create_group(
                            BASE_UDF_UDF_GROUP_TYPE_GENERIC, 3,
                            &g_group_id_1));

    udf_match_attr_t attr;
    attr.l2_type = 0x800;
    attr.l2_type_mask = 0xffff;
    attr.l3_type = 0x1;
    attr.l3_type_mask = 0xff;
    ASSERT_TRUE(nas_udf_ut_create_match(1, BASE_UDF_UDF_MATCH_TYPE_NON_TUNNEL,
                                        &attr, &g_non_tun_match_id));
    ASSERT_TRUE(nas_udf_ut_create_udf(g_group_id, g_non_tun_match_id,
                                      BASE_UDF_UDF_BASE_TYPE_L3, false, 0,
                                      NULL, 0, &g_udf_id));
    ASSERT_TRUE(nas_udf_ut_create_udf(g_group_id_1, g_non_tun_match_id,
                                      BASE_UDF_UDF_BASE_TYPE_L4, false, 4,
                                      NULL, 0, &g_udf_id_1));

    match_field_list_t allowed_fields = {BASE_ACL_MATCH_TYPE_SRC_MAC,
                                         BASE_ACL_MATCH_TYPE_IN_INTF,
                                         BASE_ACL_MATCH_TYPE_UDF};
    udf_group_id_list_t udf_grp_ids = {g_group_id, g_group_id_1};
    ASSERT_TRUE(nas_udf_ut_create_acl_table(100, allowed_fields, udf_grp_ids,
                                            &g_acl_table_id));
    ASSERT_TRUE(nas_udf_ut_create_acl_counter(g_acl_table_id, true, true,
                                              &g_acl_counter_id));
    ASSERT_TRUE(nas_udf_ut_create_acl_entry(g_acl_table_id, 5, &g_acl_entry_id));
}

TEST(nas_udf_acl, udf_entry_cleanup)
{
    if (g_obj_id_list.size() >= 8) {
        g_acl_entry_id = g_obj_id_list[0];
        g_acl_counter_id = g_obj_id_list[1];
        g_acl_table_id = g_obj_id_list[2];
        g_udf_id = g_obj_id_list[3];
        g_udf_id_1 = g_obj_id_list[4];
        g_non_tun_match_id = g_obj_id_list[5];
        g_group_id = g_obj_id_list[6];
        g_group_id_1 = g_obj_id_list[7];
    }
    if (g_acl_entry_id != 0) {
        ASSERT_TRUE(nas_udf_ut_delete_acl_entry(g_acl_entry_id, g_acl_table_id));
        g_acl_entry_id = 0;
    }
    if (g_acl_counter_id != 0) {
        ASSERT_TRUE(nas_udf_ut_delete_acl_counter(g_acl_counter_id, g_acl_table_id));
        g_acl_counter_id = 0;
    }
    if (g_acl_table_id != 0) {
        ASSERT_TRUE(nas_udf_ut_delete_acl_table(g_acl_table_id));
        g_acl_table_id = 0;
    }
    if (g_udf_id != 0) {
        ASSERT_TRUE(nas_udf_ut_delete_udf(g_udf_id));
        g_udf_id = 0;
    }
    if (g_udf_id_1 != 0) {
        ASSERT_TRUE(nas_udf_ut_delete_udf(g_udf_id_1));
        g_udf_id_1 = 0;
    }
    if (g_non_tun_match_id != 0) {
        ASSERT_TRUE(nas_udf_ut_delete_match(g_non_tun_match_id));
        g_non_tun_match_id = 0;
    }
    if (g_group_id != 0) {
        ASSERT_TRUE(nas_udf_ut_delete_group(g_group_id));
        g_group_id = 0;
    }
    if (g_group_id_1 != 0) {
        ASSERT_TRUE(nas_udf_ut_delete_group(g_group_id_1));
        g_group_id_1 = 0;
    }
}

int main(int argc, char *argv[])
{
    if (argc > 1 && strncmp(argv[1], "id=", 3) == 0) {
        char *orig_argv0 = argv[0];
        char *id_str = argv[1] + 3;
        char *ptr;
        do {
            if (!isdigit(*id_str)) {
                break;
            }
            nas_obj_id_t id = strtol(id_str, &ptr, 0);
            g_obj_id_list.push_back(id);
            id_str = ptr + 1;
        } while(*ptr == ',');
        cout << "Input object ID: ";
        for (auto id: g_obj_id_list) {
            cout << id << " ";
        }
        cout << endl;
        argc --;
        argv ++;
        argv[0] = orig_argv0;
    }
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
