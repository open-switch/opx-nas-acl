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

#include "event_log.h"
#include "gtest/gtest.h"
#include "nas_acl_log.h"
#include "nas_base_utils.h"
#include "nas_acl_cps.h"
#include "nas_switch.h"
#include "nas_acl_filter.h"
#include "nas_acl_common.h"
#include <stdio.h>
#include <iostream>
#include <stdlib.h>

#define ut_printf if (ut_print_is_enabled ()) printf

#define NAS_ACL_UT_DEF_SWITCH_ID 0
#define NAS_ACL_UT_START_FILTER  BASE_ACL_MATCH_TYPE_SRC_IPV6
#define NAS_ACL_UT_END_FILTER    BASE_ACL_MATCH_TYPE_ICMP_CODE
#define NAS_ACL_UT_NUM_FILTERS   \
        (NAS_ACL_UT_END_FILTER - NAS_ACL_UT_START_FILTER + 1)
#define NAS_ACL_UT_MAX_NPUS      1
#define NAS_ACL_UT_NUM_PORTS_PER_NPU 8

#define NAS_ACL_UT_START_ACTION BASE_ACL_ACTION_TYPE_REDIRECT_PORT
#define NAS_ACL_UT_END_ACTION   BASE_ACL_ACTION_TYPE_SET_CPU_QUEUE

#define NAS_ACL_UT_MAX_TABLES 3

#define NAS_ACL_UT_STAGE_TO_STR(_stage) \
        ((_stage == BASE_ACL_STAGE_INGRESS) ? "Ingress" : \
         (_stage == BASE_ACL_STAGE_EGRESS) ? "Egress" : "Invalid")

#define NAS_ACL_UT_CREATE 1
#define NAS_ACL_UT_GET    2
#define NAS_ACL_UT_MODIFY 3
#define NAS_ACL_UT_DELETE 4

#define NAS_ACL_UT_OP_TO_STR(op) \
        ((op == NAS_ACL_UT_CREATE) ? "CREATE" : \
         ((op == NAS_ACL_UT_GET) ? "GET" : \
         ((op == NAS_ACL_UT_MODIFY) ? "MODIFY" : \
          ((op == NAS_ACL_UT_DELETE) ? "DELETE" : "INVALID"))))

typedef std::vector<uint64_t> ut_val_list_t;
typedef std::set<npu_id_t>    ut_npu_list_t;

typedef ut_npu_list_t::const_iterator const_ut_npu_list_iter_t;

typedef struct _ut_filter_t {
    BASE_ACL_MATCH_TYPE_t  type;
    ut_val_list_t          val_list;
} ut_filter_t;

typedef struct _ut_action_t {
    BASE_ACL_ACTION_TYPE_t  type;
    ut_val_list_t           val_list;
} ut_action_t;

struct filter_comp {
    bool operator() (const ut_filter_t& lhs, const ut_filter_t& rhs) {
        return (lhs.type < rhs.type);
    }
};

struct action_comp {
    bool operator() (const ut_action_t& lhs, const ut_action_t& rhs) {
        return (lhs.type < rhs.type);
    }
};

typedef std::set<ut_filter_t, filter_comp> ut_filter_list_t;
typedef std::set<ut_action_t, action_comp> ut_action_list_t;

typedef struct _nas_acl_ut_entry {
    uint32_t            index;  /* Key to the entries */
    nas_switch_id_t     switch_id;
    nas_obj_id_t        table_id;
    nas_obj_id_t        entry_id;
    uint32_t            priority;
    ut_filter_list_t    filter_list;
    ut_action_list_t    action_list;
    ut_npu_list_t       npu_list;
    bool                update_priority;
    bool                update_filter;
    bool                update_action;
    bool                update_npu;
    bool                verified;
    bool                to_be_verified;
} ut_entry_t;

typedef std::unordered_map<uint32_t, ut_entry_t> ut_entry_list_t;

typedef struct _nas_acl_ut_table {
    char                            name [32];
    nas_switch_id_t                 switch_id;
    nas_obj_id_t                    table_id;
    BASE_ACL_STAGE_t                stage;
    uint_t                          priority;
    std::set<BASE_ACL_MATCH_TYPE_t> filters;
    ut_npu_list_t                   npu_list;
    bool                            npu_sent_in_mod_req;
    ut_entry_list_t                 entries;
    std::vector<nas_obj_id_t>       counter_ids;
} nas_acl_ut_table_t;

typedef std::vector<cps_api_attr_id_t> ut_attr_id_list_t;

extern nas_acl_ut_table_t g_nas_acl_ut_tables [NAS_ACL_UT_MAX_TABLES];

nas_acl_ut_table_t* find_table (nas_obj_id_t table_id);

bool nas_acl_ut_entry_create_test (nas_acl_ut_table_t& table);
bool nas_acl_ut_entry_modify_test (nas_acl_ut_table_t& table);
bool nas_acl_ut_entry_delete_test (nas_acl_ut_table_t& table, bool validate=true);
bool nas_acl_ut_entry_incr_modify_test (nas_acl_ut_table_t& table);
bool nas_acl_ut_entry_get_by_table_test (nas_acl_ut_table_t& table);
bool nas_acl_ut_entry_get_by_switch_test (nas_switch_id_t switch_id);
bool nas_acl_ut_entry_get_all_test ();
bool ut_fill_entry_action (cps_api_object_t obj, const ut_entry_t& entry);

void nas_acl_ut_init_tables ();
bool nas_acl_ut_table_create ();
bool nas_acl_ut_table_modify ();
bool nas_acl_ut_table_get ();
bool nas_acl_ut_table_delete ();

cps_api_return_code_t
nas_acl_ut_cps_api_commit (cps_api_transaction_params_t *param,
                           bool                          rollback_required);
cps_api_return_code_t nas_acl_ut_cps_api_get (cps_api_get_params_t *param,
                                              size_t                index);
bool nas_acl_ut_counter_delete (nas_acl_ut_table_t& table);
bool nas_acl_ut_stats_get_test (nas_acl_ut_table_t& table);
bool nas_acl_ut_stats_set_test (nas_acl_ut_table_t& table);
bool nas_acl_ut_entry_count_enable (nas_acl_ut_table_t& table, bool pkt, bool byte);

bool ut_print_is_enabled ();
void ut_print_set_status (bool);

void ut_dump_attr_id_list (std::vector<cps_api_attr_id_t>& internal_ids);

void ut_dump_attr_id_list (cps_api_attr_id_t *attr_id_list,
                           size_t             attr_id_size);

void nas_acl_ut_env_init ();
bool nas_acl_ut_is_on_target ();
bool nas_acl_ut_lag_create(const char *lag_name, int sub_if_num, ...);
bool nas_acl_ut_lag_delete(const char *lag_name);
bool nas_acl_ut_src_port_entry_create(nas_acl_ut_table_t& table,
                                      int priority, const char *intf_name);
bool nas_acl_ut_nbr_dst_hit_entry_create(nas_acl_ut_table_t& table,
                                         int priority);
bool nas_acl_ut_route_dst_hit_entry_create(nas_acl_ut_table_t& table,
                                           int priority);
bool nas_acl_ut_nh_redir_entry_create(nas_acl_ut_table_t& table,
                                      int priority);
bool nas_acl_ut_table_entry_delete(nas_acl_ut_table_t& table);
bool nas_acl_ut_nh_redir_entry_delete(nas_acl_ut_table_t& table);
