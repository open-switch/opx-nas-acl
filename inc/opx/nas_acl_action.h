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
 * \file   nas_acl_action.h
 * \brief  NAS ACL Action entry Class Definition
 * \date   04-2015
 */

#ifndef _NAS_ACL_ACTION_H_
#define _NAS_ACL_ACTION_H_

#include "dell-base-acl.h"
#include "std_assert.h"
#include "std_ip_utils.h"
#include "nas_base_utils.h"
#include "nas_ndi_acl.h"
#include "nas_acl_common.h"
#include <string.h>
#include <vector>
#include <unordered_map>

using ndi_acl_action_list_t = std::vector<ndi_acl_entry_action_t>;

typedef enum _nas_acl_obj_key_type_t {
    NAS_OBJ_KEY_TYPE_OBJ_ID,
    NAS_OBJ_KEY_TYPE_HN,
} nas_acl_obj_key_type_t;

typedef struct _nas_acl_obj_key_t {
    nas_acl_obj_key_type_t type;
    union {
        nas_obj_id_t nas_obj_id;
        struct {
            uint32_t vrf_id;
            hal_ip_addr_t dest_addr;
        } nh_key;
    };
} nas_acl_obj_key_t;

struct _obj_key_hash {
    size_t operator()(const nas_acl_obj_key_t& key) const {
        size_t hash;
        if (key.type == NAS_OBJ_KEY_TYPE_OBJ_ID) {
            hash = std::hash<uint64_t>()(key.nas_obj_id);
        } else {
            char buff[HAL_INET6_TEXT_LEN + 1];
            hash = std::hash<int>()(key.nh_key.vrf_id);
            hash ^= (std::hash<int>()(key.nh_key.dest_addr.af_index) << 1);
            std_ip_to_string(&key.nh_key.dest_addr, buff, HAL_INET6_TEXT_LEN);
            std::string ip_str(buff);
            hash ^= (std::hash<std::string>()(ip_str) << 1);
        }
        return hash;
    }
};

struct _obj_key_equal {
    bool operator()(const nas_acl_obj_key_t& k1, const nas_acl_obj_key_t& k2) const {
        if (k1.type != k2.type) {
            return false;
        }
        if (k1.type == NAS_OBJ_KEY_TYPE_OBJ_ID) {
            return (k1.nas_obj_id == k2.nas_obj_id);
        } else {
            return ((k1.nh_key.vrf_id == k2.nh_key.vrf_id) &&
                    (std_ip_cmp_ip_addr(&k1.nh_key.dest_addr, &k2.nh_key.dest_addr) == 0));
        }
    }
};

static inline bool operator==(const nas_acl_obj_key_t& k1, const nas_acl_obj_key_t& k2) {
    return _obj_key_equal()(k1, k2);
}

class nas_acl_action_t
{
    public:
        static bool is_type_valid (BASE_ACL_ACTION_TYPE_t type) noexcept {
            return nas_acl_action_is_type_valid (type);
        }

        static const char* type_name (BASE_ACL_ACTION_TYPE_t type) noexcept {
            return nas_acl_action_type_name (type);
        }

        bool is_counter () const noexcept
        { return (action_type() == BASE_ACL_ACTION_TYPE_SET_COUNTER); }

        const char* name () const noexcept;

        void dbg_dump () const;

        nas_acl_action_t (BASE_ACL_ACTION_TYPE_t t);

        BASE_ACL_ACTION_TYPE_t action_type () const noexcept {return _a_info.action_type;}
        void set_values_type (ndi_acl_action_values_type_t type) {_a_info.values_type = type;};

        const nas::ifindex_list_t& get_action_if_list () const noexcept;

        void set_u8_action_val (const nas_acl_common_data_list_t& data_list);
        void set_u16_action_val (const nas_acl_common_data_list_t& data_list);
        void set_u32_action_val (const nas_acl_common_data_list_t& data_list);
        void set_obj_id_action_val (const nas_acl_common_data_list_t& data_list);
        void set_ipv4_action_val (const nas_acl_common_data_list_t& data_list);
        void set_ipv6_action_val (const nas_acl_common_data_list_t& data_list);
        void set_mac_action_val (const nas_acl_common_data_list_t& val_list);
        void set_opaque_data_action_val (const nas_acl_common_data_list_t& data_list);
        void set_opaque_data_list_action_val (const nas_acl_common_data_list_t& data_list);
        void set_log_action_val (const nas_acl_common_data_list_t& data_list);
        void set_action_ifindex (const nas_acl_common_data_list_t& data_list);
        void set_action_ifindex_list (const nas_acl_common_data_list_t& data_list);
        void set_pkt_action_val (const nas_acl_common_data_list_t& data_list);
        void set_ndi_counter_ids (const nas::ndi_obj_id_table_t & ndi_obj_id_table);
        void set_opaque_data_nexthop_val (const nas_acl_common_data_list_t& data_list);

        void get_u8_action_val (nas_acl_common_data_list_t& data_list) const;
        void get_u16_action_val (nas_acl_common_data_list_t& data_list) const;
        void get_u32_action_val (nas_acl_common_data_list_t& data_list) const;
        void get_obj_id_action_val (nas_acl_common_data_list_t& data_list) const;
        void get_ipv4_action_val (nas_acl_common_data_list_t& data_list) const;
        void get_ipv6_action_val (nas_acl_common_data_list_t& data_list) const;
        void get_mac_action_val (nas_acl_common_data_list_t& val_list) const;
        void get_opaque_data_action_val (nas_acl_common_data_list_t& data_list) const;
        void get_log_action_val (nas_acl_common_data_list_t& data_list) const;
        void get_action_ifindex (nas_acl_common_data_list_t& data_list) const;
        void get_action_ifindex_list (nas_acl_common_data_list_t& data_list) const;
        void get_pkt_action_val (nas_acl_common_data_list_t& val_list) const;
        void get_opaque_data_nexthop_val (nas_acl_common_data_list_t& data_list) const;

        nas_obj_id_t  counter_id () const noexcept {return _nas_oid;}

        bool copy_action_ndi (ndi_acl_action_list_t& ndi_alist,
                              npu_id_t npu_id, nas::mem_alloc_helper_t& m) const;

        bool operator!= (const nas_acl_action_t& second) const;

    private:
        void _set_opaque_data (const nas_acl_common_data_list_t& data_list);
        bool _ndi_copy_one_obj_id (ndi_acl_entry_action_t& ndi_action,
                                   npu_id_t npu_id) const;
        bool _ndi_copy_obj_id_list (ndi_acl_entry_action_t& ndi_action,
                                    npu_id_t npu_id,
                                    nas::mem_alloc_helper_t& mem_trakr) const;
        bool _ndi_copy_nh_obj_id (ndi_acl_entry_action_t& ndi_action,
                                  npu_id_t npu_id) const;

        // Value for In/Out port/port-list Action and
        // Value for Redirect_port action
        nas::ifindex_list_t      _ifindex_list;

        // Value for Counter Action
        nas_obj_id_t             _nas_oid = 0;

        // Values for following Actions are stored as table of
        // nas-obj-id <-> ndi_obj_id_table mapping:
        //   - REDIRECT_PORT - ONLY if the port is a lag -
        //                     ifindex is used as nas_obj_id
        //   - Mirror, IP Nexthop, CPU Queue Action.
        //          Basically any action that takes Opaque data as param.
        std::unordered_map<nas_acl_obj_key_t, nas::ndi_obj_id_table_t, _obj_key_hash, _obj_key_equal>
            _nas2ndi_oid_tbl;

        // Values for all other actions are stored directly in NDI structure
        ndi_acl_entry_action_t   _a_info;
};

inline const nas::ifindex_list_t&
nas_acl_action_t::get_action_if_list () const noexcept
{
    return _ifindex_list;
}

inline const char* nas_acl_action_t::name () const noexcept
{
    return type_name (action_type());
}

#endif
