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
 * \file   nas_acl_filter.h
 * \brief  NAS ACL Filter Match Field Class Definition
 * \date   04-2015
 */

#ifndef _NAS_ACL_FILTER_H_
#define _NAS_ACL_FILTER_H_

#include "dell-base-acl.h"
#include "std_assert.h"
#include "nas_base_utils.h"
#include "nas_ndi_acl.h"
#include "nas_acl_common.h"
#include "nas_acl_table.h"
#include <string.h>
#include <vector>
#include <unordered_map>

class nas_acl_filter_t
{
    public:
        static bool is_type_valid (BASE_ACL_MATCH_TYPE_t f_type) noexcept {
            return nas_acl_filter_is_type_valid (f_type);
        }

        static const char* type_name (BASE_ACL_MATCH_TYPE_t type) noexcept {
            return nas_acl_filter_type_name (type);
        }

        static bool is_npu_specific (BASE_ACL_MATCH_TYPE_t f_type) noexcept {
            return (f_type == BASE_ACL_MATCH_TYPE_IN_PORTS ||
                    f_type == BASE_ACL_MATCH_TYPE_IN_PORT ||
                    f_type == BASE_ACL_MATCH_TYPE_IN_INTFS ||
                    f_type == BASE_ACL_MATCH_TYPE_IN_INTF);
        }

        const char* name () const noexcept;
        void dbg_dump () const;

        nas_acl_filter_t (const nas_acl_table* table, BASE_ACL_MATCH_TYPE_t t);

        BASE_ACL_MATCH_TYPE_t filter_type () const noexcept {return _f_info.filter_type;}
        size_t filter_offset () const noexcept {return _f_info.udf_seq_no;}
        bool is_npu_specific () const noexcept;

        void get_u8_filter_val (nas_acl_common_data_list_t& val_list) const;
        void get_u16_filter_val (nas_acl_common_data_list_t& val_list) const;
        void get_u32_filter_val (nas_acl_common_data_list_t& val_list) const;
        void get_ipv4_filter_val (nas_acl_common_data_list_t& val_list) const;
        void get_ipv6_filter_val (nas_acl_common_data_list_t& val_list) const;
        void get_mac_filter_val (nas_acl_common_data_list_t& val_list) const;
        void get_l4_port_range_filter_val (nas_acl_common_data_list_t& val_list) const;
        void get_l4_port_match_filter_val (nas_acl_common_data_list_t& val_list) const;
        void get_ip_flag_filter_val (nas_acl_common_data_list_t& val_list) const;
        void get_tcp_flag_filter_val (nas_acl_common_data_list_t& val_list) const;
        void get_ip_type_filter_val (nas_acl_common_data_list_t& val_list) const;
        void get_ip_frag_filter_val (nas_acl_common_data_list_t& val_list) const;
        void get_filter_ifindex_list (nas_acl_common_data_list_t& val_list) const;
        void get_filter_ifindex (nas_acl_common_data_list_t& val_list) const;
        void get_udf_filter_val (nas_acl_common_data_list_t& val_list) const;

        const nas::ifindex_list_t& get_filter_if_list () const noexcept;
        nas::npu_set_t get_npu_list () const;

        void set_u8_filter_val (const nas_acl_common_data_list_t& val_list);
        void set_u16_filter_val (const nas_acl_common_data_list_t& val_list);
        void set_u32_filter_val (const nas_acl_common_data_list_t& val_list);
        void set_ipv4_filter_val (const nas_acl_common_data_list_t& val_list);
        void set_ipv6_filter_val (const nas_acl_common_data_list_t& val_list);
        void set_mac_filter_val (const nas_acl_common_data_list_t& val_list);
        void set_l4_port_range_filter_val (const nas_acl_common_data_list_t& val_list);
        void set_l4_port_match_filter_val (const nas_acl_common_data_list_t& val_list);
        void set_ip_flag_filter_val (const nas_acl_common_data_list_t& val_list);
        void set_tcp_flag_filter_val (const nas_acl_common_data_list_t& val_list);
        void set_ip_type_filter_val (const nas_acl_common_data_list_t& val_list);
        void set_ip_frag_filter_val (const nas_acl_common_data_list_t& val_list);
        void set_filter_ifindex_list (const nas_acl_common_data_list_t& val_list);
        void set_filter_ifindex (const nas_acl_common_data_list_t& val_list);
        void set_udf_filter_val (const nas_acl_common_data_list_t& val_list);

        nas_obj_id_t get_udf_group_from_pos(size_t udf_grp_pos) const;
        size_t get_udf_group_pos(nas_obj_id_t udf_grp_id) const;

        bool copy_filter_ndi (ndi_acl_entry_filter_t* ndi_filter_p,
                              npu_id_t npu_id, nas::mem_alloc_helper_t& m) const;

        bool operator!= (const nas_acl_filter_t& second) const noexcept;

    private:
        bool _ndi_copy_one_obj_id(ndi_acl_entry_filter_t* ndi_filter_p,
                                  npu_id_t npu_id) const;
        // Estimated number of ports in a filter of type In ports or Out ports
        static constexpr size_t port_count_estm = 5;

        // Values for following Filters are stored as table of
        // nas-obj-id <-> ndi_obj_id_table mapping:
        //   - IN_PORT/OUT_PORT - ONLY if the port is a lag -
        //                        ifindex is used as nas_obj_id
        std::unordered_map<nas_obj_id_t, nas::ndi_obj_id_table_t>  _nas2ndi_oid_tbl;
        ndi_acl_entry_filter_t   _f_info;
        nas::ifindex_list_t   _ifindex_list;

        const nas_acl_table* _table_p = nullptr;
};

inline const nas::ifindex_list_t&
nas_acl_filter_t::get_filter_if_list () const noexcept
{
    return _ifindex_list;
}

inline const char* nas_acl_filter_t::name () const noexcept
{
    return nas_acl_filter_type_name (filter_type());
}

inline bool nas_acl_filter_t::is_npu_specific () const noexcept
{
    return (nas_acl_filter_t::is_npu_specific (filter_type ()));
}
#endif
