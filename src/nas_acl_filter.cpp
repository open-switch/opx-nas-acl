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
 * \file   nas_acl_filter.cpp
 * \brief  NAS ACL Filter Match Field implementation
 * \date   04-2015
 */

#include "std_ip_utils.h"
#include "std_mutex_lock.h"
#include "hal_if_mapping.h"
#include "nas_if_utils.h"
#include "nas_vlan_consts.h"
#include "nas_qos_consts.h"
#include "nas_acl_log.h"
#include "nas_acl_filter.h"
#include "nas_acl_utl.h"
#include <unordered_map>
#include <arpa/inet.h>

nas_acl_filter_t::nas_acl_filter_t (const nas_acl_table* table, BASE_ACL_MATCH_TYPE_t t)
    : _table_p(table)
{
    if (!is_type_valid (t)) {
        throw nas::base_exception {NAS_ACL_E_ATTR_VAL, __PRETTY_FUNCTION__,
            std::string {"Invalid filter type "} + std::to_string (t)};
    }

    memset (&_f_info, 0, sizeof (_f_info));
    _f_info.filter_type = t;

    if (t == BASE_ACL_MATCH_TYPE_IN_PORTS ||
        t == BASE_ACL_MATCH_TYPE_OUT_PORTS ||
        t == BASE_ACL_MATCH_TYPE_IN_INTFS ||
        t == BASE_ACL_MATCH_TYPE_OUT_INTFS) {
        // Reserve initial space for some ports
        // The list can grow beyond this if required
        _ifindex_list.reserve(nas_acl_filter_t::port_count_estm);
    }
    if (t == BASE_ACL_MATCH_TYPE_NEIGHBOR_DST_HIT ||
        t == BASE_ACL_MATCH_TYPE_ROUTE_DST_HIT) {
        _f_info.values_type = NDI_ACL_FILTER_BOOL;
    }
}

static bool _validate_ip_type_data (uint32_t ip_type) noexcept
{
    switch (ip_type) {
        case BASE_ACL_MATCH_IP_TYPE_ANY:
        case BASE_ACL_MATCH_IP_TYPE_IP:
        case BASE_ACL_MATCH_IP_TYPE_NON_IP:
        case BASE_ACL_MATCH_IP_TYPE_IPV4ANY:
        case BASE_ACL_MATCH_IP_TYPE_NON_IPV4:
        case BASE_ACL_MATCH_IP_TYPE_IPV6ANY:
        case BASE_ACL_MATCH_IP_TYPE_NON_IPV6:
        case BASE_ACL_MATCH_IP_TYPE_ARP:
        case BASE_ACL_MATCH_IP_TYPE_ARP_REQUEST:
        case BASE_ACL_MATCH_IP_TYPE_ARP_REPLY:
            break;

        default:
            return false;
    }
    return true;
}

static bool _validate_ip_frag_data (uint32_t ip_frag) noexcept
{
    switch (ip_frag) {
        case BASE_ACL_MATCH_IP_FRAG_ANY:
        case BASE_ACL_MATCH_IP_FRAG_NON_FRAG:
        case BASE_ACL_MATCH_IP_FRAG_NON_FRAG_OR_HEAD:
        case BASE_ACL_MATCH_IP_FRAG_HEAD:
        case BASE_ACL_MATCH_IP_FRAG_NON_HEAD:
            break;

        default:
            return false;
    }
    return true;
}

void nas_acl_filter_t::get_u32_filter_val (nas_acl_common_data_list_t& val_list) const
{
    nas_acl_common_data_t match_data = {};
    nas_acl_common_data_t match_mask = {};

    match_data.u32 = _f_info.data.values.u32;
    val_list.push_back (match_data);
    match_mask.u32 = _f_info.mask.values.u32;
    val_list.push_back (match_mask);
}

void nas_acl_filter_t::set_u32_filter_val (const nas_acl_common_data_list_t& val_list)
{
    _f_info.values_type     = NDI_ACL_FILTER_U32;
    _f_info.data.values.u32 = val_list.at(0).u32;
    if (val_list.size () > 1) {
        _f_info.mask.values.u32 = val_list.at(1).u32;
    }
}

void nas_acl_filter_t::get_u16_filter_val (nas_acl_common_data_list_t& val_list) const
{
    nas_acl_common_data_t match_data = {};
    nas_acl_common_data_t match_mask = {};

    match_data.u16 = _f_info.data.values.u16;
    val_list.push_back (match_data);
    match_mask.u16 = _f_info.mask.values.u16;
    val_list.push_back (match_mask);
}

void nas_acl_filter_t::set_u16_filter_val (const nas_acl_common_data_list_t& val_list)
{
    _f_info.values_type     = NDI_ACL_FILTER_U16;
    _f_info.data.values.u16 = val_list.at(0).u16;
    if (val_list.size () > 1) {
        _f_info.mask.values.u16 = val_list.at(1).u16;
    }
}

void nas_acl_filter_t::get_u8_filter_val (nas_acl_common_data_list_t& val_list) const
{
    nas_acl_common_data_t match_data = {};
    nas_acl_common_data_t match_mask = {};

    match_data.u8 = _f_info.data.values.u8;
    val_list.push_back (match_data);
    match_mask.u8 = _f_info.mask.values.u8;
    val_list.push_back (match_mask);
}

void nas_acl_filter_t::set_u8_filter_val (const nas_acl_common_data_list_t& val_list)
{
    _f_info.values_type    = NDI_ACL_FILTER_U8;
    _f_info.data.values.u8 = val_list.at(0).u8;
    if (val_list.size () > 1) {
        _f_info.mask.values.u8      = val_list.at(1).u8;
    }
}

void nas_acl_filter_t::get_ipv4_filter_val (nas_acl_common_data_list_t& val_list) const
{
    nas_acl_common_data_t match_addr;
    nas_acl_common_data_t match_mask;

    // IPv4 value can be considered as an array of bytes - copy this into the bytes array
    auto& val = _f_info.data.values.ipv4;
    auto val_u8 = (uint8_t*) &val;
    auto& bytes = match_addr.bytes;
    bytes.insert (bytes.begin(), val_u8, val_u8+sizeof (val));

    auto& mask = _f_info.mask.values.ipv4;
    auto mask_u8 = (uint8_t*) &mask;
    auto& bytes_mask = match_mask.bytes;
    bytes_mask.insert (bytes_mask.begin(), mask_u8, mask_u8+ sizeof (mask));

    val_list.push_back (match_addr);
    val_list.push_back (match_mask);
}

void nas_acl_filter_t::get_ipv6_filter_val (nas_acl_common_data_list_t& val_list) const
{
    nas_acl_common_data_t match_addr;
    nas_acl_common_data_t match_mask;

    // IPv6 value can be considered as an array of bytes - copy this into the bytes array
    auto& val = _f_info.data.values.ipv6;
    auto val_u8 = (uint8_t*) &val;
    auto& bytes = match_addr.bytes;
    bytes.insert(bytes.begin(), val_u8, val_u8+sizeof (val));

    auto& mask = _f_info.mask.values.ipv6;
    auto mask_u8 = (uint8_t*) &mask;
    auto& bytes_mask = match_mask.bytes;
    bytes_mask.insert (bytes_mask.begin(), mask_u8, mask_u8+ sizeof (mask));

    val_list.push_back (match_addr);
    val_list.push_back (match_mask);
}

void nas_acl_filter_t::set_ipv4_filter_val (const nas_acl_common_data_list_t& val_list)
{
    _f_info.values_type = NDI_ACL_FILTER_IPV4_ADDR;
    // IPv4 value can be considered as an array of bytes - copy from the bytes array
    memcpy ((uint8_t*)&_f_info.data.values.ipv4, val_list.at(0).bytes.data(),
            sizeof (_f_info.data.values.ipv4));
    memcpy ((uint8_t*)&_f_info.mask.values.ipv4, val_list.at(1).bytes.data(),
            sizeof (_f_info.mask.values.ipv4));
}

void nas_acl_filter_t::set_ipv6_filter_val (const nas_acl_common_data_list_t& val_list)
{
    _f_info.values_type = NDI_ACL_FILTER_IPV6_ADDR;
    // IPv6 value can be considered as an array of bytes - copy from the bytes array
    memcpy ((uint8_t*)&_f_info.data.values.ipv6, val_list.at(0).bytes.data(),
            sizeof (_f_info.data.values.ipv6));
    memcpy ((uint8_t*)&_f_info.mask.values.ipv6, val_list.at(1).bytes.data(),
            sizeof (_f_info.mask.values.ipv6));
}

void nas_acl_filter_t::get_mac_filter_val (nas_acl_common_data_list_t& val_list) const
{
    nas_acl_common_data_t match_addr;
    nas_acl_common_data_t match_mask;

    const uint8_t* mac_p = _f_info.data.values.mac;
    const uint8_t* mac_mask_p = _f_info.mask.values.mac;
    auto& bytes = match_addr.bytes;
    auto& bytes_mask = match_mask.bytes;

    bytes.insert (bytes.begin(), mac_p, mac_p+ HAL_MAC_ADDR_LEN);
    bytes_mask.insert (bytes_mask.begin(), mac_mask_p, mac_mask_p+ HAL_MAC_ADDR_LEN);

    val_list.push_back (match_addr);
    val_list.push_back (match_mask);
}

void nas_acl_filter_t::set_mac_filter_val (const nas_acl_common_data_list_t& val_list)
{
    _f_info.values_type = NDI_ACL_FILTER_MAC_ADDR;
    memcpy (_f_info.data.values.mac, val_list.at(0).bytes.data(), HAL_MAC_ADDR_LEN);
    memcpy (_f_info.mask.values.mac, val_list.at(1).bytes.data(), HAL_MAC_ADDR_LEN);
}

void nas_acl_filter_t::get_ip_type_filter_val (nas_acl_common_data_list_t& val_list) const
{
    nas_acl_common_data_t ip_type;

    ip_type.u32 = _f_info.data.ip_type;

    val_list.push_back (ip_type);
}

void nas_acl_filter_t::set_ip_type_filter_val (const nas_acl_common_data_list_t& val_list)
{
    auto val = val_list.at(0).u32;

    if (!_validate_ip_type_data (val)) {
        throw nas::base_exception {NAS_ACL_E_ATTR_VAL, __PRETTY_FUNCTION__,
            std::string {"Invalid IP type value "} + std::to_string (val)};
    }
    _f_info.values_type  = NDI_ACL_FILTER_IP_TYPE;
    _f_info.data.ip_type = (BASE_ACL_MATCH_IP_TYPE_t) val;
}

void nas_acl_filter_t::get_ip_frag_filter_val (nas_acl_common_data_list_t& val_list) const
{
    nas_acl_common_data_t ip_frag;

    ip_frag.u32 = _f_info.data.ip_frag;

    val_list.push_back (ip_frag);
}

void nas_acl_filter_t::set_ip_frag_filter_val (const nas_acl_common_data_list_t& val_list)
{
    auto val = val_list.at(0).u32;

    if (!_validate_ip_frag_data (val)) {
        throw nas::base_exception {NAS_ACL_E_ATTR_VAL, __PRETTY_FUNCTION__,
            std::string {"Invalid IP frag value "} + std::to_string (val)};
    }
    _f_info.values_type  = NDI_ACL_FILTER_IP_FRAG;
    _f_info.data.ip_frag = (BASE_ACL_MATCH_IP_FRAG_t) val;
}

void nas_acl_filter_t::get_filter_ifindex_list (nas_acl_common_data_list_t& val_list) const
{
    nas_acl_common_data_t if_list_data;

    if (_ifindex_list.size () != 0) {

        for (auto ifindex: _ifindex_list) {
            if_list_data.ifindex_list.push_back (ifindex);
        }

        val_list.push_back (if_list_data);
    }
}

void nas_acl_filter_t::set_filter_ifindex_list (const nas_acl_common_data_list_t& val_list)
{
    _f_info.values_type  = NDI_ACL_FILTER_PORTLIST;

    for (auto match_data: val_list) {
        for (auto port: match_data.ifindex_list) {
            _ifindex_list.push_back (port);
        }
    }
}

void nas_acl_filter_t::get_filter_ifindex (nas_acl_common_data_list_t& val_list) const
{
    nas_acl_common_data_t data;

    if (_ifindex_list.size () != 0) {
       data.ifindex = _ifindex_list.at(0);
       val_list.push_back (data);
    }
}

void nas_acl_filter_t::set_filter_ifindex (const nas_acl_common_data_list_t& val_list)
{
    static constexpr size_t num_inputs = 1;

    if (val_list.size () < num_inputs) {
        throw nas::base_exception {NAS_ACL_E_MISSING_ATTR, __PRETTY_FUNCTION__,
                                   "Empty input data list"};
    }

    auto ifindex = val_list.at(0).ifindex;
    _ifindex_list.push_back (ifindex);

    if (nas_acl_utl_is_ifidx_type_lag(ifindex)) {
        nas::ndi_obj_id_table_t tmp_ndi_oid_tbl;
        if (dn_nas_lag_get_ndi_ids (ifindex, &tmp_ndi_oid_tbl) != STD_ERR_OK) {
           throw nas::base_exception {NAS_ACL_E_ATTR_VAL, __PRETTY_FUNCTION__,
                                      "Failed to get LAG NDI IDs"};
        }
        auto oid = static_cast <nas_obj_id_t> (ifindex);
        _nas2ndi_oid_tbl[oid] = std::move (tmp_ndi_oid_tbl);
        _f_info.values_type = NDI_ACL_FILTER_OBJ_ID;
    } else {
        interface_ctrl_t  intf_ctrl {};
        nas_acl_utl_ifidx_to_ndi_port (ifindex, &intf_ctrl);

        _f_info.values_type  = NDI_ACL_FILTER_PORT;
        _f_info.data.values.ndi_port.npu_id = intf_ctrl.npu_id;
        _f_info.data.values.ndi_port.npu_port = intf_ctrl.port_id;
    }
}

void nas_acl_filter_t::get_udf_filter_val(nas_acl_common_data_list_t& val_list) const
{
    nas_acl_common_data_t udf_group_id {};
    nas_acl_common_data_t udf_match_data {};
    nas_acl_common_data_t udf_match_mask {};
    size_t byte_count;
    uint8_t *byte_list;

    udf_group_id.obj_id = get_udf_group_from_pos(_f_info.udf_seq_no);

    byte_count = _f_info.data.values.ndi_u8list.byte_count;
    byte_list = _f_info.data.values.ndi_u8list.byte_list;
    auto& bytes = udf_match_data.bytes;
    bytes.insert(bytes.begin(), byte_list, byte_list + byte_count);
    byte_count = _f_info.mask.values.ndi_u8list.byte_count;
    byte_list = _f_info.mask.values.ndi_u8list.byte_list;
    auto& bytes_mask = udf_match_mask.bytes;
    bytes_mask.insert(bytes_mask.begin(), byte_list, byte_list + byte_count);

    val_list.push_back(udf_group_id);
    val_list.push_back(udf_match_data);
    val_list.push_back(udf_match_mask);
}

void nas_acl_filter_t::set_udf_filter_val(const nas_acl_common_data_list_t& val_list)
{
    size_t byte_cnt;
    uint8_t *byte_buf;

    _f_info.values_type = NDI_ACL_FILTER_U8LIST;
    _f_info.udf_seq_no = get_udf_group_pos(val_list[0].obj_id);
    byte_cnt = val_list[1].bytes.size();
    byte_buf = (uint8_t *)calloc(byte_cnt, 1);
    if (byte_buf != NULL) {
        memcpy(byte_buf, val_list[1].bytes.data(), byte_cnt);
        _f_info.data.values.ndi_u8list.byte_count = byte_cnt;
        _f_info.data.values.ndi_u8list.byte_list = byte_buf;
    }
    byte_cnt = val_list[2].bytes.size();
    byte_buf = (uint8_t *)calloc(byte_cnt, 1);
    if (byte_buf != NULL) {
        memcpy(byte_buf, val_list[2].bytes.data(), byte_cnt);
        _f_info.mask.values.ndi_u8list.byte_count = byte_cnt;
        _f_info.mask.values.ndi_u8list.byte_list = byte_buf;
    }
}

bool nas_acl_filter_t::_ndi_copy_one_obj_id(ndi_acl_entry_filter_t* ndi_filter_p,
                                            npu_id_t npu_id) const
{
    auto it_oid = _nas2ndi_oid_tbl.begin();
    if (it_oid == _nas2ndi_oid_tbl.end()) {
        return false;
    }
    auto& ndi_oid_tbl = it_oid->second;
    auto it_npu_oid = ndi_oid_tbl.find(npu_id);
    if (it_npu_oid == ndi_oid_tbl.end()) {
        return false;
    }
    NAS_ACL_LOG_DETAIL ("%s: NPU ID %d, NDI Obj Id %",
                        name(), npu_id, it_npu_oid->second);
    ndi_filter_p->data.values.ndi_obj_ref = it_npu_oid->second;
    return true;
}

bool nas_acl_filter_t::copy_filter_ndi (ndi_acl_entry_filter_t* ndi_filter_p,
                                        npu_id_t npu_id,
                                        nas::mem_alloc_helper_t& mem_trakr) const
{
    if (ndi_filter_p->values_type == NDI_ACL_FILTER_PORT &&
        _f_info.data.values.ndi_port.npu_id != npu_id)
    {
        NAS_ACL_LOG_DETAIL ("Skipping NPU %d - Filter has no ports", npu_id);
        return false;
    }

    *ndi_filter_p = _f_info;

    if (ndi_filter_p->values_type == NDI_ACL_FILTER_OBJ_ID) {
        if (!_ndi_copy_one_obj_id(ndi_filter_p, npu_id)) {
            throw nas::base_exception {NAS_ACL_E_FAIL, __PRETTY_FUNCTION__,
                std::string {name()} + ": Could not find object id for NPU " +
                std::to_string (npu_id)};
        }
    }

    if (ndi_filter_p->values_type == NDI_ACL_FILTER_PORTLIST) {

        // Assert to ensure that we are not overwriting existing portlist
        STD_ASSERT (ndi_filter_p->data.values.ndi_portlist.port_list == NULL);

        // Build the list of NPU specific ports
        std::vector<ndi_port_t> ndi_plist;

        for (auto ifindex: _ifindex_list) {
            // Convert to NPU and port
            interface_ctrl_t  intf_ctrl {};
            nas_acl_utl_ifidx_to_ndi_port (ifindex, &intf_ctrl);
            if (intf_ctrl.npu_id != npu_id) continue;
            ndi_plist.push_back (ndi_port_t {intf_ctrl.npu_id, intf_ctrl.port_id});
        }

        // No ports from this NPU in the list ?
        if (ndi_plist.empty()) {
            NAS_ACL_LOG_DETAIL ("Skipping NPU %d - Filter has no ports", npu_id);
            return false;
        }

        ndi_filter_p->data.values.ndi_portlist.port_count = ndi_plist.size();
        ndi_port_t* plist =  mem_trakr.alloc<ndi_port_t> (ndi_plist.size());
        ndi_filter_p->data.values.ndi_portlist.port_list = plist;
        memcpy (plist, ndi_plist.data(), sizeof (ndi_port_t) * ndi_plist.size());
    }

    return true;
}

nas::npu_set_t nas_acl_filter_t::get_npu_list () const
{
    nas::npu_set_t  filter_npu_list;

    if (is_npu_specific()) {
        for (auto ifindex: _ifindex_list) {
            // Convert to NPU and port
            interface_ctrl_t  intf_ctrl {};
            nas_acl_utl_ifidx_to_ndi_port (ifindex, &intf_ctrl);
            filter_npu_list.add (intf_ctrl.npu_id);
        }
    }

    return filter_npu_list;
}

bool nas_acl_filter_t::operator!= (const nas_acl_filter_t& rhs) const noexcept
{
    if (filter_type() != rhs.filter_type()) {
        return true;
    }

    if (_f_info.values_type == NDI_ACL_FILTER_PORTLIST ||
        _f_info.values_type == NDI_ACL_FILTER_PORT)
    {
        if (_ifindex_list != rhs._ifindex_list) {
            return true;
        }
    }
    else {
        if (memcmp (&_f_info, &rhs._f_info, sizeof(_f_info))) {
            return true;
        }
    }

    return false;
}

void nas_acl_filter_t::dbg_dump () const
{
    NAS_ACL_LOG_DUMP ("Filter: %s", name ());

    switch (_f_info.values_type)
    {
        case NDI_ACL_FILTER_IP_TYPE:
            NAS_ACL_LOG_DUMP ("  ip_type = %d", _f_info.data.ip_type);
            break;

        case NDI_ACL_FILTER_IP_FRAG:
            NAS_ACL_LOG_DUMP ("  ip_frag = %d", _f_info.data.ip_frag);
            break;

        case NDI_ACL_FILTER_PORTLIST:
            NAS_ACL_LOG_DUMP ("  Ports = ");
            for (auto ifindex: _ifindex_list) {
                NAS_ACL_LOG_DUMP ("%d, ", ifindex);
            }
            NAS_ACL_LOG_DUMP ("");
            break;

        case NDI_ACL_FILTER_MAC_ADDR:
            NAS_ACL_LOG_DUMP ("  mac-addr = %0x:%0x:%0x:%0x:%0x:%0x ",
                              _f_info.data.values.mac[0],
                              _f_info.data.values.mac[1],
                              _f_info.data.values.mac[2],
                              _f_info.data.values.mac[3],
                              _f_info.data.values.mac[4],
                              _f_info.data.values.mac[5]);
            NAS_ACL_LOG_DUMP ("  mac-addr-mask = %0x:%0x:%0x:%0x:%0x:%0x ",
                              _f_info.mask.values.mac[0],
                              _f_info.mask.values.mac[1],
                              _f_info.mask.values.mac[2],
                              _f_info.mask.values.mac[3],
                              _f_info.mask.values.mac[4],
                              _f_info.mask.values.mac[5]);
            break;

        case NDI_ACL_FILTER_IPV4_ADDR:
            {
                char buff[INET_ADDRSTRLEN];
                NAS_ACL_LOG_DUMP ("   ipv4 addr = %s, ipv4 addr mask = %s",
                                  inet_ntop (AF_INET, &_f_info.data.values.ipv4,
                                             buff, sizeof(buff)),
                                  inet_ntop (AF_INET, &_f_info.mask.values.ipv4,
                                             buff, sizeof(buff)));
            }
            break;

        case NDI_ACL_FILTER_IPV6_ADDR:
            {
                char buff[INET6_ADDRSTRLEN];
                NAS_ACL_LOG_DUMP ("   ipv6 addr = %s, ipv6 addr mask = %s",
                                  inet_ntop (AF_INET6, &_f_info.data.values.ipv6,
                                             buff, sizeof(buff)),
                                  inet_ntop (AF_INET6, &_f_info.mask.values.ipv6,
                                             buff, sizeof(buff)));
            }
            break;

        case NDI_ACL_FILTER_U32:
            NAS_ACL_LOG_DUMP ("  U32 Value = %u", _f_info.data.values.u32);
            NAS_ACL_LOG_DUMP ("  U32 Mask = %u", _f_info.mask.values.u32);
            break;

        case NDI_ACL_FILTER_U16:
            NAS_ACL_LOG_DUMP ("  U16 Value = %d", _f_info.data.values.u16);
            NAS_ACL_LOG_DUMP ("  U16 Mask = %d", _f_info.mask.values.u16);
            break;

        case NDI_ACL_FILTER_U8:
            NAS_ACL_LOG_DUMP ("  U8 Value = %d", _f_info.data.values.u8);
            NAS_ACL_LOG_DUMP ("  U8 Mask = %d", _f_info.mask.values.u8);
            break;

        case NDI_ACL_FILTER_U8LIST:
            NAS_ACL_LOG_DUMP("   U8 List Value Count = %d",
                             _f_info.data.values.ndi_u8list.byte_count);
            NAS_ACL_LOG_DUMP("   U8 List Value =");
            for (size_t idx = 0; idx < _f_info.data.values.ndi_u8list.byte_count; idx ++) {
                NAS_ACL_LOG_DUMP("%d, ", _f_info.data.values.ndi_u8list.byte_list[idx]);
            }
            NAS_ACL_LOG_DUMP("");
            NAS_ACL_LOG_DUMP("   U8 List Mask Count = %d",
                             _f_info.mask.values.ndi_u8list.byte_count);
            NAS_ACL_LOG_DUMP("   U8 List Mask =");
            for (size_t idx = 0; idx < _f_info.mask.values.ndi_u8list.byte_count; idx ++) {
                NAS_ACL_LOG_DUMP("%d, ", _f_info.mask.values.ndi_u8list.byte_list[idx]);
            }
            NAS_ACL_LOG_DUMP("");
            break;

        default:
            break;
    }
}

nas_obj_id_t nas_acl_filter_t::get_udf_group_from_pos(size_t udf_grp_pos) const
{
    if (_table_p == nullptr) {
        throw nas::base_exception {NAS_ACL_E_FAIL, __PRETTY_FUNCTION__,
            "ACL Table member was not initiated"};
    }
    return _table_p->udf_group_list().at(udf_grp_pos);
}

size_t nas_acl_filter_t::get_udf_group_pos(nas_obj_id_t udf_grp_id) const
{
    if (_table_p == nullptr) {
        throw nas::base_exception {NAS_ACL_E_FAIL, __PRETTY_FUNCTION__,
            "ACL Table member was not initiated"};
    }
    size_t idx = 0;
    for (auto grp_id: _table_p->udf_group_list()) {
        if (grp_id == udf_grp_id) {
            return idx;
        }
        idx ++;
    }

    throw nas::base_exception {NAS_ACL_E_ATTR_VAL, __PRETTY_FUNCTION__,
        std::string {"Invalid UDF Group ID "} + std::to_string (udf_grp_id)};
}
