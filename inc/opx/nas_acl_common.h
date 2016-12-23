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
 * \file   nas_acl_common.h
 * \brief  NAS ACL header file definitions common to all nas acl files
 * \date   05-2016
 * \author Mukesh MV & Ravikumar Sivasankar
 */

#ifndef _NAS_ACL_COMMON_H_
#define _NAS_ACL_COMMON_H_

#include "nas_types.h"
#include "nas_base_utils.h"
#include "nas_ndi_obj_id_table.h"

#define NAS_ACL_COMMON_DATA_ARR_LEN    128

#define NAS_ACL_MAX_CFI             0x1      /* 1 bit */
#define NAS_ACL_MAX_ECN             0x3      /* 2 bits */
#define NAS_ACL_MAX_IP_FLAGS        0x7      /* 3 bits */
#define NAS_ACL_MAX_IPV6_FLOW_LABEL 0xfffff  /* 20 bits */

/** NAS ACL Error codes */
#define    NAS_ACL_E_NONE           (int)STD_ERR_OK
#define    NAS_ACL_E_MEM            (int)STD_ERR (ACL, NOMEM, 0)

#define    NAS_ACL_E_MISSING_KEY    (int)STD_ERR (ACL, CFG, 1)
#define    NAS_ACL_E_MISSING_ATTR   (int)STD_ERR (ACL, CFG, 2)
#define    NAS_ACL_E_UNSUPPORTED    (int)STD_ERR (ACL, CFG, 3) // Unsupported attribute
#define    NAS_ACL_E_DUPLICATE      (int)STD_ERR (ACL, CFG, 4) // Attribute duplicated in CPS object
#define    NAS_ACL_E_ATTR_LEN       (int)STD_ERR (ACL, CFG, 5) // Unexpected attribute length

#define    NAS_ACL_E_CREATE_ONLY    (int)STD_ERR (ACL, PARAM, 1) // Modify attempt on create-only attribute
#define    NAS_ACL_E_ATTR_VAL       (int)STD_ERR (ACL, PARAM, 2) // Wrong value for attribute
#define    NAS_ACL_E_INCONSISTENT   (int)STD_ERR (ACL, PARAM, 3) // Attribute Value inconsistent
                                                                 // with other attributes

#define    NAS_ACL_E_KEY_VAL        (int)STD_ERR (ACL, NEXIST, 0) // No object with this key

#define    NAS_ACL_E_FAIL           (int)STD_ERR (ACL, FAIL, 0) // All other run time failures

typedef struct _nas_acl_common_data_t {
    union {
        uint8_t                  u8;
        uint16_t                 u16;
        uint32_t                 u32;
        uint64_t                 u64;
        nas_obj_id_t             obj_id;
        hal_ifindex_t            ifindex;
    };
    nas::ifindex_list_t      ifindex_list;
    nas::ndi_obj_id_table_t  ndi_obj_id_table;
    std::vector<uint8_t>     bytes;
} nas_acl_common_data_t;

typedef std::vector<nas_acl_common_data_t> nas_acl_common_data_list_t;

typedef enum NAS_ACL_DATA_TYPE_t {
    NAS_ACL_DATA_NONE,
    NAS_ACL_DATA_U8,
    NAS_ACL_DATA_U16,
    NAS_ACL_DATA_U32,
    NAS_ACL_DATA_U64,
    NAS_ACL_DATA_OBJ_ID,
    NAS_ACL_DATA_BIN,
    NAS_ACL_DATA_IFINDEX,
    NAS_ACL_DATA_IFNAME,
    NAS_ACL_DATA_IFINDEX_LIST,
    NAS_ACL_DATA_IFNAME_LIST,
    NAS_ACL_DATA_EMBEDDED,
    NAS_ACL_DATA_OPAQUE,
    NAS_ACL_DATA_EMBEDDED_LIST,
} NAS_ACL_DATA_TYPE_t;

inline constexpr nas_switch_id_t NAS_ACL_DEFAULT_SWITCH_ID () { return 0;}

const char* nas_acl_obj_data_type_to_str (NAS_ACL_DATA_TYPE_t obj_data_type);
const char* nas_acl_filter_type_name (BASE_ACL_MATCH_TYPE_t type) noexcept;
bool nas_acl_filter_is_type_valid (BASE_ACL_MATCH_TYPE_t f_type) noexcept;
const char* nas_acl_action_type_name (BASE_ACL_ACTION_TYPE_t type) noexcept;
bool nas_acl_action_is_type_valid (BASE_ACL_ACTION_TYPE_t type) noexcept;

#endif /* _NAS_ACL_COMMON_H_ */
