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

/**
 * filename: nas_acl_cps_key.h
 **/

/*
 * nas_acl_cps_key.h
 */

#ifndef _NAS_ACL_CPS_KEY_H_
#define _NAS_ACL_CPS_KEY_H_

#include "nas_types.h"
#include "cps_api_object.h"

// Dummy attribute ID since Switch ID is obsolete
#define NAS_ACL_SWITCH_ATTR 0

inline bool nas_acl_cps_key_set_u32 (cps_api_object_t obj,
                                     nas_attr_id_t key_attr_id,
                                     uint32_t      u32) noexcept
{
    return cps_api_set_key_data (obj, key_attr_id, cps_api_object_ATTR_T_U32,
                                 &u32, sizeof (uint32_t));
}

inline bool nas_acl_cps_key_set_obj_id (cps_api_object_t obj,
                                        nas_attr_id_t obj_key_attr_id,
                                        nas_obj_id_t  obj_id) noexcept
{
    return cps_api_set_key_data (obj, obj_key_attr_id, cps_api_object_ATTR_T_U64,
                                 &obj_id, sizeof (uint64_t));
}

inline bool nas_acl_cps_key_get_u32 (const cps_api_object_t obj,
                                     nas_attr_id_t key_attr_id,
                                     uint32_t  *key_val) noexcept
{
    auto key_attr = cps_api_get_key_data (obj, key_attr_id);
    if (key_attr) {
        *key_val = cps_api_object_attr_data_u32 (key_attr);
        return true;
    }
    *key_val = 0;
    return false;
}

inline bool nas_acl_cps_key_get_switch_id (const cps_api_object_t obj,
                                           nas_attr_id_t switch_key_attr_id,
                                           nas_switch_id_t  *switch_id) noexcept
{
    // Concept of Switch ID is obsolete in NAS - always use default Switch ID
    *switch_id = NAS_ACL_DEFAULT_SWITCH_ID ();
    return true;
}

inline bool nas_acl_cps_key_get_obj_id (const cps_api_object_t obj,
                                        nas_attr_id_t obj_key_attr_id,
                                        nas_obj_id_t  *obj_id) noexcept
{
    cps_api_object_attr_t obj_id_attr = cps_api_get_key_data (obj,
                                                              obj_key_attr_id);
    if (obj_id_attr) {
        *obj_id = cps_api_object_attr_data_u64 (obj_id_attr);
        return true;
    }
    *obj_id = 0;
    return false;
}


#endif
