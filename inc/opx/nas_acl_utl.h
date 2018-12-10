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
 * filename: nas_acl_utl.h
 */


/**
 * \file nas_acl_utl.h
 * \brief NAS ACL Utility header
 **/

#ifndef NAS_ACL_UTL_H_
#define NAS_ACL_UTL_H_

#include "hal_if_mapping.h"
#include "ds_common_types.h"
#include "dell-base-acl.h"
#include "nas_types.h"

void nas_acl_utl_ifidx_to_ndi_port (hal_ifindex_t ifindex,
                                    interface_ctrl_t *intf_ctrl_p);
bool nas_acl_utl_is_ifidx_type_lag (hal_ifindex_t ifindex);

class nas_acl_switch;

class nas_acl_id_guard_t
{
public:
    nas_acl_id_guard_t (nas_acl_switch& sw, BASE_ACL_OBJECTS_t obj, nas_obj_id_t table_id=0) noexcept
    : _sw_p(&sw), _obj_type(obj), _table_id(table_id) {};
    nas_acl_id_guard_t (nas_acl_id_guard_t&& g) noexcept;

    ~nas_acl_id_guard_t () noexcept;

    nas_obj_id_t alloc_guarded_id ();
    bool         reserve_guarded_id (nas_obj_id_t id);
    void         unguard () noexcept  {_guarding = false;_guarded_id=0;}

    nas_acl_id_guard_t (const nas_acl_id_guard_t& g) = delete;
    nas_acl_id_guard_t& operator= (const nas_acl_id_guard_t& g) = delete;
    nas_acl_id_guard_t& operator= (nas_acl_id_guard_t&& g) noexcept;

private:
    nas_acl_switch* _sw_p;
    BASE_ACL_OBJECTS_t  _obj_type;
    nas_obj_id_t    _table_id;
    bool _guarding = false;
    nas_obj_id_t _guarded_id = 0;
};

inline nas_acl_id_guard_t::nas_acl_id_guard_t (nas_acl_id_guard_t&& g) noexcept
    : _sw_p(g._sw_p), _obj_type(g._obj_type), _table_id(g._table_id)
{
    _guarded_id = g._guarded_id; _guarding = g._guarding;
    g._guarded_id = 0; g._guarding = false;
}

inline nas_acl_id_guard_t& nas_acl_id_guard_t::operator= (nas_acl_id_guard_t&& g) noexcept
{
    _sw_p = g._sw_p; _obj_type = g._obj_type; _table_id = g._table_id;
    _guarded_id = g._guarded_id; _guarding = g._guarding;
    g._guarded_id = 0; g._guarding = false;
    return *this;
}

#ifdef __cplusplus
extern "C" {
#endif

int cps_api_interface_name_to_if_index(const char *name);
const char * cps_api_interface_if_index_to_name(int index, char *buff, unsigned int len);

#ifdef __cplusplus
}
#endif

#endif /* NAS_ACL_UTL_H_ */
