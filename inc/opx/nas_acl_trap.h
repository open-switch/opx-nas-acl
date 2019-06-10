/*
 * Copyright (c) 2018 Dell Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may
 * not use this file except in compliance with the License. You may obtain
 * a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
 *
 * THIS CODE IS PROVIDED ON AN  *AS IS* BASIS, WITHOUT WARRANTIES OR
 * CONDITIONS OF ANY KIND, EITHER EXPRESS OR IMPLIED, INCLUDING WITHOUT
 * LIMITATION ANY IMPLIED WARRANTIES OR CONDITIONS OF TITLE, FITNESS
 * FOR A PARTICULAR PURPOSE, MERCHANTABLITY OR NON-INFRINGEMENT.
 *
 * See the Apache Version 2.0 License for specific language governing
 * permissions and limitations under the License.
 */

/*!
 * \file   nas_acl_trap.h
 * \brief  NAS Trap Header
 * \date   10-2018
 */

#ifndef _NAS_ACL_TRAP_H_
#define _NAS_ACL_TRAP_H_

#include "dell-base-acl.h"
#include "dell-base-trap.h"
#include "nas_ndi_obj_id_table.h"
#include "nas_base_obj.h"
#include "nas_ndi_acl.h"
#include "nas_ndi_trap.h"

class nas_acl_switch;

#define NAS_ACL_TRAP_TYPE_DEF           BASE_TRAP_TRAP_TYPE_ACL

#define NAS_ACL_TRAP_GRP_ID_NONE        0


/**
* @class NAS ACL Trapid
* @brief ACL Trapid class derived from Base Object
*
* This Class and its methods are designed to be used from CPS request
* handler routines.
* Member functions of this class will throw the
* base_exception or the base_ndi_exception.
*
* Hence the creation, and all member access/calls to objects of this class
* should be wrapped in a try-catch block
*
*/

#define NAS_ACL_TRAP_NLEN 32

class nas_acl_trap final : public nas::base_obj_t
{
public:
    nas_acl_trap(nas_acl_switch* switch_p);

    nas_acl_switch& get_switch() const noexcept;


    nas_obj_id_t trap_id() const noexcept { return _trap_id; }
    BASE_TRAP_TRAP_TYPE_t type() const noexcept {return _type;}
    const char* name() const override {return _name;}
    nas_obj_id_t group() const noexcept {return _group_id;}
    ndi_obj_id_t get_ndi_obj_id(npu_id_t npu_id) const;


    void set_trap_id(nas_obj_id_t id) { _trap_id = id; }
    void set_name(const char *name);
    void set_type(BASE_TRAP_TRAP_TYPE_t t) { _type = t; mark_attr_dirty(BASE_TRAP_TRAP_TYPE); }
    void set_group(nas_obj_id_t id) { _group_id = id; mark_attr_dirty(BASE_TRAP_TRAP_TRAP_GROUP_ID); }

    void commit_create(bool rolling_back) override;
    nas::attr_set_t commit_modify (base_obj_t& entry_orig, bool rolling_back) override;
    void commit_delete(bool rolling_back) override;

    void inc_acl_ref_count() {_acl_ref_cnt ++;}
    void dec_acl_ref_count() {if (_acl_ref_cnt > 0) _acl_ref_cnt --;}


    bool is_acl_ref() const noexcept {return _acl_ref_cnt > 0;}

    e_event_log_types_enums ev_log_mod_id() const override {return ev_log_t_ACL;}
    const char* ev_log_mod_name() const override {return "NAS-ACL";}


    bool push_create_obj_to_npu(npu_id_t npu_id, void* ndi_obj) override;
    bool push_delete_obj_to_npu(npu_id_t npu_id) override;
    bool push_leaf_attr_to_npu (nas_attr_id_t nas_attr_id, npu_id_t npu_id) override;

private:
    BASE_TRAP_TRAP_TYPE_t _type = NAS_ACL_TRAP_TYPE_DEF;

    nas_obj_id_t _trap_id = 0;

    char _name[NAS_ACL_TRAP_NLEN] = "";
    nas_obj_id_t _group_id = NAS_ACL_TRAP_GRP_ID_NONE;

    size_t _acl_ref_cnt = 0;

    // List of mapped NDI IDs one for each NPU
    // managed by this NAS component
    nas::ndi_obj_id_table_t   _ndi_obj_ids;
};

#endif
