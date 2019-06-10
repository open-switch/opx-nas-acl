/*
 * Copyright (c) 2019 Dell EMC, All rights reserved.
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
 * \file   nas_acl_trapgrp.h
 * \brief  NAS Trap Group Header
 * \date   1-2019
 */

#ifndef _NAS_ACL_TRAPGRP_H_
#define _NAS_ACL_TRAPGRP_H_

#include "dell-base-acl.h"
#include "dell-base-trap.h"
#include "nas_ndi_obj_id_table.h"
#include "nas_base_obj.h"
#include "nas_ndi_acl.h"
#include "nas_ndi_trap.h"

class nas_acl_switch;

#define NAS_ACL_TRAPGRP_ADMIN_DEF          true
#define NAS_ACL_TRAPGRP_QUEUE_ID_DEF       0

/**
* @class NAS ACL Trapgrp
* @brief ACL Trapgrp class derived from Base Object
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

#define NAS_ACL_TRAPGRP_NLEN 32

class nas_acl_trapgrp final : public nas::base_obj_t
{
public:
    nas_acl_trapgrp(nas_acl_switch* switch_p);

    nas_acl_switch& get_switch() const noexcept;


    nas_obj_id_t trapgrp_id() const noexcept { return _trapgrp_id; }
    nas_obj_id_t queue() const noexcept {return _queue_id;}
    const char* name() const override {return _name;}
    nas_obj_id_t admin_state() const noexcept {return _admin_state;}
    ndi_obj_id_t get_ndi_obj_id(npu_id_t npu_id) const;


    void set_trapgrp_id(nas_obj_id_t id) { _trapgrp_id = id; }
    void set_name(const char *name);
    void set_queue(nas_obj_id_t id) { _queue_id = id; mark_attr_dirty(BASE_TRAP_TRAP_GROUP_QUEUE_ID); }
    void set_admin_state(bool state) { _admin_state = state; mark_attr_dirty(BASE_TRAP_TRAP_GROUP_ADMIN); }

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
    nas_obj_id_t _trapgrp_id = 0;
    nas_obj_id_t _queue_id = NAS_ACL_TRAPGRP_QUEUE_ID_DEF;
    
    char _name[NAS_ACL_TRAPGRP_NLEN] = "";
    bool _admin_state = NAS_ACL_TRAPGRP_ADMIN_DEF;

    size_t _acl_ref_cnt = 0;

    // List of mapped NDI IDs one for each NPU
    // managed by this NAS component
    nas::ndi_obj_id_table_t   _ndi_obj_ids;
};

#endif
