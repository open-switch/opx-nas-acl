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
 * filename: nas_acl_switch_list.h
 */


/**
 * \file nas_acl_switch_list.h
 * \brief NAS ACL Switch List header
 **/

#ifndef _NAS_ACL_SWITCH_LIST_H_
#define _NAS_ACL_SWITCH_LIST_H_

#include "nas_types.h"
#include "nas_acl_switch.h"
#include <map>

typedef std::map <nas_obj_id_t, nas_acl_switch> switch_list_t;

const switch_list_t&   nas_acl_get_switch_list () noexcept;
nas_acl_switch&        nas_acl_get_switch (nas_switch_id_t switch_id);

#endif
