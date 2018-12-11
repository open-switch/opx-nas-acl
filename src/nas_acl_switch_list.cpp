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
 * filename: nas_acl_switch_list.cpp
 */


/**
 * \file nas_acl_switch_list.cpp
 * \brief NAS ACL Switch store
 **/

#include "nas_acl_switch_list.h"
#include "nas_acl_switch.h"
#include "nas_switch.h"

static switch_list_t&  _switches = * new switch_list_t{};

static nas_acl_switch& _save_switch (nas_acl_switch&& s)
{
    /* Inserting new Switch into cache,
     * by moving contents from the argument passed in.
     * Return reference to the newly inserted Switch */
    auto p = _switches.insert (std::make_pair (s.id(), std::move(s)));
    return (p.first->second);
}

const switch_list_t& nas_acl_get_switch_list () noexcept
{
    return _switches;
}

nas_acl_switch& nas_acl_get_switch (nas_switch_id_t switch_id)
{
    /* Try getting switch from local cache.
     * If not present then query it from NAS common library and
     * cache it
     */
    auto it = _switches.find(switch_id);

    if (it != _switches.end ()) {
        return it->second;

    } else {
        // Not in cache .. create a new switch
        // Initialize it with switch ID
        nas_acl_switch sw_tmp{switch_id};

        const nas_switch_detail_t* sw =  nas_switch (switch_id);

        if (sw == NULL) {
            throw nas::base_exception {NAS_ACL_E_KEY_VAL, __PRETTY_FUNCTION__,
                                       std::string {"Invalid Switch ID"}
                                       + std::to_string (switch_id)};
        }

        for (size_t count = 0; count < sw->number_of_npus; count++)
            sw_tmp.add_npu (sw->npus[count]);

        return _save_switch (std::move (sw_tmp));
    }
}
