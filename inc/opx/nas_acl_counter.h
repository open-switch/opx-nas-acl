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

/*
 * filename: nas_acl_counter.h
 */


/**
 * \file nas_acl_counter.h
 * \brief NAS ACL Counter Class Definition
 **/

#include "nas_ndi_obj_id_table.h"
#include "nas_base_obj.h"
#include "nas_ndi_acl.h"
#include "nas_acl_log.h"
#include "std_assert.h"
#include <set>

class nas_acl_switch;
class nas_acl_table;

#ifndef NAS_ACL_COUNTER_H_
#define NAS_ACL_COUNTER_H_

class nas_acl_counter_t final : public nas::base_obj_t
{
public:
    enum class counter {
        PKT,
        BYTE,
    };
    ////// Constructor /////
    nas_acl_counter_t (const nas_acl_table* table_p);

    /////// Accessors ////////
    const nas_acl_table&     get_table() const noexcept {return *_table_p;}
    nas_obj_id_t             table_id() const noexcept;
    const char*              table_name() const noexcept;
    nas_obj_id_t             counter_id() const noexcept {return _counter_id;}
    ndi_obj_id_t             ndi_obj_id (npu_id_t npu_id) const;
    bool                     is_obj_in_npu (npu_id_t  npu_id) const noexcept;
    bool following_table_npus () const noexcept {return _following_table_npus;}

    t_std_error get_pkt_count_ndi(npu_id_t,  uint64_t*) const noexcept;
    t_std_error get_byte_count_ndi(npu_id_t, uint64_t*) const noexcept;

    bool is_pkt_count_enabled() const noexcept {return _enable_pkt_count;}
    bool is_byte_count_enabled() const noexcept {return _enable_byte_count;}

    //////// Modifiers ////////
    void set_counter_id (nas_obj_id_t id);
    void set_type (uint_t type, bool reset=true);
    void set_counter_name(const char* name);
    void add_npu (npu_id_t npu_id, bool reset=true) override;
    void add_ref (nas_obj_id_t entry_id);
    void del_ref (nas_obj_id_t entry_id);

    void set_pkt_count_ndi (npu_id_t,  uint64_t) const;
    void set_byte_count_ndi (npu_id_t, uint64_t) const;

    const char* name () const override {return "ACL Counter";}
    e_event_log_types_enums ev_log_mod_id () const
        override {return ev_log_t_ACL;}
    const char* ev_log_mod_name () const override {return "NAS-ACL";}

    void commit_create (bool rolling_back) override;
    nas::attr_set_t commit_modify (base_obj_t& entry_orig,
                                   bool rolling_back) override;
    void commit_delete (bool rolling_back) override;

    bool push_create_obj_to_npu (npu_id_t npu_id, void* ndi_obj) override;

    bool push_delete_obj_to_npu (npu_id_t npu_id) override;

    bool push_leaf_attr_to_npu (nas_attr_id_t attr_id,
                                npu_id_t npu_id) override {return true;}
    const char* counter_name() const
    {
        if (_counter_name.size() > 0) {
            return _counter_name.c_str();
        } else {
            return nullptr;
        }
    }

private:
    const nas_acl_table*   _table_p;
    nas_obj_id_t           _counter_id = 0;
    std::string            _counter_name;
    bool                   _enable_pkt_count = false;
    bool                   _enable_byte_count = false;
    bool                   _following_table_npus = true;

    /* Used only in case of Modify - as a Diff */
    std::set<BASE_ACL_COUNTER_TYPE_t>  _types_to_be_pushed;

    /* List of entries referring to this counter */
    std::set<nas_obj_id_t>   _refs;

    // List of mapped NDI IDs one for each NPU
    // managed by this NAS component
    nas::ndi_obj_id_table_t  _ndi_obj_ids;

    void copy_table_npus ();
    void diff_counter_type (nas_acl_counter_t& counter_orig);
    bool _validate_entry_counter (counter c_type, npu_id_t npu_id,
                                  ndi_obj_id_t *ndi_counter_id_p) const noexcept;
};

inline void nas_acl_counter_t::set_counter_id (nas_obj_id_t id) {
    STD_ASSERT (_counter_id == 0); // Something wrong .. Counter already has a ID
    _counter_id = id;
}

inline bool nas_acl_counter_t::is_obj_in_npu (npu_id_t  npu_id) const noexcept {
    return (_ndi_obj_ids.find (npu_id) != _ndi_obj_ids.end ());
}

inline ndi_obj_id_t  nas_acl_counter_t::ndi_obj_id (npu_id_t npu_id) const {
    return _ndi_obj_ids.at (npu_id);
}

inline void nas_acl_counter_t::add_ref (nas_obj_id_t entry_id) {
    _refs.insert (entry_id);
    NAS_ACL_LOG_DETAIL ("Counter %ld referred by Entry %ld", counter_id(), entry_id);
}
inline void nas_acl_counter_t:: del_ref (nas_obj_id_t entry_id) {
    _refs.erase (entry_id);
    NAS_ACL_LOG_DETAIL ("Counter %ld no longer referred by Entry %ld", counter_id(), entry_id);
}

#endif /* NAS_ACL_COUNTER_H_ */
