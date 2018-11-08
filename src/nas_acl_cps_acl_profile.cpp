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
 * \file   nas_acl_cps_acl_profile.cpp
 * \brief  This file contains CPS functions related to ACL profile functionality
 * \date   08-2018
 */

#include "event_log.h"
#include "std_error_codes.h"
#include "std_utils.h"
#include "std_error_codes.h"
#include "nas_acl_log.h"
#include "nas_acl_cps.h"
#include "cps_api_object_key.h"
#include "cps_class_map.h"
#include "nas_acl_cps_key.h"
#include "nas_sw_profile_api.h"

/* this function is used to retrieve the switch ACL profile information */
t_std_error
nas_acl_profile_info_get (cps_api_get_params_t *param, size_t index,
                          cps_api_object_t filter_obj) noexcept
{
    t_std_error       rc = NAS_ACL_E_NONE;
    nas_switch_id_t   switch_id;

    cps_api_object_attr_t switch_id_attr = cps_api_object_attr_get (filter_obj,
                                                  BASE_ACL_SWITCHING_ENTITY_SWITCH_ID);

    if ((switch_id_attr != NULL) &&
        ((switch_id = cps_api_object_attr_data_u32(switch_id_attr)) != NAS_CMN_DEFAULT_SWITCH_ID)) {
        NAS_ACL_LOG_ERR ("switch id(%d) not valid", switch_id);
        return NAS_ACL_E_ATTR_VAL;
    }

    cps_api_object_t obj = cps_api_object_list_create_obj_and_append (param->list);

    if (!obj) {
        NAS_ACL_LOG_ERR ("Obj Append failed for ACL profile get. Index: %ld", index);
        return STD_ERR(ACL, FAIL, 0);
    }

    if (!cps_api_key_from_attr_with_qual (cps_api_object_key (obj),
                BASE_ACL_SWITCHING_ENTITY_OBJ,
                cps_api_qualifier_TARGET)) {
        NAS_ACL_LOG_ERR ("Failed to create Key from Switching entity Object");
        return STD_ERR(ACL, FAIL, 0);
    }

    cps_api_object_attr_add_u32(obj,
            BASE_ACL_SWITCHING_ENTITY_SWITCH_ID,
            NAS_CMN_DEFAULT_SWITCH_ID);

    rc = nas_sw_acl_profile_info_get (obj);

    return (rc);
}


/* this function is used to retrieve the app-group information from ACL profile */
t_std_error
nas_acl_profile_app_group_info_get (cps_api_get_params_t *param, size_t index,
                                    cps_api_object_t filter_obj) noexcept
{
    t_std_error       rc = NAS_ACL_E_NONE;
    nas_switch_id_t   switch_id;
    char              app_group_name[NAS_CMN_PROFILE_NAME_SIZE];

    cps_api_qualifier_t qualifier = cps_api_key_get_qual(cps_api_object_key(filter_obj));

    cps_api_object_attr_t switch_id_attr = cps_api_object_attr_get (filter_obj,
                                                  BASE_ACL_SWITCHING_ENTITY_SWITCH_ID);
    cps_api_object_attr_t  app_group_id_attr = cps_api_object_attr_get (filter_obj,
                                                      BASE_ACL_SWITCHING_ENTITY_APP_GROUP_ID);

    if ((switch_id_attr != NULL) &&
        ((switch_id = cps_api_object_attr_data_u32(switch_id_attr)) != NAS_CMN_DEFAULT_SWITCH_ID)) {
        NAS_ACL_LOG_ERR ("switch id(%d) not valid", switch_id);
        return NAS_ACL_E_MISSING_KEY;
    }

    if (app_group_id_attr == NULL) {
        /* get all app group information */
        rc = nas_sw_acl_profile_app_group_info_get (NULL, true, param->list, qualifier);
    } else {
        /* get app group information for given app_group_name */
        safestrncpy(app_group_name, (const char *)cps_api_object_attr_data_bin(app_group_id_attr),
                    sizeof(app_group_name));

        /* retrieve the app-group level info */
        rc = nas_sw_acl_profile_app_group_info_get (app_group_name, false, param->list, qualifier);
    }

    return (rc);
}

/* this function is used to configure the acl profile app-group to pool-count */
t_std_error
nas_acl_profile_set (cps_api_object_t obj,
                     cps_api_object_t prev,
                     bool             is_rollbk_op) noexcept
{
    t_std_error       rc = NAS_ACL_E_NONE;
    nas_switch_id_t   switch_id;
    char              app_group_name[NAS_CMN_PROFILE_NAME_SIZE];

    cps_api_object_attr_t switch_id_attr = cps_api_object_attr_get (obj,
                                                  BASE_ACL_SWITCHING_ENTITY_SWITCH_ID);
    cps_api_object_attr_t  app_group_id_attr = cps_api_object_attr_get (obj,
                                                  BASE_ACL_SWITCHING_ENTITY_APP_GROUP_ID);

    cps_api_object_attr_t val_attr = cps_api_object_attr_get (obj,
                                                  BASE_ACL_SWITCHING_ENTITY_APP_GROUP_POOL_COUNT);

    if ((switch_id_attr == NULL) || (app_group_id_attr == NULL)) {
        NAS_ACL_LOG_ERR ("Switch ID and APP group id is a mandatory key for update.");
        return NAS_ACL_E_MISSING_KEY;
    }

    switch_id = cps_api_object_attr_data_u32(switch_id_attr);
    if (switch_id != NAS_CMN_DEFAULT_SWITCH_ID) {
        NAS_ACL_LOG_ERR ("switch id(%d) not valid", switch_id);
        return NAS_ACL_E_KEY_VAL;
    }

    if (val_attr == NULL)
    {
        NAS_ACL_LOG_ERR ("Missing attribute");
        return NAS_ACL_E_MISSING_ATTR;
    }

    NAS_ACL_LOG_BRIEF ("%sSwitch Id: %d",
                       (is_rollbk_op) ? "** ROLLBACK **: " : "", switch_id);

    safestrncpy(app_group_name,
                (const char *) cps_api_object_attr_data_bin(app_group_id_attr),
                sizeof(app_group_name));

    uint32_t next_boot_pool_count = cps_api_object_attr_data_u32(val_attr);

    NAS_ACL_LOG_BRIEF("switch-id:%d, app_group_name:%s, next_boot_pool_count:%d",
                      switch_id, app_group_name, next_boot_pool_count);

    /* configure the app-group level info */
    rc = nas_sw_acl_profile_app_group_info_set (app_group_name, next_boot_pool_count,
                                                cps_api_oper_SET);
    if (rc != STD_ERR_OK)
    {
        NAS_ACL_LOG_ERR("Error in configuration - switch-id:%d, "
                        "app_group_name:%s, next_boot_pool_count:%d",
                        switch_id, app_group_name, next_boot_pool_count);
        return NAS_ACL_E_FAIL;
    }

    /* update the running CPS DB */
    rc = nas_switch_upd_acl_profile_info_to_running_cps_db (switch_id);
    if (rc != STD_ERR_OK)
    {
        NAS_ACL_LOG_ERR("Error in updating ACL profile DB to running CPS DB.");
        return NAS_ACL_E_FAIL;
    }

    NAS_ACL_LOG_BRIEF ("Successful ");
    return NAS_ACL_E_NONE;

}
