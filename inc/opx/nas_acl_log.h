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

/*!
 * \file   nas_acl_common.h
 * \brief  NAS ACL Common macros and typedefs
 * \date   02-2015
 * \author Mukesh MV & Ravikumar Sivasankar
 */

#ifndef _NAS_ACL_LOG_H_
#define _NAS_ACL_LOG_H_

#include "event_log_types.h"
#include "event_log.h"

#define NAS_ACL_LOG_BRIEF(vararg...) \
        EV_LOGGING (ACL, INFO, "NAS-ACL", ## vararg)

#define NAS_ACL_LOG_DETAIL(vararg...) \
        EV_LOGGING (ACL, DEBUG, "NAS-ACL", ## vararg)

#define NAS_ACL_LOG_NOTICE(vararg...) \
        EV_LOGGING (ACL, NOTICE, "NAS-ACL", ## vararg)

#define NAS_ACL_LOG_WARNING(vararg...) \
        EV_LOGGING (ACL, WARNING, "NAS-ACL", ## vararg)

#define NAS_ACL_LOG_ERR(vararg...) \
        EV_LOGGING (ACL, ERR, "NAS-ACL", ## vararg)

#define NAS_ACL_LOG_DUMP(vararg...) \
        EV_LOGGING (ACL, DEBUG, "NAS-ACL", ## vararg)

#endif /* _NAS_ACL_LOG_H_ */
