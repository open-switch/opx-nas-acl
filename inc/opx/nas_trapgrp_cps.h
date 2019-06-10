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
 * \file   nas_trapgrp_cps.h
 * \brief  NAS TRAPGRP CPS API prototypes
 * \date   12-2018
 */

#ifndef _NAS_TRAPGRP_CPS_H_
#define _NAS_TRAPGRP_CPS_H_

#include "cps_api_operation.h"
#include "dell-base-trap.h"

cps_api_return_code_t nas_trapgrp_cps_api_read (void * context,
                                                cps_api_get_params_t * param,
                                                size_t ix);

cps_api_return_code_t nas_trapgrp_cps_api_write (void * context,
                                                 cps_api_transaction_params_t * param,
                                                 size_t ix);

cps_api_return_code_t nas_trapgrp_cps_api_rollback (void * context,
                                                    cps_api_transaction_params_t * param,
                                                    size_t index);

#endif
