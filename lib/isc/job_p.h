/*
 * Copyright (C) Internet Systems Consortium, Inc. ("ISC")
 *
 * SPDX-License-Identifier: MPL-2.0
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, you can obtain one at https://mozilla.org/MPL/2.0/.
 *
 * See the COPYRIGHT file distributed with this work for additional
 * information regarding copyright ownership.
 */

#pragma once

#include <isc/align.h>
#include <isc/job.h>
#include <isc/loop.h>
#include <isc/os.h>
#include <isc/uv.h>

/*%
 * NOTE: We are using struct __cds_wfcq_head that doesn't have an internal
 * mutex, because we are only using enqueue and splice, and those don't need
 * any synchronization (see urcu/wfcqueue.h for detailed description).
 */
typedef struct isc_jobqueue {
	alignas(ISC_OS_CACHELINE_SIZE) struct __cds_wfcq_head head;
	alignas(ISC_OS_CACHELINE_SIZE) struct cds_wfcq_tail tail;
} isc_jobqueue_t;

typedef ISC_LIST(isc_job_t) isc_joblist_t;

void
isc__job_cb(uv_idle_t *handle);

void
isc__job_close(uv_handle_t *handle);
