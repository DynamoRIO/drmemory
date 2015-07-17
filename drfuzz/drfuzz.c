/* **********************************************************
 * Copyright (c) 2015 Google, Inc.  All rights reserved.
 * **********************************************************/

/*
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * * Redistributions of source code must retain the above copyright notice,
 *   this list of conditions and the following disclaimer.
 *
 * * Redistributions in binary form must reproduce the above copyright notice,
 *   this list of conditions and the following disclaimer in the documentation
 *   and/or other materials provided with the distribution.
 *
 * * Neither the name of Google, Inc. nor the names of its contributors may be
 *   used to endorse or promote products derived from this software without
 *   specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL GOOGLE, INC. OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
 * CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH
 * DAMAGE.
 */

#include "dr_api.h"
#include "dr_defines.h"
#include "drwrap.h"
#include "drmgr.h"
#include "hashtable.h"
#include "utils.h"
#include "drfuzz.h"

#ifdef UNIX
typedef dr_siginfo_t drfuzz_crash_info_t;
typedef dr_signal_action_t drfuzz_crash_action_t;
# define CRASH_CONTINUE DR_SIGNAL_DELIVER
#else
typedef dr_exception_t drfuzz_crash_info_t;
typedef bool drfuzz_crash_action_t;
# define CRASH_CONTINUE true
#endif

#ifdef UNIX
# define DRFUZZ_CRASH_CONTINUE = DR_SIGNAL_DELIVER
#else /* WINDOWS */
# define DRFUZZ_CRASH_CONTINUE = false
#endif

static int drfuzz_init_count;

static int tls_idx_fuzzer;

static hashtable_t fuzz_target_htable;

static void
thread_exit(void *dcontext);

static drfuzz_crash_action_t
crash_handler(void *dcontext, drfuzz_crash_info_t *crash);

static void
free_fuzz_target(void *p);

DR_EXPORT drmf_status_t
drfuzz_init(client_id_t client_id)
{
    drmf_status_t res;
    int count = dr_atomic_add32_return_sum(&drfuzz_init_count, 1);
    if (count > 1)
        return DRMF_SUCCESS;

    res = drmf_check_version(client_id);
    if (res != DRMF_SUCCESS)
        return res;

    drwrap_init();

#ifdef UNIX
    drmgr_register_signal_event(crash_handler);
#else /* WINDOWS */
    drmgr_register_exception_event(crash_handler);
#endif
    drmgr_register_thread_exit_event(thread_exit);

    tls_idx_fuzzer = drmgr_register_tls_field();
    if (tls_idx_fuzzer < 0) {
        LOG(1, "drfuzz failed to reserve TLS slot--initialization failed");
        return DRMF_ERROR;
    }

    /* Synchronized to allow addition and removal of fuzz targets during execution
     * of the target program, e.g. to explore control flow paths.
     */
    hashtable_init_ex(&fuzz_target_htable, 3, HASH_INTPTR, false/*no strdup*/,
                      true/*synchronized*/, free_fuzz_target, NULL/*no custom hash*/,
                      NULL/*no custom comparator*/);

    return DRMF_SUCCESS;
}

DR_EXPORT drmf_status_t
drfuzz_exit(void)
{
    int count = dr_atomic_add32_return_sum(&drfuzz_init_count, -1);
    if (count > 0)
        return DRMF_SUCCESS;
    if (count < 0)
        return DRSYM_ERROR;

    drwrap_exit();

    hashtable_delete(&fuzz_target_htable);

    return DRMF_SUCCESS;
}

static void
thread_exit(void *dcontext)
{
    /* XXX i#1734: NYI */
}

static drfuzz_crash_action_t
crash_handler(void *dcontext, drfuzz_crash_info_t *crash)
{
    /* XXX i#1734: NYI */
    return CRASH_CONTINUE;
}

static void
free_fuzz_target(void *p)
{
    /* XXX i#1734: NYI */
}
