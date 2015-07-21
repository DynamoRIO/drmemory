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

#define TEST_ONE_BIT_SET(x) (((x) > 0 && ((x) & ((x)-1)) == 0) || ((x) << 1) == 0)

typedef struct _fuzz_target_t {
    app_pc func_pc;
    uint arg_count;
    drfuzz_flags_t flags;
    void (*pre_fuzz_cb)(generic_func_t, void *, INOUT void **);
    bool (*post_fuzz_cb)(generic_func_t, void *, void *);
} fuzz_target_t;

static int drfuzz_init_count;

static int tls_idx_fuzzer;

static hashtable_t fuzz_target_htable;

static void
thread_exit(void *dcontext);

static void
pre_fuzz_handler(void *wrapcxt, INOUT void **user_data);

static void
post_fuzz_handler(void *wrapcxt, void *user_data);

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

DR_EXPORT drmf_status_t
drfuzz_fuzz_target(generic_func_t func_pc, uint arg_count, drfuzz_flags_t flags,
                   void (*pre_fuzz_cb)(generic_func_t target_pc, void *fuzzcxt,
                                       INOUT void **user_data),
                   bool (*post_fuzz_cb)(generic_func_t target_pc, void *fuzzcxt,
                                        void *user_data))
{
    fuzz_target_t *target;

    if (func_pc == NULL)
        return DRMF_ERROR_INVALID_PARAMETER;

    if (!TEST_ONE_BIT_SET(flags & DRFUZZ_CALLCONV_MASK))
        return DRMF_ERROR_INVALID_PARAMETER;

    target = global_alloc(sizeof(fuzz_target_t), HEAPSTAT_MISC);
    target->func_pc = (app_pc) func_pc;
    target->arg_count = arg_count;
    target->flags = flags;
    target->pre_fuzz_cb = pre_fuzz_cb;
    target->post_fuzz_cb = post_fuzz_cb;
    if (!hashtable_add(&fuzz_target_htable, func_pc, target)) {
        free_fuzz_target(target);
        return DRMF_ERROR_INVALID_PARAMETER; /* entry already exists */
    }

    /* wrap after adding to hashtable: avoids racing on presence of hashtable entry */
    if (drwrap_wrap((app_pc) func_pc, pre_fuzz_handler, post_fuzz_handler)) {
        return DRMF_SUCCESS;
    } else {
        hashtable_remove(&fuzz_target_htable, func_pc); /* ignore result: error already */
        return DRMF_ERROR;
    }
}

DR_EXPORT drmf_status_t
drfuzz_get_target_arg(generic_func_t target, int arg, OUT void **arg_value)
{
    /* XXX i#1734: NYI */
    return DRMF_ERROR_NOT_IMPLEMENTED;
}

DR_EXPORT drmf_status_t
drfuzz_set_arg(void *fuzzcxt, int arg, void *val)
{
    if (drwrap_set_arg(fuzzcxt, arg, val))
        return DRMF_SUCCESS;
    else
        return DRMF_ERROR;
    /* XXX i#1734: NYI return DRMF_ERROR when called outside pre_fuzz_handler */
}

static void
pre_fuzz_handler(void *wrapcxt, INOUT void **user_data)
{
    /* XXX i#1734: NYI */
}

static void
post_fuzz_handler(void *wrapcxt, void *user_data)
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
    global_free(p, sizeof(fuzz_target_t), HEAPSTAT_MISC);
}
