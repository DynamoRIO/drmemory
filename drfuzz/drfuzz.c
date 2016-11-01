/* **********************************************************
 * Copyright (c) 2015-2016 Google, Inc.  All rights reserved.
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
#include <string.h>
#include "drwrap.h"
#include "drmgr.h"
#include "hashtable.h"
#include "utils.h"
#include "drfuzz.h"
#include "drfuzz_internal.h"
#include "drfuzz_mutator.h" /* default mutator */
#include "../framework/drmf.h"

#ifdef UNIX
# include <signal.h>
#endif

#define ARGSIZE(target) ((target)->arg_count * sizeof(reg_t))

#ifdef UNIX
typedef dr_signal_action_t drfuzz_fault_action_t;
# define CRASH_CONTINUE DR_SIGNAL_DELIVER
#else
typedef bool drfuzz_fault_action_t;
# define CRASH_CONTINUE true
#endif

static uint64 num_total_bbs;

/* Represents one fuzz target together with the client's registered callbacks */
typedef struct _fuzz_target_t {
    app_pc func_pc;
    uint arg_count;
    uint flags;
    uint64 num_bbs;  /* number of basic blocks seen during fuzzing */
    void *user_data; /* see drfuzz_{g,s}et_target_user_data() */
    void (*delete_user_data_cb)(void *user_data);
    void (*pre_fuzz_cb)(void *, generic_func_t, dr_mcontext_t *);
    bool (*post_fuzz_cb)(void *, generic_func_t);
} fuzz_target_t;

/* Restores the return address corresponding to the normal call stack in case it was
 * clobbered. For example, in x86 a client may use dr_clobber_retaddr_after_read() to
 * improve call stack legibility; or in ARM the app may save the link register to the
 * stack, in which case we will not know where to find it when returning from fuzzing.
 */
typedef struct _retaddr_unclobber_t {
#ifdef X86
    reg_t *retaddr_loc;     /* stack location of the return address */
#endif
    reg_t retaddr;          /* return address value (while this target is live) */
} retaddr_unclobber_t;

/**************************************************************************************
 * Fuzzing Terminology:
 *
 *   Top-level Fuzz Target: An execution of a fuzz target in which no other fuzz targets
 *                          precede it on the call stack; also known as an "outer" target.
 *   Nested Fuzz Target:    A fuzz target execution that follows other fuzz targets on the
 *                          call stack; also known as an "inner" target. Note that a given
 *                          function may be called as a top-level target at one point
 *                          during execution, and as a nested target at some other point.
 *   Fuzz Pass:             A sequence of fuzzer-driven repetitions of one top-level
 *                          target, in which mutation of arguments covers the full domain
 *                          of each argument to the extent specified in the mutation plan.
 *   Fuzz Iteration:        A single invocation of a top-level fuzz target, including all
 *                          iterations of all nested targets encountered.
 */

/* Snapshot of a fuzz_pass_context_t */
typedef struct _target_iterator_t {
    void *dcontext; /* the dcontext corresponding to the captured fuzz_pass_context_t */
    uint index;     /* iteration index */
    uint target_count;
    drfuzz_target_frame_t *targets;
} target_iterator_t;

/* max size of the recorded chain of faults for a single fuzz target (stored in
 * drfuzz_fault_thread_state_t.faults) in the current implementation.
 */
#define FAULT_CHAIN_ARRAY_MAX 2
#define FIRST_FAULT(fp) ((fp)->thread_state->faults[0])
#define LAST_FAULT(fp) ((fp)->thread_state->faults[1])
#define SIZEOF_FAULT_CHAIN_ARRAY (FAULT_CHAIN_ARRAY_MAX * sizeof(drfuzz_fault_t))

/* Stores thread-specific state for an executing fuzz target, which is required for
 * repeating the target and for reporting a crash (can't use the drwrap `user_data` b/c
 * it is deleted in post-wrap, and we must hold these values from post-wrap to pre-wrap).
 */
typedef struct _pass_target_t {
    void *wrapcxt;
    fuzz_target_t *target;
    reg_t xsp;            /* stack level at entry to the fuzz target */
#ifdef ARM
    reg_t lr;             /* link register value at entry */
#endif
    retaddr_unclobber_t unclobber; /* see comment on retaddr_unclobber_t */
    reg_t *original_args; /* original arg values passed by the app to the fuzz target */
    reg_t *current_args;  /* fuzzed argument values for the current iteration */
    void *user_data;      /* see drfuzz_{g,s}et_target_per_thread_user_data() */
    void (*delete_user_data_cb)(void *fuzzcxt, void *user_data);
    struct _pass_target_t *next;   /* chains either stack in fuzz_pass_context_t */
} pass_target_t;

/* Thread-local storage for a fuzz pass context, including the set of targets that are
 * live on the call stack, and a cache of targets that have been live in this fuzz pass.
 */
typedef struct _fuzz_pass_context_t {
    /*
     * dcontext of the thread
     */
    void *dcontext;
    /* Stack of fuzz targets that are live on this thread; i.e., the subset of the call
     * stack which are fuzz targets. Chained in pass_target_t.next.
     */
    pass_target_t *live_targets;
    /* Stack-shaped cache of fuzz targets that have been live in the current fuzz pass,
     * but are not presently live. Cleared at the end of each fuzz pass, or anytime a fuzz
     * pass diverges from its cached target stack. Chained in pass_target_t.next.
     */
    pass_target_t *cached_targets;
    /* Stores thread state information about live fuzz targets and chained faults whenever
     * a critical fault occurs on this context's thread. Also stores the live fuzz targets
     * when this thread is terminated by an application crash.
     */
    drfuzz_fault_thread_state_t *thread_state;
} fuzz_pass_context_t;

typedef void (*fault_event_t)(void *fuzzcxt,
                              drfuzz_fault_t *fault,
                              drfuzz_fault_ex_t *fault_ex);

typedef void (*fault_delete_callback_t)(void *fuzzcxt,
                                        drfuzz_fault_t *fault);

typedef void (*crash_thread_event_t)(void *fuzzcxt,
                                     drfuzz_fault_thread_state_t *state);

typedef void (*crash_process_event_t)(drfuzz_crash_state_t *state);

/* Container for client-registered callback lists */
typedef struct _drfuzz_callbacks_t {
    fault_event_t fault_event;
    fault_delete_callback_t fault_delete_callback;
    crash_thread_event_t crash_thread_event;
    crash_process_event_t crash_process_event;
} drfuzz_callbacks_t;

static int drfuzz_init_count;

static int tls_idx_fuzzer;

static hashtable_t fuzz_target_htable;

static drfuzz_callbacks_t *callbacks;

static void
thread_init(void *dcontext);

static void
thread_exit(void *dcontext);

static dr_emit_flags_t
bb_event(void *drcontext, void *tag, instrlist_t *bb,
         bool for_trace, bool translating);

static void
pre_fuzz_handler(void *wrapcxt, INOUT void **user_data);

static void
post_fuzz_handler(void *wrapcxt, void *user_data);

static pass_target_t *
lookup_live_target(fuzz_pass_context_t *fp, app_pc target_pc);

static pass_target_t *
activate_cached_target(fuzz_pass_context_t *fp, app_pc target_pc);

static pass_target_t *
create_pass_target(void *dcontext, void *wrapcxt);

static drfuzz_fault_thread_state_t *
create_fault_state(void *dcontext);

static drfuzz_target_iterator_t *
create_target_iterator(fuzz_pass_context_t *fp);

static void
capture_fault(void *dcontext, drfuzz_fault_t *fault, drfuzz_fault_ex_t *fault_ex);

static drfuzz_fault_action_t
fault_handler(void *dcontext, drfuzz_fault_ex_t *fault_ex);

static bool
is_critical_fault(drfuzz_fault_ex_t *fault);

static void
clear_cached_targets(fuzz_pass_context_t *fp);

static void
clear_pass_targets(fuzz_pass_context_t *fp);

static void
clear_thread_state(fuzz_pass_context_t *fp);

static void
free_fuzz_target(void *p);

static void
free_pass_target(fuzz_pass_context_t *fp, pass_target_t *target);

static void
free_thread_state(fuzz_pass_context_t *fp);

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

    callbacks = global_alloc(sizeof(drfuzz_callbacks_t), HEAPSTAT_MISC);
    memset(callbacks, 0, sizeof(drfuzz_callbacks_t));

    drmgr_init();
    drwrap_init();

#ifdef UNIX
    drmgr_register_signal_event(fault_handler);
#else /* WINDOWS */
    drmgr_register_exception_event(fault_handler);
#endif
    drmgr_register_thread_init_event(thread_init);
    drmgr_register_thread_exit_event(thread_exit);
    drmgr_register_bb_app2app_event(bb_event, NULL);

    tls_idx_fuzzer = drmgr_register_tls_field();
    if (tls_idx_fuzzer < 0) {
        DRFUZZ_ERROR("drfuzz failed to reserve TLS slot--initialization failed\n");
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
        return DRMF_ERROR;

    global_free(callbacks, sizeof(drfuzz_callbacks_t), HEAPSTAT_MISC);

    drmgr_exit();
    drwrap_exit();

    hashtable_delete(&fuzz_target_htable);

    return DRMF_SUCCESS;
}

static void
thread_init(void *dcontext)
{
    fuzz_pass_context_t *fp = thread_alloc(dcontext, sizeof(fuzz_pass_context_t),
                                           HEAPSTAT_MISC);
    memset(fp, 0, sizeof(fuzz_pass_context_t));
    fp->dcontext = dcontext;
    fp->thread_state = create_fault_state(dcontext);
    drmgr_set_tls_field(dcontext, tls_idx_fuzzer, (void *) fp);
}

static void
thread_exit(void *dcontext)
{
    fuzz_pass_context_t *fp = (fuzz_pass_context_t *) drmgr_get_tls_field(dcontext,
                                                                          tls_idx_fuzzer);

    /* crash is indicated by aborted fuzz targets, even if the app did a hard exit() */
    if (fp->live_targets != NULL) {
        if (callbacks->crash_thread_event != NULL) {
            /* There may be targets already captured by a fault event. If not, and if fuzz
             * targets were evidently aborted, then make them available in an iterator.
             */
            if (fp->thread_state->targets == NULL && fp->live_targets != NULL)
                fp->thread_state->targets = create_target_iterator(fp);

            callbacks->crash_thread_event(fp, fp->thread_state);
        }
    }

    free_thread_state(fp);
    clear_pass_targets(fp);
    thread_free(dcontext, fp, sizeof(fuzz_pass_context_t), HEAPSTAT_MISC);
}

static dr_emit_flags_t
bb_event(void *drcontext, void *tag, instrlist_t *bb,
         bool for_trace, bool translating)
{
    fuzz_pass_context_t *fp;
    pass_target_t *live;

    if (for_trace || translating)
        return DR_EMIT_DEFAULT;

    /* It is ok to be racy, so hold no locks for updating. */
    /* update global num_bbs */
    num_total_bbs++;
    /* update num_bbs for each live target */
    fp = (fuzz_pass_context_t *) drmgr_get_tls_field(drcontext, tls_idx_fuzzer);
    live = fp->live_targets;
    if (live != NULL) {
        /* XXX: the function entry basic block is not counted because the live target
         * is only added on its first execution after bb_event.
         */
        live->target->num_bbs++;
        DRFUZZ_LOG(3, "basic block "UINT64_FORMAT_STRING" @"PFX" during fuzzing "PFX"\n",
                   live->target->num_bbs, tag, live->target->func_pc);
    }
    return DR_EMIT_DEFAULT;
}

DR_EXPORT drmf_status_t
drfuzz_fuzz_target(generic_func_t func_pc, uint arg_count, uint flags, uint wrap_flags,
                   void (*pre_fuzz_cb)(void *fuzzcxt, generic_func_t target_pc,
                                       dr_mcontext_t *mc),
                   bool (*post_fuzz_cb)(void *fuzzcxt, generic_func_t target_pc))
{
    fuzz_target_t *target;

    if (func_pc == NULL)
        return DRMF_ERROR_INVALID_PARAMETER;

    target = global_alloc(sizeof(fuzz_target_t), HEAPSTAT_MISC);
    memset(target, 0, sizeof(fuzz_target_t));
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
    if (drwrap_wrap_ex((app_pc) func_pc, pre_fuzz_handler, post_fuzz_handler,
                       NULL, wrap_flags)) {
        return DRMF_SUCCESS;
    } else {
        hashtable_remove(&fuzz_target_htable, func_pc); /* ignore result: error already */
        return DRMF_ERROR;
    }
}

DR_EXPORT drmf_status_t
drfuzz_unfuzz_target(generic_func_t func_pc)
{
    drmf_status_t res = DRMF_SUCCESS;
    fuzz_pass_context_t *fp = drfuzz_get_fuzzcxt();
    pass_target_t *live_target = lookup_live_target(fp, (app_pc) func_pc);
    fuzz_target_t *target = hashtable_lookup(&fuzz_target_htable, func_pc);

    if (target == NULL)
        return DRMF_ERROR_INVALID_PARAMETER;
    if (live_target != NULL) {
        /* XXX i#1734: ideally we would check all threads, or flag the target as live */
        DRFUZZ_ERROR("Attempt to unfuzz a live fuzz target\n");
        return DRMF_ERROR; /* cannot unfuzz the target in this state */
    }
    if (!hashtable_remove(&fuzz_target_htable, func_pc)) {
        DRFUZZ_ERROR("failed to remove "PIFX" from the fuzz target hashtable\n", func_pc);
        res = DRMF_ERROR;         /* Missing entry does not prevent unfuzzing, */
        free_fuzz_target(target); /* but at least free it.                     */
    }
    if (!drwrap_unwrap((app_pc) func_pc, pre_fuzz_handler, post_fuzz_handler)) {
        DRFUZZ_ERROR("failed to unwrap the fuzz target "PIFX" via drwrap_unwrap\n",
                     func_pc);
        res = DRMF_ERROR;
    }
    return res;
}

DR_EXPORT drmf_status_t
drfuzz_register_fault_event(void (*event)(void *fuzzcxt,
                                          drfuzz_fault_t *fault,
                                          drfuzz_fault_ex_t *fault_ex))
{
    if (callbacks->fault_event != NULL)
        return DRMF_ERROR;
    callbacks->fault_event = event;
    return DRMF_SUCCESS;
}

DR_EXPORT drmf_status_t
drfuzz_unregister_fault_event(void (*event)(void *fuzzcxt,
                                          drfuzz_fault_t *fault,
                                          drfuzz_fault_ex_t *fault_ex))
{
    if (callbacks->fault_event != event)
        return DRMF_ERROR_INVALID_PARAMETER;
    callbacks->fault_event = NULL;
    return DRMF_SUCCESS;
}

DR_EXPORT drmf_status_t
drfuzz_register_fault_delete_callback(void (*callback)(void *fuzzcxt,
                                                       drfuzz_fault_t *fault))
{
    if (callbacks->fault_delete_callback != NULL)
        return DRMF_ERROR;
    callbacks->fault_delete_callback = callback;
    return DRMF_SUCCESS;
}

DR_EXPORT drmf_status_t
drfuzz_unregister_fault_delete_callback(void (*callback)(void *fuzzcxt,
                                                         drfuzz_fault_t *fault))
{
    if (callbacks->fault_delete_callback != callback)
        return DRMF_ERROR_INVALID_PARAMETER;
    callbacks->fault_delete_callback = NULL;
    return DRMF_SUCCESS;
}

DR_EXPORT
drmf_status_t
drfuzz_register_crash_thread_event(void (*event)(void *fuzzcxt,
                                                 drfuzz_fault_thread_state_t *state))
{
    if (callbacks->crash_thread_event != NULL)
        return DRMF_ERROR;
    callbacks->crash_thread_event = event;
    return DRMF_SUCCESS;
}

DR_EXPORT drmf_status_t
drfuzz_unregister_crash_thread_event(void (*event)(void *fuzzcxt,
                                                   drfuzz_fault_thread_state_t *state))
{
    if (callbacks->crash_thread_event != event)
        return DRMF_ERROR_INVALID_PARAMETER;
    callbacks->crash_thread_event = NULL;
    return DRMF_SUCCESS;
}

DR_EXPORT drmf_status_t
drfuzz_register_crash_process_event(void (*event)(drfuzz_crash_state_t *state))
{
    if (callbacks->crash_process_event != NULL)
        return DRMF_ERROR;
    callbacks->crash_process_event = event;
    return DRMF_SUCCESS;
}

DR_EXPORT drmf_status_t
drfuzz_unregister_crash_process_event(void (*event)(drfuzz_crash_state_t *state))
{
    if (callbacks->crash_process_event != event)
        return DRMF_ERROR_INVALID_PARAMETER;
    callbacks->crash_process_event = NULL;
    return DRMF_SUCCESS;
}

DR_EXPORT void *
drfuzz_get_fuzzcxt(void)
{
    /* XXX i#1734: might prefer to return a status code, because this may fail,
     * e.g. during startup the client may call this before any thread init events,
     * in which case the fuzzcxt will not have been initialized into our TLS slot.
     */
    return drmgr_get_tls_field(dr_get_current_drcontext(), tls_idx_fuzzer);
}

DR_EXPORT void *
drfuzz_get_drcontext(void *fuzzcxt)
{
    return ((fuzz_pass_context_t *) fuzzcxt)->dcontext;
}

DR_EXPORT drmf_status_t
drfuzz_get_target_num_bbs(generic_func_t func_pc, uint64 *num_bbs)
{
    fuzz_target_t *target;

    if (num_bbs == NULL)
        return DRMF_ERROR_INVALID_PARAMETER;

    if (func_pc == NULL) {
        *num_bbs = num_total_bbs;
        return DRMF_SUCCESS;
    }

    target = hashtable_lookup(&fuzz_target_htable, func_pc);
    if (target == NULL)
        return DRMF_ERROR_INVALID_PARAMETER;
    *num_bbs = target->num_bbs;
    return DRMF_SUCCESS;
}

DR_EXPORT drmf_status_t
drfuzz_get_arg(void *fuzzcxt, generic_func_t target_pc, int arg, bool original,
               OUT void **arg_value)
{
    fuzz_pass_context_t *fp = (fuzz_pass_context_t *) fuzzcxt;
    pass_target_t *target;

    if (target_pc == NULL)
        target = fp->live_targets;
    else
        target = lookup_live_target(fp, (app_pc) target_pc);

    if (target == NULL || arg >= target->target->arg_count)
        return DRMF_ERROR_INVALID_PARAMETER;

    if (original)
        *arg_value = (void *) target->original_args[arg];
    else
        *arg_value = (void *) target->current_args[arg];

    return DRMF_SUCCESS;
}

DR_EXPORT drmf_status_t
drfuzz_set_arg(void *fuzzcxt, int arg, void *val)
{
    fuzz_pass_context_t *fp = (fuzz_pass_context_t *) fuzzcxt;

    if (drwrap_set_arg(fp->live_targets->wrapcxt, arg, val))
        return DRMF_SUCCESS;
    else
        return DRMF_ERROR;
}

DR_EXPORT drmf_status_t
drfuzz_get_target_user_data(IN generic_func_t target_pc, OUT void **user_data)
{
    fuzz_target_t *target = hashtable_lookup(&fuzz_target_htable, target_pc);

    if (target == NULL)
        return DRMF_ERROR_INVALID_PARAMETER;

    *user_data = target->user_data;
    return DRMF_SUCCESS;
}

DR_EXPORT drmf_status_t
drfuzz_set_target_user_data(IN generic_func_t target_pc, IN void *user_data,
                            IN void (*delete_callback)(void *user_data))
{
    fuzz_target_t *target = hashtable_lookup(&fuzz_target_htable, target_pc);

    if (target == NULL)
        return DRMF_ERROR_INVALID_PARAMETER;

    target->user_data = user_data;
    target->delete_user_data_cb = delete_callback;
    return DRMF_SUCCESS;
}

DR_EXPORT drmf_status_t
drfuzz_get_target_per_thread_user_data(IN void *fuzzcxt, IN generic_func_t target_pc,
                                       OUT void **user_data)
{
    fuzz_pass_context_t *fp = (fuzz_pass_context_t *) fuzzcxt;
    pass_target_t *target;

    if (fp == NULL) {
        void *dcontext = dr_get_current_drcontext();
        fp = (fuzz_pass_context_t *) drmgr_get_tls_field(dcontext, tls_idx_fuzzer);
    }

    target = lookup_live_target(fp, (app_pc) target_pc);
    if (target == NULL)
        return DRMF_ERROR_INVALID_PARAMETER;

    *user_data = target->user_data;
    return DRMF_SUCCESS;
}

DR_EXPORT drmf_status_t
drfuzz_set_target_per_thread_user_data(IN void *fuzzcxt, IN generic_func_t target_pc,
                                       IN void *user_data,
                                       IN void (*delete_callback)(void *fuzzcxt,
                                                                  void *user_data))
{
    fuzz_pass_context_t *fp = (fuzz_pass_context_t *) fuzzcxt;
    pass_target_t *target;

    if (fp == NULL) {
        void *dcontext = dr_get_current_drcontext();
        fp = (fuzz_pass_context_t *) drmgr_get_tls_field(dcontext, tls_idx_fuzzer);
    }

    target = lookup_live_target(fp, (app_pc) target_pc);
    if (target == NULL)
        return DRMF_ERROR_INVALID_PARAMETER;

    target->user_data = user_data;
    target->delete_user_data_cb = delete_callback;
    return DRMF_SUCCESS;
}

static void
pre_fuzz_handler(void *wrapcxt, INOUT void **user_data)
{
    void *dcontext = drwrap_get_drcontext(wrapcxt);
    app_pc target_to_fuzz = drwrap_get_func(wrapcxt);
    fuzz_target_t *target = hashtable_lookup(&fuzz_target_htable, target_to_fuzz);
    fuzz_pass_context_t *fp = (fuzz_pass_context_t *) drmgr_get_tls_field(dcontext,
                                                                          tls_idx_fuzzer);
    bool is_target_entry = false;
    pass_target_t *live = NULL;
    dr_mcontext_t *mc;
    uint i;

    ASSERT(target != NULL, "pre_fuzz must be associated with a fuzz target");

    DRFUZZ_LOG(3, "pre_fuzz() for target "PFX" with %d args\n",
               target_to_fuzz, target->arg_count);

    /* XXX i#1734: this heuristic may be incorrect when a handled fault occurs during
     * the very last iteration of the last fuzz pass on any thread.
     */
    clear_thread_state(fp);

    /* Stop the target iterator that was captured at the last critical fault, because
     * the fact that we are in pre-fuzz implies the fault was handled and doesn't matter.
     */
    if (fp->thread_state->targets != NULL)
        drfuzz_target_iterator_stop(fp->thread_state->targets);

    /* XXX: assumes the fuzz target is never called recursively */
    if (fp->live_targets != NULL && fp->live_targets->target->func_pc == target_to_fuzz) {
        live = fp->live_targets; /* this is a repetition of the last live target */
    } else {
        is_target_entry = true; /* this is a new invocation of a target */
        live = activate_cached_target(fp, target_to_fuzz); /* check the cache */
        if (live == NULL)
            live = create_pass_target(dcontext, wrapcxt);
        live->next = fp->live_targets; /* push to live stack */
        fp->live_targets = live;
    }

    /* required by dr_redirect_execution() (avoids having to merge the mcontext) */
    mc = drwrap_get_mcontext_ex(wrapcxt, DR_MC_ALL); /* XXX: can we relax this? */

    if (is_target_entry) {
        live->xsp = mc->xsp;
#ifdef X86
        live->unclobber.retaddr_loc = (reg_t *) mc->xsp; /* see retaddr_unclobber_t */
#endif
        IF_ARM(live->lr = mc->lr);
        live->unclobber.retaddr = (reg_t) drwrap_get_retaddr(wrapcxt);
        DRFUZZ_LOG(4, "fuzz target "PFX": saving stack pointer "PFX"\n",
                   target_to_fuzz, mc->xsp);
        for (i = 0; i < target->arg_count; i++) { /* store the original arg values */
            live->original_args[i] = (reg_t) drwrap_get_arg(wrapcxt, i);
            /* copy original args to current args for the first iteration of the fuzz */
            live->current_args[i] = live->original_args[i];
            DRFUZZ_LOG(4, "fuzz target "PFX": saving original arg #%d: "PFX"\n",
                       target_to_fuzz, i, live->original_args[i]);
        }
    }

    /* restore the original arg values before calling the client */
    for (i = 0; i < target->arg_count; i++) {
        DRFUZZ_LOG(4, "fuzz target "PFX": restoring original arg #%d: "PFX"\n",
                   target_to_fuzz, i, live->original_args[i]);
        drwrap_set_arg(wrapcxt, i, (void *) live->original_args[i]);
    }

#ifdef ARM
    mc->lr = live->unclobber.retaddr; /* restore retaddr to link register */
#else /* X86 */
    *live->unclobber.retaddr_loc = live->unclobber.retaddr; /* restore retaddr to stack */
#endif

    target->pre_fuzz_cb(fp, (generic_func_t) target_to_fuzz, mc);
    drwrap_set_mcontext(wrapcxt);
    for (i = 0; i < target->arg_count; i++)
        live->current_args[i] = (reg_t) drwrap_get_arg(wrapcxt, i);

    *user_data = fp;
}

static void
post_fuzz_handler(void *wrapcxt, void *user_data)
{
    fuzz_pass_context_t *fp = (fuzz_pass_context_t *) user_data;
    pass_target_t *live = fp->live_targets;
    bool repeat = live->target->post_fuzz_cb(fp, (generic_func_t) live->target->func_pc);

    DRFUZZ_LOG(3, "post_fuzz() for target "PFX" (%s)\n", live->target->func_pc,
               repeat ? "repeat" : "stop");

    if (repeat) {
        dr_mcontext_t *mc = drwrap_get_mcontext(wrapcxt);
        IF_DEBUG(drext_status_t redirect_status;);
        /* restore the original xsp before repeating */
        DRFUZZ_LOG(4, "fuzz target "PFX": restoring xsp to "PFX"\n",
                   live->target->func_pc, live->xsp);
        mc->xsp = live->xsp;
        /* Restore lr, to avoid incorrect flushes in drwrap from it thinking there
         * is a different retaddr for our repeating function.
         */
        IF_ARM(mc->lr = live->lr);
        mc->pc = live->target->func_pc;
        IF_DEBUG(redirect_status =) drwrap_redirect_execution(wrapcxt);
        DRFUZZ_LOG(4, "fuzz target "PFX" requesting redirect to self entry; result: %d\n",
                   live->target->func_pc, live->target->func_pc, redirect_status);
    } else { /* the current target is finished, so pop from live stack and cache it */
        fp->live_targets = live->next;   /* pop from live stack */
        live->next = fp->cached_targets; /* push to cached stack */
        fp->cached_targets = live;

        if (fp->live_targets == NULL) /* clear cached targets after fuzz pass has ended */
            clear_cached_targets(fp);
    }
}

static pass_target_t *
lookup_live_target(fuzz_pass_context_t *fp, app_pc target_pc)
{
    pass_target_t *scan = fp->live_targets;
    while (scan != NULL) {
        if (scan->target->func_pc == target_pc)
            return scan;
        scan = scan->next;
    }
    return NULL;
}

static pass_target_t *
activate_cached_target(fuzz_pass_context_t *fp, app_pc target_pc)
{
    if (fp->cached_targets != NULL) {
        if (fp->cached_targets->target->func_pc == target_pc) {
            pass_target_t *live = fp->cached_targets;
            fp->cached_targets = fp->cached_targets->next;
            return live;
        } else { /* call stack diverges from cached stack, so clear it out */
            clear_cached_targets(fp);
        }
    }
    return NULL;
}

static pass_target_t *
create_pass_target(void *dcontext, void *wrapcxt)
{
    app_pc target_pc = drwrap_get_func(wrapcxt);
    fuzz_target_t *target = hashtable_lookup(&fuzz_target_htable, target_pc);
    pass_target_t *live = thread_alloc(dcontext, sizeof(pass_target_t), HEAPSTAT_MISC);
    memset(live, 0, sizeof(pass_target_t));
    live->wrapcxt = wrapcxt;
    live->original_args = thread_alloc(dcontext, ARGSIZE(target), HEAPSTAT_MISC);
    live->current_args = thread_alloc(dcontext, ARGSIZE(target), HEAPSTAT_MISC);
    live->target = target;
    return live;
}

static drfuzz_fault_thread_state_t *
create_fault_state(void *dcontext)
{
    drfuzz_fault_thread_state_t *state;

    state = thread_alloc(dcontext, sizeof(drfuzz_fault_thread_state_t), HEAPSTAT_MISC);
    memset(state, 0, sizeof(drfuzz_fault_thread_state_t));
    state->faults_observed = 0;
    state->fault_count = 0;
    /* allocate first and last now */
    state->faults = thread_alloc(dcontext, SIZEOF_FAULT_CHAIN_ARRAY, HEAPSTAT_MISC);
    memset(state->faults, 0, SIZEOF_FAULT_CHAIN_ARRAY);
    return state;
}

static drfuzz_target_iterator_t *
create_target_iterator(fuzz_pass_context_t *fp)
{
    uint i, j;
    pass_target_t *target;
    target_iterator_t *iter;
    drfuzz_target_frame_t *frame;

    iter = thread_alloc(fp->dcontext, sizeof(target_iterator_t), HEAPSTAT_MISC);
    memset(iter, 0, sizeof(target_iterator_t));
    iter->dcontext = fp->dcontext;
    for (target = fp->live_targets; target != NULL; target = target->next)
        iter->target_count++;
    iter->targets = thread_alloc(fp->dcontext,
                                 sizeof(drfuzz_target_frame_t) * iter->target_count,
                                 HEAPSTAT_MISC);

    for (i = 0, target = fp->live_targets; target != NULL; i++, target = target->next) {
        frame = &iter->targets[i];
        frame->func_pc = target->target->func_pc;
        frame->arg_count = target->target->arg_count;
        frame->arg_values = thread_alloc(fp->dcontext, sizeof(reg_t) * frame->arg_count,
                                         HEAPSTAT_MISC);
        for (j = 0; j < frame->arg_count; j++)
            frame->arg_values[j] = target->current_args[i];
    }

    return (drfuzz_target_iterator_t *) iter;
}

DR_EXPORT drfuzz_target_iterator_t *
drfuzz_target_iterator_start(void *fuzzcxt)
{
    return (void *) create_target_iterator((fuzz_pass_context_t *) fuzzcxt);
}

DR_EXPORT drfuzz_target_frame_t *
drfuzz_target_iterator_next(drfuzz_target_iterator_t *iter_in)
{
    target_iterator_t *iter = (target_iterator_t *) iter_in;
    if (iter->index < iter->target_count)
        return (void *) &iter->targets[iter->index++];
    else
        return NULL;
}

DR_EXPORT drmf_status_t
drfuzz_target_iterator_stop(drfuzz_target_iterator_t *iter_in)
{
    uint i;
    target_iterator_t *iter = (target_iterator_t *) iter_in;

    for (i = 0; i < iter->target_count; i++) {
        thread_free(iter->dcontext, iter->targets[i].arg_values,
                    sizeof(iter->targets[i].arg_values[0]), HEAPSTAT_MISC);
    }
    thread_free(iter->dcontext, iter->targets,
                sizeof(drfuzz_target_frame_t) * iter->target_count, HEAPSTAT_MISC);
    thread_free(iter->dcontext, iter, sizeof(target_iterator_t), HEAPSTAT_MISC);

    return DRMF_SUCCESS;
}

static void
capture_fault(void *dcontext, drfuzz_fault_t *fault, drfuzz_fault_ex_t *fault_ex)
{
#ifdef UNIX
    fault->fault_code = fault_ex->sig;
    fault->fault_pc = fault_ex->mcontext->pc;
    fault->access_address = fault_ex->access_address;
#else /* WINDOWS */
    fault->fault_code = fault_ex->record->ExceptionCode;
    fault->fault_pc = fault_ex->record->ExceptionAddress;
    fault->access_address = (byte *) fault_ex->record->ExceptionInformation[1];
#endif
    fault->thread_id = dr_get_thread_id(dcontext);
}

static drfuzz_fault_action_t
fault_handler(void *dcontext, drfuzz_fault_ex_t *fault_ex)
{
    if (is_critical_fault(fault_ex) && callbacks->fault_event != NULL) {
        drfuzz_fault_t *fault;
        fuzz_pass_context_t *fp;

        fp = (fuzz_pass_context_t *) drmgr_get_tls_field(dcontext, tls_idx_fuzzer);
        if (fp->live_targets == NULL) {
            /* Only keep one fault on a thread having no live fuzz targets, because we
             * have no easy way to tell when the fault has been handled (given at least
             * one fuzz target, we can assume that the next re-entry to pre-fuzz implies
             * the fault must have been properly handled by the app somewhere.
             */
            clear_thread_state(fp);
        } else {
            /* Capture the fuzz targets in case the app crashes before the fault is
             * handled (which does not necessarily mean this fault caused the crash.
             * This iterator will be automatically stopped (and freed) on either
             * pre-fuzz or during thread_exit(). The documentation instructs the client
             * not to stop this iterator.
             */
            fp->thread_state->targets = create_target_iterator(fp);
        }

        if (fp->thread_state->fault_count == FAULT_CHAIN_ARRAY_MAX) {
            if (callbacks->fault_delete_callback != NULL) /* remove the last one */
                callbacks->fault_delete_callback(fp, &LAST_FAULT(fp));
            fp->thread_state->fault_count--;
        }

        fp->thread_state->faults_observed++;
        fault = &fp->thread_state->faults[fp->thread_state->fault_count++];
        capture_fault(dcontext, fault, fault_ex);
        callbacks->fault_event(fp, fault, fault_ex);
    }
    return CRASH_CONTINUE;
}

static inline bool
is_critical_fault(drfuzz_fault_ex_t *fault)
{
    /* XXX i#1734: allow the client to configure the set of faults that are considered
     * critical, and extend the default set to include e.g. SIGILL, SIGABRT, etc.
     */
#ifdef WINDOWS
    return (fault->record->ExceptionCode == EXCEPTION_ACCESS_VIOLATION);
#else /* UNIX */
    return (fault->sig == SIGSEGV || fault->sig == SIGBUS);
#endif
}

static void
clear_cached_targets(fuzz_pass_context_t *fp)
{
    pass_target_t *cached, *next;
    for (cached = fp->cached_targets; cached != NULL; cached = next) {
        next = cached->next;
        free_pass_target(fp, cached);
    }
    fp->cached_targets = NULL;
}

static void
clear_pass_targets(fuzz_pass_context_t *fp)
{
    pass_target_t *live, *next;
    for (live = fp->live_targets; live != NULL; live = next) {
        next = live->next;
        free_pass_target(fp, live);
    }
    fp->live_targets = NULL;
    clear_cached_targets(fp);
}

static void
clear_thread_state(fuzz_pass_context_t *fp)
{
    uint i;

    if (callbacks->fault_delete_callback != NULL) {
        for (i = 0; i < fp->thread_state->fault_count; i++)
            callbacks->fault_delete_callback(fp, &fp->thread_state->faults[i]);
    }
    fp->thread_state->fault_count = 0;
    fp->thread_state->faults_observed = 0;
}

static void
free_fuzz_target(void *p)
{
    fuzz_target_t *target = (fuzz_target_t *) p;

    if (target->delete_user_data_cb != NULL && target->user_data != NULL)
        target->delete_user_data_cb(target->user_data);
    global_free(target, sizeof(fuzz_target_t), HEAPSTAT_MISC);
}

static void
free_pass_target(fuzz_pass_context_t *fp, pass_target_t *target)
{
    if (target->delete_user_data_cb != NULL && target->user_data != NULL)
        target->delete_user_data_cb(fp, target->user_data);
    thread_free(fp->dcontext, target->original_args, ARGSIZE(target->target),
                HEAPSTAT_MISC);
    thread_free(fp->dcontext, target->current_args, ARGSIZE(target->target),
                HEAPSTAT_MISC);
    thread_free(fp->dcontext, target, sizeof(*target), HEAPSTAT_MISC);
}

static void
free_thread_state(fuzz_pass_context_t *fp)
{
    if (fp->thread_state == NULL)
        return;

    if (fp->thread_state->targets != NULL)
        drfuzz_target_iterator_stop((void *) fp->thread_state->targets);
    if (callbacks->fault_delete_callback != NULL && fp->thread_state->fault_count > 0) {
        callbacks->fault_delete_callback(fp, &FIRST_FAULT(fp));
        if (fp->thread_state->fault_count == 2)
            callbacks->fault_delete_callback(fp, &LAST_FAULT(fp));
    }
    thread_free(fp->dcontext, fp->thread_state->faults, SIZEOF_FAULT_CHAIN_ARRAY,
                HEAPSTAT_MISC);
    thread_free(fp->dcontext, fp->thread_state, sizeof(drfuzz_fault_thread_state_t),
                HEAPSTAT_MISC);
}

/***************************************************************************
 * Mutator
 */

#define DRFUZZLIB_MIN_VERSION_USED 1

/* XXX: can we share this somehow with the auxlib in drmemory/syscall.c? */

/* The "local" var is a char * for storing which bind failed */
#define BINDFUNC(api, local, name) \
    (local = #name, \
     (api)->name = (void *) dr_lookup_aux_library_routine((api)->handle, #name))

/* To avoid having to deploy and load a separate default library we link statically
 * and point at the interface here:
 */
static drfuzz_mutator_api_t default_mutator = {
    /* XXX: we could further macro-ify drfuzz_mutator.h to avoid duplication here */
    sizeof(default_mutator),
    NULL,
    drfuzz_mutator_start,
    drfuzz_mutator_has_next_value,
    drfuzz_mutator_get_current_value,
    drfuzz_mutator_get_next_value,
    drfuzz_mutator_stop,
    drfuzz_mutator_feedback,
};

DR_EXPORT drmf_status_t
drfuzz_mutator_load(IN const char *lib_path, INOUT drfuzz_mutator_api_t *api)
{
    int *ver_compat, *ver_cur;
    char *func;

    /* If we add new fields we'll need more struct_size checks */
    if (api == NULL || api->struct_size != sizeof(*api))
        return DRMF_ERROR_INVALID_PARAMETER;

    if (lib_path == NULL) {
        *api = default_mutator;
        return DRMF_SUCCESS;
    }

    api->handle = dr_load_aux_library(lib_path, NULL, NULL);
    if (api->handle == NULL) {
        DRFUZZ_ERROR("Error loading mutator library %s"NL, lib_path);
        return DRMF_ERROR;
    }

    /* version check */
    ver_compat = (int *)
        dr_lookup_aux_library_routine(api->handle, DRFUZZLIB_VERSION_COMPAT_NAME);
    ver_cur = (int *)
        dr_lookup_aux_library_routine(api->handle, DRFUZZLIB_VERSION_CUR_NAME);
    if (ver_compat == NULL || ver_cur == NULL ||
        *ver_compat > DRFUZZLIB_MIN_VERSION_USED ||
        *ver_cur < DRFUZZLIB_MIN_VERSION_USED) {
        DRFUZZ_ERROR("Version %d mismatch with mutator library %s version %d-%d"NL,
                     DRFUZZLIB_MIN_VERSION_USED, lib_path,
                     (ver_compat == NULL) ? -1 : *ver_cur,
                     (ver_compat == NULL) ? -1 : *ver_cur);
        dr_unload_aux_library(api->handle);
        return DRMF_ERROR;
    }
    DRFUZZ_LOG(1, "Loaded mutator library %s ver=%d-%d\n",
               lib_path, *ver_compat, *ver_cur);

    if (BINDFUNC(api, func, drfuzz_mutator_start) == NULL ||
        BINDFUNC(api, func, drfuzz_mutator_has_next_value) == NULL ||
        BINDFUNC(api, func, drfuzz_mutator_get_current_value) == NULL ||
        BINDFUNC(api, func, drfuzz_mutator_get_next_value) == NULL ||
        BINDFUNC(api, func, drfuzz_mutator_stop) == NULL ||
        BINDFUNC(api, func, drfuzz_mutator_feedback) == NULL) {
        DRFUZZ_ERROR("Required export %s missing from mutator library %s"NL,
                     func, lib_path);
        dr_unload_aux_library(api->handle);
        return DRMF_ERROR;
    }

    return DRMF_SUCCESS;
}

DR_EXPORT drmf_status_t
drfuzz_mutator_unload(IN drfuzz_mutator_api_t *api)
{
    if (api == NULL)
        return DRMF_ERROR_INVALID_PARAMETER;
    if (api == &default_mutator)
        return DRMF_SUCCESS;
    if (!dr_unload_aux_library(api->handle)) {
        DRFUZZ_ERROR("Failed to unload mutator library");
        return DRMF_ERROR;
    }
    return DRMF_SUCCESS;
}
