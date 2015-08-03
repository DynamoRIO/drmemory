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
#include <string.h>
#include "drwrap.h"
#include "drmgr.h"
#include "hashtable.h"
#include "utils.h"
#include "drfuzz.h"

#define ARGSIZE(target) ((target)->arg_count * sizeof(reg_t))

#ifdef UNIX
typedef dr_siginfo_t drfuzz_crash_info_t;
typedef dr_signal_action_t drfuzz_crash_action_t;
# define CRASH_CONTINUE DR_SIGNAL_DELIVER
#else
typedef dr_exception_t drfuzz_crash_info_t;
typedef bool drfuzz_crash_action_t;
# define CRASH_CONTINUE true
#endif

/* Represents one fuzz target together with the client's registered callbacks */
typedef struct _fuzz_target_t {
    app_pc func_pc;
    uint arg_count;
    drfuzz_flags_t flags;
    void (*pre_fuzz_cb)(generic_func_t, void *, INOUT void **);
    bool (*post_fuzz_cb)(generic_func_t, void *, void *);
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

/* Stores thread-specific state for an executing fuzz target, which is required for
 * repeating the target and for reporting a crash (can't use the drwrap `user_data` b/c
 * it is deleted in post-wrap, and we must hold these values from post-wrap to pre-wrap).
 */
typedef struct _pass_target_t {
    fuzz_target_t *target;
    reg_t xsp;            /* stack level at entry to the fuzz target */
    retaddr_unclobber_t unclobber; /* see comment on retaddr_unclobber_t */
    reg_t *original_args; /* original arg values passed by the app to the fuzz target */
    reg_t *current_args;  /* fuzzed argument values for the current iteration */
    struct _pass_target_t *next;   /* chains either stack in fuzz_pass_context_t */
} pass_target_t;

/* Thread-local storage for a fuzz pass context, including the set of targets that are
 * live on the call stack, and a cache of targets that have been live in this fuzz pass.
 */
typedef struct _fuzz_pass_context_t {
    /* Stack of fuzz targets that are live on this thread; i.e., the subset of the call
     * stack which are fuzz targets. Chained in pass_target_t.next.
     */
    pass_target_t *live_targets;
    /* Stack-shaped cache of fuzz targets that have been live in the current fuzz pass,
     * but are not presently live. Cleared at the end of each fuzz pass, or anytime a fuzz
     * pass diverges from its cached target stack. Chained in pass_target_t.next.
     */
    pass_target_t *cached_targets;
} fuzz_pass_context_t;

static int drfuzz_init_count;

static int tls_idx_fuzzer;

static hashtable_t fuzz_target_htable;

static void
thread_init(void *dcontext);

static void
thread_exit(void *dcontext);

static void
pre_fuzz_handler(void *wrapcxt, INOUT void **user_data);

static void
post_fuzz_handler(void *wrapcxt, void *user_data);

static pass_target_t *
lookup_live_target(fuzz_pass_context_t *fp, app_pc target_pc);

static pass_target_t *
activate_cached_target(void *dcontext, fuzz_pass_context_t *fp, app_pc target_pc);

static pass_target_t *
create_pass_target(void *dcontext, app_pc target_pc);

static drfuzz_crash_action_t
crash_handler(void *dcontext, drfuzz_crash_info_t *crash);

static void
clear_cached_targets(void *dcontext, fuzz_pass_context_t *fp);

static void
clear_pass_targets(void *dcontext, fuzz_pass_context_t *fp);

static void
free_fuzz_target(void *p);

static void
free_pass_target(void *dcontext, pass_target_t *target);

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

    drmgr_init();
    drwrap_init();

#ifdef UNIX
    drmgr_register_signal_event(crash_handler);
#else /* WINDOWS */
    drmgr_register_exception_event(crash_handler);
#endif
    drmgr_register_thread_init_event(thread_init);
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
        return DRMF_ERROR;

    drwrap_exit();
    drmgr_exit();

    hashtable_delete(&fuzz_target_htable);

    return DRMF_SUCCESS;
}

static void
thread_init(void *dcontext)
{
    fuzz_pass_context_t *fp = thread_alloc(dcontext, sizeof(fuzz_pass_context_t),
                                           HEAPSTAT_MISC);
    memset(fp, 0, sizeof(fuzz_pass_context_t));
    drmgr_set_tls_field(dcontext, tls_idx_fuzzer, (void *) fp);
}

static void
thread_exit(void *dcontext)
{
    fuzz_pass_context_t *fp = (fuzz_pass_context_t *) drmgr_get_tls_field(dcontext,
                                                                          tls_idx_fuzzer);
    clear_pass_targets(dcontext, fp);
    thread_free(dcontext, fp, sizeof(fuzz_pass_context_t), HEAPSTAT_MISC);
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

    if (!TESTONE(DRFUZZ_CALLCONV_MASK, flags))
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
drfuzz_get_arg(generic_func_t target_pc, int arg, bool original, OUT void **arg_value)
{
    void *dcontext = dr_get_current_drcontext();
    fuzz_pass_context_t *fp = (fuzz_pass_context_t *) drmgr_get_tls_field(dcontext,
                                                                          tls_idx_fuzzer);
    pass_target_t *target = lookup_live_target(fp, (app_pc) target_pc);

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
    if (drwrap_set_arg(fuzzcxt, arg, val))
        return DRMF_SUCCESS;
    else
        return DRMF_ERROR;
    /* XXX i#1734: NYI return DRMF_ERROR when called outside pre_fuzz_handler */
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

    LOG(3, "pre_fuzz() for target "PFX" with %d args\n",
        target_to_fuzz, target->arg_count);

    /* XXX: assumes the fuzz target is never called recursively */
    if (fp->live_targets != NULL && fp->live_targets->target->func_pc == target_to_fuzz) {
        live = fp->live_targets; /* this is a repetition of the last live target */
    } else {
        is_target_entry = true; /* this is a new invocation of a target */
        live = activate_cached_target(dcontext, fp, target_to_fuzz); /* check the cache */
        if (live == NULL)
            live = create_pass_target(dcontext, drwrap_get_func(wrapcxt));
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
        live->unclobber.retaddr = (reg_t) drwrap_get_retaddr(wrapcxt);
        LOG(4, "fuzz target "PFX": saving stack pointer "PFX"\n",
            target_to_fuzz, mc->xsp);
        for (i = 0; i < target->arg_count; i++) { /* store the original arg values */
            live->original_args[i] = (reg_t) drwrap_get_arg(wrapcxt, i);
            /* copy original args to current args for the first iteration of the fuzz */
            live->current_args[i] = live->original_args[i];
            LOG(4, "fuzz target "PFX": saving original arg #%d: "PFX"\n",
                target_to_fuzz, i, live->original_args[i]);
        }
    }

    /* restore the original arg values before calling the client */
    for (i = 0; i < target->arg_count; i++) {
        LOG(4, "fuzz target "PFX": restoring original arg #%d: "PFX"\n",
            target_to_fuzz, i, live->original_args[i]);
        drwrap_set_arg(wrapcxt, i, (void *) live->original_args[i]);
    }

#ifdef ARM
    mc->lr = live->unclobber.retaddr; /* restore retaddr to link register */
#else /* X86 */
    *live->unclobber.retaddr_loc = live->unclobber.retaddr; /* restore retaddr to stack */
#endif

    target->pre_fuzz_cb((generic_func_t) target_to_fuzz, wrapcxt,
                        NULL/*XXX i#1734: NYI*/);
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
    bool repeat = live->target->post_fuzz_cb((generic_func_t) live->target->func_pc,
                                             wrapcxt, NULL/*XXX i#1734: NYI*/);

    LOG(3, "post_fuzz() for target "PFX" (%s)\n", live->target->func_pc,
        repeat ? "repeat" : "stop");

    if (repeat) {
        dr_mcontext_t *mc = drwrap_get_mcontext(wrapcxt);
        IF_DEBUG(drext_status_t redirect_status;);
        /* restore the original xsp before repeating */
        LOG(4, "fuzz target "PFX": restoring xsp to "PFX"\n", live->target->func_pc,
            live->xsp);
        mc->xsp = live->xsp;
        mc->pc = live->target->func_pc;
        IF_DEBUG(redirect_status =) drwrap_redirect_execution(wrapcxt);
        LOG(4, "fuzz target "PFX" requesting redirect to self entry; result: %d\n",
            live->target->func_pc, live->target->func_pc, redirect_status);
    } else { /* the current target is finished, so pop from live stack and cache it */
        fp->live_targets = live->next;   /* pop from live stack */
        live->next = fp->cached_targets; /* push to cached stack */
        fp->cached_targets = live;

        if (fp->live_targets == NULL) /* clear cached targets after fuzz pass has ended */
            clear_cached_targets(drwrap_get_drcontext(wrapcxt), fp);
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
activate_cached_target(void *dcontext, fuzz_pass_context_t *fp, app_pc target_pc)
{
    if (fp->cached_targets != NULL) {
        if (fp->cached_targets->target->func_pc == target_pc) {
            pass_target_t *live = fp->cached_targets;
            fp->cached_targets = fp->cached_targets->next;
            return live;
        } else { /* call stack diverges from cached stack, so clear it out */
            clear_cached_targets(dcontext, fp);
        }
    }
    return NULL;
}

static pass_target_t *
create_pass_target(void *dcontext, app_pc target_pc)
{
    fuzz_target_t *target = hashtable_lookup(&fuzz_target_htable, target_pc);
    pass_target_t *live = thread_alloc(dcontext, sizeof(pass_target_t), HEAPSTAT_MISC);
    live->original_args = thread_alloc(dcontext, ARGSIZE(target), HEAPSTAT_MISC);
    live->current_args = thread_alloc(dcontext, ARGSIZE(target), HEAPSTAT_MISC);
    live->target = target;
    return live;
}

static drfuzz_crash_action_t
crash_handler(void *dcontext, drfuzz_crash_info_t *crash)
{
    /* XXX i#1734: NYI */
    return CRASH_CONTINUE;
}

static void
clear_cached_targets(void *dcontext, fuzz_pass_context_t *fp)
{
    pass_target_t *cached, *next;
    for (cached = fp->cached_targets; cached != NULL; cached = next) {
        next = cached->next;
        free_pass_target(dcontext, cached);
    }
    fp->cached_targets = NULL;
}

static void
clear_pass_targets(void *dcontext, fuzz_pass_context_t *fp)
{
    pass_target_t *live, *next;
    for (live = fp->live_targets; live != NULL; live = next) {
        next = live->next;
        free_pass_target(dcontext, live);
    }
    fp->live_targets = NULL;
    clear_cached_targets(dcontext, fp);
}

static void
free_fuzz_target(void *p)
{
    global_free(p, sizeof(fuzz_target_t), HEAPSTAT_MISC);
}

static void
free_pass_target(void *dcontext, pass_target_t *pass)
{
    thread_free(dcontext, pass->original_args, ARGSIZE(pass->target), HEAPSTAT_MISC);
    thread_free(dcontext, pass->current_args, ARGSIZE(pass->target), HEAPSTAT_MISC);
    thread_free(dcontext, pass, sizeof(*pass), HEAPSTAT_MISC);
}
