/* **********************************************************
 * Copyright (c) 2014-2015 Google, Inc.  All rights reserved.
 * Copyright (c) 2010 VMware, Inc.  All rights reserved.
 * **********************************************************/

/* Dr. Memory: the memory debugger
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation;
 * version 2.1 of the License, and no later version.

 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * Library General Public License for more details.

 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

/***************************************************************************
 * perturb.c: Dr. Memory app timing perturbation
 */

#include "dr_api.h"
#include "drmgr.h"
#include "drmemory.h"
#include "utils.h"
#include "options.h"
#include "heap.h" /* get_ntdll_base */
#ifdef LINUX
# include "sysnum_linux.h"
# include <linux/sched.h> /* CLONE_VM */
#elif defined(MACOS)
# include <sys/syscall.h>
#endif

enum {
    SYNCH_INSTR,
    SYNCH_SYSCALL,
    SYNCH_LIBRARY,
    SYNCH_THREAD,
    SYNCH_PROCESS,
};

#if defined(DEBUG) || defined(STATISTICS)
static const char * const synch_type[] = {
    "instr",
    "syscall",
    "library",
    "thread",
    "process",
};
# define NUM_TYPES (sizeof(synch_type)/sizeof(synch_type[0]))
#endif

#ifdef STATISTICS
static uint count[NUM_TYPES];
#endif

#ifdef WINDOWS
/* thread/process */
static int sysnum_CreateThread;
static int sysnum_CreateThreadEx;
static int sysnum_CreateProcess;
static int sysnum_CreateProcessEx;
static int sysnum_CreateUserProcess;
/* synch related */
static int sysnum_SuspendThread;
static int sysnum_ResumeThread;
static int sysnum_AlertResumeThread;
static int sysnum_AlertThread;
static int sysnum_DelayExecution;
static int sysnum_ReplyWaitReceivePort;
static int sysnum_ReplyWaitReceivePortEx;
static int sysnum_ReplyWaitReplyPort;
static int sysnum_ReplyWaitSendChannel;
static int sysnum_RequestWaitReplyPort;
static int sysnum_SendWaitReplyChannel;
static int sysnum_SetHighWaitLowEventPair;
static int sysnum_SetLowWaitHighEventPair;
static int sysnum_SignalAndWaitForSingleObject;
static int sysnum_WaitForDebugEvent;
static int sysnum_WaitForKeyedEvent;
static int sysnum_WaitForMultipleObjects;
static int sysnum_WaitForSingleObject;
static int sysnum_WaitHighEventPair;
static int sysnum_WaitLowEventPair;
/* mutex can be acquired via NtCreateMutant and not just via Nt*Wait* */
static int sysnum_CreateMutant;
static int sysnum_ReleaseMutant;
static int sysnum_ReleaseSemaphore;
static int sysnum_PulseEvent;
static int sysnum_ResetEvent;
static int sysnum_SetEvent;
static int sysnum_SetEventBoostPriority;
static int sysnum_SetHighEventPair;
static int sysnum_SetLowEventPair;
/* ignoring NtLockFile, NtLockRegistryKey, NtLockVirtualMemory,
 * NtUnlockFile, NtUnlockVirtualMemory
 */
#endif

static dr_emit_flags_t
perturb_event_bb_analysis(void *drcontext, void *tag, instrlist_t *bb,
                          bool for_trace, bool translating, void **user_data);

static dr_emit_flags_t
perturb_event_bb_insert(void *drcontext, void *tag, instrlist_t *bb, instr_t *inst,
                        bool for_trace, bool translating, void *user_data);

/***************************************************************************
 * Insert delays in synch and thread/process operations to try and force
 * abnormal thread orderings and tease out race conditions
 */

/* called via clean call from cache as well as from thread and fork events */
static void
do_delay(uint type)
{
    uint delay_ms = dr_get_random_value(options.perturb_max);
    ASSERT(type < NUM_TYPES, "invalid synch type");
    if (type == SYNCH_INSTR) {
        /* For instrs, sleeping for even 1ms is way too long so we have
         * a loop of moderately slow operations: library call that reads
         * from TLS.  Note that putting a syscall in this loop is too slow
         * by an order of magnitude.
         */
        uint i;
        LOG(3, "perturb instr: delaying by %d\n", delay_ms);
        for (i = 0; i < delay_ms; i++)
            dr_get_current_drcontext();
        /* We include one sleep for a potential thread switch */
        dr_sleep(0);
    } else {
        LOG(2, "perturb %s: delaying by %d ms\n", synch_type[type], delay_ms);
        /* In some cases it might be better to have a delay that the
         * scheduler is not aware of: but usually we do want a thread
         * switch
         */
        dr_sleep(delay_ms);
    }
    STATS_INC(count[type]);
}

static bool
is_synch_routine(app_pc pc)
{
    /* FIXME: intercept module load and if see pthreads then intercept
     * routines like pthread_join, pthread_mutex_*, pthread_rwlock_*,
     * pthread_spin_*, pthread_cond_*, etc.
     * However, if most of the locking routines are using locked
     * instrs, we've already got that covered: though it the
     * app is using pthreads it might be better to perturb
     * the pthreads routines and ignore the raw instr stream.
     *
     * For Windows, intercept RtlEnterCriticalSection,
     * RtlLeaveCriticalSection, and RtlTryEnterCriticalSection.
     */
    return false;
}

void
perturb_init(void)
{
    drmgr_priority_t priority = {sizeof(priority), "drmemory.perturb", NULL, NULL,
                                 DRMGR_PRIORITY_INSERT_PERTURB};
    ASSERT(options.perturb, "should not be called");
    if (!drmgr_register_bb_instrumentation_event(perturb_event_bb_analysis,
                                                 perturb_event_bb_insert,
                                                 &priority))
        ASSERT(false, "drmgr registration failed");
    if (options.perturb_seed != 0)
        dr_set_random_seed(options.perturb_seed);
    LOG(1, "initial random seed: %d\n", dr_get_random_seed());
}

void
perturb_module_load(void *drcontext, const module_data_t *info, bool loaded)
{
#ifdef WINDOWS
    const char *modname = dr_module_preferred_name(info);
    if (modname == NULL)
        return;

# define INIT_SYSNUM(name, dc, mod, ok_to_fail) do {                        \
    sysnum_##name = sysnum_from_name("Nt"#name);                            \
    ASSERT(ok_to_fail || sysnum_##name >= 0, "cannot find "#name" sysnum"); \
} while (0);

    if (stri_eq(modname, "ntdll.dll")) {
        INIT_SYSNUM(CreateThread, drcontext, info, false);
        INIT_SYSNUM(CreateThreadEx, drcontext, info, true); /*Vista+ only*/
        INIT_SYSNUM(CreateProcess, drcontext, info, false);
        INIT_SYSNUM(CreateProcessEx, drcontext, info, true); /*Vista+ only*/
        INIT_SYSNUM(CreateUserProcess, drcontext, info, true); /*Vista+ only*/
        INIT_SYSNUM(SuspendThread, drcontext, info, false);
        INIT_SYSNUM(ResumeThread, drcontext, info, false);
        INIT_SYSNUM(AlertResumeThread, drcontext, info, false);
        INIT_SYSNUM(AlertThread, drcontext, info, false);
        INIT_SYSNUM(DelayExecution, drcontext, info, false);
        INIT_SYSNUM(ReplyWaitReceivePort, drcontext, info, false);
        INIT_SYSNUM(ReplyWaitReceivePortEx, drcontext, info, true); /*2K+ only*/
        INIT_SYSNUM(ReplyWaitReplyPort, drcontext, info, false);
        INIT_SYSNUM(ReplyWaitSendChannel, drcontext, info, true); /*2K- only*/
        INIT_SYSNUM(RequestWaitReplyPort, drcontext, info, false);
        INIT_SYSNUM(SendWaitReplyChannel, drcontext, info, true); /*2K- only*/
        INIT_SYSNUM(SetHighWaitLowEventPair, drcontext, info, false);
        INIT_SYSNUM(SetLowWaitHighEventPair, drcontext, info, false);
        INIT_SYSNUM(SignalAndWaitForSingleObject, drcontext, info, false);
        INIT_SYSNUM(WaitForDebugEvent, drcontext, info, true); /*XP+ only*/
        INIT_SYSNUM(WaitForKeyedEvent, drcontext, info, true); /*XP+ only*/
        INIT_SYSNUM(WaitForMultipleObjects, drcontext, info, false);
        INIT_SYSNUM(WaitForSingleObject, drcontext, info, false);
        INIT_SYSNUM(WaitHighEventPair, drcontext, info, false);
        INIT_SYSNUM(WaitLowEventPair, drcontext, info, false);
        INIT_SYSNUM(CreateMutant, drcontext, info, false);
        INIT_SYSNUM(ReleaseMutant, drcontext, info, false);
        INIT_SYSNUM(ReleaseSemaphore, drcontext, info, false);
        INIT_SYSNUM(PulseEvent, drcontext, info, false);
        INIT_SYSNUM(ResetEvent, drcontext, info, false);
        INIT_SYSNUM(SetEvent, drcontext, info, false);
        INIT_SYSNUM(SetEventBoostPriority, drcontext, info, false);
        INIT_SYSNUM(SetHighEventPair, drcontext, info, false);
        INIT_SYSNUM(SetLowEventPair, drcontext, info, false);
    }
#endif
}

void
perturb_exit(void)
{
    /* nothing yet */
}

#ifdef STATISTICS
void
perturb_dump_statistics(file_t f)
{
    int i;
    dr_fprintf(f, "-perturb delays added:\n");
    for (i = 0; i < NUM_TYPES; i++)
        dr_fprintf(f, "\t%12s: %9u\n", synch_type[i], count[i]);
}
#endif

/***************************************************************************
 * Insert delays in parent and child of fork and thread and at thread exit
 */

void
perturb_fork_init(void)
{
    do_delay(SYNCH_PROCESS);
}

void
perturb_thread_init(void)
{
    do_delay(SYNCH_THREAD);
}

void
perturb_thread_exit(void)
{
    do_delay(SYNCH_THREAD);
}

void
perturb_pre_fork(void)
{
    do_delay(SYNCH_PROCESS);
}

#ifndef MACOS
static void
perturb_pre_thread(void)
{
    do_delay(SYNCH_THREAD);
}

static void
perturb_pre_synch_syscall(void)
{
    do_delay(SYNCH_SYSCALL);
}
#endif

/***************************************************************************
 * Insert delays before synch-related syscalls
 */

bool
perturb_pre_syscall(void *drcontext, int sysnum)
{
#ifdef UNIX
    switch (sysnum) {
# ifdef LINUX
    case SYS_clone: {
        uint flags = (uint) dr_syscall_get_param(drcontext, 0);
        if (TEST(CLONE_VM, flags)) {
            perturb_pre_thread();
            break;
        }
        /* else, fall through */
    }
    case SYS_futex:
        perturb_pre_synch_syscall();
        break;
# elif defined(MACOS)
    /* FIXME i#1438: add Mac thread monitoring */
# endif
    case SYS_fork:
        perturb_pre_fork();
        break;
    }
#else
    if (sysnum == sysnum_CreateProcess ||
        sysnum == sysnum_CreateProcessEx ||
        sysnum == sysnum_CreateUserProcess)
        perturb_pre_fork();
    else if (sysnum == sysnum_CreateThread ||
             sysnum == sysnum_CreateThreadEx)
        perturb_pre_thread();
    else if (sysnum == sysnum_SuspendThread ||
             sysnum == sysnum_ResumeThread ||
             sysnum == sysnum_AlertResumeThread ||
             sysnum == sysnum_AlertThread ||
             sysnum == sysnum_DelayExecution ||
             sysnum == sysnum_ReplyWaitReceivePort ||
             sysnum == sysnum_ReplyWaitReceivePortEx ||
             sysnum == sysnum_ReplyWaitReplyPort ||
             sysnum == sysnum_ReplyWaitSendChannel ||
             sysnum == sysnum_RequestWaitReplyPort ||
             sysnum == sysnum_SendWaitReplyChannel ||
             sysnum == sysnum_SetHighWaitLowEventPair ||
             sysnum == sysnum_SetLowWaitHighEventPair ||
             sysnum == sysnum_SignalAndWaitForSingleObject ||
             sysnum == sysnum_WaitForDebugEvent ||
             sysnum == sysnum_WaitForKeyedEvent ||
             sysnum == sysnum_WaitForMultipleObjects ||
             sysnum == sysnum_WaitForSingleObject ||
             sysnum == sysnum_WaitHighEventPair ||
             sysnum == sysnum_WaitLowEventPair ||
             sysnum == sysnum_CreateMutant ||
             sysnum == sysnum_ReleaseMutant ||
             sysnum == sysnum_ReleaseSemaphore ||
             sysnum == sysnum_PulseEvent ||
             sysnum == sysnum_ResetEvent ||
             sysnum == sysnum_SetEvent ||
             sysnum == sysnum_SetEventBoostPriority ||
             sysnum == sysnum_SetHighEventPair ||
             sysnum == sysnum_SetLowEventPair) {
        perturb_pre_synch_syscall();
    }
#endif
    return true; /* execute syscall */
}

/***************************************************************************
 * Insert delays before raw lock operations
 */

static bool
instr_is_synch_op(instr_t *inst)
{
#ifdef X86
    return (instr_get_prefix_flag(inst, PREFIX_LOCK) ||
            /* xchg always locks */
            (instr_get_opcode(inst) == OP_xchg &&
             !opnd_same(instr_get_src(inst, 0),
                        instr_get_src(inst, 1))));
#elif defined(ARM)
    return instr_is_exclusive_store(inst);
#endif
}

static dr_emit_flags_t
perturb_event_bb_analysis(void *drcontext, void *tag, instrlist_t *bb,
                          bool for_trace, bool translating, void **user_data)
{
    return DR_EMIT_DEFAULT;
}

static dr_emit_flags_t
perturb_event_bb_insert(void *drcontext, void *tag, instrlist_t *bb, instr_t *inst,
                        bool for_trace, bool translating, void *user_data)
{
    /* i#2402: Temporarily disable auto predication globally due to poor
     * interaction with internal control flow we emit.
     */
    drmgr_disable_auto_predication(drcontext, bb);

    if (instr_is_synch_op(inst)) {
        dr_insert_clean_call(drcontext, bb, inst, (void *)do_delay, false,
                             1, OPND_CREATE_INT32(SYNCH_INSTR));
    } else if (is_synch_routine(instr_get_app_pc(inst))) {
        dr_insert_clean_call(drcontext, bb, inst, (void *)do_delay, false,
                             1, OPND_CREATE_INT32(SYNCH_LIBRARY));
    }
    /* XXX: maybe add delay on post as well as pre */
    return DR_EMIT_DEFAULT;
}
