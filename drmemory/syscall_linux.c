/* **********************************************************
 * Copyright (c) 2010-2017 Google, Inc.  All rights reserved.
 * Copyright (c) 2009-2010 VMware, Inc.  All rights reserved.
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

#include "dr_api.h"
#include "drmemory.h"
#include "syscall.h"
#include "syscall_os.h"
#include "shadow.h"
#include "slowpath.h"
#include "sysnum_linux.h"
#include "alloc_drmem.h"
#include "alloc.h"
#include "heap.h"
#include "stack.h"
#include "report.h"

#include <linux/sched.h>
#include <sys/prctl.h>

/***************************************************************************
 * SYSTEM CALLS FOR LINUX
 */

void
syscall_os_init(void *drcontext)
{
}

void
syscall_os_exit(void)
{
}

void
syscall_os_thread_init(void *drcontext)
{
}

void
syscall_os_thread_exit(void *drcontext)
{
}

void
syscall_os_module_load(void *drcontext, const module_data_t *info, bool loaded)
{
}

/***************************************************************************
 * PER-SYSCALL HANDLING
 */

bool
os_process_syscall_memarg(drsys_arg_t *arg)
{
    return false; /* not handled */
}

static void
handle_clone(void *drcontext, dr_mcontext_t *mc)
{
    uint flags = (uint) dr_syscall_get_param(drcontext, 0);
    app_pc newsp = (app_pc) dr_syscall_get_param(drcontext, 1);

    if (!options.shadowing)
        return;

    /* PR 418629: we need to change the stack from defined (marked when it
     * was allocated) to unaddressable.  Originally we couldn't get the stack
     * bounds in the thread init event (xref PR 395156) so we watch here:
     * we could move this code now but not worth it.
     * FIXME: should we watch SYS_exit and put stack back to defined
     * in case it's re-used?  Seems better to leave it unaddressable
     * since may be more common to have racy accesses we want to flag
     * rather than legitimate re-use?
     */
    if (TEST(CLONE_VM, flags) && newsp != NULL) {
        app_pc stack_base = NULL;
        size_t stack_size;
        /* newsp is TOS */
        ASSERT(options.track_heap, "now relying on -track_heap in general");
        if (is_in_heap_region(newsp)) {
            /* How find base of malloc chunk to then find size?
             * Don't want to store all mallocs in an interval data structure
             * (shown to be slow in PR 535568).
             * Maybe hardcode knowledge of how far from upper address
             * glibc clone() sets newsp?
             * Actually, should just walk shadow memory until hit
             * unaddressable.
             */
            /* FIXME: NEVER TESTED! */
            app_pc pc;
            ssize_t sz;
            /* PR 525807 added an interval tree of "large mallocs" */
            if (malloc_large_lookup(newsp, &pc, (size_t*)&sz)) {
                stack_base = pc;
                stack_size = sz;
            } else {
                /* Should be rare so we just do brute force and slow */
                pc = shadow_prev_dword(newsp, newsp - options.stack_swap_threshold,
                                       SHADOW_UNADDRESSABLE);
                sz = malloc_chunk_size(pc+1);
                if (sz > 0) { /* returns -1 on failure */
                    stack_base = pc + 1;
                    stack_size = sz;
                }
            }
        } else {
            /* On linux a pre-adjacent mmap w/ same prot will be merged into the
             * same region as returned by dr_query_memory() and we'll mark it as
             * unaddressable => many false positives (on FC10, adding a printf
             * to suite/tests/linux/clone.c between the stack mmap and the clone
             * call resulted in the merge).  My solution is to track mmaps and
             * assume a stack will be a single mmap (maybe separate guard page
             * but that should be noprot so ok to not mark unaddress: xref PR
             * 406328).
             */
            if (!mmap_anon_lookup(newsp, &stack_base, &stack_size)) {
                /* Fall back to a query */
                LOG(2, "thread stack "PFX" not in mmap table, querying\n", newsp);
                if (!dr_query_memory(newsp - 1, &stack_base, &stack_size, NULL)) {
                    /* We can estimate the stack end by assuming that clone()
                     * puts less than a page on the stack, but the base is harder:
                     * instead we rely on PR 525807 handle_push_addressable() to
                     * mark the stack unaddr one page at a time.
                     */
                    stack_base = NULL;
                }
            }
        }
        if (stack_base != NULL) {
            LOG(2, "changing thread stack "PFX"-"PFX" -"PFX" to unaddressable\n",
                stack_base, stack_base + stack_size, newsp);
            ASSERT(stack_base + stack_size >= newsp,
                   "new thread's stack alloc messed up");
            if (options.check_stack_bounds) {
                /* assume that above newsp should stay defined */
                shadow_set_range(stack_base, newsp, SHADOW_UNADDRESSABLE);
                check_stack_size_vs_threshold(drcontext, stack_size);
                if (BEYOND_TOS_REDZONE_SIZE > 0) {
                    size_t redzone_sz = BEYOND_TOS_REDZONE_SIZE;
                    if (newsp - BEYOND_TOS_REDZONE_SIZE < stack_base)
                        redzone_sz = newsp - stack_base;
                    shadow_set_range(newsp - redzone_sz, newsp, SHADOW_UNDEFINED);
                }
            }
        } else {
            LOG(0, "ERROR: cannot find bounds of new thread's stack "PFX"\n",
                newsp);
            ASSERT(false, "can't find bounds of thread's stack");
        }
    }
}

#define PRCTL_NAME_SZ 16 /* from man page */

static void
check_prctl_whitelist(byte *prctl_arg1)
{
    /* disable instrumentation on seeing prctl(PR_SET_NAME) that does not
     * match any of the specified ,-separated names (PR 574018)
     */
    char nm[PRCTL_NAME_SZ+1];
    ASSERT(options.prctl_whitelist[0] != '\0', "caller should check for empty op");
    if (safe_read(prctl_arg1, PRCTL_NAME_SZ, nm)) {
        bool on_whitelist = false;
        char *s, *next;
        char *list_end = options.prctl_whitelist + strlen(options.prctl_whitelist);
        size_t white_sz;
        NULL_TERMINATE_BUFFER(nm);
        LOG(1, "prctl set name %s\n", nm);
        s = options.prctl_whitelist;
        while (s < list_end) {
            next = strchr(s, ',');
            if (next == NULL)
                white_sz = (list_end - s);
            else
                white_sz = (next - s);
            LOG(2, "comparing \"%s\" with whitelist entry \"%.*s\" sz=%d\n",
                nm, white_sz, s, white_sz);
            if (strncmp(nm, s, white_sz) == 0) {
                LOG(0, "prctl name %s matches whitelist\n", nm);
                on_whitelist = true;
                break;
            }
            s += white_sz + 1 /* skip , itself */;
        }
        if (!on_whitelist) {
            /* ideally: suspend world, then set options, then flush
             * w/o resuming.
             * FIXME: just setting options is unsafe if another thread
             * hits an event and fails to restore state or sthg.
             * Fortunately we expect most uses of PR_SET_NAME to be
             * immediately after forking.
             * Ideally we'd call dr_suspend_all_other_threads()
             * and nest dr_flush_region() inside it but both want
             * the same master lock: should check whether easy to support
             * via internal vars indicating whether lock held.
             */
            ELOGF(0, f_global, "\n*********\nDISABLING MEMORY CHECKING for %s\n", nm);
            options.shadowing = false;
            options.track_allocs = false;
            options.count_leaks = false;
            dr_flush_region(0, ~((ptr_uint_t)0));
        }
    }
}

static void
handle_pre_prctl(void *drcontext, dr_mcontext_t *mc)
{
    uint request = (uint) dr_syscall_get_param(drcontext, 0);
    ptr_int_t arg1 = (ptr_int_t) dr_syscall_get_param(drcontext, 1);
    /* They all use param #0, which is checked via table specifying 1 arg.
     * Officially it's a 5-arg syscall but so far nothing using beyond 2 args.
     */
    /* XXX: could use SYSINFO_SECONDARY_TABLE instead */
    switch (request) {
    case PR_SET_NAME:
    case PR_GET_NAME:
        if (request == PR_SET_NAME && options.prctl_whitelist[0] != '\0')
            check_prctl_whitelist((byte *)arg1);
        break;
    }
}

static void
handle_pre_execve(void *drcontext)
{
#ifndef USE_DRSYMS
    /* PR 453867: tell postprocess.pl to watch for new logdir and
     * fork a new copy.
     * FIXME: what if syscall fails?  Punting on that for now.
     * Note that if it fails and then a later one succeeds, postprocess.pl
     * will replace the first with the last.
     */
    char logdir[MAXIMUM_PATH]; /* one reason we're not inside os_post_syscall() */
    size_t bytes_read = 0;
    /* Not using safe_read() since we want a partial read if hits page boundary */
    dr_safe_read((void *) dr_syscall_get_param(drcontext, 0),
                 BUFFER_SIZE_BYTES(logdir), logdir, &bytes_read);
    if (bytes_read < BUFFER_SIZE_BYTES(logdir))
        logdir[bytes_read] = '\0';
    NULL_TERMINATE_BUFFER(logdir);
    ELOGF(0, f_fork, "EXEC path=%s\n", logdir);
#endif
}

/* for tasks unrelated to shadowing that are common to all tools */
bool
os_shared_pre_syscall(void *drcontext, cls_syscall_t *pt, drsys_sysnum_t sysnum,
                      dr_mcontext_t *mc, drsys_syscall_t *syscall)
{
    bool res = true;
    switch (sysnum.number) {
    case SYS_close: {
        /* DRi#357 has DR isolating our files for us, so nothing to do here anymore */
        break;
    }
    case SYS_execve: {
        handle_pre_execve(drcontext);
        break;
    }
    case SYS_clone: {
        handle_clone(drcontext, mc);
        break;
    }
    case SYS_prctl: {
        handle_pre_prctl(drcontext, mc);
        break;
    }
    }
    return res;
}

/* for tasks unrelated to shadowing that are common to all tools */
void
os_shared_post_syscall(void *drcontext, cls_syscall_t *pt, drsys_sysnum_t sysnum,
                       dr_mcontext_t *mc, drsys_syscall_t *syscall)
{
    switch (sysnum.number) {
    case SYS_clone: {
        uint flags = (uint) syscall_get_param(drcontext, 0);
        if (TEST(CLONE_VM, flags)) {
            thread_id_t child = dr_syscall_get_result(drcontext);
            report_child_thread(drcontext, child);
            break;
        }
        /* else, fall through */
    }
    case SYS_fork: {
#ifndef USE_DRSYMS
        /* PR 453867: tell postprocess.pl to not exit until it sees a message
         * from the child starting up.
         */
        process_id_t child = dr_syscall_get_result(drcontext);
        if (child != 0)
            ELOGF(0, f_fork, "FORK child=%d\n", child);
#endif
        break;
    }
    }
}

