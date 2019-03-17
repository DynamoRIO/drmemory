/* **********************************************************
 * Copyright (c) 2011-2019 Google, Inc.  All rights reserved.
 * Copyright (c) 2008-2010 VMware, Inc.  All rights reserved.
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
 * STACK ADJUSTMENT HANDLING
 */

#include "dr_api.h"
#include "drmemory.h"
#include "slowpath.h"
#include "spill.h"
#include "fastpath.h"
#include "stack.h"
#include "stack_arch.h"
#include "shadow.h"
#include "heap.h"
#include "alloc.h"
#include "alloc_drmem.h"

#ifdef STATISTICS
uint adjust_esp_executions;
uint adjust_esp_fastpath;
uint stack_swaps;
uint stack_swap_triggers;
uint push_addressable;
uint push_addressable_heap;
uint push_addressable_mmap;
uint zero_loop_aborts_fault;
uint zero_loop_aborts_thresh;
#endif

/***************************************************************************
 * STACK SWAP THRESHOLD ADJUSTMENTS
 *
 * If our -stack_swap_threshold is too big or too small we can easily have
 * false positives and/or false negatives so we try to handle unknown
 * stack regions and different sizes of stacks and of stack allocations
 * and deallocations.  Xref PR 525807.
 */

/* number of swap triggers that aren't really swaps before we increase
 * the swap threshold
 */
#define MAX_NUMBER_NON_SWAPS 16

/* we use the stack_swap_threshold for other parts of the code like
 * callstacks and Ki handling so don't let it get too small:
 * though now we use TYPICAL_STACK_MIN_SIZE for Ki and
 * a hardcoded constant for callstacks so making smaller:
 */
#define MIN_SWAP_THRESHOLD 2048

void
check_stack_size_vs_threshold(void *drcontext, size_t stack_size)
{
    /* It's better to have the threshold too small than too big, since
     * over-detecting swaps is much better than under-detecting
     * because we have a nice control point for verifying a swap.
     */
    if (stack_size < options.stack_swap_threshold) {
        /* If the app is near base of stack and swaps not to base of
         * adjacent-higher stack but to near its lowest addr then we
         * could have a quite small delta so go pretty small.
         * check_stack_swap() will bring it back up if there are a
         * lot of large allocs.
         * I originally based this on the stack size but really
         * it only depends on how close adjacent stacks are and how
         * near the end of the stack they get.  Now I just drop
         * to the min and count on check_stack_swap() to bring back up
         * if necessary.
         */
        size_t new_thresh = MIN_SWAP_THRESHOLD;
        if (new_thresh < MIN_SWAP_THRESHOLD)
            new_thresh = MIN_SWAP_THRESHOLD;
        if (new_thresh < options.stack_swap_threshold)
            update_stack_swap_threshold(drcontext, new_thresh);
    }
}

/* Retrieves the bounds for the malloc or mmap region containing addr.
 * If addr is in a small malloc this routine will fail.
 */
static bool
get_stack_region_bounds(byte *addr, byte **base OUT, size_t *size OUT)
{
    if (is_in_heap_region(addr)) {
        return malloc_large_lookup(addr, base, size);
    } else {
#if defined(UNIX) && defined(TOOL_DR_MEMORY)
        /* see notes in handle_clone(): OS query not good enough */
        if (mmap_anon_lookup(addr, base, size))
            return true;
#endif
        return dr_query_memory(addr, base, size, NULL);
    }
}

static bool
check_stack_swap(byte *cur_xsp, byte *new_xsp)
{
    /* We check whether this is really a stack swap.  If it is we don't need to
     * do anything.  If it is not we need to handle as an alloc or dealloc to
     * avoid false positives and false negatives.  We also consider increasing
     * the threshold but it's easier to handle when too small than when too
     * large.  Xref PR 525807.
     */
    byte *stack_start;
    size_t stack_size;
    STATS_INC(stack_swap_triggers);
    ASSERT(options.check_stack_bounds, "shouldn't be called");
    if (get_stack_region_bounds(cur_xsp, &stack_start, &stack_size)) {
        LOG(3, "stack bounds "PFX" "PFX"-"PFX"\n", cur_xsp,
            stack_start, stack_start + stack_size);
        if (new_xsp >= stack_start && new_xsp < stack_start + stack_size) {
            static int num_non_swaps;
            LOG(1, "stack adjust "PFX" to "PFX" @"PFX"is really intra-stack adjust\n",
                cur_xsp, new_xsp,
                /* retaddr for shared slowpath */
                get_own_tls_value(esp_spill_slot_base(true)));
            /* Reluctantly increase the threshold linearly: better too small */
            if (num_non_swaps++ > MAX_NUMBER_NON_SWAPS) {
                num_non_swaps = 0;
                update_stack_swap_threshold(dr_get_current_drcontext(),
                                            options.stack_swap_threshold + PAGE_SIZE);
            }
            return false;
        }
    } else
        LOG(1, "WARNING: cannot determine stack bounds for "PFX"\n", cur_xsp);
    LOG(1, "stack swap "PFX" => "PFX"\n", cur_xsp, new_xsp);
    STATS_INC(stack_swaps);
    /* If don't know stack bounds: better to treat as swap, smaller chance
     * of false positives and better to have false negs than tons of pos
     */
    /* FIXME PR 542004: instead of waiting for push of addr memory and
     * handle_push_addressable(), we should mark below new_xsp as unaddr here:
     * but are we sure the app is using this as a stack?  It's possible it's in
     * an optimized loop and it's using xsp as a general-purpose register.
     */
    return true;
}

bool
handle_push_addressable(app_loc_t *loc, app_pc addr, app_pc start_addr,
                        size_t sz, dr_mcontext_t *mc)
{
    /* To detect unknown stacks, and attempt to prevent a too-large
     * stack swap threshold, when we see a push of addressable memory
     * we check whether we should act.  Xref PR 525807.
     * FIXME PR 542004: check on all esp adjusts for
     * addressable memory.
     * Note that a too-large stack swap threshold should usually
     * happen only for swaps between unknown stacks that were
     * allocated together and are similar sizes, so the unknown stack
     * handling's adjustment of the threshold is the only mechanism
     * here.  Swapping from a known stack to a nearby unknown stack of
     * a smaller size is not going to be detected: fortunately it's
     * rare, and we can tell users to use the -stack_swap_threshold
     * for those cases.  Risks include false positives and negatives.
     */
    bool handled = false;
    ASSERT(options.check_stack_bounds, "shouldn't be called");
    STATS_INC(push_addressable);
    /* We provide an option to disable if our handling isn't working
     * and we just want to get some performance and don't care about
     * false positives/negatives and have already tuned the stack swap
     * threshold.
     */
    if (options.check_push) {
        byte *stack_start;
        size_t stack_size;
#if defined(STATISTICS) || defined(DEBUG)
        bool is_heap = false;
#endif
        /* we want to do two things:
         * 1) mark beyond-TOS as unaddressable
         * 2) make sure -stack_swap_threshold is small enough: malloc-based
         *    stacks are often small (PR 525807).  our check_stack_swap()
         *    handles a too-small threshold.
         */
        if (is_in_heap_region(addr)) {
#if defined(STATISTICS) || defined(DEBUG)
            is_heap = true;
#endif
            LOG(1, "WARNING: "PFX" is treating heap memory "PFX" as a stack!\n",
                loc_to_print(loc), addr);
        } else {
            LOG(1, "WARNING: "PFX" is treating mmap memory "PFX" as a stack!\n",
                loc_to_print(loc), addr);
        }
        if (get_stack_region_bounds(addr, &stack_start, &stack_size)) {
            LOG(1, "assuming %s "PFX"-"PFX" is a stack\n",
                is_heap ? "large malloc" : "mmap",
                stack_start, stack_start + stack_size);
#ifdef STATISTICS
            if (is_heap)
                STATS_INC(push_addressable_heap);
            else
                STATS_INC(push_addressable_mmap);
#endif
            handled = true;
            /* We don't nec. know the stack bounds since some apps malloc
             * a struct that has some fields and then a stack, so we do one
             * page at a time.  Alternatives include (PR 542004):
             * - have an API where the app tells us its stack bounds: or if
             *   constant could just be a runtime option
             * - stop if hit a defined shadow value before the page size.  can
             *   only do this on 1st time to rule out stale stack values that
             *   can happen if swaps include rollbacks (e.g., swap to base like
             *   DR does w/ dstack, or longjmp from sigaltstack).  thus would
             *   need to remember every stack (and remove from data struct on
             *   dealloc).
             */
            shadow_set_range((addr - PAGE_SIZE < stack_start) ? stack_start :
                             /* stop at start_addr: don't mark what's being
                              * pushed as unaddr!
                              */
                             (addr - PAGE_SIZE), start_addr, SHADOW_UNADDRESSABLE);
            if (BEYOND_TOS_REDZONE_SIZE > 0) {
                size_t redzone_sz = BEYOND_TOS_REDZONE_SIZE;
                if (start_addr - BEYOND_TOS_REDZONE_SIZE < stack_start)
                    redzone_sz = start_addr - stack_start;
                shadow_set_range(start_addr - redzone_sz, start_addr, SHADOW_UNDEFINED);
            }
            check_stack_size_vs_threshold(dr_get_current_drcontext(), stack_size);
        } else {
            ELOG(0, "ERROR: "PFX" pushing addressable memory: possible Dr. Memory bug\n",
                 loc_to_print(loc));
            if (options.pause_at_unaddressable)
                wait_for_user("pushing addressable memory!");
        }
    }
    return handled;
}

/***************************************************************************/

bool
instr_writes_esp(instr_t *inst)
{
    int i;
    for (i = 0; i < instr_num_dsts(inst); i++) {
        opnd_t opnd = instr_get_dst(inst, i);
        if (opnd_is_reg(opnd) && opnd_uses_reg(opnd, DR_REG_XSP)) {
            /* opnd_uses_reg checks for sub-reg SP */
            return true;
        }
    }
    return false;
}

/* PR 447537: adjust_esp's shared fast and slow paths */
byte *shared_esp_slowpath_shadow;
byte *shared_esp_slowpath_defined;
byte *shared_esp_slowpath_zero;
/* Indexed by:
 * - sp_action
 * - eflags_live
 * - esp_adjust_t
 * There is no shared fast path for stack zeroing, we always do that inline.
 */
byte *
shared_esp_fastpath[SP_ADJUST_ACTION_FASTPATH_MAX+1][2][ESP_ADJUST_FAST_LAST+1];

/* N.B.: mcontext is not in consistent app state, for efficiency.
 * esp is guaranteed to hold app value, though.
 */
void
handle_esp_adjust(esp_adjust_t type, reg_t val/*either relative delta, or absolute*/,
                  sp_adjust_action_t sp_action)
{
    ptr_int_t delta = (ptr_int_t) val;
    void *drcontext = dr_get_current_drcontext();
    dr_mcontext_t mc; /* do not init whole thing: memset is expensive */
    mc.size = sizeof(mc);
    mc.flags = DR_MC_CONTROL; /* only need xsp */
    STATS_INC(adjust_esp_executions);
    dr_get_mcontext(drcontext, &mc);

    if (type == ESP_ADJUST_ABSOLUTE ||
        type == ESP_ADJUST_ABSOLUTE_POSTPOP) {
        LOG(3, "esp adjust absolute esp="PFX" => "PFX"\n", mc.xsp, val);
        delta = val - mc.xsp;
        /* Treat as a stack swap (vs ebp->esp, etc.) if a large change */
        if ((delta > options.stack_swap_threshold ||
             delta < -options.stack_swap_threshold) &&
            check_stack_swap((byte *)mc.xsp, (byte *)val)) {
            /* Stack swap: nothing to do */
            return;
        }
    } else if (type == ESP_ADJUST_AND) {
        ptr_int_t newval = mc.xsp & val;
        delta = newval - mc.xsp;
        LOG(3, "esp adjust and mask="PIFX" esp="PFX" delta="SZFMT"\n",
            val, mc.xsp, delta);
        if ((delta > options.stack_swap_threshold ||
             delta < -options.stack_swap_threshold) &&
            check_stack_swap((byte *)mc.xsp, (byte *)newval)) {
            /* Stack swap: nothing to do */
            return;
        }
    } else {
        if (type == ESP_ADJUST_NEGATIVE)
            delta = -delta;
        /* We assume a swap would not happen w/ a relative adjustment */
        if (delta > options.stack_swap_threshold ||
            delta < -options.stack_swap_threshold) {
            LOG(1, "WARNING: relative stack adjustment %d > swap threshold\n",
                delta);
        }
        if (type == ESP_ADJUST_RET_IMMED)
            mc.xsp += 4; /* pop of retaddr happens first */
        LOG(3, "esp adjust relative esp="PFX" delta=%d\n", mc.xsp, delta);
    }
    if (delta != 0) {
        if (sp_action == SP_ADJUST_ACTION_ZERO) {
            if (BEYOND_TOS_REDZONE_SIZE > 0) {
                /* FIXME i#1205: zeroing conflicts w/ redzone: NYI */
                ASSERT_NOT_IMPLEMENTED();
            }
            if (delta < 0) {
                /* zero out newly allocated stack space to avoid stale
                 * pointers from misleading our leak scan (PR 520916).
                 * yes, I realize it may not be perfectly transparent.
                 */
                memset((app_pc)(mc.xsp + delta), 0, -delta);
            }
        } else {
            app_pc sp = (app_pc)mc.xsp - BEYOND_TOS_REDZONE_SIZE;
            shadow_set_range(delta > 0 ? sp : (sp + delta),
                             delta > 0 ? (sp + delta) : sp,
                             (delta > 0 ? SHADOW_UNADDRESSABLE :
                              ((sp_action == SP_ADJUST_ACTION_DEFINED) ?
                               SHADOW_DEFINED : SHADOW_UNDEFINED)));
            if (BEYOND_TOS_REDZONE_SIZE > 0) {
                sp = (app_pc)mc.xsp + delta;
                if (type == ESP_ADJUST_ABSOLUTE_POSTPOP) {
                    /* Don't undo the pop portion of OP_leave, which already happened
                     * due to instru ordering.
                     */
                    sp += sizeof(void*);
                }
                shadow_set_range(sp - BEYOND_TOS_REDZONE_SIZE, sp,
                                 (sp_action == SP_ADJUST_ACTION_DEFINED) ?
                                 SHADOW_DEFINED : SHADOW_UNDEFINED);
            }
        }
    }
}

int
esp_spill_slot_base(sp_adjust_action_t sp_action)
{
    /* for whole-bb, we can end up using 1-3 for whole-bb and 4-5 for
     * the required ecx+edx for these shared routines
     * FIXME: opt: we should we xchg w/ whole-bb in
     * instrument_esp_adjust_fastpath() like we do for esp slowpath,
     * and thus make use of a global eax: then should have at most
     * slot 4 used so can always use 5 here
     */
    if (whole_bb_spills_enabled())
        return SPILL_SLOT_6;
    else if (sp_action != SP_ADJUST_ACTION_ZERO) {
        /* we don't have shared_esp_fastpath, and instrument slowpath only
         * uses slots 1 and 2
         */
        return SPILL_SLOT_3;
    } else
        return SPILL_SLOT_5;
}

/* N.B.: mcontext is not in consistent app state, for efficiency.
 * esp is guaranteed to hold app value, though.
 */
void
handle_esp_adjust_shared_slowpath(reg_t val/*either relative delta, or absolute*/,
                                  sp_adjust_action_t sp_action)
{
    /* Rather than force gen code to pass another arg we derive the type */
    esp_adjust_t type;
    /* Get the return address from this slowpath call */
    app_pc pc = (app_pc) get_own_tls_value(esp_spill_slot_base(sp_action));
    instr_t inst;
    void *drcontext = dr_get_current_drcontext();

    /* We decode forward past eflags and register restoration, none of which
     * should reference esp.  The next instr is the app instr.
     */
    instr_init(drcontext, &inst);
    while (true) {
        pc = decode(drcontext, pc, &inst);
        ASSERT(instr_valid(&inst), "unknown suspect instr");
        if (instr_writes_esp(&inst)) {
#ifdef X64
            /* Handle DR's rip-rel mangling where we'll have 2 steps:
             *  48bc706808a8f77f0000 mov rsp,offset varstack!stack1 (00007ff7`a8086870)
             *  488b2424        mov     rsp,qword ptr [rsp]
             */
            ptr_int_t ignored;
            if (instr_is_mov_constant(&inst, &ignored)) {
                bool skip = false;
                instr_t next;
                instr_init(drcontext, &next);
                decode(drcontext, pc, &next);
                if (instr_writes_esp(&next))
                    skip = true;
                instr_free(drcontext, &next);
                if (skip) {
                    instr_reset(drcontext, &inst);
                    continue;
                }
            }
#endif
            /* ret gets mangled: we'll skip the ecx save and hit the pop */
            type = get_esp_adjust_type(&inst, true/*mangled*/);
            ASSERT(needs_esp_adjust(&inst, sp_action) ||
                   type == ESP_ADJUST_RET_IMMED, "found wrong esp-using instr");
            handle_esp_adjust(type, val, sp_action);
            break;
        }
        if (instr_is_cti(&inst)) {
            ASSERT(false, "somehow missed app esp-adjust instr");
            break;
        }
        instr_reset(drcontext, &inst);
    }
    instr_free(drcontext, &inst);
    /* paranoid: if didn't find the esp-adjust instr just skip the adjust call */
}

static app_pc
generate_shared_esp_slowpath_helper(void *drcontext, instrlist_t *ilist, app_pc pc,
                                    sp_adjust_action_t sp_action)
{
    /* PR 447537: adjust_esp's shared_slowpath.
     * On entry:
     *   - scratch1 holds the val arg
     *   - scratch2 holds the return address
     * Need retaddr in persistent storage: slot5 is guaranteed free.
     */
    PRE(ilist, NULL, XINST_CREATE_store
        (drcontext, spill_slot_opnd(drcontext, esp_spill_slot_base(sp_action)),
         opnd_create_reg(ESP_SLOW_SCRATCH2)));
    dr_insert_clean_call(drcontext, ilist, NULL,
                         (void *)handle_esp_adjust_shared_slowpath, false, 2,
                         opnd_create_reg(ESP_SLOW_SCRATCH1), OPND_CREATE_INT32(sp_action));
    PRE(ilist, NULL, XINST_CREATE_jump_mem
        (drcontext, spill_slot_opnd(drcontext, esp_spill_slot_base(sp_action))));

    pc = instrlist_encode(drcontext, ilist, pc, false);
    instrlist_clear(drcontext, ilist);
    return pc;
}

app_pc
generate_shared_esp_slowpath(void *drcontext, instrlist_t *ilist, app_pc pc)
{
    shared_esp_slowpath_shadow = pc;
    pc = generate_shared_esp_slowpath_helper(drcontext, ilist, pc,
                                             SP_ADJUST_ACTION_SHADOW);
    shared_esp_slowpath_defined = pc;
    pc = generate_shared_esp_slowpath_helper(drcontext, ilist, pc,
                                             SP_ADJUST_ACTION_DEFINED);
    shared_esp_slowpath_zero = pc;
    pc = generate_shared_esp_slowpath_helper(drcontext, ilist, pc,
                                             SP_ADJUST_ACTION_ZERO);
    return pc;
}

app_pc
generate_shared_esp_fastpath(void *drcontext, instrlist_t *ilist, app_pc pc)
{
    /* PR 447537: adjust_esp's shared fastpath
     * On entry:
     *   - ecx holds the val arg
     *   - edx holds the return address
     * Uses slot5 and slot6.
     * We have multiple versions for {sp_action,eflags,adjust-type}.
     */
    int eflags_live;
    sp_adjust_action_t sp_action;
    esp_adjust_t type;
    if (!options.esp_fastpath)
        return pc;
    ASSERT(ESP_ADJUST_FAST_FIRST == 0, "esp enum error");
    /* No shared_esp_fastpath gencode for zeroing. */
    for (sp_action = 0; sp_action <= SP_ADJUST_ACTION_FASTPATH_MAX; sp_action++) {
        for (eflags_live = 0; eflags_live < 2; eflags_live++) {
            for (type = ESP_ADJUST_FAST_FIRST; type <= ESP_ADJUST_FAST_LAST; type++) {
                shared_esp_fastpath[sp_action][eflags_live][type] = pc;
                generate_shared_esp_fastpath_helper
                    (drcontext, ilist, eflags_live, sp_action, type);
                pc = instrlist_encode(drcontext, ilist, pc, true);
                instrlist_clear(drcontext, ilist);
            }
        }
    }
    return pc;
}

/* Instrument an esp modification that is not also a read or write
 * Returns whether instrumented
 */
bool
instrument_esp_adjust(void *drcontext, instrlist_t *bb, instr_t *inst, bb_info_t *bi,
                      sp_adjust_action_t sp_action)
{
    /* i#677: We don't need -esp_fastpath gencode for insert_zeroing_loop(). */
    if (options.esp_fastpath || sp_action == SP_ADJUST_ACTION_ZERO)
        return instrument_esp_adjust_fastpath(drcontext, bb, inst, bi, sp_action);
    else
        return instrument_esp_adjust_slowpath(drcontext, bb, inst, bi, sp_action);
}

