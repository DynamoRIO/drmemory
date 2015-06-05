/* **********************************************************
 * Copyright (c) 2011-2015 Google, Inc.  All rights reserved.
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
#include "readwrite.h"
#include "spill.h"
#include "fastpath.h"
#include "stack.h"
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

static int
esp_spill_slot_base(sp_adjust_action_t sp_action);

static bool
needs_esp_adjust(instr_t *inst, sp_adjust_action_t sp_action);

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
        if (opnd_is_reg(opnd) && opnd_uses_reg(opnd, REG_XSP)) {
            /* opnd_uses_reg checks for sub-reg SP */
            return true;
        }
    }
    return false;
}

/* i#1500: we need to handle this as an esp adjustment */
bool
instr_pop_into_esp(instr_t *inst)
{
    if (instr_get_opcode(inst) == OP_pop) {
        opnd_t dst = instr_get_dst(inst, 0);
        if (opnd_is_reg(dst) && opnd_uses_reg(dst, REG_XSP))
            return true;
    }
    return false;
}

/* Handle an instruction at pc that writes to esp */
typedef enum {
    ESP_ADJUST_ABSOLUTE,
    ESP_ADJUST_FAST_FIRST = ESP_ADJUST_ABSOLUTE,
    ESP_ADJUST_NEGATIVE,
    ESP_ADJUST_POSITIVE,
    ESP_ADJUST_RET_IMMED, /* positive, but after a pop */
    ESP_ADJUST_AND, /* and with a mask */
    ESP_ADJUST_FAST_LAST = ESP_ADJUST_AND, /* we only support and w/ immed in fastpath */
    ESP_ADJUST_INVALID,
} esp_adjust_t;

/* PR 447537: adjust_esp's shared fast and slow paths */
static byte *shared_esp_slowpath_shadow;
static byte *shared_esp_slowpath_defined;
static byte *shared_esp_slowpath_zero;
/* Indexed by:
 * - sp_action
 * - eflags_live
 * - esp_adjust_t
 * There is no shared fast path for stack zeroing, we always do that inline.
 */
static byte *
shared_esp_fastpath[SP_ADJUST_ACTION_FASTPATH_MAX+1][2][ESP_ADJUST_FAST_LAST+1];

static esp_adjust_t
get_esp_adjust_type(uint opc)
{
    switch (opc) {
    case OP_mov_st:
    case OP_mov_ld:
    case OP_leave:
    case OP_lea:
    case OP_xchg:
    case OP_cmovb:
    case OP_cmovnb:
    case OP_cmovbe:
    case OP_cmovnbe:
    case OP_cmovl:
    case OP_cmovnl:
    case OP_cmovle:
    case OP_cmovnle:
    case OP_cmovo:
    case OP_cmovno:
    case OP_cmovp:
    case OP_cmovnp:
    case OP_cmovs:
    case OP_cmovns:
    case OP_cmovz:
    case OP_cmovnz:
    case OP_pop: /* pop into xsp */
        return ESP_ADJUST_ABSOLUTE;
    case OP_inc:
    case OP_dec:
    case OP_add:
        return ESP_ADJUST_POSITIVE;
    case OP_sub:
        return ESP_ADJUST_NEGATIVE;
    case OP_ret:
        return ESP_ADJUST_RET_IMMED;
    case OP_enter:
        return ESP_ADJUST_NEGATIVE;
    case OP_and:
        return ESP_ADJUST_AND;
    default:
        return ESP_ADJUST_INVALID;
    }
}

/* N.B.: mcontext is not in consistent app state, for efficiency.
 * esp is guaranteed to hold app value, though.
 */
static void
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

    if (type == ESP_ADJUST_ABSOLUTE) {
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
        LOG(3, "esp adjust and esp="PFX" delta=%d\n", mc.xsp, delta);
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
            if (delta < 0) {
                /* zero out newly allocated stack space to avoid stale
                 * pointers from misleading our leak scan (PR 520916).
                 * yes, I realize it may not be perfectly transparent.
                 */
                memset((app_pc)(mc.xsp + delta), 0, -delta);
            }
        } else {
            shadow_set_range((app_pc) (delta > 0 ? mc.xsp : (mc.xsp + delta)),
                             (app_pc) (delta > 0 ? (mc.xsp + delta) : mc.xsp),
                             (delta > 0 ? SHADOW_UNADDRESSABLE :
                              ((sp_action == SP_ADJUST_ACTION_DEFINED) ?
                               SHADOW_DEFINED : SHADOW_UNDEFINED)));
        }
    }
}

static int
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
static void
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
            /* ret gets mangled: we'll skip the ecx save and hit the pop */
            if (instr_get_opcode(&inst) == OP_pop &&
                !instr_pop_into_esp(&inst))
                type = get_esp_adjust_type(OP_ret);
            else {
                type = get_esp_adjust_type(instr_get_opcode(&inst));
                ASSERT(needs_esp_adjust(&inst, sp_action), "found wrong esp-using instr");
            }
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

/* i#668: instrument code to handle esp adjustment via cmovcc. */
static void
instrument_esp_cmovcc_adjust(void *drcontext,
                             instrlist_t *bb,
                             instr_t *inst,
                             instr_t *skip,
                             bb_info_t *bi)
{
    instr_t *jcc;
    int opc = instr_get_opcode(inst);
    /* restore the app's aflags if necessary */
    if (whole_bb_spills_enabled()) {
        restore_aflags_if_live(drcontext, bb, inst, NULL, bi);
        /* to avoid eflags save on the mark_eflags_used later */
        bi->eflags_used = true;
    }
    /* jcc skip */
    jcc = INSTR_CREATE_jcc_short(drcontext,
                                 instr_cmovcc_to_jcc(opc),
                                 opnd_create_instr(skip));
    instr_invert_cbr(jcc);
    PRE(bb, inst, jcc);
}

static app_pc
generate_shared_esp_slowpath_helper(void *drcontext, instrlist_t *ilist, app_pc pc,
                                    sp_adjust_action_t sp_action)
{
    /* PR 447537: adjust_esp's shared_slowpath.
     * On entry:
     *   - ecx holds the val arg
     *   - edx holds the return address
     * Need retaddr in persistent storage: slot5 is guaranteed free.
     */
    PRE(ilist, NULL, INSTR_CREATE_mov_st
        (drcontext, spill_slot_opnd(drcontext, esp_spill_slot_base(sp_action)),
         opnd_create_reg(DR_REG_XDX)));
    dr_insert_clean_call(drcontext, ilist, NULL,
                         (void *)handle_esp_adjust_shared_slowpath, false, 2,
                         opnd_create_reg(DR_REG_XCX), OPND_CREATE_INT32(sp_action));
    PRE(ilist, NULL, INSTR_CREATE_jmp_ind
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

/* assumes that inst does write to esp */
static bool
needs_esp_adjust(instr_t *inst, sp_adjust_action_t sp_action)
{
    /* implicit esp changes (e.g., push and pop) are handled during
     * the read/write: this is for explicit esp changes.
     * -leaks_only doesn't care about push, since it writes, or about pop,
     * since shrinking the stack is ignored there.
     */
    int opc = instr_get_opcode(inst);
    if ((opc_is_push(opc) || opc_is_pop(opc)) &&
        /* handle implicit esp adjustments that are not reads or writes */
        (opc != OP_ret || !opnd_is_immed_int(instr_get_src(inst, 0))) &&
        opc != OP_enter && opc != OP_leave) {
        /* esp changes are all reads or writes */
        /* pop into esp is an adjustment we must handle (i#1500) */
        if (!instr_pop_into_esp(inst))
            return false;
    }
    /* -leaks_only doesn't care about shrinking the stack
     * technically OP_leave doesn't have to shrink it: we assume it does
     * (just checking leaks: not huge risk)
     */
    if ((sp_action == SP_ADJUST_ACTION_ZERO) &&
        (opc == OP_inc || opc == OP_ret || opc == OP_leave ||
         (opc == OP_add && opnd_is_immed_int(instr_get_src(inst, 0)) &&
          opnd_get_immed_int(instr_get_src(inst, 0)) >= 0) ||
         (opc == OP_sub && opnd_is_immed_int(instr_get_src(inst, 0)) &&
          opnd_get_immed_int(instr_get_src(inst, 0)) <= 0)))
        return false;
    /* We no longer consider sysenter a special ret, but it still writes esp
     * according to DR, so we explicitly ignore it here.
     */
    if (opc == OP_sysenter)
        return false;
    /* We ignore stack changes due to int* */
    if (opc == OP_int || opc == OP_int3 || opc == OP_into)
        return false;
    /* Ignore "or esp,esp" (PR ) */
    if (opc == OP_or && opnd_is_reg(instr_get_src(inst, 0)) &&
        opnd_is_reg(instr_get_dst(inst, 0)) &&
        opnd_get_reg(instr_get_src(inst, 0)) == REG_XSP &&
        opnd_get_reg(instr_get_dst(inst, 0)) == REG_XSP)
        return false;
    return true;
}

/* Instrument an esp modification that is not also a read or write.
 * Returns whether instrumented.
 */
static bool
instrument_esp_adjust_slowpath(void *drcontext, instrlist_t *bb, instr_t *inst,
                               bb_info_t *bi, sp_adjust_action_t sp_action)
{
    /* implicit esp changes (e.g., push and pop) are handled during
     * the read/write: this is for explicit esp changes
     */
    int opc = instr_get_opcode(inst);
    opnd_t arg;
    esp_adjust_t type;
    instr_t *skip;

    if (!needs_esp_adjust(inst, sp_action))
        return false;

    skip = INSTR_CREATE_label(drcontext);
    if (opc_is_cmovcc(opc))
        instrument_esp_cmovcc_adjust(drcontext, bb, inst, skip, bi);

    /* Call handle_esp_adjust */
    arg = instr_get_src(inst, 0); /* immed is 1st src */
    if (opc == OP_xchg) {
        if (opnd_is_reg(arg) && opnd_get_reg(arg) == DR_REG_XSP) {
            arg = instr_get_src(inst, 1);
        }
    }

    if (!options.shared_slowpath &&
        (opnd_uses_reg(arg, DR_REG_XAX) ||
         opnd_uses_reg(arg, DR_REG_XSP) ||
         opc == OP_lea)) {
        ASSERT(!whole_bb_spills_enabled(), "spill slot conflict");
        /* Put value into tls slot since clean call setup will cause
         * eax and esp to no longer contain app values.
         * If is plain DR_REG_XAX, could pull from pusha slot: but that's fragile.
         * For lea, we can't push the address: we must get it into a register.
         * FIXME: new dr_insert_clean_call() does support eax/esp args, right?
         */
        if (opnd_is_memory_reference(arg)) {
            /* Go through eax to get to tls */
            ASSERT(dr_max_opnd_accessible_spill_slot() >= SPILL_SLOT_1,
                   "DR spill slot not accessible");
            spill_reg(drcontext, bb, inst, DR_REG_XAX, SPILL_SLOT_2);
            if (opc == OP_lea) {
                PRE(bb, inst,
                    INSTR_CREATE_lea(drcontext, opnd_create_reg(DR_REG_XAX), arg));
            } else {
                PRE(bb, inst,
                    INSTR_CREATE_mov_ld(drcontext, opnd_create_reg(DR_REG_XAX), arg));
            }
            spill_reg(drcontext, bb, inst, DR_REG_XAX, SPILL_SLOT_1);
            restore_reg(drcontext, bb, inst, DR_REG_XAX, SPILL_SLOT_2);
        } else {
            ASSERT(opnd_is_reg(arg), "internal error");
            spill_reg(drcontext, bb, inst, opnd_get_reg(arg), SPILL_SLOT_1);
        }
        arg = spill_slot_opnd(drcontext, SPILL_SLOT_1);
    } else if (opc == OP_inc || opc == OP_dec) {
        arg = OPND_CREATE_INT32(opc == OP_inc ? 1 : -1);
    } else if (opc == OP_ret) {
        ASSERT(opnd_is_immed_int(arg), "internal error");
        /* else should have returned up above */
        opnd_set_size(&arg, OPSZ_VARSTACK);
    } else if (opc == OP_enter) {
        /* frame pushes (including nested) are handled elsewhere as writes */
        ASSERT(opnd_is_immed_int(arg), "internal error");
    } else if (opc == OP_leave) {
        /* the pop is handled elsewhere as a write */
        arg = opnd_create_reg(DR_REG_XBP);
    } else if (opc == OP_pop) {
        /* pop into xsp (i#1500) */
        arg = instr_get_src(inst, 1);
    }

    type = get_esp_adjust_type(opc);
    if (type == ESP_ADJUST_INVALID) {
        tls_util_t *pt = PT_GET(drcontext);
        ELOGPT(0, pt, "ERROR: new stack-adjusting instr: ");
        instr_disassemble(drcontext, inst, pt->f);
        ELOGPT(0, pt, "\n");
        ASSERT(false, "unhandled stack adjustment");
    }

    if (options.shared_slowpath) {
        instr_t *retaddr = INSTR_CREATE_label(drcontext);
        scratch_reg_info_t si1 = {DR_REG_XCX, true, false, false, REG_NULL, SPILL_SLOT_1};
        scratch_reg_info_t si2 = {DR_REG_XDX, true, false, false, REG_NULL, SPILL_SLOT_2};
        reg_id_t arg_tgt;
        if (opnd_is_immed_int(arg))
            opnd_set_size(&arg, OPSZ_PTR);
        if (bi->reg1.reg != REG_NULL) {
            /* use global scratch regs
             * FIXME: opt: generalize and use for fastpath too: but more complex
             * there since have 3 scratches and any one could be the extra local.
             */
            if (bi->reg1.reg == DR_REG_XCX || bi->reg2.reg == DR_REG_XCX)
                si1.dead = true;
            else
                si1.xchg = (bi->reg1.reg == DR_REG_XDX) ? bi->reg2.reg : bi->reg1.reg;
            if (bi->reg1.reg == DR_REG_XDX || bi->reg2.reg == DR_REG_XDX)
                si2.dead = true;
            else {
                si2.xchg = (bi->reg1.reg == DR_REG_XCX) ? bi->reg2.reg :
                    ((si1.xchg == bi->reg1.reg) ? bi->reg2.reg : bi->reg1.reg);
            }
            /* restore from spill slot prior to setting up arg */
            if (opnd_uses_reg(arg, bi->reg1.reg)) {
                insert_spill_global(drcontext, bb, inst, &bi->reg1, false/*restore*/);
            } else if (opnd_uses_reg(arg, bi->reg2.reg)) {
                insert_spill_global(drcontext, bb, inst, &bi->reg2, false/*restore*/);
            }
            /* mark as used after the restore to avoid superfluous restore */
            mark_scratch_reg_used(drcontext, bb, bi, &bi->reg1);
            mark_scratch_reg_used(drcontext, bb, bi, &bi->reg2);
        } else {
            /* we assume regs are all holding app state and we can use arg directly */
        }
        /* if saving ecx via xchg we must do xchg after, else mess up app values */
        if (si1.xchg != REG_NULL)
            arg_tgt = si1.xchg;
        else {
            arg_tgt = DR_REG_XCX;
            insert_spill_or_restore(drcontext, bb, inst, &si1, true/*save*/, false);
        }
        if (opnd_is_memory_reference(arg)) {
            if (opc == OP_lea) {
                PRE(bb, inst, INSTR_CREATE_lea(drcontext, opnd_create_reg(arg_tgt), arg));
            } else {
                PRE(bb, inst, INSTR_CREATE_mov_ld(drcontext, opnd_create_reg(arg_tgt),
                                                  arg));
            }
        } else
            PRE(bb, inst, INSTR_CREATE_mov_st(drcontext, opnd_create_reg(arg_tgt), arg));
        if (si1.xchg != REG_NULL) {
            /* now put arg into ecx, and saved ecx into dead xchg-w/ reg */
            insert_spill_or_restore(drcontext, bb, inst, &si1, true/*save*/, false);
        }
        /* spill/xchg edx after, since if xchg can mess up arg's app values */
        insert_spill_or_restore(drcontext, bb, inst, &si2, true/*save*/, false);
        /* we don't need to negate here since handle_adjust_esp() does that */
        PRE(bb, inst,
            INSTR_CREATE_mov_imm(drcontext, opnd_create_reg(DR_REG_XDX),
                                 opnd_create_instr(retaddr)));
        PRE(bb, inst, INSTR_CREATE_jmp
            (drcontext, opnd_create_pc((sp_action == SP_ADJUST_ACTION_ZERO) ?
                                       shared_esp_slowpath_zero :
                                       ((sp_action == SP_ADJUST_ACTION_DEFINED) ?
                                        shared_esp_slowpath_defined :
                                        shared_esp_slowpath_shadow))));
        PRE(bb, inst, retaddr);
        insert_spill_or_restore(drcontext, bb, inst, &si2, false/*restore*/, false);
        insert_spill_or_restore(drcontext, bb, inst, &si1, false/*restore*/, false);
    } else {
        dr_insert_clean_call(drcontext, bb, inst,
                             (void *) handle_esp_adjust,
                             false, 3, OPND_CREATE_INT32(type), arg, sp_action);
    }
    PRE(bb, inst, skip);
    return true;
}

/* Handle a fault while zeroing the app stack (PR 570843) */
bool
handle_zeroing_fault(void *drcontext, byte *target, dr_mcontext_t *raw_mc,
                     dr_mcontext_t *mc)
{
    /* We inline our code so we can't just check is_in_gencode.
     * We aborting the loop if this is our fault.
     * This risks false negatives but presumably the fault indicates
     * the current end of the stack so there shouldn't be stale data
     * beyond it.
     */
    bool ours = false;
    byte *nxt_pc;
    instr_t inst, app_inst;
    byte *pc = raw_mc->pc;
    ASSERT(ZERO_STACK(), "incorrectly called");

    instr_init(drcontext, &app_inst);
    instr_init(drcontext, &inst);
    if (!safe_decode(drcontext, mc->pc, &app_inst, NULL))
        goto handle_zeroing_fault_done;
    if (!safe_decode(drcontext, pc, &inst, &nxt_pc))
        goto handle_zeroing_fault_done;

    if (instr_get_opcode(&inst) == OP_mov_st &&
        opnd_is_immed_int(instr_get_src(&inst, 0)) &&
        opnd_get_immed_int(instr_get_src(&inst, 0)) == 0 &&
        /* if raw instr is a store but app instr write esp, assume
         * it's our instru
         */
        instr_get_opcode(&app_inst) != OP_mov_st &&
        instr_writes_esp(&app_inst)) {
        /* walk past the store and jmp */
        instr_reset(drcontext, &inst);
        pc = nxt_pc;
        nxt_pc = decode(drcontext, pc, &inst);
        ASSERT(instr_get_opcode(&inst) == OP_jmp_short, "jmp follows store");
        LOG(2, "zeroing write fault @"PFX" => sending to end of loop "PFX"\n",
            raw_mc->pc, nxt_pc);
        STATS_INC(zero_loop_aborts_fault);
        raw_mc->pc = nxt_pc;
        ours = true;
    }
 handle_zeroing_fault_done:
    instr_free(drcontext, &app_inst);
    instr_free(drcontext, &inst);
    return ours;
}

/* Inserts stack zeroing loop for -leaks_only */
static void
insert_zeroing_loop(void *drcontext, instrlist_t *bb, instr_t *inst,
                    bb_info_t *bi, fastpath_info_t *mi, reg_id_t reg_mod,
                    esp_adjust_t type, instr_t *retaddr, bool eflags_live)
{
    instr_t *loop_repeat = INSTR_CREATE_label(drcontext);
    /* since we statically know we don't need slowpath (even if unaligned:
     * ok to write unaligned dwords via mov_st) and we only go in one
     * direction and don't need address translation, the loop is small
     * enough to inline
     */
    if (whole_bb_spills_enabled())
        mark_eflags_used(drcontext, bb, bi);
    else if (eflags_live)
        insert_save_aflags(drcontext, bb, inst, &mi->eax, mi->aflags);
    PRE(bb, inst,
        INSTR_CREATE_mov_ld(drcontext, opnd_create_reg(mi->reg1.reg),
                            opnd_create_reg(REG_XSP)));
    ASSERT(type != ESP_ADJUST_RET_IMMED, "ret ignored for -leaks_only");
    if (type != ESP_ADJUST_ABSOLUTE && type != ESP_ADJUST_AND) {
        /* calculate the end of the loop */
        PRE(bb, inst,
            INSTR_CREATE_add(drcontext, opnd_create_reg(reg_mod),
                             opnd_create_reg(mi->reg1.reg)));
    }
    /* only zero if allocating stack, not when deallocating */
    PRE(bb, inst,
        INSTR_CREATE_cmp(drcontext, opnd_create_reg(reg_mod),
                         opnd_create_reg(REG_XSP)));
    PRE(bb, inst,
        INSTR_CREATE_jcc(drcontext, OP_jae_short, opnd_create_instr(retaddr)));
    /* now we know we're decreasing stack addresses, so start zeroing.
     * not using rep stos b/c w/ DF preservation (even using a sophisticated
     * scheme) it ended up being slower for the regular esp adjust loop so
     * it would be for here as well presumably.
     */

    /* We don't have a slowpath so we can't verify whether a swap so we just
     * bail if it could be and risk false negatives which are preferable to
     * zeroing out non-stack app memory!
     * We assume a swap would not happen w/ a relative adjustment.
     */
    if (type == ESP_ADJUST_ABSOLUTE || type == ESP_ADJUST_AND/*abs passed to us*/) {
        PRE(bb, inst,
            INSTR_CREATE_sub(drcontext, opnd_create_reg(mi->reg1.reg),
                             opnd_create_reg(reg_mod)));
        PRE(bb, inst,
            INSTR_CREATE_cmp(drcontext, opnd_create_reg(mi->reg1.reg),
                             OPND_CREATE_INT32(options.stack_swap_threshold)));
#ifdef STATISTICS
        if (options.statistics) {
            instr_t *nostat = INSTR_CREATE_label(drcontext);
            int disp;
            PRE(bb, inst,
                INSTR_CREATE_jcc(drcontext, OP_jb_short, opnd_create_instr(nostat)));
            ASSERT_TRUNCATE(disp, int, (ptr_int_t)&zero_loop_aborts_thresh);
            disp = (int)(ptr_int_t)&zero_loop_aborts_thresh;
            PRE(bb, inst,
                INSTR_CREATE_inc(drcontext, OPND_CREATE_MEM32(REG_NULL, disp)));
            PRE(bb, inst,
                INSTR_CREATE_jmp_short(drcontext, opnd_create_instr(retaddr)));
            PRE(bb, inst, nostat);
        } else {
#endif
            PRE(bb, inst,
                INSTR_CREATE_jcc(drcontext, OP_jae_short, opnd_create_instr(retaddr)));
#ifdef STATISTICS
        }
#endif
        /* Restore xsp to reg1 */
        PRE(bb, inst,
            INSTR_CREATE_mov_ld(drcontext, opnd_create_reg(mi->reg1.reg),
                                opnd_create_reg(REG_XSP)));
    }

    PRE(bb, inst, loop_repeat);
    PRE(bb, inst,
        INSTR_CREATE_sub(drcontext, opnd_create_reg(mi->reg1.reg),
                         OPND_CREATE_INT8(4)));
    PRE(bb, inst,
        INSTR_CREATE_cmp(drcontext, opnd_create_reg(mi->reg1.reg),
                         opnd_create_reg(reg_mod)));
    PRE(bb, inst,
        INSTR_CREATE_jcc(drcontext, OP_jb_short, opnd_create_instr(retaddr)));
    /* The exact sequence after this potentially-faulting store is assumed
     * in handle_zeroing_fault()
     */
    PREXL8M(bb, inst,
            INSTR_XL8(INSTR_CREATE_mov_st(drcontext, OPND_CREATE_MEM32(mi->reg1.reg, 0),
                                          OPND_CREATE_INT32(0)),
                      instr_get_app_pc(inst)));
    PRE(bb, inst,
        INSTR_CREATE_jmp_short(drcontext, opnd_create_instr(loop_repeat)));
    PRE(bb, inst, retaddr);
    if (eflags_live)
        insert_restore_aflags(drcontext, bb, inst, &mi->eax, mi->aflags);
}

/* Instrument an esp modification that is not also a read or write
 * Returns whether instrumented
 */
static bool
instrument_esp_adjust_fastpath(void *drcontext, instrlist_t *bb, instr_t *inst,
                               bb_info_t *bi, sp_adjust_action_t sp_action)
{
    /* implicit esp changes (e.g., push and pop) are handled during
     * the read/write: this is for explicit esp changes
     */
    int opc = instr_get_opcode(inst);
    opnd_t arg;
    instr_t *retaddr;
    fastpath_info_t mi;
    bool negate = false;
    bool eflags_live;
    esp_adjust_t type = get_esp_adjust_type(opc);
    reg_id_t reg_mod;
    instr_t *skip;

    if (!needs_esp_adjust(inst, sp_action))
        return false;

    arg = instr_get_src(inst, 0); /* 1st src for nearly all cases */

    if (opc == OP_ret) {
        ASSERT(opnd_is_immed_int(arg), "internal error");
        /* else should have returned up above */
    } else if (opc == OP_inc) {
        arg = OPND_CREATE_INT32(1);
    } else if (opc == OP_dec) {
        arg = OPND_CREATE_INT32(-1);
    } else if (opc == OP_add) {
        /* all set */
    } else if (opc == OP_sub) {
        negate = true;
    } else if (opc == OP_enter) {
        negate = true;
    } else if (opc == OP_mov_st || opc == OP_mov_ld ||
               opc == OP_leave || opc == OP_lea ||
               opc_is_cmovcc(opc)) {
        /* absolute */
    } else if (opc == OP_xchg) {
        if (opnd_is_reg(arg) && opnd_uses_reg(arg, DR_REG_XSP))
            arg = instr_get_src(inst, 1);
    } else if (opc == OP_and && opnd_is_immed_int(arg)) {
        /* absolute */
    } else {
        return instrument_esp_adjust_slowpath(drcontext, bb, inst, bi, sp_action);
    }

    memset(&mi, 0, sizeof(mi));
    mi.bb = bi;

    skip = INSTR_CREATE_label(drcontext);
    if (opc_is_cmovcc(opc))
        instrument_esp_cmovcc_adjust(drcontext, bb, inst, skip, bi);

    /* set up regs and spill info */
    if (sp_action == SP_ADJUST_ACTION_ZERO) {
        pick_scratch_regs(inst, &mi, false/*anything*/, false/*2 args only*/,
                          false/*3rd must be ecx*/, arg, opnd_create_null());
        reg_mod = mi.reg2.reg;
        mark_scratch_reg_used(drcontext, bb, bi, &mi.reg2);
        insert_spill_or_restore(drcontext, bb, inst, &mi.reg2, true/*save*/, false);
    } else {
        /* we can't have ecx using SPILL_SLOT_EFLAGS_EAX since shared fastpath
         * will use it, so we communicate that via mi.eax.
         * for whole_bb_spills_enabled() we also have to rule out eax, since
         * shared fastpath assumes edx, ebx, and ecx are the scratch regs.
         * FIXME: opt: we should we xchg w/ whole-bb like we do for esp slowpath:
         * then allow eax and xchg w/ it.  Must be careful about spill
         * ordering w/ arg retrieval if arg uses regs.
         */
        mi.eax.used = true;
        mi.eax.dead = false;
        pick_scratch_regs(inst, &mi, true/*must be abcd*/, true/*need 3rd reg*/,
                          true/*3rd must be ecx*/, arg,
                          opnd_create_reg(DR_REG_XAX)/*no eax*/);
        reg_mod = mi.reg3.reg;
        ASSERT(mi.reg3.reg == DR_REG_XCX, "shared_esp_fastpath reg error");
        ASSERT((mi.reg2.reg == DR_REG_XBX && mi.reg1.reg == DR_REG_XDX) ||
               (mi.reg2.reg == DR_REG_XDX && mi.reg1.reg == DR_REG_XBX),
               "shared_esp_fastpath reg error");
        mark_scratch_reg_used(drcontext, bb, bi, &mi.reg3);
        insert_spill_or_restore(drcontext, bb, inst, &mi.reg3, true/*save*/, false);
        if (whole_bb_spills_enabled())
            mark_eflags_used(drcontext, bb, bi);
    }
    eflags_live = (!whole_bb_spills_enabled() && mi.aflags != EFLAGS_WRITE_6);
    if (sp_action != SP_ADJUST_ACTION_ZERO) {
        ASSERT(!eflags_live || mi.reg3.slot != SPILL_SLOT_EFLAGS_EAX,
               "shared_esp_fastpath slot error");
    }
    /* for whole-bb we can't use the SPILL_SLOT_EFLAGS_EAX */
    ASSERT(!whole_bb_spills_enabled() || !eflags_live, "eflags spill conflict");

    retaddr = INSTR_CREATE_label(drcontext);

    if (whole_bb_spills_enabled() && !opnd_is_immed_int(arg)) {
        /* restore from spill slot so we read app values for arg */
        if (opnd_uses_reg(arg, bi->reg1.reg)) {
            insert_spill_global(drcontext, bb, inst, &bi->reg1, false/*restore*/);
        } else if (opnd_uses_reg(arg, bi->reg2.reg)) {
            insert_spill_global(drcontext, bb, inst, &bi->reg2, false/*restore*/);
        }
    }

    mark_scratch_reg_used(drcontext, bb, bi, &mi.reg1);
    if (sp_action != SP_ADJUST_ACTION_ZERO)
        mark_scratch_reg_used(drcontext, bb, bi, &mi.reg2);

    /* get arg first in case it uses another reg we're going to clobber */
    if (opc == OP_lea) {
        PRE(bb, inst, INSTR_CREATE_lea(drcontext, opnd_create_reg(reg_mod), arg));
        ASSERT(!negate, "esp adjust OP_lea error");
        ASSERT(type == ESP_ADJUST_ABSOLUTE, "esp adjust OP_lea error");
    } else if (opc == OP_and) {
        PRE(bb, inst, INSTR_CREATE_mov_ld(drcontext, opnd_create_reg(reg_mod),
                                          opnd_create_reg(REG_XSP)));
        /* app is about to execute and, so flags are dead */
        PRE(bb, inst, INSTR_CREATE_and(drcontext, opnd_create_reg(reg_mod), arg));
    } else if (opnd_is_immed_int(arg)) {
        if (negate) {
            /* PR 416446: can't use opnd_get_size(arg) since max negative is
             * too big for max positive.  We're enlarging to OPSZ_4 later anyway.
             */
            arg = opnd_create_immed_int(-opnd_get_immed_int(arg), OPSZ_4);
        }
        /* OP_ret has OPSZ_2 immed, and OP_add, etc. often have OPSZ_1 */
        opnd_set_size(&arg, OPSZ_4);
        PRE(bb, inst, INSTR_CREATE_mov_imm(drcontext, opnd_create_reg(reg_mod), arg));
    } else {
        PRE(bb, inst, INSTR_CREATE_mov_ld(drcontext, opnd_create_reg(reg_mod), arg));
        if (negate)
            PRE(bb, inst, INSTR_CREATE_neg(drcontext, opnd_create_reg(reg_mod)));
    }

    insert_spill_or_restore(drcontext, bb, inst, &mi.reg1, true/*save*/, false);
    if (sp_action == SP_ADJUST_ACTION_ZERO) {
        insert_zeroing_loop(drcontext, bb, inst, bi, &mi, reg_mod, type,
                            retaddr, eflags_live);
    } else {
        /* should we trade speed for space and move this spill/restore into
         * shared_fastpath? then need to nail down which of reg2 vs reg1 is which.
         */
        insert_spill_or_restore(drcontext, bb, inst, &mi.reg2, true/*save*/, false);

        PRE(bb, inst,
            INSTR_CREATE_mov_imm(drcontext, opnd_create_reg(DR_REG_XDX),
                                 opnd_create_instr(retaddr)));
        ASSERT(type >= ESP_ADJUST_FAST_FIRST &&
               type <= ESP_ADJUST_FAST_LAST, "invalid type for esp fastpath");
        ASSERT(sp_action <= SP_ADJUST_ACTION_FASTPATH_MAX, "sp_action OOB");
        PRE(bb, inst,
            INSTR_CREATE_jmp(drcontext,
                             opnd_create_pc(shared_esp_fastpath
                                            [sp_action]
                                            /* don't trust true always being 1 */
                                            [eflags_live ? 1 : 0]
                                            [type])));
        PRE(bb, inst, retaddr);
    }

    insert_spill_or_restore(drcontext, bb, inst, &mi.reg3, false/*restore*/, false);
    insert_spill_or_restore(drcontext, bb, inst, &mi.reg2, false/*restore*/, false);
    insert_spill_or_restore(drcontext, bb, inst, &mi.reg1, false/*restore*/, false);
    PRE(bb, inst, skip);
    return true;
}

/* Note that handle_special_shadow_fault() makes assumptions about the exact
 * instr sequence here so it can find the slowpath entry point
 */
static void
generate_shared_esp_fastpath_helper(void *drcontext, instrlist_t *bb,
                                    bool eflags_live,
                                    sp_adjust_action_t sp_action,
                                    esp_adjust_t type)
{
    fastpath_info_t mi;
    instr_t *loop_push, *loop_done, *restore;
    instr_t *loop_next_shadow, *loop_shadow_lookup, *shadow_lookup;
    instr_t *pop_one_block, *push_one_block;
    instr_t *push_unaligned, *push_aligned, *push_one_done;
    instr_t *pop_unaligned, *pop_aligned, *pop_one_done;

    instr_t *pop_aligned_loop = INSTR_CREATE_label(drcontext);
    instr_t *pop_aligned_done = INSTR_CREATE_label(drcontext);
    instr_t *pop_unaligned_loop = INSTR_CREATE_label(drcontext);
    instr_t *pop_unaligned_done = INSTR_CREATE_label(drcontext);
    instr_t *push_aligned_loop = INSTR_CREATE_label(drcontext);
    instr_t *push_aligned_done = INSTR_CREATE_label(drcontext);
    instr_t *push_unaligned_loop = INSTR_CREATE_label(drcontext);
    instr_t *push_unaligned_done = INSTR_CREATE_label(drcontext);

    /* i#412: For some modules (rsaenh.dll) we mark new stack memory as defined.
     */
    uint shadow_dword_newmem = (sp_action == SP_ADJUST_ACTION_DEFINED ?
                                SHADOW_DWORD_DEFINED : SHADOW_DWORD_UNDEFINED);
    uint shadow_dqword_newmem = (sp_action == SP_ADJUST_ACTION_DEFINED ?
                                 SHADOW_DQWORD_DEFINED : SHADOW_DQWORD_UNDEFINED);

    push_unaligned = INSTR_CREATE_label(drcontext);
    push_aligned = INSTR_CREATE_label(drcontext);
    push_one_done = INSTR_CREATE_label(drcontext);
    pop_unaligned = INSTR_CREATE_label(drcontext);
    pop_aligned = INSTR_CREATE_label(drcontext);
    pop_one_done = INSTR_CREATE_label(drcontext);
    loop_push = INSTR_CREATE_label(drcontext);
    loop_done = INSTR_CREATE_label(drcontext);
    loop_next_shadow = INSTR_CREATE_label(drcontext);
    loop_shadow_lookup = INSTR_CREATE_label(drcontext);
    shadow_lookup = INSTR_CREATE_label(drcontext);
    restore = INSTR_CREATE_label(drcontext);
    pop_one_block = INSTR_CREATE_label(drcontext);
    push_one_block = INSTR_CREATE_label(drcontext);

    memset(&mi, 0, sizeof(mi));
    mi.slowpath = INSTR_CREATE_label(drcontext);
    /* we do not optimize for OF */
    mi.aflags = (!eflags_live ? 0 : EFLAGS_WRITE_6);
    mi.eax.reg = DR_REG_XAX;
    mi.eax.used = true;
    mi.eax.dead = false;
    mi.eax.xchg = REG_NULL;
    /* for whole-bb we shouldn't end up using this spill slot */
    mi.eax.slot = SPILL_SLOT_EFLAGS_EAX;
    mi.reg1.reg = DR_REG_XDX;
    mi.reg2.reg = DR_REG_XBX;
    mi.reg3.reg = DR_REG_XCX;
    mi.memsz = 4;

    /* save the 2 args for retrieval at end */
    PRE(bb, NULL,
        INSTR_CREATE_mov_st
        (drcontext, spill_slot_opnd(drcontext, esp_spill_slot_base(true/*shadow*/)+1),
         opnd_create_reg(DR_REG_XCX))); /* holds delta or abs val */
    PRE(bb, NULL,
        INSTR_CREATE_mov_st
        (drcontext, spill_slot_opnd(drcontext, esp_spill_slot_base(true/*shadow*/)),
         opnd_create_reg(DR_REG_XDX))); /* holds retaddr */

    if (eflags_live)
        insert_save_aflags(drcontext, bb, NULL, &mi.eax, mi.aflags);
    /* spilling eax is a relic from when I had rep_stos here, but it
     * works well as a 3rd scratch reg so I'm leaving it: before I had
     * to do some local spills below anyway so same amount of mem traffic
     */
    PRE(bb, NULL, INSTR_CREATE_mov_st
        (drcontext, spill_slot_opnd(drcontext, esp_spill_slot_base(true/*shadow*/)+2),
         opnd_create_reg(DR_REG_XAX)));

    /* the initial address to look up in the shadow table is cur esp */
    PRE(bb, NULL,
        INSTR_CREATE_mov_ld(drcontext, opnd_create_reg(mi.reg1.reg),
                            opnd_create_reg(DR_REG_XSP)));
    if (type == ESP_ADJUST_RET_IMMED) {
        /* pop of retaddr happens first (handled in definedness routines) */
        PRE(bb, NULL,
            INSTR_CREATE_add(drcontext, opnd_create_reg(mi.reg1.reg),
                             OPND_CREATE_INT8(4)));
    }

    /* for absolute, calculate the delta */
    if (type == ESP_ADJUST_ABSOLUTE || type == ESP_ADJUST_AND/*abs passed to us*/) {
        PRE(bb, NULL,
            INSTR_CREATE_sub(drcontext, opnd_create_reg(mi.reg3.reg),
                             opnd_create_reg(mi.reg1.reg)));
        /* Treat as a stack swap if a large change.
         * We assume a swap would not happen w/ a relative adjustment.
         */
        PRE(bb, NULL,
            INSTR_CREATE_cmp(drcontext, opnd_create_reg(mi.reg3.reg),
                             OPND_CREATE_INT32(options.stack_swap_threshold)));
        /* We need to verify whether it's a real swap */
        add_jcc_slowpath(drcontext, bb, NULL, OP_jg/*short doesn't reach*/, &mi);
        PRE(bb, NULL,
            INSTR_CREATE_cmp(drcontext, opnd_create_reg(mi.reg3.reg),
                             OPND_CREATE_INT32(-options.stack_swap_threshold)));
        /* We need to verify whether it's a real swap */
        add_jcc_slowpath(drcontext, bb, NULL, OP_jl/*short doesn't reach*/, &mi);
    }

    /* Ensure the size is 4-aligned so our loop works out */
    PRE(bb, NULL,
        INSTR_CREATE_test(drcontext, opnd_create_reg(mi.reg3.reg),
                          OPND_CREATE_INT32(0x3)));
    add_jcc_slowpath(drcontext, bb, NULL, OP_jnz/*short doesn't reach*/, &mi);
    /* div by 4 */
    PRE(bb, NULL, INSTR_CREATE_sar(drcontext, opnd_create_reg(mi.reg3.reg),
                                   OPND_CREATE_INT8(2)));

    PRE(bb, NULL, loop_shadow_lookup);
    /* To support crossing 64K blocks we must decrement xsp prior to translating
     * instead of decrementing the translation
     */
    PRE(bb, NULL,
        INSTR_CREATE_cmp(drcontext, opnd_create_reg(mi.reg3.reg), OPND_CREATE_INT32(0)));
    PRE(bb, NULL,
        INSTR_CREATE_jcc(drcontext, OP_jg_short, opnd_create_instr(shadow_lookup)));
    PRE(bb, NULL,
        INSTR_CREATE_jcc(drcontext, OP_je, opnd_create_instr(loop_done)));
    PRE(bb, NULL,
        INSTR_CREATE_sub(drcontext, opnd_create_reg(mi.reg1.reg), OPND_CREATE_INT8(4)));
    PRE(bb, NULL, shadow_lookup);
    /* for looping back through the xl8 addr is not DR_REG_XSP so we cannot recover
     * it and must preserve across the table lookup in eax
     */
    PRE(bb, NULL,
        INSTR_CREATE_mov_st(drcontext, opnd_create_reg(REG_XAX),
                            opnd_create_reg(mi.reg1.reg)));
    /* we don't need a 3rd scratch for the lookup, and we rely on reg3 being preserved */
    add_shadow_table_lookup(drcontext, bb, NULL, &mi, false/*need addr*/,
                            false, false/*bail if not aligned*/, false,
                            mi.reg1.reg, mi.reg2.reg, REG_NULL, true/*check alignment*/);

    /* now addr of shadow byte is in reg1.
     * we want offs within shadow block in reg2: but storing displacement
     * in shadow table (PR 553724) means add_shadow_table_lookup no longer computes
     * the offs so we must compute it ourselves.
     */
    PRE(bb, NULL,
        INSTR_CREATE_mov_st(drcontext, opnd_create_reg(mi.reg2.reg),
                            opnd_create_reg(REG_XAX)));
    /* FIXME: if we aligned shadow blocks to 16K we could simplify this block-end calc */
    /* compute offs within shadow block */
    PRE(bb, NULL,
        INSTR_CREATE_movzx(drcontext, opnd_create_reg(mi.reg2.reg),
                           opnd_create_reg(reg_ptrsz_to_16(mi.reg2.reg))));
    PRE(bb, NULL,
        INSTR_CREATE_shr(drcontext, opnd_create_reg(mi.reg2.reg), OPND_CREATE_INT8(2)));
    /* calculate start of shadow block */
    PRE(bb, NULL, INSTR_CREATE_neg(drcontext, opnd_create_reg(mi.reg2.reg)));
    PRE(bb, NULL, INSTR_CREATE_add(drcontext, opnd_create_reg(mi.reg2.reg),
                                   opnd_create_reg(mi.reg1.reg)));

    /* we need separate loops for inc vs dec */
    PRE(bb, NULL,
        INSTR_CREATE_cmp(drcontext, opnd_create_reg(mi.reg3.reg), OPND_CREATE_INT32(0)));
    PRE(bb, NULL,
        INSTR_CREATE_jcc(drcontext, OP_jl, opnd_create_instr(loop_push)));
    /* we tested equality above */

    /* reg1 has address of shadow table for cur esp, and address is aligned to 4.
     * now compute the new esp, and then mark in between as unaddressable/undefined.
     * one shadow byte == 4 stack bytes at a time.
     * verify still within same 64K-covering shadow block, else bail.
     */

    /******* increasing loop *******/
    /* Note that I implemented a rep_stos version for PR 582200, with
     * a sophisticated DF preservation scheme that avoided any
     * pushf+popf by tracking the app's DF and the current DF in TLS
     * and using cld/std here if necessary, with lazy DF restoration
     * on an app DF read, but still it was more costly than a mov_st
     * loop on every benchmark except mesa, causing as much as a 25%
     * slowdown.  mov_st is about 12% slower on mesa, but we live with
     * it since it's faster on everything else.
     */
    /* calculate end of shadow block: reg2 holds start currently */
    PRE(bb, NULL, INSTR_CREATE_add(drcontext, opnd_create_reg(mi.reg2.reg),
                                   OPND_CREATE_INT32(get_shadow_block_size())));
    /* loop for increasing stack addresses = pop */
    /* FIXME: would it be more efficient to compute by aligning the app addr
     * to 64K and dividing by 4 to get iters?
     */
    /* calculate iters until hit end of shadow block in reg2 */
    PRE(bb, NULL,
        INSTR_CREATE_sub(drcontext, opnd_create_reg(mi.reg2.reg),
                         opnd_create_reg(mi.reg1.reg)));
    PRE(bb, NULL,
        INSTR_CREATE_cmp(drcontext, opnd_create_reg(mi.reg2.reg),
                          opnd_create_reg(mi.reg3.reg)));
    PRE(bb, NULL,
        INSTR_CREATE_jcc(drcontext, OP_jae_short, opnd_create_instr(pop_one_block)));
    /* reaches beyond shadow block: put remaining iters in reg2 */
    PRE(bb, NULL,
        INSTR_CREATE_sub(drcontext, opnd_create_reg(mi.reg3.reg),
                         opnd_create_reg(mi.reg2.reg)));
    PRE(bb, NULL,
        INSTR_CREATE_xchg(drcontext, opnd_create_reg(mi.reg3.reg),
                          opnd_create_reg(mi.reg2.reg)));
    PRE(bb, NULL, INSTR_CREATE_jmp_short(drcontext, opnd_create_instr(pop_unaligned)));
    PRE(bb, NULL, pop_one_block);
    /* within this shadow block: zero remaining iters in reg2 */
    PRE(bb, NULL,
        INSTR_CREATE_xor(drcontext, opnd_create_reg(mi.reg2.reg),
                         opnd_create_reg(mi.reg2.reg)));

    /* first loop until edi is aligned */
    PRE(bb, NULL, pop_unaligned);
    PRE(bb, NULL,
        INSTR_CREATE_test(drcontext, opnd_create_reg(mi.reg3.reg),
                          opnd_create_reg(mi.reg3.reg)));
    PRE(bb, NULL,
        INSTR_CREATE_jcc(drcontext, OP_jz_short, opnd_create_instr(pop_one_done)));
    PRE(bb, NULL,
        INSTR_CREATE_test(drcontext, opnd_create_reg(mi.reg1.reg),
                          OPND_CREATE_INT32(0x3)));
    PRE(bb, NULL,
        INSTR_CREATE_jcc(drcontext, OP_jz_short, opnd_create_instr(pop_aligned)));
    PRE(bb, NULL,
        INSTR_CREATE_mov_st(drcontext, OPND_CREATE_MEM8(mi.reg1.reg, 0),
                            OPND_CREATE_INT8((char)SHADOW_DWORD_UNADDRESSABLE)));
    PRE(bb, NULL,
        INSTR_CREATE_dec(drcontext, opnd_create_reg(mi.reg3.reg)));
    PRE(bb, NULL,
        INSTR_CREATE_inc(drcontext, opnd_create_reg(mi.reg1.reg)));
    PRE(bb, NULL,
        INSTR_CREATE_jmp_short(drcontext, opnd_create_instr(pop_unaligned)));

    /* now do aligned portion: save count away and div by 4 */
    PRE(bb, NULL, pop_aligned);

    /* Save our count so we can finish off any unaligned iters after our dword loop */
    PRE(bb, NULL,
        INSTR_CREATE_mov_st(drcontext, opnd_create_reg(REG_XAX),
                            opnd_create_reg(mi.reg3.reg)));

    PRE(bb, NULL,
        INSTR_CREATE_shr(drcontext, opnd_create_reg(mi.reg3.reg),
                         OPND_CREATE_INT8(2)));
    PRE(bb, NULL, pop_aligned_loop);
    PRE(bb, NULL,
        INSTR_CREATE_test(drcontext, opnd_create_reg(mi.reg3.reg),
                          opnd_create_reg(mi.reg3.reg)));
    PRE(bb, NULL,
        INSTR_CREATE_jcc(drcontext, OP_jz_short, opnd_create_instr(pop_aligned_done)));
    PRE(bb, NULL,
        INSTR_CREATE_mov_st(drcontext, OPND_CREATE_MEM32(mi.reg1.reg, 0),
                            OPND_CREATE_INT32(SHADOW_DQWORD_UNADDRESSABLE)));
    PRE(bb, NULL,
        INSTR_CREATE_dec(drcontext, opnd_create_reg(mi.reg3.reg)));
    PRE(bb, NULL,
        INSTR_CREATE_add(drcontext, opnd_create_reg(mi.reg1.reg), OPND_CREATE_INT32(4)));
    PRE(bb, NULL,
        INSTR_CREATE_jmp_short(drcontext, opnd_create_instr(pop_aligned_loop)));
    PRE(bb, NULL, pop_aligned_done);

    /* now finish off any unaligned iters */
    PRE(bb, NULL,
        INSTR_CREATE_mov_st(drcontext, opnd_create_reg(mi.reg3.reg),
                            opnd_create_reg(REG_XAX)));
    PRE(bb, NULL,
        INSTR_CREATE_and(drcontext, opnd_create_reg(mi.reg3.reg),
                         OPND_CREATE_INT32(0x00000003)));
    PRE(bb, NULL, pop_unaligned_loop);
    PRE(bb, NULL,
        INSTR_CREATE_test(drcontext, opnd_create_reg(mi.reg3.reg),
                          opnd_create_reg(mi.reg3.reg)));
    PRE(bb, NULL,
        INSTR_CREATE_jcc(drcontext, OP_jz_short, opnd_create_instr(pop_unaligned_done)));
    PRE(bb, NULL,
        INSTR_CREATE_mov_st(drcontext, OPND_CREATE_MEM8(mi.reg1.reg, 0),
                            OPND_CREATE_INT8((char)SHADOW_DWORD_UNADDRESSABLE)));
    PRE(bb, NULL,
        INSTR_CREATE_dec(drcontext, opnd_create_reg(mi.reg3.reg)));
    PRE(bb, NULL,
        INSTR_CREATE_inc(drcontext, opnd_create_reg(mi.reg1.reg)));
    PRE(bb, NULL,
        INSTR_CREATE_jmp_short(drcontext, opnd_create_instr(pop_unaligned_loop)));
    PRE(bb, NULL, pop_unaligned_done);

    PRE(bb, NULL, pop_one_done);

    PRE(bb, NULL,
        INSTR_CREATE_test(drcontext, opnd_create_reg(mi.reg2.reg),
                          opnd_create_reg(mi.reg2.reg)));
    PRE(bb, NULL,
        INSTR_CREATE_jcc(drcontext, OP_je, opnd_create_instr(loop_done)));
    PRE(bb, NULL,
        INSTR_CREATE_mov_st(drcontext, opnd_create_reg(mi.reg3.reg),
                            opnd_create_reg(mi.reg2.reg)));
    PRE(bb, NULL, INSTR_CREATE_jmp_short(drcontext, opnd_create_instr(loop_next_shadow)));


    /******* shadow block boundary handler, shared by both loops *******/
    PRE(bb, NULL, loop_next_shadow);
    /* PR 503778: handle moving off the end of this shadow block
     * hit end => loop back to shadow lookup (size still aligned).  first:
     * - put esp in reg1 and then add (stored count - remaining count), w/o
     *   touching reg3 which will still hold remaining count
     * Note that if new shadow lookup fails we'll re-do the already-completed
     * loop iters in the slowpath.
     */
    /* the initial address to look up in the shadow table is cur esp */
    PRE(bb, NULL,
        INSTR_CREATE_mov_ld(drcontext, opnd_create_reg(mi.reg1.reg),
                            opnd_create_reg(DR_REG_XSP)));
    if (type == ESP_ADJUST_RET_IMMED) {
        /* pop of retaddr happens first (handled in definedness routines) */
        PRE(bb, NULL,
            INSTR_CREATE_add(drcontext, opnd_create_reg(mi.reg1.reg),
                             OPND_CREATE_INT8(4)));
    }
    if (type == ESP_ADJUST_ABSOLUTE) {
        /* TLS slot holds abs esp so re-compute orig delta */
        PRE(bb, NULL,
            INSTR_CREATE_mov_ld
            (drcontext, opnd_create_reg(mi.reg2.reg),
             spill_slot_opnd(drcontext, esp_spill_slot_base(true/*shadow*/)+1)));
        PRE(bb, NULL,
            INSTR_CREATE_sub(drcontext, opnd_create_reg(mi.reg2.reg),
                             opnd_create_reg(mi.reg1.reg)));
        PRE(bb, NULL,
            INSTR_CREATE_add
            (drcontext, opnd_create_reg(mi.reg1.reg), opnd_create_reg(mi.reg2.reg)));
    } else {
        PRE(bb, NULL,
            INSTR_CREATE_add
            (drcontext, opnd_create_reg(mi.reg1.reg),
             spill_slot_opnd(drcontext, esp_spill_slot_base(true/*shadow*/)+1)));
    }
    PRE(bb, NULL, INSTR_CREATE_shl(drcontext, opnd_create_reg(mi.reg3.reg),
                                   OPND_CREATE_INT8(2)));
    PRE(bb, NULL,
        INSTR_CREATE_sub(drcontext, opnd_create_reg(mi.reg1.reg),
                         opnd_create_reg(mi.reg3.reg)));
    PRE(bb, NULL, INSTR_CREATE_sar(drcontext, opnd_create_reg(mi.reg3.reg),
                                   OPND_CREATE_INT8(2)));
    PRE(bb, NULL, INSTR_CREATE_jmp(drcontext,
                                   opnd_create_instr(loop_shadow_lookup)));

    /******* decreasing loop *******/
    PRE(bb, NULL, loop_push);
    /* start of shadow block is in reg2, shadow addr is in reg1, count is in reg3 */
    /* loop for decreasing stack addresses = push */
    /* calculate iters until hit start of shadow block in reg2 */
    /* must dec since our loop decs after and we already -4 xsp */
    PRE(bb, NULL,
        INSTR_CREATE_dec(drcontext, opnd_create_reg(mi.reg2.reg)));
    PRE(bb, NULL,
        INSTR_CREATE_sub(drcontext, opnd_create_reg(mi.reg2.reg),
                         opnd_create_reg(mi.reg1.reg)));
    PRE(bb, NULL,
        INSTR_CREATE_cmp(drcontext, opnd_create_reg(mi.reg2.reg),
                          opnd_create_reg(mi.reg3.reg)));
    PRE(bb, NULL,
        INSTR_CREATE_jcc(drcontext, OP_jbe_short, opnd_create_instr(push_one_block)));
    /* reaches beyond shadow block: put remaining iters in reg2 */
    PRE(bb, NULL,
        INSTR_CREATE_sub(drcontext, opnd_create_reg(mi.reg3.reg),
                         opnd_create_reg(mi.reg2.reg)));
    PRE(bb, NULL,
        INSTR_CREATE_xchg(drcontext, opnd_create_reg(mi.reg3.reg),
                          opnd_create_reg(mi.reg2.reg)));
    PRE(bb, NULL, INSTR_CREATE_jmp_short(drcontext, opnd_create_instr(push_unaligned)));
    PRE(bb, NULL, push_one_block);
    /* within this shadow block: zero remaining iters in reg2 */
    PRE(bb, NULL,
        INSTR_CREATE_xor(drcontext, opnd_create_reg(mi.reg2.reg),
                         opnd_create_reg(mi.reg2.reg)));

    /* first loop until edi is aligned */
    PRE(bb, NULL, push_unaligned);
    PRE(bb, NULL,
        INSTR_CREATE_test(drcontext, opnd_create_reg(mi.reg3.reg),
                          opnd_create_reg(mi.reg3.reg)));
    PRE(bb, NULL,
        INSTR_CREATE_jcc(drcontext, OP_jz_short, opnd_create_instr(push_one_done)));
    /* much easier to detect aligned, so we have an extra iter on a match to
     * get back far enough for a 4-byte forward write
     */
    PRE(bb, NULL,
        INSTR_CREATE_test(drcontext, opnd_create_reg(mi.reg1.reg),
                          OPND_CREATE_INT32(0x3)));
    PRE(bb, NULL,
        INSTR_CREATE_jcc(drcontext, OP_jz_short, opnd_create_instr(push_aligned)));
    PRE(bb, NULL,
        INSTR_CREATE_mov_st(drcontext, OPND_CREATE_MEM8(mi.reg1.reg, 0),
                            OPND_CREATE_INT8((char)shadow_dword_newmem)));
    PRE(bb, NULL,
        INSTR_CREATE_inc(drcontext, opnd_create_reg(mi.reg3.reg)));
    PRE(bb, NULL,
        INSTR_CREATE_dec(drcontext, opnd_create_reg(mi.reg1.reg)));
    PRE(bb, NULL,
        INSTR_CREATE_jmp_short(drcontext, opnd_create_instr(push_unaligned)));
    /* now do aligned portion: save count away and div by 4.
     * since mov_st writes forward we do one more and then subtract.
     */
    PRE(bb, NULL, push_aligned);
    PRE(bb, NULL,
        INSTR_CREATE_mov_st(drcontext, OPND_CREATE_MEM8(mi.reg1.reg, 0),
                            OPND_CREATE_INT8((char)shadow_dword_newmem)));
    PRE(bb, NULL,
        INSTR_CREATE_inc(drcontext, opnd_create_reg(mi.reg3.reg)));
    PRE(bb, NULL,
        INSTR_CREATE_sub(drcontext, opnd_create_reg(mi.reg1.reg), OPND_CREATE_INT8(4)));

    /* We can't overshoot so sar is not sufficient (e.g., -17 >> 2 == -5,
     * and we want -4).  We could add 3 and then sar, but simpler to neg
     * + sar/shr and count down.
     */
    PRE(bb, NULL,
        INSTR_CREATE_neg(drcontext, opnd_create_reg(mi.reg3.reg)));
    /* Save the count for the unaligned iters after: simpler to save as positive */
    PRE(bb, NULL,
        INSTR_CREATE_mov_st(drcontext, opnd_create_reg(REG_XAX),
                            opnd_create_reg(mi.reg3.reg)));
    PRE(bb, NULL,
        INSTR_CREATE_sar(drcontext, opnd_create_reg(mi.reg3.reg),
                         OPND_CREATE_INT8(2)));
    PRE(bb, NULL, push_aligned_loop);
    PRE(bb, NULL,
        INSTR_CREATE_test(drcontext, opnd_create_reg(mi.reg3.reg),
                          opnd_create_reg(mi.reg3.reg)));
    PRE(bb, NULL,
        INSTR_CREATE_jcc(drcontext, OP_jz_short, opnd_create_instr(push_aligned_done)));
    /* I measured cmp-and-store-if-no-match on speck2k gcc and it was
     * marginally slower so doing a blind store.  usually these stack adjusts
     * are writing new shadow values.
     */
    PRE(bb, NULL,
        INSTR_CREATE_mov_st(drcontext, OPND_CREATE_MEM32(mi.reg1.reg, 0),
                            OPND_CREATE_INT32(shadow_dqword_newmem)));
    PRE(bb, NULL,
        INSTR_CREATE_dec(drcontext, opnd_create_reg(mi.reg3.reg)));
    PRE(bb, NULL,
        INSTR_CREATE_sub(drcontext, opnd_create_reg(mi.reg1.reg), OPND_CREATE_INT32(4)));
    PRE(bb, NULL,
        INSTR_CREATE_jmp_short(drcontext, opnd_create_instr(push_aligned_loop)));
    PRE(bb, NULL, push_aligned_done);

    /* now finish off any unaligned iters. count is still positive. */
    PRE(bb, NULL,
        INSTR_CREATE_add(drcontext, opnd_create_reg(mi.reg1.reg), OPND_CREATE_INT8(3)));
    PRE(bb, NULL,
        INSTR_CREATE_mov_st(drcontext, opnd_create_reg(mi.reg3.reg),
                            opnd_create_reg(REG_XAX)));
    PRE(bb, NULL,
        INSTR_CREATE_and(drcontext, opnd_create_reg(mi.reg3.reg),
                         OPND_CREATE_INT32(0x00000003)));
    PRE(bb, NULL, push_unaligned_loop);
    PRE(bb, NULL,
        INSTR_CREATE_test(drcontext, opnd_create_reg(mi.reg3.reg),
                          opnd_create_reg(mi.reg3.reg)));
    PRE(bb, NULL,
        INSTR_CREATE_jcc(drcontext, OP_jz_short, opnd_create_instr(push_unaligned_done)));
    PRE(bb, NULL,
        INSTR_CREATE_mov_st(drcontext, OPND_CREATE_MEM8(mi.reg1.reg, 0),
                            OPND_CREATE_INT8((char)shadow_dword_newmem)));
    PRE(bb, NULL,
        INSTR_CREATE_dec(drcontext, opnd_create_reg(mi.reg3.reg)));
    PRE(bb, NULL,
        INSTR_CREATE_dec(drcontext, opnd_create_reg(mi.reg1.reg)));
    PRE(bb, NULL,
        INSTR_CREATE_jmp_short(drcontext, opnd_create_instr(push_unaligned_loop)));
    PRE(bb, NULL, push_unaligned_done);

    PRE(bb, NULL, push_one_done);
    PRE(bb, NULL,
        INSTR_CREATE_test(drcontext, opnd_create_reg(mi.reg2.reg),
                          opnd_create_reg(mi.reg2.reg)));
    PRE(bb, NULL,
        INSTR_CREATE_jcc(drcontext, OP_jz_short, opnd_create_instr(loop_done)));
    PRE(bb, NULL,
        INSTR_CREATE_mov_st(drcontext, opnd_create_reg(mi.reg3.reg),
                            opnd_create_reg(mi.reg2.reg)));
    PRE(bb, NULL, INSTR_CREATE_jmp(drcontext, opnd_create_instr(loop_next_shadow)));

    PRE(bb, NULL, loop_done);
#ifdef STATISTICS
    if (options.statistics) {
        int disp;
        ASSERT_TRUNCATE(disp, int, (ptr_int_t)&adjust_esp_fastpath);
        disp = (int)(ptr_int_t)&adjust_esp_fastpath;
        PRE(bb, NULL,
            INSTR_CREATE_inc(drcontext, OPND_CREATE_MEM32(REG_NULL, disp)));
    }
#endif
    PRE(bb, NULL, INSTR_CREATE_jmp_short(drcontext, opnd_create_instr(restore)));

    PRE(bb, NULL, mi.slowpath);
    /* The exact code sequence here is pattern-matched in handle_special_shadow_fault()
     * so for simplicity we use a nop
     */
    PRE(bb, NULL, INSTR_CREATE_nop(drcontext));
    if (options.shared_slowpath) {
        /* note that handle_special_shadow_fault() assumes the first restore
         * from tls after a faulting store is the first instr of the slowpath
         */
        /* note that we aren't restoring regs saved at call site.
         * we only need app esp value in slowpath callee so it works out.
         * FIXME: are we ever crashing as app might, when referencing our val arg?
         * then need to go back to caller, restore, then to slowpath?
         */
        PRE(bb, NULL,
            INSTR_CREATE_mov_ld
            (drcontext, opnd_create_reg(DR_REG_XCX),
             spill_slot_opnd(drcontext, esp_spill_slot_base(true/*shadow*/)+1)));
        /* we use tailcall to avoid two indirect jumps, at cost of extra eflags
         * restore: shared_slowpath will ret to our caller
         */
        PRE(bb, NULL,
            INSTR_CREATE_mov_ld
            (drcontext, opnd_create_reg(DR_REG_XDX),
             spill_slot_opnd(drcontext, esp_spill_slot_base(true/*shadow*/))));
        if (type == ESP_ADJUST_NEGATIVE) {
            /* slowpath does its own negation */
            PRE(bb, NULL, INSTR_CREATE_neg(drcontext, opnd_create_reg(DR_REG_XCX)));
        }
        /* since not returning here, must restore flags */
        PRE(bb, NULL, INSTR_CREATE_mov_ld
            (drcontext, opnd_create_reg(DR_REG_XAX),
             spill_slot_opnd(drcontext, esp_spill_slot_base(true/*shadow*/)+2)));
        if (eflags_live)
            insert_restore_aflags(drcontext, bb, NULL, &mi.eax, mi.aflags);
        PRE(bb, NULL,
            INSTR_CREATE_jmp(drcontext, opnd_create_pc(shared_esp_slowpath_shadow)));
    } else {
        dr_insert_clean_call(drcontext, bb, NULL,
                             (void *) handle_esp_adjust_shared_slowpath,
                             false, 2,
                             spill_slot_opnd
                             (drcontext, esp_spill_slot_base(sp_action)+1),
                             OPND_CREATE_INT32(sp_action));
    }

    PRE(bb, NULL, restore);
    PRE(bb, NULL, INSTR_CREATE_mov_ld
        (drcontext, opnd_create_reg(DR_REG_XAX),
         spill_slot_opnd(drcontext, esp_spill_slot_base(true/*shadow*/)+2)));
    if (eflags_live)
        insert_restore_aflags(drcontext, bb, NULL, &mi.eax, mi.aflags);
    PRE(bb, NULL, INSTR_CREATE_jmp_ind
        (drcontext, spill_slot_opnd(drcontext, esp_spill_slot_base(true/*shadow*/))));
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

/* Caller has made the memory writable and holds a lock */
void
esp_fastpath_update_swap_threshold(void *drcontext, int new_threshold)
{
    int eflags_live;
    sp_adjust_action_t sp_action;
    byte *pc, *end_pc;
    instr_t inst;
    instr_init(drcontext, &inst);
    /* No shared_esp_fastpath for zeroing. */
    for (sp_action = 0; sp_action <= SP_ADJUST_ACTION_FASTPATH_MAX; sp_action++) {
        for (eflags_live = 0; eflags_live < 2; eflags_live++) {
            /* only ESP_ADJUST_ABSOLUTE checks for a stack swap: swaps aren't relative */
            int found = 0;
            pc = shared_esp_fastpath[sp_action][eflags_live][ESP_ADJUST_ABSOLUTE];
            ASSERT(ESP_ADJUST_ABSOLUTE < ESP_ADJUST_FAST_LAST,
                   "ESP_ADJUST_ABSOLUTE+1 will be OOB");
            end_pc = shared_esp_fastpath[sp_action][eflags_live][ESP_ADJUST_ABSOLUTE+1];
            LOG(3, "updating swap threshold in gencode "PFX"-"PFX"\n", pc, end_pc);
            do {
                pc = decode(drcontext, pc, &inst);
                if (instr_get_opcode(&inst) == OP_cmp &&
                    opnd_is_reg(instr_get_src(&inst, 0)) &&
                    opnd_is_immed_int(instr_get_src(&inst, 1))) {
                    ptr_int_t immed = opnd_get_immed_int(instr_get_src(&inst, 1));
                    LOG(3, "found cmp ending @"PFX" immed="PIFX"\n", pc, immed);
                    if (immed == options.stack_swap_threshold) {
                        /* could replace through IR and re-encode but want to
                         * check cache line
                         */
                        if (CROSSES_ALIGNMENT(pc-4, 4, proc_get_cache_line_size())) {
                            /* not that worried: not worth suspend-world */
                            LOG(1, "WARNING: updating gencode across cache line!\n");
                        }
                        /* immed is always last */
                        ASSERT(*(int*)(pc-4) == options.stack_swap_threshold,
                               "imm last?");
                        *(int*)(pc-4) = new_threshold;
                        found++;
                    } else if (immed == -options.stack_swap_threshold) {
                        if (CROSSES_ALIGNMENT(pc-4, 4, proc_get_cache_line_size())) {
                            /* not that worried: not worth suspend-world */
                            LOG(1, "WARNING: updating gencode across cache line!\n");
                        }
                        ASSERT(*(int*)(pc-4) == -options.stack_swap_threshold,
                               "imm last?");
                        *(int*)(pc-4) = -new_threshold;
                        found++;
                    }
                }
                instr_reset(drcontext, &inst);
                if (found >= 2)
                    break;
            } while (pc < end_pc);
            ASSERT(found == 2, "cannot find both threshold cmps in esp fastpath!");
        }
    }
    instr_free(drcontext, &inst);
}

/* Instrument an esp modification that is not also a read or write
 * Returns whether instrumented
 */
bool
instrument_esp_adjust(void *drcontext, instrlist_t *bb, instr_t *inst, bb_info_t *bi,
                      sp_adjust_action_t sp_action)
{
    if (options.esp_fastpath)
        return instrument_esp_adjust_fastpath(drcontext, bb, inst, bi, sp_action);
    else
        return instrument_esp_adjust_slowpath(drcontext, bb, inst, bi, sp_action);
}

