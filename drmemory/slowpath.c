/* **********************************************************
 * Copyright (c) 2010-2017 Google, Inc.  All rights reserved.
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
 * slowpath.c: Dr. Memory memory read/write slowpath handling
 */

#include "dr_api.h"
#include "drutil.h"
#include "drmemory.h"
#include "instru.h"
#include "slowpath.h"
#include "slowpath_arch.h"
#include "spill.h"
#include "fastpath.h"
#include "stack.h"
#include "alloc_drmem.h"
#include "heap.h"
#include "alloc.h"
#include "report.h"
#include "shadow.h"
#include "syscall.h"
#include "replace.h"
#include "perturb.h"
#include "annotations.h"
#ifdef TOOL_DR_HEAPSTAT
# include "../drheapstat/staleness.h"
#endif
#include "pattern.h"
#include <stddef.h>
#include "asm_utils.h"

#ifdef STATISTICS
/* per-opcode counts */
uint64 slowpath_count[OP_LAST+1];
/* per-opsz counts */
uint64 slowpath_sz1;
uint64 slowpath_sz2;
uint64 slowpath_sz4;
uint64 slowpath_sz8;
uint64 slowpath_sz10;
uint64 slowpath_sz16;
uint64 slowpath_szOther;

/* PR 423757: periodic stats dump */
uint next_stats_dump;

uint num_faults;
uint num_slowpath_faults;
#endif

#ifdef STATISTICS
uint slowpath_executions;
uint medpath_executions;
uint read_slowpath;
uint write_slowpath;
uint push_slowpath;
uint pop_slowpath;
uint read_fastpath;
uint write_fastpath;
uint push_fastpath;
uint pop_fastpath;
uint read4_fastpath;
uint write4_fastpath;
uint push4_fastpath;
uint pop4_fastpath;
uint slow_instead_of_fast;
uint heap_header_exception;
uint tls_exception;
uint alloca_exception;
uint strlen_exception;
uint strlen_uninit_exception;
uint strcpy_exception;
uint rawmemchr_exception;
uint strmem_unaddr_exception;
uint strrchr_exception;
uint andor_exception;
uint bitfield_const_exception;
uint bitfield_xor_exception;
uint loader_DRlib_exception;
uint cppexcept_DRlib_exception;
uint fldfst_exception;
uint heap_func_ref_ignored;
uint reg_dead;
uint reg_xchg;
uint reg_spill;
uint reg_spill_slow;
uint reg_spill_own;
uint reg_spill_used_in_bb;
uint reg_spill_unused_in_bb;
uint addressable_checks_elided;
uint aflags_saved_at_top;
uint xl8_shared;
uint xl8_not_shared_reg_conflict;
uint xl8_not_shared_scratch_conflict;
uint xl8_not_shared_disp_too_big;
uint xl8_not_shared_unaligned;
uint xl8_not_shared_mem2mem;
uint xl8_not_shared_offs;
uint xl8_not_shared_slowpaths;
uint xl8_shared_slowpath_instrs;
uint xl8_shared_slowpath_count;
uint slowpath_unaligned;
uint slowpath_8_at_border;
uint num_bbs;
#endif

/***************************************************************************
 * Registers
 */

/* To relocate restores to the common slowpath yet still support
 * site-specific scratch registers we have restore patterns for
 * every possible combination
 */
/* XXX i#1726: update for ARM */
/* variable-reg: reg1 and reg2 */
enum {
    SPILL_REG_NONE, /* !used and !dead */
    SPILL_REG_EAX,  /* this reg is spilled to tls */
    SPILL_REG_ECX,
    SPILL_REG_EDX,
    SPILL_REG_EBX,
    SPILL_REG_EAX_DEAD, /* this reg is dead */
    SPILL_REG_ECX_DEAD,
    SPILL_REG_EDX_DEAD,
    SPILL_REG_EBX_DEAD,
    SPILL_REG_NUM,
};
enum {
    SPILL_REG3_NOSPILL,
    SPILL_REG3_SPILL,
    SPILL_REG3_NUM,
};
enum {
    SPILL_EFLAGS_NOSPILL,
    SPILL_EFLAGS_5_NOEAX,
    SPILL_EFLAGS_6_NOEAX,
    SPILL_EFLAGS_5_EAX,
    SPILL_EFLAGS_6_EAX,
    SPILL_EFLAGS_NUM,
};
#define SPILL_REG3_REG   DR_REG_XCX

/* The 4 indices are: reg1, reg2, reg3, eflags */
byte *shared_slowpath_entry_local[SPILL_REG_NUM][SPILL_REG_NUM][SPILL_REG3_NUM][SPILL_EFLAGS_NUM];
/* For whole-bb spilling, we do not restore eflags, but reg3 can be anything */
byte *shared_slowpath_entry_global[SPILL_REG_NUM][SPILL_REG_NUM][SPILL_REG_NUM];
byte *shared_slowpath_region;
byte *shared_slowpath_entry;
/* adjust_esp's shared fast and slow paths pointers are below */

/* Lock for updating gencode later */
static void *gencode_lock;

/***************************************************************************
 * ISA
 */

bool
instr_propagatable_dsts(instr_t *inst)
{
    int i;
    bool res = false;
    int opc = instr_get_opcode(inst);
    for (i = 0; i < instr_num_dsts(inst); i++) {
        opnd_t opnd = instr_get_dst(inst, i);
        /* i#1543, i#243: we now shadow xmm regs and propagate and mirror xmm
         * operations (at least most of them: work in progress).
         */
        if ((opnd_is_reg(opnd) && reg_is_shadowed(opc, opnd_get_reg(opnd))) ||
            opnd_is_memory_reference(opnd)) {
            res = true;
        } else {
            res = false;
            break;
        }
    }
    return res;
}

#ifdef TOOL_DR_MEMORY
/* drcontext can be NULL if the operand is an immed int.
 *
 * For mmx, xmm, or ymm sources, returns just the lower reg_t bits.
 * XXX: we'll need to return the full value for handling OP_pand, etc.!
 * For now we only use this to get shift amounts for which we can ignore
 * all high bits.
 */
bool
get_cur_src_value(void *drcontext, instr_t *inst, uint i, reg_t *val)
{
    dr_mcontext_t mc; /* do not init whole thing: memset is expensive */
    opnd_t src = instr_get_src(inst, i);
    if (val == NULL)
        return false;
    if (opnd_is_immed_int(src)) {
        *val = (reg_t) opnd_get_immed_int(src);
        return true;
    }
    ASSERT(drcontext != NULL, "need drcontext for non-immed opnd");
    mc.size = sizeof(mc);
    mc.flags = DR_MC_CONTROL|DR_MC_INTEGER; /* don't need xmm */
    dr_get_mcontext(drcontext, &mc);
    if (opnd_is_memory_reference(src)) {
        app_pc addr = opnd_compute_address(src, &mc);
        size_t sz = opnd_size_in_bytes(opnd_get_size(src));
        if (sz > sizeof(*val))
            return false;
        return (safe_read(addr, sz, val));
    } else if (opnd_is_reg(src)) {
        byte val32[sizeof(dr_ymm_t)];
        reg_id_t reg = opnd_get_reg(src);
        if (!reg_is_gpr(reg)) {
            mc.flags |= DR_MC_MULTIMEDIA;
            dr_get_mcontext(drcontext, &mc);
        }
        if (!reg_get_value_ex(reg, &mc, val32))
            return false;
        *val = *(reg_t*)val32;
        return true;
    }
    return false;
}

static inline bool
opnds_overlap(opnd_t op1, opnd_t op2)
{
    /* XXX: should we check overlap on memory opnd? */
    return (opnd_same(op1, op2) ||
            (opnd_is_reg(op1) && opnd_is_reg(op2) && opnd_share_reg(op1, op2)));
}

bool
instrs_share_opnd(instr_t *in1, instr_t *in2)
{
    int i, j;
    for (i = 0; i < instr_num_srcs(in1); i++) {
        for (j = 0; j < instr_num_srcs(in2); j++) {
            if (opnds_overlap(instr_get_src(in1, i), instr_get_src(in2, j)))
                return true;
        }
        for (j = 0; j < instr_num_dsts(in2); j++) {
            if (opnds_overlap(instr_get_src(in1, i), instr_get_dst(in2, j)))
                return true;
        }
    }
    for (i = 0; i < instr_num_dsts(in1); i++) {
        for (j = 0; j < instr_num_srcs(in2); j++) {
            if (opnds_overlap(instr_get_dst(in1, i), instr_get_src(in2, j)))
                return true;
        }
        for (j = 0; j < instr_num_dsts(in2); j++) {
            if (opnds_overlap(instr_get_dst(in1, i), instr_get_dst(in2, j)))
                return true;
        }
    }
    return false;
}
#endif /* TOOL_DR_MEMORY */

/***************************************************************************
 * Definedness and Addressability Checking
 */

void
shadow_combine_init(shadow_combine_t *comb, instr_t *inst, uint opcode, uint max)
{
    uint i;
    uint init_shadow = SHADOW_DEFINED;
    if (opc_dst_subreg_nonlow(opcode) &&
        inst != NULL && instr_num_dsts(inst) == 1) {
        opnd_t dst = instr_get_dst(inst, 0);
        if (opnd_is_reg(dst)) {
            reg_id_t reg = opnd_get_reg(dst);
            uint opsz = opnd_size_in_bytes(opnd_get_size(dst));
            uint regsz = opnd_size_in_bytes(reg_get_size(reg));
            if (opsz < regsz) {
                /* For opcodes that write to only part of the reg and leave the
                 * rest unchanged and don't write to just the bottom of the reg,
                 * we have to pass every byte of the register shadow to
                 * map_src_to_dst().  We need to incorporate the prior reg
                 * shadow values, which we can't solely do later as we need to
                 * distinguish what was written by the opcode.  By using
                 * BITLEVEL we ensure that shadow_combine() will clobber this
                 * rather than OR it in.
                 */
                init_shadow = SHADOW_DEFINED_BITLEVEL;
            }
        }
    }
    comb->dst = comb->raw;
    /* Initialize to defined so we can aggregate operands as we go.
     * This works with no-source instrs (rdtsc, etc.)
     * This also makes small->large work out w/o any special processing
     * (movsz, movzx, cwde, etc.): but XXX: are there any src/dst size
     * mismatches where we do NOT want to set dst bytes beyond count
     * of src bytes to defined?
     */
    for (i = 0; i < max; i++)
        comb->dst[i] = init_shadow;
    comb->eflags = SHADOW_DEFINED;
    comb->inst = inst;
    comb->opcode = opcode;
}

#ifdef TOOL_DR_MEMORY

/* Adds a new source operand's value to the array of shadow vals in
 * comb->dst to be assigned to the destination.
 */
static void
integrate_register_shadow(shadow_combine_t *comb INOUT, int opnum,
                          reg_id_t reg, uint shadow, bool pushpop)
{
    uint i, sz;

    if (reg == REG_EFLAGS) {
        /* eflags propagates to all bytes */
        uint dstsz;
        accum_shadow(&comb->eflags, SHADOW_DWORD2BYTE(shadow, 0));
        if (instr_num_dsts(comb->inst) == 0)
            return;
        dstsz = opnd_size_in_bytes(opnd_get_size(instr_get_dst(comb->inst, 0)));
        for (i = 0; i < dstsz; i++)
            accum_shadow(&comb->dst[i], SHADOW_DWORD2BYTE(shadow, i));
        return;
    }

    /* PR 426162: ignore stack register source if instr also has memref
     * using same register as addressing register, since memref will do a
     * definedness check for us, and if the reg is undefined we do NOT want
     * to propagate it as it will end up in a regular dest, say pop into a
     * reg, when that dest should only depend on the memref (since on
     * reported error we set addressing register to defined).
     */
    if (pushpop && reg_overlap(reg, DR_REG_XSP))
        return;

    if (integrate_register_shadow_arch(comb, opnum, reg, shadow, pushpop))
        return;

    if (opc_dst_subreg_nonlow(comb->opcode)) {
        /* Deliberately bypassing opnd_get_size() so we can pick the right bits out
         * of the reg for opcodes that are sub-xmm but pull from higher than offset
         * 0 (e.g., pextr*).
         */
        ASSERT(comb->opnd_valid, "need opnd valid for subreg-nonzero opcodes");
        sz = opnd_size_in_bytes(reg_get_size(reg));
    } else
        sz = opnd_size_in_bytes(opnd_get_size(comb->opnd));
    for (i = 0; i < sz; i++)
        map_src_to_dst(comb, opnum, i, SHADOW_DWORD2BYTE(shadow, i));
}

/* Assigns the array of source shadow_vals to the destination register shadow */
static void
assign_register_shadow(shadow_combine_t *comb INOUT, int opnum, opnd_t opnd,
                       reg_id_t reg, bool pushpop)
{
    uint shift = 0;
    uint sz, i;

    /* Here we need to de-mux from the side-by-side dests in the array
     * into individual register dests.
     * We also have to shift dsts that do NOT simply go into the lowest slot.
     */

    if (assign_register_shadow_arch(comb, opnum, opnd, reg, pushpop, &shift))
        return;

    if (pushpop && reg_overlap(reg, DR_REG_XSP))
        return;

    if (opc_dst_subreg_nonlow(comb->opcode)) {
        uint shadow = get_shadow_register(reg);
        /* Deliberately bypassing opnd_get_size() so we can pick the right bits out
         * of the reg for opcodes that are sub-xmm but pull from higher than offset
         * 0 (e.g., pextr*).
         */
        sz = opnd_size_in_bytes(reg_get_size(reg));
        /* Replace the BITLEVEL markers with the register's prior shadow value */
        for (i = 0; i < sz; i++) {
            if (comb->dst[i] == SHADOW_DEFINED_BITLEVEL)
                comb->dst[i] = SHADOW_DWORD2BYTE(shadow, i);
        }
    } else
        sz = opnd_size_in_bytes(opnd_get_size(opnd));

    shift *= sz;
    register_shadow_set_byte(reg, reg_offs_in_dword(reg), comb->dst[shift + 0]);
    if (sz > 1) {
        ASSERT(reg_offs_in_dword(reg) == 0, "invalid reg offs");
        for (i = 1; i < sz; i++) {
            ASSERT(shift + i < OPND_SHADOW_ARRAY_LEN, "shadow_vals overflow");
            register_shadow_set_byte(reg, i, comb->dst[shift + i]);
        }
    }
}

void
register_shadow_mark_defined(reg_id_t reg, size_t sz)
{
    uint i;
    if (sz == sizeof(void*) && reg_is_gpr(reg))
        register_shadow_set_ptrsz(reg, SHADOW_PTRSZ_DEFINED);
    else if (sz == 4 && reg_is_gpr(reg)) {
        /* We assume the cases where we call this are not app writes and thus we don't
         * want to clear the top 32 bits for x64.
         */
        register_shadow_set_dword(reg, SHADOW_DWORD_DEFINED);
    } else {
        for (i = 0; i < sz; i++)
            register_shadow_set_byte(reg, i, SHADOW_DEFINED);
    }
}

bool
opnd_uses_nonignorable_memory(opnd_t opnd)
{
    /* XXX: we could track ebp/r11 and try to determine when not used as frame ptr */
    return (opnd_is_memory_reference(opnd) &&
            /* pattern mode */
            (options.pattern == 0 ? true : pattern_opnd_needs_check(opnd)) &&
            /* stack access */
            (options.check_stack_access ||
             !opnd_is_base_disp(opnd) ||
             (reg_to_pointer_sized(opnd_get_base(opnd)) != DR_REG_XSP &&
              reg_to_pointer_sized(opnd_get_base(opnd)) != REG_FRAME_PTR) ||
             opnd_get_index(opnd) != REG_NULL ||
             opnd_is_far_memory_reference(opnd)));
}

/* Called by slow_path() after initial decode.  Expected to free inst. */
bool
slow_path_without_uninitialized(void *drcontext, dr_mcontext_t *mc, instr_t *inst,
                                app_loc_t *loc, size_t instr_sz)
{
    opnd_t opnd, memop = opnd_create_null();
    int opc, i, num_srcs, num_dsts;
    uint sz;
    bool pushpop_stackop;
    uint flags;
    ASSERT(!options.check_uninitialized, "should not be called");

    opc = instr_get_opcode(inst);
    num_srcs = (IF_X86_ELSE(opc == OP_lea, false)) ? 0 : num_true_srcs(inst, mc);
    for (i = 0; i < num_srcs; i++) {
        opnd = instr_get_src(inst, i);
        if (opnd_uses_nonignorable_memory(opnd)) {
            opnd = adjust_memop(inst, opnd, false, &sz, &pushpop_stackop);
            if (pushpop_stackop && options.check_stack_bounds)
                flags = MEMREF_PUSHPOP | MEMREF_IS_READ;
            else
                flags = MEMREF_CHECK_ADDRESSABLE | MEMREF_IS_READ;
            memop = opnd;
            check_mem_opnd_nouninit(opc, flags, loc, opnd, sz, mc);
        }
    }

    num_dsts = num_true_dsts(inst, mc);
    for (i = 0; i < num_dsts; i++) {
        opnd = instr_get_dst(inst, i);
        if (opnd_uses_nonignorable_memory(opnd)) {
            opnd = adjust_memop(inst, opnd, true, &sz, &pushpop_stackop);
            if (pushpop_stackop && options.check_stack_bounds)
                flags = MEMREF_PUSHPOP | MEMREF_WRITE;
            else
                flags = MEMREF_CHECK_ADDRESSABLE;
            memop = opnd;
            check_mem_opnd_nouninit(opc, flags, loc, opnd, sz, mc);
        }
    }

    instr_free(drcontext, inst);

    /* call this last after freeing inst in case it does a synchronous flush */
    slow_path_xl8_sharing(loc, instr_sz, memop, mc);

    return true;
}
#endif /* TOOL_DR_MEMORY */

/* Does everything in C code, except for handling non-push/pop writes to esp.
 *
 * General design:
 * + comb.dest[] array holds the shadow values for the destinations.
 *   If there are multiple dests, they are laid out side-by-side.
 * + Shadow values are combined via combine_shadows() which does OR-combining.
 *
 * First we walk the sources and add each in turn to the shadow array via:
 * + integrate_register_shadow() for regs
 * + handle_mem_ref() with MEMREF_USE_VALUES for memrefs
 * Both call map_src_to_dst() which determines where in
 * the dst shadow array to put each source, thus handling arbitrary
 * opcodes with weird data movements.
 *
 * Then we walk the dests and call handle_mem_ref() or
 * assign_register_shadow() on each, which pulls from comb.dest[]'s shadow vals.
 *
 * XXX: can we change handle_mem_ref() and map_src_to_dst() to not operate on
 * one byte at a time, so we can make the slowpath more closely match the
 * fastpath code, and thus make it easier to transition opcodes to the fastpath?
 */
bool
slow_path_with_mc(void *drcontext, app_pc pc, app_pc decode_pc, dr_mcontext_t *mc)
{
    instr_t inst;
    int opc;
#ifdef TOOL_DR_MEMORY
    opnd_t opnd;
    int i, num_srcs, num_dsts;
    uint sz;
    shadow_combine_t comb;
    bool check_definedness, pushpop, pushpop_stackop;
    bool check_srcs_after;
    bool always_defined;
    opnd_t memop = opnd_create_null();
    size_t instr_sz;
    cls_drmem_t *cpt = (cls_drmem_t *) drmgr_get_cls_field(drcontext, cls_idx_drmem);
#endif
    app_loc_t loc;

#if defined(STATISTICS) && defined(TOOL_DR_MEMORY)
    /* PR 423757: periodic stats dump, both for server apps that don't
     * close cleanly and to get stats out prior to overflow.
     */
    int execs = atomic_add32_return_sum((volatile int *)&slowpath_executions, 1);
    if (execs == next_stats_dump) {
        /* still racy: could skip a dump, but that's ok */
        ATOMIC_ADD32(next_stats_dump, options.stats_dump_interval);
        dr_fprintf(f_global, "\n**** per-%dK-slowpath stats dump:\n",
                   options.stats_dump_interval/1000);
        dump_statistics();
    }
#endif

    pc_to_loc(&loc, pc);

    /* Locally-spilled and whole-bb-spilled (PR 489221) registers have
     * already been restored in shared_slowpath, so we can properly
     * emulate addresses referenced.  We can't restore whole-bb-spilled
     * here b/c we don't have the bb tag.  Eflags may not be restored
     * but we don't rely on them here.
     */

    ASSERT(decode_pc != NULL, "single_arg_slowpath removed");

#ifdef TOOL_DR_MEMORY
    if (decode_pc != NULL) {
        if (medium_path_arch(decode_pc, &loc, mc))
            return true;
    }
#endif /* TOOL_DR_MEMORY */

    instr_init(drcontext, &inst);
#ifdef TOOL_DR_MEMORY
    instr_sz = decode(drcontext, decode_pc, &inst) - decode_pc;
#else
    decode(drcontext, decode_pc, &inst);
#endif
    ASSERT(instr_valid(&inst), "invalid instr");
    opc = instr_get_opcode(&inst);

    slowpath_update_app_loc_arch(opc, decode_pc, &loc);

#ifdef STATISTICS
    STATS_INC(slowpath_count[opc]);
    {
        uint bytes = instr_memory_reference_size(&inst);
        if (bytes == 0) {
            if (instr_num_dsts(&inst) > 0 &&
                !opnd_is_pc(instr_get_dst(&inst, 0)) &&
                !opnd_is_instr(instr_get_dst(&inst, 0)))
                bytes = opnd_size_in_bytes(opnd_get_size(instr_get_dst(&inst, 0)));
            else if (instr_num_srcs(&inst) > 0 &&
                     !opnd_is_pc(instr_get_src(&inst, 0)) &&
                     !opnd_is_instr(instr_get_src(&inst, 0)))
                bytes = opnd_size_in_bytes(opnd_get_size(instr_get_src(&inst, 0)));
            else
                bytes = 0;
        }
        if (bytes == 1)
            STATS_INC(slowpath_sz1);
        else if (bytes == 2)
            STATS_INC(slowpath_sz2);
        else if (bytes == 4)
            STATS_INC(slowpath_sz4);
        else if (bytes == 8)
            STATS_INC(slowpath_sz8);
        else if (bytes == 10)
            STATS_INC(slowpath_sz10);
        else if (bytes == 16)
            STATS_INC(slowpath_sz16);
        else
            STATS_INC(slowpath_szOther);
    }
#endif

    DOLOG(3, {
        LOG(3, "\nslow_path "PFX": ", pc);
        instr_disassemble(drcontext, &inst, LOGFILE_GET(drcontext));
        if (instr_num_dsts(&inst) > 0 &&
            opnd_is_memory_reference(instr_get_dst(&inst, 0))) {
            umbra_shadow_memory_info_t info;
            umbra_shadow_memory_info_init(&info);
            LOG(3, " | 0x%x",
                shadow_get_byte(&info,
                                opnd_compute_address(instr_get_dst(&inst, 0),
                                                     mc)));
        }
        LOG(3, "\n");
    });

#ifdef TOOL_DR_HEAPSTAT
    return slow_path_for_staleness(drcontext, mc, &inst, &loc);

#else
    if (!options.check_uninitialized)
        return slow_path_without_uninitialized(drcontext, mc, &inst, &loc, instr_sz);

    LOG(4, "shadow registers prior to instr:\n");
    DOLOG(4, { print_shadow_registers(); });

    /* We need to do the following:
     * - check addressability of all memory operands
     * - check definedness of all source operands if:
     *   o no GPR or memory dest (=> no way to store definedness)
     *   o if options.check_uninit_non_moves is on and this is not just a move
     * - check definedness of certain source operands:
     *   o base or index register to a memory ref
     *     (includes esp/ebp operand to a push/pop)
     *   o ecx to stringop
     *   o ebp to enter/leave
     * - combine definedness of source operands and store
     *   in dest operand shadows
     * - if a pop, make stack slot(s) unaddressable
     *
     * Usually there's one destination we need to transfer
     * definedness to.  If there are more, we can fit them side by
     * side in our 8-dword-capacity comb->dst array.
     */
    check_definedness = instr_check_definedness(&inst);
    always_defined = result_is_always_defined(&inst, false/*us*/);
    pushpop = opc_is_push(opc) || opc_is_pop(opc);
    check_srcs_after = instr_needs_all_srcs_and_vals(&inst);
    if (check_srcs_after) {
        /* We need to check definedness of addressing registers, and so we do
         * our normal src loop but we do not check undefinedness or combine
         * sources.  Below we pass pointers to later in comb->dst to
         * check_mem_opnd() and integrate_register_shadow(), causing the 2
         * sources to be laid out side-by-side in comb->dst.
         */
        ASSERT(instr_num_srcs(&inst) == 2, "and/or special handling error");
        check_definedness = false;
        IF_DEBUG(comb.opsz = 0;) /* for asserts below */
    }

    shadow_combine_init(&comb, &inst, opc, OPND_SHADOW_ARRAY_LEN);

    num_srcs = num_true_srcs(&inst, mc);
#ifdef X86
    if (opc == OP_lea)
        num_srcs = IF_X64_ELSE(opnd_is_rel_addr(instr_get_src(&inst, 0)), false) ? 0 : 2;
#endif
 check_srcs:
    for (i = 0; i < num_srcs; i++) {
        if (IF_X86_ELSE(opc == OP_lea, false)) {
            /* special case: treat address+base as propagatable sources
             * code below can handle REG_NULL
             */
            if (i == 0)
                opnd = opnd_create_reg(opnd_get_base(instr_get_src(&inst, 0)));
            else
                opnd = opnd_create_reg(opnd_get_index(instr_get_src(&inst, 0)));
        } else {
            opnd = instr_get_src(&inst, i);
        }
        if (opnd_is_memory_reference(opnd)) {
            int flags = 0;
            opnd = adjust_memop(&inst, opnd, false, &sz, &pushpop_stackop);
            /* do not combine srcs if checking after */
            if (check_srcs_after) {
                ASSERT(i == 0 || sz >= comb.opsz, "check-after needs >=-size srcs");
                comb.dst = &comb.raw[i*sz]; /* shift the dst in the array */
            }
            shadow_combine_set_opnd(&comb, opnd, sz);
            /* check_mem_opnd() checks definedness of base registers,
             * addressability of address, and if necessary checks definedness
             * and adjusts addressability of address.
             */
            if (pushpop_stackop)
                flags |= MEMREF_PUSHPOP;
            if (always_defined) {
                LOG(2, "marking and/or/xor with 0/~0/self as defined @"PFX"\n", pc);
                /* w/o MEMREF_USE_VALUES, handle_mem_ref() will use SHADOW_DEFINED */
            } else if (check_definedness || always_check_definedness(&inst, i)) {
                flags |= MEMREF_CHECK_DEFINEDNESS;
                if (options.leave_uninit)
                    flags |= MEMREF_USE_VALUES;
            } else {
                /* If we're checking, to avoid further errors we do not
                 * propagate the shadow vals (and thus we essentially
                 * propagate SHADOW_DEFINED).
                 * Conveniently all the large operand sizes always
                 * have check_definedness since they involve fp or sse.
                 */
                ASSERT(sz <= sizeof(comb.raw), "internal shadow val error");
                flags |= MEMREF_USE_VALUES;
            }
            memop = opnd;
            check_mem_opnd(opc, flags, &loc, opnd, sz, mc, i, &comb);
        } else if (opnd_is_reg(opnd)) {
            reg_id_t reg = opnd_get_reg(opnd);
            if (reg_is_shadowed(opc, reg)) {
                uint shadow = get_shadow_register(reg);
                if (opc_dst_subreg_nonlow(opc)) {
                    /* We need the whole reg as this opcode references high up */
                    sz = opnd_size_in_bytes(reg_get_size(reg));
                } else
                    sz = opnd_size_in_bytes(opnd_get_size(opnd));
                /* do not combine srcs if checking after */
                if (check_srcs_after) {
                    ASSERT(i == 0 || sz >= comb.opsz, "check-after needs >=-size srcs");
                    comb.dst = &comb.raw[i*sz]; /* shift the dst in the array */
                }
                shadow_combine_set_opnd(&comb, opnd, sz);
                if (always_defined) {
                    /* if result defined regardless, don't propagate (is
                     * equivalent to propagating SHADOW_DEFINED) or check */
                } else if (check_definedness || always_check_definedness(&inst, i)) {
                    check_register_defined(drcontext, reg, &loc, sz, mc, &inst);
                    if (options.leave_uninit) {
                        integrate_register_shadow(&comb, i, reg, shadow, pushpop);
                    }
                } else {
                    /* See above: we only propagate when not checking */
                    integrate_register_shadow(&comb, i, reg, shadow, pushpop);
                }
            } /* else always defined */
        } else /* always defined */
            ASSERT(opnd_is_immed_int(opnd) || opnd_is_pc(opnd), "unexpected opnd");
        DOLOG(4, {
            int j;
            LOG(4, "shadows after src %d ", i);
            opnd_disassemble(drcontext, opnd, LOGFILE_GET(drcontext));
            LOG(4, ": ");
            for (j = 0; j < OPND_SHADOW_ARRAY_LEN; j++)
                LOG(4, "%d", comb.raw[j]);
            LOG(4, ", eflags: %d\n", comb.eflags);
        });
    }

    /* eflags source */
    if (TESTANY(EFLAGS_READ_ARITH, instr_get_eflags(&inst, DR_QUERY_DEFAULT))) {
        uint shadow = get_shadow_eflags();
        /* for check_srcs_after we leave comb.dst where it last was */
        if (always_defined) {
            /* if result defined regardless, don't propagate (is
             * equivalent to propagating SHADOW_DEFINED) or check */
        } else if (check_definedness) {
            check_register_defined(drcontext, REG_EFLAGS, &loc, 1, mc, &inst);
            if (options.leave_uninit)
                integrate_register_shadow(&comb, 0, REG_EFLAGS, shadow, pushpop);
        } else {
            /* See above: we only propagate when not checking */
            integrate_register_shadow(&comb, 0, REG_EFLAGS, shadow, pushpop);
        }
    } else if (num_srcs == 0) {
        /* do not propagate from comb.dst since dst size could be large (i#458)
         * (fxsave, etc.)
         */
        always_defined = true;
    }

    if (check_srcs_after)
        comb.dst = comb.raw; /* restore */

    if (check_srcs_after) {
        /* turn back on for dsts */
        check_definedness = instr_check_definedness(&inst);
        if (check_andor_sources(drcontext, mc, &inst, &comb, decode_pc + instr_sz)) {
            if (TESTANY(EFLAGS_WRITE_ARITH,
                        instr_get_eflags(&inst, DR_QUERY_INCLUDE_ALL))) {
                /* We have to redo the eflags propagation.  map_src_to_dst() combined
                 * all the laid-out sources, some of which we made defined in
                 * check_andor_sources.
                 */
                comb.eflags = SHADOW_DEFINED;
                for (i = 0; i < OPND_SHADOW_ARRAY_LEN; i++)
                    accum_shadow(&comb.eflags, comb.dst[i]);
            }
        }
        if (check_definedness) {
            /* If we need to report undefs we have to go back */
            bool all_defined = true;
            for (i = 0; i < OPND_SHADOW_ARRAY_LEN; i++) {
                if (comb.dst[i] != SHADOW_DEFINED) {
                    all_defined = false;
                    break;
                }
            }
            if (!all_defined) {
                /* We do not bother to suppress reporting the particular bytes that
                 * may have been "defined" due to 0/1 in the other operand since
                 * doing so would require duplicating/extracting all the reporting
                 * logic above for regs and in handle_mem_ref(): our goto here is
                 * slightly less ugly.
                 */
                LOG(4, "and/or not all defined and need to check def: restarting\n");
                /* Avoid recursing, and don't do the side-by-side layout this time */
                check_srcs_after = false;
                for (i = 0; i < OPND_SHADOW_ARRAY_LEN; i++)
                    comb.dst[i] = SHADOW_DEFINED;
                comb.eflags = SHADOW_DEFINED;
                goto check_srcs;
            }
        }
    }

    num_dsts = num_true_dsts(&inst, mc);
    for (i = 0; i < num_dsts; i++) {
        opnd = instr_get_dst(&inst, i);
        if (opnd_is_memory_reference(opnd)) {
            int flags = MEMREF_WRITE;
            opnd = adjust_memop(&inst, opnd, true, &sz, &pushpop_stackop);
            if (pushpop_stackop)
                flags |= MEMREF_PUSHPOP;
            if (cpt->mem2fpmm_source != NULL && cpt->mem2fpmm_pc == pc) {
                /* i#471 fld;fstp heuristic: fstp's dest was marked bitlevel to
                 * get us here.  Do a special-case propagate.
                 */
                umbra_shadow_memory_info_t info;
                LOG(3, "propagating fld;fstp from "PFX"\n", cpt->mem2fpmm_source);
                /* We use a fake movs in handle_mem_ref() (can't just do
                 * shadow_copy_range() b/c we need to check base reg for
                 * definedness, check for addressability, etc.)
                 */
                umbra_shadow_memory_info_init(&info);
                shadow_set_byte(&info, cpt->mem2fpmm_dest, cpt->mem2fpmm_prev_shadow);
                comb.movs_addr = cpt->mem2fpmm_source;
                flags |= MEMREF_MOVS | MEMREF_USE_VALUES;
                cpt->mem2fpmm_source = NULL;
            } else if (always_defined) {
                /* w/o MEMREF_USE_VALUES, handle_mem_ref() will use SHADOW_DEFINED */
            } else if (check_definedness) {
                flags |= MEMREF_CHECK_DEFINEDNESS;
                if (options.leave_uninit)
                    flags |= MEMREF_USE_VALUES;
                /* since checking, we mark as SHADOW_DEFINED (see above) */
            } else {
                ASSERT(sz <= sizeof(comb.raw), "internal shadow val error");
                flags |= MEMREF_USE_VALUES;
            }
            /* check addressability, and propagate
             * we arranged xchg/xadd to not need shifting; nothing else does either.
             */
            memop = opnd;
            check_mem_opnd(opc, flags, &loc, opnd, sz, mc, i, &comb);
        } else if (opnd_is_reg(opnd)) {
            reg_id_t reg = opnd_get_reg(opnd);
            if (reg_is_shadowed(opc, reg)) {
                assign_register_shadow(&comb, i, opnd, reg, pushpop);
            }
        } else
            ASSERT(opnd_is_immed_int(opnd) || opnd_is_pc(opnd), "unexpected opnd");
    }
    if (TESTANY(EFLAGS_WRITE_ARITH, instr_get_eflags(&inst, DR_QUERY_INCLUDE_ALL))) {
        set_shadow_eflags(comb.eflags);
    }

    LOG(4, "shadow registers after instr:\n");
    DOLOG(4, { print_shadow_registers(); });

    instr_free(drcontext, &inst);

    /* call this last after freeing inst in case it does a synchronous flush */
    slow_path_xl8_sharing(&loc, instr_sz, memop, mc);

    DOLOG(5, { /* this pollutes the logfile, so it's a pain to have at 4 or lower */
        if (pc == decode_pc/*else retpc not in tls3*/) {
            /* Test translation when have both args */
            /* we want the ultimate target, not whole_bb_spills_enabled()'s
             * SPILL_SLOT_5 intermediate target
             */
            byte *ret_pc = (byte *) get_own_tls_value(SPILL_SLOT_SLOW_RET);
            /* ensure event_restore_state() returns true */
            byte *xl8;
            cpt->self_translating = true;
            xl8 = dr_app_pc_from_cache_pc(ret_pc);
            cpt->self_translating = false;
            LOG(3, "translation test: cache="PFX", orig="PFX", xl8="PFX"\n",
                ret_pc, pc, xl8);
            ASSERT(xl8 == pc ||
                   IF_X86((options.repstr_to_loop &&
                           /* Depending on -no_fastpath we'll get here for the jecxz
                            * pointing at the loop, the loop, or the stringop.
                            */
                           (opc_is_stringop(opc) || opc == OP_loop) &&
                           /* For repstr_to_loop we changed pc */
                           (xl8 == loc_to_pc(&loc) ||
                            /* For repstr_to_loop OP_loop, ret_pc is the restore
                             * code after stringop and before OP_loop*, so we'll get
                             * post-xl8 pc.
                             */
                            xl8 == decode_next_pc(drcontext, loc_to_pc(&loc)))) ||)
                   /* ret_pc may be a global reg restore, and for -no_fastpath
                    * this will use the prior xl8 since there's no meta-xl8 and
                    * the real app instr is beyond ret_pc.
                    */
                   (instr_at_pc_is_restore(drcontext, ret_pc) &&
                    pc == decode_next_pc(drcontext, xl8)) ||
                   /* for native ret we changed pc */
                   (options.replace_malloc && opc == IF_X86_ELSE(OP_ret, OP_bx) &&
                    alloc_entering_replace_routine(xl8)),
                   "xl8 doesn't match");
        }
    });
    return true;
#endif /* !TOOL_DR_HEAPSTAT */
}

/* called from code cache */
static bool
slow_path(app_pc pc, app_pc decode_pc)
{
    void *drcontext = dr_get_current_drcontext();
    dr_mcontext_t mc; /* do not init whole thing: memset is expensive */
    bool res;
    mc.size = sizeof(mc);
    mc.flags = DR_MC_CONTROL|DR_MC_INTEGER; /* don't need xmm */
    dr_get_mcontext(drcontext, &mc);
    res = slow_path_with_mc(drcontext, pc, decode_pc, &mc);
#ifdef TOOL_DR_MEMORY
    DODEBUG({
        cls_drmem_t *cpt = (cls_drmem_t *) drmgr_get_cls_field(drcontext, cls_idx_drmem);
        /* Try to ensure that mem2fpmm_source doesn't "escape" */
        ASSERT(cpt->mem2fpmm_source == NULL ||
               (pc >= cpt->mem2fpmm_load_pc && pc <= cpt->mem2fpmm_pc),
               "mem2fpmm source escaped");
    });
#endif
    return res;
}

/* Returns whether a single pc can be used for app reporting and
 * decoding of the app instr (or, whether a separate decode pc can be
 * used b/c there's fixup code for the pc to report in the slowpath).
 * The OUT param is either an immed int opnd or an instr opnd that can be
 * used as an intpr opnd for decoding.
 */
static bool
instr_shared_slowpath_decode_pc(instr_t *inst, fastpath_info_t *mi,
                                opnd_t *decode_pc_opnd)
{
    app_pc pc = instr_get_app_pc(inst);
    app_pc decode_pc = dr_app_pc_for_decoding(pc);
    if (!options.shared_slowpath) {
        *decode_pc_opnd = OPND_CREATE_INTPTR(decode_pc);
        return false;
    }
    if (mi->bb->fake_xl8_override_instr == inst) {
        *decode_pc_opnd = OPND_CREATE_INTPTR(mi->bb->fake_xl8_override_pc);
        return true;
    } else if (mi->bb->fake_xl8 != NULL) {
        *decode_pc_opnd = OPND_CREATE_INTPTR(mi->bb->fake_xl8);
        return true;
    } else if (pc != decode_pc) {
        /* We have to handle DR trampolines so we pass in a separate pc to
         * decode from
         */
        *decode_pc_opnd = OPND_CREATE_INTPTR(decode_pc);
        return false;
    } else if (pc == instr_get_raw_bits(inst)) {
        /* If it matches the raw bits we know we only need one pc */
        *decode_pc_opnd = OPND_CREATE_INTPTR(pc);
        return true;
    } else {
        if (options.replace_malloc && alloc_entering_replace_routine(pc)) {
            /* drwrap_replace_native() emulates a push for call site
             * replacement via generated instrs whose app pcs do not match
             * their code cache forms.
             */
        } else {
            DOLOG(1, {
                if (IF_X86_ELSE(instr_get_opcode(inst) == OP_xchg &&
                                opnd_is_reg(instr_get_dst(inst, 1)) &&
                                opnd_get_reg(instr_get_dst(inst, 1)) == DR_REG_XAX &&
                                opnd_is_base_disp(instr_get_dst(inst, 0)) &&
                                opnd_get_base(instr_get_dst(inst, 0)) == DR_REG_XAX,
                                false)) {
                    /* this is the retaddr clobber from bb_handle_chkstk() */
                } else {
                    void *drcontext = dr_get_current_drcontext();
                    LOG(1, "unknown generated app instr: ");
                    instr_disassemble(drcontext, inst, LOGFILE_GET(drcontext));
                    LOG(1, "\n");
                }
            });
            /* To try and handle any generated app2app we point at the
             * cache instr.  We'll have to construct fake instrs to point
             * at if we end up encountering any mangled instrs.
             */
        }
        /* drwrap_replace() for x86_64 and ARM uses a jmp through a reg */
        ASSERT(instr_is_app(inst) || !instr_is_cti(inst), "assuming non-mangled");
        *decode_pc_opnd = opnd_create_instr(inst);
        return false;
    }
}

bool
instr_can_use_shared_slowpath(instr_t *inst, fastpath_info_t *mi)
{
    opnd_t ignore;
    return instr_shared_slowpath_decode_pc(inst, mi, &ignore);
}

void
instrument_slowpath(void *drcontext, instrlist_t *bb, instr_t *inst,
                    fastpath_info_t *mi)
{
    opnd_t decode_pc_opnd;
    ASSERT(options.pattern == 0, "No slow path for pattern mode");
    if (instr_shared_slowpath_decode_pc(inst, mi, &decode_pc_opnd)
        IF_ARM(&& false/*NYI: see below*/)) {
#ifdef X86
        /* Since the clean call instr sequence is quite long we share
         * it among all bbs.  Rather than switch to a clean stack we jmp
         * there and jmp back.  Since we don't nest we can get away
         * w/ a single TLS slot.  The other is used for the arg.  We
         * inline the call if the 2nd arg is different.
         * Note that having slow_path use dr_redirect_execution() instead
         * of coming back here is problematic since when would we execute the
         * app instr?  Can't do it before since need to emulate addresses,
         * and don't have a single-step or other way to have target not be
         * executed directly in future.
         */
        instr_t *appinst = INSTR_CREATE_label(drcontext);
        if (mi == NULL) {
            ASSERT(!whole_bb_spills_enabled(), "whole-bb needs tls preserved");
            instru_insert_mov_pc(drcontext, bb, inst,
                                 spill_slot_opnd(drcontext, SPILL_SLOT_1),
                                 decode_pc_opnd);
            /* XXX: this hardcoded address will be wrong if this
             * fragment is shifted, but DR now disables shifting in the
             * presence of clients (i#784, DRi#696).
             * The old trace API would end up copying this, but the new one
             * copies from the app code, so there's no problem there.
             * And so long as we're never at a "safe spot" in the lean procedure,
             * DR won't relocate us or remove our return point out from underneath us.
             */
            instru_insert_mov_pc(drcontext, bb, inst,
                                 spill_slot_opnd(drcontext, SPILL_SLOT_2),
                                 opnd_create_instr(appinst));
            PRE(bb, inst,
                XINST_CREATE_jump(drcontext, opnd_create_pc(shared_slowpath_entry)));
        } else {
            /* Don't restore, and put consts into registers if we can, to save space */
            scratch_reg_info_t *s1, *s2, *s3;
            int r1, r2, r3, ef = 0;
            bool spill_eax;
            byte *tgt;
            s1 = &mi->reg1;
            s2 = &mi->reg2;
            s3 = &mi->reg3;
            /* For whole-bb spilling we sometimes have reg3 in slot1 or slot2 b/c
             * we picked ecx as a whole-bb spill: simplest to shuffle here
             */
            if (whole_bb_spills_enabled() && mi->reg3.global) {
                if (mi->reg3.slot == SPILL_SLOT_1) {
                    s1 = &mi->reg3;
                    s3 = &mi->reg1;
                } else {
                    ASSERT(mi->reg3.slot == SPILL_SLOT_2, "spill assumption violated");
                    s2 = &mi->reg3;
                    s3 = &mi->reg2;
                }
            }
            ASSERT(s1->slot == SPILL_SLOT_1 && s2->slot == SPILL_SLOT_2, "slot error");
            r1 = (s1->dead ? (s1->reg - DR_REG_XAX + SPILL_REG_EAX_DEAD) :
                  ((!s1->used || s1->xchg != REG_NULL) ? SPILL_REG_NONE :
                   (s1->reg - DR_REG_XAX + SPILL_REG_EAX)));
            r2 = (s2->dead ? (s2->reg - DR_REG_XAX + SPILL_REG_EAX_DEAD) :
                  ((!s2->used || s2->xchg != REG_NULL) ? SPILL_REG_NONE :
                   (s2->reg - DR_REG_XAX + SPILL_REG_EAX)));
            if (whole_bb_spills_enabled()) {
                /* reg3 just like 1 and 2: can be any reg */
                r3 = (s3->dead ? (s3->reg - DR_REG_XAX + SPILL_REG_EAX_DEAD) :
                      ((!s3->used || s3->xchg != REG_NULL) ? SPILL_REG_NONE :
                       (s3->reg - DR_REG_XAX + SPILL_REG_EAX)));
            } else {
                /* if reg3 is dead we do not need to restore */
                r3 = ((!s3->used || s3->dead || s3->xchg != REG_NULL) ?
                      SPILL_REG3_NOSPILL : SPILL_REG3_SPILL);
                spill_eax = (mi->eax.used && !mi->eax.dead && mi->eax.xchg == REG_NULL);
                ef = ((whole_bb_spills_enabled() ||
                       mi->aflags == EFLAGS_WRITE_ARITH) ? SPILL_EFLAGS_NOSPILL :
                      ((mi->aflags == EFLAGS_WRITE_OF) ?
                       (spill_eax ? SPILL_EFLAGS_5_EAX : SPILL_EFLAGS_5_NOEAX) :
                       (spill_eax ? SPILL_EFLAGS_6_EAX : SPILL_EFLAGS_6_NOEAX)));
            }
            ASSERT(r1 >= 0 && r1 < SPILL_REG_NUM, "shared slowpath index error");
            ASSERT(r2 >= 0 && r2 < SPILL_REG_NUM, "shared slowpath index error");
            tgt = (whole_bb_spills_enabled() ?
                   shared_slowpath_entry_global[r1][r2][r3]:
                   shared_slowpath_entry_local[r1][r2][r3][ef]);
            ASSERT(tgt != NULL, "targeting un-generated slowpath");
            instru_insert_mov_pc(drcontext, bb, inst,
                                 (r1 == SPILL_REG_NONE) ?
                                 spill_slot_opnd(drcontext, SPILL_SLOT_SLOW_PARAM) :
                                 opnd_create_reg(s1->reg),
                                 decode_pc_opnd);
            instru_insert_mov_pc(drcontext, bb, inst,
                                 (r2 == SPILL_REG_NONE) ?
                                 spill_slot_opnd(drcontext, SPILL_SLOT_SLOW_RET) :
                                 opnd_create_reg(s2->reg),
                                 opnd_create_instr(appinst));
            PRE(bb, inst, XINST_CREATE_jump(drcontext, opnd_create_pc(tgt)));
        }
        PRE(bb, inst, appinst);
        /* If we entered the slowpath, we've clobbered the reg holding the address to
         * share so we have to clear it.  Rather than slow_path_xl8_sharing() doing so,
         * which requires a 2-step return and a fixed TLS slot to get it back into the
         * per-call-site reg, we pay a little in inlined cache size and clear it here.
         */
        if (SHARING_XL8_ADDR(mi)) {
            instru_insert_mov_pc(drcontext, bb, inst, opnd_create_reg(mi->reg1.reg),
                                 OPND_CREATE_INTPTR(shadow_bitlevel_addr()));
        }
#else
        /* FIXME i#1726: add ARM port.  Some of the above code was
         * made cross-platform, but the per-scratch-reg code and some
         * of the generated instrs are x86-specific still.
         */
        ASSERT_NOT_IMPLEMENTED();
#endif
    } else {
        app_pc pc = instr_get_app_pc(inst);
        if (mi != NULL) {
            /* We assume caller did a restore */
        }
        if (!opnd_same(OPND_CREATE_INTPTR(pc), decode_pc_opnd)) {
            LOG(1, "INFO: app "PFX" has separate decode pc\n", pc);
        }
        dr_insert_clean_call(drcontext, bb, inst,
                             (void *) slow_path, false, 2,
                             OPND_CREATE_INTPTR(pc),
                             decode_pc_opnd);
    }
}

bool
is_in_gencode(byte *pc)
{
#ifdef TOOL_DR_HEAPSTAT
    ASSERT(false, "should not get here");
#endif
    return (pc >= shared_slowpath_region &&
            pc < shared_slowpath_region + SHARED_SLOWPATH_SIZE);
}

#ifdef X86 /* XXX i#1726: update for ARM */
static void
shared_slowpath_save_param(void *drcontext, instrlist_t *ilist, int type)
{
    if ((type >= SPILL_REG_EAX && type <= SPILL_REG_EBX) ||
        (type >= SPILL_REG_EAX_DEAD && type <= SPILL_REG_EBX_DEAD)) {
        reg_id_t reg = (type >= SPILL_REG_EAX && type <= SPILL_REG_EBX) ?
            (DR_REG_XAX + (type - SPILL_REG_EAX)) :
            (DR_REG_XAX + (type - SPILL_REG_EAX_DEAD));
        /* Store from site-specific reg into TLS for clean call param */
        PRE(ilist, NULL, INSTR_CREATE_mov_st
            (drcontext, spill_slot_opnd(drcontext, SPILL_SLOT_SLOW_PARAM),
             opnd_create_reg(reg)));
    } /* else param was put straight in tls slot */
}

static void
shared_slowpath_save_retaddr(void *drcontext, instrlist_t *ilist, int type)
{
    if ((type >= SPILL_REG_EAX && type <= SPILL_REG_EBX) ||
        (type >= SPILL_REG_EAX_DEAD && type <= SPILL_REG_EBX_DEAD)) {
        reg_id_t reg = (type >= SPILL_REG_EAX && type <= SPILL_REG_EBX) ?
            (DR_REG_XAX + (type - SPILL_REG_EAX)) :
            (DR_REG_XAX + (type - SPILL_REG_EAX_DEAD));
        /* Store from site-specific reg into TLS for clean call ret */
        PRE(ilist, NULL, INSTR_CREATE_mov_st
            (drcontext, spill_slot_opnd(drcontext, SPILL_SLOT_SLOW_RET),
             opnd_create_reg(reg)));
    } /* else param was put straight in tls slot */
}

static void
shared_slowpath_restore(void *drcontext, instrlist_t *ilist, int type, int slot)
{
    if ((type >= SPILL_REG_EAX && type <= SPILL_REG_EBX) ||
        (type >= SPILL_REG_EAX_DEAD && type <= SPILL_REG_EBX_DEAD)) {
        reg_id_t reg = (type >= SPILL_REG_EAX && type <= SPILL_REG_EBX) ?
            (DR_REG_XAX + (type - SPILL_REG_EAX)) :
            (DR_REG_XAX + (type - SPILL_REG_EAX_DEAD));
        /* Restore app value to reg for emulation in slowpath */
        PRE(ilist, NULL, INSTR_CREATE_mov_ld
            (drcontext, opnd_create_reg(reg), spill_slot_opnd(drcontext, slot)));
    } /* else param was put straight in tls slot */
}
#endif

byte *
generate_shared_slowpath(void *drcontext, instrlist_t *ilist, byte *pc)
{
#ifdef X86
    int r1, r2, r3, ef;

    /* Create our shared slowpath.  To save space at the "call" site, we
     * restore the spilled registers/eflags here; but to support site-specific
     * selection of which registers to use, we have every possible restore
     * sequence here.  An alternative is to have the C code determine
     * which registers/eflags were spilled and swap the registers with the
     * tls slots.
     * The call site places the single value for both args in reg1
     * (this slowpath call is not supported if the values differ) and
     * the return pc in reg2 and then jmps to the appropriate restore
     * entry point.  After restoring and putting the args into spill
     * slots, we do a clean call, which redirects afterward and so
     * does not return.
     */
    shared_slowpath_entry = pc;
    dr_insert_clean_call(drcontext, ilist, NULL,
                         (void *) slow_path, false, 2,
                         spill_slot_opnd(drcontext, SPILL_SLOT_SLOW_PARAM),
                         spill_slot_opnd(drcontext, SPILL_SLOT_SLOW_PARAM));
    PRE(ilist, NULL,
        XINST_CREATE_jump_mem(drcontext, spill_slot_opnd
                              (drcontext, SPILL_SLOT_SLOW_RET)));
    pc = instrlist_encode(drcontext, ilist, pc, false);
    instrlist_clear(drcontext, ilist);

    for (r1 = 0; r1 < SPILL_REG_NUM; r1++) {
        for (r2 = 0; r2 < SPILL_REG_NUM; r2++) {
            /* for whole-bb, r3 is not always ecx */
            for (r3 = 0; r3 < (whole_bb_spills_enabled() ?
                               SPILL_REG_NUM : SPILL_REG3_NUM); r3++) {
                /* for whole-bb, eflags is never restored here */
                for (ef = 0; ef < (whole_bb_spills_enabled() ? 1 : SPILL_EFLAGS_NUM);
                     ef++) {
                    if (!whole_bb_spills_enabled() && ef != SPILL_EFLAGS_NOSPILL) {
                        if (ef == SPILL_EFLAGS_6_EAX ||
                            ef == SPILL_EFLAGS_6_NOEAX) {
                            PRE(ilist, NULL, INSTR_CREATE_add
                                (drcontext, opnd_create_reg(REG_AL),
                                 OPND_CREATE_INT8(0x7f)));
                        }
                        PRE(ilist, NULL, INSTR_CREATE_sahf(drcontext));
                        if (ef == SPILL_EFLAGS_6_EAX ||
                            ef == SPILL_EFLAGS_5_EAX) {
                            restore_reg(drcontext, ilist, NULL, DR_REG_XAX,
                                        SPILL_SLOT_EFLAGS_EAX);
                        }
                    }
                    if (whole_bb_spills_enabled()) {
                        shared_slowpath_restore(drcontext, ilist, r3, SPILL_SLOT_4);
                    } else if (r3 != SPILL_REG3_NOSPILL) {
                        restore_reg(drcontext, ilist, NULL, SPILL_REG3_REG,
                                       spill_reg3_slot(ef == SPILL_EFLAGS_NOSPILL,
                                                       ef != SPILL_EFLAGS_5_EAX &&
                                                       ef != SPILL_EFLAGS_6_EAX,
                                                       r1 >= SPILL_REG_EAX_DEAD &&
                                                       r1 <= SPILL_REG_EBX_DEAD,
                                                       r2 >= SPILL_REG_EAX_DEAD &&
                                                       r2 <= SPILL_REG_EBX_DEAD));
                    }
                    shared_slowpath_save_retaddr(drcontext, ilist, r2);
                    shared_slowpath_restore(drcontext, ilist, r2, SPILL_SLOT_2);
                    shared_slowpath_save_param(drcontext, ilist, r1);
                    shared_slowpath_restore(drcontext, ilist, r1, SPILL_SLOT_1);
                    PRE(ilist, NULL,
                        XINST_CREATE_jump(drcontext,
                                          opnd_create_pc(shared_slowpath_entry)));
                    if (whole_bb_spills_enabled())
                        shared_slowpath_entry_global[r1][r2][r3] = pc;
                    else
                        shared_slowpath_entry_local[r1][r2][r3][ef] = pc;
                    pc = instrlist_encode(drcontext, ilist, pc, true);
                    instrlist_clear(drcontext, ilist);
                }
            }
        }
    }
    return pc;
#else
    /* FIXME i#1726: add ARM port.  Some of the above code was made cross-platform, but
     * the per-scratch-reg code and some of the generated instrs are x86-specific still.
     * We may want to start with just a regular clean call for ARM.
     */
    ASSERT_NOT_IMPLEMENTED();
    return pc;
#endif
}

void
gencode_init(void)
{
#ifdef TOOL_DR_MEMORY
    instrlist_t *ilist;
    void *drcontext = dr_get_current_drcontext();
    byte *pc;
    IF_DEBUG(bool ok;)
#endif

    gencode_lock = dr_mutex_create();

#ifdef STATISTICS
    next_stats_dump = options.stats_dump_interval;
#endif

#ifdef TOOL_DR_MEMORY
    ilist = instrlist_create(drcontext);

    shared_slowpath_region = (byte *)
        nonheap_alloc(SHARED_SLOWPATH_SIZE,
                      DR_MEMPROT_READ|DR_MEMPROT_WRITE|DR_MEMPROT_EXEC,
                      HEAPSTAT_GENCODE);
    pc = shared_slowpath_region;

    pc = generate_shared_slowpath(drcontext, ilist, pc);
    ASSERT(pc - shared_slowpath_region <= SHARED_SLOWPATH_SIZE,
           "shared esp slowpath too large");

    pc = generate_shared_esp_slowpath(drcontext, ilist, pc);
    ASSERT(pc - shared_slowpath_region <= SHARED_SLOWPATH_SIZE,
           "shared esp slowpath too large");
    pc = generate_shared_esp_fastpath(drcontext, ilist, pc);
    ASSERT(pc - shared_slowpath_region <= SHARED_SLOWPATH_SIZE,
           "shared esp fastpath too large");

    instrlist_clear_and_destroy(drcontext, ilist);

    /* now mark as +rx (non-writable) */
    IF_DEBUG(ok = )
        dr_memory_protect(shared_slowpath_region, SHARED_SLOWPATH_SIZE,
                          DR_MEMPROT_READ|DR_MEMPROT_EXEC);
    ASSERT(ok, "-w failed on shared routines gencode");

    DOLOG(2, {
        byte *end_pc = pc;
        pc = shared_slowpath_region;
        LOG(2, "shared_slowpath region:\n");
        while (pc < end_pc) {
            pc = disassemble_with_info(drcontext, pc, f_global,
                                       true/*show pc*/, true/*show bytes*/);
        }
     });
#endif
}

void
gencode_exit(void)
{
    dr_mutex_destroy(gencode_lock);
#ifdef TOOL_DR_MEMORY
    nonheap_free(shared_slowpath_region, SHARED_SLOWPATH_SIZE,
                 HEAPSTAT_GENCODE);
#endif
}

/* PR 525807: try to handle small malloced stacks */
void
update_stack_swap_threshold(void *drcontext, int new_threshold)
{
    IF_DEBUG(bool ok;)
    if (stack_swap_threshold_fixed) {
        /* If user specifies a threshold we disable our dynamic adjustments */
        return;
    }
    LOG(1, "updating stack swap threshold from "PIFX" to "PIFX"\n",
        options.stack_swap_threshold, new_threshold);
    dr_mutex_lock(gencode_lock);
    if (dr_memory_protect(shared_slowpath_region, SHARED_SLOWPATH_SIZE,
                          DR_MEMPROT_READ|DR_MEMPROT_WRITE|DR_MEMPROT_EXEC)) {
        esp_fastpath_update_swap_threshold(drcontext, new_threshold);
        IF_DEBUG(ok = )
            dr_memory_protect(shared_slowpath_region, SHARED_SLOWPATH_SIZE,
                              DR_MEMPROT_READ|DR_MEMPROT_EXEC);
        ASSERT(ok, "-w failed on shared routines gencode");
        options.stack_swap_threshold = new_threshold;
    } else
        ASSERT(false, "+w failed on shared routines gencode");
    dr_mutex_unlock(gencode_lock);
}

#ifdef TOOL_DR_MEMORY
static uint
memref_idx(uint flags, uint i)
{
    return (TEST(MEMREF_SINGLE_BYTE, flags) ? 0 :
            (TEST(MEMREF_SINGLE_WORD, flags) ? (i % 2) :
             (TEST(MEMREF_SINGLE_DWORD, flags) ? (i %4 ) : i)));
}

/* handle_mem_ref checks addressability and if necessary checks
 * definedness and adjusts addressability
 * returns true if no errors were found
 */
bool
handle_mem_ref_internal(uint flags, app_loc_t *loc, app_pc addr, size_t sz,
                        dr_mcontext_t *mc,
                        /* these 2 are required for MEMREF_USE_VALUES */
                        int opnum, shadow_combine_t *comb INOUT)
{
    uint i;
    bool allgood = true;
    /* report ranges of errors instead of individual bytes */
    app_pc bad_addr = NULL, bad_end = NULL;
    /* i#580: can't use NULL as sentinel b/c will not report as unaddr */
    bool found_bad_addr = false;
    uint bad_type = SHADOW_DEFINED; /* i.e., no error */
#ifdef STATISTICS
    bool was_special = options.shadowing ?
        shadow_get_special(addr, NULL) : false;
    bool exception = false;
#endif
    umbra_shadow_memory_info_t info;
    app_pc stack_base = NULL;
    size_t stack_size = 0;
    bool handled_push_addr = false;
    bool is_write =
        /* ADDR is assumed to be for writes only (i#517) */
        TESTANY(MEMREF_WRITE | MEMREF_CHECK_ADDRESSABLE, flags) &&
        !TEST(MEMREF_IS_READ, flags);
    if (options.pattern != 0)
        return pattern_handle_mem_ref(loc, addr, sz, mc, is_write);
    umbra_shadow_memory_info_init(&info);
    ASSERT(options.shadowing, "shadowing disabled");
    LOG(3, "memref: %s @"PFX" "PFX" "PIFX" bytes (pre-dword 0x%02x 0x%02x)%s\n",
        TEST(MEMREF_WRITE, flags) ? (TEST(MEMREF_PUSHPOP, flags) ? "push" : "write") :
        (TEST(MEMREF_PUSHPOP, flags) ? "pop" : "read"), loc_to_print(loc), addr, sz,
        shadow_get_dword(&info, addr), shadow_get_dword(&info, addr+4),
        was_special ? " (was special)" : "");
    ASSERT(addr + sz > addr, "address overflow"); /* no overflow */
    /* xref PR 466036: a very large size and a bogus address can take an
     * extremely long time here, as we query the stack bounds for every
     * single byte: now we cache them but will still be slow.
     */
    /* note that gap compiled by cl has an 18MB rep stos (PR 502506) */
    ASSERT(TEST(MEMREF_ABORT_AFTER_UNADDR, flags) ||
           sz < 32*1024*1024, "suspiciously large size");
    ASSERT(!TEST(MEMREF_USE_VALUES, flags) || comb != NULL,
           "internal invalid parameters");
    /* if no uninit, should only write to shadow mem for push/pop */
    ASSERT(options.check_uninitialized ||
           !TEST(MEMREF_WRITE, flags) ||
           TEST(MEMREF_PUSHPOP, flags), "invalid flags");
#ifdef STATISTICS
    if (TEST(MEMREF_WRITE, flags)) {
        if (TEST(MEMREF_PUSHPOP, flags))
            STATS_INC(push_slowpath);
        else
            STATS_INC(write_slowpath);
    } else {
        if (TEST(MEMREF_PUSHPOP, flags))
            STATS_INC(pop_slowpath);
        else
            STATS_INC(read_slowpath);
    }
#endif
    for (i = 0; i < sz; i++) {
        uint shadow = shadow_get_byte(&info, addr + i);
        ASSERT(shadow <= 3, "internal error");
        if (shadow == SHADOW_UNADDRESSABLE) {
            if (TEST(MEMREF_PUSHPOP, flags) &&
                (!TEST(MEMREF_WRITE, flags) || BEYOND_TOS_REDZONE_SIZE > 0)) {
                ELOG(0, "ERROR: "PFX" popping unaddressable memory: possible Dr. Memory "
                     "bug\n", loc_to_print(loc));
                if (options.pause_at_unaddressable)
                    wait_for_user("popping unaddressable memory!");
            }
            /* XXX: stack ranges: right now we assume that a push makes memory
             * addressable, but really should check if in stack range
             */
            if (TEST(MEMREF_PUSHPOP, flags) && TEST(MEMREF_WRITE, flags)) {
                /* Push without stack redzone */
                ASSERT(!TEST(MEMREF_MOVS, flags), "internal movs error");
                shadow_set_byte(&info, addr + i, TEST(MEMREF_USE_VALUES, flags) ?
                                comb->dst[memref_idx(flags, i)] : SHADOW_DEFINED);
                /* We shouldn't get here for BEYOND_TOS_REDZONE_SIZE > 0 */
                if (BEYOND_TOS_REDZONE_SIZE > 0) {
                    shadow_set_byte(&info, addr + i - BEYOND_TOS_REDZONE_SIZE,
                                    SHADOW_UNDEFINED);
                }
            } else {
                /* We check stack bounds here and cache to avoid
                 * check_undefined_exceptions having to do it over and over (did
                 * show up on pc sampling at one point).  We assume that
                 * mcontext contains the app's esp for all callers (including
                 * our custom clean calls).
                 */
                bool addr_on_stack = false;
                if (stack_base == NULL)
                    stack_size = allocation_size((app_pc)mc->xsp, &stack_base);
                LOG(4, "comparing %08x %08x %08x %08x\n",
                    addr+i, stack_base, stack_base+stack_size, mc->xsp);
                /* We used to also check addr+<xsp but if we mess up our TOS tracking
                 * we end up not reporting any unaddr, as if addr_on_stack is false
                 * then we consider the stack itself an "unknown region" (i#1501).
                 * The risk of going to full stack_size is that our memquery might
                 * see a guard page or something else up there?
                 */
                if (addr+i >= stack_base && addr+i < stack_base+stack_size)
                    addr_on_stack = true;
                if (!check_unaddressable_exceptions(is_write, loc,
                                                    addr + i, sz, addr_on_stack, mc)) {
                    bool new_bad = true;
                    if (found_bad_addr) {
                        if (bad_type != SHADOW_UNADDRESSABLE) {
                            ASSERT(bad_type == SHADOW_UNDEFINED,
                                   "internal report error");
                            report_undefined_read
                                (loc, bad_addr, bad_end + 1 - bad_addr,
                                 addr, addr + sz, mc);
                        } else if (bad_end < addr + i - 1 ||
                                   (TEST(MEMREF_ABORT_AFTER_UNADDR, flags) &&
                                    bad_end + 1 - bad_addr >= MEMREF_ABORT_AFTER_SIZE)) {
                            report_unaddressable_access
                                (loc, bad_addr, bad_end + 1 - bad_addr,
                                 is_write ? DR_MEMPROT_WRITE : DR_MEMPROT_READ,
                                 addr, addr + sz, mc);
                            if (TEST(MEMREF_ABORT_AFTER_UNADDR, flags)) {
                                found_bad_addr = false; /* avoid double-report */
                                break;
                            }
                        } else
                            new_bad = false;
                    }
                    if (new_bad) {
                        found_bad_addr = true;
                        bad_type = SHADOW_UNADDRESSABLE;
                        bad_addr = addr + i;
                    } /* else extend current bad */
                    bad_end = addr + i;
                    /* We follow Memcheck's lead and set to defined to avoid too
                     * many subsequent errors, for undefined.  However, for unaddr,
                     * we leave it that way (to avoid our own asserts if it's on
                     * the stack, and to report later but different accesses to it) --
                     * which works out b/c combine_shadows() will propagate it as
                     * though it were defined (i#1476).
                     */
                    if (addr_on_stack) {
                        LOG(2, "unaddressable beyond TOS: leaving unaddressable\n");
                    } else if (bad_type != SHADOW_UNADDRESSABLE) {
                        shadow_set_byte(&info, addr+i, SHADOW_DEFINED);
                    }
                    allgood = false;
                }
#ifdef STATISTICS
                else {
                    exception = true;
                    LOG(3, "unaddr exception for "PFX"\n", addr+i);
                }
#endif
            }
        } else if (!TESTANY(MEMREF_WRITE | MEMREF_CHECK_ADDRESSABLE, flags)) {
            if (shadow == SHADOW_UNDEFINED) {
                /* Must check for exceptions even if not reporting, since
                 * may alter value of shadow */
                if (!check_undefined_exceptions(TEST(MEMREF_PUSHPOP, flags),
                                                is_write, loc, addr + i, sz, &shadow,
                                                mc, &i) &&
                    TEST(MEMREF_CHECK_DEFINEDNESS, flags)) {
                    bool new_bad = true;
                    if (found_bad_addr) {
                        if (bad_type != SHADOW_UNDEFINED) {
                            ASSERT(bad_type == SHADOW_UNADDRESSABLE,
                                   "internal report error");
                            report_unaddressable_access
                                (loc, bad_addr, bad_end + 1 - bad_addr,
                                 is_write ? DR_MEMPROT_WRITE : DR_MEMPROT_READ,
                                 addr, addr + sz, mc);
                            if (TEST(MEMREF_ABORT_AFTER_UNADDR, flags)) {
                                found_bad_addr = false; /* avoid double-report */
                                break;
                            }
                        } else if (bad_end < addr + i - 1) {
                            report_undefined_read
                                (loc, bad_addr, bad_end + 1 - bad_addr,
                                 addr, addr + sz, mc);
                        } else
                            new_bad = false;
                    }
                    if (new_bad) {
                        found_bad_addr = true;
                        bad_type = SHADOW_UNDEFINED;
                        bad_addr = addr + i;
                    } /* else extend current bad */
                    bad_end = addr + i;
                    allgood = false;
                    /* Set to defined to avoid duplicate errors */
                    if (!options.leave_uninit)
                        shadow_set_byte(&info, addr+i, SHADOW_DEFINED);
                }
#ifdef STATISTICS
                else
                    exception = true;
#endif
            } else if (TEST(MEMREF_CHECK_DEFINEDNESS, flags) &&
                       shadow == SHADOW_DEFINED_BITLEVEL) {
                allgood = false;
                ASSERT(false, "bitlevel NOT YET IMPLEMENTED");
            }
            if (TEST(MEMREF_PUSHPOP, flags)) {
                /* Pop */
                if (BEYOND_TOS_REDZONE_SIZE > 0) {
                    shadow_set_byte(&info, addr + i, SHADOW_UNDEFINED);
                    shadow_set_byte(&info, addr + i - BEYOND_TOS_REDZONE_SIZE,
                                    SHADOW_UNADDRESSABLE);
                } else
                    shadow_set_byte(&info, addr + i, SHADOW_UNADDRESSABLE);
            }
        } else if (!TEST(MEMREF_CHECK_ADDRESSABLE, flags)) {
            uint newval;
            if (TEST(MEMREF_PUSHPOP, flags) &&
                (BEYOND_TOS_REDZONE_SIZE == 0 ||
                 shadow_get_byte(&info, addr + i - BEYOND_TOS_REDZONE_SIZE) !=
                 SHADOW_UNADDRESSABLE)) {
                if (!handled_push_addr) {
                    /* only call once: don't want to mark push target as unaddr,
                     * so each byte will trigger here: avoid extra warnings in logs
                     */
                    handled_push_addr =
                        handle_push_addressable(loc, addr + i, addr, sz, mc);
                }
            }
            if (TEST(MEMREF_PUSHPOP, flags) && TEST(MEMREF_WRITE, flags) &&
                BEYOND_TOS_REDZONE_SIZE > 0) {
                /* Push with stack redzone */
                ASSERT(!TEST(MEMREF_MOVS, flags), "internal movs error");
                shadow_set_byte(&info, addr + i, TEST(MEMREF_USE_VALUES, flags) ?
                                comb->dst[memref_idx(flags, i)] : SHADOW_DEFINED);
                shadow_set_byte(&info, addr + i - BEYOND_TOS_REDZONE_SIZE,
                                SHADOW_UNDEFINED);
            } else {
                if (TEST(MEMREF_MOVS, flags)) {
                    ASSERT(TEST(MEMREF_USE_VALUES, flags), "internal movs error");
                    ASSERT(memref_idx(flags, i) == i, "internal movs error");
                    newval = shadow_get_byte(&info, comb->movs_addr + i);
                } else {
                    newval = TEST(MEMREF_USE_VALUES, flags) ?
                        comb->dst[memref_idx(flags, i)] : SHADOW_DEFINED;
                }
                if (shadow == SHADOW_DEFINED_BITLEVEL ||
                    newval == SHADOW_DEFINED_BITLEVEL) {
                    ASSERT(false, "bitlevel NOT YET IMPLEMENTED");
                } else {
                    if (shadow == newval) {
                        LOG(4, "store @"PFX" to "PFX" w/ already-same-val "PIFX"\n",
                            loc_to_print(loc), addr+i, newval);
                    } else {
                        LOG(4, "store @"PFX" to "PFX" val="PIFX"\n",
                            loc_to_print(loc), addr + i, newval);
                        shadow_set_byte(&info, addr + i, newval);
                    }
                }
            }
        }
        if (!TEST(MEMREF_WRITE, flags) && TEST(MEMREF_USE_VALUES, flags)) {
            ASSERT(!TEST(MEMREF_MOVS, flags), "internal movs error");
            /* combine with current value */
            map_src_to_dst(comb, opnum, memref_idx(flags, i), shadow);
        }
        if (MAP_4B_TO_1B) {
            /* only need to process each 4-byte address region once */
            bool is_bad = (bad_end == addr+i);
            if (POINTER_OVERFLOW_ON_ADD(addr, 4))
                break;
            i = ((ptr_uint_t)ALIGN_FORWARD(addr + i + 1, 4) - (ptr_uint_t)addr);
            if (is_bad)
                bad_end = addr + (i > sz ? sz : i) - 1;
        }
    }
#ifdef STATISTICS
    /* check whether should have hit fast path */
    if (sz > 1 && !ALIGNED(addr, sz) && loc->type != APP_LOC_SYSCALL) {
        if (sz == 8 && ALIGNED(addr, 4)) {
            /* we allow 8-aligned-to-4, but if off block end we'll come here */
            if (((ptr_uint_t)addr & 0xffff) == 0xfffc)
                STATS_INC(slowpath_8_at_border);
        } else
            STATS_INC(slowpath_unaligned);
        DOLOG(3, {
            char buf[MAX_SYMBOL_LEN + MAX_FILENAME_LEN*2/*extra for PRINT_ABS_ADDRESS*/];
            size_t sofar = 0;
            umbra_shadow_memory_info_t info;
            umbra_shadow_memory_info_init(&info);
            print_address(buf, BUFFER_SIZE_BYTES(buf), &sofar, loc_to_pc(loc),
                          NULL, true/*for log*/);
            NULL_TERMINATE_BUFFER(buf);
            LOG(1, "unaligned slow @"PFX" %s "PFX" "PIFX
                " bytes (pre 0x%02x 0x%02x)%s %s ",
                loc_to_print(loc),
                TEST(MEMREF_WRITE, flags) ?
                (TEST(MEMREF_PUSHPOP, flags) ? "push" : "write") :
                (TEST(MEMREF_PUSHPOP, flags) ? "pop" : "read"),
                addr, sz, shadow_get_dword(&info, addr),
                shadow_get_dword(&info, addr+4),
                was_special ? " (was special)" : "", buf);
            disassemble_with_info(dr_get_current_drcontext(), loc_to_pc(loc), f_global,
                                  false/*!show pc*/, true/*show bytes*/);
        });
    }
    if (allgood && !was_special && (sz == 1 || ALIGNED(addr, 4)) && !exception &&
        loc->type != APP_LOC_SYSCALL /* not a system call */) {
        LOG(3, "\tin slow path for unknown reason @"PFX" "PFX"\n", loc_to_pc(loc), addr);
        STATS_INC(slow_instead_of_fast);
    }
#endif
    if (found_bad_addr) {
        if (bad_type == SHADOW_UNDEFINED)
            report_undefined_read(loc, bad_addr, bad_end + 1 - bad_addr,
                                  addr, addr + sz, mc);
        else {
            ASSERT(bad_type == SHADOW_UNADDRESSABLE, "internal report error");
            report_unaddressable_access
                (loc, bad_addr, bad_end + 1 - bad_addr,
                 is_write ? DR_MEMPROT_WRITE : DR_MEMPROT_READ, addr, addr + sz, mc);
        }
    }
    return allgood;
}

/* handle_mem_ref checks addressability and if necessary checks
 * definedness and adjusts addressability
 * returns true if no errors were found
 */
bool
handle_mem_ref(uint flags, app_loc_t *loc, app_pc addr, size_t sz, dr_mcontext_t *mc)
{
    ASSERT(!TEST(MEMREF_USE_VALUES, flags), "using values requires shadow_combine_t");
    return handle_mem_ref_internal(flags, loc, addr, sz, mc, 0, NULL);
}
#endif /* TOOL_DR_MEMORY */

bool
check_mem_opnd(uint opc, uint flags, app_loc_t *loc, opnd_t opnd, uint sz,
               dr_mcontext_t *mc, int opnum, shadow_combine_t *comb INOUT)
{
    app_pc addr = NULL;
#ifdef TOOL_DR_MEMORY
    int i;
#endif

    IF_X86(ASSERT(opc != OP_lea, "lea should not get here"));

#ifdef TOOL_DR_MEMORY
    if (options.check_uninitialized) {
        /* First check definedness of base+index regs */
        for (i = 0; i < opnd_num_regs_used(opnd); i++) {
            reg_id_t reg = opnd_get_reg_used(opnd, i);
            if (!reg_is_segment(reg) &&
                !is_shadow_register_defined(get_shadow_register(reg))) {
                /* FIXME: report which bytes within reg via container params? */
                report_undefined_read
                    (loc, (app_pc)(ptr_int_t)reg,
                     opnd_size_in_bytes(reg_get_size(reg)), NULL, NULL, mc);
                /* Set to defined to avoid duplicate errors */
                register_shadow_mark_defined(reg, opnd_size_in_bytes(reg_get_size(reg)));
            }
        }
    }
#endif

    if (check_mem_opnd_arch(opc, flags, loc, opnd, sz, mc, opnum, comb))
        return true;

    addr = opnd_compute_address(opnd, mc);
    if (opc == OP_pop && !TEST(MEMREF_PUSHPOP, flags) &&
        opnd_is_base_disp(opnd) && opnd_uses_reg(opnd, DR_REG_XSP)) {
        /* XXX i#1502: we probably want a solution coming from DR, but for
         * now we fix this inside DrMem.
         */
        if (opnd_get_base(opnd) == DR_REG_XSP)
            addr += sizeof(void*);
        else if (opnd_get_index(opnd) == DR_REG_XSP) {
            addr += opnd_get_scale(opnd)*sizeof(void*);
        } else {
            tls_util_t *pt = PT_GET(dr_get_current_drcontext());
            ELOGPT(0, pt, "ERROR: unhandled pop into base-disp using esp: ");
            opnd_disassemble(dr_get_current_drcontext(), opnd, pt->f);
            ELOGPT(0, pt, "\n");
            ASSERT(false, "unhandled pop into base-disp using esp");
        }
    }

    if (sz == 0)
        return true;
#ifdef TOOL_DR_MEMORY
    return handle_mem_ref_internal(flags, loc, addr, sz, mc, opnum, comb);
#else
    return handle_mem_ref(flags, loc, addr, sz, mc);
#endif
}

bool
check_mem_opnd_nouninit(uint opc, uint flags, app_loc_t *loc, opnd_t opnd, uint sz,
                        dr_mcontext_t *mc)
{
    ASSERT(!TEST(MEMREF_USE_VALUES, flags), "using values requires shadow_combine_t");
    return check_mem_opnd(opc, flags, loc, opnd, sz, mc, 0, NULL);
}

bool
check_register_defined(void *drcontext, reg_id_t reg, app_loc_t *loc, size_t sz,
                       dr_mcontext_t *mc, instr_t *inst)
{
#ifdef TOOL_DR_MEMORY
    uint shadow = (reg == REG_EFLAGS) ? get_shadow_eflags() : get_shadow_register(reg);
    ASSERT(CHECK_UNINITS(), "shouldn't be called");
    if (reg != REG_EFLAGS && sz < opnd_size_in_bytes(reg_get_size(reg))) {
        /* only check sub-reg piece */
        shadow &= (1 << (sz*2)) - 1;
    }
    if (!is_shadow_register_defined(shadow)) {
        if (!check_undefined_reg_exceptions(drcontext, loc, reg, mc, inst)) {
            /* FIXME: report which bytes within reg via container params? */
            report_undefined_read(loc, (app_pc)(ptr_int_t)reg, sz, NULL, NULL, mc);
            if (reg == REG_EFLAGS) {
                /* now reset to avoid complaining on every branch from here on out */
                set_shadow_eflags(SHADOW_DWORD_DEFINED);
            } else {
                /* Set to defined to avoid duplicate errors */
                register_shadow_mark_defined(reg, sz);
            }
        }
    }
    /* check again, since exception may have marked as defined */
    shadow = (reg == REG_EFLAGS) ? get_shadow_eflags() : get_shadow_register(reg);
    return is_shadow_register_defined(shadow);
#else
    return true;
#endif
}

#ifdef TOOL_DR_MEMORY
/***************************************************************************
 * Module bounds
 *
 * i#412: Mark stack frames as defined in rsaenh.dll to avoid false positives
 * during random number generation.
 *
 * We assume that there are no concurrent rsaenh.dll loads, but there may be
 * other threads in the bb event.  To make sure they never observe any wide
 * intervals such as [0, old_end) during unload, we set the base to POINTER_MAX.
 * This means that no matter the order of updates, the reader will always
 * observe the old rsaenh.dll interval or an empty interval.
 *
 * XXX: Between ntdll, msvcr*, msvcp*, and rsaenh, we have a lot of dlls whose
 * bounds we cache.  Refactor this into a modbounds.c module.
 */

#ifdef WINDOWS
static app_pc rsaenh_base = (app_pc) POINTER_MAX;
static app_pc rsaenh_end = NULL;
#endif /* WINDOWS */

void
slowpath_module_load(void *drcontext, const module_data_t *mod, bool loaded)
{
#ifdef WINDOWS
    if (_stricmp("rsaenh.dll", dr_module_preferred_name(mod)) == 0) {
        rsaenh_base = mod->start;
        rsaenh_end = mod->end;
    }
#endif /* WINDOWS */
}

void
slowpath_module_unload(void *drcontext, const module_data_t *mod)
{
#ifdef WINDOWS
    if (_stricmp("rsaenh.dll", dr_module_preferred_name(mod)) == 0) {
        rsaenh_base = (app_pc) POINTER_MAX;
        rsaenh_end = NULL;
    }
#endif /* WINDOWS */
}

bool
should_mark_stack_frames_defined(app_pc pc)
{
#ifdef WINDOWS
    return (pc >= rsaenh_base && pc < rsaenh_end);
#else
    return false;
#endif
}

/***************************************************************************
 * Unit tests
 */

#ifdef BUILD_UNIT_TESTS
int
main(int argc, char *argv[])
{
    void *drcontext = dr_standalone_init();

    slowpath_unit_tests_arch(drcontext);

    /* add more tests here */

    dr_printf("success\n");
    return 0;
}
#endif

#endif /* TOOL_DR_MEMORY */
