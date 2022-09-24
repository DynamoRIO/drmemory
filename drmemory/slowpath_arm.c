/* **********************************************************
 * Copyright (c) 2015-2022 Google, Inc.  All rights reserved.
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
 * slowpath_arm.c: Dr. Memory memory read/write slowpath handling for ARM
 */

#include "dr_api.h"
#include "dr_defines.h"
#include "dr_ir_instr.h"
#include "dr_ir_opcodes_aarch64.h"
#include "dr_ir_opnd.h"
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

/***************************************************************************
 * ISA
 */

bool
reg_is_8bit(reg_id_t reg)
{
    return false; /* no 8-bit GPR: SIMD don't count */
}

bool
reg_is_8bit_high(reg_id_t reg)
{
    return false; /* no 8-bit GPR: SIMD don't count */
}

bool
reg_is_16bit(reg_id_t reg)
{
    return false; /* no 8-bit GPR: SIMD don't count */
}

bool
reg_offs_in_dword(reg_id_t reg)
{
    return 0;
}

opnd_t
get_pushpop_offset(instr_t *inst){
    uint opc = instr_get_opcode(inst);
        /* Call handle_esp_adjust */
    opnd_t arg;
    switch(opc){
        case OP_sub:
        case OP_add:
            arg = instr_get_src(inst, 1);
            break;
        case OP_stp:

            arg = instr_get_src(inst, 3);
            break;
        case OP_str:
        case OP_ldr:
        case OP_ldp:
            arg = instr_get_src(inst, 2);
            break;
        default:
            return opnd_create_null();
    }
    return arg;
}

bool
opc_is_push(uint opc)
{
    if ((opc == OP_str || opc == OP_strb || opc == OP_strh || opc == OP_stur || opc == OP_stp)){
        return true;
    }

    return false;
}

bool
instr_is_push(instr_t *instr)
{
    if (!opc_is_push(instr_get_opcode(instr)))
        return false;

    bool writes_to_stack = false;
    uint num_dsts = instr_num_dsts(instr);
    for (uint i =0;i<num_dsts;i++){
        if (opnd_uses_reg(instr_get_dst(instr, i), DR_REG_XSP) && opnd_is_memory_reference(instr_get_dst(instr, i)))
            writes_to_stack = true;
    }
    if (!writes_to_stack)
        return false;

    for (uint i =0;i<num_dsts;i++){
        if (opnd_uses_reg(instr_get_dst(instr, i), DR_REG_XSP) && opnd_is_reg(instr_get_dst(instr, i)))
            return true;
    }
    return false;
}

bool
opc_is_pop(uint opc)
{
    if ((opc == OP_ldr || opc == OP_ldrb || opc == OP_ldrh || opc == OP_ldur || opc == OP_ldp)){
        return true;
    }
    return false;
}

bool
instr_is_pop(instr_t *instr)
{
    if (!opc_is_pop(instr_get_opcode(instr)))
        return false;

    bool reads_off_stack = false;
    uint num_srcs = instr_num_srcs(instr);
    for (uint i =0;i<num_srcs;i++){
        if (opnd_uses_reg(instr_get_src(instr, i), DR_REG_XSP) && opnd_is_memory_reference(instr_get_src(instr, i)))
            reads_off_stack = true;
    }
    if (!reads_off_stack)
        return false;

    uint num_dsts = instr_num_dsts(instr);
    for (uint i =0;i<num_dsts;i++){
        if (opnd_uses_reg(instr_get_dst(instr, i), DR_REG_XSP) && opnd_is_reg(instr_get_dst(instr, i)))
            return true;
    }
    return false;
}


bool
opc_is_stringop_loop(uint opc)
{
    return false;
}

bool
opc_is_stringop(uint opc)
{
    return false;
}

bool
opc_is_loopcc(uint opc)
{
    return false;
}

bool
opc_is_gpr_shift(uint opc)
{
    return (opc == OP_lslv || opc == OP_lsrv || opc == OP_asrv ||
            opc == OP_rorv || opc == OP_ubfm || opc == OP_extr);
}

bool
instr_is_jcc(instr_t *inst)
{
    return instr_is_cbr(inst);
}

bool
opc_is_cmovcc(uint opc)
{
    return false;
}

bool
opc_is_fcmovcc(uint opc)
{
    return false;
}

/* can 2nd dst be treated as simply an extension of the 1st */
bool
opc_2nd_dst_is_extension(uint opc)
{
    return false;
}

bool
reg_is_shadowed(int opc, reg_id_t reg)
{
    /* i#471: we don't yet shadow floating-point regs */
    return reg_is_gpr(reg);
}

bool
xax_is_used_subsequently(instr_t *inst)
{
    return false;
}

uint
adjust_memop_push_offs(instr_t *inst)
{
    return 0;
}

opnd_t
adjust_memop(instr_t *inst, opnd_t opnd, bool write, uint *opsz, bool *pushpop_stackop)
{
    /* DR's IR now properly encodes push sizes (DRi#164), except for OP_enter */
    uint sz = opnd_size_in_bytes(opnd_get_size(opnd));
    bool push = instr_is_push(inst);
    bool pop = instr_is_pop(inst);
    bool pushpop = false; /* is mem ref on stack for push/pop */
    if (opnd_uses_reg(opnd, DR_REG_XSP)) {
        if (write && push && opnd_is_base_disp(opnd)) {
            uint extra_push_sz = adjust_memop_push_offs(inst);
            pushpop = true;
            if (extra_push_sz > 0) {
                sz += extra_push_sz;
                opnd_set_disp(&opnd, opnd_get_disp(opnd) - sz);
            }
        } else if (!write && pop && opnd_is_base_disp(opnd)) {
            if (!instr_pop_into_esp(inst))
                pushpop = true;
        }
    }
    /* we assume only +w ref for push (-w for pop) is the stack adjust */
    ASSERT(pushpop || ((!write || !push) && (write || !pop)) || instr_pop_into_esp(inst),
           "internal stack op bad assumption");
    *opsz = sz;
    *pushpop_stackop = pushpop;
    return opnd;
}

/* Some source operands we always check.  Note that we don't need to explicitly
 * list stack pointers or stringop bases as our basedisp checks already
 * look at those registers.
 */
bool
always_check_definedness(instr_t *inst, int opnum)
{
    uint opc = instr_get_opcode(inst);
    return (opc_is_gpr_shift(opc) && opnum == 0);
}

// TODO: make sub functions for checks like these, like instr_is_exclusive_store(instr_t *instr)
static bool
opc_is_move(uint opc)
{
    return (opc == OP_ldrb || opc == OP_ldrh || opc == OP_ldr || opc == OP_ldur || opc == OP_ldr ||
            opc == OP_strb || opc == OP_strh || opc == OP_str || opc == OP_stur || opc == OP_str || opc == OP_swp ||
            opc == OP_movz || opc == OP_movk || opc == OP_movn ||
            opc == OP_add || opc == OP_orr);
}

/* For some instructions we check all source operands for definedness. */
bool
instr_check_definedness(instr_t *inst)
{
    uint opc = instr_get_opcode(inst);
    return
        /* always check conditional jumps */
        instr_is_cbr(inst) ||
        (options.check_uninit_non_moves && !opc_is_move(opc)) ||
        options.check_uninit_all ||
        (options.check_uninit_cmps &&
         /* a compare writes eflags but nothing else, or is a loop, cmps, or cmovcc.
          * for cmpxchg* only some operands are compared: see always_check_definedness.
          */
         ((instr_num_dsts(inst) == 0 &&
           TESTANY(EFLAGS_WRITE_ALL, instr_get_eflags(inst, DR_QUERY_INCLUDE_ALL))) ||
          opc == OP_subs)) ||
        (!instr_propagatable_dsts(inst) &&
         !TESTANY(EFLAGS_WRITE_ALL, instr_get_eflags(inst, DR_QUERY_INCLUDE_ALL)) &&
         /* though prefetch has nowhere to propagate uninit shadow vals to, we
          * do not want to raise errors.  so we ignore, under the assumption
          * that a real move will happen soon enough to propagate: if not,
          * little harm done.  i#244.
          */
         !instr_is_prefetch(inst));
}

/***************************************************************************
 * Definedness and Addressability Checking
 */

bool
result_is_always_defined(instr_t *inst, bool natively)
{
    /* Even if source operands are undefined, don't consider this instr as
     * reading undefined values if:
     * 1) clearing/setting all bits via:
     *   - and with 0
     *   - or with ~0
     *   - xor with self
     *   - packed subtract with self
     *   - sbb with self (PR 425498): now handled via num_true_srcs since must
     *     propagate eflags (PR 425622)
     */
    int opc = instr_get_opcode(inst);

#ifdef TOOL_DR_MEMORY
    /* i#1529: mark an entire module defined */
    if (!natively && options.check_uninit_blocklist[0] != '\0') {
        /* Fastpath should have already checked the cached value in
         * bb_info_t.mark_defined, so we should only be paying this
         * cost for each slowpath entry.
         */
        app_pc pc = instr_get_app_pc(inst) != NULL ?
            instr_get_app_pc(inst) : instr_get_raw_bits(inst);
        if (module_is_on_check_uninit_blocklist(pc)) {
            LOG(3, "module is on uninit blocklist: always defined\n");
            return true;
        }
    }
#endif

    /* Though our general non-const per-byte 0/1 checking would cover this,
     * we optimize by looking for entire-dword consts up front
     */
    if ((opc == OP_and &&
         opnd_is_immed_int(instr_get_src(inst, 0)) &&
         opnd_get_immed_int(instr_get_src(inst, 0)) == 0) ||
        (opc == OP_ands &&
         opnd_is_immed_int(instr_get_src(inst, 1)) &&
         opnd_get_immed_int(instr_get_src(inst, 1)) == 0) ||
        (opc == OP_orr &&
         opnd_is_immed_int(instr_get_src(inst, 1)) &&
         opnd_get_immed_int(instr_get_src(inst, 1)) == ~0) ||
        ((opc == OP_eor) &&
         opnd_same(instr_get_src(inst, 0), instr_get_src(inst, 1)))) {
        STATS_INC(andor_exception);
        return true;
    }
    return false;
}

#ifdef TOOL_DR_MEMORY
/* All current non-syscall uses already have inst decoded so we require it
 * for efficiency
 */
bool
check_undefined_reg_exceptions(void *drcontext, app_loc_t *loc, reg_id_t reg,
                               dr_mcontext_t *mc, instr_t *inst)
{
    return false;
}

bool
check_undefined_exceptions(bool pushpop, bool write, app_loc_t *loc, app_pc addr,
                           uint sz, uint *shadow, dr_mcontext_t *mc, uint *idx)
{
    return false;
}


/* Opcodes that write to subreg at locations not fixed in the low part of the reg */
bool
opc_dst_subreg_nonlow(int opc)
{
    switch (opc) {
    case OP_bfm:
    case OP_sbfm:
    case OP_ubfm:
    case OP_lslv:
    case OP_lsrv:
    case OP_asrv:
        return true;
    }
    return false;
}

/* Same base interface as map_src_to_dst(), but this one takes in an
 * arbitrary opcode that can differ from comb->opcode, a per-element
 * src_bytenum, an offset for the dst bytenum, and a per-element opsz,
 * allowing for use on packed shifts as well as GPR shifts.
 */
static bool
map_src_to_dst_shift(shadow_combine_t *comb INOUT, uint opc, int opnum, int src_bytenum,
                     uint src_offs, uint opsz, uint shadow)
{
    reg_t shift;
    /* Be sure to use opsz, the element size, NOT comb->opsz; similarly, use
     * the passed-in opc, NOT comb->opcode, for the operation.
     */
    ASSERT(comb->inst != NULL, "need inst for shifts");
    ASSERT(opc_is_gpr_shift(comb->opcode),
           "unknown shift");
    if (!get_cur_src_value(dr_get_current_drcontext(), comb->inst, 0, &shift)) {
        ASSERT(false, "failed to get shift amount");
        /* graceful failure */
        return false;
    }
    LOG(4, " src bytenum %d, offs %d, opsz %d, shift %d\n", src_bytenum, src_offs,
        opsz, shift);
    if (shift > opsz*8)
        shift = opsz*8; /* XXX i#101: for a rotate we want shift % (opsz*8) */
    if (shift == 0) {
        /* no flags are changed for shift==0 */
        accum_shadow(&comb->dst[src_offs + src_bytenum], shadow);
        return true;
    }
    if (opc == OP_lslv) {
        /* If shift % 8 != 0 we touch two bytes: */
        int map1 = src_bytenum + shift/8;
        int map2 = src_bytenum + (shift-1)/8 + 1;
        if (map1 >= opsz) {
            if (map1 == opsz) {
                /* bit shifted off goes to CF */
                LOG(4, "  accum eflags %d + %d\n", comb->eflags, shadow);
                accum_shadow(&comb->eflags, shadow);
            }
            /* shifted off the end */
            return true;
        }
        LOG(4, "  accum @%d %d + %d\n", src_offs + map1, comb->dst[src_offs + map1],
            shadow);
        accum_shadow(&comb->dst[src_offs + map1], shadow);
        if (map1 != map2 && map2 < opsz) {
            LOG(4, "  accum @%d %d + %d\n", src_offs + map2, comb->dst[src_offs + map2],
                shadow);
            accum_shadow(&comb->dst[src_offs + map2], shadow);
        }
        accum_shadow(&comb->eflags, shadow);
        return true;
    } else if (opc == OP_lsrv || opc == OP_asrv) {
        /* If shift % 8 != 0 we touch two bytes: */
        int map1 = src_bytenum - shift/8;
        int map2 = src_bytenum - ((shift-1)/8 + 1);
        if (opc == OP_asrv && src_bytenum == opsz - 1) {
            /* Top bit is what's shifted in */
            int i;
            for (i = 0; i <= shift/8 && i < opsz; i ++)
                accum_shadow(&comb->dst[src_offs + opsz - 1 - i], shadow);
            accum_shadow(&comb->eflags, shadow);
            return true;
        }
        if (map1 >= 0) { /* if not shifted off the end */
            LOG(4, "  accum @%d %d + %d\n", src_offs + map1, comb->dst[src_offs + map1],
                shadow);
            accum_shadow(&comb->dst[src_offs + map1], shadow);
        }
        if (map1 != map2 && map2 >= 0) {
            LOG(4, "  accum @%d %d + %d\n", src_offs + map2, comb->dst[src_offs + map2],
                shadow);
            accum_shadow(&comb->dst[src_offs + map2], shadow);
        }
        accum_shadow(&comb->eflags, shadow);
        /* We assume we don't need to proactively mark the top now-0 bits
         * as defined for OP_shr b/c our method of combining starts w/ defined
         */
        return true;
    } else {
        /* FIXME i#101: add rotate opcodes + shrd/shld */
    }
    return false; /* unhandled */
}

/* Takes the shadow value \p shadow for the \p src_bytenum-th byte in
 * the source operand ordinal \p opnum of instruction \p inst and
 * places it into comb's dst and eflags repositories, combining with
 * what's already there.
 */
void
map_src_to_dst(shadow_combine_t *comb INOUT, int opnum, int src_bytenum, uint shadow)
{
    int opc = comb->opcode;

    if (opc_is_gpr_shift(opc)) {
        if (map_src_to_dst_shift(comb, comb->opcode, opnum, src_bytenum, 0,
                                 comb->opsz, shadow)) {
            SHADOW_COMBINE_CHECK_OPND(comb, src_bytenum);
            return; /* handled */
        }
    }

    switch (opc) {
    default:
        accum_shadow(&comb->dst[src_bytenum], shadow);
       break;
    }

    /* By default all source bytes influence eflags.  If an opcode wants to do
     * otherwise it needs to return prior to here.
     */
    if (comb->inst != NULL &&
        TESTANY(EFLAGS_WRITE_ALL, instr_get_eflags(comb->inst, DR_QUERY_INCLUDE_ALL)))
        accum_shadow(&comb->eflags, shadow);
    return;
}
#endif /* TOOL_DR_MEMORY */

bool
instr_needs_all_srcs_and_vals(instr_t *inst)
{
    /* For bitwise and + or we need to know the shadow value and the real value
     * of all sources before we can decide whether any one source's
     * undefinedness is an issue!
     */
    int opc = instr_get_opcode(inst);
    return (opc == OP_and || opc == OP_ands || opc == OP_orr || opc == OP_eor);
}

#ifdef TOOL_DR_MEMORY

/* Caller has already checked that "val" is defined */

/* Returns whether the definedness values changed at all */
bool
check_andor_sources(void *drcontext, dr_mcontext_t *mc, instr_t *inst,
                    shadow_combine_t *comb INOUT, app_pc next_pc)
{
    return false;
}

/* Returns whether to skip the general integration */
bool
integrate_register_shadow_arch(shadow_combine_t *comb INOUT, int opnum,
                               reg_id_t reg, uint shadow, bool pushpop)
{
    return false;
}

/* Returns whether to skip the general assignment code */
bool
assign_register_shadow_arch(shadow_combine_t *comb INOUT, int opnum, opnd_t opnd,
                            reg_id_t reg, bool pushpop, uint *shift INOUT)
{
    return false;
}
#endif /* TOOL_DR_MEMORY */

int
num_true_srcs(instr_t *inst, dr_mcontext_t *mc /*optional*/)
{
    int opc = instr_get_opcode(inst);
    /* sbc with self should consider all srcs except eflags defined (thus can't
     * be in result_is_always_defined) (PR 425498, PR 425622)
     */
    if (opc == OP_sbc && opnd_same(instr_get_src(inst, 0), instr_get_src(inst, 1)))
        return 0;

    return instr_num_srcs(inst);
}

int
num_true_dsts(instr_t *inst, dr_mcontext_t *mc /*optional*/)
{
    return instr_num_dsts(inst);
}

#ifdef TOOL_DR_MEMORY
/* Returns whether it handled the instruction */
bool
medium_path_arch(app_pc decode_pc, app_loc_t *loc, dr_mcontext_t *mc)
{
    return false;
}
#endif /* TOOL_DR_MEMORY */

void
slowpath_update_app_loc_arch(uint opc, app_pc decode_pc, app_loc_t *loc)
{
}

bool
check_mem_opnd_arch(uint opc, uint flags, app_loc_t *loc, opnd_t opnd, uint sz,
                    dr_mcontext_t *mc, int opnum, shadow_combine_t *comb INOUT)
{
    return false;
}

#ifdef TOOL_DR_MEMORY
/***************************************************************************
 * Unit tests
 */

#ifdef BUILD_UNIT_TESTS
void
slowpath_unit_tests_arch(void *drcontext)
{
    /* add more tests here */
}
#endif

#endif /* TOOL_DR_MEMORY */
