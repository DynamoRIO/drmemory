/* **********************************************************
 * Copyright (c) 2015-2018 Google, Inc.  All rights reserved.
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

bool
opc_is_push(uint opc)
{
    ASSERT_NOT_IMPLEMENTED(); /* FIXME i#1726: NYI */
    return false;
}

bool
opc_is_pop(uint opc)
{
    ASSERT_NOT_IMPLEMENTED(); /* FIXME i#1726: NYI */
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
    ASSERT_NOT_IMPLEMENTED(); /* FIXME i#1726: NYI */
    return false;
}

bool
instr_is_jcc(instr_t *inst)
{
    return instr_is_cbr(inst);
}

bool
opc_is_cmovcc(uint opc)
{
    ASSERT_NOT_IMPLEMENTED(); /* FIXME i#1726: NYI */
    return false;
}

bool
opc_is_fcmovcc(uint opc)
{
    ASSERT_NOT_IMPLEMENTED(); /* FIXME i#1726: NYI */
    return false;
}

/* can 2nd dst be treated as simply an extension of the 1st */
bool
opc_2nd_dst_is_extension(uint opc)
{
    ASSERT_NOT_IMPLEMENTED(); /* FIXME i#1726: NYI */
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
    ASSERT_NOT_IMPLEMENTED(); /* FIXME i#1726: NYI */
    return opnd;
}

/* Some source operands we always check.  Note that we don't need to explicitly
 * list stack pointers or stringop bases as our basedisp checks already
 * look at those registers.
 */
bool
always_check_definedness(instr_t *inst, int opnum)
{
    ASSERT_NOT_IMPLEMENTED(); /* FIXME i#1726: NYI */
    return false;
}

/* For some instructions we check all source operands for definedness. */
bool
instr_check_definedness(instr_t *inst)
{
    ASSERT_NOT_IMPLEMENTED(); /* FIXME i#1726: NYI */
    return false;
}

/***************************************************************************
 * Definedness and Addressability Checking
 */

bool
result_is_always_defined(instr_t *inst, bool natively)
{
    ASSERT_NOT_IMPLEMENTED(); /* FIXME i#1726: NYI */
    return false;
}

#ifdef TOOL_DR_MEMORY
bool
check_undefined_reg_exceptions(void *drcontext, app_loc_t *loc, reg_id_t reg,
                               dr_mcontext_t *mc, instr_t *inst)
{
    ASSERT_NOT_IMPLEMENTED(); /* FIXME i#1726: NYI */
    return false;
}

bool
check_undefined_exceptions(bool pushpop, bool write, app_loc_t *loc, app_pc addr,
                           uint sz, uint *shadow, dr_mcontext_t *mc, uint *idx)
{
    ASSERT_NOT_IMPLEMENTED(); /* FIXME i#1726: NYI */
    return false;
}

/* Opcodes that write to subreg at locations not fixed in the low part of the reg */
bool
opc_dst_subreg_nonlow(int opc)
{
    ASSERT_NOT_IMPLEMENTED(); /* FIXME i#1726: NYI */
    return false;
}

/* Takes the shadow value \p shadow for the \p src_bytenum-th byte in
 * the source operand ordinal \p opnum of instruction \p inst and
 * places it into comb's dst and eflags repositories, combining with
 * what's already there.
 */
void
map_src_to_dst(shadow_combine_t *comb INOUT, int opnum, int src_bytenum, uint shadow)
{
    ASSERT_NOT_IMPLEMENTED(); /* FIXME i#1726: NYI */
}
#endif /* TOOL_DR_MEMORY */

bool
instr_needs_all_srcs_and_vals(instr_t *inst)
{
    ASSERT_NOT_IMPLEMENTED(); /* FIXME i#1726: NYI */
    return false;
}

#ifdef TOOL_DR_MEMORY
/* Returns whether the definedness values changed at all */
bool
check_andor_sources(void *drcontext, dr_mcontext_t *mc, instr_t *inst,
                    shadow_combine_t *comb INOUT, app_pc next_pc)
{
    ASSERT_NOT_IMPLEMENTED(); /* FIXME i#1726: NYI */
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
    ASSERT_NOT_IMPLEMENTED(); /* FIXME i#1726: NYI */
    return instr_num_srcs(inst);
}

int
num_true_dsts(instr_t *inst, dr_mcontext_t *mc /*optional*/)
{
    ASSERT_NOT_IMPLEMENTED(); /* FIXME i#1726: NYI */
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
