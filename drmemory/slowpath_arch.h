/* **********************************************************
 * Copyright (c) 2010-2015 Google, Inc.  All rights reserved.
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
 * slowpath_arch.h: arch-specific internal slowpath declarations
 */

#ifndef _SLOWPATH_ARCH_H_
#define _SLOWPATH_ARCH_H_ 1

#include "dr_api.h"
#include "shadow.h"

/* pusha/popa need 8 dwords, as does a ymm data xfer */
#define MAX_DWORDS_TRANSFER 8
#define OPND_SHADOW_ARRAY_LEN (MAX_DWORDS_TRANSFER * sizeof(uint))

typedef struct _shadow_combine_t {
    /* Array of shadow vals from sources to dests: each uint entry in the
     * array is a shadow for one byte being transferred from source(s) to dest.
     * Larger mem refs either have no transfer (e.g., fxsave), or if
     * they do (rep movs) we handle them specially.
     */
    uint raw[OPND_SHADOW_ARRAY_LEN];
    /* Indirection, to support laying out all srcs side-by-side and not combining any.
     * All references to the array should go through dst instead of raw.
     */
    uint *dst;
    /* Shadow value to write to eflags */
    uint eflags;
    /* The instr we're processing.  This is optional: it can be NULL, but then
     * the code using this struct needs to handle all special data movement
     * on its own, must still set the opcode, and must propagate shadow eflags.
     */
    instr_t *inst;
    /* Must be set */
    uint opcode;
    /* These must be set when processing sources, and thus when calling
     * check_mem_opnd() or integrate_register_shadow() for non-eflag sources.
     * These exist to support artificial constructions.  They should not be
     * extract from inst (it's a little fragile -- we kind of rely on only
     * accessing inst for certain types of instrs that we never fake).
     */
#ifdef DEBUG
    bool opnd_valid; /* whether opnd and opsz are set */
#endif
    opnd_t opnd;
    size_t opsz; /* in bytes */
    /* For handling OP_movs */
    byte *movs_addr;
} shadow_combine_t;

static inline uint
combine_shadows(uint shadow1, uint shadow2)
{
    /* This routine only looks at two one-byte values.
     * We ignore BITLEVEL for now.
     * We assume UNADDR will be reported, and we want to propagate
     * defined afterward in any case to avoid chained errors (xref i#1476).
     */
    ASSERT((shadow1 & ~0xf) == 0 && (shadow2 & ~0xf) == 0, "non-byte shadows");
    return (shadow1 == SHADOW_UNDEFINED || shadow2 == SHADOW_UNDEFINED) ?
        SHADOW_UNDEFINED : SHADOW_DEFINED;
}

static inline void
accum_shadow(uint *shadow1, uint shadow2)
{
    *shadow1 = combine_shadows(*shadow1, shadow2);
}

static inline void
shadow_combine_set_opnd(shadow_combine_t *comb, opnd_t opnd, uint opsz)
{
    comb->opnd = opnd;
    comb->opsz = opsz;
#ifdef DEBUG
    comb->opnd_valid = true;
#endif
}

/* comb is a shadow_combine_t* */
#ifdef DEBUG
# define SHADOW_COMBINE_CHECK_OPND(comb, bytenum) do {\
    ASSERT((comb)->opnd_valid, "have to set opnd");   \
    if ((bytenum) + 1 == (comb)->opsz)                \
        (comb)->opnd_valid = false;                   \
} while (0)
#else
# define SHADOW_COMBINE_CHECK_OPND(comb, bytenum) /* nothing */
#endif

void
shadow_combine_init(shadow_combine_t *comb, instr_t *inst, uint opcode, uint max);

/* Opcodes that write to subreg at locations not fixed in the low part of the reg */
bool
opc_dst_subreg_nonlow(int opc);

bool
instr_propagatable_dsts(instr_t *inst);

bool
instrs_share_opnd(instr_t *in1, instr_t *in2);

bool
get_cur_src_value(void *drcontext, instr_t *inst, uint i, reg_t *val);

void
register_shadow_mark_defined(reg_id_t reg, size_t sz);

/* Takes the shadow value \p shadow for the \p src_bytenum-th byte in
 * the source operand ordinal \p opnum of instruction \p inst and
 * places it into comb's dst and eflags repositories, combining with
 * what's already there.
 */
void
map_src_to_dst(shadow_combine_t *comb INOUT, int opnum, int src_bytenum, uint shadow);

/* Returns whether the definedness values changed at all */
bool
check_andor_sources(void *drcontext, dr_mcontext_t *mc, instr_t *inst,
                    shadow_combine_t *comb INOUT, app_pc next_pc);

/* Returns whether to skip the general integration */
bool
integrate_register_shadow_arch(shadow_combine_t *comb INOUT, int opnum,
                               reg_id_t reg, uint shadow, bool pushpop);

/* Returns whether to skip the general assignment code */
bool
assign_register_shadow_arch(shadow_combine_t *comb INOUT, int opnum, opnd_t opnd,
                            reg_id_t reg, bool pushpop, uint *shift INOUT);

/* Returns whether it handled the instruction */
bool
medium_path_arch(app_pc decode_pc, app_loc_t *loc, dr_mcontext_t *mc);

void
slowpath_update_app_loc_arch(uint opc, app_pc decode_pc, app_loc_t *loc);

bool
check_mem_opnd(uint opc, uint flags, app_loc_t *loc, opnd_t opnd, uint sz,
               dr_mcontext_t *mc, int opnum, shadow_combine_t *comb INOUT);

bool
check_mem_opnd_arch(uint opc, uint flags, app_loc_t *loc, opnd_t opnd, uint sz,
                    dr_mcontext_t *mc, int opnum, shadow_combine_t *comb INOUT);

bool
check_undefined_exceptions(bool pushpop, bool write, app_loc_t *loc, app_pc addr,
                           uint sz, uint *shadow, dr_mcontext_t *mc, uint *idx);

bool
check_undefined_reg_exceptions(void *drcontext, app_loc_t *loc, reg_id_t reg,
                               dr_mcontext_t *mc, instr_t *inst);

#if defined(TOOL_DR_MEMORY) && defined(BUILD_UNIT_TESTS)
void
slowpath_unit_tests_arch(void *drcontext);
#endif

#endif /* _SLOWPATH_ARCH_H_ */
