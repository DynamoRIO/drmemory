/* **********************************************************
 * Copyright (c) 2015 Google, Inc.  All rights reserved.
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
 * ARM-specific stack adjustment code
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
#include "utils.h"

/***************************************************************************/

/* i#1500: we need to handle this as an esp adjustment */
bool
instr_pop_into_esp(instr_t *inst)
{
    if (instr_is_pop(inst)) {
        bool writes_to_sp = instr_reg_in_dst(inst, DR_REG_XSP);

        if (writes_to_sp)
            return true;
    }
    return false;
}

esp_adjust_t
get_esp_adjust_type(instr_t *inst, bool mangled)
{
    uint opc = instr_get_opcode(inst);

    if (!instr_reg_in_dst(inst, DR_REG_XSP))
        return ESP_ADJUST_INVALID;

    switch (opc) {
    case OP_movz:
    case OP_orr:
    case OP_swp:
        return ESP_ADJUST_ABSOLUTE;
    case OP_ret:
        return ESP_ADJUST_RET_IMMED;
    case OP_str:
    case OP_stp:
    case OP_ldr:
    case OP_ldp:
    case OP_ldur:
        if (instr_reg_in_src(inst, DR_REG_XSP))
            return ESP_ADJUST_POSITIVE;
        else
            return ESP_ADJUST_ABSOLUTE;
    case OP_add:
        if (instr_reg_in_src(inst, DR_REG_XSP))
            return ESP_ADJUST_POSITIVE;
        else
            return ESP_ADJUST_ABSOLUTE;
    case OP_sub:
        if (instr_reg_in_src(inst, DR_REG_XSP))
            return ESP_ADJUST_NEGATIVE;
        else
            return ESP_ADJUST_ABSOLUTE;
    case OP_and:
        if (instr_reg_in_src(inst, DR_REG_XSP))
            return ESP_ADJUST_AND;
        else
            return ESP_ADJUST_ABSOLUTE;
    default:
        return ESP_ADJUST_INVALID;
    }
}

/* assumes that inst does write to esp */
bool
needs_esp_adjust(instr_t *inst, sp_adjust_action_t sp_action)
{
    /* implicit esp changes (e.g., push and pop) are handled during
     * the read/write: this is for explicit esp changes.
     * -leaks_only doesn't care about push, since it writes, or about pop,
     * since shrinking the stack is ignored there.
     */
    uint opc = instr_get_opcode(inst);
    /* -leaks_only doesn't care about shrinking the stack
     * technically OP_leave doesn't have to shrink it: we assume it does
     * (just checking leaks: not huge risk)
     */
    if ((sp_action == SP_ADJUST_ACTION_ZERO) &&
        (opc == OP_ret ||
         (opc == OP_add && opnd_is_immed_int(instr_get_src(inst, 0)) &&
          opnd_get_immed_int(instr_get_src(inst, 0)) >= 0) ||
         (opc == OP_sub && opnd_is_immed_int(instr_get_src(inst, 0)) &&
          opnd_get_immed_int(instr_get_src(inst, 0)) <= 0)))
        return false;


    /* Ignore "or esp,esp" (PR ) */
    if (opc == OP_orr && opnd_is_reg(instr_get_src(inst, 0)) &&
        opnd_is_reg(instr_get_dst(inst, 0)) &&
        opnd_get_reg(instr_get_src(inst, 0)) == REG_XSP &&
        opnd_get_reg(instr_get_dst(inst, 0)) == REG_XSP)
        return false;
    return true;
}

/* Instrument an esp modification that is not also a read or write.
 * Returns whether instrumented.
 */
bool
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

    arg = get_pushpop_offset(inst);

    if (opnd_is_null(arg))
        ASSERT_NOT_REACHED();

    type = get_esp_adjust_type(inst, false/*!mangled*/);
    if (type == ESP_ADJUST_INVALID) {
        tls_util_t *pt = PT_GET(drcontext);
        ELOGPT(0, pt, "ERROR: new stack-adjusting instr: ");
        instr_disassemble(drcontext, inst, pt->f);
        ELOGPT(0, pt, "\n");
        ASSERT(false, "unhandled stack adjustment");
    }

    if (opc == OP_stp) {
        int64 imm = opnd_get_immed_int(arg);
        imm = imm + ((imm > 0) ? -16 : 16);
        arg = OPND_CREATE_INT64(imm);
    }

    dr_insert_clean_call(drcontext, bb, inst,
                            (void *) handle_esp_adjust,
                            false, 3, OPND_CREATE_INT32(type), arg, OPND_CREATE_INT32(sp_action));

    PRE(bb, inst, skip);
    return true;
}


void
esp_fastpath_update_swap_threshold(void *drcontext, int new_threshold)
{
    ASSERT_NOT_IMPLEMENTED();
}

void
generate_shared_esp_fastpath_helper(void *drcontext, instrlist_t *bb,
                                    bool eflags_live,
                                    sp_adjust_action_t sp_action,
                                    esp_adjust_t type)
{
    ASSERT_NOT_IMPLEMENTED();
}

bool
instrument_esp_adjust_fastpath(void *drcontext, instrlist_t *bb, instr_t *inst,
                               bb_info_t *bi, sp_adjust_action_t sp_action)
{
    ASSERT_NOT_IMPLEMENTED();
    return false;
}