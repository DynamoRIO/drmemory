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
 * x86-specific stack adjustment code
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

/***************************************************************************/

/* i#1500: we need to handle this as an esp adjustment */
bool
instr_pop_into_esp(instr_t *inst)
{
    if (instr_get_opcode(inst) == OP_pop) {
        opnd_t dst = instr_get_dst(inst, 0);
        if (opnd_is_reg(dst) && opnd_uses_reg(dst, DR_REG_XSP))
            return true;
    }
    return false;
}

esp_adjust_t
get_esp_adjust_type(instr_t *inst, bool mangled)
{
    uint opc = instr_get_opcode(inst);
    switch (opc) {
    case OP_mov_st:
    case OP_mov_ld:
    case OP_mov_imm:
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
        return ESP_ADJUST_ABSOLUTE;
    case OP_leave:
        return ESP_ADJUST_ABSOLUTE_POSTPOP;
    case OP_pop:
        if (!mangled || instr_pop_into_esp(inst))
            return ESP_ADJUST_ABSOLUTE;
        /* else, fall through: it's a mangled OP_ret */
    case OP_ret:
        return ESP_ADJUST_RET_IMMED;
    case OP_inc:
    case OP_dec:
    case OP_add:
        return ESP_ADJUST_POSITIVE;
    case OP_sub:
        return ESP_ADJUST_NEGATIVE;
    case OP_enter:
        return ESP_ADJUST_NEGATIVE;
    case OP_and:
        return ESP_ADJUST_AND;
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

    type = get_esp_adjust_type(inst, false/*!mangled*/);
    if (type == ESP_ADJUST_INVALID) {
        tls_util_t *pt = PT_GET(drcontext);
        ELOGPT(0, pt, "ERROR: new stack-adjusting instr: ");
        instr_disassemble(drcontext, inst, pt->f);
        ELOGPT(0, pt, "\n");
        ASSERT(false, "unhandled stack adjustment");
    }

    if (options.shared_slowpath) {
        instr_t *retaddr = INSTR_CREATE_label(drcontext);
        scratch_reg_info_t si1 = {
            ESP_SLOW_SCRATCH1, true, false, false, REG_NULL, SPILL_SLOT_1
        };
        scratch_reg_info_t si2 = {
            ESP_SLOW_SCRATCH2, true, false, false, REG_NULL, SPILL_SLOT_2
        };
        reg_id_t arg_tgt;
        if (opnd_is_immed_int(arg))
            opnd_set_size(&arg, OPSZ_PTR);
        if (bi->reg1.reg != REG_NULL) {
            /* use global scratch regs
             * FIXME: opt: generalize and use for fastpath too: but more complex
             * there since have 3 scratches and any one could be the extra local.
             */
            if (bi->reg1.reg == ESP_SLOW_SCRATCH1 || bi->reg2.reg == ESP_SLOW_SCRATCH1)
                si1.dead = true;
            else {
                si1.xchg = (bi->reg1.reg == ESP_SLOW_SCRATCH2) ?
                    bi->reg2.reg : bi->reg1.reg;
            }
            if (bi->reg1.reg == ESP_SLOW_SCRATCH2 || bi->reg2.reg == ESP_SLOW_SCRATCH2)
                si2.dead = true;
            else {
                si2.xchg = (bi->reg1.reg == ESP_SLOW_SCRATCH1) ? bi->reg2.reg :
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
            arg_tgt = ESP_SLOW_SCRATCH1;
            insert_spill_or_restore(drcontext, bb, inst, &si1, true/*save*/, false);
        }
        if (opnd_is_memory_reference(arg)) {
            if (opc == OP_lea) {
                PRE(bb, inst, INSTR_CREATE_lea(drcontext, opnd_create_reg(arg_tgt), arg));
            } else {
                PRE(bb, inst, INSTR_CREATE_mov_ld(drcontext, opnd_create_reg(arg_tgt),
                                                  arg));
            }
        } else {
            if (opnd_is_immed_int(arg)) {
                instrlist_insert_mov_immed_ptrsz(drcontext, opnd_get_immed_int(arg),
                                                 opnd_create_reg(arg_tgt), bb, inst,
                                                 NULL, NULL);
            } else {
                PRE(bb, inst, INSTR_CREATE_mov_st(drcontext, opnd_create_reg(arg_tgt),
                                                  arg));
            }
        }
        if (si1.xchg != REG_NULL) {
            /* now put arg into ecx, and saved ecx into dead xchg-w/ reg */
            insert_spill_or_restore(drcontext, bb, inst, &si1, true/*save*/, false);
        }
        /* spill/xchg edx after, since if xchg can mess up arg's app values */
        insert_spill_or_restore(drcontext, bb, inst, &si2, true/*save*/, false);
        /* we don't need to negate here since handle_adjust_esp() does that */
        PRE(bb, inst,
            INSTR_CREATE_mov_imm(drcontext, opnd_create_reg(ESP_SLOW_SCRATCH2),
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
    if (type != ESP_ADJUST_ABSOLUTE && type != ESP_ADJUST_ABSOLUTE_POSTPOP &&
        type != ESP_ADJUST_AND) {
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
    if (type == ESP_ADJUST_ABSOLUTE || type == ESP_ADJUST_ABSOLUTE_POSTPOP ||
        type == ESP_ADJUST_AND/*abs passed to us*/) {
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
bool
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
    esp_adjust_t type = get_esp_adjust_type(inst, false/*!mangled*/);
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
void
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
    /* We make this signed so that 0xffffffff will encode for x64 as -1. */
    int shadow_dqword_newmem = (sp_action == SP_ADJUST_ACTION_DEFINED ?
                                SHADOW_DQWORD_DEFINED : SHADOW_DQWORD_UNDEFINED);

    IF_X64(ASSERT_NOT_IMPLEMENTED()); /* XXX i#2027: NYI */
    ASSERT(type != ESP_ADJUST_ABSOLUTE_POSTPOP || BEYOND_TOS_REDZONE_SIZE == 0,
           "handling OP_leave properly with a stack redzone in fastpath is NYI");

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
    if (type == ESP_ADJUST_ABSOLUTE || type == ESP_ADJUST_ABSOLUTE_POSTPOP ||
        type == ESP_ADJUST_AND/*abs passed to us*/) {
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
    if (type == ESP_ADJUST_ABSOLUTE || type == ESP_ADJUST_ABSOLUTE_POSTPOP) {
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

/* Caller has made the memory writable and holds a lock */
void
esp_fastpath_update_swap_threshold(void *drcontext, int new_threshold)
{
    int eflags_live;
    sp_adjust_action_t sp_action;
    byte *pc, *end_pc;
    instr_t inst;
    if (!options.esp_fastpath)
        return;
    instr_init(drcontext, &inst);
    /* No shared_esp_fastpath for zeroing. */
    for (sp_action = 0; sp_action <= SP_ADJUST_ACTION_FASTPATH_MAX; sp_action++) {
        for (eflags_live = 0; eflags_live < 2; eflags_live++) {
            /* Only ESP_ADJUST_ABSOLUTE checks for a stack swap: swaps aren't relative,
             * and we assume OP_leave is not used to swap stacks.
             */
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
