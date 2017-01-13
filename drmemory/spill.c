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
 * spill.c: Dr. Memory scratch register spilling
 */

#include "dr_api.h"
#include "drreg.h"
#include "utils.h"
#include "client_per_thread.h"
#include "options.h"
#include "spill.h"
#include "instru.h"
#include "slowpath.h"
#include "replace.h"
#include "shadow.h"
#include "fastpath.h"

#include <stddef.h> /* offsetof */

/***************************************************************************
 * We allocate our own register spill slots for faster access than
 * the non-directly-addressable DR slots (only 3 are direct).
 */

/* Indirection to allow us to switch which TLS slots we use for spill slots */
#define MAX_FAST_DR_SPILL_SLOT SPILL_SLOT_3

/* We used to store segment bases in some TLS slots that were followed by the
 * reg spill slots, but now that DR has API support for bases we don't need them
 * anymore:
 */
#define NUM_INSTRU_TLS_SLOTS 0

/* drreg allocates our reg spill slots in pattern mode */
#define NUM_TLS_SLOTS \
    (NUM_INSTRU_TLS_SLOTS + (options.pattern == 0 ? options.num_spill_slots : 0))

reg_id_t seg_tls;

/* the offset of our tls_instr_t + reg spill tls slots */
static uint tls_instru_base;

/* we store a pointer in regular tls for access to other threads' TLS */
static int tls_idx_instru = -1;

byte *
get_own_seg_base(void)
{
#ifdef WINDOWS
    return (byte *) get_TEB();
#else
    return dr_get_dr_segment_base(seg_tls);
#endif
}

static bool
handle_drreg_error(drreg_status_t status)
{
    ASSERT(false, "drreg bb event failure");
    /* XXX: can we share the tool crash message? */
    NOTIFY_ERROR("FATAL ERROR: internal register failure %d: please report this", status);
    dr_abort();
    return true; /* we handled it */
}

void
instru_tls_init(void)
{
    if (options.pattern != 0) {
        drreg_options_t ops = {
            sizeof(ops), options.num_spill_slots, options.conservative,
            handle_drreg_error,
        };
        IF_DEBUG(drreg_status_t res =)
            drreg_init(&ops);
        ASSERT(res == DRREG_SUCCESS, "fatal error: failed to initialize drreg");
    }
    if (NUM_TLS_SLOTS > 0) {
        IF_DEBUG(bool ok =)
            dr_raw_tls_calloc(&seg_tls, &tls_instru_base, NUM_TLS_SLOTS, 0);
        ASSERT(ok, "fatal error: unable to reserve tls slots");
        LOG(2, "TLS spill base: "PIFX"\n", tls_instru_base);
        tls_idx_instru = drmgr_register_tls_field();
        ASSERT(tls_idx_instru > -1, "failed to reserve TLS slot");
        ASSERT(seg_tls == EXPECTED_SEG_TLS, "unexpected tls segment");
    } else {
        /* We still need the seg base.
         * XXX: DR should provide an API to retrieve it w/o allocating slots!
         */
        if (dr_raw_tls_calloc(&seg_tls, &tls_instru_base, 1, 0)) {
            dr_raw_tls_cfree(tls_instru_base, 1);
        } else {
            /* Fall back to hardcoded defaults */
#ifdef X86
# ifdef X64
            seg_tls = DR_SEG_GS;
# else
            seg_tls = DR_SEG_FS;
# endif
#elif defined(ARM)
# ifdef X64
            seg_tls = DR_REG_TPIDRURO;
# else
            seg_tls = DR_REG_TPIDRURW;
# endif
#endif
        }
    }
}

void
instru_tls_exit(void)
{
    if (NUM_TLS_SLOTS > 0) {
        IF_DEBUG(bool ok =)
            dr_raw_tls_cfree(tls_instru_base, NUM_TLS_SLOTS);
        ASSERT(ok, "WARNING: unable to free tls slots");
        drmgr_unregister_tls_field(tls_idx_instru);
    }
    if (options.pattern != 0) {
        IF_DEBUG(drreg_status_t res =)
            drreg_exit();
        ASSERT(res == DRREG_SUCCESS, "WARNING: drreg failed on exit");
    }
}

void
instru_tls_thread_init(void *drcontext)
{
#ifdef UNIX
    /* We used to acquire the app's fs and gs bases (via opnd_compute address on
     * a synthetic far-base-disp opnd) but with early injection they aren't set
     * up yet, and we'd need to do work to handle changes: instead, now that
     * DR supplies dr_insert_get_seg_base(), we just use that.
     */
    LOG(1, "dr: TLS base="PFX"\n", dr_get_dr_segment_base(seg_tls));
#endif
    if (NUM_TLS_SLOTS > 0) {
        /* store in per-thread data struct so we can access from another thread */
        drmgr_set_tls_field(drcontext, tls_idx_instru, (void *)
                            (get_own_seg_base() + tls_instru_base));
    }
}

void
instru_tls_thread_exit(void *drcontext)
{
    if (NUM_TLS_SLOTS > 0)
        drmgr_set_tls_field(drcontext, tls_idx_instru, NULL);
}

uint
num_own_spill_slots(void)
{
    return options.num_spill_slots;
}

static opnd_t
opnd_create_own_spill_slot(uint index)
{
    ASSERT(index < options.num_spill_slots, "spill slot index overflow");
    ASSERT(INSTRUMENT_MEMREFS(), "incorrectly called");
    return opnd_create_far_base_disp_ex
        /* must use 0 scale to match what DR decodes for opnd_same */
        (seg_tls, REG_NULL, REG_NULL, 0,
         tls_instru_base + (NUM_INSTRU_TLS_SLOTS + index)*sizeof(ptr_uint_t), OPSZ_PTR,
         /* we do NOT want an addr16 prefix since most likely going to run on
          * Core or Core2, and P4 doesn't care that much */
         false, true, false);
}

ptr_uint_t
get_own_tls_value(uint index)
{
    ASSERT(NUM_TLS_SLOTS > 0, "should not get here if we have no slots");
    if (index < options.num_spill_slots) {
        byte *seg_base = get_own_seg_base();
        return *(ptr_uint_t *) (seg_base + tls_instru_base +
                                (NUM_INSTRU_TLS_SLOTS + index)*sizeof(ptr_uint_t));
    } else {
        dr_spill_slot_t DR_slot = index - options.num_spill_slots;
        return dr_read_saved_reg(dr_get_current_drcontext(), DR_slot);
    }
}

void
set_own_tls_value(uint index, ptr_uint_t val)
{
    ASSERT(NUM_TLS_SLOTS > 0, "should not get here if we have no slots");
    if (index < options.num_spill_slots) {
        byte *seg_base = get_own_seg_base();
        *(ptr_uint_t *)(seg_base + tls_instru_base +
                        (NUM_INSTRU_TLS_SLOTS + index)*sizeof(ptr_uint_t)) = val;
    } else {
        dr_spill_slot_t DR_slot = index - options.num_spill_slots;
        dr_write_saved_reg(dr_get_current_drcontext(), DR_slot, val);
    }
}

ptr_uint_t
get_thread_tls_value(void *drcontext, uint index)
{
    ASSERT(NUM_TLS_SLOTS > 0, "should not get here if we have no slots");
    if (index < options.num_spill_slots) {
        byte *tls = (byte *) drmgr_get_tls_field(drcontext, tls_idx_instru);
        return *(ptr_uint_t *)
            (tls + (NUM_INSTRU_TLS_SLOTS + index)*sizeof(ptr_uint_t));
    } else {
        dr_spill_slot_t DR_slot = index - options.num_spill_slots;
        return dr_read_saved_reg(drcontext, DR_slot);
    }
}

void
set_thread_tls_value(void *drcontext, uint index, ptr_uint_t val)
{
    ASSERT(NUM_TLS_SLOTS > 0, "should not get here if we have no slots");
    if (index < options.num_spill_slots) {
        byte *tls = (byte *) drmgr_get_tls_field(drcontext, tls_idx_instru);
        *(ptr_uint_t *)
            (tls + (NUM_INSTRU_TLS_SLOTS + index)*sizeof(ptr_uint_t)) = val;
    } else {
        dr_spill_slot_t DR_slot = index - options.num_spill_slots;
        dr_write_saved_reg(drcontext, DR_slot, val);
    }
}

ptr_uint_t
get_raw_tls_value(uint offset)
{
#ifdef X86
    ptr_uint_t val;
# ifdef WINDOWS
    val = *(ptr_uint_t *)(((byte *)get_TEB()) + offset);
# else
#  ifdef X64
    asm("movzbq %0, %%"ASM_XAX : : "m"(offset) : ASM_XAX);
#  else
    asm("movzbl %0, %%"ASM_XAX : : "m"(offset) : ASM_XAX);
#  endif
    asm("mov %%"ASM_SEG":(%%"ASM_XAX"), %%"ASM_XAX : : : ASM_XAX);
    asm("mov %%"ASM_XAX", %0" : "=m"(val) : : ASM_XAX);
# endif
    return val;
#else
    /* FIXME i#1726: port to ARM */
    ASSERT_NOT_REACHED();
    return 0;
#endif
}

int
spill_reg3_slot(bool eflags_dead, bool eax_dead, bool r1_dead, bool r2_dead)
{
    if (whole_bb_spills_enabled())
        return SPILL_SLOT_4;
    if (eflags_dead || eax_dead)
        return SPILL_SLOT_EFLAGS_EAX;
    /* we can only use slots 1 and 2 if no spill or xchg, since for xchg
     * we restore and then use the tls slot for slowpath param, so truly
     * if r1/r2 is dead.  even then we must restore reg3 first in slowpath prefix
     * before we move param into tls slot.
     */
    if (r1_dead)
        return SPILL_SLOT_1;
    if (r2_dead)
        return SPILL_SLOT_2;
    return SPILL_SLOT_4;
}

void
spill_reg(void *drcontext, instrlist_t *ilist, instr_t *where, reg_id_t reg,
          dr_spill_slot_t slot)
{
    ASSERT(options.pattern == 0, "not converted to drreg yet");
    if (slot < options.num_spill_slots) {
        STATS_INC(reg_spill_own);
        PRE(ilist, where,
            XINST_CREATE_store(drcontext, opnd_create_own_spill_slot(slot),
                               opnd_create_reg(reg)));
    } else {
        dr_spill_slot_t DR_slot = slot - options.num_spill_slots;
#ifdef STATISTICS
        if (DR_slot > MAX_FAST_DR_SPILL_SLOT)
            STATS_INC(reg_spill_slow);
#endif
        dr_save_reg(drcontext, ilist, where, reg, DR_slot);
    }
}

void
restore_reg(void *drcontext, instrlist_t *ilist, instr_t *where, reg_id_t reg,
            dr_spill_slot_t slot)
{
    ASSERT(options.pattern == 0, "not converted to drreg yet");
    if (slot < options.num_spill_slots) {
        PRE(ilist, where,
            XINST_CREATE_load(drcontext, opnd_create_reg(reg),
                              opnd_create_own_spill_slot(slot)));
    } else {
        dr_spill_slot_t DR_slot = slot - options.num_spill_slots;
        dr_restore_reg(drcontext, ilist, where, reg, DR_slot);
    }
}

opnd_t
spill_slot_opnd(void *drcontext, dr_spill_slot_t slot)
{
    ASSERT(options.pattern == 0, "not converted to drreg yet");
    if (slot < options.num_spill_slots) {
        return opnd_create_own_spill_slot(slot);
    } else {
        dr_spill_slot_t DR_slot = slot - options.num_spill_slots;
        return dr_reg_spill_slot_opnd(drcontext, DR_slot);
    }
}

static bool
is_spill_slot_opnd(void *drcontext, opnd_t op)
{
    static uint offs_min_own, offs_max_own, offs_min_DR, offs_max_DR;
    if (offs_max_DR == 0) {
        offs_min_own = opnd_get_disp(opnd_create_own_spill_slot(0));
        offs_max_own = opnd_get_disp(opnd_create_own_spill_slot
                                     (options.num_spill_slots - 1));
        offs_min_DR = opnd_get_disp(dr_reg_spill_slot_opnd(drcontext, SPILL_SLOT_1));
        offs_max_DR = opnd_get_disp(dr_reg_spill_slot_opnd
                                    (drcontext, dr_max_opnd_accessible_spill_slot()));
    }
    if (opnd_is_far_base_disp(op) &&
        opnd_get_index(op) == REG_NULL &&
        opnd_get_segment(op) == seg_tls) {
        uint offs = opnd_get_disp(op);
        if (offs >= offs_min_own && offs <= offs_max_own)
            return true;
        if (offs >= offs_min_DR && offs <= offs_max_DR)
            return true;
    }
    return false;
}

/***************************************************************************
 * STATE RESTORATION
 */

/* Our state restoration model for non-pattern, until we transition
 * them to use drreg as well (i#1795): only whole-bb scratch regs and aflags
 * need to be restored (i.e., all local scratch regs are restored
 * before any app instr).  For each such reg or aflags, we guarantee
 * that either the app value is in TLS at each app instr (where fault
 * might happen) or the app value is dead and it's ok to have garbage
 * in TLS b/c the app will write it before reading (this is all modulo
 * the app's own fault handler going off on a different path (xref
 * DRi#400): so we're slightly risky here).
 *
 * We also perform a few other shadow-related restorations at the end
 * of this routine.
 */
bool
event_restore_state(void *drcontext, bool restore_memory, dr_restore_state_info_t *info)
{
    bool shadow_write = false;
    instr_t inst;
    uint memopidx;
    bool write;
    byte *addr;
    /* If always app_code_consistent could just re-analyze aflags, but not
     * the case so we have to store whether we've done eflags-at-top
     */
#ifdef X86
    /* XXX PR 485216: we should restore dead registers on a fault, but it
     * would be a perf hit to save them: for now we don't do anything.
     * It's doubtful an app will ever have a problem with that.
     */
    bb_saved_info_t *save;
#endif

#ifdef TOOL_DR_MEMORY
    cls_drmem_t *cpt = (cls_drmem_t *) drmgr_get_cls_field(drcontext, cls_idx_drmem);
    ASSERT(cpt != NULL, "cpt shouldn't be null");

    if (!INSTRUMENT_MEMREFS())
        return true;

    if (options.pattern != 0) /* pattern is using drreg */
        return true;

    /* Are we asking DR to translate just pc?  Then return true and ignore regs */
    if (cpt->self_translating) {
        ASSERT(options.verbose >= 3, "only used for -verbose 3+");
        return true;
    }
#endif

#ifdef X86 /* ARM uses drreg's state restoration */
    hashtable_lock(&bb_table);
    save = (bb_saved_info_t *) hashtable_lookup(&bb_table, info->fragment_info.tag);
# ifdef TOOL_DR_MEMORY
    LOG(2, "%s: raw pc="PFX", xl8 pc="PFX", tag="PFX"\n",
        __FUNCTION__, info->raw_mcontext->pc, info->mcontext->pc,
        info->fragment_info.tag);
    DOLOG(2, {
        /* We leave the translation as being in our own library, since no
         * other good alternative.  We document this to users.
         */
        if (in_replace_routine(info->mcontext->pc))
            LOG(2, "fault in replace_ routine "PFX"\n", info->mcontext->pc);
    });
# endif
    if (save != NULL) {
        /* We save first thing and restore prior to last instr.
         * Our restore clobbers the eflags value in our tls slot, so
         * on a fault in the last instr we should do nothing.
         * FIXME: NOT ENOUGH TESTED:
         * need carefully constructed tests like tests/state.c
         */
        if (info->mcontext->pc != save->last_instr &&
            /* i#1466: only restore after first_restore_pc */
            info->mcontext->pc >= save->first_restore_pc) {
            /* Use drcontext's shadow, not executing thread's shadow! (PR 475211) */
            ptr_uint_t regval;
            if (save->eflags_saved) {
                IF_DEBUG(ptr_uint_t orig_flags = info->mcontext->xflags;)
                uint sahf;
                regval = save->aflags_in_eax ? info->raw_mcontext->xax :
                    get_thread_tls_value(drcontext, SPILL_SLOT_EFLAGS_EAX);
                sahf = (regval & 0xff00) >> 8;
                info->mcontext->xflags &= ~0xff;
                info->mcontext->xflags |= sahf;
                if (TEST(1, regval)) /* from "seto al" */
                    info->mcontext->xflags |= EFLAGS_OF;
                LOG(2, "translated eflags from "PFX" to "PFX"\n",
                    orig_flags, info->mcontext->xflags);
            }
            /* Restore whole-bb spilled registers (PR 489221).  Note that
             * now we're closer to being able to restore app state at any
             * point: but we still don't have any local 3rd scratch reg
             * recorded.
             */
            if (save->scratch1 != REG_NULL) {
                regval = get_thread_tls_value(drcontext, SPILL_SLOT_1);
                LOG(2, "restoring per-bb %s to "PFX"\n",
                    get_register_name(save->scratch1), regval);
                reg_set_value(save->scratch1, info->mcontext, regval);
            }
            if (save->scratch2 != REG_NULL) {
                regval = get_thread_tls_value(drcontext, SPILL_SLOT_2);
                LOG(2, "restoring per-bb %s to "PFX"\n",
                    get_register_name(save->scratch2), regval);
                reg_set_value(save->scratch2, info->mcontext, regval);
            }
            if (save->aflags_in_eax) {
                regval = get_thread_tls_value(drcontext, SPILL_SLOT_5);
                LOG(2, "restoring %s to "PFX"\n",
                    get_register_name(DR_REG_XAX), regval);
                reg_set_value(DR_REG_XAX, info->mcontext, regval);
            }
        }
    }
    hashtable_unlock(&bb_table);
#endif /* X86 */

#ifndef TOOL_DR_MEMORY
    /* Dr. Heapstat has no fault paths */
    return true;
#endif

    /* Note that although we now have non-meta instrumentation that
     * comes through here for PR 448701 we do not restore registers
     * here since no such fault will make it to the app.
     * PR 480208: we do need to restore for a thread relocation.  For now we
     * return false to force thread suspension elsewhere (b/c we can't relocate
     * for the 1st of our two-part sub-dword dst write), if the translation is
     * targeting our own meta-may-fault instr, which will always be a write to
     * shadow memory == DR memory.
     */
    if (!info->raw_mcontext_valid) {
        ASSERT(false, "should always have raw_mcontext");
        return true;
    }
    instr_init(drcontext, &inst);
    decode(drcontext, info->raw_mcontext->pc, &inst);
    ASSERT(instr_valid(&inst), "unknown translation instr");
    DOLOG(3, {
        LOG(3, "considering to-be-translated instr: ");
        instr_disassemble(drcontext, &inst, LOGFILE_GET(drcontext));
        LOG(3, "\n");
    });
    for (memopidx = 0;
         instr_compute_address_ex(&inst, info->raw_mcontext, memopidx, &addr, &write);
         memopidx++) {
        if (write && dr_memory_is_dr_internal(addr)) {
            shadow_write = true;
            break;
        }
    }
    instr_free(drcontext, &inst);
    if (shadow_write) {
        /* An app write to a random address could fool us, but shouldn't be
         * a problem: DR will just suspend somewhere else.
         */
        if (!restore_memory) {
            /* We could move the state restoration code from
             * handle_special_shadow_fault() to here and return true, except
             * we'd also have to change our two-part sub-dword dst write to get
             * the final value in a reg before committing.  So, we return false,
             * and only restore the state when we need to determine the app's
             * mem address for a real fault.
             */
            LOG(1, "failing non-fault translation\n");
            return false;
        }
        /* else, it must be our own special-shadow fault, handled by our
         * signal/exception events below
         */
    }
#ifdef TOOL_DR_MEMORY
    else if (restore_memory && cpt->mem2fpmm_source != NULL) {
        /* Our i#471 heuristic could end up with a thread relocation in between
         * the fld and the fstp.  In such a case we restore the shadow.
         */
        umbra_shadow_memory_info_t info;
        shadow_set_byte(&info, cpt->mem2fpmm_dest, cpt->mem2fpmm_prev_shadow);
        cpt->mem2fpmm_source = NULL;
    }
#endif

    return true;
}

/***************************************************************************
 * SCRATCH REGISTER SELECTION
 */

#ifdef X86 /* ARM uses drreg's state restoration */

# ifdef DEBUG
static void
print_scratch_reg(void *drcontext, scratch_reg_info_t *si, int num, file_t file)
{
    dr_fprintf(file, "r%d=", num);
    opnd_disassemble(drcontext, opnd_create_reg(si->reg), file);
    if (si->xchg != REG_NULL) {
        dr_fprintf(file, " xchg ");
        opnd_disassemble(drcontext, opnd_create_reg(si->xchg), file);
    } else if (si->dead) {
        dr_fprintf(file, " dead");
    } else {
        dr_fprintf(file, "spill#%d", si->slot);
    }
}

static void
check_scratch_reg_no_overlap(scratch_reg_info_t *s1, scratch_reg_info_t *s2)
{
    ASSERT(s1->reg != s2->reg, "scratch reg error");
    ASSERT(s1->xchg != s2->reg, "scratch reg error");
    ASSERT(s2->xchg != s1->reg, "scratch reg error");
    /* if both are using slots (no xchg, not dead) then make sure they differ */
    ASSERT(s1->xchg != REG_NULL || s2->xchg != REG_NULL ||
           s1->dead || s2->dead ||
           s1->slot != s2->slot, "scratch reg error");
}
# endif /* DEBUG */

/* It's up to the caller to ensure that fixed was not already chosen
 * for an earlier scratch reg
 */
static void
pick_scratch_reg_helper(fastpath_info_t *mi, scratch_reg_info_t *si,
                        int live[NUM_LIVENESS_REGS],
                        bool only_abcd, reg_id_t fixed, int slot,
                        opnd_t no_overlap1, opnd_t no_overlap2)
{
    int nxt_dead;
    for (nxt_dead = 0; nxt_dead < NUM_LIVENESS_REGS; nxt_dead++) {
        if (live[nxt_dead] == LIVE_DEAD)
            break;
    }
    si->global = false;
    /* FIXME PR 463053: we're technically being a little unsafe here:
     * even if a register is dead on the normal path, if a fault
     * can occur before the register is written to, we should
     * restore its value in the fault handler.  Pretty pathological
     * so for now we ignore it, given that we have larger problems
     * and we need the speed.
     */
    if (nxt_dead < NUM_LIVENESS_REGS &&
        (!only_abcd || nxt_dead <= DR_REG_XBX - REG_START) &&
        !opnd_uses_reg(no_overlap1, REG_START + nxt_dead) &&
        !opnd_uses_reg(no_overlap2, REG_START + nxt_dead) &&
        /* do not pick local reg that overlaps w/ whole-bb reg */
        REG_START + nxt_dead != mi->bb->reg1.reg &&
        REG_START + nxt_dead != mi->bb->reg2.reg) {
        /* we can use it directly */
        si->reg = REG_START + nxt_dead;
        si->xchg = REG_NULL;
        si->dead = true;
        STATS_INC(reg_dead);
        live[nxt_dead] = LIVE_LIVE;
    } else if (nxt_dead < NUM_LIVENESS_REGS &&
               /* FIXME OPT: if we split the spills up we could use xchg for
                * reg2 or reg3 even if not for reg1
                */
               !opnd_uses_reg(no_overlap1, REG_START + nxt_dead) &&
               !opnd_uses_reg(no_overlap2, REG_START + nxt_dead) &&
               !opnd_uses_reg(no_overlap1, fixed) &&
               !opnd_uses_reg(no_overlap2, fixed) &&
               /* do not pick local reg that overlaps w/ whole-bb reg */
               REG_START + nxt_dead != mi->bb->reg1.reg &&
               REG_START + nxt_dead != mi->bb->reg2.reg) {
        /* pick fixed reg and xchg for it */
        si->reg = fixed;
        si->xchg = REG_START + nxt_dead;
        si->dead = false;
        STATS_INC(reg_xchg);
        live[nxt_dead] = LIVE_LIVE;
    } else {
        /* pick fixed reg and spill it */
        si->reg = fixed;
        si->xchg = REG_NULL;
        si->dead = false;
        si->slot = slot;
        STATS_INC(reg_spill);
   }
}

/* Chooses scratch registers and sets liveness and eflags info
 * If mi->eax.used is set, does NOT determine how to spill eax based
 * on eflags and does NOT use the SPILL_SLOT_EFLAGS_EAX unless eflags
 * is dead.
 */
void
pick_scratch_regs(instr_t *inst, fastpath_info_t *mi, bool only_abcd, bool need3,
                  bool reg3_must_be_ecx, opnd_t no_overlap1, opnd_t no_overlap2)
{
    int nxt_dead;
    int live[NUM_LIVENESS_REGS];
    /* Slots for additional local regs, when using whole-bb slots 1 and 2
     * for regs and slot 3 (SPILL_SLOT_EFLAGS_EAX) for eflags
     */
    int local_slot[] = {SPILL_SLOT_4, SPILL_SLOT_5};
    int local_idx = 0;
    IF_DEBUG(const int local_idx_max = sizeof(local_slot)/sizeof(local_slot[0]);)
    mi->aflags = get_aflags_and_reg_liveness(inst, live, false/* regs too */);

    ASSERT((whole_bb_spills_enabled() && mi->bb->reg1.reg != REG_NULL) ||
           (!whole_bb_spills_enabled() && mi->bb->reg1.reg == REG_NULL),
           "whole_bb_spills_enabled() should correspond to reg1,reg2 being set");

    /* don't pick esp since it can't be an index register */
    live[DR_REG_XSP - REG_START] = LIVE_LIVE;

    if (mi->eax.used) {
        /* caller wants us to ignore eax and eflags */
    } else if (!whole_bb_spills_enabled() && mi->aflags != EFLAGS_WRITE_ARITH) {
        mi->eax.reg = DR_REG_XAX;
        mi->eax.used = true;
        mi->eax.dead = (live[DR_REG_XAX - REG_START] == LIVE_DEAD);
        /* Ensure we don't use eax for another scratch reg */
        if (mi->eax.dead) {
            live[DR_REG_XAX - REG_START] = LIVE_LIVE;
            STATS_INC(reg_dead);
        } else
            STATS_INC(reg_spill);
        /* we do not try to xchg instead of spilling as that would complicate
         * shared_slowpath, spill_reg3_slot, etc.
         */
        mi->eax.xchg = REG_NULL;
        mi->eax.slot = SPILL_SLOT_EFLAGS_EAX;
        mi->eax.global = false;
    } else
        mi->eax.used = false;

    /* Up to 3 scratch regs (beyond eax for eflags) need to be from
     * ecx, edx, ebx so we can reference low and high 8-bit sub-regs
     */
    mi->reg1.used = false; /* set later */
    mi->reg2.used = false; /* set later */
    mi->reg3.used = false; /* set later */

    if (need3) {
        if (reg3_must_be_ecx && mi->bb->reg1.reg == DR_REG_XCX) {
            mi->reg3 = mi->bb->reg1;
            mi->reg3.dead = (live[mi->reg3.reg - REG_START] == LIVE_DEAD);
        } else if (reg3_must_be_ecx && mi->bb->reg2.reg == DR_REG_XCX) {
            mi->reg3 = mi->bb->reg2;
            mi->reg3.dead = (live[mi->reg3.reg - REG_START] == LIVE_DEAD);
        } else if (reg3_must_be_ecx && only_abcd) {
            /* instrument_fastpath requires reg3 to be ecx since we have
             * to use cl for OP_shl var op.
             */
            mi->reg3.reg = DR_REG_XCX;
            mi->reg3.dead = (live[mi->reg3.reg - REG_START] == LIVE_DEAD);
            mi->reg3.global = false;
            /* Ensure we don't use for another scratch reg */
            live[mi->reg3.reg - REG_START] = LIVE_LIVE;
            if (!mi->reg3.dead) {
                for (nxt_dead = 0; nxt_dead < NUM_LIVENESS_REGS; nxt_dead++) {
                    if (live[nxt_dead] == LIVE_DEAD)
                        break;
                }
                if (nxt_dead < NUM_LIVENESS_REGS &&
                    !opnd_uses_reg(no_overlap1, REG_START + nxt_dead) &&
                    !opnd_uses_reg(no_overlap2, REG_START + nxt_dead) &&
                    !opnd_uses_reg(no_overlap1, mi->reg3.reg) &&
                    !opnd_uses_reg(no_overlap2, mi->reg3.reg) &&
                    /* we can't xchg with what we'll use for reg1 or reg2 */
                    REG_START + nxt_dead != DR_REG_XDX &&
                    REG_START + nxt_dead != DR_REG_XBX &&
                    /* do not pick local reg that overlaps w/ whole-bb reg */
                    REG_START + nxt_dead != mi->bb->reg1.reg &&
                    REG_START + nxt_dead != mi->bb->reg2.reg) {
                    mi->reg3.xchg = REG_START + nxt_dead;
                    live[nxt_dead] = LIVE_LIVE;
                    STATS_INC(reg_xchg);
                } else {
                    mi->reg3.slot = spill_reg3_slot(mi->aflags == EFLAGS_WRITE_ARITH,
                                                    !mi->eax.used || mi->eax.dead,
                                                    /* later we'll update these */
                                                    false, false);
                    STATS_INC(reg_spill);
                }
            } else
                STATS_INC(reg_dead);
        } else {
            pick_scratch_reg_helper(mi, &mi->reg3, live, only_abcd,
                                    (mi->bb->reg1.reg == DR_REG_XCX ?
                                     ((mi->bb->reg2.reg == DR_REG_XDX) ?
                                      DR_REG_XBX : DR_REG_XDX) :
                                     ((mi->bb->reg2.reg == DR_REG_XCX) ?
                                      ((mi->bb->reg1.reg == DR_REG_XDX) ?
                                       DR_REG_XBX : DR_REG_XDX)
                                      : DR_REG_XCX)),
                                    spill_reg3_slot(mi->aflags == EFLAGS_WRITE_6,
                                                    !mi->eax.used || mi->eax.dead,
                                                    /* later we'll update these */
                                                    false, false),
                                    no_overlap1, no_overlap2);
        }
        if (mi->bb->reg1.reg != REG_NULL && !mi->reg3.dead && mi->reg3.xchg == REG_NULL) {
            if (!mi->reg3.global) {
                /* spill_reg3_slot() should return SPILL_SLOT_4 for us */
                ASSERT(mi->reg3.slot == local_slot[local_idx], "reg3: wrong slot!");
                local_idx++;
            } else
                ASSERT(mi->reg3.slot < SPILL_SLOT_EFLAGS_EAX, "reg3 global: 0 or 1!");
        }
   } else
        mi->reg3.reg = REG_NULL;

    if (mi->bb->reg1.reg != REG_NULL &&
        (!need3 || !reg3_must_be_ecx || mi->bb->reg1.reg != DR_REG_XCX) &&
        /* we only need to check for overlap for xchg (since messes up
         * app values) so we ignore no_overlap*
         */
        (!mi->eax.used || mi->bb->reg1.reg != DR_REG_XAX)) {
        /* Use whole-bb spilled reg (PR 489221) */
        mi->reg1 = mi->bb->reg1;
        mi->reg1.dead = (live[mi->reg1.reg - REG_START] == LIVE_DEAD);
    } else {
        /* Pick primary scratch reg */
        ASSERT(local_idx < local_idx_max, "local slot overflow");
        pick_scratch_reg_helper(mi, &mi->reg1, live, only_abcd,
                                (need3 && mi->reg3.reg == DR_REG_XDX) ?
                                DR_REG_XCX :
                                ((mi->bb->reg2.reg == DR_REG_XDX) ?
                                 DR_REG_XBX : DR_REG_XDX),
                                /* if whole-bb ecx is in slot 1 or 2, use 3rd slot */
                                (mi->bb->reg1.reg == REG_NULL) ? SPILL_SLOT_1 :
                                local_slot[local_idx++], no_overlap1, no_overlap2);
    }


    if (mi->bb->reg2.reg != REG_NULL &&
        (!need3 || !reg3_must_be_ecx || mi->bb->reg2.reg != DR_REG_XCX) &&
        (!mi->eax.used || mi->bb->reg2.reg != DR_REG_XAX)) {
        /* Use whole-bb spilled reg (PR 489221) */
        mi->reg2 = mi->bb->reg2;
        mi->reg2.dead = (live[mi->reg2.reg - REG_START] == LIVE_DEAD);
    } else {
        /* Pick secondary scratch reg */
        ASSERT(local_idx < local_idx_max, "local slot overflow");
        pick_scratch_reg_helper(mi, &mi->reg2, live, only_abcd,
                                mi->reg1.reg == DR_REG_XBX ?
                                ((need3 && mi->reg3.reg == DR_REG_XDX) ?
                                 DR_REG_XCX : DR_REG_XDX) :
                                ((need3 && mi->reg3.reg == DR_REG_XBX) ?
                                 DR_REG_XCX : DR_REG_XBX),
                                /* if whole-bb ecx is in slot 1 or 2, use 3rd slot */
                                (mi->bb->reg2.reg == REG_NULL) ? SPILL_SLOT_2 :
                                local_slot[local_idx++], no_overlap1, no_overlap2);
    }

    if (mi->bb->reg1.reg == REG_NULL &&
        need3 && !mi->reg3.dead && mi->reg3.xchg == REG_NULL) {
        /* See if we can use slots 1 or 2 instead: matters when using DR slots */
        mi->reg3.slot = spill_reg3_slot(mi->aflags == EFLAGS_WRITE_ARITH,
                                        !mi->eax.used || mi->eax.dead,
                                        mi->reg1.dead, mi->reg2.dead);
    }

    DOLOG(4, {
        void *drcontext = dr_get_current_drcontext();
        tls_util_t *pt = PT_GET(drcontext);
        ASSERT(pt != NULL, "should always have dcontext in cur DR");
        LOG(3, "scratch: ");
        instr_disassemble(drcontext, inst, LOGFILE(pt));
        LOG(3, "| ");
        print_scratch_reg(drcontext, &mi->reg1, 1, LOGFILE(pt));
        LOG(3, ", ");
        print_scratch_reg(drcontext, &mi->reg2, 2, LOGFILE(pt));
        if (need3) {
            LOG(3, ", ");
            print_scratch_reg(drcontext, &mi->reg3, 3, LOGFILE(pt));
        }
        LOG(3, "\n");
    });

# ifdef DEBUG
    check_scratch_reg_no_overlap(&mi->reg1, &mi->reg2);
    if (need3) {
        check_scratch_reg_no_overlap(&mi->reg1, &mi->reg3);
        check_scratch_reg_no_overlap(&mi->reg2, &mi->reg3);
    }
# endif
}
#endif /* X86 */

static bool
insert_spill_common(void *drcontext, instrlist_t *bb, instr_t *inst,
                    scratch_reg_info_t *si, bool spill,
                    bool just_xchg, bool do_global)
{
#ifdef X86 /* XXX i#1795: eliminate this and port to drreg */
    /* No need to do a local spill/restore if globally spilled (PR 489221) */
    if (si->used && !si->dead && (!si->global || do_global)) {
        if (si->xchg != REG_NULL) {
            /* spill/restore are identical */
            PRE(bb, inst, INSTR_CREATE_xchg
                (drcontext, opnd_create_reg(si->reg), opnd_create_reg(si->xchg)));
        } else if (!just_xchg) {
            if (spill)
                spill_reg(drcontext, bb, inst, si->reg, si->slot);
            else
                restore_reg(drcontext, bb, inst, si->reg, si->slot);
        }
        if (!spill && do_global) {
            /* FIXME PR 553724: avoid later redundant restore at
             * bottom of bb by setting used to false here.
             * However that's not working for reasons I haven't yet determined.
             */
        }
        return true;
    }
    return false;
#else
    /* FIXME i#1795/i#1726: port shadow modes to use drreg */
    ASSERT_NOT_REACHED();
    return false;
#endif
}

bool
insert_spill_global(void *drcontext, instrlist_t *bb, instr_t *inst,
                    scratch_reg_info_t *si, bool spill)
{
    return insert_spill_common(drcontext, bb, inst, si, spill, false, true);
}

void
insert_spill_or_restore(void *drcontext, instrlist_t *bb, instr_t *inst,
                        scratch_reg_info_t *si, bool spill, bool just_xchg)
{
    insert_spill_common(drcontext, bb, inst, si, spill, just_xchg, false);
}

/* insert aflags save code sequence w/o spill: lahf; seto %al; */
void
insert_save_aflags_nospill(void *drcontext, instrlist_t *ilist,
                           instr_t *inst, bool save_oflag)
{
#ifdef X86 /* XXX i#1795: eliminate this and port to drreg */
    PRE(ilist, inst, INSTR_CREATE_lahf(drcontext));
    if (save_oflag) {
        PRE(ilist, inst,
            INSTR_CREATE_setcc(drcontext, OP_seto, opnd_create_reg(DR_REG_AL)));
    }
#else
    /* FIXME i#1795/i#1726: port shadow modes to use drreg */
    ASSERT_NOT_REACHED();
#endif
}

/* insert aflags restore code sequence w/o spill: add %al, 0x7f; sahf; */
void
insert_restore_aflags_nospill(void *drcontext, instrlist_t *ilist,
                              instr_t *inst, bool restore_oflag)
{
#ifdef X86 /* XXX i#1795: eliminate this and port to drreg */
    if (restore_oflag) {
        PRE(ilist, inst, INSTR_CREATE_add
            (drcontext, opnd_create_reg(REG_AL), OPND_CREATE_INT8(0x7f)));
    }
    PRE(ilist, inst, INSTR_CREATE_sahf(drcontext));
#else
    /* FIXME i#1795/i#1726: port shadow modes to use drreg */
    ASSERT_NOT_REACHED();
#endif
}

void
insert_save_aflags(void *drcontext, instrlist_t *bb, instr_t *inst,
                   scratch_reg_info_t *si, int aflags)
{
#ifdef X86 /* XXX i#1795: eliminate this and port to drreg */
    if (si->reg != REG_NULL) {
        ASSERT(si->reg == DR_REG_XAX, "must use eax for aflags");
        insert_spill_or_restore(drcontext, bb, inst, si, true/*save*/, false);
    }
    insert_save_aflags_nospill(drcontext, bb, inst, aflags != EFLAGS_WRITE_OF);
#else
    /* FIXME i#1795/i#1726: port shadow modes to use drreg */
    ASSERT_NOT_REACHED();
#endif
}

void
insert_restore_aflags(void *drcontext, instrlist_t *bb, instr_t *inst,
                      scratch_reg_info_t *si, int aflags)
{
#ifdef X86 /* XXX i#1795: eliminate this and port to drreg */
    insert_restore_aflags_nospill(drcontext, bb, inst,
                                  aflags != EFLAGS_WRITE_OF);
    if (si->reg != REG_NULL) {
        ASSERT(si->reg == DR_REG_XAX, "must use eax for aflags");
        insert_spill_or_restore(drcontext, bb, inst, si, false/*restore*/, false);
    }
#else
    /* FIXME i#1795/i#1726: port shadow modes to use drreg */
    ASSERT_NOT_REACHED();
#endif
}

static inline bool
scratch_reg1_is_avail(instr_t *inst, fastpath_info_t *mi, bb_info_t *bi)
{
    int opc = instr_get_opcode(inst);
    return (bi->reg1.reg != DR_REG_NULL &&
            bi->reg1.used &&
             /* ensure neither sharing w/ next nor sharing w/ prev */
            !SHARING_XL8_ADDR_BI(bi) && mi != NULL && !mi->use_shared &&
            /* cmovcc does an aflags restore after the lea, so reg1 needs
             * to stay untouched
             */
            !opc_is_cmovcc(opc) && !opc_is_fcmovcc(opc));
}

static inline bool
scratch_reg2_is_avail(instr_t *inst, fastpath_info_t *mi, bb_info_t *bi)
{
    int opc = instr_get_opcode(inst);
    return (bi->reg2.reg != DR_REG_NULL &&
            bi->reg2.used &&
            /* we use reg2 for cmovcc */
            !opc_is_cmovcc(opc) && !opc_is_fcmovcc(opc));
}

/* single eflags save per bb */
void
save_aflags_if_live(void *drcontext, instrlist_t *bb, instr_t *inst,
                    fastpath_info_t *mi, bb_info_t *bi)
{
#ifdef X86 /* XXX i#1795: eliminate this and port to drreg */
    scratch_reg_info_t si;
    /* We save aflags unless there's no read prior to the 1st write.
     * We clobber eax while doing so if eax is dead.
     * Technically both are unsafe: should restore on a fault (PR
     * 463053) but we consider that too pathological to bother.
     */
    bool eax_dead = bi->eax_dead ||
        (bi->reg1.reg == DR_REG_XAX && scratch_reg1_is_avail(inst, mi, bi)) ||
        (bi->reg2.reg == DR_REG_XAX && scratch_reg2_is_avail(inst, mi, bi));
    ASSERT(options.pattern == 0, "pattern is using drreg");
    if (!bi->eflags_used)
        return;
    if (bi->aflags != EFLAGS_WRITE_ARITH) {
        /* slot 5 won't be used for 3rd reg (that's 4) and is ok for temp use */
        si.slot = SPILL_SLOT_5;
        if (eax_dead || bi->aflags_where == AFLAGS_IN_EAX) {
            si.reg = REG_NULL;
        } else {
            si.reg = DR_REG_XAX;
            /* reg1 is used for xl8 sharing so check whether shared_memop is set
             * == share w/ next.  it's cleared prior to post-app-write aflags save
             * so we use mi->use_shared to detect share w/ prev.
             * for aflags restore code added later it's ok to be too conservative:
             * these fields should all be cleared anyway, and won't matter for
             * top-of-bb save.
             * we can assume that reg2 is dead.
             */
            if (scratch_reg1_is_avail(inst, mi, bi))
                si.xchg = bi->reg1.reg;
            else if (scratch_reg2_is_avail(inst, mi, bi))
                si.xchg = bi->reg2.reg;
            else
                si.xchg = REG_NULL;
            ASSERT(si.xchg != DR_REG_XAX, "xchg w/ self is not a save");
            si.used = true;
            si.dead = false;
            si.global = false; /* to enable the save */
        }
        insert_save_aflags(drcontext, bb, inst, &si, bi->aflags);
        /* optimization:
         * We keep the flags in eax if eax is not used in any app instrs later.
         * XXX: we can be more aggressive to keep the flags in eax if it is
         * not used in app instr between here and the next eflags restore.
         * Since a lahf followed by a read of eax causes a partial-reg
         * stall that could improve perf noticeably.
         * However, this would make the state restore more complex.
         */
        if (bi->aflags_where == AFLAGS_UNKNOWN) {
# ifdef TOOL_DR_MEMORY
            /* i#1466: remember where to start restore state for pattern mode.
             * In pattern mode, we only save eax if we save aflags. i#1466 is a bug
             * that tries to restore eax on a fault before we saving eax, so we use
             * first_restore_pc to remember where eax is saved and only restore eax
             * for fault happening after that pc.
             * For shadow mode, it should always start from the first pc, and we
             * set first_restore_pc to be NULL.
             */
            if (options.pattern != 0) {
                ASSERT(bi->first_restore_pc == NULL,
                       "first_restore_pc must be NULL if aflags_where is not set");
                bi->first_restore_pc = (mi == NULL ? instr_get_app_pc(inst) : mi->xl8);
                ASSERT(bi->first_restore_pc != NULL, "instr app_pc must not be NULL");
            }
            /* We can avoid saving eflags to TLS and restoring app %eax if we know that
             * %eax is not used later in the bb. This might be called in the middle of
             * a bb, so we need use first_restore_pc to remember where we start stealing
             * %eax (#i1466).
             */
            if (!xax_is_used_subsequently(inst) && options.pattern != 0) {
                /* To keep aflags in %eax, we need a permanent TLS store for
                 * storing app's %eax value. Current implementation uses SLOT 5,
                 * which is used for third register spill and temporary eax
                 * spill on aflags saving. So this optimization is only applied
                 * in pattern mode.
                 * XXX: to apply this optimization in shadow mode, we should use
                 * a permanent TLS slot, and make sure neither spill reg1 nor
                 * reg2 uses %eax.
                 */
                /* - eax is not used by app later in bb
                 * - eax is holding aflags
                 * - app's eax is in tls slot from now on
                 */
                bi->aflags_where = AFLAGS_IN_EAX;
            } else
# endif
                bi->aflags_where = AFLAGS_IN_TLS;
        }
        if (bi->aflags_where == AFLAGS_IN_EAX)
            return;
        /* save aflags into tls */
        PRE(bb, inst, INSTR_CREATE_mov_st
            (drcontext, spill_slot_opnd(drcontext, SPILL_SLOT_EFLAGS_EAX),
             opnd_create_reg(DR_REG_XAX)));
        if (!eax_dead) { /* restore eax  */
            /* I used to use xchg to avoid needing two instrs, but xchg w/ mem's
             * lock of the bus shows up as a measurable perf hit (PR 553724)
             */
            insert_spill_or_restore(drcontext, bb, inst, &si, false/*restore*/, false);
        }
    }
#else
    /* FIXME i#1795/i#1726: port shadow modes to use drreg */
    ASSERT_NOT_REACHED();
#endif
}

/* Single eflags save per bb
 * N.B.: the sequence added here is matched in restore_mcontext_on_shadow_fault()
 */
void
restore_aflags_if_live(void *drcontext, instrlist_t *bb, instr_t *inst,
                       fastpath_info_t *mi, bb_info_t *bi)
{
#ifdef X86 /* XXX i#1795: eliminate this and port to drreg */
    scratch_reg_info_t si;
    if (!bi->eflags_used)
        return;
    ASSERT(bi->aflags_where == AFLAGS_IN_TLS ||
           bi->aflags_where == AFLAGS_IN_EAX,
           "bi->aflags_where is not set");
    ASSERT(options.pattern == 0, "pattern is using drreg");
    si.reg  = DR_REG_XAX;
    si.xchg = REG_NULL;
    si.slot = SPILL_SLOT_EFLAGS_EAX;
    si.used = true;
    si.dead = false;
    si.global = false; /* to enable the restore */
    if (bi->aflags_where == AFLAGS_IN_TLS) {
        if (bi->eax_dead ||
            (bi->reg1.reg == DR_REG_XAX && scratch_reg1_is_avail(inst, mi, bi)) ||
            (bi->reg2.reg == DR_REG_XAX && scratch_reg2_is_avail(inst, mi, bi))) {
            insert_spill_or_restore(drcontext, bb, inst, &si, false/*restore*/, false);
            /* we do NOT want the eax-restore at the end of insert_restore_aflags() */
            si.reg = DR_REG_NULL;
        } else {
            si.slot = SPILL_SLOT_5;
            /* See notes in save_aflags_if_live on sharing impacting reg1 being scratch */
            if (scratch_reg1_is_avail(inst, mi, bi))
                si.xchg = bi->reg1.reg;
            else if (scratch_reg2_is_avail(inst, mi, bi))
                si.xchg = bi->reg2.reg;
            ASSERT(si.xchg != DR_REG_XAX, "xchg w/ self is not a save");
            /* I used to use xchg to avoid needing two instrs, but xchg w/ mem's
             * lock of the bus shows up as a measurable perf hit (PR 553724)
             */
            insert_spill_or_restore(drcontext, bb, inst, &si, true/*save*/, false);
            PRE(bb, inst, INSTR_CREATE_mov_ld
                (drcontext, opnd_create_reg(DR_REG_XAX),
                 spill_slot_opnd(drcontext, SPILL_SLOT_EFLAGS_EAX)));
            /* we DO want the eax-restore at the end of insert_restore_aflags() */
        }
    } else { /* AFLAGS_IN_EAX */
        si.slot = SPILL_SLOT_5;
    }
    insert_restore_aflags(drcontext, bb, inst, &si, bi->aflags);
    /* avoid re-restoring.  FIXME: do this for insert_spill_global too? */
    bi->eflags_used = false;
#else
    /* FIXME i#1795/i#1726: port shadow modes to use drreg */
    ASSERT_NOT_REACHED();
#endif
}

/***************************************************************************
 * Whole-bb spilling (PR 489221)
 */

#ifdef X86 /* XXX i#1795: eliminate this and port to drreg */
static void
pick_bb_scratch_regs_helper(opnd_t opnd, int uses[NUM_LIVENESS_REGS])
{
    int j;
    for (j = 0; j < opnd_num_regs_used(opnd); j++) {
        reg_id_t reg = opnd_get_reg_used(opnd, j);
        if (reg_is_gpr(reg)) {
            int idx = reg_to_pointer_sized(reg) - REG_START;
            ASSERT(idx >= 0 && idx < NUM_LIVENESS_REGS, "reg enum error");
            uses[idx]++;
            if (opnd_is_memory_reference(opnd))
                uses[idx]++;
        }
    }
}

static void
pick_bb_scratch_regs(instr_t *inst, bb_info_t *bi)
{
    /* Pick the best regs to use as scratch.  We want the fewest uses,
     * since we have to restore on each use (twice for a memref: once
     * for lea, once for app instr).
     * Having varying scratch regs per bb forces us to store which
     * ones so we can restore on slowpath/shadow fault/app fault but
     * it is worth it to shrink fastpath instru.
     *
     * Plan: pick just 2 scratches, and then those that need 3
     * (mem2mem or sub-dword) have to grab a local 3rd but adjust so
     * that ecx is considered #3.
     * Going to always put whole-bb eflags into tls slot, so not
     * considering leaving it in eax and getting 2 more scratch regs, for
     * simplicity: though that could be more efficient for some bbs.
     *
     * Future work PR 492073: if bb has high scores for all regs, try to
     * split into 2: maybe 1st half diff from 2nd half.  Or, fall back to
     * per-instr, can be less expensive than restoring regs before each lea
     * and app instr.
     */
    int uses[NUM_LIVENESS_REGS] = {0,};
    int i, uses_least = INT_MAX, uses_second = INT_MAX;

    while (inst != NULL) {
        if (instr_is_app(inst)) {
            for (i = 0; i < instr_num_dsts(inst); i++)
                pick_bb_scratch_regs_helper(instr_get_dst(inst, i), uses);
            for (i = 0; i < instr_num_srcs(inst); i++)
                pick_bb_scratch_regs_helper(instr_get_src(inst, i), uses);
            if (instr_is_cti(inst))
                break;
        }
        inst = instr_get_next(inst);
    }
    /* Too risky to use esp: if no alt sig stk (ESXi) or on Windows can't
     * handle fault
     */
    uses[DR_REG_XSP - REG_START] = INT_MAX;
#ifdef X86
    /* Future work PR 492073: If esi/edi/ebp are among the least-used, xchg
     * w/ cx/dx/bx and swap in each app instr.  Have to ensure results in
     * legal instrs (if app uses sub-dword, or certain addressing modes).
     */
    uses[DR_REG_XBP - REG_START] = INT_MAX;
    uses[DR_REG_XSI - REG_START] = INT_MAX;
    uses[DR_REG_XDI - REG_START] = INT_MAX;
#elif defined(ARM)
    /* stolen reg must not be used */
    uses[dr_get_stolen_reg() - REG_START] = INT_MAX;
    uses[DR_REG_LR - REG_START] = INT_MAX;
    uses[DR_REG_PC - REG_START] = INT_MAX;
#endif /* X86/ARM */
#ifdef X64
    /* XXX i#1632: once we have byte-to-byte shadowing we shouldn't need
     * just a/b/c/d regs and should be able to use these.  For now with
     * 1B-to-2b we need %ah, etc.
     */
    for (i = DR_REG_R8; i <= DR_REG_R15; i++) {
        ASSERT(i - REG_START < NUM_LIVENESS_REGS, "overflow");
        uses[i - REG_START] = INT_MAX;
    }
#endif
    for (i = 0; i < NUM_LIVENESS_REGS; i++) {
        if (uses[i] < uses_least) {
            uses_second = uses_least;
            bi->reg2.reg = bi->reg1.reg;
            uses_least = uses[i];
            bi->reg1.reg = REG_START + i;
        } else if (uses[i] < uses_second) {
            uses_second = uses[i];
            bi->reg2.reg = REG_START + i;
        }
    }
    /* For PR 493257 (share shadow translations) we do NOT want reg1 to be
     * eax, so we can save eflags w/o clobbering shared shadow addr in reg1
     */
    if (bi->reg1.reg == DR_REG_XAX) {
        scratch_reg_info_t tmp = bi->reg1;
        ASSERT(bi->reg2.reg != DR_REG_XAX, "reg2 shouldn't be eax");
        bi->reg1 = bi->reg2;
        bi->reg2 = tmp;
    }
    /* We don't want ecx in reg1, for sharing.  Even though we swap
     * when we need ecx as a 3rd reg, sharing really wants reg1==whole-bb reg1.
     */
    else if (bi->reg1.reg == DR_REG_XCX && bi->reg2.reg != DR_REG_XAX) {
        scratch_reg_info_t tmp = bi->reg1;
        ASSERT(bi->reg2.reg != DR_REG_XCX, "reg2 shouldn't equal reg1");
        DOLOG(3, {
                void *drcontext = dr_get_current_drcontext();
            LOG(3, "swapping reg1 ");
            opnd_disassemble(drcontext, opnd_create_reg(bi->reg1.reg),
                             LOGFILE(PT_GET(drcontext)));
            LOG(3, " and reg2 ");
            opnd_disassemble(drcontext, opnd_create_reg(bi->reg2.reg),
                             LOGFILE(PT_GET(drcontext)));
            LOG(3, "\n");
        });
        bi->reg1 = bi->reg2;
        bi->reg2 = tmp;
    }
    ASSERT(bi->reg1.reg <= DR_REG_XBX, "NYI non-a/b/c/d reg");
    bi->reg1.slot = SPILL_SLOT_1;
    /* Dead-across-whole-bb is rare so we don't bother to support xchg */
    bi->reg1.xchg = REG_NULL;
    /* The dead fields will be computed in fastpath_pre_app_instr */
    bi->reg1.dead = false;
    bi->reg1.used = false; /* will be set once used */
    bi->reg1.global = true;
    ASSERT(bi->reg2.reg <= DR_REG_XBX, "NYI non-a/b/c/d reg");
    ASSERT(bi->reg1.reg != bi->reg2.reg, "reg conflict");
    bi->reg2.slot = SPILL_SLOT_2;
    bi->reg2.xchg = REG_NULL;
    bi->reg2.dead = false;
    bi->reg2.used = false; /* will be set once used */
    bi->reg2.global = true;

#ifdef STATISTICS
    if (uses_least > 0) {
        STATS_INC(reg_spill_used_in_bb);
    } else {
        STATS_INC(reg_spill_unused_in_bb);
    } if (uses_second > 0) {
        STATS_INC(reg_spill_used_in_bb);
    } else {
        STATS_INC(reg_spill_unused_in_bb);
    }
#endif
    DOLOG(3, {
        void *drcontext = dr_get_current_drcontext();
        tls_util_t *pt = PT_GET(drcontext);
        ASSERT(pt != NULL, "should always have dcontext in cur DR");
        LOG(3, "whole-bb scratch: ");
        print_scratch_reg(drcontext, &bi->reg1, 1, LOGFILE(pt));
        LOG(3, " x%d, ", uses_least);
        print_scratch_reg(drcontext, &bi->reg2, 2, LOGFILE(pt));
        LOG(3, " x%d\n", uses_second);
    });
}
#endif /* X86 */

bool
whole_bb_spills_enabled(void)
{
    /* Whole-bb eflags and register saving requires spill slots that
     * can be live across instructions == our own spill slots.
     * We use SPILL_SLOT_1, SPILL_SLOT_2, and SPILL_SLOT_EFLAGS_EAX
     * for 2 registers and eflags.
     */
    return (options.num_spill_slots >= SPILL_SLOT_EFLAGS_EAX &&
#ifdef TOOL_DR_HEAPSTAT
            options.staleness &&
#endif
            /* should we enable whole-bb for -leaks_only?
             * we'd need to enable bb table and state restore on fault.
             * since it's rare to have more than one stack adjust in a
             * single bb, I don't think we'd gain enough perf to be worth
             * the complexity.
             */
            INSTRUMENT_MEMREFS());
}

void
fastpath_top_of_bb(void *drcontext, void *tag, instrlist_t *bb, bb_info_t *bi)
{
    instr_t *inst = instrlist_first(bb);
#ifdef DEBUG
    /* We look at instr pc, not the tag, to handle displaced code such
     * as for the vsyscall hook.
     */
    app_pc prev_pc = instr_get_app_pc(instrlist_first_app(bb));
    ASSERT(prev_pc != NULL, "bb first app pc must not be NULL");
    /* i#260 and i#1466: bbs must be contiguous */
    if (inst != NULL && whole_bb_spills_enabled() &&
        /* bi->is_repstr_to_loop is set in app2app and may mess up the instr pc */
        !bi->is_repstr_to_loop) {
        for (; inst != NULL; inst = instr_get_next_app(inst)) {
            app_pc cur_pc = instr_get_app_pc(inst);
            if (cur_pc == NULL)
                continue;
            /* relax the check here instead of "cur_pc == prev_pc + instr_length"
             * to allow client adding fake app instr
             */
            ASSERT(cur_pc >= prev_pc, "bb is not contiguous");
            prev_pc = cur_pc;
        }
        inst = instrlist_first(bb);
    }
#endif
    if (inst == NULL || !whole_bb_spills_enabled() ||
        /* pattern is using drreg */
        options.pattern != 0) {
        bi->eflags_used = false;
        bi->reg1.reg = REG_NULL;
        bi->reg1.used = false;
        bi->reg2.reg = REG_NULL;
        bi->reg2.used = false;
        return;
    }
#ifdef X86 /* XXX i#1795: eliminate this and port to drreg */
    /* analyze bb and pick which scratch regs to use.  don't actually do
     * the spills until we know there's actual instrumentation in this bb.
     * we don't also delay the analysis b/c it's simpler to analyze the
     * unmodified instrlist: we do add clean calls that don't count as
     * instru we need to spill for, etc.  we could put in checks for meta
     * but will wait until analysis shows up as perf bottleneck.
     */
    pick_bb_scratch_regs(inst, bi);
#endif
}

/* Invoked before the regular pre-app instrumentation */
void
fastpath_pre_instrument(void *drcontext, instrlist_t *bb, instr_t *inst, bb_info_t *bi)
{
#ifdef X86
    int live[NUM_LIVENESS_REGS];
#endif
    app_pc pc = instr_get_app_pc(inst);
    if (pc != NULL) {
        if (bi->first_app_pc == NULL)
            bi->first_app_pc = pc;
        bi->last_app_pc = pc;
    }

    if (!whole_bb_spills_enabled())
        return;
    if (options.pattern != 0) /* pattern is using drreg */
        return;
#ifdef X86 /* XXX i#1795: eliminate this and port to drreg */
    /* Haven't instrumented below here yet, so forward analysis should
     * see only app instrs
     * XXX i#777: should do reverse walk during analysis phase and store results
     * in bit array in new note fields
     */
    bi->aflags = get_aflags_and_reg_liveness(inst, live, options.pattern != 0);
    /* Update the dead fields */
    if (bi->reg1.reg != DR_REG_NULL)
        bi->reg1.dead = (live[bi->reg1.reg - REG_START] == LIVE_DEAD);
    if (bi->reg2.reg != DR_REG_NULL)
        bi->reg2.dead = (live[bi->reg2.reg - REG_START] == LIVE_DEAD);

    bi->eax_dead = (live[DR_REG_XAX - REG_START] == LIVE_DEAD);
#endif
}

bool
instr_is_spill(instr_t *inst)
{
    return (instr_get_opcode(inst) == IF_X86_ELSE(OP_mov_st, OP_str) &&
            is_spill_slot_opnd(dr_get_current_drcontext(), instr_get_dst(inst, 0)) &&
            opnd_is_reg(instr_get_src(inst, 0)));
}

bool
instr_is_restore(instr_t *inst)
{
    return (instr_get_opcode(inst) == IF_X86_ELSE(OP_mov_ld, OP_ldr) &&
            is_spill_slot_opnd(dr_get_current_drcontext(), instr_get_src(inst, 0)) &&
            opnd_is_reg(instr_get_dst(inst, 0)));
}

bool
instr_at_pc_is_restore(void *drcontext, byte *pc)
{
    instr_t inst;
    bool res;
    instr_init(drcontext, &inst);
    res = (decode(drcontext, pc, &inst) != NULL &&
           instr_is_restore(&inst));
    instr_free(drcontext, &inst);
    return res;
}

void
mark_eflags_used(void *drcontext, instrlist_t *bb, bb_info_t *bi)
{
    instr_t *where_spill = (bi == NULL || bi->spill_after == NULL) ?
        instrlist_first(bb) : instr_get_next(bi->spill_after);
    if (!whole_bb_spills_enabled() || bi == NULL/*gencode*/ || bi->eflags_used)
        return;
    /* optimization: if flags are dead then ignore our use.
     * technically unsafe (PR 463053).
     * FIXME: for use in fastpath_pre_instrument() for post-instr
     * save are we using the pre-instr analysis?
     */
    if (bi->aflags == EFLAGS_WRITE_ARITH) {
        LOG(4, "eflags are dead so not saving\n");
        return;
    }
    /* To use global-eax for eflags we must spill regs before flags */
    while (instr_is_meta(where_spill) &&
           instr_is_spill(where_spill) &&
           instr_get_next(where_spill) != NULL)
        where_spill = instr_get_next(where_spill);
    LOG(4, "marking eflags used => spilling if live\n");
    bi->eflags_used = true;
    save_aflags_if_live(drcontext, bb, where_spill, NULL, bi);
#ifdef STATISTICS
    if (bi->aflags != EFLAGS_WRITE_ARITH)
        STATS_INC(aflags_saved_at_top);
#endif
}

void
mark_scratch_reg_used(void *drcontext, instrlist_t *bb,
                      bb_info_t *bi, scratch_reg_info_t *si)
{
    instr_t *where_spill = (bi == NULL || bi->spill_after == NULL) ?
        instrlist_first(bb) : instr_get_next(bi->spill_after);
    /* Update global used values, and if global save on first use in bb */
    if (si->used)
        return;
    if (si->global) {
        ASSERT(bi != NULL, "should only use global in bb, not gencode");
        /* To use global-eax for eflags we must spill regs before flags */
        while (instr_get_prev(where_spill) != NULL &&
               instr_is_meta(instr_get_prev(where_spill)) &&
               /* We want to NOT walk back into clean call: clean call
                * ends in restore, not spill
                */
               instr_is_spill(instr_get_prev(where_spill)))
            where_spill = instr_get_prev(where_spill);
        if (si->reg == bi->reg1.reg) {
            bi->reg1.used = true;
            insert_spill_global(drcontext, bb, where_spill, &bi->reg1, true/*save*/);
        } else {
            ASSERT(si->reg == bi->reg2.reg, "global vs local mismatch");
            bi->reg2.used = true;
            insert_spill_global(drcontext, bb, where_spill, &bi->reg2, true/*save*/);
        }
    }
    /* Even if global we have to mark the si copy as used too */
    si->used = true;
}

bool
instr_needs_eflags_restore(instr_t *inst, uint aflags_liveness)
{
    return (TESTANY(EFLAGS_READ_ARITH,
                    instr_get_eflags(inst, DR_QUERY_DEFAULT)) ||
            /* If the app instr writes some subset of eflags we need to restore
             * rest so they're combined properly
             */
            (TESTANY(EFLAGS_WRITE_ARITH,
                     instr_get_eflags(inst, DR_QUERY_INCLUDE_ALL)) &&
             aflags_liveness != EFLAGS_WRITE_ARITH));
}

/* Invoked after the regular pre-app instrumentation */
void
fastpath_pre_app_instr(void *drcontext, instrlist_t *bb, instr_t *inst,
                       bb_info_t *bi, fastpath_info_t *mi)
{
    /* Preserve app semantics wrt global spilled registers */
    /* XXX i#777: gets next instr, and below does liveness analysis w/ forward scan.
     * should use stored info from reverse scan done during analysis phase.
     */
#ifdef X86
    instr_t *next = instr_get_next(inst);
    int live[NUM_LIVENESS_REGS];
    bool restored_for_read = false;
#endif

    if (!whole_bb_spills_enabled())
        return;
    if (options.pattern != 0) /* pattern is using drreg */
        return;

#ifdef X86 /* XXX i#1795: eliminate this and port to drreg */
    /* If this is the last instr, the end-of-bb restore will restore for any read,
     * and everything is dead so we can ignore writes
     */
    if (next == NULL)
        return;

    /* Before each read, restore global spilled registers */
    if (instr_needs_eflags_restore(inst, bi->aflags))
        restore_aflags_if_live(drcontext, bb, inst, mi, bi);
    /* Optimization: don't bother to restore if this is not a meaningful read
     * (e.g., xor with self)
     */
    if ((bi->reg1.reg != DR_REG_NULL || bi->reg2.reg != DR_REG_NULL) &&
        (!result_is_always_defined(inst, true/*natively*/) ||
         /* if sub-dword then we have to restore for rest of bits */
         opnd_get_size(instr_get_src(inst, 0)) != OPSZ_4)) {
        /* we don't mark as used: if unused so far, no reason to restore */
        if (instr_reads_from_reg(inst, bi->reg1.reg, DR_QUERY_INCLUDE_ALL) ||
            /* if sub-reg is written we need to restore rest */
            (instr_writes_to_reg(inst, bi->reg1.reg, DR_QUERY_INCLUDE_ALL) &&
             !instr_writes_to_exact_reg(inst, bi->reg1.reg, DR_QUERY_INCLUDE_ALL)) ||
            /* for conditional write, simplest to restore before and save after, b/c
             * if cond fails we have to avoid saving bogus value
             */
            (instr_writes_to_reg(inst, bi->reg1.reg, DR_QUERY_INCLUDE_ALL) &&
             !instr_writes_to_reg(inst, bi->reg1.reg, DR_QUERY_DEFAULT))) {
            restored_for_read = true;
            /* If reg1 holds a shared shadow addr, better to preserve it than
             * to have to re-translate
             */
            if (!opnd_is_null(bi->shared_memop)) {
                if (instr_writes_to_reg(inst, bi->reg1.reg, DR_QUERY_INCLUDE_ALL) ||
                    instr_writes_to_reg(inst, bi->reg2.reg, DR_QUERY_INCLUDE_ALL) ||
                    /* must consider reading the other reg (PR 494169) */
                    instr_reads_from_reg(inst, bi->reg2.reg, DR_QUERY_INCLUDE_ALL)) {
                    /* give up: not worth complexity (i#165 covers handling) */
                    STATS_INC(xl8_not_shared_reg_conflict);
                    bi->shared_memop = opnd_create_null();
                } else {
                    PRE(bb, inst,
                        XINST_CREATE_store(drcontext, opnd_create_reg(bi->reg2.reg),
                                           opnd_create_reg(bi->reg1.reg)));
                    PRE(bb, next,
                        XINST_CREATE_store(drcontext, opnd_create_reg(bi->reg1.reg),
                                           opnd_create_reg(bi->reg2.reg)));
                }
            }
            insert_spill_global(drcontext, bb, inst, &bi->reg1, false/*restore*/);
        }
        if (instr_reads_from_reg(inst, bi->reg2.reg, DR_QUERY_INCLUDE_ALL) ||
            /* if sub-reg is written we need to restore rest */
            (instr_writes_to_reg(inst, bi->reg2.reg, DR_QUERY_INCLUDE_ALL) &&
             !instr_writes_to_exact_reg(inst, bi->reg2.reg, DR_QUERY_INCLUDE_ALL)) ||
            /* for conditional write, simplest to restore before and save after, b/c
             * if cond fails we have to avoid saving bogus value
             */
            (instr_writes_to_reg(inst, bi->reg2.reg, DR_QUERY_INCLUDE_ALL) &&
             !instr_writes_to_reg(inst, bi->reg2.reg, DR_QUERY_DEFAULT))) {
            restored_for_read = true;
            insert_spill_global(drcontext, bb, inst, &bi->reg2, false/*restore*/);
        }
    }

    /* After each write, update global spilled values, unless that reg is
     * dead (xref PR 463053 for safety)
     */
    /* Haven't instrumented below here yet, so forward analysis should
     * see only app instrs
     */
    /* We updated reg*.dead in fastpath_pre_instrument() but here we want
     * liveness post-app-instr
     */
    bi->aflags = get_aflags_and_reg_liveness(next, live, options.pattern != 0);
    /* Update the dead fields */
    if (bi->reg1.reg != DR_REG_NULL)
        bi->reg1.dead = (live[bi->reg1.reg - REG_START] == LIVE_DEAD);
    if (bi->reg2.reg != DR_REG_NULL)
        bi->reg2.dead = (live[bi->reg2.reg - REG_START] == LIVE_DEAD);
    bi->eax_dead = (live[DR_REG_XAX - REG_START] == LIVE_DEAD);

    if (bi->reg1.reg != DR_REG_NULL &&
        instr_writes_to_reg(inst, bi->reg1.reg, DR_QUERY_INCLUDE_ALL)) {
        if (!bi->reg1.dead) {
            bi->reg1.used = true;
            insert_spill_global(drcontext, bb, next, &bi->reg1, true/*save*/);
        }
        /* If reg1 holds a shared shadow addr, better to preserve it than
         * to have to re-translate.  We must do this even if reg1 is dead.
         */
        if (!opnd_is_null(bi->shared_memop)) {
            if (restored_for_read ||
                (instr_writes_to_reg(inst, bi->reg2.reg, DR_QUERY_INCLUDE_ALL) &&
                 !bi->reg2.dead)) {
                /* give up: not worth complexity for now (i#165 covers handling) */
                STATS_INC(xl8_not_shared_reg_conflict);
                bi->shared_memop = opnd_create_null();
            } else {
                bi->reg1.used = true;
                PRE(bb, inst,
                    XINST_CREATE_store(drcontext, opnd_create_reg(bi->reg2.reg),
                                       opnd_create_reg(bi->reg1.reg)));
                PRE(bb, next,
                    XINST_CREATE_store(drcontext, opnd_create_reg(bi->reg1.reg),
                                       opnd_create_reg(bi->reg2.reg)));
            }
        }
    }
    if (bi->reg2.reg != DR_REG_NULL &&
        instr_writes_to_reg(inst, bi->reg2.reg, DR_QUERY_INCLUDE_ALL) &&
        !bi->reg2.dead) {
        bi->reg2.used = true;
        insert_spill_global(drcontext, bb, next, &bi->reg2, true/*save*/);
    }
    if (TESTANY(EFLAGS_WRITE_ARITH,
                instr_get_eflags(inst, DR_QUERY_INCLUDE_ALL)) &&
        bi->aflags != EFLAGS_WRITE_ARITH) {
        /* Optimization: no need if next is jcc and we just checked definedness */
        if (IF_DRMEM(bi->eflags_defined && ) instr_is_jcc(next)) {
            /* We just wrote to real eflags register, so don't restore at end */
            LOG(4, "next instr is jcc so not saving eflags\n");
            bi->eflags_used = false;
        } else {
            save_aflags_if_live(drcontext, bb, next, mi, bi);
        }
    }
#endif /* X86 */
}

void
fastpath_bottom_of_bb(void *drcontext, void *tag, instrlist_t *bb,
                      bb_info_t *bi, bool added_instru, bool translating,
                      bool check_ignore_unaddr)
{
    instr_t *last = instrlist_last(bb);
    bb_saved_info_t *save;
    if (!whole_bb_spills_enabled())
        return;
    ASSERT(!added_instru || instrlist_first(bb) != NULL, "can't add instru w/o instrs");

    /* the .used field controls whether we actually saved, and thus restore */
    LOG(3, "whole-bb scratch: r1=%s, r2=%s, efl=%s\n",
        bi->reg1.used ? "used" : "unused",
        bi->reg2.used ? "used" : "unused",
        bi->eflags_used ? "used" : "unused");

    if (!translating) {
        /* Add to table so we can restore on slowpath or a fault */
        save = (bb_saved_info_t *) global_alloc(sizeof(*save), HEAPSTAT_PERBB);
        memset(save, 0, sizeof(*save));
        /* If dead initially and only used later, fine to have fault path
         * restore from TLS early since dead.  But if never used and thus never
         * spilled then we have to tell the fault path to not restore from TLS.
         */
        if (bi->reg1.used)
            save->scratch1 = bi->reg1.reg;
        else
            save->scratch1 = REG_NULL;
        if (bi->reg2.used)
            save->scratch2 = bi->reg2.reg;
        else
            save->scratch2 = REG_NULL;
        save->eflags_saved = bi->eflags_used;
        save->aflags_in_eax = (bi->aflags_where == AFLAGS_IN_EAX);
        /* We store the pc of the last instr, since everything is restored
         * already (and NOT present in our tls slots) if have a fault in that
         * instr: unless it's a transformed repstr, in which case the final
         * OP_loop won't fault, so a fault will be before the restores (i#532).
         */
        if (bi->is_repstr_to_loop)
            save->last_instr = NULL;
        else
            save->last_instr = bi->last_app_pc;
        /* i#1466: remember the first_restore_pc for restore state in pattern mode */
        save->first_restore_pc = bi->first_restore_pc;
        save->check_ignore_unaddr = check_ignore_unaddr;
        /* i#826: share_xl8_max_diff can change, save it. */
        save->share_xl8_max_diff = bi->share_xl8_max_diff;
        /* store style of instru rather than ask DR to store xl8.
         * XXX DRi#772: could add flush callback and avoid this save
         */
        save->pattern_4byte_check_only = bi->pattern_4byte_check_only;

        /* we store the size and assume bbs are contiguous so we can free (i#260) */
        ASSERT(bi->first_app_pc != NULL, "first instr should have app pc");
        ASSERT(bi->last_app_pc != NULL, "last instr should have app pc");
        if (bi->is_repstr_to_loop) /* first is +1 hack */
            bi->first_app_pc = bi->last_app_pc;
        else {
            ASSERT(bi->last_app_pc >= bi->first_app_pc,
                   "bb should be contiguous w/ increasing pcs");
        }
        save->bb_size = decode_next_pc(drcontext, bi->last_app_pc) - bi->first_app_pc;

        /* PR 495787: Due to non-precise flushing we can have a flushed bb
         * removed from the htables and then a new bb created before we received
         * the deletion event.  We can't tell this apart from duplication due to
         * thread-private copies: but this mechanism should handle that as well,
         * since our saved info should be deterministic and identical for each
         * copy.  Note that we do not want a new "unreachable event" b/c we need
         * to keep our bb info around in case the semi-flushed bb hits a fault.
         */
        hashtable_lock(&bb_table);
        bb_save_add_entry(tag, save);
        hashtable_unlock(&bb_table);
    }
    if (options.pattern != 0) /* pattern is using drreg */
        return;

    /* We do this *after* recording what to restore, b/c this can change the used
     * fields (i#1458).
     */
    if (added_instru) {
        restore_aflags_if_live(drcontext, bb, last, NULL, bi);
        if (bi->reg1.reg != DR_REG_NULL)
            insert_spill_global(drcontext, bb, last, &bi->reg1, false/*restore*/);
        if (bi->reg2.reg != DR_REG_NULL)
            insert_spill_global(drcontext, bb, last, &bi->reg2, false/*restore*/);
    }
}
