/* **********************************************************
 * Copyright (c) 2010-2018 Google, Inc.  All rights reserved.
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

/* We need at most 3 simulataneous scratch reg slots + eflags */
#define NUM_REG_SPILL_SLOTS 4

/* Non-pattern mode uses a few slots separate from drreg. */
#define NEED_OWN_TLS_SLOTS() (options.pattern == 0)

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
    drreg_options_t ops = {
        sizeof(ops), NUM_REG_SPILL_SLOTS, options.conservative, handle_drreg_error,
    };
    IF_DEBUG(drreg_status_t res =)
        drreg_init(&ops);
    ASSERT(res == DRREG_SUCCESS, "fatal error: failed to initialize drreg");
    if (NEED_OWN_TLS_SLOTS()) {
        IF_DEBUG(bool ok =)
            dr_raw_tls_calloc(&seg_tls, &tls_instru_base, options.num_spill_slots, 0);
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
    IF_DEBUG(drreg_status_t res =)
        drreg_exit();
    ASSERT(res == DRREG_SUCCESS, "WARNING: drreg failed on exit");
    if (NEED_OWN_TLS_SLOTS()) {
        IF_DEBUG(bool ok =)
            dr_raw_tls_cfree(tls_instru_base, options.num_spill_slots);
        ASSERT(ok, "WARNING: unable to free tls slots");
        drmgr_unregister_tls_field(tls_idx_instru);
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
    if (NEED_OWN_TLS_SLOTS()) {
        /* store in per-thread data struct so we can access from another thread */
        drmgr_set_tls_field(drcontext, tls_idx_instru, (void *)
                            (get_own_seg_base() + tls_instru_base));
    }
}

void
instru_tls_thread_exit(void *drcontext)
{
    if (NEED_OWN_TLS_SLOTS())
        drmgr_set_tls_field(drcontext, tls_idx_instru, NULL);
}

static opnd_t
opnd_create_own_spill_slot(uint index)
{
    ASSERT(index < options.num_spill_slots, "spill slot index overflow");
    ASSERT(INSTRUMENT_MEMREFS(), "incorrectly called");
    return opnd_create_far_base_disp_ex
        /* must use 0 scale to match what DR decodes for opnd_same */
        (seg_tls, REG_NULL, REG_NULL, 0,
         tls_instru_base + index*sizeof(ptr_uint_t), OPSZ_PTR,
         /* we do NOT want an addr16 prefix since most likely going to run on
          * Core or Core2, and P4 doesn't care that much */
         false, true, false);
}

ptr_uint_t
get_own_tls_value(uint index)
{
    ASSERT(options.num_spill_slots > 0, "should not get here if we have no slots");
    if (index < options.num_spill_slots) {
        byte *seg_base = get_own_seg_base();
        return *(ptr_uint_t *) (seg_base + tls_instru_base + index*sizeof(ptr_uint_t));
    } else {
        dr_spill_slot_t DR_slot = index - options.num_spill_slots;
        return dr_read_saved_reg(dr_get_current_drcontext(), DR_slot);
    }
}

void
set_own_tls_value(uint index, ptr_uint_t val)
{
    ASSERT(options.num_spill_slots > 0, "should not get here if we have no slots");
    if (index < options.num_spill_slots) {
        byte *seg_base = get_own_seg_base();
        *(ptr_uint_t *)(seg_base + tls_instru_base + index*sizeof(ptr_uint_t)) = val;
    } else {
        dr_spill_slot_t DR_slot = index - options.num_spill_slots;
        dr_write_saved_reg(dr_get_current_drcontext(), DR_slot, val);
    }
}

ptr_uint_t
get_thread_tls_value(void *drcontext, uint index)
{
    ASSERT(options.num_spill_slots > 0, "should not get here if we have no slots");
    if (index < options.num_spill_slots) {
        byte *tls = (byte *) drmgr_get_tls_field(drcontext, tls_idx_instru);
        return *(ptr_uint_t *)(tls + index*sizeof(ptr_uint_t));
    } else {
        dr_spill_slot_t DR_slot = index - options.num_spill_slots;
        return dr_read_saved_reg(drcontext, DR_slot);
    }
}

void
set_thread_tls_value(void *drcontext, uint index, ptr_uint_t val)
{
    ASSERT(options.num_spill_slots > 0, "should not get here if we have no slots");
    if (index < options.num_spill_slots) {
        byte *tls = (byte *) drmgr_get_tls_field(drcontext, tls_idx_instru);
        *(ptr_uint_t *)(tls + index*sizeof(ptr_uint_t)) = val;
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

opnd_t
spill_slot_opnd(void *drcontext, dr_spill_slot_t slot)
{
    ASSERT(options.pattern == 0, "not converted to drreg yet");
    return opnd_create_own_spill_slot(slot);
}

/***************************************************************************
 * STATE RESTORATION
 */

/* drreg takes care of restoring for spilled registers.  We just need
 * to perform a few shadow-related restorations.
 */
bool
event_restore_state(void *drcontext, bool restore_memory, dr_restore_state_info_t *info)
{
    bool shadow_write = false;
    instr_t inst;
    uint memopidx;
    bool write;
    byte *addr;

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
 * drreg wrappers that assert on failure and update fastpath_info_t.
 */

void
reserve_aflags(void *drcontext, instrlist_t *ilist, instr_t *where)
{
    IF_DEBUG(drreg_status_t res =)
        drreg_reserve_aflags(drcontext, ilist, where);
    /* We're ok with IN_USE b/c of our "lazy spill, single restore" strategy. */
    ASSERT(res == DRREG_SUCCESS || res == DRREG_ERROR_IN_USE, "failed to reserve aflags");
    LOG(4, "\t%s @"PFX"\n", __FUNCTION__, instr_get_app_pc(where));
}

void
unreserve_aflags(void *drcontext, instrlist_t *ilist, instr_t *where)
{
    IF_DEBUG(drreg_status_t res =)
        drreg_unreserve_aflags(drcontext, ilist, where);
    /* We're ok with INVALID b/c of our "lazy spill, single restore" strategy. */
    ASSERT(res == DRREG_SUCCESS || res == DRREG_ERROR_INVALID_PARAMETER,
           "failed to unreserve aflags");
    LOG(4, "\t%s @"PFX"\n", __FUNCTION__, instr_get_app_pc(where));
}

reg_id_t
reserve_register(void *drcontext, instrlist_t *ilist, instr_t *where,
                 drvector_t *reg_allowed,
                 INOUT fastpath_info_t *mi, OUT reg_id_t *reg_out)
{
    reg_id_t reg;
    IF_DEBUG(drreg_status_t res =)
        drreg_reserve_register(drcontext, ilist, where, reg_allowed, &reg);
    ASSERT(res == DRREG_SUCCESS, "failed to reserve scratch register");
    if (mi != NULL) {
        ASSERT(reg_out != NULL, "need to know reg dest");
        if (reg_out == &mi->reg1) {
            mi->reg1_8 = reg_ptrsz_to_8(reg);
            mi->reg1_16 = reg_ptrsz_to_16(reg);
        } else if (reg_out == &mi->reg2) {
            mi->reg2_16 = reg_ptrsz_to_16(reg);
            mi->reg2_8 = reg_ptrsz_to_8(reg);
            if (reg >= DR_REG_XAX && reg <= DR_REG_XBX)
                mi->reg2_8h = reg_ptrsz_to_8h(reg);
            else
                mi->reg2_8h = DR_REG_NULL;
        } else if (reg_out == &mi->reg3) {
            mi->reg3_8 = reg_ptrsz_to_8(reg);
            mi->reg3_16 = reg_ptrsz_to_16(reg);
        }
    }
    return reg;
}

void
unreserve_register(void *drcontext, instrlist_t *ilist, instr_t *where, reg_id_t reg,
                   INOUT fastpath_info_t *mi, bool force_restore_now)
{
    IF_DEBUG(drreg_status_t res =)
        drreg_unreserve_register(drcontext, ilist, where, reg);
    if (force_restore_now)
        drreg_get_app_value(drcontext, ilist, where, reg, reg);
    ASSERT(res == DRREG_SUCCESS, "failed to unreserve scratch register");
    if (mi != NULL) {
        if (reg == mi->reg1) {
            mi->reg1 = DR_REG_NULL;
            mi->reg1_8 = DR_REG_NULL;
            mi->reg1_16 = DR_REG_NULL;
        } else if (reg == mi->reg2) {
            mi->reg2 = DR_REG_NULL;
            mi->reg2_16 = DR_REG_NULL;
            mi->reg2_8 = DR_REG_NULL;
            mi->reg2_8h = DR_REG_NULL;
        } else if (reg == mi->reg3) {
            mi->reg3 = DR_REG_NULL;
            mi->reg3_8 = DR_REG_NULL;
            mi->reg3_16 = DR_REG_NULL;
        }
    }
}

void
reserve_shared_register(void *drcontext, instrlist_t *ilist, instr_t *where,
                        drvector_t *reg_allowed, INOUT fastpath_info_t *mi)
{
    ASSERT(mi != NULL && mi->bb != NULL, "shared register requires fastpath & bb info");
    if (mi->reg1 == DR_REG_NULL) {
        if (mi->bb->shared_reg != DR_REG_NULL)
            mi->reg1 = mi->bb->shared_reg;
        else {
            mi->reg1 = reserve_register(drcontext, ilist, where, reg_allowed, mi,
                                        &mi->reg1);
            mi->bb->shared_reg = mi->reg1;
        }
    } else
        ASSERT(mi->reg1 == mi->bb->shared_reg, "shared register inconsistency");
}

void
unreserve_shared_register(void *drcontext, instrlist_t *ilist, instr_t *where,
                          INOUT fastpath_info_t *mi, INOUT bb_info_t *bi)
{
    ASSERT(bi != NULL, "shared register requires fastpath && bb info");
    if (bi->shared_reg != DR_REG_NULL) {
        unreserve_register(drcontext, ilist, where, bi->shared_reg, NULL, false);
        bi->shared_reg = DR_REG_NULL;
        if (mi != NULL) {
            ASSERT(bi->shared_reg == mi->reg1, "shared register inconsistency");
            mi->reg1 = DR_REG_NULL;
        }
    }
}

static bool
instr_is_spill(void *drcontext, instr_t *inst, reg_id_t *reg_spilled OUT)
{
    bool spill;
    drreg_status_t res = drreg_is_instr_spill_or_restore(drcontext, inst, &spill,
                                                         NULL, reg_spilled);
    ASSERT(res == DRREG_SUCCESS, "failed to query drreg for spill info");
    return spill;
}

static bool
instr_is_restore(void *drcontext, instr_t *inst, reg_id_t *reg_restored OUT)
{
    bool restore;
    drreg_status_t res = drreg_is_instr_spill_or_restore(drcontext, inst, NULL,
                                                         &restore, reg_restored);
    ASSERT(res == DRREG_SUCCESS, "failed to query drreg for spill info");
    return restore;
}

bool
instr_at_pc_is_restore(void *drcontext, byte *pc)
{
    instr_t inst;
    bool res;
    instr_init(drcontext, &inst);
    res = (decode(drcontext, pc, &inst) != NULL &&
           instr_is_restore(drcontext, &inst, NULL));
    instr_free(drcontext, &inst);
    return res;
}

/* XXX i#1795: we should remove this once everything is converted to drreg */
bool
whole_bb_spills_enabled(void)
{
    return (
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

#ifdef DEBUG
void
print_scratch_reg(void *drcontext, reg_id_t reg, instr_t *where, const char *name,
                  file_t file)
{
    if (reg == DR_REG_NULL)
        return;
    bool is_dr, is_dead;
    uint tls_offs;
    drreg_status_t res =
        drreg_reservation_info(drcontext, reg, NULL, &is_dr, &tls_offs);
    ASSERT(res == DRREG_SUCCESS, "failed to get reservation info");
    res = drreg_is_register_dead(drcontext, reg, where, &is_dead);
    ASSERT(res == DRREG_SUCCESS, "failed to get deadness");
    dr_fprintf(file, "%s=", name);
    opnd_disassemble(drcontext, opnd_create_reg(reg), file);
    if (is_dead) {
        dr_fprintf(file, " dead");
    } else {
        dr_fprintf(file, " spill@0x%x%s", tls_offs, is_dr ? " (DR)" : "");
    }
}

void
check_scratch_reg_parity(void *drcontext, instrlist_t *bb, instr_t *app_instr,
                         instr_t *instru_start)
{
    instr_t *in;
    tls_util_t *pt = PT_GET(drcontext);
    if (instru_start == NULL)
        in = instrlist_first(bb);
    else
        in = instr_get_next(instru_start);
    bool past_cti = false;
    reg_id_t spilled;
    for (; in != app_instr; in = instr_get_next(in)) {
        if (!past_cti && instr_is_cti(in))
            past_cti = true;
        if (instr_is_spill(drcontext, in, &spilled) && past_cti) {
            instr_t *forw;
            reg_id_t restored;
            bool local_restore = false;
            for (forw = in; forw != app_instr; forw = instr_get_next(forw)) {
                if (instr_is_restore(drcontext, forw, &restored) && restored == spilled) {
                    local_restore = true;
                    break;
                }
                if (instr_is_cti(forw))
                    break;
            }
            if (!local_restore) {
                ELOGPT(0, pt, "ERROR: local reg spill w/o cti parity for app instr: ");
                instr_disassemble(drcontext, app_instr, pt->f);
                ELOGPT(0, pt, "\n\nentire instrlist:");
                instrlist_disassemble(drcontext, NULL, bb, pt->f);
                ASSERT(false, "local reg spill w/o cti parity!");
            }
        }
    }
}
#endif
