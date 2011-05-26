/* **********************************************************
 * Copyright (c) 2010-2011 Google, Inc.  All rights reserved.
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
 * readwrite.c: Dr. Memory read/write instrumentation
 */

#include "dr_api.h"
#include "drmemory.h"
#include "readwrite.h"
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
#ifdef TOOL_DR_HEAPSTAT
# include "../drheapstat/staleness.h"
#endif

/* State restoration: need to record which bbs have eflags-save-at-top.
 * We store the app pc of the last instr in the bb.
 */
#define BB_HASH_BITS 12
hashtable_t bb_table;

/* PR 493257: share shadow translation across multiple instrs.  But, abandon
 * sharing for memrefs that cross 64K boundaries and keep exiting to slowpath.
 * This table tracks slowpath exits and whether to share.
 */
#define XL8_SHARING_HASH_BITS 10
hashtable_t xl8_sharing_table;

/* alloca handling in fastpath (i#91) */
#define IGNORE_UNADDR_HASH_BITS 6
hashtable_t ignore_unaddr_table;

/* Handle slowpath for OP_loop in repstr_to_loop properly (i#391).
 * We map the address of an allocated OP_loop to the app_pc of the original
 * app rep-stringop instr.  We also map the reverse so we can delete it
 * (we don't want to pay the cost of storing this in bb_saved_info_t for
 * every single bb).  We're helped there b/c repstr_to_loop always
 * has single-instr bbs so the tag is the rep-stringop instr pc.
 */
#define STRINGOP_HASH_BITS 6
static hashtable_t stringop_us2app_table;
static hashtable_t stringop_app2us_table;
static void *stringop_lock; /* protects both tables */
/* Entry in stringop_app2us_table */
typedef struct _stringop_entry_t {
    /* an OP_loop encoding, decoded by slow_path */
    byte loop_instr[LOOP_INSTR_LENGTH];
    /* This is used to handle non-precise flushing */
    byte ignore_next_delete;
} stringop_entry_t;

#ifdef STATISTICS
/* per-opcode counts */
uint64 slowpath_count[OP_LAST+1];
/* per-opsz counts */
uint64 slowpath_sz1;
uint64 slowpath_sz2;
uint64 slowpath_sz4;
uint64 slowpath_sz8;
uint64 slowpath_szOther;

/* PR 423757: periodic stats dump */
uint next_stats_dump;

uint num_faults;
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
uint strcpy_exception;
uint rawmemchr_exception;
uint strmem_unaddr_exception;
uint strrchr_exception;
uint andor_exception;
uint loader_DRlib_exception;
uint cppexcept_DRlib_exception;
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
uint xl8_not_shared_disp_too_big;
uint xl8_not_shared_unaligned;
uint xl8_not_shared_mem2mem;
uint xl8_not_shared_offs;
uint xl8_not_shared_slowpaths;
uint xl8_shared_slowpath_instrs;
uint xl8_shared_slowpath_count;
uint slowpath_unaligned;
uint slowpath_8_at_border;
uint app_instrs_fastpath;
uint app_instrs_no_dup;
uint xl8_app_for_slowpath;
uint movs4_src_unaligned;
uint movs4_dst_unaligned;
uint movs4_src_undef;
uint movs4_med_fast;
#endif

/***************************************************************************
 * Registers
 */

/* To relocate restores to the common slowpath yet still support
 * site-specific scratch registers we have restore patterns for
 * every possible combination
 */
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
#define SPILL_REG3_REG   REG_ECX

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

/* The 4 indices are: reg1, reg2, reg3, eflags */
byte *shared_slowpath_entry_local[SPILL_REG_NUM][SPILL_REG_NUM][SPILL_REG3_NUM][SPILL_EFLAGS_NUM];
/* For whole-bb spilling, we do not restore eflags, but reg3 can be anything */
byte *shared_slowpath_entry_global[SPILL_REG_NUM][SPILL_REG_NUM][SPILL_REG_NUM];
byte *shared_slowpath_region;
byte *shared_slowpath_entry;
/* adjust_esp's shared fast and slow paths pointers are below */

/* Indirection to allow us to switch which TLS slots we use for spill slots */
#define MAX_FAST_DR_SPILL_SLOT SPILL_SLOT_3

/* Lock for updating gencode later */
static void *gencode_lock;

void
spill_reg(void *drcontext, instrlist_t *ilist, instr_t *where, reg_id_t reg,
          dr_spill_slot_t slot)
{
    if (slot < options.num_spill_slots) {
        STATS_INC(reg_spill_own);
        PRE(ilist, where,
            INSTR_CREATE_mov_st(drcontext, opnd_create_own_spill_slot(slot),
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
    if (slot < options.num_spill_slots) {
        PRE(ilist, where,
            INSTR_CREATE_mov_ld(drcontext, opnd_create_reg(reg),
                                opnd_create_own_spill_slot(slot)));
    } else {
        dr_spill_slot_t DR_slot = slot - options.num_spill_slots;
        dr_restore_reg(drcontext, ilist, where, reg, DR_slot);
    }
}

opnd_t
spill_slot_opnd(void *drcontext, dr_spill_slot_t slot)
{
    if (slot < options.num_spill_slots) {
        return opnd_create_own_spill_slot(slot);
    } else {
        dr_spill_slot_t DR_slot = slot - options.num_spill_slots;
        return dr_reg_spill_slot_opnd(drcontext, DR_slot);
    }
}

bool
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
        opnd_get_segment(op) == SEG_FS) {
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
    /* FIXME PR 485216: we should restore dead registers on a fault, but it
     * would be a perf hit to save them: for now we don't do anything.
     * It's doubtful an app will ever have a problem with that.
     */
    bb_saved_info_t *save;

#ifdef TOOL_DR_MEMORY
    per_thread_t *pt = (per_thread_t *) dr_get_tls_field(drcontext);
    client_per_thread_t *cpt;
    ASSERT(pt != NULL, "pt shouldn't be null");
    cpt = (client_per_thread_t *) pt->client_data;

    if (options.leaks_only || !options.shadowing)
        return true;

    /* Are we asking DR to translate just pc?  Then return true and ignore regs */
    if (cpt->self_translating) {
        ASSERT(options.single_arg_slowpath || options.verbose >= 3,
               "only used for single_arg_slowpath or -verbose 3+");
        return true;
    }
#endif

    hashtable_lock(&bb_table);
    save = (bb_saved_info_t *) hashtable_lookup(&bb_table, info->fragment_info.tag);
#ifdef TOOL_DR_MEMORY
    DOLOG(2, {
        /* We leave the translation as being in our own library, since no
         * other good alternative.  We document this to users.
         */
        if (in_replace_routine(info->mcontext->pc))
            LOG(2, "fault in replace_ routine "PFX"\n", info->mcontext->pc);
    });
#endif
    if (save != NULL) {
        /* We save first thing and restore prior to last instr.
         * Our restore clobbers the eflags value in our tls slot, so
         * on a fault in the last instr we should do nothing.
         * FIXME: NOT TESTED: need carefully constructed test to hit this
         */
        if (info->mcontext->pc != save->last_instr) {
            /* Use drcontext's shadow, not executing thread's shadow! (PR 475211) */
            ptr_uint_t regval;
            if (save->eflags_saved) {
                IF_DEBUG(ptr_uint_t orig_flags = info->mcontext->eflags;)
                uint sahf;
                regval = get_thread_tls_value(drcontext, SPILL_SLOT_EFLAGS_EAX);
                sahf = (regval & 0xff00) >> 8;
                info->mcontext->eflags &= ~0xff;
                info->mcontext->eflags |= sahf;
                if (TEST(1, regval)) /* from "seto al" */
                    info->mcontext->eflags |= EFLAGS_OF;
                LOG(2, "translated eflags from "PFX" to "PFX"\n",
                    orig_flags, info->mcontext->eflags);
            }
            /* Restore whole-bb spilled registers (PR 489221).  Note that
             * now we're closer to being able to restore app state at any
             * point: but we still don't have any local 3rd scratch reg
             * recorded.
             */
            if (save->scratch1 != REG_NULL) {
                regval = get_thread_tls_value(drcontext, SPILL_SLOT_1);
                LOG(2, "restoring per-bb %d to "PFX"\n", save->scratch1, regval);
                reg_set_value(save->scratch1, info->mcontext, regval);
            }
            if (save->scratch2 != REG_NULL) {
                regval = get_thread_tls_value(drcontext, SPILL_SLOT_2);
                LOG(2, "restoring per-bb %d to "PFX"\n", save->scratch2, regval);
                reg_set_value(save->scratch2, info->mcontext, regval);
            }
        }
    }
    hashtable_unlock(&bb_table);
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
        per_thread_t *pt = (per_thread_t *) dr_get_tls_field(drcontext);
        LOG(3, "considering to-be-translated instr: ");
        instr_disassemble(drcontext, &inst, pt->f);
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

    return true;
}

static void
bb_table_free_entry(void *entry)
{
    bb_saved_info_t *save = (bb_saved_info_t *) entry;
    ASSERT(save->ignore_next_delete == 0, "premature deletion");
    global_free(save, sizeof(*save), HEAPSTAT_PERBB);
}

static void
stringop_free_entry(void *entry)
{
    stringop_entry_t *e = (stringop_entry_t *) entry;
    ASSERT(e->loop_instr[0] == LOOP_INSTR_OPCODE, "invalid entry");
    global_free(e, sizeof(*e), HEAPSTAT_PERBB);
}

void
event_fragment_delete(void *drcontext, void *tag)
{
    bb_saved_info_t *save;
    stringop_entry_t *stringop;
#ifdef TOOL_DR_MEMORY
    if (options.leaks_only || !options.shadowing)
        return;
#endif

    hashtable_lock(&bb_table);
    save = (bb_saved_info_t *) hashtable_lookup(&bb_table, tag);
    if (save != NULL) {
        /* PR 495787: handle non-precise flushing where new bbs can be created
         * before the old ones are fully deleted
         */
        LOG(3, "event_fragment_delete "PFX" ignore_next_delete=%d\n",
            tag, save->ignore_next_delete);
        if (save->ignore_next_delete == 0)
            hashtable_remove(&bb_table, tag);
        else /* hashtable lock is held so no race here */
            save->ignore_next_delete--;
    }
    hashtable_unlock(&bb_table);

    dr_mutex_lock(stringop_lock);
    /* We rely on repstr_to_loop arranging the repstr to be the only
     * instr and thus the tag (i#391) (and we require -disable_traces)
     */
    stringop = (stringop_entry_t *) hashtable_lookup(&stringop_app2us_table, tag);
    if (stringop != NULL) {
        if (stringop->ignore_next_delete == 0) {
            IF_DEBUG(bool found;)
            hashtable_remove(&stringop_app2us_table, tag);
            IF_DEBUG(found =)
                hashtable_remove(&stringop_us2app_table, (void *)stringop);
            ASSERT(found, "entry should be in both tables");
        } else
            stringop->ignore_next_delete--;
    }
    dr_mutex_unlock(stringop_lock);

    /* XXX i#260: ideally would also remove xl8_sharing_table entries
     * but would need to decode forward (not always safe) and query
     * every app pc, or store bb size and then walk entire
     * xl8_sharing_table or switch it to an rbtree, or also store a
     * pointer in the bb hashtable.
     * Without removing, new code that replaces old code at the same address
     * can fail to be optimized b/c it will use the old code's history: so
     * a perf failure, not a correctness failure.
     * -single_arg_slowpath adds a second entry with cache pc for each app
     * pc entry, which is harder to delete but we're not deleting anything
     * now anyway.
     */
    /* FIXME i#260: ditto for ignore_unaddr_table, though there we
     * could have false negatives!
     */
}

/***************************************************************************
 * ISA
 */

#if 0 /* currently unused */
static bool
reg_is_caller_saved(reg_id_t reg)
{
    return (reg == REG_EAX || reg == REG_EDX || reg == REG_ECX);
}
#endif

bool
reg_is_gpr(reg_id_t reg)
{
    return (reg >= REG_RAX && reg <= REG_DIL);
}

bool
reg_is_8bit(reg_id_t reg)
{
    return (reg >= REG_START_8 && reg <= REG_STOP_8);
}

bool
reg_is_8bit_high(reg_id_t reg)
{
    return (reg >= REG_AH && reg <= REG_BH);
}

bool
reg_is_16bit(reg_id_t reg)
{
    return (reg >= REG_START_16 && reg <= REG_STOP_16);
}

bool
reg_offs_in_dword(reg_id_t reg)
{
    if (reg_is_8bit_high(reg))
        return 1;
    else
        return 0;
}

reg_id_t
reg_32_to_8h(reg_id_t reg)
{
    ASSERT(reg >= REG_EAX && reg <= REG_EBX,
           "reg_32_to_8h: passed non-32-bit a-d reg");
    return (reg - REG_EAX) + REG_AH;
}

bool
opc_is_push(uint opc)
{
    return (opc == OP_push || opc == OP_push_imm ||
            opc == OP_call || opc == OP_call_ind ||
            opc == OP_call_far || opc == OP_call_far_ind ||
            opc == OP_pushf || opc == OP_pusha || opc == OP_enter);
    /* We ignore kernel stack changes: OP_int, OP_int3, and OP_into */
}

bool
opc_is_pop(uint opc)
{
    return (opc == OP_pop || opc == OP_popf || opc == OP_popa || opc == OP_leave ||
            opc == OP_ret || opc == OP_ret_far || opc == OP_iret
#ifdef WINDOWS
            /* b/c DR hides the post-sysenter ret we treat it as a ret */
            || opc == OP_sysenter
#endif
            );
}

bool
opc_is_stringop_loop(uint opc)
{
    return (opc == OP_rep_ins || opc == OP_rep_outs || opc == OP_rep_movs ||
            opc == OP_rep_stos || opc == OP_rep_lods || opc == OP_rep_cmps ||
            opc == OP_repne_cmps || opc == OP_rep_scas || opc == OP_repne_scas);
}

bool
opc_is_stringop(uint opc)
{
    return (opc_is_stringop_loop(opc) ||
            opc == OP_ins || opc == OP_outs || opc == OP_movs ||
            opc == OP_stos || opc == OP_lods || opc == OP_cmps ||
            opc == OP_cmps || opc == OP_scas || opc == OP_scas);
}

static instr_t *
create_nonloop_stringop(void *drcontext, instr_t *inst)
{
    instr_t *res;
    int nsrc = instr_num_srcs(inst);
    int ndst = instr_num_dsts(inst);
    uint opc = instr_get_opcode(inst);
    int i;
    ASSERT(opc_is_stringop_loop(opc), "invalid param");
    switch (opc) {
    case OP_rep_ins:    opc = OP_ins; break;;
    case OP_rep_outs:   opc = OP_outs; break;;
    case OP_rep_movs:   opc = OP_movs; break;;
    case OP_rep_stos:   opc = OP_stos; break;;
    case OP_rep_lods:   opc = OP_lods; break;;
    case OP_rep_cmps:   opc = OP_cmps; break;;
    case OP_repne_cmps: opc = OP_cmps; break;;
    case OP_rep_scas:   opc = OP_scas; break;;
    case OP_repne_scas: opc = OP_scas; break;;
    default: ASSERT(false, "not a stringop loop opcode"); return NULL;
    }
    res = instr_build(drcontext, opc, ndst - 1, nsrc - 1);
    /* We assume xcx is last src and last dst */
    ASSERT(opnd_is_reg(instr_get_src(inst, nsrc - 1)) &&
           opnd_uses_reg(instr_get_src(inst, nsrc - 1), REG_XCX),
           "rep opnd order assumption violated");
    ASSERT(opnd_is_reg(instr_get_dst(inst, ndst - 1)) &&
           opnd_uses_reg(instr_get_dst(inst, ndst - 1), REG_XCX),
           "rep opnd order assumption violated");
    for (i = 0; i < nsrc - 1; i++)
        instr_set_src(res, i, instr_get_src(inst, i));
    for (i = 0; i < ndst - 1; i++)
        instr_set_dst(res, i, instr_get_dst(inst, i));
    instr_set_translation(res, instr_get_app_pc(inst));
    return res;
}

static bool
opc_is_loop(uint opc)
{
    return (opc == OP_jecxz || opc == OP_loop || opc == OP_loope || opc == OP_loopne);
}

static bool
opc_is_move(uint opc)
{
    return (opc == OP_mov_ld || opc == OP_mov_st || opc == OP_xchg ||
            opc == OP_movzx || opc == OP_movsx ||
            opc == OP_push || opc == OP_pop || opc == OP_pusha || opc == OP_popa ||
            opc == OP_ins || opc == OP_outs || opc == OP_movs ||
            opc == OP_stos || opc == OP_lods ||
            opc == OP_rep_ins || opc == OP_rep_outs || opc == OP_rep_movs ||
            opc == OP_rep_stos || opc == OP_rep_lods);
}

static bool
opc_is_load_seg(uint opc)
{
    return (opc == OP_les || opc == OP_lds || opc == OP_lss ||
            opc == OP_lfs || opc == OP_lgs);
}

/* count is in src #0 */
static bool
opc_is_gpr_shift_src0(uint opc)
{
    return (opc == OP_shl || opc == OP_shr || opc == OP_sar ||
            opc == OP_rol || opc == OP_ror || 
            opc == OP_rcl || opc == OP_rcr);
}

/* count is in src #1 */
static bool
opc_is_gpr_shift_src1(uint opc)
{
    return (opc == OP_shld || opc == OP_shrd);
}

bool
opc_is_gpr_shift(uint opc)
{
    return (opc_is_gpr_shift_src0(opc) || opc_is_gpr_shift_src1(opc));
}

bool
opc_is_jcc(uint opc)
{
    return ((opc >= OP_jo && opc <= OP_jnle) ||
            (opc >= OP_jo_short && opc <= OP_jnle_short));
}

bool
opc_is_cmovcc(uint opc)
{
    return (opc >= OP_cmovo && opc <= OP_cmovnle);
}

bool
opc_is_fcmovcc(uint opc)
{
    return (opc >= OP_fcmovb && opc <= OP_fcmovnu);
}

static bool
opc_loads_into_eip(uint opc)
{
    return (opc == OP_ret || opc == OP_ret_far || opc == OP_iret ||
            opc == OP_call_ind || opc == OP_jmp_ind ||
            opc == OP_call_far_ind || opc == OP_jmp_far_ind
#ifdef WINDOWS
            /* b/c DR hides the post-sysenter ret we treat it as a ret */
            || opc == OP_sysenter
#endif
            );
}

/* can 2nd dst be treated as simply an extension of the 1st */
bool
opc_2nd_dst_is_extension(uint opc)
{
    return (opc == OP_rdtsc || opc == OP_rdmsr || opc == OP_rdpmc ||
            opc == OP_cpuid /*though has 4 dsts*/ ||
            opc == OP_div || opc == OP_idiv ||
            opc == OP_mul || opc == OP_imul);
}

static bool
instr_mem_or_gpr_dsts(instr_t *inst)
{
    int i;
    bool res = false;
    for (i = 0; i < instr_num_dsts(inst); i++) {
        opnd_t opnd = instr_get_dst(inst, i);
        if ((opnd_is_reg(opnd) && reg_is_gpr(opnd_get_reg(opnd))) ||
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
static bool
get_cur_src_value(void *drcontext, instr_t *inst, uint i, reg_t *val)
{
    dr_mcontext_t mc = {sizeof(mc),};
    opnd_t src = instr_get_src(inst, i);
    if (val == NULL)
        return false;
    dr_get_mcontext(drcontext, &mc);
    if (opnd_is_memory_reference(src)) {
        app_pc addr = opnd_compute_address(src, &mc);
        size_t sz = opnd_size_in_bytes(opnd_get_size(src));
        if (sz > sizeof(*val))
            return false;
        return (safe_read(addr, sz, val));
    } else if (opnd_is_reg(src)) {
        *val = reg_get_value(opnd_get_reg(src), &mc);
        return true;
    } else if (opnd_is_immed_int(src)) {
        *val = (reg_t) opnd_get_immed_int(src);
        return true;
    }
    return false;
}
#endif /* TOOL_DR_MEMORY */

uint
adjust_memop_push_offs(instr_t *inst)
{
    /* DR's IR now properly encodes push sizes (DRi#164), except for OP_enter */
    if (instr_get_opcode(inst) == OP_enter) {
        /* OP_enter's esp adjust (1st immed) is handled in
         * instrument_esp_adjust, as it doesn't write those bytes
         */
        uint extra_pushes = opnd_get_immed_int(instr_get_src(inst, 1));
        uint sz = opnd_size_in_bytes(opnd_get_size(instr_get_dst(inst, 1)));
        ASSERT(opnd_is_immed_int(instr_get_src(inst, 1)), "internal error");
        return sz*extra_pushes;
    }
    return 0;
}

opnd_t
adjust_memop(instr_t *inst, opnd_t opnd, bool write, uint *opsz, bool *pushpop_stackop)
{
    /* DR's IR now properly encodes push sizes (DRi#164), except for OP_enter */
    uint opc = instr_get_opcode(inst);
    uint sz = opnd_size_in_bytes(opnd_get_size(opnd));
    bool push = opc_is_push(opc);
    bool pop = opc_is_pop(opc);
    bool pushpop = false; /* is mem ref on stack for push/pop */
    if (opnd_uses_reg(opnd, REG_ESP) || opc == OP_leave/*(ebp) not (esp)*/) {
        if (write && push && opnd_is_base_disp(opnd)) {
            uint extra_push_sz = adjust_memop_push_offs(inst);
            pushpop = true;
            if (extra_push_sz > 0) {
                sz += extra_push_sz;
                opnd_set_disp(&opnd, opnd_get_disp(opnd) - sz);
            }
        } else if (!write && pop && opnd_is_base_disp(opnd)) {
            pushpop = true;
            if (opc == OP_leave) {
                /* OP_leave's ebp->esp is handled in instrument_esp_adjust; here we
                 * treat it as simply a pop into ebp, though using the esp value
                 * copied from ebp, which we emulate here since we're doing it
                 * before the adjust instead of after: FIXME we'll report
                 * errors in both in the wrong order.
                 */
                ASSERT(opnd_get_base(opnd) == REG_EBP, "OP_leave opnd wrong");
            }
            /* OP_ret w/ immed is treated as single pop here; its esp
             * adjustment is handled separately, as it doesn't read those bytes.
             */
        }
    }
    /* we assume only +w ref for push (-w for pop) is the stack adjust */
    ASSERT(pushpop || (!(write && push) && !(!write && pop)),
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
    return ((opc == OP_leave && opnum == 0) /* ebp */ ||
            /* count of loop is important: check it */
            (opc_is_stringop_loop(opc) && opnd_is_reg(instr_get_src(inst, opnum)) &&
             reg_overlap(opnd_get_reg(instr_get_src(inst, opnum)), REG_ECX)) ||
            /* the comparison operands only: the others are moves */
            (opc == OP_cmpxchg && opnum > 0/*dst, eax*/) ||
            (opc == OP_cmpxchg8b && opnum <= 2/*memop, eax, edx*/) ||
            /* always check %cl.  FIXME PR 408549: Valgrind propagates it (if undefined,
             * dest is always undefined), but for us to propagate we need
             * special checks to avoid calling adjust_source_shadow()
             */
            ((opc_is_gpr_shift_src0(opc) && opnum == 0) ||
             (opc_is_gpr_shift_src1(opc) && opnum == 1)));
}

/* For some instructions we check all source operands for definedness. */
bool
instr_check_definedness(instr_t *inst)
{
    uint opc = instr_get_opcode(inst);
    return 
        /* always check conditional jumps */
        instr_is_cbr(inst) ||
        (options.check_non_moves && !opc_is_move(opc)) ||
        (options.check_cmps &&
         /* a compare writes eflags but nothing else, or is a loop, cmps, or cmovcc.
          * for cmpxchg* only some operands are compared: see always_check_definedness.
          */
         ((instr_num_dsts(inst) == 0 &&
           TESTANY(EFLAGS_WRITE_6, instr_get_eflags(inst))) ||
          opc_is_loop(opc) || opc_is_cmovcc(opc) || opc_is_fcmovcc(opc) ||
          opc == OP_cmps || opc == OP_rep_cmps || opc == OP_repne_cmps)) ||
        /* if eip is a destination we have to check the corresponding
         * source.  for ret or call, the other dsts/srcs are just esp, which
         * has to be checked as an addressing register anyway. */
        opc_loads_into_eip(opc) ||
        opc_is_load_seg(opc) || /* we could not check the offs part */
        /* We consider arith flags as enough to transfer definedness to.
         * Note that we don't shadow the floating-point status word, so
         * most float ops should hit this. */
        (!instr_mem_or_gpr_dsts(inst) &&
         !TESTANY(EFLAGS_WRITE_6, instr_get_eflags(inst)) &&
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
result_is_always_defined(instr_t *inst)
{
    /* Even if source operands are undefined, don't consider this instr as
     * reading undefined values if:
     * 1) clearing/setting all bits via:
     *   - and with 0
     *   - or with ~0
     *   - xor with self
     *   - sbb with self (PR 425498): now handled via num_true_srcs since must
     *     propagate eflags (PR 425622)
     */
    int opc = instr_get_opcode(inst);
    /* Though our general non-const per-byte 0/1 checking would cover this,
     * we optimize by looking for entire-dword consts up front
     */
    if ((opc == OP_and &&
         opnd_is_immed_int(instr_get_src(inst, 0)) &&
         opnd_get_immed_int(instr_get_src(inst, 0)) == 0) ||
        (opc == OP_test &&
         opnd_is_immed_int(instr_get_src(inst, 1)) &&
         opnd_get_immed_int(instr_get_src(inst, 1)) == 0) ||
        (opc == OP_or &&
         opnd_is_immed_int(instr_get_src(inst, 0)) &&
         opnd_get_immed_int(instr_get_src(inst, 0)) == ~0) ||
        (opc == OP_xor &&
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
static bool
check_undefined_reg_exceptions(void *drcontext, app_loc_t *loc, reg_id_t reg,
                               dr_mcontext_t *mc, instr_t *inst)
{
    bool res = false;
    byte *pc;
    char buf[16]; /* for safe_read */
    if (loc->type != APP_LOC_PC)
        return false; /* syscall */
    ASSERT(inst != NULL, "must pass in inst if non-syscall");
    pc = loc_to_pc(loc);
    ASSERT(instr_valid(inst), "unknown suspect instr");

#ifdef LINUX
    /* PR 406535: glibc's rawmemchr does some bit tricks that can end up using
     * undefined or unaddressable values:
     * <rawmemchr+113>:
     *   0x0046b0d1  8b 48 08             mov    0x08(%eax) -> %ecx
     *   0x0046b0d4  bf ff fe fe fe       mov    $0xfefefeff -> %edi
     *   0x0046b0d9  31 d1                xor    %edx %ecx -> %ecx
     *   0x0046b0db  01 cf                add    %ecx %edi -> %edi
     *   0x0046b0dd  73 2c                jnb    $0x0046b10b
     * we have two different checks: one for !options.check_non_moves where
     * the error isn't raised until the jnb and one for error on xor.
     * FIXME: share code w/ is_rawmemchr_pattern() in alloc_drmem.c
     */
    if (options.check_non_moves) {
        static const byte RAWMEMCHR_PATTERN_NONMOVES[5] = {0xbf, 0xff, 0xfe, 0xfe, 0xfe};
        ASSERT(sizeof(RAWMEMCHR_PATTERN_NONMOVES) <= BUFFER_SIZE_BYTES(buf),
               "buf too small");
        if (reg == REG_ECX &&
            instr_get_opcode(inst) == OP_xor &&
            safe_read(pc - sizeof(RAWMEMCHR_PATTERN_NONMOVES),
                      sizeof(RAWMEMCHR_PATTERN_NONMOVES), buf) &&
            memcmp(buf, RAWMEMCHR_PATTERN_NONMOVES,
                   sizeof(RAWMEMCHR_PATTERN_NONMOVES)) == 0) {
            LOG(3, "suppressing positive from glibc rawmemchr pattern\n");
            register_shadow_set_dword(REG_ECX, SHADOW_DWORD_DEFINED);
            STATS_INC(rawmemchr_exception);
            res = true;
        } 
    } else {
        /* FIXME PR 406535: verify there's no chance of a true positive */
        static const byte RAWMEMCHR_PATTERN[9] =
            {0xbf, 0xff, 0xfe, 0xfe, 0xfe, 0x31, 0xd1, 0x01, 0xcf};
        ASSERT(sizeof(RAWMEMCHR_PATTERN) <= BUFFER_SIZE_BYTES(buf), "buf too small");
        if (reg == REG_EFLAGS &&
            (instr_get_opcode(inst) == OP_jnb ||
             instr_get_opcode(inst) == OP_jnb_short) &&
            safe_read(pc - sizeof(RAWMEMCHR_PATTERN), sizeof(RAWMEMCHR_PATTERN), buf) &&
            memcmp(buf, RAWMEMCHR_PATTERN, sizeof(RAWMEMCHR_PATTERN)) == 0) {
            uint val = get_shadow_register(REG_ECX);
            /* We want to only allow the end of the search to be suppressed,
             * to avoid suppressing a real positive.  We assume going in
             * forward direction (there is no rawmemrchr).
             * Not easy to compute whether done w/ search: for now just
             * going to require bottom byte to be defined to at least
             * not suppress the entire byte being undefined.
             * FIXME: do better: similarly w/ the strlen exceptions.
             */
            if ((val & 0x3) == 0) {
                LOG(3, "suppressing positive from glibc rawmemchr pattern\n");
                set_shadow_eflags(SHADOW_DWORD_DEFINED);
                STATS_INC(rawmemchr_exception);
                res = true;
            } else
                LOG(3, "NOT suppressing glibc rawmemchr w/ val 0x%x\n", val);
        }
    }
    /* glibc's strrchr:
     *   +0    L3  8b 56 08             mov    0x08(%esi) -> %edx
     *   +3    L3  bf ff fe fe fe       mov    $0xfefefeff -> %edi
     *   +8    L3  01 d7                add    %edx %edi -> %edi
     *   +10   L3  73 66                jnb    $0x00466986
     * glibc's strlen has several of these, for offsets 0, 4, 8, and 0xc:
     *   +0    L3  8b 48 0c             mov    0x0c(%eax) -> %ecx
     *   +3    L3  ba ff fe fe fe       mov    $0xfefefeff -> %edx
     *   +8    L3  01 ca                add    %ecx %edx -> %edx
     *   +10   L3  73 0b                jnb    $0x0046640e
     */
    /* FIXME PR 406535: verify there's no chance of a true positive */
    /* we skip the modrm of the add since it varies */
    static const uint skip = 1;
    /* we stop prior to the mov-imm opcode since it varies */
    static const byte STR_ROUTINE_PATTERN[5] =
        {0xff, 0xfe, 0xfe, 0xfe, 0x01};
    ASSERT(sizeof(STR_ROUTINE_PATTERN) <= BUFFER_SIZE_BYTES(buf), "buf too small");
    if (reg == REG_EFLAGS &&
        (instr_get_opcode(inst) == OP_jnb ||
         instr_get_opcode(inst) == OP_jnb_short) &&
        safe_read(pc - skip - sizeof(STR_ROUTINE_PATTERN),
                  sizeof(STR_ROUTINE_PATTERN), buf) &&
        memcmp(buf, STR_ROUTINE_PATTERN, sizeof(STR_ROUTINE_PATTERN)) == 0) {
        uint val;
        /* See above notes on only end of search.  For these patterns,
         * the load is into the 1st source of the add.
         */
        instr_t add;
        instr_init(drcontext, &add);
        if (safe_decode(drcontext, pc - 2, &add, NULL) &&
            instr_valid(&add) && opnd_is_reg(instr_get_src(&add, 0))) {
            val = get_shadow_register(opnd_get_reg(instr_get_src(&add, 0)));
            if ((val & 0x3) == 0) {
                LOG(3, "suppressing positive from glibc strrchr/strlen pattern\n");
                set_shadow_eflags(SHADOW_DWORD_DEFINED);
                STATS_INC(strrchr_exception);
                res = true;
            } else
                LOG(3, "NOT suppressing glibc strrchr/strlen w/ val 0x%x\n", val);
        } else {
            ASSERT(false, "strrchr/strlen pattern: invalid/unexpected instr");
        }
        instr_free(drcontext, &add);
    }
    /* strrchr again, w/ some variations on what registers are xor'd:
     *   +0    L3  31 d7                xor    %edx %edi -> %edi
     *   +2    L3  81 cf ff fe fe fe    or     $0xfefefeff %edi -> %edi
     *   +8    L3  47                   inc    %edi -> %edi
     *   +9    L3  0f 85 cb 00 00 00    jnz    $0x0046698c
     * variation:
     *   +0    L3  31 ca                xor    %ecx %edx -> %edx
     *   +2    L3  81 ca ff fe fe fe    or     $0xfefefeff %edx -> %edx
     *   +8    L3  42                   inc    %edx -> %edx
     *   +9    L3  75 4e                jnz    $0x00466417
     */
    /* FIXME PR 406535: verify there's no chance of a true positive */
    static const byte STRRCHR_PATTERN_1[7] =
        {0x81, 0xcf, 0xff, 0xfe, 0xfe, 0xfe, 0x47};
    static const byte STRRCHR_PATTERN_2[7] =
        {0x81, 0xca, 0xff, 0xfe, 0xfe, 0xfe, 0x42};
    ASSERT(sizeof(STRRCHR_PATTERN_1) == sizeof(STRRCHR_PATTERN_2), "size changed");
    ASSERT(sizeof(STRRCHR_PATTERN_1) <= BUFFER_SIZE_BYTES(buf), "buf too small");
    if (reg == REG_EFLAGS &&
        /* I've seen OP_je_short as well (in esxi glibc) => allowing any jcc */
        instr_is_cbr(inst) &&
        safe_read(pc - sizeof(STRRCHR_PATTERN_1), sizeof(STRRCHR_PATTERN_1), buf) &&
        (memcmp(buf, STRRCHR_PATTERN_1, sizeof(STRRCHR_PATTERN_1)) == 0 ||
         memcmp(buf, STRRCHR_PATTERN_2, sizeof(STRRCHR_PATTERN_2)) == 0)) {
        uint val;
        if (memcmp(buf, STRRCHR_PATTERN_2, sizeof(STRRCHR_PATTERN_2)) == 0)
            val = get_shadow_register(REG_EDX);
        else
            val = get_shadow_register(REG_EDI);
        if ((val & 0x3) == 0) {
            LOG(3, "suppressing positive from glibc strrchr pattern\n");
            set_shadow_eflags(SHADOW_DWORD_DEFINED);
            STATS_INC(strrchr_exception);
            res = true;
        } else
            LOG(3, "NOT suppressing glibc strrchr/strlen w/ val 0x%x\n", val);
    }
#endif

    return res;
}

static bool
check_undefined_exceptions(bool pushpop, bool write, app_loc_t *loc, app_pc addr,
                           uint sz, uint *shadow)
{
    bool match = false;
    /* I used to have an exception for uninits in heap headers, but w/
     * proper operation headers should be unaddr.  Plus, the exception here,
     * which marked as defined, was only in slowpath: in fastpath the uninit
     * bits are propagated and won't be recognized as heap headers when
     * they bubble up.  Thus it was removed since no longer necessary.
     */
    /* We now check for result_is_always_defined() up front in the
     * slow path to avoid the redundant decode here, which can be a
     * noticeable performance hit (PR 622253)
     */
    return match;
}

static uint
combine_shadows(uint shadow1, uint shadow2)
{
    /* FIXME PR 408551: for now we are not considering propagation to
     * more-significant bytes.
     * This routine only looks at two one-byte values in any case.
     * We ignore BITLEVEL for now.
     * We assume UNADDR will be reported, and we want to propagate
     * defined afterward in any case to avoid chained errors.
     */
    return (shadow1 == SHADOW_UNDEFINED || shadow2 == SHADOW_UNDEFINED) ?
        SHADOW_UNDEFINED : SHADOW_DEFINED;
}

/* pusha/popa need 8 dwords */
#define MAX_DWORDS_TRANSFER 8
#define OPND_SHADOW_ARRAY_LEN (MAX_DWORDS_TRANSFER * sizeof(uint))

/* Adjusts the shadow_vals for a source op.
 * Returns whether eflags should be marked as defined.
 */
static bool
adjust_source_shadow(instr_t *inst, int opnum, uint shadow_vals[OPND_SHADOW_ARRAY_LEN])
{
    int opc = instr_get_opcode(inst);
    bool eflags_defined = true;
    if (opc_is_gpr_shift(opc)) {
        uint val = 0;
        reg_t shift;
        uint opsz = opnd_size_in_bytes(opnd_get_size(instr_get_src(inst, opnum)));
        if (!get_cur_src_value(dr_get_current_drcontext(), inst,
                               opc_is_gpr_shift_src0(opc) ? 0 : 1, &shift)) {
            ASSERT(false, "failed to get shift amount");
            return eflags_defined;
        }
        if (shift > opsz*8)
            shift = opsz*8;
        if (shift == 0)
            return eflags_defined;
        /* pull out of array into single uint, process, and then put back */
        val = set_2bits(val, shadow_vals[0], 0*2);
        val = set_2bits(val, shadow_vals[1], 1*2);
        val = set_2bits(val, shadow_vals[2], 2*2);
        val = set_2bits(val, shadow_vals[3], 3*2);
        if (opc == OP_shl) {
            eflags_defined = (shadow_vals[opsz - ((shift-1)/8 + 1)] == SHADOW_DEFINED);
            /* handle overlap between 2 bytes by or-ing both quantized shifts */
            val = (val << ((((shift-1) / 8)+1)*2)) | (val << ((shift / 8)*2));
        } else if (opc == OP_shr || opc == OP_sar) {
            uint orig_val = val;
            eflags_defined = (shadow_vals[(shift-1)/8] == SHADOW_DEFINED);
            /* handle overlap between 2 bytes by or-ing both quantized shifts */
            val = (val >> ((((shift-1) / 8)+1)*2)) | (val >> ((shift / 8)*2));
            if (opc == OP_sar) {
                /* shift-in bits come from top bit so leave those in place */
                val |= orig_val;
            }
        } else {
            /* FIXME PR 406539: add rotate opcodes + shrd/shld */
        }
        shadow_vals[0] = SHADOW_DWORD2BYTE(val, 0);
        shadow_vals[1] = SHADOW_DWORD2BYTE(val, 1);
        shadow_vals[2] = SHADOW_DWORD2BYTE(val, 2);
        shadow_vals[3] = SHADOW_DWORD2BYTE(val, 3);
    }
    return eflags_defined;
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
    return (opc == OP_and || opc == OP_test || opc == OP_or);
}

#ifdef TOOL_DR_MEMORY
static bool
check_andor_sources(void *drcontext, instr_t *inst,
                    uint shadow_vals[OPND_SHADOW_ARRAY_LEN])
{
    /* The two sources have been laid out side-by-side in shadow_vals.
     * We need to combine, with special rules that suppress undefinedness
     * based on 0 or 1 values.
     */
    int opc = instr_get_opcode(inst);
    reg_t val0, val1;
    uint i, immed_opnum, nonimmed_opnum;
    bool all_defined = true;
    bool have_vals = (get_cur_src_value(drcontext, inst, 0, &val0) &&
                      get_cur_src_value(drcontext, inst, 1, &val1));
    size_t sz;
    if (opnd_is_immed_int(instr_get_src(inst, 0))) {
        immed_opnum = 0;
        nonimmed_opnum = 1;
        sz = opnd_size_in_bytes(opnd_get_size(instr_get_src(inst, 1)));
    } else {
        immed_opnum = 1;
        nonimmed_opnum = 0;
        sz = opnd_size_in_bytes(opnd_get_size(instr_get_src(inst, 0)));
        ASSERT(opnd_is_immed_int(instr_get_src(inst, 1)) ||
               sz == opnd_size_in_bytes(opnd_get_size(instr_get_src(inst, 1))),
               "check_andor_sources assumption error");
    }
    ASSERT(instr_needs_all_srcs_and_vals(inst), "check_andor_sources called incorrectly");

    /* Check for intl\strlen.asm case where it reads 4 bytes for efficiency,
     * but only if aligned.  while it does look at the extra bytes the string
     * should terminate in the valid bytes.  We assume that these constants are
     * enough to avoid false positives and don't check surrounding instrs.
     *    hello!strlen [F:\SP\vctools\crt_bld\SELF_X86\crt\src\intel\strlen.asm]:
     *       00405f91 a900010181       test    eax,0x81010100
     *       00405f96 74e8             jz      hello!strlen+0x30 (00405f80)
     *    cygwin1!strcpy:
     *       610deb96 a980808080       test    eax,0x80808080
     *       610deb9b 74e3             jz      cygwin1!strcpy+0x20 (610deb80)
     *    cygwin1!strchr+0x37:
     *       610ded17 f7c280808080     test    edx,0x80808080
     *    cygwin1!cygwin_internal+0xe7f:
     *       6101a79f 81e280808080     and     edx,0x80808080
     *       6101a7a5 74e9             jz      cygwin1!cygwin_internal+0xe70 (6101a790)
     *       6101a7a7 f7c280800000     test    edx,0x8080
     *       6101a7ad 7506             jnz     cygwin1!cygwin_internal+0xe95 (6101a7b5)
     *    crafty+0x246dd:
     *       00424706 81e100010181     and     ecx,0x81010100
     *       0042470c 751c             jnz     crafty+0x2472a (0042472a)
     *       0042470e 2500010181       and     eax,0x81010100
     *       00424713 74d3             jz      crafty+0x246e8 (004246e8)
     *     (haven't yet needed these ones, haven't analyzed whether might)
     *       00424715 2500010101       and     eax,0x1010100
     *       0042471a 7508             jnz     crafty+0x24724 (00424724)
     *       0042471c 81e600000080     and     esi,0x80000000
     *       00424722 75c4             jnz     crafty+0x246e8 (004246e8)
     *
     * We can't do these checks solely on reported undefined instances b/c of the
     * OP_and (and OP_test if -no_check_cmps) so we must mark defined.
     * Of course this leaves us open to false negatives.
     */
    if (opc != OP_or && sz == 4 &&
        opnd_is_reg(instr_get_src(inst, nonimmed_opnum)) &&
        (opnd_get_reg(instr_get_src(inst, nonimmed_opnum)) == REG_EAX ||
         opnd_get_reg(instr_get_src(inst, nonimmed_opnum)) == REG_ECX ||
         opnd_get_reg(instr_get_src(inst, nonimmed_opnum)) == REG_EDX) &&
        opnd_is_immed_int(instr_get_src(inst, immed_opnum)) &&
        (opnd_get_immed_int(instr_get_src(inst, immed_opnum)) == 0x81010100 ||
         opnd_get_immed_int(instr_get_src(inst, immed_opnum)) == 0x80808080 ||
         opnd_get_immed_int(instr_get_src(inst, immed_opnum)) == 0x00008080)) {
        LOG(3, "strlen/strcpy magic constant @"PFX"\n", instr_get_app_pc(inst));
#ifdef STATISTICS
        if (opnd_get_immed_int(instr_get_src(inst, immed_opnum)) == 0x81010100)
            STATS_INC(strlen_exception);
        else
            STATS_INC(strcpy_exception);
#endif
        for (i = 0; i < sz; i++) {
            shadow_vals[i] = SHADOW_DEFINED;
            shadow_vals[i+sz] = SHADOW_DEFINED;
        }
        return true;
    }

    for (i = 0; i < sz; i++) {
        if (shadow_vals[i] == SHADOW_UNDEFINED) {
            if (have_vals && shadow_vals[i+sz] == SHADOW_DEFINED &&
                ((opc != OP_or && DWORD2BYTE(val1, i) == 0) ||
                 (opc == OP_or && DWORD2BYTE(val1, i) == ~0))) {
                /* The 0/1 byte makes the source undefinedness not matter */
                shadow_vals[i] = SHADOW_DEFINED;
                STATS_INC(andor_exception);
                LOG(3, "0/1 byte %d suppresses undefined and/or source\n", i);
            } else
                all_defined = false;
        } else {
            ASSERT(shadow_vals[i] == SHADOW_DEFINED, "shadow val inconsistency");
            if (shadow_vals[i+sz] == SHADOW_UNDEFINED) {
                if (have_vals &&
                    ((opc != OP_or && DWORD2BYTE(val0, i) == 0) ||
                     (opc == OP_or && DWORD2BYTE(val0, i) == ~0))) {
                    /* The 0/1 byte makes the source undefinedness not matter */
                    STATS_INC(andor_exception);
                    LOG(3, "0/1 byte %d suppresses undefined and/or source\n", i);
                } else {
                    all_defined = false;
                    shadow_vals[i] = SHADOW_UNDEFINED;
                }
            } else
                ASSERT(shadow_vals[i+sz] == SHADOW_DEFINED, "shadow val inconsistency");
        }
        /* Throw out the 2nd source vals now that we've integrated */
        shadow_vals[i+sz] = SHADOW_DEFINED;
    }
    return all_defined;
}

/* Shifts for srcs that can be both mem or reg */
static uint
shadow_val_source_shift(instr_t *inst, int opc, int opnum, uint opsz)
{
    uint shift = 0;
    /* For instrs w/ multiple GPR/mem dests, or concatenated sources,
     * we need to make sure we lay out the dests side by side in the array.
     *
     * Here we check for srcs that do NOT simply go into the lowest slot:
     */
    switch (opc) {
        case OP_xchg:
        case OP_xadd:
            /* we leave potential memop (dst#0) as 0 so no shifting required there */
            shift = 1 - opnum;
            break;
        case OP_cmpxchg8b:
            /* opnds: cmpxchg8b mem8 %eax %edx %ecx %ebx -> mem8 %eax %edx
             * operation: if (edx:eax == mem8) mem8 = ecx:ebx; else edx:eax = mem8
             * we just combine all 3 sources and write the result to both dests.
             */
            switch (opnum) {
                case 0: shift = 0; break;
                case 1: shift = 0; break;
                case 2: shift = 1; break;
                case 3: shift = 1; break;
                case 4: shift = 0; break;
                default: ASSERT(false, "invalid opnum");
            }
            break;
        default: /* no shift: leave as 0 */
            break;
    }
    return (shift * opsz);
}

/* Adds a new source operand's value to the array of shadow_vals to be assigned
 * to the destination.
 */
static void
integrate_register_shadow(instr_t *inst, int opnum,
                          uint shadow_vals[OPND_SHADOW_ARRAY_LEN],
                          reg_id_t reg, uint shadow, bool pushpop)
{
    uint shift = 0;
    /* XXX: shouldn't eflags shadow affect all of the bytes, not just 1st?
     * I.e., pretend eflags is same size as other opnds?
     */
    uint regsz = (reg == REG_EFLAGS) ? 1 : opnd_size_in_bytes(reg_get_size(reg));
    int opc = instr_get_opcode(inst);
    /* PR 426162: ignore stack register source if instr also has memref
     * using same register as addressing register, since memref will do a
     * definedness check for us, and if the reg is undefined we do NOT want
     * to propagate it as it will end up in a regular dest, say pop into a
     * reg, when that dest should only depend on the memref (since on
     * reported error we set addressing register to defined).
     */
    if ((pushpop && reg_overlap(reg, REG_ESP)) ||
        ((opc == OP_leave || opc == OP_enter) && reg_overlap(reg, REG_EBP)))
        return;

    switch (opc) {
        case OP_pusha:
            shift = regsz*(reg_to_pointer_sized(reg) - REG_EAX);
            break;
        default:
            shift = shadow_val_source_shift(inst, opc, opnum, regsz);
            break;
        /* cpuid: who cares if collapse to eax */
    }

    /* Note that we don't need to un-little-endian b/c our array is
     * filled in one byte at a time in order: no words */
    shadow_vals[shift + 0] =
        combine_shadows(shadow_vals[shift + 0],
                        SHADOW_DWORD2BYTE(shadow, reg_offs_in_dword(reg)));
    if (regsz > 1) {
        ASSERT(reg_offs_in_dword(reg) == 0, "invalid reg offs");
        shadow_vals[shift + 1] =
            combine_shadows(shadow_vals[shift + 1], SHADOW_DWORD2BYTE(shadow, 1));
        if (regsz > 2) {
            shadow_vals[shift + 2] =
                combine_shadows(shadow_vals[shift + 2], SHADOW_DWORD2BYTE(shadow, 2));
            shadow_vals[shift + 3] =
                combine_shadows(shadow_vals[shift + 3], SHADOW_DWORD2BYTE(shadow, 3));
        }
    }
}

/* Assigns the array of source shadow_vals to the destination register shadow */
static void
assign_register_shadow(instr_t *inst, int opnum,
                       uint shadow_vals[OPND_SHADOW_ARRAY_LEN],
                       reg_id_t reg, bool pushpop)
{
    uint shift = 0;
    uint regsz = opnd_size_in_bytes(reg_get_size(reg));
    int opc = instr_get_opcode(inst);
    /* Here we need to de-mux from the side-by-side dests in the array
     * into individual register dests.
     * We ignore some dests:
     * - push/pop esp (or enter/leave ebp): we checked esp (ebp) source
     * - string ops ecx/esi/edi: we checked ecx/esi/edi source
     * Some instrs w/ GPR dests we'll naturally mark as defined:
     * - les, lds, lss, lfs, lgs: seg part should be checked up front,
     *                            for simplicity we check the whole thing
     * We also have to shift dsts that do NOT simply go into the lowest slot.
     */
    if (opc_is_stringop(opc)) {
        if (reg_overlap(reg, REG_EDI) || reg_overlap(reg, REG_ESI) ||
            reg_overlap(reg, REG_ECX))
            return;
    } else if ((pushpop && reg_overlap(reg, REG_ESP)) ||
               ((opc == OP_leave || opc == OP_enter) && reg_overlap(reg, REG_EBP))) {
        return;
    } else {
        switch (opc) {
            case OP_popa:
                shift = (reg_to_pointer_sized(reg) - REG_EAX);
                break;
            case OP_xchg:
            case OP_xadd:
                shift = opnum;
                break;
            case OP_cmpxchg8b:
                /* opnds: cmpxchg8b mem8 %eax %edx %ecx %ebx -> mem8 %eax %edx
                 * operation: if (edx:eax == mem8) mem8 = ecx:ebx; else edx:eax = mem8
                 * we just combine all 3 sources and write the result to both dests.
                 */
                switch (opnum) {
                    case 0: shift = 0; break;
                    case 1: shift = 0; break;
                    case 2: shift = 1; break;
                    default: ASSERT(false, "invalid opnum");
                }
                break;
            case OP_bswap:
                ASSERT(regsz == 4, "invalid bswap opsz");
                register_shadow_set_byte(reg, 0, shadow_vals[3]);
                register_shadow_set_byte(reg, 1, shadow_vals[2]);
                register_shadow_set_byte(reg, 2, shadow_vals[1]);
                register_shadow_set_byte(reg, 3, shadow_vals[0]);
                return;
            /* cpuid: who cares if collapse to eax */
            /* rdtsc, rdmsr, rdpmc: no srcs, so can use bottom slot == defined */
            /* mul, imul, div, idiv: FIXME PR 408551: should split: for now we collapse */
        }
    }

    shift *= regsz;
    register_shadow_set_byte(reg, reg_offs_in_dword(reg), shadow_vals[shift + 0]);
    if (regsz > 1) {
        ASSERT(reg_offs_in_dword(reg) == 0, "invalid reg offs");
        register_shadow_set_byte(reg, 1, shadow_vals[shift + 1]);
        if (regsz > 2) {
            register_shadow_set_byte(reg, 2, shadow_vals[shift + 2]);
            register_shadow_set_byte(reg, 3, shadow_vals[shift + 3]);
        }
    }
}

static void
register_shadow_mark_defined(reg_id_t reg)
{
    uint regsz = opnd_size_in_bytes(reg_get_size(reg));
    register_shadow_set_byte(reg, 0, SHADOW_DEFINED);
    if (regsz > 1) {
        register_shadow_set_byte(reg, 1, SHADOW_DEFINED);
        if (regsz > 2) {
            register_shadow_set_byte(reg, 2, SHADOW_DEFINED);
            register_shadow_set_byte(reg, 3, SHADOW_DEFINED);
        }
    }
}
#endif /* TOOL_DR_MEMORY */

/* PR 530902: cmovcc should ignore src+dst unless eflags matches.  For both
 * cmovcc and fcmovcc we treat an unmatched case as though the source and
 * dest do not exist: certainly source should not propagate to dest, whether
 * we should check for addressability of source is debatable: not doing it
 * for now.  We do have to check whether eflags is defined though.
 *
 * FIXME: what about cmpxchg* where the register (or ecx:ebx for 8b)
 * is not read if the cmp fails?  For now we go ahead and propagate
 * but perhaps we shouldn't be: we'll wait for a false positive to
 * take any action though, seems pretty unlikely, unlike cmovcc.
 */
int
num_true_srcs(instr_t *inst, dr_mcontext_t *mc)
{
    int opc = instr_get_opcode(inst);
    if (opc_is_cmovcc(opc) || opc_is_fcmovcc(opc)) {
        /* PR 530902: cmovcc should ignore src+dst unless eflags matches */
        if (!instr_cmovcc_triggered(inst, mc->xflags))
            return 0;
    }
    /* sbb with self should consider all srcs except eflags defined (thus can't
     * be in result_is_always_defined) (PR 425498, PR 425622)
     */
    if (opc == OP_sbb && opnd_same(instr_get_src(inst, 0), instr_get_src(inst, 1)))
        return 0;
    return instr_num_srcs(inst);
}

int
num_true_dsts(instr_t *inst, dr_mcontext_t *mc)
{
    int opc = instr_get_opcode(inst);
    if (opc_is_cmovcc(opc) || opc_is_fcmovcc(opc)) {
        /* PR 530902: cmovcc should ignore src+dst unless eflags matches */
        if (!instr_cmovcc_triggered(inst, mc->xflags))
            return 0;
    }
    return instr_num_dsts(inst);
}

#ifdef TOOL_DR_MEMORY
/* It turns out that it's not the clean call that's the bottleneck: it's
 * the decode and all the IR processing in the slow path proper.  So for a
 * common slowpath case, 4-byte OP_movs, we have an easy-to-write
 * "medium-speed-path".  Because it's mem2mem, we do not have fastpath
 * support for it yet when check_definedness fails, and maybe we never will
 * need it since this medium-path works fairly well.
 */
void
medium_path_movs4(app_loc_t *loc, dr_mcontext_t *mc)
{
    /* since esi and edi are used as base regs, we are checking
     * definedness, so we ignore the reg operands
     */
    uint shadow_vals[4];
    int i;
    LOG(3, "medium_path movs4 "PFX" src="PFX" %d%d%d%d dst="PFX" %d%d%d%d\n",
        loc_to_pc(loc), mc->esi,
        shadow_get_byte((app_pc)mc->esi), shadow_get_byte((app_pc)mc->esi+1),
        shadow_get_byte((app_pc)mc->esi+2), shadow_get_byte((app_pc)mc->esi+3),
        mc->edi, shadow_get_byte((app_pc)mc->edi), shadow_get_byte((app_pc)mc->edi+1),
        shadow_get_byte((app_pc)mc->edi+2), shadow_get_byte((app_pc)mc->edi+3));
#ifdef STATISTICS
    if (!ALIGNED(mc->esi, 4))
        STATS_INC(movs4_src_unaligned);
    if (!ALIGNED(mc->edi, 4))
        STATS_INC(movs4_dst_unaligned);
    if (shadow_get_byte((app_pc)mc->esi) != SHADOW_DEFINED ||
        shadow_get_byte((app_pc)mc->esi+1) != SHADOW_DEFINED ||
        shadow_get_byte((app_pc)mc->esi+2) != SHADOW_DEFINED ||
        shadow_get_byte((app_pc)mc->esi+3) != SHADOW_DEFINED)
        STATS_INC(movs4_src_undef);
#endif
    STATS_INC(medpath_executions);

    if (!options.check_uninitialized) {
        if ((!options.check_alignment ||
             (ALIGNED(mc->esi, 4) && ALIGNED(mc->edi, 4))) &&
            shadow_get_byte((app_pc)mc->esi) != SHADOW_UNADDRESSABLE &&
            shadow_get_byte((app_pc)mc->edi) != SHADOW_UNADDRESSABLE) {
            STATS_INC(movs4_med_fast);
            return;
        }
        check_mem_opnd(OP_movs, MEMREF_CHECK_ADDRESSABLE, loc, 
                       opnd_create_far_base_disp(SEG_DS, REG_ESI, REG_NULL, 0, 0, OPSZ_4),
                       4, mc, shadow_vals);
        check_mem_opnd(OP_movs, MEMREF_CHECK_ADDRESSABLE, loc,
                       opnd_create_far_base_disp(SEG_ES, REG_EDI, REG_NULL, 0, 0, OPSZ_4),
                       4, mc, shadow_vals);
        return;
    }

    /* The generalized routines below are just a little too slow.  The
     * common case is an unaligned movs4 whose source is fully
     * defined, or aligned or unaligned but with source undefined, and
     * with eflags defined, so we have a fastpath here.  This has been
     * good enough so no need for a real fastpath in gencode.
     * i#i#237.
     */
    /* XXX: assuming SEG_DS and SEG_ES are flat+full */
    if (is_shadow_register_defined(get_shadow_register(REG_ESI)) &&
        is_shadow_register_defined(get_shadow_register(REG_EDI)) &&
        get_shadow_eflags() == SHADOW_DEFINED) {
        uint src0 = shadow_get_byte((app_pc)mc->esi+0);
        uint src1 = shadow_get_byte((app_pc)mc->esi+1);
        uint src2 = shadow_get_byte((app_pc)mc->esi+2);
        uint src3 = shadow_get_byte((app_pc)mc->esi+3);
        if ((src0 == SHADOW_DEFINED || src0 == SHADOW_UNDEFINED) &&
            (src1 == SHADOW_DEFINED || src1 == SHADOW_UNDEFINED) &&
            (src2 == SHADOW_DEFINED || src2 == SHADOW_UNDEFINED) &&
            (src3 == SHADOW_DEFINED || src3 == SHADOW_UNDEFINED) &&
            shadow_get_byte((app_pc)mc->edi+0) != SHADOW_UNADDRESSABLE &&
            shadow_get_byte((app_pc)mc->edi+1) != SHADOW_UNADDRESSABLE &&
            shadow_get_byte((app_pc)mc->edi+2) != SHADOW_UNADDRESSABLE &&
            shadow_get_byte((app_pc)mc->edi+3) != SHADOW_UNADDRESSABLE) {
            shadow_set_byte((app_pc)mc->edi+0, src0);
            shadow_set_byte((app_pc)mc->edi+1, src1);
            shadow_set_byte((app_pc)mc->edi+2, src2);
            shadow_set_byte((app_pc)mc->edi+3, src3);
            STATS_INC(movs4_med_fast);
            return;
        }
    }

    check_mem_opnd(OP_movs, MEMREF_USE_VALUES, loc, 
                   opnd_create_far_base_disp(SEG_DS, REG_ESI, REG_NULL, 0, 0, OPSZ_4),
                   4, mc, shadow_vals);
    for (i = 0; i < 4; i++)
        shadow_vals[i] = combine_shadows(shadow_vals[i], get_shadow_eflags());
    check_mem_opnd(OP_movs, MEMREF_WRITE | MEMREF_USE_VALUES, loc,
                   opnd_create_far_base_disp(SEG_ES, REG_EDI, REG_NULL, 0, 0, OPSZ_4),
                   4, mc, shadow_vals);
}

static bool
opnd_uses_nonignorable_memory(opnd_t opnd)
{
    /* XXX: we could track ebp and try to determine when not used as frame ptr */
    return (opnd_is_memory_reference(opnd) &&
            (options.check_stack_access ||
             !opnd_is_base_disp(opnd) ||
             (reg_to_pointer_sized(opnd_get_base(opnd)) != REG_XSP &&
              reg_to_pointer_sized(opnd_get_base(opnd)) != REG_XBP) ||
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
    num_srcs = (IF_WINDOWS_ELSE(opc == OP_sysenter, false)) ? 1 :
        ((opc == OP_lea) ? 0 : num_true_srcs(inst, mc));
    for (i = 0; i < num_srcs; i++) {
        if (opc == OP_sysenter) {
#ifdef WINDOWS
            /* special case: we pretend the sysenter instr itself does the
             * ret that is hidden by DR.
             */
            opnd = OPND_CREATE_MEM32(REG_ESP, 0);
#else
            ASSERT(false, "sysenter has no sources");
#endif
        } else
            opnd = instr_get_src(inst, i);
        if (opnd_uses_nonignorable_memory(opnd)) {
            opnd = adjust_memop(inst, opnd, false, &sz, &pushpop_stackop);
            if (pushpop_stackop && options.check_stack_bounds)
                flags = MEMREF_PUSHPOP;
            else
                flags = MEMREF_CHECK_ADDRESSABLE;
            memop = opnd;
            check_mem_opnd(opc, flags, loc, opnd, sz, mc, NULL);
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
            check_mem_opnd(opc, flags, loc, opnd, sz, mc, NULL);
        }
    }

    instr_free(drcontext, inst);

    /* call this last after freeing inst in case it does a synchronous flush */
    slow_path_xl8_sharing(loc, instr_sz, memop, mc);

    return true;
}
#endif /* TOOL_DR_MEMORY */

/* Does everything in C code, except for handling non-push/pop writes to esp 
 */
bool
slow_path(app_pc pc, app_pc decode_pc)
{
    void *drcontext = dr_get_current_drcontext();
#ifdef DEBUG
    per_thread_t *pt = (per_thread_t *) dr_get_tls_field(drcontext);
#endif
    dr_mcontext_t mc = {sizeof(mc),};
    instr_t inst;
    int opc;
#ifdef TOOL_DR_MEMORY
    opnd_t opnd;
    int i, num_srcs, num_dsts;
    uint sz;
    /* Array of shadow vals from sources to dests: each uint entry in the
     * array is a shadow for one byte being transferred from source(s) to dest.
     * Larger mem refs either have no transfer (e.g., fxsave), or if
     * they do (rep movs) we handle them specially.
     */
    uint shadow_vals[OPND_SHADOW_ARRAY_LEN];
    bool check_definedness, pushpop, pushpop_stackop, src_undef = false;
    bool check_srcs_after;
    bool always_defined;
    opnd_t memop = opnd_create_null();
#endif
    size_t instr_sz;
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

    dr_get_mcontext(drcontext, &mc);
    /* Locally-spilled and whole-bb-spilled (PR 489221) registers have
     * already been restored in shared_slowpath, so we can properly
     * emulate addresses referenced.  We can't restore whole-bb-spilled
     * here b/c we don't have the bb tag.  Eflags may not be restored
     * but we don't rely on them here.
     */

    /* for jmp-to-slowpath optimization where we xl8 to get app pc (PR 494769)
     * we always pass NULL for decode_pc
     */
    if (decode_pc == NULL) {
        /* not using safe_read since in cache */
        byte *ret_pc = (byte *) get_own_tls_value(SPILL_SLOT_2);
        ASSERT(pc == NULL, "invalid params");
        ASSERT(options.single_arg_slowpath, "only used for single_arg_slowpath");
        /* If the ret pc is a jmp, we know to walk forward, bypassing
         * spills, to find the app instr (we assume app jmp never
         * needs slowpath).  If using a cloned app instr, then ret pc
         * points directly there.  Since we want to skip the clone and
         * the jmp, we always skip the instr at ret pc when returning.
         */
        pc = decode_next_pc(drcontext, ret_pc);
        ASSERT(pc != NULL, "invalid stored app instr");
        set_own_tls_value(SPILL_SLOT_2, (reg_t) pc);
        if (*ret_pc == 0xe9) {
            /* walk forward to find the app pc */
            instr_init(drcontext, &inst);
            do {
                instr_reset(drcontext, &inst);
                decode_pc = pc;
                pc = decode(drcontext, decode_pc, &inst);
                ASSERT(pc != NULL, "invalid app instr copy");
            } while (instr_is_spill(&inst) || instr_is_restore(&inst));
            instr_reset(drcontext, &inst);
        } else
            decode_pc = ret_pc;
        /* if we want the app addr later, we'll have to translate to get it */
        loc.u.addr.valid = false;
        loc.u.addr.pc = decode_pc;
        pc = NULL;
    } else
        ASSERT(!options.single_arg_slowpath, "single_arg_slowpath error");
    
#ifdef TOOL_DR_MEMORY
    if (decode_pc != NULL &&
        (*decode_pc == MOVS_4_OPCODE ||
         /* we now pass original pc from -repstr_to_loop including rep.
          * ignore other prefixes here: data16 most likely and then not movs4.
          */
         (options.repstr_to_loop && *decode_pc == REP_PREFIX &&
          *(decode_pc + 1) == MOVS_4_OPCODE))) {
        /* see comments for this routine: common enough it's worth optimizing */
        medium_path_movs4(&loc, &mc);
        /* no sharing with string instrs so no need to call
         * slow_path_xl8_sharing
         */
        return true;
    }
#endif /* TOOL_DR_MEMORY */

    instr_init(drcontext, &inst);
    instr_sz = decode(drcontext, decode_pc, &inst) - decode_pc;
    ASSERT(instr_valid(&inst), "invalid instr");
    opc = instr_get_opcode(&inst);

    if (options.repstr_to_loop && opc == OP_loop) {
        /* to point at an OP_loop but use app's repstr pc we use this table (i#391) */
        byte *rep_pc;
        dr_mutex_lock(stringop_lock);
        rep_pc = (byte *) hashtable_lookup(&stringop_us2app_table, decode_pc);
        dr_mutex_unlock(stringop_lock);
        if (rep_pc != NULL) {
            ASSERT(dr_memory_is_dr_internal(decode_pc), "must be drmem heap");
            /* use this as app pc if we report an error */
            pc_to_loc(&loc, rep_pc);
        }
    }            

#ifdef STATISTICS
    STATS_INC(slowpath_count[opc]);
    {
        opnd_size_t sz;
        if (instr_num_dsts(&inst) > 0 &&
            !opnd_is_pc(instr_get_dst(&inst, 0)) &&
            !opnd_is_instr(instr_get_dst(&inst, 0)))
            sz = opnd_get_size(instr_get_dst(&inst, 0));
        else if (instr_num_srcs(&inst) > 0 &&
                 !opnd_is_pc(instr_get_src(&inst, 0)) &&
                 !opnd_is_instr(instr_get_src(&inst, 0)))
            sz = opnd_get_size(instr_get_src(&inst, 0));
        else
            sz = OPSZ_0;
        if (sz == OPSZ_1)
            STATS_INC(slowpath_sz1);
        else if (sz == OPSZ_2)
            STATS_INC(slowpath_sz2);
        else if (sz == OPSZ_4)
            STATS_INC(slowpath_sz4);
        else if (sz == OPSZ_8)
            STATS_INC(slowpath_sz8);
        else
            STATS_INC(slowpath_szOther);
    }
#endif

    DOLOG(3, { 
        LOG(3, "\nslow_path "PFX": ", pc);
        instr_disassemble(drcontext, &inst, pt->f);
        if (instr_num_dsts(&inst) > 0 &&
            opnd_is_memory_reference(instr_get_dst(&inst, 0))) {
            LOG(3, " | 0x%x",
                shadow_get_byte(opnd_compute_address(instr_get_dst(&inst, 0), &mc)));
        }
        LOG(3, "\n");
    });

#ifdef TOOL_DR_HEAPSTAT
    return slow_path_for_staleness(drcontext, &mc, &inst, &loc);

#else
    if (!options.check_uninitialized)
        return slow_path_without_uninitialized(drcontext, &mc, &inst, &loc, instr_sz);

    LOG(4, "shadow registers prior to instr:\n");
    DOLOG(4, { print_shadow_registers(); });

    /* We need to do the following:
     * - check addressability of all memory operands
     * - check definedness of all source operands if:
     *   o no GPR or memory dest (=> no way to store definedness)
     *   o if options.check_non_moves is on and this is not just a move
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
     * side in our 8-dword-capacity shadow_vals array.
     */
    check_definedness = instr_check_definedness(&inst);
    always_defined = result_is_always_defined(&inst);
    pushpop = opc_is_push(opc) || opc_is_pop(opc);
    check_srcs_after = instr_needs_all_srcs_and_vals(&inst);
    if (check_srcs_after) {
        /* We need to check definedness of addressing registers, and so we do
         * our normal src loop but we do not check undefinedness or combine
         * sources.  Below we pass pointers to later in shadow_vals to
         * check_mem_opnd() and integrate_register_shadow(), causing the 2
         * sources to be laid out side-by-side in shadow_vals.
         */
        ASSERT(instr_num_srcs(&inst) == 2, "and/or special handling error");
        check_definedness = false;
    }

    /* Initialize to defined so we can aggregate operands as we go.
     * This works with no-source instrs (rdtsc, etc.)
     * This also makes small->large work out w/o any special processing
     * (movsz, movzx, cwde, etc.): but FIXME: are there any src/dst size
     * mismatches where we do NOT want to set dst bytes beyond count
     * of src bytes to defined?
     */
    for (i = 0; i < OPND_SHADOW_ARRAY_LEN; i++)
        shadow_vals[i] = SHADOW_DEFINED;

    num_srcs = (IF_WINDOWS_ELSE(opc == OP_sysenter, false)) ? 1 :
        ((opc == OP_lea) ? 2 : num_true_srcs(&inst, &mc));
 check_srcs:
    for (i = 0; i < num_srcs; i++) {
        bool regular_op = false;
        if (opc == OP_sysenter) {
#ifdef WINDOWS
            /* special case: we pretend the sysenter instr itself does the
             * ret that is hidden by DR.
             */
            opnd = OPND_CREATE_MEM32(REG_ESP, 0);
#else
            ASSERT(false, "sysenter has no sources");
#endif
        } else if (opc == OP_lea) {
            /* special case: treat address+base as propagatable sources 
             * code below can handle REG_NULL
             */
            if (i == 0)
                opnd = opnd_create_reg(opnd_get_base(instr_get_src(&inst, 0)));
            else
                opnd = opnd_create_reg(opnd_get_index(instr_get_src(&inst, 0)));
        } else {
            regular_op = true;
            opnd = instr_get_src(&inst, i);
        }
        if (opnd_is_memory_reference(opnd)) {
            int flags = 0;
            uint shift;
            opnd = adjust_memop(&inst, opnd, false, &sz, &pushpop_stackop);
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
            } else {
                /* If we're checking, to avoid further errors we do not
                 * propagate the shadow vals (and thus we essentially
                 * propagate SHADOW_DEFINED).
                 * Conveniently all the large operand sizes always
                 * have check_definedness since they involve fp or sse.
                 */
                ASSERT(sz <= sizeof(shadow_vals), "internal shadow val error");
                flags |= MEMREF_USE_VALUES;
            }
            shift = shadow_val_source_shift(&inst, opc, i, sz);
            memop = opnd;
            check_mem_opnd(opc, flags, &loc, opnd, sz, &mc,
                           /* do not combine srcs if checking after */
                           check_srcs_after ? &shadow_vals[i*sz] : &shadow_vals[shift]);
        } else if (opnd_is_reg(opnd)) {
            reg_id_t reg = opnd_get_reg(opnd);
            if (reg_is_gpr(reg)) {
                uint shadow = get_shadow_register(reg);
                sz = opnd_size_in_bytes(reg_get_size(reg));
                if (always_defined) {
                    /* if result defined regardless, don't propagate (is
                     * equivalent to propagating SHADOW_DEFINED) or check */
                } else if (check_definedness || always_check_definedness(&inst, i)) {
                    check_register_defined(drcontext, reg, &loc, sz, &mc, &inst);
                } else {
                    /* See above: we only propagate when not checking */
                    integrate_register_shadow
                        (&inst, i, 
                         /* do not combine srcs if checking after */
                         check_srcs_after ? &shadow_vals[i*sz] : shadow_vals,
                         reg, shadow, pushpop);
                }
            } /* else always defined */
        } else /* always defined */
            ASSERT(opnd_is_immed_int(opnd) || opnd_is_pc(opnd), "unexpected opnd");
        if (regular_op)
            src_undef = !adjust_source_shadow(&inst, i, shadow_vals);
        LOG(4, "shadow_vals after src %d ", i);
        DOLOG(4, {
            int j;
            opnd_disassemble(drcontext, opnd, pt->f);
            LOG(4, ": ");
            for (j = 0; j < OPND_SHADOW_ARRAY_LEN; j++)
                LOG(4, "%d", shadow_vals[j]);
            LOG(4, "\n");
        });
    }

    /* eflags source */
    if (TESTANY(EFLAGS_READ_6, instr_get_eflags(&inst))) {
        uint shadow = get_shadow_eflags();
        if (always_defined) {
            /* if result defined regardless, don't propagate (is
             * equivalent to propagating SHADOW_DEFINED) or check */
        } else if (check_definedness) {
            check_register_defined(drcontext, REG_EFLAGS, &loc, 1, &mc, &inst);
        } else {
            /* See above: we only propagate when not checking */
            integrate_register_shadow
                (&inst, 0, 
                 /* do not combine srcs if checking after */
                 check_srcs_after ? &shadow_vals[i*sz] : shadow_vals,
                 REG_EFLAGS, shadow, pushpop);
        }
    }

    if (check_srcs_after && !check_definedness/*avoid recursing after goto below*/) {
        /* turn back on for dsts */
        check_definedness = instr_check_definedness(&inst);
        if (!check_andor_sources(drcontext, &inst, shadow_vals) &&
            check_definedness) {
            /* We do not bother to suppress reporting the particular bytes that
             * may have been "defined" due to 0/1 in the other operand since
             * doing so would require duplicating/extracting all the reporting
             * logic above for regs and in handle_mem_ref(): our goto here is
             * slightly less ugly.
             */
            for (i = 0; i < OPND_SHADOW_ARRAY_LEN; i++)
                shadow_vals[i] = SHADOW_DEFINED;
            goto check_srcs;
        }
    }

    for (i = 0; i < OPND_SHADOW_ARRAY_LEN; i++) {
        if (shadow_vals[i] == SHADOW_UNDEFINED) {
            src_undef = true;
            break;
        }
    }

    num_dsts = num_true_dsts(&inst, &mc);
    for (i = 0; i < num_dsts; i++) {
        opnd = instr_get_dst(&inst, i);
        if (opnd_is_memory_reference(opnd)) {
            int flags = MEMREF_WRITE;
            opnd = adjust_memop(&inst, opnd, true, &sz, &pushpop_stackop);
            if (pushpop_stackop)
                flags |= MEMREF_PUSHPOP;
            if (always_defined) {
                /* w/o MEMREF_USE_VALUES, handle_mem_ref() will use SHADOW_DEFINED */
            } else if (check_definedness) {
                flags |= MEMREF_CHECK_DEFINEDNESS;
                /* since checking, we mark as SHADOW_DEFINED (see above) */
            } else {
                ASSERT(sz <= sizeof(shadow_vals), "internal shadow val error");
                flags |= MEMREF_USE_VALUES;
            }
            /* check addressability, and propagate
             * we arranged xchg/xadd to not need shifting; nothing else does either.
             */
            memop = opnd;
            check_mem_opnd(opc, flags, &loc, opnd, sz, &mc, shadow_vals);
        } else if (opnd_is_reg(opnd)) {
            reg_id_t reg = opnd_get_reg(opnd);
            if (reg_is_gpr(reg)) {
                assign_register_shadow(&inst, i, shadow_vals, reg, pushpop);
            }
        } else
            ASSERT(opnd_is_immed_int(opnd) || opnd_is_pc(opnd), "unexpected opnd");
    }
    if (TESTANY(EFLAGS_WRITE_6, instr_get_eflags(&inst))) {
        set_shadow_eflags(src_undef ? SHADOW_DWORD_UNDEFINED : SHADOW_DWORD_DEFINED);
    }

    LOG(4, "shadow registers after instr:\n");
    DOLOG(4, { print_shadow_registers(); });

    instr_free(drcontext, &inst);

    /* call this last after freeing inst in case it does a synchronous flush */
    slow_path_xl8_sharing(&loc, instr_sz, memop, &mc);

    DOLOG(4, {
        if (!options.single_arg_slowpath && pc == decode_pc/*else retpc not in tls3*/) {
            /* Test translation when have both args */
            /* we want the ultimate target, not whole_bb_spills_enabled()'s
             * SPILL_SLOT_5 intermediate target
             */
            byte *ret_pc = (byte *) get_own_tls_value(SPILL_SLOT_2);
            client_per_thread_t *cpt = (client_per_thread_t *) pt->client_data;
            /* ensure event_restore_state() returns true */
            byte *xl8;
            cpt->self_translating = true;
            xl8 = dr_app_pc_from_cache_pc(ret_pc);
            cpt->self_translating = false;
            LOG(3, "translation test: cache="PFX", orig="PFX", xl8="PFX"\n",
                ret_pc, pc, xl8);
            ASSERT(xl8 == pc || 
                   /* for repstr_to_loop we changed pc */
                   (options.repstr_to_loop && opc_is_stringop(opc) &&
                    xl8 == loc_to_pc(&loc)) ||
                   /* for repstr_to_loop OP_loop, ret_pc is the restore
                    * code after stringop and before OP_loop*, so we'll get
                    * post-xl8 pc.
                    */
                   (options.repstr_to_loop && opc == OP_loop &&
                    xl8 == decode_next_pc(drcontext, loc_to_pc(&loc))),
                   "xl8 doesn't match");
        }
    });

    return true;
#endif /* !TOOL_DR_HEAPSTAT */
}

static app_pc
instr_shared_slowpath_decode_pc(instr_t *inst)
{
    if (!options.shared_slowpath)
        return NULL;
    if (instr_get_note(inst) != NULL)
        return (app_pc) instr_get_note(inst);
    if (instr_get_app_pc(inst) == instr_get_raw_bits(inst))
        return instr_get_app_pc(inst);
    return NULL;
}

bool
instr_can_use_shared_slowpath(instr_t *inst)
{
    return (instr_shared_slowpath_decode_pc(inst) != NULL);
}

void
instrument_slowpath(void *drcontext, instrlist_t *bb, instr_t *inst,
                    fastpath_info_t *mi)
{
    app_pc decode_pc = instr_shared_slowpath_decode_pc(inst);
    if (decode_pc != NULL) {
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
            PRE(bb, inst,
                INSTR_CREATE_mov_imm(drcontext,
                                     spill_slot_opnd(drcontext, SPILL_SLOT_1),
                                     OPND_CREATE_INTPTR(decode_pc)));
            /* FIXME: this hardcoded address will be wrong if this
             * fragment is shifted, or copied into a trace is created =>
             * requires -disable_traces (or registering for trace event)
             * and shared caches (since they're not shifted: but what if
             * this particular fragment is thread-private?!?)
             */
            PRE(bb, inst,
                INSTR_CREATE_mov_imm(drcontext,
                                     spill_slot_opnd(drcontext, SPILL_SLOT_2),
                                     opnd_create_instr(appinst)));
            PRE(bb, inst,
                INSTR_CREATE_jmp(drcontext, opnd_create_pc(shared_slowpath_entry)));
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
            r1 = (s1->dead ? (s1->reg - REG_EAX + SPILL_REG_EAX_DEAD) :
                  ((!s1->used || s1->xchg != REG_NULL) ? SPILL_REG_NONE :
                   (s1->reg - REG_EAX + SPILL_REG_EAX)));
            r2 = (s2->dead ? (s2->reg - REG_EAX + SPILL_REG_EAX_DEAD) :
                  ((!s2->used || s2->xchg != REG_NULL) ? SPILL_REG_NONE :
                   (s2->reg - REG_EAX + SPILL_REG_EAX)));
            if (whole_bb_spills_enabled()) {
                /* reg3 just like 1 and 2: can be any reg */
                r3 = (s3->dead ? (s3->reg - REG_EAX + SPILL_REG_EAX_DEAD) :
                      ((!s3->used || s3->xchg != REG_NULL) ? SPILL_REG_NONE :
                       (s3->reg - REG_EAX + SPILL_REG_EAX)));
            } else {
                /* if reg3 is dead we do not need to restore */
                r3 = ((!s3->used || s3->dead || s3->xchg != REG_NULL) ?
                      SPILL_REG3_NOSPILL : SPILL_REG3_SPILL);
                spill_eax = (mi->eax.used && !mi->eax.dead && mi->eax.xchg == REG_NULL);
                ef = ((whole_bb_spills_enabled() ||
                       mi->aflags == EFLAGS_WRITE_6) ? SPILL_EFLAGS_NOSPILL :
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
            if (options.single_arg_slowpath) {
                /* for jmp-to-slowpath optimization: we point at app instr, or a
                 * clone of it, for pc to decode from (PR 494769), as the
                 * retaddr, and thus do not need a second parameter.
                 */
                mi->appclone = instr_clone(drcontext, inst);
                mi->slow_store_retaddr =
                    INSTR_CREATE_mov_imm(drcontext, 
                                         (r2 == SPILL_REG_NONE) ?
                                         spill_slot_opnd(drcontext, SPILL_SLOT_2) :
                                         opnd_create_reg(s2->reg),
                                         opnd_create_instr(mi->appclone));
                PRE(bb, inst, mi->slow_store_retaddr);
                mi->slow_jmp = INSTR_CREATE_jmp(drcontext, opnd_create_pc(tgt));
                PRE(bb, inst, mi->slow_jmp);
                instr_set_ok_to_mangle(mi->appclone, false);
                instr_set_translation(mi->appclone, NULL);
                PRE(bb, inst, mi->appclone);
            } else {
                PRE(bb, inst,
                    INSTR_CREATE_mov_imm(drcontext,
                                         (r1 == SPILL_REG_NONE) ?
                                         spill_slot_opnd(drcontext, SPILL_SLOT_1) :
                                         opnd_create_reg(s1->reg),
                                         OPND_CREATE_INTPTR(decode_pc)));
                PRE(bb, inst,
                    INSTR_CREATE_mov_imm(drcontext, 
                                         (r2 == SPILL_REG_NONE) ?
                                         spill_slot_opnd(drcontext, SPILL_SLOT_2) :
                                         opnd_create_reg(s2->reg),
                                         opnd_create_instr(appinst)));
                PRE(bb, inst, INSTR_CREATE_jmp(drcontext, opnd_create_pc(tgt)));
            }
        }
        PRE(bb, inst, appinst);
    } else {
        if (mi != NULL) {
            /* We assume caller did a restore */
        }
        /* We have to handle DR trampolines so we pass in a separate pc to
         * decode from */
        if (instr_get_app_pc(inst) != instr_get_raw_bits(inst)) {
            LOG(1, "INFO: app "PFX" vs decode "PFX"\n",
                instr_get_app_pc(inst), instr_get_raw_bits(inst));
        }
        dr_insert_clean_call(drcontext, bb, inst,
                             (void *) slow_path, false, 2,
                             OPND_CREATE_INTPTR(instr_get_app_pc(inst)),
                             OPND_CREATE_INTPTR(instr_get_raw_bits(inst)));
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

static void
shared_slowpath_spill(void *drcontext, instrlist_t *ilist, int type, int slot)
{
    if (type >= SPILL_REG_EAX && type <= SPILL_REG_EBX) {
        PRE(ilist, NULL, INSTR_CREATE_xchg
            (drcontext, spill_slot_opnd(drcontext, slot),
             opnd_create_reg(REG_EAX + (type - SPILL_REG_EAX))));
    } else if (type >= SPILL_REG_EAX_DEAD && type <= SPILL_REG_EBX_DEAD) {
        PRE(ilist, NULL, INSTR_CREATE_mov_st
            (drcontext, spill_slot_opnd(drcontext, slot),
             opnd_create_reg(REG_EAX + (type - SPILL_REG_EAX_DEAD))));
    } /* else param was put straight in tls slot */
}

byte *
generate_shared_slowpath(void *drcontext, instrlist_t *ilist, byte *pc)
{
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
                         spill_slot_opnd(drcontext, SPILL_SLOT_1),
                         spill_slot_opnd(drcontext, SPILL_SLOT_1));
    PRE(ilist, NULL,
        INSTR_CREATE_jmp_ind(drcontext, spill_slot_opnd
                             (drcontext, whole_bb_spills_enabled() ?
                              /* for whole-bb spills we need two-step return */
                              SPILL_SLOT_5 : SPILL_SLOT_2)));
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
                    instr_t *return_point = NULL;
                    if (whole_bb_spills_enabled()) {
                        return_point = INSTR_CREATE_label(drcontext);
                    } else if (ef != SPILL_EFLAGS_NOSPILL) {
                        if (ef == SPILL_EFLAGS_6_EAX ||
                            ef == SPILL_EFLAGS_6_NOEAX) {
                            PRE(ilist, NULL, INSTR_CREATE_add
                                (drcontext, opnd_create_reg(REG_AL),
                                 OPND_CREATE_INT8(0x7f)));
                        }
                        PRE(ilist, NULL, INSTR_CREATE_sahf(drcontext));
                        if (ef == SPILL_EFLAGS_6_EAX ||
                            ef == SPILL_EFLAGS_5_EAX) {
                            restore_reg(drcontext, ilist, NULL, REG_EAX,
                                        SPILL_SLOT_EFLAGS_EAX);
                        }
                    }
                    if (whole_bb_spills_enabled()) {
                        shared_slowpath_spill(drcontext, ilist, r3, SPILL_SLOT_4);
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
                    shared_slowpath_spill(drcontext, ilist, r2, SPILL_SLOT_2);
                    if (options.single_arg_slowpath) {
                        /* for jmp-to-slowpath optimization we don't have 2nd
                         * param, so pass 0 (PR 494769)
                         */
                        if (r1 >= SPILL_REG_EAX && r1 <= SPILL_REG_EBX) {
                            PRE(ilist, NULL, INSTR_CREATE_mov_imm
                                (drcontext,
                                 opnd_create_reg(REG_EAX + (r1 - SPILL_REG_EAX)),
                                 OPND_CREATE_INT32(0)));
                        } else if (r1 >= SPILL_REG_EAX_DEAD && r1 <= SPILL_REG_EBX_DEAD) {
                            PRE(ilist, NULL, INSTR_CREATE_mov_imm
                                (drcontext,
                                 opnd_create_reg(REG_EAX + (r1 - SPILL_REG_EAX_DEAD)),
                                 OPND_CREATE_INT32(0)));
                        } else {
                            PRE(ilist, NULL, INSTR_CREATE_mov_st
                                (drcontext, spill_slot_opnd(drcontext, SPILL_SLOT_1), 
                                 OPND_CREATE_INT32(0)));
                        }
                    }
                    shared_slowpath_spill(drcontext, ilist, r1, SPILL_SLOT_1);

                    if (whole_bb_spills_enabled()) {
                        /* we need to put the app's reg values back into the
                         * whole-bb spill slots.  slow_path() doesn't know which
                         * regs are being used, so we do it here via a two-step
                         * return process.  if no regs are spilled we could
                         * skip this: but would need to xfer from slot2 to slot5,
                         * which would require a spill, so we don't bother.
                         */
                        PRE(ilist, NULL,
                            INSTR_CREATE_mov_st(drcontext, 
                                                spill_slot_opnd(drcontext, SPILL_SLOT_5),
                                                opnd_create_instr(return_point)));
                    }
                    PRE(ilist, NULL,
                        INSTR_CREATE_jmp(drcontext,
                                         opnd_create_pc(shared_slowpath_entry)));
                    if (whole_bb_spills_enabled()) {
                        bool tgt_in_reg;
                        reg_id_t regtgt = REG_NULL;
                        PRE(ilist, NULL, return_point);
                        /* instrument_slowpath() re-arranges so the whole-bb
                         * spills are always r1 and r2 (have to be, since using
                         * slots 1 & 2)
                         */
                        if (r2 >= SPILL_REG_EAX && r2 <= SPILL_REG_EBX) {
                            regtgt = REG_EAX + (r2 - SPILL_REG_EAX);
                            PRE(ilist, NULL,
                                INSTR_CREATE_xchg
                                (drcontext, spill_slot_opnd(drcontext, SPILL_SLOT_2),
                                 opnd_create_reg(regtgt)));
                            tgt_in_reg = true;
                        } else
                            tgt_in_reg = false;
                        if (r1 >= SPILL_REG_EAX && r1 <= SPILL_REG_EBX) {
                            /* we use xchg instead of mov_st to support
                             * PR 493257 where slowpath put shared shadow addr
                             * into slot1 and we restore it to reg1 here
                             */
                            PRE(ilist, NULL,
                                INSTR_CREATE_xchg
                                (drcontext, spill_slot_opnd(drcontext, SPILL_SLOT_1),
                                 opnd_create_reg(REG_EAX + (r1 - SPILL_REG_EAX))));
                        } else if (r1 >= SPILL_REG_EAX_DEAD && r1 <= SPILL_REG_EBX_DEAD) {
                            /* for PR 493257 we need to restore shared addr.
                             * should we split up if many bbs don't need this?
                             */
                            PRE(ilist, NULL,
                                INSTR_CREATE_mov_ld
                                (drcontext,
                                 opnd_create_reg(REG_EAX + (r1 - SPILL_REG_EAX_DEAD)),
                                 spill_slot_opnd(drcontext, SPILL_SLOT_1)));
                        }
                        if (tgt_in_reg) {
                            PRE(ilist, NULL,
                                INSTR_CREATE_jmp_ind(drcontext, opnd_create_reg(regtgt)));
                        } else {
                            PRE(ilist, NULL,
                                INSTR_CREATE_jmp_ind
                                (drcontext, spill_slot_opnd(drcontext, SPILL_SLOT_2)));
                        }
                    }

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
}

void
instrument_init(void)
{
#ifdef TOOL_DR_MEMORY
    void *drcontext = dr_get_current_drcontext();
    byte *pc;
    bool ok;
    instrlist_t *ilist;
#endif

    if (!options.shadowing)
        return;

#ifdef TOOL_DR_MEMORY
    ilist = instrlist_create(drcontext);

    shared_slowpath_region = (byte *)
        nonheap_alloc(SHARED_SLOWPATH_SIZE,
                      DR_MEMPROT_READ|DR_MEMPROT_WRITE|DR_MEMPROT_EXEC,
                      HEAPSTAT_GENCODE);
    pc = shared_slowpath_region;

    if (!options.leaks_only) {
        pc = generate_shared_slowpath(drcontext, ilist, pc);
        ASSERT(pc - shared_slowpath_region <= SHARED_SLOWPATH_SIZE,
               "shared esp slowpath too large");
    }

    pc = generate_shared_esp_slowpath(drcontext, ilist, pc);
    ASSERT(pc - shared_slowpath_region <= SHARED_SLOWPATH_SIZE,
           "shared esp slowpath too large");
    if (!options.leaks_only) {
        pc = generate_shared_esp_fastpath(drcontext, ilist, pc);
        ASSERT(pc - shared_slowpath_region <= SHARED_SLOWPATH_SIZE,
               "shared esp fastpath too large");
    }

    instrlist_clear_and_destroy(drcontext, ilist);

    /* now mark as +rx (non-writable) */
    ok = dr_memory_protect(shared_slowpath_region, SHARED_SLOWPATH_SIZE,
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

    if (!options.leaks_only) {
        gencode_lock = dr_mutex_create();

        hashtable_init_ex(&bb_table, BB_HASH_BITS, HASH_INTPTR, false/*!strdup*/,
                          false/*!synch*/, bb_table_free_entry, NULL, NULL);
        hashtable_init(&xl8_sharing_table, XL8_SHARING_HASH_BITS, HASH_INTPTR,
                       false/*!strdup*/);
        hashtable_init(&ignore_unaddr_table, IGNORE_UNADDR_HASH_BITS, HASH_INTPTR,
                       false/*!strdup*/);
        stringop_lock = dr_mutex_create();
        hashtable_init_ex(&stringop_app2us_table, STRINGOP_HASH_BITS, HASH_INTPTR,
                          false/*!strdup*/, false/*!synch*/,
                          stringop_free_entry, NULL, NULL);
        hashtable_init_ex(&stringop_us2app_table, STRINGOP_HASH_BITS, HASH_INTPTR,
                          false/*!strdup*/, false/*!synch*/, NULL, NULL, NULL);

#ifdef STATISTICS
        next_stats_dump = options.stats_dump_interval;
#endif
        
#ifdef TOOL_DR_MEMORY
        replace_init();
#endif
    }
}

void
instrument_exit(void)
{
    if (!options.shadowing)
        return;
#ifdef TOOL_DR_MEMORY
    nonheap_free(shared_slowpath_region, SHARED_SLOWPATH_SIZE, HEAPSTAT_GENCODE);
#endif
    if (!options.leaks_only) {
        dr_mutex_destroy(gencode_lock);
        LOG(1, "final bb table size: %u bits, %u entries\n",
            bb_table.table_bits, bb_table.entries);
        hashtable_delete(&bb_table);
        hashtable_delete(&xl8_sharing_table);
        hashtable_delete(&ignore_unaddr_table);
        dr_mutex_destroy(stringop_lock);
        hashtable_delete(&stringop_app2us_table);
        hashtable_delete(&stringop_us2app_table);
#ifdef TOOL_DR_MEMORY
        replace_exit();
#endif
    }
}

/* PR 525807: try to handle small malloced stacks */
void
update_stack_swap_threshold(void *drcontext, int new_threshold)
{
    bool ok;
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
        ok = dr_memory_protect(shared_slowpath_region, SHARED_SLOWPATH_SIZE,
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
#endif

static bool
stringop_equal(uint val1, uint val2, uint opsz)
{
    if (opsz == 1)
        return ((val1 & 0xff) == (val2 & 0xff));
    else if (opsz == 2)
        return ((val1 & 0xffff) == (val2 & 0xffff));
    else if (opsz == 4)
        return (val1 == val2);
    else
        ASSERT(false, "bad stringop opsz internal error");
    return false;
}

static void
get_stringop_range(reg_t base, reg_t count, reg_t eflags, uint opsz,
                 app_pc *start/*OUT*/, app_pc *end/*OUT*/)
{
    /* ecx is a pre-iter check; zf is a post-iter check */
    if (TEST(EFLAGS_DF, eflags)) {
        /* decrement each iter */
        *start = (app_pc) (base - (count-1)*opsz);
        *end = (app_pc) (base + opsz);
    } else {
        *start = (app_pc) (base);
        *end = (app_pc) (base + count*opsz);
    }
}

#ifdef TOOL_DR_MEMORY
/* for jmp-to-slowpath optimization where we xl8 to get app pc (PR 494769) */
static app_pc
translate_cache_pc(byte *pc_to_xl8)
{
    app_pc res;
    void *drcontext = dr_get_current_drcontext();
    per_thread_t *pt = (per_thread_t *) dr_get_tls_field(drcontext);
    client_per_thread_t *cpt;
    ASSERT(pt != NULL, "pt shouldn't be null");
    cpt = (client_per_thread_t *) pt->client_data;
    ASSERT(cpt != NULL, "pt shouldn't be null");
    ASSERT(pc_to_xl8 != NULL, "invalid param");
    ASSERT(options.single_arg_slowpath, "only used for single_arg_slowpath");
    /* ensure event_restore_state() returns true */
    cpt->self_translating = true;
    res = dr_app_pc_from_cache_pc(pc_to_xl8);
    cpt->self_translating = false;
    ASSERT(res != NULL, "failure to determine app pc on slowpath");
    STATS_INC(xl8_app_for_slowpath);
    LOG(3, "translated "PFX" to "PFX" for slowpath\n", pc_to_xl8, res);
    return res;
}
#endif

app_pc
loc_to_pc(app_loc_t *loc)
{
    ASSERT(loc != NULL && loc->type == APP_LOC_PC, "invalid param");
    if (!loc->u.addr.valid) {
#ifdef TOOL_DR_MEMORY
        ASSERT(options.single_arg_slowpath, "only used for single_arg_slowpath");
        /* pc field holds cache pc that must be translated */
        ASSERT(dr_memory_is_dr_internal(loc->u.addr.pc), "invalid untranslated pc");
        loc->u.addr.pc = translate_cache_pc(loc->u.addr.pc);
        ASSERT(loc->u.addr.pc != NULL, "translation failed");
        loc->u.addr.valid = true;
#else
        ASSERT(false, "NYI");
#endif
    }
    return loc->u.addr.pc;
}

app_pc
loc_to_print(app_loc_t *loc)
{
    ASSERT(loc != NULL, "invalid param");
    if (loc->type == APP_LOC_PC) {
        /* perf hit to translate so only at high loglevel */
        DOLOG(3, { return loc_to_pc(loc); });
        return loc->u.addr.valid ? loc->u.addr.pc : NULL;
    } else {
        ASSERT(loc->type == APP_LOC_SYSCALL, "unknown type");
        return (app_pc) loc->u.syscall.sysnum;
    }
}

bool
check_mem_opnd(uint opc, uint flags, app_loc_t *loc, opnd_t opnd, uint sz,
               dr_mcontext_t *mc, uint *shadow_vals)
{
    app_pc addr = NULL, end;
#ifdef TOOL_DR_MEMORY
    int i;
#endif

    ASSERT(opc != OP_lea, "lea should not get here");

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
                register_shadow_mark_defined(reg);
            }
        }
    }
#endif

    if (opc_is_stringop_loop(opc) &&
        /* with -repstr_to_loop, a decoded repstr is really a non-rep str */
        !options.repstr_to_loop) {
        /* We assume flat segments for es and ds */
        /* FIXME: support addr16!  we're assuming 32-bit edi, esi! */
        ASSERT(reg_get_size(opnd_get_base(opnd)) == OPSZ_4,
               "no support yet for addr16 string operations!");
        if (opc == OP_rep_stos || opc == OP_rep_lods) {
            /* store from al/ax/eax into es:edi; load from es:esi into al/ax/eax */
            get_stringop_range(opc == OP_rep_stos ? mc->edi : mc->esi,
                               mc->ecx, mc->eflags, sz, &addr, &end);
            LOG(3, "rep %s "PFX"-"PFX"\n", opc == OP_rep_stos ? "stos" : "lods",
                addr, end);
            flags |= (sz == 1 ? MEMREF_SINGLE_BYTE :
                      (sz == 2 ? MEMREF_SINGLE_WORD : MEMREF_SINGLE_DWORD));
            sz = end - addr;
        } else if (opc == OP_rep_movs) {
            /* move from ds:esi to es:edi */
            LOG(3, "rep movs "PFX" "PFX" "PIFX"\n", mc->edi, mc->esi, mc->ecx);
            /* FIXME: if checking definedness of sources, really
             * should do read+write in lockstep, since an earlier
             * write could make a later read ok; for now we punt on
             * that.  We do an overlap check and warn below.
             * If we're propagating and not checking sources, then the
             * overlap is fine: we'll go through the source, ensure addressable
             * but do nothing if undefined, and then go through dest copying
             * from source in lockstep.
             */
            get_stringop_range(mc->esi, mc->ecx, mc->eflags, sz, &addr, &end);
            if (!TEST(MEMREF_WRITE, flags)) {
                flags &= ~MEMREF_USE_VALUES;
            } else {
                ASSERT(shadow_vals != NULL, "assuming have shadow if marked write");
                flags |= MEMREF_MOVS | MEMREF_USE_VALUES;
                shadow_vals[0] = (uint) addr;
                get_stringop_range(mc->edi, mc->ecx, mc->eflags, sz, &addr, &end);
                if (TEST(MEMREF_CHECK_DEFINEDNESS, flags) &&
                    end > (app_pc)shadow_vals[0] &&
                    addr < ((app_pc)shadow_vals[0]) + (end - addr))
                    ELOG(0, "WARNING: rep movs overlap while checking definedness not fully supported!\n");
            }
            sz = end - addr;
        } else if (opc == OP_rep_scas || opc == OP_repne_scas) {
            /* compare es:edi to al/ax/eax */
            /* we can't just do post-instr check since we want to warn of
             * unaddressable refs prior to their occurrence, so we emulate
             * FIXME: we aren't aggregating errors in adjacent bytes */
            LOG(3, "rep scas @"PFX" "PFX" "PIFX"\n", loc_to_print(loc), mc->edi, mc->ecx);
            while (mc->ecx != 0) { /* note the != instead of > */
                uint val;
                bool eq;
                handle_mem_ref(flags, loc, (app_pc)mc->edi, sz, mc, shadow_vals);
                /* remember that our notion of unaddressable is not real so we have
                 * to check with the OS to see if this will fault
                 */
                ASSERT(sz <= sizeof(uint), "internal error");
                if (safe_read((void *)mc->edi, sz, &val)) {
                    /* Assume the real instr will fault here.
                     * FIXME: if the instr gets resumed our check won't re-execute! */
                    break; 
                }
                eq = stringop_equal(val, mc->eax, sz);
                mc->edi += (TEST(EFLAGS_DF, mc->eflags) ? -1 : 1) * sz;
                mc->ecx--;
                if ((opc == OP_rep_scas && !eq) ||
                    (opc == OP_repne_scas && eq))
                    break;
            }
            return true;
        } else if (opc == OP_rep_cmps || opc == OP_repne_cmps) {
            /* compare ds:esi to es:edi */
            /* FIXME: we aren't aggregating errors in adjacent bytes */
            if (reg_overlap(opnd_get_base(opnd), REG_EDI))
                return true; /* we check both when passed esi base */
            LOG(3, "rep cmps @"PFX" "PFX" "PFX" "PIFX"\n",
                loc_to_print(loc), mc->edi, mc->esi, mc->ecx);
            while (mc->ecx != 0) { /* note the != instead of > */
                uint val1, val2;
                bool eq;
                handle_mem_ref(flags, loc, (app_pc)mc->esi, sz, mc, shadow_vals);
                handle_mem_ref(flags, loc, (app_pc)mc->edi, sz, mc, shadow_vals);
                /* remember that our notion of unaddressable is not real so we have
                 * to check with the OS to see if this will fault
                 */
                ASSERT(sz <= sizeof(uint), "internal error");
                if (!safe_read((void *)mc->esi, sz, &val1) ||
                    !safe_read((void *)mc->edi, sz, &val2)) {
                    /* Assume the real instr will fault here.
                     * FIXME: if the instr gets resumed our check won't re-execute! */
                    break; 
                }
                eq = stringop_equal(val1, val2, sz);
                mc->edi += (TEST(EFLAGS_DF, mc->eflags) ? -1 : 1) * sz;
                mc->esi += (TEST(EFLAGS_DF, mc->eflags) ? -1 : 1) * sz;
                mc->ecx--;
                if ((opc == OP_rep_cmps && !eq) ||
                    (opc == OP_repne_cmps && eq))
                    break;
            }
            return true;
        } else
            ASSERT(false, "unknown string operation");
    } else {
        addr = opnd_compute_address(opnd, mc);
    }
    if (sz == 0)
        return true;
    return handle_mem_ref(flags, loc, addr, sz, mc, shadow_vals);
}

#ifdef TOOL_DR_MEMORY
/* handle_mem_ref checks addressability and if necessary checks
 * definedness and adjusts addressability
 */
bool
handle_mem_ref(uint flags, app_loc_t *loc, app_pc addr, size_t sz, dr_mcontext_t *mc,
               uint *shadow_vals)
{
    uint i;
    bool allgood = true;
    /* report ranges of errors instead of individual bytes */
    app_pc bad_addr = NULL, bad_end = NULL;
    uint bad_type = SHADOW_DEFINED; /* i.e., no error */
#ifdef STATISTICS
    bool was_special = shadow_get_special(addr, NULL);
    bool exception = false;
#endif
    app_pc stack_base = NULL;
    size_t stack_size = 0;
    bool handled_push_addr = false;
    ASSERT(!options.leaks_only && options.shadowing, "shadowing disabled");
    LOG(3, "memref: %s @"PFX" "PFX" "PIFX" bytes (pre-dword 0x%02x 0x%02x)%s\n",
        TEST(MEMREF_WRITE, flags) ? (TEST(MEMREF_PUSHPOP, flags) ? "push" : "write") :
        (TEST(MEMREF_PUSHPOP, flags) ? "pop" : "read"), loc_to_print(loc), addr, sz,
        shadow_get_dword(addr), shadow_get_dword(addr+4),
        was_special ? " (was special)" : "");
    ASSERT(addr + sz > addr, "address overflow"); /* no overflow */
    /* xref PR 466036: a very large size and a bogus address can take an
     * extremely long time here, as we query the stack bounds for every
     * single byte: now we cache them but will still be slow.
     */
    /* note that gap compiled by cl has an 18MB rep stos (PR 502506) */
    ASSERT(sz < 32*1024*1024, "suspiciously large size");
    ASSERT(!TEST(MEMREF_USE_VALUES, flags) || shadow_vals != NULL,
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
        uint shadow = shadow_get_byte(addr + i);
        ASSERT(shadow <= 3, "internal error");
        if (shadow == SHADOW_UNADDRESSABLE) {
            if (TEST(MEMREF_PUSHPOP, flags) && !TEST(MEMREF_WRITE, flags)) {
                ELOG(0, "ERROR: "PFX" popping unaddressable memory: possible Dr. Memory bug\n",
                     loc_to_print(loc));
                if (options.pause_at_unaddressable)
                    wait_for_user("popping unaddressable memory!");
            }
            /* FIXME: stack ranges: right now we assume that a push makes memory
             * addressable, but really should check if in stack range
             */
            if (TEST(MEMREF_PUSHPOP, flags) && TEST(MEMREF_WRITE, flags)) {
                ASSERT(!TEST(MEMREF_MOVS, flags), "internal movs error");
                shadow_set_byte(addr + i, TEST(MEMREF_USE_VALUES, flags) ?
                                shadow_vals[memref_idx(flags, i)] : SHADOW_DEFINED);
            } else {
                /* We check stack bounds here and cache to avoid
                 * check_undefined_exceptions having to do it over and over (did
                 * show up on pc sampling at one point).  We assume that
                 * mcontext contains the app's esp for all callers (including
                 * our custom clean calls).
                 */
                bool addr_on_stack = false;
                if (stack_base == NULL)
                    stack_size = allocation_size((app_pc)mc->esp, &stack_base);
                LOG(4, "comparing %08x %08x %08x %08x\n",
                    addr+i, stack_base, stack_base+stack_size, mc->esp);
                if (addr+i >= stack_base && addr+i < stack_base+stack_size &&
                    addr+i < (app_pc)mc->esp)
                    addr_on_stack = true;
                if (!check_unaddressable_exceptions(TEST(MEMREF_WRITE, flags), loc,
                                                    addr + i, sz, addr_on_stack)) {
                    bool new_bad = true;
                    if (bad_addr != NULL) {
                        if (bad_type != SHADOW_UNADDRESSABLE) {
                            ASSERT(bad_type == SHADOW_UNDEFINED,
                                   "internal report error");
                            report_undefined_read
                                (loc, bad_addr, bad_end + 1 - bad_addr,
                                 addr, addr + sz, mc);
                        } else if (bad_end < addr + i - 1) {
                            report_unaddressable_access
                                (loc, bad_addr, bad_end + 1 - bad_addr,
                                 TEST(MEMREF_WRITE, flags), addr, addr + sz, mc);
                        } else
                            new_bad = false;
                    }
                    if (new_bad) {
                        bad_type = SHADOW_UNADDRESSABLE;
                        bad_addr = addr + i;
                    } /* else extend current bad */
                    bad_end = addr + i;
                    /* We follow Memcheck's lead and set to defined to avoid too
                     * many subsequent errors.  However, if it's on the stack but
                     * beyond TOS, we leave it as undefined to avoid our own
                     * asserts.
                     */
                    if (addr_on_stack) {
                        LOG(2, "unaddressable beyond TOS: leaving unaddressable\n");
                    } else {
                        shadow_set_byte(addr+i, SHADOW_DEFINED);
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
                                                TEST(MEMREF_WRITE, flags),
                                                loc, addr + i, sz, &shadow) &&
                    TEST(MEMREF_CHECK_DEFINEDNESS, flags)) {
                    bool new_bad = true;
                    if (bad_addr != NULL) {
                        if (bad_type != SHADOW_UNDEFINED) {
                            ASSERT(bad_type == SHADOW_UNADDRESSABLE,
                                   "internal report error");
                            report_unaddressable_access
                                (loc, bad_addr, bad_end + 1 - bad_addr,
                                 TEST(MEMREF_WRITE, flags), addr, addr + sz, mc);
                        } else if (bad_end < addr + i - 1) {
                            report_undefined_read
                                (loc, bad_addr, bad_end + 1 - bad_addr,
                                 addr, addr + sz, mc);
                        } else
                            new_bad = false;
                    }
                    if (new_bad) {
                        bad_type = SHADOW_UNDEFINED;
                        bad_addr = addr + i;
                    } /* else extend current bad */
                    bad_end = addr + i;
                    allgood = false;
                    /* Set to defined to avoid duplicate errors */
                    shadow_set_byte(addr+i, SHADOW_DEFINED);
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
                shadow_set_byte(addr + i, SHADOW_UNADDRESSABLE);
            }
        } else if (!TEST(MEMREF_CHECK_ADDRESSABLE, flags)) {
            uint newval;
            if (TEST(MEMREF_PUSHPOP, flags)) {
                if (!handled_push_addr) {
                    /* only call once: don't want to mark push target as unaddr,
                     * so each byte will trigger here: avoid extra warnings in logs
                     */
                    handled_push_addr =
                        handle_push_addressable(loc, addr + i, addr, sz, mc);
                }
            }
            if (TEST(MEMREF_MOVS, flags)) {
                ASSERT(TEST(MEMREF_USE_VALUES, flags), "internal movs error");
                ASSERT(memref_idx(flags, i) == i, "internal movs error");
                newval = shadow_get_byte(((app_pc)shadow_vals[0]) + i);
            } else {
                newval = TEST(MEMREF_USE_VALUES, flags) ?
                    shadow_vals[memref_idx(flags, i)] : SHADOW_DEFINED;
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
                    shadow_set_byte(addr + i, newval);
                }
            }
        }
        if (!TEST(MEMREF_WRITE, flags) && TEST(MEMREF_USE_VALUES, flags)) {
            ASSERT(!TEST(MEMREF_MOVS, flags), "internal movs error");
            /* combine with current value
             * FIXME: this is a simplistic way to combine multiple sources: we're
             * ignoring promotion to more-significant bytes, etc.
             */
            shadow_vals[memref_idx(flags, i)] =
                combine_shadows(shadow_vals[memref_idx(flags, i)], shadow);
        }
        if (MAP_4B_TO_1B) {
            /* only need to process each 4-byte address region once */
            if (POINTER_OVERFLOW_ON_ADD(addr, 4))
                break;
            i = ((ptr_uint_t)ALIGN_FORWARD(addr + i + 1, 4) - (ptr_uint_t)addr);
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
            LOG(1, "unaligned slow @"PFX" %s "PFX" "PIFX" bytes (pre 0x%02x 0x%02x)%s ",
                loc_to_print(loc),
                TEST(MEMREF_WRITE, flags) ?
                (TEST(MEMREF_PUSHPOP, flags) ? "push" : "write") :
                (TEST(MEMREF_PUSHPOP, flags) ? "pop" : "read"),
                addr, sz, shadow_get_dword(addr), shadow_get_dword(addr+4), was_special ? " (was special)" : "");
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
    if (bad_addr != NULL) {
        if (bad_type == SHADOW_UNDEFINED)
            report_undefined_read(loc, bad_addr, bad_end + 1 - bad_addr,
                                  addr, addr + sz, mc);
        else {
            ASSERT(bad_type == SHADOW_UNADDRESSABLE, "internal report error");
            report_unaddressable_access
                (loc, bad_addr, bad_end + 1 - bad_addr, TEST(MEMREF_WRITE, flags),
                 addr, addr + sz, mc);
        }
    }
    return allgood;
}
#endif /* TOOL_DR_MEMORY */

bool
check_register_defined(void *drcontext, reg_id_t reg, app_loc_t *loc, size_t sz,
                       dr_mcontext_t *mc, instr_t *inst)
{
#ifdef TOOL_DR_MEMORY
    uint shadow = (reg == REG_EFLAGS) ? get_shadow_eflags() : get_shadow_register(reg);
    if (!is_shadow_register_defined(shadow)) {
        if (!check_undefined_reg_exceptions(drcontext, loc, reg, mc, inst)) {
            /* FIXME: report which bytes within reg via container params? */
            report_undefined_read(loc, (app_pc)(ptr_int_t)reg, sz, NULL, NULL, mc);
            if (reg == REG_EFLAGS) {
                /* now reset to avoid complaining on every branch from here on out */
                set_shadow_eflags(SHADOW_DWORD_DEFINED);
            } else {
                /* Set to defined to avoid duplicate errors */
                register_shadow_mark_defined(reg);
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

/* PR 580123: add fastpath for rep string instrs by converting to normal loop */
static void
convert_repstr_to_loop(void *drcontext, instrlist_t *bb, bb_info_t *bi,
                       bool translating)
{
    instr_t *inst, *next_inst;
    bool delete_rest = false;
    uint opc;

    ASSERT(options.repstr_to_loop, "shouldn't be called");

    /* Make a rep string instr be its own bb: the loop is going to
     * duplicate the tail anyway, and have to terminate at the added cbr.
     */
    for (inst = instrlist_first(bb);
         inst != NULL;
         inst = next_inst) {
        next_inst = instr_get_next(inst);
        opc = instr_get_opcode(inst);
        if (delete_rest) {
            instrlist_remove(bb, inst);
            instr_destroy(drcontext, inst);
        } else if (opc_is_stringop_loop(opc)) {
            delete_rest = true;
            if (inst != instrlist_first(bb)) {
                instrlist_remove(bb, inst);
                instr_destroy(drcontext, inst);
            }
        }
    }

    /* Convert to a regular loop if it's the sole instr */
    inst = instrlist_first(bb);
    opc = instr_get_opcode(inst);
    if (opc_is_stringop_loop(opc)) {
        app_pc xl8 = instr_get_app_pc(inst);
        opnd_t xcx = instr_get_dst(inst, instr_num_dsts(inst) - 1);
        instr_t *loop, *pre_loop, *jecxz, *zero, *iter;
        stringop_entry_t *old, *entry;
        IF_DEBUG(bool ok;)
        ASSERT(opnd_uses_reg(xcx, REG_XCX), "rep string opnd order mismatch");
        ASSERT(inst == instrlist_last(bb), "repstr not alone in bb");
        LOG(3, "converting rep string into regular loop\n");

        pre_loop = INSTR_CREATE_label(drcontext);
        /* hack to handle loop decrementing xcx: simpler if could have 2 cbrs! */
        zero = INSTR_CREATE_mov_imm(drcontext, xcx,
                                    opnd_create_immed_int(1, opnd_get_size(xcx)));
        iter = INSTR_CREATE_label(drcontext);

        /* if xcx is 0 we'll skip ahead and will restore the whole-bb regs
         * at the bottom of the bb so make sure we save first.
         * this relies on fastpath_top_of_bb() executing earlier, so once
         * change to app-to-app before all instru may have to recognize
         * the meta-jecxz during initial instru.
         */
        if (whole_bb_spills_enabled()) {
            mark_scratch_reg_used(drcontext, bb, bi, &bi->reg1);
            mark_scratch_reg_used(drcontext, bb, bi, &bi->reg2);
            mark_eflags_used(drcontext, bb, bi);
            /* eflag saving may have clobbered xcx, which we need for jecxz */
            if (bi->reg1.reg == REG_XCX || bi->reg2.reg == REG_XCX) {
                insert_spill_global(drcontext, bb, inst,
                                    (bi->reg1.reg == REG_XCX) ? &bi->reg1 : &bi->reg2,
                                    false/*restore*/);
            }
        }

        /* A rep string instr does check for 0 up front.  DR limits us
         * to 1 cbr so we have to make a meta cbr.  If ecx is uninit
         * the loop* will catch it so we're ok not instrumenting this.
         * I would just jecxz to loop, but w/ instru it can't reach so
         * I have to add yet more meta-jmps that will execute each
         * iter.  Grrr.
         */
        jecxz = INSTR_CREATE_jecxz(drcontext, opnd_create_instr(zero));
        /* be sure to match the same counter reg width */
        instr_set_src(jecxz, 1, xcx);
        PRE(bb, inst, jecxz);
        PRE(bb, inst, INSTR_CREATE_jmp_short(drcontext, opnd_create_instr(iter)));
        PRE(bb, inst, zero);
        /* if app ecx is spilled must spill the 1 */
        if (whole_bb_spills_enabled() && bi->reg1.reg == REG_XCX)
            insert_spill_global(drcontext, bb, inst, &bi->reg1, true/*save*/);
        if (whole_bb_spills_enabled() && bi->reg2.reg == REG_XCX)
            insert_spill_global(drcontext, bb, inst, &bi->reg2, true/*save*/);
        /* target the instrumentation for the loop, not loop itself */
        PRE(bb, inst, INSTR_CREATE_jmp(drcontext, opnd_create_instr(pre_loop)));
        PRE(bb, inst, iter);

        PREXL8(bb, inst, INSTR_XL8(create_nonloop_stringop(drcontext, inst), xl8));
        /* We could point instr_can_use_shared_slowpath() at the final byte of the
         * instr (i.e., past the rep prefix) and have shared_slowpath fix up the pc
         * if it reports an error, and perhaps assume the string instr is immediately
         * after the return from slowpath (should be true since shouldn't pick edi or
         * esi as scratch regs, and none of the string instrs read aflags) so it can
         * look for data16 prefix.  But it's simpler to handle data16 prefix by
         * pointing at the start of the instr and having shared_slowpath assume there
         * are no repstrs doing loops so no loop emulation is needed.  This means the
         * slowpath will consider xcx an operand here in addition to at the loop
         * instr below but that shouldn't be a problem: if xcx is uninit it will get
         * reported once and w/ the right pc.  Xref i#353.
         */
        instr_set_note(instr_get_prev(inst), (void *)xl8);

        PRE(bb, inst, pre_loop);
        if (opc == OP_rep_cmps || opc == OP_rep_scas) {
            loop = INSTR_CREATE_loope(drcontext, opnd_create_pc(xl8));
        } else if (opc == OP_repne_cmps || opc == OP_repne_scas) {
            loop = INSTR_CREATE_loopne(drcontext, opnd_create_pc(xl8));
        } else {
            loop = INSTR_CREATE_loop(drcontext, opnd_create_pc(xl8));
        }
        /* be sure to match the same counter reg width */
        instr_set_src(loop, 1, xcx);
        instr_set_dst(loop, 0, xcx);

        /* We need to tell instr_can_use_shared_slowpath() what app pc to use
         * while pointing it at an OP_loop instr.
         * For -fastpath, we should go to slowpath only if ecx is uninit, but
         * even then we can't afford to treat as a string op: will read wrong
         * mem addr b/c the just-executed string op adjusted edi/esi (i#391).
         * Solution is to allocate some memory and create a fake OP_loop there.
         * We use a hashtable to map from that to the app_pc.
         * We free by relying on the stringop being the first instr and thus
         * the tag (=> no trace support).
         */
        if (translating) {
            dr_mutex_lock(stringop_lock);
            entry = (stringop_entry_t *) hashtable_lookup(&stringop_app2us_table, xl8);
            ASSERT(entry != NULL, "stringop entry should exit on translation");
            dr_mutex_unlock(stringop_lock);
        } else {
            entry = (stringop_entry_t *) global_alloc(sizeof(*entry), HEAPSTAT_PERBB);
            entry->loop_instr[0] = LOOP_INSTR_OPCODE;
            entry->loop_instr[1] = 0;
            entry->ignore_next_delete = 0;
            dr_mutex_lock(stringop_lock);
            old = (stringop_entry_t *)
                hashtable_add_replace(&stringop_app2us_table, xl8, (void *)entry);
            if (old != NULL) {
                ASSERT(old->ignore_next_delete < UCHAR_MAX, "ignore_next_delete overflow");
                entry->ignore_next_delete = old->ignore_next_delete + 1;
                global_free(old, sizeof(*old), HEAPSTAT_PERBB);
                LOG(2, "stringop "PFX" duplicated: assuming non-precise flushing\n", xl8);
            }
            IF_DEBUG(ok = )
                hashtable_add(&stringop_us2app_table, (void *)entry, xl8);
            /* only freed for heap reuse on hashtable removal */
            ASSERT(ok, "not possible to have existing from-heap entry");
            dr_mutex_unlock(stringop_lock);
        }

        instr_set_note(loop, (void *)entry);
        PREXL8(bb, inst, INSTR_XL8(loop, xl8));

        /* now throw out the orig instr */
        instrlist_remove(bb, inst);
        instr_destroy(drcontext, inst);
    }
}

/* Conversions to app code itself that should happen before instrumentation */
static void
app_to_app_transformations(void *drcontext, instrlist_t *bb, bb_info_t *bi,
                           bool translating)
{
    if (options.repstr_to_loop && options.shadowing)
        convert_repstr_to_loop(drcontext, bb, bi, translating);
}

dr_emit_flags_t
instrument_bb(void *drcontext, void *tag, instrlist_t *bb,
              bool for_trace, bool translating)
{
    per_thread_t *pt = (per_thread_t *) dr_get_tls_field(drcontext);
    instr_t *inst, *next_inst, *first;
    uint i;
    app_pc pc;
    uint opc;
    bool has_gpr, has_mem, has_noignorable_mem;
    bool check_ignore_unaddr = false, entering_alloc, exiting_alloc;
    bb_info_t bi;
    fastpath_info_t mi;
    bool added_instru = false;

#ifdef TOOL_DR_MEMORY
    static bool first_bb = true;
    /* No way to get app xsp at init or thread init (i#117) so we do it here */
    if (first_bb) {
        set_initial_layout();
        first_bb = false;
    }
#endif
    memset(&bi, 0, sizeof(bi));
    memset(&mi, 0, sizeof(mi));

    LOG(5, "in instrument_bb\n");
    DOLOG(3, instrlist_disassemble(drcontext, tag, bb, pt->f););
#ifdef TOOL_DR_MEMORY
    DOLOG(4, { 
        if (options.shadowing) {
            LOG(4, "shadow register values:\n");
            print_shadow_registers();
        }
    });
#endif

    /* Rather than having DR store translations, it takes less space for us to
     * use the bb table we already have
     */
    if (options.shadowing) {
        if (translating) {
            bb_saved_info_t *save;
            hashtable_lock(&bb_table);
            save = (bb_saved_info_t *) hashtable_lookup(&bb_table, tag);
            ASSERT(save != NULL, "missing bb info");
            if (save->check_ignore_unaddr)
                check_ignore_unaddr = true;
            hashtable_unlock(&bb_table);
        } else {
            /* We want to ignore unaddr refs by heap routines (when touching headers,
             * etc.).  We want to stay on the fastpath so we put checks there.
             * We decide up front since in_heap_routine changes dynamically
             * and if we recreate partway into the first bb we'll get it wrong:
             * though now that we're checking the first bb from alloc_instrument
             * it doesn't matter.
             */
            check_ignore_unaddr = (options.check_ignore_unaddr &&
                                   pt->in_heap_routine > 0);
            DOLOG(2, {
                if (check_ignore_unaddr)
                    LOG(2, "inside heap routine: adding nop-if-mem-unaddr checks\n");
            });
#ifdef TOOL_DR_MEMORY
            if (options.check_memset_unaddr &&
                in_replace_memset(dr_fragment_app_pc(tag))) {
                /* since memset is later called by heap routines, add in-heap checks
                 * now (i#234).  we add them to other mem and string routines as well
                 * rather than try
                 */
                check_ignore_unaddr = true;
                LOG(2, "inside memset routine @"PFX": adding nop-if-mem-unaddr checks\n",
                    tag);
            }
#endif
        }
    }

    /* First, do replacements; then, app-to-app; finally, instrument. */
    alloc_replace_instrument(drcontext, bb);
#ifdef TOOL_DR_MEMORY
    if (!options.leaks_only && options.shadowing) {
        /* String routine replacement */
        replace_instrument(drcontext, bb);
        /* XXX: this should be AFTER app_to_app_transformations, but something's
         * not working right: the rep-movs transformation is marking something
         * as meta that shouldn't be?!?
         */
        fastpath_top_of_bb(drcontext, tag, bb, &bi);
    }
#endif
    app_to_app_transformations(drcontext, bb, &bi, translating);

    first = instrlist_first(bb);

    for (inst = instrlist_first(bb);
         inst != NULL;
         inst = next_inst) {

	next_inst = instr_get_next(inst);
        /* app_to_app_transformations does insert some meta instrs: ignore them */
        if (!instr_ok_to_mangle(inst))
            continue;
        pc = instr_get_app_pc(inst);

        if (options.perturb) {
            /* Perturb timing */
            perturb_instrument(drcontext, bb, inst);
        }

        /* Memory allocation tracking */
        alloc_instrument(drcontext, bb, inst, &entering_alloc, &exiting_alloc);
        /* We can't change check_ignore_unaddr in the middle b/c of recreation
         * so only set if entering/exiting on first
         */
        if (inst == first && options.shadowing && options.check_ignore_unaddr) {
            if (entering_alloc) {
                check_ignore_unaddr = true;
                LOG(2, "entering heap routine: adding nop-if-mem-unaddr checks\n");
            } else if (exiting_alloc) {
                /* we wait until post-call so pt->in_heap_routine >0 in post-call
                 * bb event, so avoid adding checks there
                 */
                check_ignore_unaddr = false;
                LOG(2, "exiting heap routine: NOT adding nop-if-mem-unaddr checks\n");
            }
        }

#if defined(LINUX) && defined(TOOL_DR_MEMORY)
        if (!options.leaks_only && options.shadowing &&
            hashtable_lookup(&sighand_table, (void*)pc) != NULL) {
            instrument_signal_handler(drcontext, bb, inst, pc);
        }
#endif

        if (!options.leaks_only && options.shadowing) {
            /* We want to spill AFTER any clean call in case it changes mcontext */
            bi.spill_after = instr_get_prev(inst);
            
            /* update liveness of whole-bb spilled regs */
            fastpath_pre_instrument(drcontext, bb, inst, &bi);
        }

        opc = instr_get_opcode(inst);
        if (instr_is_syscall(inst)) {
            /* new syscall events mean we no longer have to add a clean call
             */
#ifdef TOOL_DR_MEMORY
            check_syscall_gateway(inst);
#endif
            /* we treat interrupts and syscalls, including the call*
             * for a wow64 syscall, as though they do not write to the
             * stack or esp (for call*, since we never see the
             * corresponding ret instruction): for sysenter though
             * we treat is as though it performs the ret that DR misses
             * (on Windows).
             */
#ifdef WINDOWS
            if (instr_get_opcode(inst) != OP_sysenter)
#endif
                continue;
        }
#ifdef WINDOWS
        ASSERT(!instr_is_wow64_syscall(inst), "syscall identification error");
#endif
        if (!options.shadowing && !options.leaks_only)
            continue;
        if (instr_is_interrupt(inst))
            continue;
        if (instr_is_nop(inst) &&
            /* work around DR bug PR 332257 */
            (instr_get_opcode(inst) != OP_xchg ||
             opnd_same(instr_get_dst(inst, 0), instr_get_dst(inst, 1))))
            continue;

        /* if there are no gpr or mem operands, we can ignore it */
        has_gpr = false;
        has_mem = false;
        has_noignorable_mem = false;
        for (i = 0; i < instr_num_dsts(inst); i++) {
            opnd_t opnd = instr_get_dst(inst, i);
            if (opnd_is_memory_reference(opnd) && instr_get_opcode(inst) != OP_lea)
                has_mem = true;
#ifdef TOOL_DR_MEMORY
            if (opnd_uses_nonignorable_memory(opnd))
                has_noignorable_mem = true;
#endif
            if (opnd_is_reg(opnd) && reg_is_gpr(opnd_get_reg(opnd))) {
                has_gpr = true;
                /* written to => no longer known to be addressable,
                 * unless modified by const amt: we look for push/pop
                 */
                if (!(opc_is_push(opc) || (opc_is_pop(opc) && i > 0))) {
                    bi.addressable[reg_to_pointer_sized(opnd_get_reg(opnd)) -
                                   REG_EAX] = false;
                }
            }
        }
        if (!has_gpr || !has_mem) {
            for (i = 0; i < instr_num_srcs(inst); i++) {
                opnd_t opnd = instr_get_src(inst, i);
                if (opnd_is_memory_reference(opnd) && instr_get_opcode(inst) != OP_lea)
                    has_mem = true;
#ifdef TOOL_DR_MEMORY
                if (opnd_uses_nonignorable_memory(opnd))
                    has_noignorable_mem = true;
#endif
                if (opnd_is_reg(opnd) && reg_is_gpr(opnd_get_reg(opnd)))
                    has_gpr = true;
            }
        }
        if (!has_gpr && !has_mem &&
            !TESTANY(EFLAGS_READ_6|EFLAGS_WRITE_6, instr_get_eflags(inst)))
            continue;

        /* for cmp/test+jcc -check_cmps don't need to instrument jcc */
        if (bi.eflags_defined && opc_is_jcc(instr_get_opcode(inst)))
            continue;

        if (!options.leaks_only && options.shadowing &&
            (options.check_uninitialized || has_noignorable_mem)) {
            if (instr_ok_for_instrument_fastpath(inst, &mi, &bi)) {
                instrument_fastpath(drcontext, bb, inst, &mi, check_ignore_unaddr);
                added_instru = true;
            } else {
                LOG(3, "fastpath unavailable "PFX": ", pc);
                DOLOG(3, { instr_disassemble(drcontext, inst, pt->f); });
                LOG(3, "\n");
                bi.shared_memop = opnd_create_null();
                /* Restore whole-bb spilled regs (PR 489221) 
                 * FIXME: optimize via liveness analysis
                 */
                mi.reg1 = bi.reg1;
                mi.reg2 = bi.reg2;
                memset(&mi.reg3, 0, sizeof(mi.reg3));
                instrument_slowpath(drcontext, bb, inst,
                                    whole_bb_spills_enabled() ? &mi : NULL);
                /* for whole-bb slowpath does interact w/ global regs */
                added_instru = whole_bb_spills_enabled();
            }
        }
        /* do esp adjust last, for ret immed; leave wants it the
         * other way but we compensate in adjust_memop() */
        /* -leaks_only co-opts esp-adjust code to zero out newly allocated stack
         * space to avoid stale pointers from prior frames from misleading our
         * leak scan (PR 520916).  yes, I realize it may not be perfectly
         * transparent.
         */
        if ((options.leaks_only || options.shadowing) &&
            (options.check_uninitialized || options.check_stack_bounds) &&
            instr_writes_esp(inst)) {
            /* any new spill must be after the fastpath instru */
            bi.spill_after = instr_get_prev(inst);
            if (instrument_esp_adjust(drcontext, bb, inst, &bi)) {
                /* instru clobbered reg1 so no sharing across it */
                bi.shared_memop = opnd_create_null();
            }
            added_instru = true;
        }

        /* None of the "continues" above need to be processed here */
        if (!options.leaks_only && options.shadowing)
            fastpath_pre_app_instr(drcontext, bb, inst, &bi, &mi);

        if (mi.appclone != NULL) {
            instr_t *nxt = instr_get_next(mi.appclone);
            ASSERT(options.single_arg_slowpath, "only used for single_arg_slowpath");
            while (nxt != NULL &&
                   (instr_is_label(nxt) || instr_is_spill(nxt) || instr_is_restore(nxt)))
                nxt = instr_get_next(nxt);
            ASSERT(nxt != NULL, "app clone error");
            DOLOG(3, {
                per_thread_t *pt = (per_thread_t *) dr_get_tls_field(drcontext);
                LOG(3, "comparing: ");
                instr_disassemble(drcontext, mi.appclone, pt->f);
                LOG(3, "\n");
                LOG(3, "with: ");
                instr_disassemble(drcontext, nxt, pt->f);
                LOG(3, "\n");
            });
            STATS_INC(app_instrs_fastpath);
            /* only destroy if app instr won't be mangled */
            if (instr_same(mi.appclone, nxt) &&
                !instr_is_cti(nxt) &&
                /* FIXME PR 494769: -single_arg_slowpath cannot be on by default
                 * until b/c we can't predict whether an instr will be mangled
                 * for selfmod!  Also, today we're not looking for mangling of
                 * instr_has_rel_addr_reference().  The option is off by default
                 * until that's addressed by implementing i#156/PR 306163 and
                 * adding post-mangling bb and trace events.
                 */
                !instr_is_syscall(nxt) &&
                !instr_is_interrupt(nxt)) {
                ASSERT(mi.slow_store_retaddr != NULL, "slowpath opt error");
                ASSERT(opnd_is_instr(instr_get_src(mi.slow_store_retaddr, 0)) &&
                       opnd_get_instr(instr_get_src(mi.slow_store_retaddr, 0)) ==
                       mi.appclone, "slowpath opt error");
                /* point at the jmp so slow_path() knows to return right afterward */
                instr_set_src(mi.slow_store_retaddr, 0, opnd_create_instr(mi.slow_jmp));
                instrlist_remove(bb, mi.appclone);
                instr_destroy(drcontext, mi.appclone);
                mi.appclone = NULL;
                STATS_INC(app_instrs_no_dup);
            } else {
                DOLOG(3, {
                    per_thread_t *pt = (per_thread_t *) dr_get_tls_field(drcontext);
                    LOG(3, "need dup for: ");
                    instr_disassemble(drcontext, mi.appclone, pt->f);
                    LOG(3, "\n");
                });
            }
        }
    }
    LOG(5, "\texiting instrument_bb\n");

    if (!options.leaks_only && options.shadowing) {
        fastpath_bottom_of_bb(drcontext, tag, bb, &bi, added_instru, translating,
                              check_ignore_unaddr);
    }

    /* We store whether check_ignore_unaddr in our own data struct to avoid
     * DR having to store translations, so we can recreate deterministically.
     */
    return DR_EMIT_DEFAULT;
}
