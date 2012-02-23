/* **********************************************************
 * Copyright (c) 2010-2012 Google, Inc.  All rights reserved.
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
#include "drutil.h"
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
#include "annotations.h"
#ifdef TOOL_DR_HEAPSTAT
# include "../drheapstat/staleness.h"
#endif
#include "pattern.h"
#include <stddef.h>

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

#ifdef TOOL_DR_MEMORY
static dr_emit_flags_t
instru_event_bb_app2app(void *drcontext, void *tag, instrlist_t *bb,
                        bool for_trace, bool translating, OUT void **user_data);

static dr_emit_flags_t
instru_event_bb_analysis(void *drcontext, void *tag, instrlist_t *bb,
                         bool for_trace, bool translating, void *user_data);

static dr_emit_flags_t
instru_event_bb_insert(void *drcontext, void *tag, instrlist_t *bb, instr_t *inst,
                       bool for_trace, bool translating, void *user_data);

static dr_emit_flags_t
instru_event_bb_instru2instru(void *drcontext, void *tag, instrlist_t *bb,
                              bool for_trace, bool translating, void *user_data);
#endif /* TOOL_DR_MEMORY */

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
 * we allocate our own register spill slots for faster access than
 * the non-directly-addressable DR slots (only 3 are direct)
 */

#ifdef LINUX
/* Data for which we need direct addressability access from instrumentation */
typedef struct _tls_instru_t {
    /* We store segment bases here for dynamic access from thread-shared code */
    byte *app_fs_base;
    byte *app_gs_base;
    byte *dr_fs_base;
    byte *dr_gs_base;
} tls_instru_t;
/* followed by reg spill slots */
# define NUM_INSTRU_TLS_SLOTS (sizeof(tls_instru_t)/sizeof(byte *))
#else
# define NUM_INSTRU_TLS_SLOTS 0
/* just reg spill slots */
#endif

#define NUM_TLS_SLOTS (NUM_INSTRU_TLS_SLOTS + options.num_spill_slots)

/* the offset of our tls_instr_t + reg spill tls slots */
static uint tls_instru_base;

/* we store a pointer in regular tls for access to other threads' TLS */
static int tls_idx_instru = -1;

#ifdef LINUX
static uint
tls_base_offs(void)
{
    ASSERT(INSTRUMENT_MEMREFS(), "incorrectly called");
    return tls_instru_base +
        offsetof(tls_instru_t, IF_X64_ELSE(dr_gs_base, dr_fs_base));
}

/* Create a far memory reference opnd to access DR's TLS memory slot
 * for getting app's TLS base address. 
 */
opnd_t
opnd_create_seg_base_slot(reg_id_t seg, opnd_size_t opsz)
{
    uint stored_base_offs;
    ASSERT(INSTRUMENT_MEMREFS(), "incorrectly called");
    ASSERT(seg == SEG_FS || seg == SEG_GS, "only fs and gs supported");
    stored_base_offs = tls_instru_base +
        ((seg == SEG_FS) ? offsetof(tls_instru_t, app_fs_base) : 
         offsetof(tls_instru_t, app_gs_base));
    return opnd_create_far_base_disp_ex
        (SEG_FS, REG_NULL, REG_NULL, 1, stored_base_offs, opsz,
         /* we do NOT want an addr16 prefix since most likely going to run on
          * Core or Core2, and P4 doesn't care that much */
         false, true, false);
}
#endif

byte *
get_own_seg_base(void)
{
    byte *seg_base;
#ifdef WINDOWS
    seg_base = (byte *) get_TEB();
#else
    uint offs = tls_base_offs();
    asm("movzx %0, %%"ASM_XAX : : "m"(offs) : ASM_XAX);
    asm("mov %%"ASM_SEG":(%%"ASM_XAX"), %%"ASM_XAX : : : ASM_XAX);
    asm("mov %%"ASM_XAX", %0" : "=m"(seg_base) : : ASM_XAX);
#endif
    return seg_base;
}

static void
instru_tls_init(void)
{
    reg_id_t seg;
    IF_DEBUG(bool ok =)
        dr_raw_tls_calloc(&seg, &tls_instru_base, NUM_TLS_SLOTS, 0);
    LOG(2, "TLS spill base: "PIFX"\n", tls_instru_base);
    tls_idx_instru = drmgr_register_tls_field();
    ASSERT(NUM_TLS_SLOTS > 0, "NUM_TLS_SLOTS should be > 0");
    ASSERT(tls_idx_instru > -1, "failed to reserve TLS slot");
    ASSERT(ok, "fatal error: unable to reserve tls slots");
    ASSERT(seg == IF_X64_ELSE(SEG_GS, SEG_FS), "unexpected tls segment");
}

static void
instru_tls_exit(void)
{
    IF_DEBUG(bool ok =)
        dr_raw_tls_cfree(tls_instru_base, NUM_TLS_SLOTS);
    ASSERT(ok, "WARNING: unable to free tls slots");
    drmgr_unregister_tls_field(tls_idx_instru);
}

static void
instru_tls_thread_init(void *drcontext)
{
#ifdef LINUX
    tls_instru_t *tls;
    dr_mcontext_t mc; /* do not init whole thing: memset is expensive */
    mc.size = sizeof(mc);
    mc.flags = DR_MC_CONTROL|DR_MC_INTEGER; /* don't need xmm */

    /* bootstrap: can't call get_own_seg_base() until set up seg base fields */
    byte *app_fs_base =
        opnd_compute_address(opnd_create_far_base_disp(SEG_FS, REG_NULL, REG_NULL,
                                                       0, 0, OPSZ_lea), &mc);
    byte *app_gs_base =
        opnd_compute_address(opnd_create_far_base_disp(SEG_GS, REG_NULL, REG_NULL,
                                                       0, 0, OPSZ_lea), &mc);
    byte *dr_fs_base = dr_get_dr_segment_base(SEG_FS);
    byte *dr_gs_base = dr_get_dr_segment_base(SEG_GS);
# ifdef X64
    tls = (tls_instru_t *) (dr_gs_base + tls_instru_base);
# else
    tls = (tls_instru_t *) (dr_fs_base + tls_instru_base);
# endif
    /* FIXME PR 406315: look for dynamic changes to fs and gs */
    tls->app_fs_base = app_fs_base;
    tls->app_gs_base = app_gs_base;
    tls->dr_fs_base  = dr_fs_base;
    tls->dr_gs_base  = dr_gs_base;
    LOG(1, "app: fs base="PFX", gs base="PFX"\n"
        "dr: fs base"PFX", gs base="PFX"\n",
        app_fs_base, app_gs_base, dr_fs_base, dr_gs_base);
    /* store in per-thread data struct so we can access from another thread */
    drmgr_set_tls_field(drcontext, tls_idx_instru, (void *) tls);
#else
    /* store in per-thread data struct so we can access from another thread */
    drmgr_set_tls_field(drcontext, tls_idx_instru, (void *)
                        (get_own_seg_base() + tls_instru_base));
#endif
}

static void
instru_tls_thread_exit(void *drcontext)
{
    drmgr_set_tls_field(drcontext, tls_idx_instru, NULL);
}

uint
num_own_spill_slots(void)
{
    return options.num_spill_slots;
}

opnd_t
opnd_create_own_spill_slot(uint index)
{
    ASSERT(index < options.num_spill_slots, "spill slot index overflow");
    ASSERT(INSTRUMENT_MEMREFS(), "incorrectly called");
    return opnd_create_far_base_disp_ex
        /* must use 0 scale to match what DR decodes for opnd_same */
        (SEG_FS, REG_NULL, REG_NULL, 0,
         tls_instru_base + (NUM_INSTRU_TLS_SLOTS + index)*sizeof(ptr_uint_t), OPSZ_PTR,
         /* we do NOT want an addr16 prefix since most likely going to run on
          * Core or Core2, and P4 doesn't care that much */
         false, true, false);
}

ptr_uint_t
get_own_tls_value(uint index)
{
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
    ptr_uint_t val;
#ifdef WINDOWS
    val = *(ptr_uint_t *)(((byte *)get_TEB()) + offset);
#else
    asm("movzx %0, %%"ASM_XAX : : "m"(offset) : ASM_XAX);
    asm("mov %%"ASM_SEG":(%%"ASM_XAX"), %%"ASM_XAX : : : ASM_XAX);
    asm("mov %%"ASM_XAX", %0" : "=m"(val) : : ASM_XAX);
#endif
    return val;
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
    cls_drmem_t *cpt = (cls_drmem_t *) drmgr_get_cls_field(drcontext, cls_idx_drmem);
    ASSERT(cpt != NULL, "cpt shouldn't be null");

    if (!options.shadowing)
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
    LOG(3, "freeing stringop entry "PFX" ignore_next_delete %d\n",
        e, e->ignore_next_delete);
    global_free(e, sizeof(*e), HEAPSTAT_PERBB);
}

void
instrument_fragment_delete(void *drcontext/*may be NULL*/, void *tag)
{
    bb_saved_info_t *save;
    stringop_entry_t *stringop;
    uint bb_size = 0;
#ifdef TOOL_DR_MEMORY
    if (!options.shadowing)
        return;
#endif

    hashtable_lock(&bb_table);
    save = (bb_saved_info_t *) hashtable_lookup(&bb_table, tag);
    if (save != NULL) {
        /* PR 495787: handle non-precise flushing where new bbs can be created
         * before the old ones are fully deleted
         */
        LOG(2, "event_fragment_delete "PFX" ignore_next_delete=%d\n",
            tag, save->ignore_next_delete);
        if (save->ignore_next_delete == 0) {
            bb_size = save->bb_size;
            hashtable_remove(&bb_table, tag);
        } else /* hashtable lock is held so no race here */
            save->ignore_next_delete--;
    }
    hashtable_unlock(&bb_table);

    if (bb_size > 0) {
        /* i#260: remove xl8_sharing_table entries.  We can't
         * decode forward (not always safe) and query every app pc, so we store the
         * bb size and assume bbs are contiguous (no elision) and there are no traces
         * (already assuming that for i#114 and dr_fragment_exists_at()).  We assume
         * walking these hashtables is faster than switching to an rbtree, and it's
         * not worth storing pointers in bb_saved_info_t.
         *
         * Without removing, new code that replaces old code at the same address can
         * fail to be optimized b/c it will use the old code's history: so a perf
         * failure, not a correctness failure.
         */
        /* XXX i#551: -single_arg_slowpath adds a second xl8_sharing_table entry with
         * cache pc for each app pc entry which we are not deleting yet.  May need a
         * table to map the two.  Xref DRi#409: while there's no good solution from
         * the DR side for app pc flushing, perhaps some event on re-using cache pcs
         * could work but seems too specialized.
         */
        /* i#768: We used to invalidate entries from ignore_unaddr_table here,
         * but that ends up thrashing the code cache.  Instead we remove stale
         * entries in the new bb event if the alloca pattern no longer matches.
         */
        app_pc start = dr_fragment_app_pc(tag);
        /* It turns out that hashtable_remove_range() is really slow: xl8_sharing_table
         * gets quite large (12 bits on chrome ui_tests single test) and walking
         * it on every single fragment delete is quite slow.
         * This is faster:
         */
        int i;
        for (i = 0; i < bb_size; i++) {
            hashtable_remove(&xl8_sharing_table, (void *)(start + i));
        }
    }

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
            LOG(2, "removing tag "PFX" and stringop entry "PFX"\n",
                tag, stringop);
            ASSERT(found, "entry should be in both tables");
        } else {
            LOG(2, "stringop entry "PFX" for tag "PFX" nextdel=%d\n",
                stringop, tag, stringop->ignore_next_delete);
            stringop->ignore_next_delete--;
        }
    }
    dr_mutex_unlock(stringop_lock);
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
    dr_mcontext_t mc; /* do not init whole thing: memset is expensive */
    opnd_t src = instr_get_src(inst, i);
    if (val == NULL)
        return false;
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
        uint extra_pushes = (uint) opnd_get_immed_int(instr_get_src(inst, 1));
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
        (options.check_uninit_non_moves && !opc_is_move(opc)) ||
        options.check_uninit_all ||
        (options.check_uninit_cmps &&
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
     * we have two different checks: one for !options.check_uninit_non_moves where
     * the error isn't raised until the jnb and one for error on xor.
     * FIXME: share code w/ is_rawmemchr_pattern() in alloc_drmem.c
     */
    if (options.check_uninit_non_moves ||
        options.check_uninit_all) {
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
     * OP_and (and OP_test if -no_check_uninit_cmps) so we must mark defined.
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

bool
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
            opnd = opnd_create_null();
#endif
        } else
            opnd = instr_get_src(inst, i);
        if (opnd_uses_nonignorable_memory(opnd)) {
            opnd = adjust_memop(inst, opnd, false, &sz, &pushpop_stackop);
            if (pushpop_stackop && options.check_stack_bounds)
                flags = MEMREF_PUSHPOP | MEMREF_IS_READ;
            else
                flags = MEMREF_CHECK_ADDRESSABLE | MEMREF_IS_READ;
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
slow_path_with_mc(void *drcontext, app_pc pc, app_pc decode_pc, dr_mcontext_t *mc)
{
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
        medium_path_movs4(&loc, mc);
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
        instr_disassemble(drcontext, &inst, LOGFILE_GET(drcontext));
        if (instr_num_dsts(&inst) > 0 &&
            opnd_is_memory_reference(instr_get_dst(&inst, 0))) {
            LOG(3, " | 0x%x",
                shadow_get_byte(opnd_compute_address(instr_get_dst(&inst, 0), mc)));
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
        ((opc == OP_lea) ? 2 : num_true_srcs(&inst, mc));
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
                if (options.leave_uninit)
                    flags |= MEMREF_USE_VALUES;
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
            check_mem_opnd(opc, flags, &loc, opnd, sz, mc,
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
                    check_register_defined(drcontext, reg, &loc, sz, mc, &inst);
                    if (options.leave_uninit) {
                        integrate_register_shadow
                            (&inst, i, 
                             /* do not combine srcs if checking after */
                             check_srcs_after ? &shadow_vals[i*sz] : shadow_vals,
                             reg, shadow, pushpop);
                    }
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
            opnd_disassemble(drcontext, opnd, LOGFILE_GET(drcontext));
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
            check_register_defined(drcontext, REG_EFLAGS, &loc, 1, mc, &inst);
            if (options.leave_uninit) {
                integrate_register_shadow
                    (&inst, 0, 
                     /* do not combine srcs if checking after */
                     check_srcs_after ? &shadow_vals[i*sz] : shadow_vals,
                     REG_EFLAGS, shadow, pushpop);
            }
        } else {
            /* See above: we only propagate when not checking */
            integrate_register_shadow
                (&inst, 0, 
                 /* do not combine srcs if checking after */
                 check_srcs_after ? &shadow_vals[i*sz] : shadow_vals,
                 REG_EFLAGS, shadow, pushpop);
        }
    } else if (num_srcs == 0) {
        /* do not propagate from shadow_vals since dst size could be large (i#458)
         * (fxsave, etc.)
         */
        always_defined = true;
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

    num_dsts = num_true_dsts(&inst, mc);
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
                if (options.leave_uninit)
                    flags |= MEMREF_USE_VALUES;
                /* since checking, we mark as SHADOW_DEFINED (see above) */
            } else {
                ASSERT(sz <= sizeof(shadow_vals), "internal shadow val error");
                flags |= MEMREF_USE_VALUES;
            }
            /* check addressability, and propagate
             * we arranged xchg/xadd to not need shifting; nothing else does either.
             */
            memop = opnd;
            check_mem_opnd(opc, flags, &loc, opnd, sz, mc, shadow_vals);
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
    slow_path_xl8_sharing(&loc, instr_sz, memop, mc);

    DOLOG(4, {
        if (!options.single_arg_slowpath && pc == decode_pc/*else retpc not in tls3*/) {
            /* Test translation when have both args */
            /* we want the ultimate target, not whole_bb_spills_enabled()'s
             * SPILL_SLOT_5 intermediate target
             */
            byte *ret_pc = (byte *) get_own_tls_value(SPILL_SLOT_2);
            /* ensure event_restore_state() returns true */
            byte *xl8;
            cls_drmem_t *cpt = (cls_drmem_t *)
                drmgr_get_cls_field(drcontext, cls_idx_drmem);
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

/* called from code cache */
static bool
slow_path(app_pc pc, app_pc decode_pc)
{
    void *drcontext = dr_get_current_drcontext();
    dr_mcontext_t mc; /* do not init whole thing: memset is expensive */
    mc.size = sizeof(mc);
    mc.flags = DR_MC_CONTROL|DR_MC_INTEGER; /* don't need xmm */
    dr_get_mcontext(drcontext, &mc);
    return slow_path_with_mc(drcontext, pc, decode_pc, &mc);
}

static app_pc
instr_shared_slowpath_decode_pc(instr_t *inst, fastpath_info_t *mi)
{
    if (!options.shared_slowpath)
        return NULL;
    if (mi->bb->fake_xl8_override_instr == inst)
        return mi->bb->fake_xl8_override_pc;
    else if (mi->bb->fake_xl8 != NULL)
        return mi->bb->fake_xl8;
    else if (instr_get_app_pc(inst) == instr_get_raw_bits(inst))
        return instr_get_app_pc(inst);
    return NULL;
}

bool
instr_can_use_shared_slowpath(instr_t *inst, fastpath_info_t *mi)
{
    return (instr_shared_slowpath_decode_pc(inst, mi) != NULL);
}

void
instrument_slowpath(void *drcontext, instrlist_t *bb, instr_t *inst,
                    fastpath_info_t *mi)
{
    app_pc decode_pc = instr_shared_slowpath_decode_pc(inst, mi);
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

    drmgr_priority_t priority = {sizeof(priority), "drmemory.instru", NULL, NULL,
                                 DRMGR_PRIORITY_INSTRU};
    drutil_init();
    annotate_init();

#ifdef TOOL_DR_MEMORY
    /* XXX: at some point we should design a cleaner interaction between
     * various drmemory/ components and drheapstat/.
     * For now sticking w/ the original where drheapstat's bb events
     * call into here.
     */
    if (!drmgr_register_bb_instrumentation_ex_event
        (instru_event_bb_app2app, instru_event_bb_analysis,
         instru_event_bb_insert, instru_event_bb_instru2instru,
         &priority)) {
        ASSERT(false, "drmgr registration failed");
    }
#endif

    /* we need bb event for leaks_only */
    if (!INSTRUMENT_MEMREFS())
        return;

    instru_tls_init();

#ifdef TOOL_DR_MEMORY
    if (options.shadowing) {
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
    }
#endif

    if (options.shadowing) {
        gencode_lock = dr_mutex_create();

        hashtable_init_ex(&bb_table, BB_HASH_BITS, HASH_INTPTR, false/*!strdup*/,
                          false/*!synch*/, bb_table_free_entry, NULL, NULL);
        hashtable_init(&xl8_sharing_table, XL8_SHARING_HASH_BITS, HASH_INTPTR,
                       false/*!strdup*/);
        hashtable_init(&ignore_unaddr_table, IGNORE_UNADDR_HASH_BITS, HASH_INTPTR,
                       false/*!strdup*/);
    }
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
    if (INSTRUMENT_MEMREFS())
        replace_init();
#endif
}

void
instrument_exit(void)
{
    annotate_exit();
    drutil_exit();
    if (!INSTRUMENT_MEMREFS())
        return;
#ifdef TOOL_DR_MEMORY
    if (options.shadowing) {
        nonheap_free(shared_slowpath_region, SHARED_SLOWPATH_SIZE, 
                     HEAPSTAT_GENCODE);
    }
#endif
    if (options.shadowing) {
        dr_mutex_destroy(gencode_lock);
        hashtable_delete_with_stats(&bb_table, "bb_table");
        hashtable_delete_with_stats(&xl8_sharing_table, "xl8_sharing");
        hashtable_delete_with_stats(&ignore_unaddr_table, "ignore_unaddr");
    }
    dr_mutex_destroy(stringop_lock);
    hashtable_delete(&stringop_app2us_table);
    hashtable_delete(&stringop_us2app_table);
#ifdef TOOL_DR_MEMORY
    if (INSTRUMENT_MEMREFS())
        replace_exit();
#endif
    instru_tls_exit();
}

void
instrument_thread_init(void *drcontext)
{
    if (!INSTRUMENT_MEMREFS())
        return;
    instru_tls_thread_init(drcontext);
}

void
instrument_thread_exit(void *drcontext)
{
    if (!INSTRUMENT_MEMREFS())
        return;
    instru_tls_thread_exit(drcontext);
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
    cls_drmem_t *cpt = (cls_drmem_t *) drmgr_get_cls_field(drcontext, cls_idx_drmem);
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
 * returns true if no errors were found
 */
bool
handle_mem_ref(uint flags, app_loc_t *loc, app_pc addr, size_t sz, dr_mcontext_t *mc,
               uint *shadow_vals)
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
    app_pc stack_base = NULL;
    size_t stack_size = 0;
    bool handled_push_addr = false;
    bool is_write =
        /* ADDR is assumed to be for writes only (i#517) */
        TESTANY(MEMREF_WRITE | MEMREF_CHECK_ADDRESSABLE, flags) &&
        !TEST(MEMREF_IS_READ, flags);
    if (options.pattern != 0)
        return pattern_handle_mem_ref(loc, addr, sz, mc, is_write);
    ASSERT(options.shadowing, "shadowing disabled");
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
    ASSERT(TEST(MEMREF_ABORT_AFTER_UNADDR, flags) ||
           sz < 32*1024*1024, "suspiciously large size");
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
                                 is_write, addr, addr + sz, mc);
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
                                                is_write, loc, addr + i, sz, &shadow) &&
                    TEST(MEMREF_CHECK_DEFINEDNESS, flags)) {
                    bool new_bad = true;
                    if (found_bad_addr) {
                        if (bad_type != SHADOW_UNDEFINED) {
                            ASSERT(bad_type == SHADOW_UNADDRESSABLE,
                                   "internal report error");
                            report_unaddressable_access
                                (loc, bad_addr, bad_end + 1 - bad_addr,
                                 is_write, addr, addr + sz, mc);
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
            char buf[256];
            size_t sofar = 0;
            print_address(buf, BUFFER_SIZE_BYTES(buf), &sofar, loc_to_pc(loc),
                          NULL, true/*for log*/);
            NULL_TERMINATE_BUFFER(buf);
            LOG(1, "unaligned slow @"PFX" %s "PFX" "PIFX" bytes (pre 0x%02x 0x%02x)%s %s ",
                loc_to_print(loc),
                TEST(MEMREF_WRITE, flags) ?
                (TEST(MEMREF_PUSHPOP, flags) ? "push" : "write") :
                (TEST(MEMREF_PUSHPOP, flags) ? "pop" : "read"),
                addr, sz, shadow_get_dword(addr), shadow_get_dword(addr+4),
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
                (loc, bad_addr, bad_end + 1 - bad_addr, is_write, addr, addr + sz, mc);
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

#ifdef TOOL_DR_MEMORY
/* PR 580123: add fastpath for rep string instrs by converting to normal loop */
static void
convert_repstr_to_loop(void *drcontext, instrlist_t *bb, bb_info_t *bi,
                       bool translating)
{
    bool expanded;
    instr_t *string;
    ASSERT(options.repstr_to_loop, "shouldn't be called");
    /* The bulk of the code here is now in the drutil library */
    if (!drutil_expand_rep_string_ex(drcontext, bb, &expanded, &string))
        ASSERT(false, "drutil failed");
    if (expanded) {
        stringop_entry_t *old, *entry;
        app_pc xl8 = instr_get_app_pc(string);
        IF_DEBUG(bool ok;)
        LOG(3, "converting rep string into regular loop\n");

        /* we handle the jecxz skipping lazy spill in the insert routine */

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
        bi->fake_xl8_override_instr = string;
        bi->fake_xl8_override_pc = xl8;

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
                IF_DEBUG(bool found;)
                LOG(2, "stringop xl8 "PFX" duplicated at "PFX
                    ": assuming non-precise flushing\n", xl8, old);
                ASSERT(old->ignore_next_delete < UCHAR_MAX, "ignore_next_delete overflow");
                entry->ignore_next_delete = old->ignore_next_delete + 1;
                global_free(old, sizeof(*old), HEAPSTAT_PERBB);
                IF_DEBUG(found =)
                    hashtable_remove(&stringop_us2app_table, (void *)old);
                ASSERT(found, "entry should be in both tables");
            }
            IF_DEBUG(ok = )
                hashtable_add(&stringop_us2app_table, (void *)entry, xl8);
            LOG(2, "adding stringop entry "PFX" for xl8 "PFX"\n",
                entry, xl8);
            /* only freed for heap reuse on hashtable removal */
            ASSERT(ok, "not possible to have existing from-heap entry");
            dr_mutex_unlock(stringop_lock);
        }

        /* we have the jecxz, mov $1, 2 jmps, and this loop all treated as OP_loop by
         * slowpath.  not a problem: ok to treat all as reading xcx.
         */
        bi->fake_xl8 = (app_pc) entry;

        bi->is_repstr_to_loop = true;
    }
}

/* Conversions to app code itself that should happen before instrumentation */
static dr_emit_flags_t
instru_event_bb_app2app(void *drcontext, void *tag, instrlist_t *bb,
                        bool for_trace, bool translating, OUT void **user_data)
{
    bb_info_t *bi;
#ifdef TOOL_DR_MEMORY
    static bool first_bb = true;
    /* No way to get app xsp at init or thread init (i#117) so we do it here */
    if (first_bb) {
        set_initial_layout();
        first_bb = false;
    }
#endif

    /* we pass bi among all 4 phases */
    bi = thread_alloc(drcontext, sizeof(*bi), HEAPSTAT_PERBB);
    memset(bi, 0, sizeof(*bi));
    *user_data = (void *) bi;

    LOG(SYSCALL_VERBOSE, "in event_basic_block(tag="PFX")%s%s\n", tag,
        for_trace ? " for trace" : "", translating ? " translating" : "");
    DOLOG(3, instrlist_disassemble(drcontext, tag, bb, LOGFILE_GET(drcontext)););

    if (options.repstr_to_loop && INSTRUMENT_MEMREFS())
        convert_repstr_to_loop(drcontext, bb, bi, translating);

    return DR_EMIT_DEFAULT;
}

static dr_emit_flags_t
instru_event_bb_analysis(void *drcontext, void *tag, instrlist_t *bb,
                         bool for_trace, bool translating, void *user_data)
{
    bb_info_t *bi = (bb_info_t *) user_data;

    LOG(4, "ilist before analysis:\n");
    DOLOG(4, instrlist_disassemble(drcontext, tag, bb, LOGFILE_GET(drcontext)););

#ifdef USE_DRSYMS
    /* symbol of each bb is very useful for debugging */
    DOLOG(3, {
        char buf[128];
        size_t sofar = 0;
        ssize_t len;
        if (!translating) {
            BUFPRINT(buf, BUFFER_SIZE_ELEMENTS(buf), sofar, len,
                     "new basic block @"PFX" ==", tag);
            print_symbol(tag, buf, BUFFER_SIZE_ELEMENTS(buf), &sofar);
            LOG(1, "%s\n", buf);
        }
    });
#endif
#ifdef TOOL_DR_MEMORY
    DOLOG(4, { 
        if (options.shadowing) {
            LOG(4, "shadow register values:\n");
            print_shadow_registers();
        }
    });
#endif

#ifdef TOOL_DR_MEMORY
    if (options.shadowing)
        fastpath_top_of_bb(drcontext, tag, bb, bi);
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
                bi->check_ignore_unaddr = true;
            hashtable_unlock(&bb_table);
        } else {
            /* We want to ignore unaddr refs by heap routines (when touching headers,
             * etc.).  We want to stay on the fastpath so we put checks there.
             * We decide up front since in_heap_routine changes dynamically
             * and if we recreate partway into the first bb we'll get it wrong:
             * though now that we're checking the first bb from alloc_instrument
             * it doesn't matter.
             */
            bi->check_ignore_unaddr = (options.check_ignore_unaddr &&
                                       alloc_in_heap_routine(drcontext));
            DOLOG(2, {
                if (bi->check_ignore_unaddr)
                    LOG(2, "inside heap routine: adding nop-if-mem-unaddr checks\n");
            });
#ifdef TOOL_DR_MEMORY
            if (options.check_memset_unaddr &&
                in_replace_memset(dr_fragment_app_pc(tag))) {
                /* since memset is later called by heap routines, add in-heap checks
                 * now (i#234).  we add them to other mem and string routines as well
                 * rather than try
                 */
                bi->check_ignore_unaddr = true;
                LOG(2, "inside memset routine @"PFX": adding nop-if-mem-unaddr checks\n",
                    tag);
            }
#endif
        }
    }

    bi->first_instr = true;

    return DR_EMIT_DEFAULT;
}

static dr_emit_flags_t
instru_event_bb_insert(void *drcontext, void *tag, instrlist_t *bb, instr_t *inst,
                       bool for_trace, bool translating, void *user_data)
{
    bb_info_t *bi = (bb_info_t *) user_data;
    uint i;
    app_pc pc = instr_get_app_pc(inst);
    uint opc;
    bool has_gpr, has_mem, has_noignorable_mem;
    fastpath_info_t mi;

    if (!instr_ok_to_mangle(inst))
        goto instru_event_bb_insert_done;

    memset(&mi, 0, sizeof(mi));

    /* We can't change bi->check_ignore_unaddr in the middle b/c of recreation
     * so only set if entering/exiting on first
     */
    if (bi->first_instr && INSTRUMENT_MEMREFS() && options.check_ignore_unaddr) {
        if (alloc_entering_alloc_routine(pc)) {
            bi->check_ignore_unaddr = true;
            LOG(2, "entering heap routine: adding nop-if-mem-unaddr checks\n");
        } else if (alloc_exiting_alloc_routine(pc)) {
            /* we wait until post-call so pt->in_heap_routine >0 in post-call
             * bb event, so avoid adding checks there
             */
            bi->check_ignore_unaddr = false;
            LOG(2, "exiting heap routine: NOT adding nop-if-mem-unaddr checks\n");
        }
    }

    if (bi->first_instr && bi->is_repstr_to_loop) {
        /* if xcx is 0 we'll skip ahead and will restore the whole-bb regs
         * at the bottom of the bb so make sure we save first.
         * this is a case of internal control flow messing up code that
         * was taking advantage of the simplicity of linear block code!
         */
        if (whole_bb_spills_enabled()) {
            mark_scratch_reg_used(drcontext, bb, bi, &bi->reg1);
            mark_scratch_reg_used(drcontext, bb, bi, &bi->reg2);
            mark_eflags_used(drcontext, bb, bi);
            /* eflag saving may have clobbered xcx, which we need for jecxz, but
             * jecxz is an app instr now so we should naturally restore it
             */
        }
    }

#if defined(LINUX) && defined(TOOL_DR_MEMORY)
    if (options.shadowing &&
        hashtable_lookup(&sighand_table, (void*)pc) != NULL) {
        instrument_signal_handler(drcontext, bb, inst, pc);
    }
#endif

    if (options.shadowing) {
        /* We want to spill AFTER any clean call in case it changes mcontext */
        /* XXX: examine this: how make it more in spirit of drmgr? */
        bi->spill_after = instr_get_prev(inst);
        
        /* update liveness of whole-bb spilled regs */
        fastpath_pre_instrument(drcontext, bb, inst, bi);
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
            goto instru_event_bb_insert_done;
    }
#ifdef WINDOWS
    ASSERT(!instr_is_wow64_syscall(inst), "syscall identification error");
#endif
#ifdef TOOL_DR_MEMORY
    if (options.pattern != 0) {
        pattern_instrument_check(drcontext, bb, inst);
        goto instru_event_bb_insert_done;
    }
#endif
    if (!options.shadowing && !options.leaks_only)
        goto instru_event_bb_insert_done;
    if (instr_is_interrupt(inst))
        goto instru_event_bb_insert_done;
    if (instr_is_nop(inst) &&
        /* work around DR bug PR 332257 */
        (instr_get_opcode(inst) != OP_xchg ||
         opnd_same(instr_get_dst(inst, 0), instr_get_dst(inst, 1))))
        goto instru_event_bb_insert_done;
    
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
                bi->addressable[reg_to_pointer_sized(opnd_get_reg(opnd)) -
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
        goto instru_event_bb_insert_done;
    
    /* for cmp/test+jcc -check_uninit_cmps don't need to instrument jcc */
    if (bi->eflags_defined && opc_is_jcc(instr_get_opcode(inst)))
        goto instru_event_bb_insert_done;
    
    if (options.shadowing &&
        (options.check_uninitialized || has_noignorable_mem)) {
        if (instr_ok_for_instrument_fastpath(inst, &mi, bi)) {
            instrument_fastpath(drcontext, bb, inst, &mi, bi->check_ignore_unaddr);
            bi->added_instru = true;
        } else {
            LOG(3, "fastpath unavailable "PFX": ", pc);
            DOLOG(3, { instr_disassemble(drcontext, inst, LOGFILE_GET(drcontext)); });
            LOG(3, "\n");
            bi->shared_memop = opnd_create_null();
            /* Restore whole-bb spilled regs (PR 489221) 
             * FIXME: optimize via liveness analysis
             */
            mi.reg1 = bi->reg1;
            mi.reg2 = bi->reg2;
            memset(&mi.reg3, 0, sizeof(mi.reg3));
            instrument_slowpath(drcontext, bb, inst,
                                whole_bb_spills_enabled() ? &mi : NULL);
            /* for whole-bb slowpath does interact w/ global regs */
            bi->added_instru = whole_bb_spills_enabled();
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
        instr_writes_esp(inst)) {
        bool shadow_xsp = options.shadowing &&
            (options.check_uninitialized || options.check_stack_bounds);
        bool zero_stack = ZERO_STACK();
        if (shadow_xsp || zero_stack) {
            /* any new spill must be after the fastpath instru */
            bi->spill_after = instr_get_prev(inst);
            if (instrument_esp_adjust(drcontext, bb, inst, bi, shadow_xsp)) {
                /* instru clobbered reg1 so no sharing across it */
                bi->shared_memop = opnd_create_null();
            }
            if (shadow_xsp && zero_stack) {
                /* w/o definedness info we need to zero as well to find leaks */
                instrument_esp_adjust(drcontext, bb, inst, bi, false/*zero*/);
            }
        }
        bi->added_instru = true;
    }

    /* None of the "goto instru_event_bb_insert_dones" above need to be processed here */
    if (options.shadowing)
        fastpath_pre_app_instr(drcontext, bb, inst, bi, &mi);

    if (mi.appclone != NULL) {
        instr_t *nxt = instr_get_next(mi.appclone);
        ASSERT(options.single_arg_slowpath, "only used for single_arg_slowpath");
        while (nxt != NULL &&
               (instr_is_label(nxt) || instr_is_spill(nxt) || instr_is_restore(nxt)))
            nxt = instr_get_next(nxt);
        ASSERT(nxt != NULL, "app clone error");
        DOLOG(3, {
                LOG(3, "comparing: ");
                instr_disassemble(drcontext, mi.appclone, LOGFILE_GET(drcontext));
                LOG(3, "\n");
                LOG(3, "with: ");
                instr_disassemble(drcontext, nxt, LOGFILE_GET(drcontext));
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
                    LOG(3, "need dup for: ");
                    instr_disassemble(drcontext, mi.appclone, LOGFILE_GET(drcontext));
                    LOG(3, "\n");
                });
        }
    }
    
 instru_event_bb_insert_done:
    if (bi->first_instr)
        bi->first_instr = false;
    /* We store whether bi->check_ignore_unaddr in our own data struct to avoid
     * DR having to store translations, so we can recreate deterministically.
     */
    return DR_EMIT_DEFAULT;
}

static dr_emit_flags_t
instru_event_bb_instru2instru(void *drcontext, void *tag, instrlist_t *bb,
                              bool for_trace, bool translating, void *user_data)
{
    bb_info_t *bi = (bb_info_t *) user_data;

#ifdef TOOL_DR_MEMORY
    /* XXX i#777: should do reverse scan during analysis and store info */
    if (options.pattern != 0)
        pattern_instrument_reverse_scan(drcontext, bb);
#endif

    if (options.shadowing) {
        fastpath_bottom_of_bb(drcontext, tag, bb, bi, bi->added_instru, translating,
                              bi->check_ignore_unaddr);
    }

    LOG(4, "final ilist:\n");
    DOLOG(4, instrlist_disassemble(drcontext, tag, bb, LOGFILE_GET(drcontext)););

    thread_free(drcontext, bi, sizeof(*bi), HEAPSTAT_PERBB);
    return DR_EMIT_DEFAULT;
}

#endif /* TOOL_DR_MEMORY */
