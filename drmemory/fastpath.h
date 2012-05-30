/* **********************************************************
 * Copyright (c) 2011-2012 Google, Inc.  All rights reserved.
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
 * fastpath.c: Dr. Memory shadow instrumentation fastpath
 */

#ifndef _FASTPATH_H_
#define _FASTPATH_H_ 1

#include "callstack.h" /* app_loc_t */

/* reg liveness */
enum {
    LIVE_UNKNOWN,
    LIVE_LIVE,
    LIVE_DEAD,
};
enum {
    AFLAGS_UNKNOWN = 0,
    AFLAGS_IN_TLS,
    AFLAGS_IN_EAX,
};
#ifdef X64
# define NUM_LIVENESS_REGS 16
# define REG_START     REG_START_64
#else
# define NUM_LIVENESS_REGS 8
# define REG_START     REG_START_32
#endif

typedef struct _scratch_reg_info_t {
    reg_id_t reg;
    bool used;
    bool dead;
    bool global; /* spilled across whole bb (PR 489221) */
    /* we spill if used && !dead, either via xchg w/ a dead reg or via
     * a tls spill slot
     */
    reg_id_t xchg;
    int slot;
} scratch_reg_info_t;

struct _bb_info_t; /* forward decl */
typedef struct _bb_info_t bb_info_t;

typedef struct _opnd_info_t {
    opnd_t app;    /* app opnd: if null then other fields are invalid */
    opnd_t shadow; /* either value for src or memref for dst */
    opnd_t offs;   /* sub-dword offset */
} opnd_info_t;

#define MAX_FASTPATH_SRCS 3
#define MAX_FASTPATH_DSTS 2
typedef struct _fastpath_info_t {
    bb_info_t *bb;
    
    /* Filled in by instr_ok_for_instrument_fastpath()
     * The fastpath handles up to 3 sources and 2 dests subject to:
     * - Only one source memop
     * - Only one dest memop
     * Memop opnds are always #0, even for alu where dst[0]==src[0].
     * Opnds are packed: i.e., if opnd_is_null(src[i]) then always
     * opnd_is_null(src[i+1]).
     * We handle a 2nd dest that is a register by writing same result to it.
     */
    opnd_info_t src[MAX_FASTPATH_SRCS];
    opnd_info_t dst[MAX_FASTPATH_DSTS];
    int opnum[MAX_FASTPATH_SRCS];
    bool store;
    bool load;
    bool pushpop;
    bool mem2mem;
    bool load2x; /* two mem sources */

    /* filled in by adjust_opnds_for_fastpath() */
    reg_id_t src_reg;
    reg_id_t dst_reg;
    opnd_t memop;
    /* XXX: perhaps should fold sizes into opnd_info_t */
    int opsz; /* destination operand size */
    uint memsz; /* primary memory ref size */
    int src_opsz; /* source operand size */
    opnd_t memoffs; /* if memref is sub-dword, offset within containing dword */
    bool check_definedness;
    bool check_eflags_defined;

    /* filled in by instrument_fastpath() */
    bool zero_rest_of_offs; /* when calculate mi->offs, zero rest of bits in reg */
    bool pushpop_stackop;
    bool need_offs;
    bool need_nonoffs_reg3;
    bool need_slowpath;
    instr_t *slowpath;
    /* scratch registers */
    int aflags; /* plus eax for aflags */
    scratch_reg_info_t eax;
    scratch_reg_info_t reg1;
    scratch_reg_info_t reg2;
    scratch_reg_info_t reg3;
    /* cached sub-scratch-regs */
    reg_id_t reg1_8;
    reg_id_t reg2_16;
    reg_id_t reg2_8;
    reg_id_t reg2_8h;
    reg_id_t reg3_8;
    /* is this instr using shared xl8? */
    bool use_shared;
    /* for jmp-to-slowpath optimization (PR 494769) */
    instr_t *appclone;
    instr_t *slow_store_retaddr;
    instr_t *slow_jmp;
    int num_to_propagate;
} fastpath_info_t;

/* Share inter-instruction info across whole bb */
struct _bb_info_t {
    /* whole-bb spilling (PR 489221) */
    int aflags;
    int aflags_where;
    bool eax_dead;
    bool eflags_used;
    bool is_repstr_to_loop;
    scratch_reg_info_t reg1;
    scratch_reg_info_t reg2;
    /* the instr after which we should spill global regs */
    instr_t *spill_after;
    /* elide redundant addressable checks for base/index registers */
    bool addressable[NUM_LIVENESS_REGS];
    /* elide redundant eflags definedness check for cmp/test,jcc */
    bool eflags_defined;
    /* PR 493257: share shadow translation across multiple instrs */
    opnd_t shared_memop;      /* the orig memop that did a full load */
    int shared_disp_reg1;     /* disp from orig memop already in reg1 */
    int shared_disp_implicit; /* implicit disp from orig memop (push/pop) */
    /* filled in during analysis and insert phases */
    bool check_ignore_unaddr;
    /* style of instrumentation:
     * too many false alarms for app like bzip2 using 2byte-check (i#750),
     * in which case, we switch to 4byte-checks-only mode.
     */
    bool pattern_4byte_check_only;
#ifdef DEBUG
    bool pattern_4byte_check_field_set;
#endif
    bool first_instr;
    bool added_instru;
    /* for calculating size of bb */
    app_pc first_app_pc;
    app_pc last_app_pc;
    /* for repstr loop xform: fake app pcs to use for slowpath.
     * we used to keep these in note fields but w/ drmgr we can no longer
     * do that.  inserting labels is awkward b/c they get separated from their
     * app instrs.
     */
    app_pc fake_xl8; /* general for whole bb */
    instr_t *fake_xl8_override_instr; /* override fake_xl8 for this instr */
    app_pc fake_xl8_override_pc;
    /* i#826: share_xl8_max_diff changes over time, so save it. */
    uint share_xl8_max_diff;
};

/* Info per bb we need to save in order to restore app state */
typedef struct _bb_saved_info_t {
    reg_id_t scratch1;
    reg_id_t scratch2;
    /* This is used to handle non-precise flushing */
    byte ignore_next_delete;
    bool aflags_in_eax:1;
    bool eflags_saved:1;
    /* For PR 578892, to avoid DR having to store translations */
    bool check_ignore_unaddr:1;
    /* store style of instru rather than ask DR to store xl8.
     * XXX DRi#772: could add flush callback and avoid this save
     */
    bool pattern_4byte_check_only:1;
    /* we store the size and assume bbs are contiguous so we can free (i#260) */
    ushort bb_size;
    app_pc last_instr;
    /* i#826: share_xl8_max_diff changes over time, so save it. */
    uint share_xl8_max_diff;
} bb_saved_info_t;

bool
instr_ok_for_instrument_fastpath(instr_t *inst, fastpath_info_t *mi, bb_info_t *bi);

#ifdef LINUX
dr_signal_action_t
event_signal_instrument(void *drcontext, dr_siginfo_t *info);
#else
bool
event_exception_instrument(void *drcontext, dr_exception_t *excpt);
#endif

void
initialize_fastpath_info(fastpath_info_t *mi, bb_info_t *bi);

void
instrument_fastpath(void *drcontext, instrlist_t *bb, instr_t *inst,
                    fastpath_info_t *mi, bool check_ignore_unaddr);

/* Whole-bb spilling */
bool
whole_bb_spills_enabled(void);

void
mark_scratch_reg_used(void *drcontext, instrlist_t *bb,
                      bb_info_t *bi, scratch_reg_info_t *si);

void
mark_eflags_used(void *drcontext, instrlist_t *bb, bb_info_t *bi);

void
fastpath_top_of_bb(void *drcontext, void *tag, instrlist_t *bb, bb_info_t *bi);

void
fastpath_pre_instrument(void *drcontext, instrlist_t *bb, instr_t *inst, bb_info_t *bi);

void
fastpath_pre_app_instr(void *drcontext, instrlist_t *bb, instr_t *inst,
                       bb_info_t *bi, fastpath_info_t *mi);

void
fastpath_bottom_of_bb(void *drcontext, void *tag, instrlist_t *bb,
                      bb_info_t *bi, bool added_instru, bool translating,
                      bool check_ignore_unaddr);

void
slow_path_xl8_sharing(app_loc_t *loc, size_t inst_sz, opnd_t memop, dr_mcontext_t *mc);

/***************************************************************************
 * For stack.c: perhaps should move stack.c's fastpath code here and avoid
 * exporting these?
 */

void
insert_spill_or_restore(void *drcontext, instrlist_t *bb, instr_t *inst,
                        scratch_reg_info_t *si, bool spill, bool just_xchg);

bool
insert_spill_global(void *drcontext, instrlist_t *bb, instr_t *inst,
                    scratch_reg_info_t *si, bool spill);

void
pick_scratch_regs(instr_t *inst, fastpath_info_t *mi, bool only_abcd, bool need3,
                  bool reg3_must_be_ecx, opnd_t no_overlap1, opnd_t no_overlap2);

/* insert aflags save code sequence w/o spill: lahf; seto %al; */
void
insert_save_aflags_nospill(void *drcontext, instrlist_t *ilist,
                           instr_t *inst, bool save_oflag);

/* insert aflags restore code sequence w/o spill: add %al, 0x7f; sahf; */
void
insert_restore_aflags_nospill(void *drcontext, instrlist_t *ilist,
                              instr_t *inst, bool restore_oflag);

void
insert_save_aflags(void *drcontext, instrlist_t *bb, instr_t *inst,
                   scratch_reg_info_t *si, int aflags);

void
insert_restore_aflags(void *drcontext, instrlist_t *bb, instr_t *inst,
                      scratch_reg_info_t *si, int aflags);

void
restore_aflags_if_live(void *drcontext, instrlist_t *bb, instr_t *inst,
                       fastpath_info_t *mi, bb_info_t *bi);

void
add_jcc_slowpath(void *drcontext, instrlist_t *bb, instr_t *inst, uint jcc_opcode,
                 fastpath_info_t *mi);

void
add_shadow_table_lookup(void *drcontext, instrlist_t *bb, instr_t *inst,
                        fastpath_info_t *mi,
                        bool get_value, bool value_in_reg2, bool need_offs,
                        bool zero_rest_of_offs,
                        reg_id_t reg1, reg_id_t reg2, reg_id_t reg3,
                        bool jcc_short_slowpath, bool check_alignment);

/***************************************************************************
 * Utility routines
 */

bool
instr_is_spill(instr_t *inst);

bool
instr_is_restore(instr_t *inst);

#endif /* _FASTPATH_H_ */
