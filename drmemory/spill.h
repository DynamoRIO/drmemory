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
 * spill.h: Dr. Memory scratch register handling
 */

#ifndef _SPILL_H_
#define _SPILL_H_ 1

#include "fastpath.h"

#ifdef DEBUG
# ifdef X86
/* use seg_tls for actual code */
#  define EXPECTED_SEG_TLS IF_X64_ELSE(SEG_GS, SEG_FS)
# elif defined(ARM)
#  define EXPECTED_SEG_TLS dr_get_stolen_reg()
# endif /* X86 */
#endif /* DEBUG */
extern reg_id_t seg_tls;

/***************************************************************************
 * REGISTER SPILLING
 */

/* eflags eax and up-front save use this slot, and whole-bb spilling stores
 * eflags itself (lahf+seto) here
 */
#define SPILL_SLOT_EFLAGS_EAX SPILL_SLOT_3

/* We separate the TLS slots we use to send params to the slowpath from those
 * used for reg preservation, to make using drreg simpler.
 */
#define SPILL_SLOT_SLOW_PARAM SPILL_SLOT_5
#define SPILL_SLOT_SLOW_RET   SPILL_SLOT_6

int
spill_reg3_slot(bool eflags_dead, bool eax_dead, bool r1_dead, bool r2_dead);

void
spill_reg(void *drcontext, instrlist_t *ilist, instr_t *where, reg_id_t reg,
          dr_spill_slot_t slot);

void
restore_reg(void *drcontext, instrlist_t *ilist, instr_t *where, reg_id_t reg,
            dr_spill_slot_t slot);

opnd_t
spill_slot_opnd(void *drcontext, dr_spill_slot_t slot);

byte *
get_own_seg_base(void);

uint
num_own_spill_slots(void);

ptr_uint_t
get_own_tls_value(uint index);

void
set_own_tls_value(uint index, ptr_uint_t val);

ptr_uint_t
get_thread_tls_value(void *drcontext, uint index);

void
set_thread_tls_value(void *drcontext, uint index, ptr_uint_t val);

ptr_uint_t
get_raw_tls_value(uint offset);

void
instru_tls_init(void);

void
instru_tls_exit(void);

void
instru_tls_thread_init(void *drcontext);

void
instru_tls_thread_exit(void *drcontext);

/***************************************************************************
 * SCRATCH REGISTERS
 */

bool
instr_needs_eflags_restore(instr_t *inst, uint aflags_liveness);

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

uint
get_aflags_and_reg_liveness(instr_t *inst, int live[NUM_LIVENESS_REGS],
                            bool aflags_only);

void
save_aflags_if_live(void *drcontext, instrlist_t *bb, instr_t *inst,
                    fastpath_info_t *mi, bb_info_t *bi);

void
restore_aflags_if_live(void *drcontext, instrlist_t *bb, instr_t *inst,
                       fastpath_info_t *mi, bb_info_t *bi);

#endif /* _SPILL_H_ */
