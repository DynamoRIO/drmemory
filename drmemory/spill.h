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

/* We separate the TLS slots we use to send params to the slowpath from those
 * used for reg preservation, to make using drreg simpler.
 * These are slots within our own TLS.
 */
#define SPILL_SLOT_SLOW_PARAM SPILL_SLOT_1
#define SPILL_SLOT_SLOW_RET   SPILL_SLOT_2

opnd_t
spill_slot_opnd(void *drcontext, dr_spill_slot_t slot);

byte *
get_own_seg_base(void);

/***************************************************************************
 * These are all for our own slots as distinct from drreg.
 */

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

//NOCHECKIN only used for drreg -- should drreg provide these
bool
instr_is_spill(instr_t *inst);

bool
instr_is_restore(instr_t *inst);

bool
instr_at_pc_is_restore(void *drcontext, byte *pc);

/***************************************************************************
 * drreg wrappers that assert on failure and update fastpath_info_t.
 */

void
reserve_aflags(void *drcontext, instrlist_t *ilist, instr_t *where);

void
unreserve_aflags(void *drcontext, instrlist_t *ilist, instr_t *where);

void
reserve_register(void *drcontext, instrlist_t *ilist, instr_t *where,
                 drvector_t *reg_allowed, OUT reg_id_t *reg, INOUT fastpath_info_t *mi);

void
unreserve_register(void *drcontext, instrlist_t *ilist, instr_t *where, reg_id_t reg,
                   INOUT fastpath_info_t *mi);

/* For translation sharing we reserve the same register across the whole bb. */
void
reserve_shared_register(void *drcontext, instrlist_t *ilist, instr_t *where,
                        drvector_t *reg_allowed, INOUT fastpath_info_t *mi);

void
unreserve_shared_register(void *drcontext, instrlist_t *ilist, instr_t *where,
                          INOUT fastpath_info_t *mi);

#endif /* _SPILL_H_ */
