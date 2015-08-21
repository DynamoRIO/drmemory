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
 * instru.h: Dr. Memory top-level instrumentation control routines
 */

#ifndef _INSTRU_H_
#define _INSTRU_H_ 1

#include "fastpath.h" /* bb_saved_info_t */

extern hashtable_t stringop_us2app_table;
extern void *stringop_lock;
extern bool first_bb; /* has the 1st bb been executed yet? */

void
instrument_init(void);

void
instrument_exit(void);

void
instrument_thread_init(void *drcontext);

void
instrument_thread_exit(void *drcontext);

size_t
instrument_persist_ro_size(void *drcontext, void *perscxt);

bool
instrument_persist_ro(void *drcontext, void *perscxt, file_t fd);

bool
instrument_resurrect_ro(void *drcontext, void *perscxt, byte **map INOUT);

void
bb_save_add_entry(app_pc key, bb_saved_info_t *save);

void
instru_insert_mov_pc(void *drcontext, instrlist_t *bb, instr_t *inst,
                     opnd_t dst, opnd_t pc_opnd);

#endif /* _INSTRU_H_ */
