/* **********************************************************
 * Copyright (c) 2008-2009 VMware, Inc.  All rights reserved.
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
 * alloc_drmem.h: Dr. Memory heap tracking specific to Dr. Memory
 */

#ifndef _ALLOC_DRMEM_H_
#define _ALLOC_DRMEM_H_ 1

#ifdef LINUX
extern hashtable_t sighand_table;
#endif

void
alloc_drmem_init(void);

void
alloc_drmem_exit(void);

bool
check_unaddressable_exceptions(bool write, app_loc_t *loc, app_pc addr, uint sz);

#ifdef LINUX
dr_signal_action_t
event_signal_alloc(void *drcontext, dr_siginfo_t *info);

void
instrument_signal_handler(void *drcontext, instrlist_t *bb, instr_t *inst,
                          app_pc pc);

bool
mmap_anon_lookup(byte *addr, byte **start OUT, size_t *size OUT);
#endif

void
handle_new_heap_region(app_pc start, app_pc end, dr_mcontext_t *mc);

void
handle_removed_heap_region(app_pc start, app_pc end, dr_mcontext_t *mc);

void
check_reachability(bool at_exit);

bool
overlaps_delayed_free(byte *start, byte *end, byte **free_start, byte **free_end);

#endif /* _ALLOC_DRMEM_H_ */
