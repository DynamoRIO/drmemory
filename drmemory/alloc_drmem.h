/* **********************************************************
 * Copyright (c) 2013-2020 Google, Inc.  All rights reserved.
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

#include "callstack.h" /* app_loc_t */

void
alloc_drmem_init(void);

void
alloc_drmem_exit(void);

bool
check_unaddressable_exceptions(bool write, app_loc_t *loc, app_pc addr, uint sz,
                               bool addr_on_stack, dr_mcontext_t *mc);

void
event_kernel_xfer(void *drcontext, const dr_kernel_xfer_info_t *info);

#ifdef UNIX
dr_signal_action_t
event_signal_alloc(void *drcontext, dr_siginfo_t *info);

bool
mmap_anon_lookup(byte *addr, byte **start OUT, size_t *size OUT);
#endif

void
handle_new_heap_region(app_pc start, app_pc end, dr_mcontext_t *mc);

void
handle_removed_heap_region(app_pc start, app_pc end, dr_mcontext_t *mc);

void
check_reachability(bool at_exit);

/* Returns true if the overlap is in any portion of freed memory,
 * including padding and redzones.  The returned bounds can be used to
 * rule out padding and redzones if desired.
 * For -no_replace_malloc, the returned pcs is a clone and must be
 * freed with packed_callstack_free().
 */
bool
overlaps_delayed_free(byte *start, byte *end,
                      byte **free_start OUT, /* app base */
                      byte **free_end OUT,   /* app request size */
                      packed_callstack_t **pcs OUT,
                      bool delayed_only);

bool
is_alloca_pattern(void *drcontext, app_pc pc, app_pc next_pc, instr_t *inst,
                  bool *now_addressable OUT);

/* check if region [addr, addr + size) overlaps with any malloc redzone,
 * - if overlaps, return true and fill all the passed in parameters,
 * - otherwise, return false and NO parameters is filled.
 */
bool
region_in_redzone(byte *addr, size_t size,
                  packed_callstack_t **alloc_pcs OUT,
                  app_pc *app_start OUT,
                  app_pc *app_end OUT,
                  app_pc *redzone_start OUT,
                  app_pc *redzone_end OUT);

/* Synchronizes access to malloc callstacks (malloc_get_client_data()) */
void
alloc_callstack_lock(void);

void
alloc_callstack_unlock(void);

#endif /* _ALLOC_DRMEM_H_ */
