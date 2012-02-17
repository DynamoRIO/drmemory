/* **********************************************************
 * Copyright (c) 2012 Google, Inc.  All rights reserved.
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

#ifndef _PATTERN_H_
#define _PATTERN_H_ 1

void
pattern_init(void);

void
pattern_instrument_check(void *drcontext, instrlist_t *ilist, instr_t *app);

void
pattern_instrument_reverse_scan(void *drcontext, instrlist_t *ilist);

bool
pattern_handle_segv_fault(void *drcontext, dr_mcontext_t *raw_mc);

bool
pattern_handle_ill_fault(void *drcontext, dr_mcontext_t *raw_mc, 
                         dr_mcontext_t *mc);

void
pattern_init(void);

void
pattern_exit(void);

void
pattern_handle_malloc(app_pc app_base,  size_t app_size,
                      app_pc real_base, size_t real_size);

void
pattern_handle_real_free(app_pc base,  size_t size, bool delayed);

void
pattern_handle_delayed_free(app_pc base, size_t size);

void
pattern_handle_realloc(app_pc old_base, size_t old_size,
                       app_pc new_base, size_t new_size, app_pc new_real_base);

bool
pattern_addr_in_redzone(byte *addr);

#endif /* _PATTERN_H_ */
