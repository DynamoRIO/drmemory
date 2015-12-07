/* **********************************************************
 * Copyright (c) 2012-2016 Google, Inc.  All rights reserved.
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

#include "fastpath.h"   /* for bb_info_t */
#include "callstack.h"  /* for app_loc_t */
#include "alloc.h"      /* for malloc_info_t */

/* default pattern value if user does not specify any. */
/* NOTE: the selection of pattern value may affect performance greatly.
 * A popular value used by a program (e.g. 0, ASCII) should not be used as
 * a pattern value, as it may trigger a lot of illegal instruction exceptions
 * and expensive lookups.
 */
#define DEFAULT_PATTERN 0xf1fd

instr_t *
pattern_instrument_check(void *drcontext, instrlist_t *ilist, instr_t *app,
                         bb_info_t *bi, bool translating);

void
pattern_instrument_reverse_scan(void *drcontext, instrlist_t *ilist);

#ifdef X86
void
pattern_instrument_repstr(void *drcontext, instrlist_t *ilist,
                          bb_info_t *bi, bool translating);
#endif

bool
pattern_handle_segv_fault(void *drcontext, dr_mcontext_t *raw_mc,
                          dr_mcontext_t *mc
                          _IF_WINDOWS(app_pc target)
                          _IF_WINDOWS(bool guard));

bool
pattern_handle_ill_fault(void *drcontext, dr_mcontext_t *raw_mc,
                         dr_mcontext_t *mc);

void
pattern_init(void);

void
pattern_exit(void);

void
pattern_handle_malloc(malloc_info_t *info);

void
pattern_handle_real_free(malloc_info_t *info, bool delayed);

void
pattern_handle_delayed_free(malloc_info_t *info);

void
pattern_handle_realloc(malloc_info_t *old_info, malloc_info_t *new_info,
                       bool for_reuse);

void
pattern_new_redzone(app_pc start, size_t size);

bool
pattern_handle_mem_ref(app_loc_t *loc, app_pc addr, size_t size,
                       dr_mcontext_t *mc, bool is_write);

bool
pattern_opnd_needs_check(opnd_t opnd);

#endif /* _PATTERN_H_ */
