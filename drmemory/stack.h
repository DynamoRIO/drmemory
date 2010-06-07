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
 * stack.c: Dr. Memory stack-adjust instrumentation
 */

#ifndef _STACK_H_
#define _STACK_H_ 1

#include "fastpath.h"

#ifdef STATISTICS
extern uint adjust_esp_executions;
extern uint adjust_esp_fastpath;
extern uint stack_swaps;
extern uint stack_swap_triggers;
extern uint push_addressable;
extern uint push_addressable_heap;
extern uint push_addressable_mmap;
#endif

/* since we dynamically adjust options.stack_swap_threshold we use a separate
 * constant for typical min stack size
 */
#define TYPICAL_STACK_MIN_SIZE (32*1024)

bool
needs_esp_adjust(instr_t *inst);

app_pc
generate_shared_esp_slowpath(void *drcontext, instrlist_t *ilist, app_pc pc);

app_pc
generate_shared_esp_fastpath(void *drcontext, instrlist_t *ilist, app_pc pc);

bool
instr_writes_esp(instr_t *inst);

/* Instrument an esp modification that is not also a read or write
 * Returns whether instrumented
 */
bool
instrument_esp_adjust(void *drcontext, instrlist_t *bb, instr_t *inst, bb_info_t *bi);

void
check_stack_size_vs_threshold(void *drcontext, size_t stack_size);

void
esp_fastpath_update_swap_threshold(void *drcontext, int new_threshold);

bool
handle_push_addressable(app_loc_t *loc, app_pc addr, app_pc start_addr,
                        size_t sz, dr_mcontext_t *mc);

#endif /* _STACK_H_ */
