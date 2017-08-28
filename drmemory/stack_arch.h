/* **********************************************************
 * Copyright (c) 2011-2017 Google, Inc.  All rights reserved.
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
 * stack_arch.h: stack-adjust internal defines shared with arch-specific code
 */

#ifndef _STACK_ARCH_H_
#define _STACK_ARCH_H_ 1

/* Handle an instruction at pc that writes to esp */
typedef enum {
    ESP_ADJUST_ABSOLUTE,
    ESP_ADJUST_FAST_FIRST = ESP_ADJUST_ABSOLUTE,
    ESP_ADJUST_ABSOLUTE_POSTPOP, /* OP_leave where the pop was already done */
    ESP_ADJUST_NEGATIVE,
    ESP_ADJUST_POSITIVE,
    ESP_ADJUST_RET_IMMED, /* positive, but after a pop */
    ESP_ADJUST_AND, /* and with a mask */
    ESP_ADJUST_FAST_LAST = ESP_ADJUST_AND, /* we only support and w/ immed in fastpath */
    ESP_ADJUST_INVALID,
} esp_adjust_t;

extern byte *shared_esp_slowpath_shadow;
extern byte *shared_esp_slowpath_defined;
extern byte *shared_esp_slowpath_zero;
extern byte *
shared_esp_fastpath[SP_ADJUST_ACTION_FASTPATH_MAX+1][2][ESP_ADJUST_FAST_LAST+1];

#ifdef X86
# define ESP_SLOW_SCRATCH1 DR_REG_XCX
# define ESP_SLOW_SCRATCH2 DR_REG_XDX
#else
# define ESP_SLOW_SCRATCH1 DR_REG_R0
# define ESP_SLOW_SCRATCH2 DR_REG_R1
#endif

bool
instr_pop_into_esp(instr_t *inst);

esp_adjust_t
get_esp_adjust_type(instr_t *inst, bool mangled);

int
esp_spill_slot_base(sp_adjust_action_t sp_action);

bool
needs_esp_adjust(instr_t *inst, sp_adjust_action_t sp_action);

void
handle_esp_adjust_shared_slowpath(reg_t val/*either relative delta, or absolute*/,
                                  sp_adjust_action_t sp_action);

void
handle_esp_adjust(esp_adjust_t type, reg_t val/*either relative delta, or absolute*/,
                  sp_adjust_action_t sp_action);

bool
instrument_esp_adjust_slowpath(void *drcontext, instrlist_t *bb, instr_t *inst,
                               bb_info_t *bi, sp_adjust_action_t sp_action);

bool
instrument_esp_adjust_fastpath(void *drcontext, instrlist_t *bb, instr_t *inst,
                               bb_info_t *bi, sp_adjust_action_t sp_action);

void
generate_shared_esp_fastpath_helper(void *drcontext, instrlist_t *bb,
                                    bool eflags_live,
                                    sp_adjust_action_t sp_action,
                                    esp_adjust_t type);

#endif /* _STACK_ARCH_H_ */
