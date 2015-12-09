/* **********************************************************
 * Copyright (c) 2015 Google, Inc.  All rights reserved.
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
 * ARM-specific stack adjustment code
 */

#include "dr_api.h"
#include "drmemory.h"
#include "slowpath.h"
#include "spill.h"
#include "fastpath.h"
#include "stack.h"
#include "stack_arch.h"
#include "shadow.h"
#include "heap.h"
#include "alloc.h"
#include "alloc_drmem.h"

/***************************************************************************/

/* i#1500: we need to handle this as an esp adjustment */
bool
instr_pop_into_esp(instr_t *inst)
{
    ASSERT_NOT_IMPLEMENTED(); /* FIXME i#1726: NYI */
    return false;
}

esp_adjust_t
get_esp_adjust_type(instr_t *inst, bool mangled)
{
    ASSERT_NOT_IMPLEMENTED(); /* FIXME i#1726: NYI */
    return ESP_ADJUST_INVALID;
}

/* assumes that inst does write to esp */
bool
needs_esp_adjust(instr_t *inst, sp_adjust_action_t sp_action)
{
    ASSERT_NOT_IMPLEMENTED(); /* FIXME i#1726: NYI */
    return false;
}

/* Instrument an esp modification that is not also a read or write.
 * Returns whether instrumented.
 */
bool
instrument_esp_adjust_slowpath(void *drcontext, instrlist_t *bb, instr_t *inst,
                               bb_info_t *bi, sp_adjust_action_t sp_action)
{
    ASSERT_NOT_IMPLEMENTED(); /* FIXME i#1726: NYI */
    /* Probably a lot of code can be shared with stack_x86.c: it
     * needs further refactoring.
     */
    return false;
}

/* Handle a fault while zeroing the app stack (PR 570843) */
bool
handle_zeroing_fault(void *drcontext, byte *target, dr_mcontext_t *raw_mc,
                     dr_mcontext_t *mc)
{
    ASSERT_NOT_IMPLEMENTED(); /* FIXME i#1726: NYI */
    /* Probably a lot of code can be shared with stack_x86.c: it
     * needs further refactoring.
     */
    return false;
}

/* Instrument an esp modification that is not also a read or write
 * Returns whether instrumented
 */
bool
instrument_esp_adjust_fastpath(void *drcontext, instrlist_t *bb, instr_t *inst,
                               bb_info_t *bi, sp_adjust_action_t sp_action)
{
    ASSERT_NOT_IMPLEMENTED(); /* FIXME i#1726: NYI */
    /* Probably a lot of code can be shared with stack_x86.c: it
     * needs further refactoring.
     */
    return false;
}

/* Note that handle_special_shadow_fault() makes assumptions about the exact
 * instr sequence here so it can find the slowpath entry point
 */
void
generate_shared_esp_fastpath_helper(void *drcontext, instrlist_t *bb,
                                    bool eflags_live,
                                    sp_adjust_action_t sp_action,
                                    esp_adjust_t type)
{
    ASSERT_NOT_IMPLEMENTED(); /* FIXME i#1726: NYI */
    /* Probably a lot of code can be shared with stack_x86.c: it
     * needs further refactoring.
     */
}

/* Caller has made the memory writable and holds a lock */
void
esp_fastpath_update_swap_threshold(void *drcontext, int new_threshold)
{
    ASSERT_NOT_IMPLEMENTED(); /* FIXME i#1726: NYI */
    /* Probably a lot of code can be shared with stack_x86.c: it
     * needs further refactoring.
     */
}
