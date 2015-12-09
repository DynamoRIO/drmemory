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
 * fastpath_arm.c: Dr. Memory shadow instrumentation fastpath for ARM
 */

#include "dr_api.h"
#include "drmemory.h"
#include "slowpath.h"
#include "spill.h"
#include "fastpath.h"
#include "shadow.h"
#include "stack.h"
#ifdef TOOL_DR_MEMORY
# include "alloc_drmem.h"
# include "report.h"
#endif
#include "pattern.h"

#ifdef UNIX
# include <signal.h> /* for SIGSEGV */
#else
# include <stddef.h> /* for offsetof */
#endif

bool
instr_ok_for_instrument_fastpath(instr_t *inst, fastpath_info_t *mi, bb_info_t *bi)
{
    ASSERT_NOT_IMPLEMENTED(); /* FIXME i#1726: NYI */
    /* Probably a lot of code can be shared with fastpath_x86.c: it
     * needs further refactoring.
     */
    return false;
}

void
instrument_fastpath(void *drcontext, instrlist_t *bb, instr_t *inst,
                    fastpath_info_t *mi, bool check_ignore_unaddr)
{
    ASSERT_NOT_IMPLEMENTED(); /* FIXME i#1726: NYI */
    /* Probably a lot of code can be shared with fastpath_x86.c: it
     * needs further refactoring.
     */
}

#ifdef UNIX
dr_signal_action_t
event_signal_instrument(void *drcontext, dr_siginfo_t *info)
{
    ASSERT_NOT_IMPLEMENTED(); /* FIXME i#1726: NYI */
    /* Probably a lot of code can be shared with fastpath_x86.c: it
     * needs further refactoring.
     */
    return DR_SIGNAL_DELIVER;
}
#endif
