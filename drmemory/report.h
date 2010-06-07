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
 * report.h: Dr. Memory error reporting
 */

#ifndef _REPORT_H_
#define _REPORT_H_ 1

#include "callstack.h"

void
report_init(void);

void
report_exit(void);

#ifdef LINUX
void
report_fork_init(void);
#endif

void
report_summary(void);

void
report_thread_init(void *drcontext);

void
report_thread_exit(void *drcontext);

void
report_unaddressable_access(app_loc_t *loc, app_pc addr, size_t sz, bool write,
                            app_pc container_start, app_pc container_end,
                            dr_mcontext_t *mc);

void
report_undefined_read(app_loc_t *loc, app_pc addr, size_t sz,
                      app_pc container_start, app_pc container_end,
                      dr_mcontext_t *mc);

void
report_invalid_free(app_loc_t *loc, app_pc addr, dr_mcontext_t *mc);

void
report_warning(app_loc_t *loc, dr_mcontext_t *mc, const char *msg);

/* saves the values of all counts that are modified in report_leak() */
void
report_leak_stats_checkpoint(void);

/* restores the values of all counts that are modified in report_leak() to their
 * values as recorded in the last report_leak_stats_checkpoint() call.
 */
void
report_leak_stats_revert(void);

void
report_leak(bool known_malloc, app_pc addr, size_t size, bool early,
            bool reachable, bool maybe_reachable, uint shadow_state,
            packed_callstack_t *pcs);

void
report_malloc(app_pc start, app_pc end, const char *routine, dr_mcontext_t *mc);

void
report_heap_region(bool add, app_pc start, app_pc end, dr_mcontext_t *mc);

#if DEBUG
void
report_callstack(void *drcontext, dr_mcontext_t *mc);
#endif /* DEBUG */

#endif /* _REPORT_H_ */
