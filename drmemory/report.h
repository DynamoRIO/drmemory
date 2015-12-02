/* **********************************************************
 * Copyright (c) 2011-2015 Google, Inc.  All rights reserved.
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
 * report.h: Dr. Memory error reporting
 */

#ifndef _REPORT_H_
#define _REPORT_H_ 1

#include "callstack.h"

/* A prefix for supplying additional info on a reported error beyond
 * the primary line, timestamp line, and callstack itself (from PR 535568)
 */
#define INFO_PFX IF_DRSYMS_ELSE("Note: ", "  info: ")

void
report_init(void);

void
report_exit(void);

void
report_exit_if_errors(void);

#ifdef UNIX
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
report_unaddr_warning(app_loc_t *loc, dr_mcontext_t *mc, const char *msg,
                      app_pc addr, size_t sz, bool report_instruction);

void
report_unaddressable_access(app_loc_t *loc, app_pc addr, size_t sz,
                            uint access_type, /* DR_MEMPROT_ flag */
                            app_pc container_start, app_pc container_end,
                            dr_mcontext_t *mc);

void
report_undefined_read(app_loc_t *loc, app_pc addr, size_t sz,
                      app_pc container_start, app_pc container_end,
                      dr_mcontext_t *mc);

void
report_invalid_heap_arg(app_loc_t *loc, app_pc addr, dr_mcontext_t *mc,
                        const char *msg, bool is_free);

void
report_mismatched_heap(app_loc_t *loc, app_pc addr, dr_mcontext_t *mc,
                       const char *msg, packed_callstack_t *pcs);

void
report_warning(app_loc_t *loc, dr_mcontext_t *mc, const char *msg,
               app_pc addr, size_t sz, bool report_instruction);

#ifdef WINDOWS
void
report_gdi_error(app_loc_t *loc, dr_mcontext_t *mc, const char *msg,
                 packed_callstack_t *aux_pcs, const char *aux_msg);

void
report_handle_leak(void *drcontext, dr_mcontext_t *mc, const char *msg,
                   app_loc_t *loc,  packed_callstack_t *pcs,
                   packed_callstack_t *aux_pcs, bool potential);
#endif

/* saves the values of all counts that are modified in report_leak() */
void
report_leak_stats_checkpoint(void);

/* restores the values of all counts that are modified in report_leak() to their
 * values as recorded in the last report_leak_stats_checkpoint() call.
 */
void
report_leak_stats_revert(void);

void
report_leak(bool known_malloc, app_pc addr, size_t size, size_t indirect_size,
            bool early, bool reachable, bool maybe_reachable, uint shadow_state,
            packed_callstack_t *pcs, bool count_reachable, bool show_reachable);

void
report_malloc(app_pc start, app_pc end, const char *routine, dr_mcontext_t *mc);

void
report_heap_region(bool add, app_pc start, app_pc end, dr_mcontext_t *mc);

#if DEBUG
void
report_callstack(void *drcontext, dr_mcontext_t *mc);
#endif /* DEBUG */

void
print_timestamp_elapsed(char *buf, size_t bufsz, size_t *sofar);

void
print_timestamp_elapsed_to_file(file_t f, const char *prefix);

void
report_child_thread(void *drcontext, thread_id_t child);

bool
module_is_on_check_uninit_blacklist(app_pc pc);

#endif /* _REPORT_H_ */
