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
 * alloc.h: Dr. Memory heap tracking
 */

#ifndef _ALLOC_H_
#define _ALLOC_H_ 1

#include "per_thread.h"
#include "utils.h"
#include "callstack.h"

/* All mallocs we've seen align to 8 */
#define MALLOC_CHUNK_ALIGNMENT 8

/* Flags stored with each malloc entry */
enum {
    MALLOC_RESERVED_1 = 0x01,
    MALLOC_RESERVED_2 = 0x02,
    MALLOC_RESERVED_3 = 0x04,
    MALLOC_RESERVED_4 = 0x08,
    MALLOC_CLIENT_1 =   0x10,
    MALLOC_CLIENT_2 =   0x20,
    MALLOC_CLIENT_3 =   0x40,
    MALLOC_CLIENT_4 =   0x80,
};

/* system/lib calls we want to intercept */
#ifdef WINDOWS
extern int sysnum_mmap;
extern int sysnum_munmap;
extern int sysnum_valloc;
extern int sysnum_vfree;
extern int sysnum_cbret;
extern int sysnum_continue;
extern int sysnum_setcontext;
#endif
extern app_pc addr_KiAPC;
extern app_pc addr_KiCallback;
extern app_pc addr_KiException;
extern app_pc addr_KiRaise;

#ifdef STATISTICS
extern uint post_call_flushes;
extern uint num_mallocs;
extern uint num_large_mallocs;
extern uint num_frees;
#endif

void
alloc_init(bool track_heap, size_t redzone_size, bool size_in_redzone,
           bool record_allocs, bool get_padded_size);

void
alloc_exit(void);

void
alloc_instrument(void *drcontext, instrlist_t *bb, instr_t *inst,
                 bool *entering_alloc, bool *exiting_alloc);

bool
alloc_syscall_filter(void *drcontext, int sysnum);

void
handle_pre_alloc_syscall(void *drcontext, int sysnum, dr_mcontext_t *mc,
                         per_thread_t *pt);

void
handle_post_alloc_syscall(void *drcontext, int sysnum, dr_mcontext_t *mc,
                          per_thread_t *pt);

void
malloc_add(app_pc start, app_pc end, app_pc real_end,
           bool pre_us, uint client_flags, dr_mcontext_t *mc, app_pc post_call);

void
malloc_remove(app_pc start);

void
malloc_set_valid(app_pc start, bool valid);

/* Looks up mallocs in the "large malloc table" (for mallocs used as stacks) */
bool
malloc_large_lookup(byte *addr, byte **start OUT, size_t *size OUT);

bool
malloc_is_pre_us_ex(app_pc start, bool ok_if_invalid);

bool
malloc_is_pre_us(app_pc start);

app_pc
malloc_end(app_pc start);

/* Returns -1 on failure */
ssize_t
malloc_size(app_pc start);

/* Returns -1 on failure.  Will return invalid malloc regions. */
ssize_t
malloc_size_include_invalid(app_pc start);

void *
malloc_get_client_data(app_pc start);

uint
malloc_get_client_flags(app_pc start);

bool
malloc_set_client_flag(app_pc start, uint client_flag);

bool
malloc_clear_client_flag(app_pc start, uint client_flag);

void
malloc_iterate(void (*cb)(app_pc start, app_pc end, app_pc real_end,
                          bool pre_us, uint client_flags,
                          void *client_data, void *iter_data), void *iter_data);

/* Returns the actual allocated size.  This can be either the
 * requested size that Dr. Memory passed to the system allocator
 * (including any redzones added) or that requested size padded to
 * some alignment.  For the exact padded size, use padded_size_out.
 * Returns -1 on error.
 */
size_t
get_alloc_real_size(IF_WINDOWS_(app_pc heap) app_pc real_base, size_t app_size,
                    size_t *padded_size_out);

#ifdef LINUX
app_pc
get_brk(void);

size_t
(*malloc_usable_size)(void *p);
#endif

void
malloc_lock(void);

void
malloc_unlock(void);

/***************************************************************************
 * CLIENT CALLBACKS
 */

void                                                             
client_exit_iter_chunk(app_pc start, app_pc end, bool pre_us, uint client_flags,
                       void *client_data);

void
client_malloc_data_free(void *data);

/* A lock is held around the call to this routine.
 * The return value is stored as the client data.
 * In some cases this routine is re-called for an entry that has
 * already had its data set: in such cases, existing_data is set.
 * For all new entries, mc and post_call will be non-NULL, unless
 * during init time (i.e., pre-existing allocations).
 * The alloc entry is NOT in the alloc hashtable yet and will NOT show
 * up in hashtable iteration: use client_add_malloc_post for
 * a proper hashtable view.
 */
void *
client_add_malloc_pre(app_pc start, app_pc end, app_pc real_end,
                      void *existing_data, dr_mcontext_t *mc, app_pc post_call);

/* Called after the new alloc entry has been added to the alloc hashtable. */
void
client_add_malloc_post(app_pc start, app_pc end, app_pc real_end, void *data);

/* A lock is held around the call to this routine.
 * The alloc entry has NOT been removed from the alloc hashtable yet and
 * WILL show up in hashtable iteration: use client_remove_malloc_post for
 * a proper hashtable view.
 */
void
client_remove_malloc_pre(app_pc start, app_pc end, app_pc real_end, void *data);

/* Called after the alloc entry has been removed from the alloc hashtable.
 * The client data has been freed and so is not available.
 */
void
client_remove_malloc_post(app_pc start, app_pc end, app_pc real_end);

void
client_handle_malloc(per_thread_t *pt, app_pc base, size_t size,
                     app_pc real_base, bool zeroed, bool realloc, dr_mcontext_t *mc);

void
client_handle_realloc(per_thread_t *pt, app_pc old_base, size_t old_size,
                      app_pc new_base, size_t new_size, app_pc new_real_base,
                      dr_mcontext_t *mc);

void
client_handle_alloc_failure(size_t sz, bool zeroed, bool realloc,
                            app_pc pc, dr_mcontext_t *mc);

void
client_handle_realloc_null(app_pc pc, dr_mcontext_t *mc);

/* Returns the value to pass to free().  Return "real_base" for no change.
 * The Windows heap param is INOUT so it can be changed as well.
 */
app_pc
client_handle_free(app_pc base, size_t size, app_pc real_base, dr_mcontext_t *mc
                   _IF_WINDOWS(app_pc *heap INOUT));

void
client_invalid_heap_arg(app_pc pc, app_pc target, dr_mcontext_t *mc, const char *routine);

void
client_handle_mmap(per_thread_t *pt, app_pc base, size_t size, bool anon);

void
client_handle_munmap(app_pc base, size_t size, bool anon);

void
client_handle_munmap_fail(app_pc base, size_t size, bool anon);

#ifdef LINUX
void
client_handle_mremap(app_pc old_base, size_t old_size, app_pc new_base, size_t new_size,
                     bool image);
#endif

#ifdef WINDOWS
void
client_handle_heap_destroy(void *drcontext, per_thread_t *pt, HANDLE heap);

void
client_remove_malloc_on_destroy(HANDLE heap, byte *start, byte *end);

void
client_handle_cbret(void *drcontext, per_thread_t *pt_parent, per_thread_t *pt_child);

void
client_handle_callback(void *drcontext, per_thread_t *pt_parent, per_thread_t *pt_child,
                       bool new_depth);
#endif

void
client_pre_syscall(void *drcontext, int sysnum, per_thread_t *pt);

void
client_post_syscall(void *drcontext, int sysnum, per_thread_t *pt);

void
client_entering_heap_routine(void);

void
client_exiting_heap_routine(void);

#endif /* _ALLOC_H_ */
