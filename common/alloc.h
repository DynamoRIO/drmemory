/* **********************************************************
 * Copyright (c) 2010-2012 Google, Inc.  All rights reserved.
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
 * alloc.h: Dr. Memory heap tracking
 */

#ifndef _ALLOC_H_
#define _ALLOC_H_ 1

#include "drmgr.h"
#include "utils.h"
#include "callstack.h"

/* priority of the analysis + insert routines */
#define DRMGR_PRIORITY_INSERT_ALLOC 130

/* All mallocs we've seen align to 8.  If this is changed, update malloc_hash(). */
#define MALLOC_CHUNK_ALIGNMENT 8

typedef struct _alloc_options_t {
    bool track_allocs;
    bool track_heap;
    size_t redzone_size;
    bool size_in_redzone;
    bool record_allocs;
    /* Should we try to figure out the padded size of allocs?
     * It's not easy on Windows.
     */
    bool get_padded_size;
    /* Replace realloc with equivalent malloc+memcpy+free? */
    bool replace_realloc;
#ifdef WINDOWS
    /* Disable debug CRT checks */
    bool disable_crtdbg;
#endif
    /* prefer _msize to malloc_usable_size.
     * really something of a hack for chromium: i#314, i#320
     */
    bool prefer_msize;
    /* use symcache to cache post-call addresses (i#669) */
    bool cache_postcall;
    /* whether to intercept operator new* and operator delete* */
    bool intercept_operators;
    /* whether to be conservative about reading app stack or whether
     * to worry about racy module unloads
     */
    bool conservative;

    /* replace instead of wrap existing? */
    bool replace_malloc;
    /* only used with -replace_malloc: */
    bool external_headers; /* headers in hashtable instead of inside redzone */
    uint delay_frees;
    uint delay_frees_maxsz;

    /* Add new options here */
} alloc_options_t;

/* Flags stored with each malloc entry */
enum {
    MALLOC_RESERVED_1 = 0x0001,
    MALLOC_RESERVED_2 = 0x0002,
    MALLOC_RESERVED_3 = 0x0004,
    MALLOC_RESERVED_4 = 0x0008,
    MALLOC_CLIENT_1 =   0x0010,
    MALLOC_CLIENT_2 =   0x0020,
    MALLOC_CLIENT_3 =   0x0040,
    MALLOC_CLIENT_4 =   0x0080,
    MALLOC_RESERVED_5 = 0x0100,
    MALLOC_RESERVED_6 = 0x0200,
    MALLOC_RESERVED_7 = 0x0400,
    MALLOC_RESERVED_8 = 0x0800,
    MALLOC_POSSIBLE_CLIENT_FLAGS = (MALLOC_CLIENT_1 | MALLOC_CLIENT_2 |
                                    MALLOC_CLIENT_3 | MALLOC_CLIENT_4),
};

typedef bool (*malloc_iter_cb_t)(app_pc start, app_pc end, app_pc real_end,
                                 bool pre_us, uint client_flags,
                                 void *client_data, void *iter_data);

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

#ifdef STATISTICS
extern uint wrap_pre;
extern uint wrap_post;
extern uint num_mallocs;
extern uint num_large_mallocs;
extern uint num_frees;
#endif

/* caller should call drmgr_init() and drwrap_init() */
void
alloc_init(alloc_options_t *ops, size_t ops_size);

/* caller should call drmgr_exit() and drwrap_exit() */
void
alloc_exit(void);

void
alloc_module_load(void *drcontext, const module_data_t *info, bool loaded);

void
alloc_module_unload(void *drcontext, const module_data_t *info);

void
alloc_fragment_delete(void *drcontext, void *tag);

bool
alloc_entering_alloc_routine(app_pc pc);

bool
alloc_exiting_alloc_routine(app_pc pc);

bool
alloc_syscall_filter(void *drcontext, int sysnum);

void
handle_pre_alloc_syscall(void *drcontext, int sysnum, dr_mcontext_t *mc,
                         reg_t sysarg[], uint arg_cap);

void
handle_post_alloc_syscall(void *drcontext, int sysnum, dr_mcontext_t *mc,
                          reg_t sysarg[], uint arg_cap);

void
malloc_add(app_pc start, app_pc end, app_pc real_end,
           bool pre_us, uint client_flags, dr_mcontext_t *mc, app_pc post_call);

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

/* Returns -1 on failure.  Only looks at invalid malloc regions. */
ssize_t
malloc_size_invalid_only(app_pc start);

void *
malloc_get_client_data(app_pc start);

uint
malloc_get_client_flags(app_pc start);

bool
malloc_set_client_flag(app_pc start, uint client_flag);

bool
malloc_clear_client_flag(app_pc start, uint client_flag);

/* Iterate malloc entries and call callback function cb on each entry.
 * The bool returned by cb indicates if the iteration should continue.
 */
void
malloc_iterate(malloc_iter_cb_t cb, void *iter_data);

typedef size_t (*alloc_size_func_t)(void *);

#ifdef LINUX
byte *
get_brk(bool pre_us);

byte *
set_brk(byte *new_val);

/* this is libc's version */
extern alloc_size_func_t malloc_usable_size;
#endif

void
malloc_lock(void);

void
malloc_unlock(void);

#ifdef WINDOWS
bool
alloc_in_create(void *drcontext);
#endif

bool
alloc_in_heap_routine(void *drcontext);

/***************************************************************************
 * ALLOC REPLACEMENT
 */

bool
alloc_entering_replace_routine(app_pc pc);

bool
alloc_replace_in_cur_arena(byte *addr);

/***************************************************************************
 * CLIENT CALLBACKS
 */

/* called for each live malloc chunk at process exit */
void                                                             
client_exit_iter_chunk(app_pc start, app_pc end, bool pre_us, uint client_flags,
                       void *client_data);

/* called when malloc chunk data is being free so user data can also be freed */
void
client_malloc_data_free(void *data);

/* called when a malloc is being moved to a free list.  the stored user
 * data is replaced with the return value.
 * only called when replacing rather than wrapping malloc.
 */
void *
client_malloc_data_to_free_list(void *cur_data, dr_mcontext_t *mc, app_pc post_call);

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

/* real_size is the actual size of memory allocated by allocator.
 * If alloc_options.get_padded_size, the padded_size is passed in;
 * otherwise, an inaccurate real_size is passed in, 
 * possibly (app_size + redzone_size*2).
 */
void
client_handle_malloc(void *drcontext, app_pc base, size_t size,
                     app_pc real_base, size_t real_size, 
                     bool zeroed, bool realloc, dr_mcontext_t *mc);

void
client_handle_realloc(void *drcontext, app_pc old_base, size_t old_size,
                      app_pc new_base, size_t new_size, app_pc new_real_base,
                      dr_mcontext_t *mc);

void
client_handle_alloc_failure(size_t sz, bool zeroed, bool realloc,
                            app_pc pc, dr_mcontext_t *mc);

void
client_handle_realloc_null(app_pc pc, dr_mcontext_t *mc);

/* Returns the value to pass to free().  Return "real_base" for no change.
 * The Windows heap param is INOUT so it can be changed as well.
 * client_data is from client_add_malloc_routine().
 */
app_pc
client_handle_free(app_pc base, size_t size, app_pc real_base, size_t real_size,
                   dr_mcontext_t *mc, app_pc free_routine,
                   void *client_data _IF_WINDOWS(ptr_int_t *auxarg INOUT));

void
client_invalid_heap_arg(app_pc pc, app_pc target, dr_mcontext_t *mc, const char *routine,
                        bool is_free);

void
client_mismatched_heap(app_pc pc, app_pc target, dr_mcontext_t *mc,
                       const char *alloc_routine, const char *free_routine,
                       void *client_data);

void
client_handle_mmap(void *drcontext, app_pc base, size_t size, bool anon);

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
client_handle_heap_destroy(void *drcontext, HANDLE heap, void *client_data);

void
client_remove_malloc_on_destroy(HANDLE heap, byte *start, byte *end);

void
client_handle_cbret(void *drcontext);

void
client_handle_callback(void *drcontext);

void
client_handle_Ki(void *drcontext, app_pc pc, dr_mcontext_t *mc);

void
client_handle_exception(void *drcontext, dr_mcontext_t *mc);

void
client_handle_continue(void *drcontext, dr_mcontext_t *mc);

bool
is_in_seh(void *drcontext);

bool
is_in_seh_unwind(void *drcontext, dr_mcontext_t *mc);
#endif

void
client_pre_syscall(void *drcontext, int sysnum, reg_t sysarg[]);

void
client_post_syscall(void *drcontext, int sysnum, reg_t sysarg[]);

void
client_entering_heap_routine(void);

void
client_exiting_heap_routine(void);

/* The return value is stored as client data and passed in client_handle_free(). */
void *
client_add_malloc_routine(app_pc pc);

void
client_remove_malloc_routine(void *client_data);

#endif /* _ALLOC_H_ */
