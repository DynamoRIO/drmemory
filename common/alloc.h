/* **********************************************************
 * Copyright (c) 2010-2017 Google, Inc.  All rights reserved.
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
#define DRMGR_PRIORITY_INSERT_ALLOC  2020

/* All mallocs we've seen align to 8.  If this is changed, update malloc_hash(). */
#define MALLOC_CHUNK_ALIGNMENT 8
#ifdef WINDOWS
/* i#892: the pad size read from malloc chunk header includes the size of header */
# define MALLOC_HEADER_SIZE     8
#endif /* WINDOWS */

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
    bool shared_redzones;
    uint delay_frees;
    uint delay_frees_maxsz;

    bool skip_msvc_importers;

    /* Whether to synchronize all allocations and frees with a single
     * global lock.  This enables use of malloc_lock().  With this set
     * to false, malloc iteration or overlap checking that looks for
     * freed chunks and then separately looks for live chunks can be
     * racy and miss a chunk moved from live to free in between.  If
     * this matters, the user should set this to true and use
     * malloc_lock() across multiple iterations.
     */
    bool global_lock;

    /* Whether to query and update drsymcache for all symbol lookups */
    bool use_symcache;

    /* i#1565: we keep nosy allocs (where Rtl code delves into heap headers
     * and xors in cookies and derefs the result, crashing if we use our headers
     * or have a redzone there) native by default.  Turning this option on
     * disables that, and will lead to crashes on x64.
     */
    bool replace_nosy_allocs;

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
    MALLOC_RESERVED_9 = 0x1000,
    MALLOC_POSSIBLE_CLIENT_FLAGS = (MALLOC_CLIENT_1 | MALLOC_CLIENT_2 |
                                    MALLOC_CLIENT_3 | MALLOC_CLIENT_4),
};

/* Info on a malloc chunk used for malloc iteration and client notification */
typedef struct {
    size_t struct_size; /* only used when alloc by client: overlap routines */
    byte *base;
    size_t request_size;
    size_t pad_size;    /* request_size plus padding */
    bool pre_us;
    bool has_redzone;
    bool zeroed;        /* only applies to malloc and realloc */
    bool realloc;       /* only applies to malloc */
    uint client_flags;  /* does not apply to malloc/realloc where not set yet */
    void *client_data;  /* does not apply to malloc/realloc where not set yet */
} malloc_info_t;

typedef bool (*malloc_iter_cb_t)(malloc_info_t *info, void *iter_data);

#ifdef WINDOWS
/* system/lib calls we want to intercept that are shared w/ other modules */
extern int sysnum_continue;
extern int sysnum_setcontext;
extern int sysnum_RaiseException;
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

bool
handle_pre_alloc_syscall(void *drcontext, int sysnum, dr_mcontext_t *mc);

void
handle_post_alloc_syscall(void *drcontext, int sysnum, dr_mcontext_t *mc);

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
malloc_chunk_size(app_pc start);

/* Returns -1 on failure.  Only looks at invalid malloc regions. */
ssize_t
malloc_chunk_size_invalid_only(app_pc start);

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

#ifdef UNIX
byte *
get_brk(bool pre_us);

byte *
set_brk(byte *new_val);

/* this is libc's version */
extern alloc_size_func_t libc_malloc_usable_size;
#endif

/* This can only be called if alloc_ops.global_lock was set */
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

bool
is_in_realloc_gencode(app_pc pc);

/***************************************************************************
 * ALLOC REPLACEMENT
 */

bool
alloc_entering_replace_routine(app_pc pc);

bool
alloc_replace_in_cur_arena(byte *addr);

/* overlap check includes redzone */
bool
alloc_replace_overlaps_delayed_free(byte *start, byte *end,
                                    malloc_info_t *info INOUT);

/* overlap check includes redzone */
bool
alloc_replace_overlaps_any_free(byte *start, byte *end,
                                malloc_info_t *info INOUT);

/* overlap check includes redzone */
bool
alloc_replace_overlaps_malloc(byte *start, byte *end,
                              malloc_info_t *info INOUT);

/* Allocate application memory for clients.
 * This function can only be used with -replace_malloc and
 * does not work with malloc wrapping mode.
 */
byte *
client_app_malloc(void *drcontext, size_t size, app_pc caller);

/* Free application memory allocated from client_app_malloc.
 * This function can only be used with -replace_malloc and
 * does not work with malloc wrapping mode.
 */
void
client_app_free(void *drcontext, void *ptr, app_pc caller);

/***************************************************************************
 * CLIENT CALLBACKS
 */

/* called when malloc chunk data is being free so user data can also be freed */
void
client_malloc_data_free(void *data);

/* called when a malloc is being moved to a free list.  the stored user
 * data is replaced with the return value.
 * only called when replacing rather than wrapping malloc.
 */
void *
client_malloc_data_to_free_list(void *cur_data, dr_mcontext_t *mc, app_pc post_call);

/* called when a freed chunk is being split, allowing for a copy of the
 * stored user data to be kept with the remaining-free portion.
 */
void *
client_malloc_data_free_split(void *cur_data);

/* The return value is stored as the client data.
 * In some cases this routine is re-called for an entry that has
 * already had its data set: in such cases, info->client_data is non-NULL.
 * For all new entries, mc and post_call will be non-NULL, unless
 * during init time (i.e., pre-existing allocations).
 * The alloc entry is NOT in the alloc hashtable yet and will NOT show
 * up in hashtable iteration: use client_add_malloc_post for
 * a proper hashtable view.
 */
void *
client_add_malloc_pre(malloc_info_t *info, dr_mcontext_t *mc, app_pc post_call);

/* Called after the new alloc entry has been added to the alloc hashtable. */
void
client_add_malloc_post(malloc_info_t *info);

/* The alloc entry has NOT been freed yet and WILL show up in
 * malloc iteration: use client_remove_malloc_post to avoid this.
 */
void
client_remove_malloc_pre(malloc_info_t *info);

/* Called after the alloc entry has been freed.
 * The client data has been freed and so is not available.
 */
void
client_remove_malloc_post(malloc_info_t *info);

/* real_size is the actual size of memory allocated by allocator.
 * If alloc_options.get_padded_size, the padded_size is passed in;
 * otherwise, an inaccurate real_size is passed in,
 * possibly (app_size + redzone_size*2).
 */
void
client_handle_malloc(void *drcontext, malloc_info_t *info, dr_mcontext_t *mc);

/* for_reuse indicates whether the freed memory might be reused at any time.
 * For an in-place realloc (the old and new bases are the same), the routines
 * client_{remove,add}_malloc_{pre,post} will not be called.
 * For an out-of-place realloc, client_{remove,add}_malloc_{pre,post} will
 * be called prior to this routine, but client_handle_{free,malloc} will not
 * be called.
 */
void
client_handle_realloc(void *drcontext, malloc_info_t *old_info,
                      malloc_info_t *new_info, bool for_reuse, dr_mcontext_t *mc);

void
client_handle_alloc_failure(size_t request_size, app_pc pc, dr_mcontext_t *mc);

void
client_handle_realloc_null(app_pc pc, dr_mcontext_t *mc);

/* This is called when the app asks to free a malloc chunk.
 * For wrapping:
 *   Up to the caller to delay, via its return value.
 *   Returns the value to pass to free().  Return "tofree" for no change.
 *   The Windows heap param is INOUT so it can be changed as well.
 *   client_data is from client_add_malloc_routine().
 * For replacing:
 *   The return value is ignored.  Frees are always delayed, unless
 *   for_reuse is true.
 * for_reuse indicates whether the freed memory might be reused at any time.
 * If for_reuse is false, a subsequent call to client_handle_free_reuse()
 * will indicate when it is about to be reused.
 *
 * routine_set_data is here just for delayed frees: for DrMalloc we should
 * pull delayed frees inside and elminate this parameter.
 */
app_pc
client_handle_free(malloc_info_t *info, byte *tofree, dr_mcontext_t *mc,
                   app_pc free_routine, void *routine_set_data, bool for_reuse
                   _IF_WINDOWS(ptr_int_t *auxarg INOUT));

/* For wrapping:
 *   Never called.
 * For replacing:
 *   Called when a free chunk is about to be re-used for a new malloc.
 */
void
client_handle_free_reuse(void *drcontext, malloc_info_t *info, dr_mcontext_t *mc);

/* Called when a free chunk is split and new redzones are created
 * or adjacent free chunks are coalesced and a header disappears (the prior header
 * space is treated as a new "redzone").
 */
void
client_new_redzone(app_pc start, size_t size);

void
client_invalid_heap_arg(app_pc pc, app_pc target, dr_mcontext_t *mc, const char *routine,
                        bool is_free);

/* action is the 2nd action: "freed" or "realloc" or "queried" */
void
client_mismatched_heap(app_pc pc, app_pc target, dr_mcontext_t *mc,
                       const char *alloc_routine, const char *free_routine,
                       const char *action, void *client_data, bool C_vs_CPP);

void
client_handle_mmap(void *drcontext, app_pc base, size_t size, bool anon);

void
client_handle_munmap(app_pc base, size_t size, bool anon);

void
client_handle_munmap_fail(app_pc base, size_t size, bool anon);

#ifdef UNIX
void
client_handle_mremap(app_pc old_base, size_t old_size, app_pc new_base, size_t new_size,
                     bool image);
#endif

#ifdef WINDOWS
void
client_handle_heap_destroy(void *drcontext, HANDLE heap, void *client_data);

void
client_remove_malloc_on_destroy(HANDLE heap, byte *start, byte *end);

bool
is_in_seh(void *drcontext);

bool
is_in_seh_unwind(void *drcontext, dr_mcontext_t *mc);
#endif

void
client_pre_syscall(void *drcontext, int sysnum);

void
client_post_syscall(void *drcontext, int sysnum);

void
client_entering_heap_routine(void);

void
client_exiting_heap_routine(void);

/* The return value is stored as client data and passed in client_handle_free(). */
void *
client_add_malloc_routine(app_pc pc);

void
client_remove_malloc_routine(void *client_data);

/* Called when data is being placed on the app stack */
void
client_stack_alloc(byte *start, byte *end, bool defined);

/* Called when data is being removed from the app stack.
 * A pointer-sized value has also been placed in the return value register.
 */
void
client_stack_dealloc(byte *start, byte *end);

/* Non-interpreted code about to write to app-visible memory.  Returns true if no errors
 * were found with the write.
 */
bool
client_write_memory(byte *start, size_t size, dr_mcontext_t *mc);

/* Non-interpreted code about to read from app-visible memory.  Returns true if no errors
 * were found with the read.
 */
bool
client_read_memory(byte *start, size_t size, dr_mcontext_t *mc);

#ifdef DEBUG
void
client_print_callstack(void *drcontext, dr_mcontext_t *mc, app_pc pc);
#endif

#endif /* _ALLOC_H_ */
