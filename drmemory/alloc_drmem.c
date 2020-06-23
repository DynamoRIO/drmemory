/* **********************************************************
 * Copyright (c) 2010-2020 Google, Inc.  All rights reserved.
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

#include "dr_api.h"
#include "drmemory.h"
#include "slowpath.h"
#include "report.h"
#include "shadow.h"
#include "stack.h"
#include "syscall.h"
#include "alloc.h"
#include "heap.h"
#include "redblack.h"
#include "leak.h"
#include "memlayout.h"
#include "alloc_drmem.h"
#ifdef UNIX
# ifdef MACOS
#  include <sys/syscall.h>
#  define _XOPEN_SOURCE 700 /* required to get POSIX, etc. defines out of ucontext.h */
#  define __need_struct_ucontext64 /* seems to be missing from Mac headers */
# elif defined(LINUX)
#  include "sysnum_linux.h"
# endif
# include <signal.h>
# include <ucontext.h>
/* 32-bit plain=736, rt=892; 64-bit plain=800, rt=440 */
# define MAX_SIGNAL_FRAME_SIZE 1024
#else
# include "stack.h"
#endif
#include "pattern.h"

/* PR 465174: share allocation site callstacks.  We do not rely on
 * global malloc synchronization and instead use the
 * hashtable_{,un}lock() functions plus reference counts in the
 * payloads.
 */
#define ASTACK_TABLE_HASH_BITS 8
static hashtable_t alloc_stack_table;

#ifdef UNIX
/* PR 418629: to determine stack bounds accurately we track anon mmaps */
static rb_tree_t *mmap_tree;
static void *mmap_tree_lock; /* maybe rbtree should support internal synch */
#endif

#ifdef STATISTICS
uint alloc_stack_count;
#endif

#ifdef WINDOWS
app_pc addr_RtlLeaveCrit; /* for i#689 */
#endif

static bool process_exiting;

#ifdef X64
# define Xax Rax
# define Xbx Rbx
# define Xcx Rcx
# define Xdx Rdx
# define Xsp Rsp
# define Xbp Rbp
# define Xsi Rsi
# define Xdi Rdi
#else
# define Xax Eax
# define Xbx Ebx
# define Xcx Ecx
# define Xdx Edx
# define Xsp Esp
# define Xbp Ebp
# define Xsi Esi
# define Xdi Edi
#endif

/***************************************************************************
 * DELAYED-FREE LIST
 */

/* A FIFO implemented by an array since we have a fixed size equal
 * to options.delay_frees.
 * We store the address that should be passed to free() (i.e., it
 * includes the redzone).
 */
typedef struct _delay_free_t {
    app_pc addr; /* includes redzone */
#ifdef WINDOWS
    /* We assume the only flag even at Rtl level is HEAP_NO_SERIALIZE so we only have
     * to record the Heap (xref PR 502150).
     * This is also used for the block type for _dbg routines.
     */
    ptr_int_t auxarg;
#endif
    size_t real_size; /* includes redzones */
    bool has_redzone;
    packed_callstack_t *pcs; /* i#205 for reporting where freed */
} delay_free_t;

/* We need a separate free queue per malloc routine (PR 476805) */
typedef struct _delay_free_info_t {
    delay_free_t *delay_free_list;
    /* Head of FIFO array */
    int delay_free_head;
    /* If FIFO is full, equals options.delay_frees; else, equals
     * one past the furthest index that has been filled.
     */
    int delay_free_fill;
    /* We have a max delayed free bytes to avoid running out of memory by
     * delaying one or two giant frees
     */
    size_t delay_free_bytes;
} delay_free_info_t;

/* We could do per-thread free lists but could strand frees in idle threads;
 * plus, already impacting performance plenty so global synch ok.
 * We could do per-malloc-routine lock as well: but we stick w/ global
 * for simplicity so we can use for delay_free_tree as well.
 */
static void *delay_free_lock;

/* Interval tree for looking up whether an address is on the list (PR 535568).
 * Shared across all the queues since should be no overlap.
 */
static rb_tree_t *delay_free_tree;

#define DELAY_FREE_FULL(info) (info->delay_free_fill == options.delay_frees)

#ifdef STATISTICS
uint delayed_free_bytes; /* includes redzones */
#endif

/***************************************************************************/

static void
alloc_callstack_free(void *p);

static byte *
next_defined_ptrsz(byte *start, byte *end);

static byte *
end_of_defined_region(byte *start, byte *end);

static bool
is_register_defined(void *drcontext, reg_id_t reg);

void
alloc_drmem_init(void)
{
    alloc_options_t alloc_ops = {0,};
    alloc_ops.track_allocs = options.track_allocs;
    alloc_ops.track_heap = options.track_heap;
    alloc_ops.redzone_size = options.redzone_size;
    alloc_ops.size_in_redzone = options.size_in_redzone;
    alloc_ops.record_allocs = true; /* used to only need for -count_leaks */
    /* shadow mode assumes everything is unaddr and so doesn't need to know
     * padding b/c it will naturally be unaddr;
     * while pattern mode assumes everything is addr and has to know exact
     * bounds to mark unaddr
     */
    alloc_ops.get_padded_size = (options.pattern == 0) ? false : true;
    alloc_ops.replace_realloc = options.replace_realloc && INSTRUMENT_MEMREFS();
#ifdef WINDOWS
    alloc_ops.disable_crtdbg = options.disable_crtdbg && INSTRUMENT_MEMREFS();
#endif
    alloc_ops.prefer_msize = options.prefer_msize;
    alloc_ops.cache_postcall = IF_DRSYMS_ELSE(options.use_symcache &&
                                              options.use_symcache_postcall, false);
    /* We can't disable operator interception if !options.check_delete_mismatch
     * b/c of msvc debug delete reading headers.  For -replace_malloc we can,
     * but we still want to replace operators to ensure we get our redzones
     * with debug msvc.
     */
    alloc_ops.intercept_operators =
        (options.replace_malloc ? true : INSTRUMENT_MEMREFS());
    alloc_ops.conservative = options.conservative;
    /* replace vs wrap */
    alloc_ops.replace_malloc = options.replace_malloc;
    alloc_ops.external_headers = false; /* i#879: NYI */
    alloc_ops.shared_redzones = (options.pattern == 0);
    alloc_ops.delay_frees = options.delay_frees;
    alloc_ops.delay_frees_maxsz = options.delay_frees_maxsz;
#ifdef WINDOWS
    alloc_ops.skip_msvc_importers = options.skip_msvc_importers;
#endif
    alloc_ops.global_lock = false; /* we don't need it => can't call malloc_lock() */
    alloc_ops.use_symcache = options.use_symcache;
#ifdef WINDOWS
    alloc_ops.replace_nosy_allocs = options.replace_nosy_allocs;
#endif
    alloc_init(&alloc_ops, sizeof(alloc_ops));

    hashtable_init_ex(&alloc_stack_table, ASTACK_TABLE_HASH_BITS, HASH_CUSTOM,
                      false/*!str_dup*/, false/*using external synch*/,
                      alloc_callstack_free,
                      (uint (*)(void*)) packed_callstack_hash,
                      (bool (*)(void*, void*)) packed_callstack_cmp);

#ifdef UNIX
    mmap_tree = rb_tree_create(NULL);
    mmap_tree_lock = dr_mutex_create();
#endif

    leak_init(!options.leaks_only && options.check_uninitialized,
              options.check_leaks_on_destroy,
              options.midchunk_new_ok,
              options.midchunk_inheritance_ok,
              options.midchunk_string_ok,
              options.midchunk_size_ok,
              options.show_reachable,
              IF_WINDOWS_(options.check_encoded_pointers)
              next_defined_ptrsz,
              end_of_defined_region,
              is_register_defined);

    memlayout_init();

    if (options.delay_frees > 0) {
        delay_free_lock = dr_mutex_create();
        delay_free_tree = rb_tree_create(NULL);
    }

#ifdef WINDOWS /* for i#689 */
    ASSERT(ntdll_base != NULL, "init ordering problem");
    addr_RtlLeaveCrit = (app_pc)
        dr_get_proc_address((module_handle_t)ntdll_base, "RtlLeaveCriticalSection");
#endif
}

void
alloc_drmem_exit(void)
{
    process_exiting = true;
    leak_exit();
    alloc_exit(); /* must be before deleting alloc_stack_table */
    hashtable_delete_with_stats(&alloc_stack_table, "alloc stack table");
#ifdef UNIX
    rb_tree_destroy(mmap_tree);
    dr_mutex_destroy(mmap_tree_lock);
#endif
    if (options.delay_frees > 0) {
        rb_tree_destroy(delay_free_tree);
        dr_mutex_destroy(delay_free_lock);
    }
}

/***************************************************************************
 * MMAP TABLE
 *
 * PR 418629: to determine stack bounds accurately we track mmaps
 */

#ifdef UNIX
static void
mmap_tree_add(byte *base, size_t size)
{
    dr_mutex_lock(mmap_tree_lock);
    rb_node_t *node = rb_insert(mmap_tree, base, size, NULL);
    if (node != NULL) {
        /* merge overlap */
        app_pc merge_base, merge_end;
        size_t merge_size;
        rb_node_fields(node, &merge_base, &merge_size, NULL);
        rb_delete(mmap_tree, node);
        merge_end = (base + size > merge_base + merge_size) ?
            base + size : merge_base + merge_size;
        merge_base = (base < merge_base) ? base : merge_base;
        LOG(2, "mmap add: merged "PFX"-"PFX" with existing => "PFX"-"PFX"\n",
            base, base+size, merge_base, merge_end);
        node = rb_insert(mmap_tree, merge_base, merge_end - merge_base, NULL);
        ASSERT(node == NULL, "mmap tree error");
    }
    dr_mutex_unlock(mmap_tree_lock);
}

static bool
mmap_tree_remove(byte *base, size_t size)
{
    dr_mutex_lock(mmap_tree_lock);
    bool res = false;
    rb_node_t *node = rb_overlaps_node(mmap_tree, base, base+size);
    /* we don't know whether anon or not so ok to not be there */
    while (node != NULL) {
        /* FIXME: should we create a general data struct for interval tree that
         * does not merge adjacent, but handles removing or adding subsets/overlaps?
         * Getting similar to vm_areas, heap.c => PR 210669 as Extension for clients
         * to use too?
         */
        app_pc node_base;
        size_t node_size;
        rb_node_fields(node, &node_base, &node_size, NULL);
        rb_delete(mmap_tree, node);
        if (node_base < base) {
            node = rb_insert(mmap_tree, node_base, base - node_base, NULL);
            ASSERT(node == NULL, "mmap tree error");
        }
        if (node_base + node_size > base + size) {
            node = rb_insert(mmap_tree, base + size, (node_base + node_size) -
                             (base + size), NULL);
            ASSERT(node == NULL, "mmap tree error");
        }
        res = true;
        /* handle overlapping multiple regions */
        node = rb_overlaps_node(mmap_tree, base, base+size);
    }
    dr_mutex_unlock(mmap_tree_lock);
    return res;
}

bool
mmap_anon_lookup(byte *addr, byte **start OUT, size_t *size OUT)
{
    dr_mutex_lock(mmap_tree_lock);
    bool res = false;
    rb_node_t *node = rb_in_node(mmap_tree, addr);
    if (node != NULL) {
        rb_node_fields(node, start, size, NULL);
        res = true;
    }
    dr_mutex_unlock(mmap_tree_lock);
    return res;
}
#endif

/***************************************************************************
 * EVENTS FOR COMMON/ALLOC.C
 */

void
alloc_callstack_lock(void)
{
    hashtable_lock(&alloc_stack_table);
}

void
alloc_callstack_unlock(void)
{
    hashtable_unlock(&alloc_stack_table);
}

void
alloc_callstack_free(void *p)
{
    /* For -replace_malloc, we need to force-remove here.  With wrapping, we rely
     * on the malloc hashtable exist to free all references to these callstacks.
     * For replacing, there's no reason to iterate the heap just to clean these up.
     */
    packed_callstack_destroy(p);
}

void
shared_callstack_free(packed_callstack_t *pcs)
{
    uint count;
    if (pcs == NULL)
        return;
    /* We need to synchronize removal from the table w/ additions */
    hashtable_lock(&alloc_stack_table);
    count = packed_callstack_free(pcs);
    LOG(4, "%s: freed pcs "PFX" => refcount %d\n", __FUNCTION__, pcs, count);
    ASSERT(count != 0, "refcount should not hit 0 in malloc_table");
    if (count == 1) {
        /* One ref left, which must be the alloc_stack_table.
         * packed_callstack_free will be called by hashtable_remove
         * to dec refcount to 0 and do the actual free.
         */
        hashtable_remove(&alloc_stack_table, (void *)pcs);
    }
    hashtable_unlock(&alloc_stack_table);
}

void
client_malloc_data_free(void *data)
{
    packed_callstack_t *pcs = (packed_callstack_t *) data;
    ASSERT(pcs != NULL || !options.count_leaks, "malloc data must exist");
    shared_callstack_free(pcs);
}

/* Be sure to pass the same max_frames for all callstacks that we want
 * a comparison to.  Currently we use a separate one for malloc vs
 * free, but we expect them to never match anyway.
 */
static packed_callstack_t *
get_shared_callstack(packed_callstack_t *existing_data, dr_mcontext_t *mc,
                     app_pc post_call, uint max_frames)
{
    /* XXX i#75: when the app has a ton of mallocs that are quickly freed,
     * we spend a lot of time building and tearing down callstacks
     * (xref my original setup of not showing leak callstacks by default
     * which was for this reason and to save space: but for usability
     * it's better to have leak callstacks by default).
     * We could just record addresses and not modules, and only on
     * module unload or app exit walk the malloc table and fill
     * in the module info (and if too many unloads, switch to the
     * every-alloc scheme).
     */
    packed_callstack_t *pcs;
    if (existing_data != NULL)
        pcs = (packed_callstack_t *) existing_data;
    else {
        app_loc_t loc;
        pc_to_loc(&loc, post_call);
        packed_callstack_record(&pcs, mc, &loc, max_frames);
        /* our malloc and free callstacks use post-call as the top frame when wrapping */
        if (!options.replace_malloc)
            packed_callstack_first_frame_retaddr(pcs);
    }
    /* XXX i#246: store last malloc callstack outside of hashtable,
     * and only add to hashtable on next malloc, so that if freed
     * right away we avoid the hashtable lookup+cmp+insert+remove
     * costs
     */

    /* Synchronization: we no longer rely on malloc_lock(), as we
     * don't enable a global lock for -replace_malloc: i#949.  Thus we
     * must hold the hashtable lock across the lookup and ref count inc.
     * shared_callstack_free() grabs the hashtable lock before the final
     * remove, ensuring pcs doesn't disappear underneath us.
     */
    hashtable_lock(&alloc_stack_table);
    pcs = packed_callstack_add_to_table(&alloc_stack_table, pcs
                                        _IF_STATS(&alloc_stack_count));
    LOG(4, "%s: created pcs "PFX"\n", __FUNCTION__, pcs);
    hashtable_unlock(&alloc_stack_table);
    return pcs;
}

void *
client_add_malloc_pre(malloc_info_t *mal, dr_mcontext_t *mc, app_pc post_call)
{
    if (!options.malloc_callstacks && !options.count_leaks &&
        !options.track_origins_unaddr)
        return NULL;
    return (void *)
        get_shared_callstack((packed_callstack_t *)mal->client_data, mc, post_call,
                             options.malloc_max_frames);
}

void
client_add_malloc_post(malloc_info_t *mal)
{
    /* nothing to do */
}

void
client_remove_malloc_pre(malloc_info_t *mal)
{
    /* nothing to do: client_malloc_data_free() does the work */
}

void
client_remove_malloc_post(malloc_info_t *mal)
{
    /* nothing to do */
}

void
client_invalid_heap_arg(app_pc pc, app_pc target, dr_mcontext_t *mc, const char *routine,
                        bool is_free)
{
    app_loc_t loc;
    char msg[64];
    pc_to_loc(&loc, pc);
    dr_snprintf(msg, BUFFER_SIZE_ELEMENTS(msg), " to %s", routine);
    NULL_TERMINATE_BUFFER(msg);
    report_invalid_heap_arg(&loc, target, mc, msg, is_free);
}

void
client_mismatched_heap(app_pc pc, app_pc target, dr_mcontext_t *mc,
                       const char *alloc_routine, const char *free_routine,
                       const char *action, void *client_data, bool C_vs_CPP)
{
    app_loc_t loc;
    char msg[128];
    packed_callstack_t *pcs = NULL;
    if (C_vs_CPP && !options.check_delete_mismatch)
        return;
#ifdef WINDOWS
    if (!C_vs_CPP && !options.check_heap_mismatch)
        return;
#endif
    pc_to_loc(&loc, pc);
    /* i#642: We want to report the callstack where it was allocated.  But, we want
     * no-leak mode to be as fast as possible, so we don't record per-malloc
     * callstacks just for this feature.  Instead we try to report the allocator and
     * free routines involved.
     */
    pcs = (packed_callstack_t *) client_data;
    dr_snprintf(msg, BUFFER_SIZE_ELEMENTS(msg),
                ": allocated with %s, %s with %s",
                alloc_routine, action, free_routine);
    NULL_TERMINATE_BUFFER(msg);
    report_mismatched_heap(&loc, target, mc, msg, pcs);
}

void
client_handle_malloc(void *drcontext, malloc_info_t *mal, dr_mcontext_t *mc)
{
    /* For calloc via malloc, post-malloc marks as undefined, and we should
     * see the memset which should then mark as defined.
     * But when calloc allocates memory itself, the memset happens
     * while the memory is still unaddressable, and those writes are
     * suppressed => zeroed should be true and we mark as defined here.
     * Plus, for calloc via mmap it's simpler to not have the mmap handler
     * mark as defined and to leave as unaddressable and to mark as
     * defined here (xref PR 531619).
     */
    if (!mal->zeroed && options.track_origins_unaddr &&
        !mal->pre_us && mal->has_redzone) {
        byte **ptr;
        byte *rz_start = mal->base - options.redzone_size;
        byte *end = mal->base + mal->request_size;
        LOG(2, "set value "PFX" at "PFX"-"PFX" in allocated block\n",
            rz_start, mal->base, end);
        /* Must set before pattern_handle_malloc, so it is ok to overflow
         * to the redzone after the block.
         * In pattern mode, the redzone will be overwriten by pattern
         * value later in pattern_handle_malloc.
         */
        for (ptr = (byte **)mal->base; ptr < (byte **)end; ptr++)
            *ptr = rz_start;
    }
    if (options.shadowing) {
        uint val = mal->zeroed ? SHADOW_DEFINED : SHADOW_UNDEFINED;
        shadow_set_range(mal->base, mal->base + mal->request_size, val);
    }
    if (options.pattern != 0) {
        pattern_handle_malloc(mal);
    }
    report_malloc(mal->base, mal->base + mal->request_size,
                  mal->realloc ? "realloc" : "malloc", mc);
    leak_handle_alloc(drcontext, mal->base, mal->request_size);
    memlayout_handle_alloc(drcontext, mal->base, mal->request_size);
}

void
client_handle_realloc(void *drcontext, malloc_info_t *old_mal,
                      malloc_info_t *new_mal, bool for_reuse, dr_mcontext_t *mc)
{
    /* XXX i#69: wrapping the app's realloc is racy: old region could
     * have been malloc'd again by now!  We could synchronize all
     * malloc/free calls w/ our own locks.  The real routines have
     * locks already, so shouldn't be any perf impact.  Instead, we
     * replace the app's realloc w/ a sequence of equivalent calls.
     * This also solves PR 493888: realloc-freed memory not delayed
     * with rest of delayed free queue.
     */
    ASSERT(!options.replace_realloc || options.leaks_only, "shouldn't come here");
    /* Copy over old allocation's shadow values.  If new region is bigger, mark
     * the extra space at the end as undefined.  PR 486049.
     */
    if (options.shadowing) {
        if (new_mal->request_size > old_mal->request_size) {
            if (new_mal->base != old_mal->base)
                shadow_copy_range(old_mal->base, new_mal->base, old_mal->request_size);
            shadow_set_range(new_mal->base + old_mal->request_size,
                             new_mal->base + new_mal->request_size,
                             new_mal->zeroed ? SHADOW_DEFINED : SHADOW_UNDEFINED);
        } else {
            if (new_mal->base != old_mal->base)
                shadow_copy_range(old_mal->base, new_mal->base, new_mal->request_size);
        }

        /* If the new region is after the old region, overlap or not, compute how
         * much of the front of the old region needs to be marked unaddressable
         * and do so.  This can include the whole old region.
         */
        if (new_mal->base > old_mal->base) {
            shadow_set_range(old_mal->base,
                             /* it can overlap */
                             (new_mal->base < old_mal->base + old_mal->request_size) ?
                             new_mal->base : old_mal->base + old_mal->request_size,
                             SHADOW_UNADDRESSABLE);
        }

        /* If the new region is before the old region, overlap or not, compute how
         * much of the end of the old region needs to be marked unaddressable
         * and do so.  This can include the whole old region.  PR 486049.
         * Note: this 'if' can't be an else of the above 'if' because there is a
         *       case where the new region is fully subsumed by the old one.
         */
        if (new_mal->base + new_mal->request_size <
            old_mal->base + old_mal->request_size) {
            app_pc start;
            if (new_mal->base + new_mal->request_size < old_mal->base)/* no overlap */
                start = old_mal->base;
            else {                                  /* old & new regions overlap */
                start = new_mal->base + new_mal->request_size;
                if (MAP_4B_TO_1B) {
                    /* XXX i#650: granularity won't let us catch an error
                     * prior to next 4-aligned word in padding
                     */
                    start = (app_pc) ALIGN_FORWARD(start, 4);
                }
            }
            shadow_set_range(start, old_mal->base + old_mal->request_size,
                             SHADOW_UNADDRESSABLE);
        }
    }
    if (options.pattern != 0) {
        pattern_handle_realloc(old_mal, new_mal, for_reuse);
    }
    report_malloc(old_mal->base, old_mal->base + old_mal->request_size,
                  "realloc-old", mc);
    report_malloc(new_mal->base, new_mal->base + new_mal->request_size,
                  "realloc-new", mc);
    leak_handle_alloc(drcontext, new_mal->base, new_mal->request_size);
}

void
client_handle_alloc_failure(size_t request_size, app_pc pc, dr_mcontext_t *mc)
{
    app_loc_t loc;
    pc_to_loc(&loc, pc);
#ifdef LINUX
    LOG(1, "heap allocation failed on sz="PIFX"!  heap="PFX"-"PFX"\n",
        request_size, get_heap_start(), get_brk(false/*want full extent*/));
# ifdef STATISTICS
    LOG(1, "\tdelayed=%u\n",  delayed_free_bytes);
    /* FIXME: if delayed frees really are a problem, should we free
     * them all here and re-try the malloc?
     */
# endif
#endif
    report_warning(&loc, mc, "heap allocation failed", NULL, 0, false);
}

void
client_handle_realloc_null(app_pc pc, dr_mcontext_t *mc)
{
    /* realloc with NULL is guaranteed to be properly handled,
     * but we report a warning in case unintentional by the app.
     * Windows note: if using libc, at least for msvcr80.dll,
     * libc redirects realloc(NULL,) to malloc() so the realloc
     * does not show up at the Rtl level that we monitor.
     */
    if (options.warn_null_ptr) {
        app_loc_t loc;
        pc_to_loc(&loc, pc);
        report_warning(&loc, mc, "realloc() called with NULL pointer", NULL, 0, false);
    }
}

void *
client_add_malloc_routine(app_pc pc)
{
    /* We assume no lock is needed on creation */
    if (options.delay_frees > 0) {
        delay_free_info_t *info = (delay_free_info_t *)
            global_alloc(sizeof(*info), HEAPSTAT_MISC);
        info->delay_free_list = (delay_free_t *)
            global_alloc(options.delay_frees * sizeof(*info->delay_free_list),
                         HEAPSTAT_MISC);
        info->delay_free_head = 0;
        info->delay_free_fill = 0;
        info->delay_free_bytes = 0;
        return (void *) info;
    } else {
        return NULL;
    }
}

void
client_remove_malloc_routine(void *client_data)
{
    /* We assume no lock is needed on destroy */
    if (options.delay_frees > 0) {
        delay_free_info_t *info = (delay_free_info_t *) client_data;
        int i;
        ASSERT(info != NULL, "invalid param");
        for (i = 0; i < info->delay_free_fill; i++) {
            if (info->delay_free_list[i].addr != NULL) {
                shared_callstack_free(info->delay_free_list[i].pcs);
            }
        }
        global_free(info->delay_free_list,
                    options.delay_frees * sizeof(*info->delay_free_list), HEAPSTAT_MISC);
        global_free(info, sizeof(*info), HEAPSTAT_MISC);
    }
}

#ifdef DEBUG
static bool
print_free_tree(rb_node_t *node, void *data)
{
    app_pc start;
    size_t size;
    rb_node_fields(node, &start, &size, NULL);
    LOG(1, "\tfree tree entry: "PFX"-"PFX"\n", start, start+size);
    return true;
}
#endif

/* Retrieves the fields for the free queue entry at idx (base and
 * auxarg), adjusts the delay_free_bytes count, and removes the
 * next-to-free entry from the rbtree.  Does not change the head
 * pointer.  Caller must hold lock.
 */
static app_pc
next_to_free(delay_free_info_t *info, int idx _IF_WINDOWS(ptr_int_t *auxarg OUT),
             const char *reason)
{
    app_pc pass_to_free = NULL;
    pass_to_free = info->delay_free_list[idx].addr;
#ifdef WINDOWS
    if (auxarg != NULL)
        *auxarg = info->delay_free_list[idx].auxarg;
#endif
    if (pass_to_free != NULL) {
        rb_node_t *node = rb_find(delay_free_tree, pass_to_free);
        if (node != NULL) {
            DOLOG(2, {
                byte *start;
                size_t size;
                rb_node_fields(node, &start, &size, NULL);
                LOG(2, "deleting from delay_free_tree "PFX": "PFX"-"PFX"\n",
                    pass_to_free, start, start + size);
            });
            rb_delete(delay_free_tree, node);
        } else {
            DOLOG(1, { rb_iterate(delay_free_tree, print_free_tree, NULL); });
            ASSERT(false, "delay_free_tree inconsistent");
        }
        info->delay_free_bytes -= info->delay_free_list[idx].real_size;
        STATS_ADD(delayed_free_bytes,
                  -(int)info->delay_free_list[idx].real_size);
        LOG(2, "%s: freeing "PFX"-"PFX
            IF_WINDOWS(" auxarg="PFX) "\n", reason, pass_to_free,
            pass_to_free + info->delay_free_list[idx].real_size
            _IF_WINDOWS(auxarg == NULL ? 0 : *auxarg));
        if (options.pattern != 0) {
            /* pattern_handle_real_free only cares about redzone bounds */
            malloc_info_t mal = {sizeof(info), pass_to_free,
                                 info->delay_free_list[idx].real_size,
                                 info->delay_free_list[idx].real_size,
                                 false/*!pre_us*/, false/*redzone already in bounds*/,
                                 /* rest 0 */};
            pattern_handle_real_free(&mal, true /* delayed */);
        }
    }
    shared_callstack_free(info->delay_free_list[idx].pcs);
    info->delay_free_list[idx].pcs = NULL;
    return pass_to_free;
}

/* Returns the value to pass to free().  Return "tofree" for no change.
 * The auxarg param is INOUT so it can be changed as well.
 */
app_pc
client_handle_free(malloc_info_t *mal, byte *tofree, dr_mcontext_t *mc,
                   app_pc free_routine, void *routine_set_data, bool for_reuse
                   _IF_WINDOWS(ptr_int_t *auxarg INOUT))
{
    report_malloc(mal->base, mal->base + mal->request_size, "free", mc);

    if (options.shadowing) {
        shadow_set_range(mal->base, mal->base + mal->request_size,
                         SHADOW_UNADDRESSABLE);
    }

    ASSERT(for_reuse || options.replace_malloc, "wrap free is always for reuse");

    if (INSTRUMENT_MEMREFS() && !options.replace_malloc && options.delay_frees > 0) {
        /* PR 406762: delay frees to catch more errors.  We put
         * this to-be-freed memory in a delay FIFO and leave it as
         * unaddressable.  One the FIFO fills up we substitute the
         * oldest free for this one.
         * We don't bother to free the FIFO entries at exit time; we
         * simply exclude from our leak report.
         */
        delay_free_info_t *info = (delay_free_info_t *) routine_set_data;
        app_pc pass_to_free = NULL;
#ifdef WINDOWS
        ptr_int_t pass_auxarg;
        bool full;
#endif
        uint idx;
        size_t rz_sz = options.redzone_size;
        byte *rz_start = mal->base - (mal->has_redzone ? rz_sz : 0);
        size_t tot_sz = mal->pad_size + (mal->has_redzone ? rz_sz*2 : 0);
        ASSERT(info != NULL, "invalid param");
        ASSERT(rz_start == tofree, "tofree should equal start of redzone");
        dr_mutex_lock(delay_free_lock);
        if (tot_sz > options.delay_frees_maxsz) {
            /* we have to free this one, it's too big */
            LOG(2, "malloc size %d is larger than max delay %d so freeing immediately\n",
                tot_sz, options.delay_frees_maxsz);
            dr_mutex_unlock(delay_free_lock);
            if (options.pattern != 0)
                pattern_handle_real_free(mal, false);
            return tofree;
        }
        /* Store real base and real size: i.e., including redzones (PR 572716) */
        info->delay_free_bytes += tot_sz;
        if (info->delay_free_bytes > options.delay_frees_maxsz) {
            int head_start = info->delay_free_head;
            int idx = info->delay_free_head;
            LOG(2, "total delayed %d larger than max delay %d\n",
                info->delay_free_bytes, options.delay_frees_maxsz);
            /* we can't invoke the app's free() routine safely
             * so we look for a single free that's bigger than this one:
             * if none, we have to free this one.
             * XXX: either need call-app-routine support in DR (though
             * still have potential deadlock problems since holding lock here)
             * or switch to replacing malloc&co.
             */
            do {
                /* XXX: we could end up doing a linear walk on every free.
                 * we can also end up always freeing immediately once the
                 * queue gets full of small objects and the app is freeing large
                 * objects.  not ideal!
                 */
                if (info->delay_free_list[idx].addr != NULL &&
                    info->delay_free_list[idx].real_size >= tot_sz) {
                    LOG(2, "freeing delayed idx=%d "PFX" w/ size=%d (head=%d, fill=%d)\n",
                        idx, info->delay_free_list[idx].addr,
                        info->delay_free_list[idx].real_size,
                        info->delay_free_head, info->delay_free_fill);
                    pass_to_free = next_to_free(info, idx _IF_WINDOWS(&pass_auxarg),
                                                "exceeded delay_frees_maxsz");
                    ASSERT(info->delay_free_bytes <= options.delay_frees_maxsz,
                           "cannot happen");
                    info->delay_free_list[idx].addr = NULL;
                    break;
                }
                idx++;
                if (idx >= info->delay_free_fill)
                    break;
                if (idx >= options.delay_frees)
                    idx = 0;
            } while (idx != head_start);
            if (pass_to_free == NULL) {
                LOG(2, "malloc size %d larger than any entry + over size limit\n",
                    tot_sz);
                info->delay_free_bytes -= tot_sz;
                dr_mutex_unlock(delay_free_lock);
                if (options.pattern != 0) {
                    pattern_handle_real_free(mal, false);
                }
                return tofree;
            }
        }

        LOG(2, "inserting into delay_free_tree (queue idx=%d): "PFX
            "-"PFX" %d bytes redzone=%d\n",
            DELAY_FREE_FULL(info) ? info->delay_free_head : info->delay_free_fill,
            rz_start, rz_start + tot_sz, tot_sz, mal->has_redzone);

        if (DELAY_FREE_FULL(info)) {
            IF_WINDOWS(full = true;)
            if (pass_to_free == NULL) {
                pass_to_free = next_to_free(info, info->delay_free_head
                                            _IF_WINDOWS(&pass_auxarg),
                                            "delayed free queue full");
            }
            idx = info->delay_free_head;
            info->delay_free_head++;
            if (info->delay_free_head >= options.delay_frees)
                info->delay_free_head = 0;
        } else {
            LOG(2, "delayed free queue not full: delaying %d-th free of "PFX"-"PFX
                IF_WINDOWS(" auxarg="PFX) "\n",
                info->delay_free_fill, rz_start, rz_start + tot_sz
                _IF_WINDOWS((auxarg==NULL) ? 0:*auxarg));
            ASSERT(info->delay_free_fill <= options.delay_frees - 1, "internal error");
            IF_WINDOWS(full = false;)
            idx = info->delay_free_fill;
            info->delay_free_fill++;
            /* Rather than try to engineer a return, we continue on w/
             * pass_to_free as NULL which free() is guaranteed to handle
             */
        }

        rb_insert(delay_free_tree, rz_start, tot_sz,
                  (void *)&info->delay_free_list[idx]);

        info->delay_free_list[idx].addr = rz_start;
#ifdef WINDOWS
        /* should we be doing safe_read() and safe_write()? */
        if (auxarg != NULL) {
            info->delay_free_list[idx].auxarg = *auxarg;
            if (full)
                *auxarg = pass_auxarg;
        } else {
            info->delay_free_list[idx].auxarg = 0;
            if (full)
                ASSERT(pass_auxarg == 0, "whether using auxarg should be consistent");
        }
#endif
        info->delay_free_list[idx].real_size = tot_sz;
        info->delay_free_list[idx].has_redzone = mal->has_redzone;
        if (options.delay_frees_stack) {
            info->delay_free_list[idx].pcs =
                get_shared_callstack(NULL, mc, free_routine, options.free_max_frames);
        } else
            info->delay_free_list[idx].pcs = NULL;

        STATS_ADD(delayed_free_bytes, (uint)tot_sz);

        dr_mutex_unlock(delay_free_lock);
        if (options.pattern != 0)
            pattern_handle_delayed_free(mal);
        return pass_to_free;
    }
    if (options.pattern != 0) {
        if (options.replace_malloc && !for_reuse)
            pattern_handle_delayed_free(mal);
        else
            pattern_handle_real_free(mal, false);
    }
    return tofree; /* no change */
}

void
client_handle_free_reuse(void *drcontext, malloc_info_t *mal, dr_mcontext_t *mc)
{
    if (options.pattern != 0) {
        /* for delayed=true (final param), pattern wants bounds w/ redzones */
        pattern_handle_real_free(mal, true);
    }
}

void
client_new_redzone(app_pc start, size_t size)
{
    if (options.pattern != 0)
        pattern_new_redzone(start, size);
    /* else, shadow already unaddr b/c this is always inside a free (coalesce, split) */
}

void *
client_malloc_data_to_free_list(void *cur_data, dr_mcontext_t *mc, app_pc post_call)
{
    packed_callstack_t *pcs = (packed_callstack_t *) cur_data;
    ASSERT(options.replace_malloc, "should not be called");
    ASSERT(pcs != NULL || !options.count_leaks, "malloc data must exist");
    shared_callstack_free(pcs);
    /* replace malloc callstack with free callstack */
    if (options.delay_frees_stack) {
        return (void *)
            get_shared_callstack(NULL, mc, post_call, options.free_max_frames);
    } else {
        /* XXX: could keep the malloc callstack and report that, if labeled properly */
        return NULL;
    }
}

void *
client_malloc_data_free_split(void *cur_data)
{
    packed_callstack_t *pcs = (packed_callstack_t *) cur_data;
    ASSERT(options.replace_malloc, "should not be called");
    if (pcs != NULL) {
        ASSERT(options.delay_frees_stack, "should be NULL");
        packed_callstack_add_ref(pcs);
    }
    return pcs;
}

#ifdef WINDOWS
/* i#264: client needs to clean up any data related to allocs inside this heap */
void
client_handle_heap_destroy(void *drcontext, HANDLE heap, void *client_data)
{
    delay_free_info_t *info = (delay_free_info_t *) client_data;
    int i, num_removed = 0;
    if (options.delay_frees == 0)
        return;
    ASSERT(info != NULL, "invalid param");
    dr_mutex_lock(delay_free_lock);
    for (i = 0; i < info->delay_free_fill; i++) {
        if (info->delay_free_list[i].addr != NULL &&
            info->delay_free_list[i].auxarg == (ptr_int_t)heap) {
            /* not worth shifting the array around: just invalidate */
            rb_node_t *node = rb_find(delay_free_tree, info->delay_free_list[i].addr);
            LOG(3, "removing delayed free "PFX"-"PFX" from destroyed heap "PFX"\n",
                info->delay_free_list[i].addr,
                info->delay_free_list[i].addr +
                info->delay_free_list[i].real_size, heap);
            if (node != NULL)
                rb_delete(delay_free_tree, node);
            else
                ASSERT(false, "delay_free_tree inconsistent");
            info->delay_free_list[i].addr = NULL;
            shared_callstack_free(info->delay_free_list[i].pcs);
            info->delay_free_list[i].pcs = NULL;
            num_removed++;
        }
    }
    dr_mutex_unlock(delay_free_lock);
    LOG(2, "removed %d delayed frees from destroyed heap "PFX"\n",
        num_removed, heap);
}
#endif

bool
overlaps_delayed_free(byte *start, byte *end,
                      byte **free_start OUT, /* app base */
                      byte **free_end OUT,   /* app request size */
                      packed_callstack_t **pcs OUT,
                      bool delayed_only)
{
    bool res = false;
    rb_node_t *node;
    malloc_info_t info;
    info.struct_size = sizeof(info);
    if (options.delay_frees == 0)
        return false;
    if (options.replace_malloc) {
        /* replacement allocator is tracking all delayed frees, not us */
        bool found;
        if (delayed_only) {
            found = alloc_replace_overlaps_delayed_free(start, end, &info);
        } else {
            found = alloc_replace_overlaps_any_free(start, end, &info);
        }
        if (found) {
            if (free_start != NULL)
                *free_start = info.base;
            if (free_end != NULL)
                *free_end = info.base + info.request_size;
            /* There can be a race where this client_data is freed (due to
             * the delay-free or freed chunk being re-used), but our alloc_stack_table
             * refcount keeps it alive for the process lifetime.  So I see no
             * reason to hold a lock, and esp not to clone it here.
             */
            if (pcs != NULL)
                *pcs = (packed_callstack_t *) info.client_data;
        } else
            found = false;
        return found;
    }
    dr_mutex_lock(delay_free_lock);
    LOG(3, "overlaps_delayed_free "PFX"-"PFX"\n", start, end);
    DOLOG(3, { rb_iterate(delay_free_tree, print_free_tree, NULL); });
    node = rb_overlaps_node(delay_free_tree, start, end);
    if (node != NULL) {
        app_pc real_base;
        size_t size;
        delay_free_t *info;
        size_t redsz;
        res = true;
        rb_node_fields(node, &real_base, &size, (void **)&info);
        ASSERT(info != NULL, "invalid free tree info");
        redsz = (info->has_redzone ? options.redzone_size : 0);
        LOG(3, "\toverlap real base: "PFX", size: %d, redzone: %d\n",
            real_base, size, redsz);
        if (free_start != NULL)
            *free_start = real_base + redsz;
        /* we didn't store the requested size or padded size so we include
         * padding in free_end
         */
        if (free_end != NULL)
            *free_end = real_base + size - redsz;
        if (pcs != NULL) {
            if (info->pcs == NULL)
                *pcs = NULL;
            else
                *pcs = packed_callstack_clone(info->pcs);
        }
    }
    dr_mutex_unlock(delay_free_lock);
    return res;
}

void
client_handle_mmap(void *drcontext, app_pc base, size_t size, bool anon)
{
#ifdef WINDOWS
    if (options.shadowing) {
        if (anon) {
            /* XXX: we could pass in_heap_routine in as a bool if the overhead
             * of the CLS retrieval shows up
             */
            if (!alloc_in_heap_routine(drcontext))
                shadow_set_range(base, base+size, SHADOW_DEFINED);
            else {
                /* FIXME PR 575260: should we do what we do on linux and leave
                 * unaddr?  I haven't yet studied what Windows Heap behavior is
                 * for very large allocations.  For now marking entire
                 * as undefined and ignoring headers.
                 */
                shadow_set_range(base, base+size, SHADOW_UNDEFINED);
            }
        } else
            mmap_walk(base, size, IF_WINDOWS_(NULL) true/*add*/);
    }
#else
    if (anon) {
        /* Kernel sets to 0 but for malloc we want to treat as undefined
         * if a single large malloc chunk or as unaddressable if a new
         * malloc arena.  For calloc, or for non-alloc, we want defined.
         * We assume that post-malloc or post-calloc will take care of
         * marking however much of the mmap has been parceled out,
         * so we leave the region as unaddressable here, which handles
         * both the extra-large headers for single large chunks and
         * new arenas gracefully and without races (xref PR 427601, PR
         * 531619).
         */
        if (!alloc_in_heap_routine(drcontext) && options.shadowing)
            shadow_set_range(base, base+size, SHADOW_DEFINED);
        /* PR 418629: to determine stack bounds accurately we track mmaps */
        mmap_tree_add(base, size);
    } else if (options.shadowing) {
        /* mapping a file: if an image need to walk sub-regions.
         * FIXME: on linux though the sub-regions have their own
         * mmaps: wait for those?
         */
        mmap_walk(base, size, true/*add*/);
    }
#endif
    LOG(2, "mmap %s "PFX"-"PFX"\n", anon ? "anon" : "file",
        base, base+size);
}

void
client_handle_munmap(app_pc base, size_t size, bool anon)
{
#ifdef WINDOWS
    if (options.shadowing) {
        if (anon)
            shadow_set_range(base, base+size, SHADOW_UNADDRESSABLE);
        else
            mmap_walk(base, size, IF_WINDOWS_(NULL) false/*remove*/);
    }
#else
    /* anon not known to common/alloc.c so we see whether in the anon table */
    if (mmap_tree_remove(base, size)) {
        if (options.shadowing)
            shadow_set_range(base, base+size, SHADOW_UNADDRESSABLE);
    } else if (options.shadowing)
        mmap_walk(base, size, IF_WINDOWS_(NULL) false/*remove*/);
#endif
    LOG(2, "munmap %s "PFX"-"PFX"\n", anon ? "anon" : "file",
        base, base+size);
}

void
client_handle_munmap_fail(app_pc base, size_t size, bool anon)
{
#ifdef WINDOWS
    /* FIXME: need to restore shadow values by storing on pre-syscall */
    if (options.shadowing)
        mmap_walk(base, size, IF_WINDOWS_(NULL) true/*add*/);
#else
    if (anon) {
        /* FIXME: we need to store the shadow values in pre so we
         * can restore here.  We should also work that into our
         * race handling model.  Xref malloc race handling: but
         * that relies on detecting failures ahead of time.
         */
        if (options.shadowing)
            shadow_set_range(base, base+size, SHADOW_DEFINED);
        mmap_tree_add(base, size);
    } else if (options.shadowing)
        mmap_walk(base, size, true/*add*/);
#endif
}

#ifdef UNIX
void
client_handle_mremap(app_pc old_base, size_t old_size, app_pc new_base, size_t new_size,
                     bool image)
{
    bool shrink = (new_size < old_size);
    bool found;
    if (options.shadowing) {
        shadow_copy_range(old_base, new_base, shrink ? new_size : old_size);
        if (shrink) {
            shadow_set_range(old_base+new_size, old_base+old_size,
                             SHADOW_UNADDRESSABLE);
        } else {
            shadow_set_range(new_base+old_size, new_base+new_size,
                             image ? SHADOW_DEFINED : SHADOW_UNDEFINED);
        }
    }
    found = mmap_tree_remove(old_base, old_size);
    if (found) {
        /* an anon region */
        mmap_tree_add(new_base, new_size);
    }
}
#endif

#ifdef WINDOWS
static void
handle_Ki(void *drcontext, app_pc pc, byte *new_xsp, bool is_cb)
{
    /* The kernel has placed some data on the stack.  We assume we're
     * on the same thread stack.  FIXME: check those assumptions by checking
     * default stack bounds.
     */
    app_pc sp = new_xsp;
    TEB *teb = get_TEB();
    app_pc base_esp = teb->StackBase;
    app_pc stop_esp = NULL;
    umbra_shadow_memory_info_t info;
    if (!options.shadowing || !options.check_stack_bounds)
        return;
    umbra_shadow_memory_info_init(&info);

    if (sp < base_esp && base_esp - sp < TYPICAL_STACK_MIN_SIZE)
        stop_esp = base_esp;
    ASSERT(ALIGNED(sp, 4), "stack not aligned");
    while ((stop_esp == NULL || sp < stop_esp) &&
           /* if not on main stack, we could walk off into an adjacent
            * free space: should do mem query!
            */
           shadow_get_byte(&info, sp) == SHADOW_UNADDRESSABLE) {
        shadow_set_byte(&info, sp, SHADOW_DEFINED);
        if (MAP_4B_TO_1B)
            sp += 4; /* 4 bytes map to one so skip to next */
        else
            sp++;
        if (sp - new_xsp >= TYPICAL_STACK_MIN_SIZE) {
            ASSERT(false, "kernel-placed data on stack too large: error?");
            break; /* abort */
        }
    }
    ASSERT(ALIGNED(sp, 4), "stack not aligned");

    LOG(2, "Ki routine "PFX": marked stack "PFX"-"PFX" as defined\n",
        pc, new_xsp, sp);

    if (is_cb) {
        /* drmgr already pushed a new context */
        cls_drmem_t *cpt_parent = (cls_drmem_t *)
            drmgr_get_parent_cls_field(drcontext, cls_idx_drmem);
        ASSERT(cpt_parent != NULL, "drmgr should have pushed context already");
        if (cpt_parent == NULL)
            return; /* don't crash in release build  */
        LOG(3, "cb: cpt_parent is "PFX", cpt is "PFX"\n",
            cpt_parent, drmgr_get_cls_field(drcontext, cls_idx_drmem));
        cpt_parent->pre_callback_esp = sp;
    }
}

static void
handle_callback(void *drcontext)
{
    LOG(2, "Entering windows callback handler\n");
    syscall_handle_callback(drcontext);
}

static void
handle_cbret(void *drcontext, const dr_kernel_xfer_info_t *xfer_info)
{
    umbra_shadow_memory_info_t info;
    byte *sp = (byte *) xfer_info->source_mcontext->xsp;
    cls_drmem_t *cpt_parent = (cls_drmem_t *)
        drmgr_get_parent_cls_field(drcontext, cls_idx_drmem);
    if (cpt_parent == NULL) /* DR took over in middle of callback */
        return;
    if (!options.shadowing)
        return;
    syscall_handle_cbret(drcontext);

    if (!options.check_stack_bounds)
        return;

    ASSERT(cpt_parent->pre_callback_esp == (byte *)xfer_info->target_xsp,
           "cb xsp mismatch");
    LOG(2, "cbret: marking stack "PFX"-"PFX" as unaddressable\n",
        sp, cpt_parent->pre_callback_esp);
    LOG(3, "cbret: cpt_parent is "PFX", cpt is "PFX"\n",
        cpt_parent, drmgr_get_cls_field(drcontext, cls_idx_drmem));
    umbra_shadow_memory_info_init(&info);
    for (; sp < cpt_parent->pre_callback_esp; sp++)
        shadow_set_byte(&info, sp, SHADOW_UNADDRESSABLE);
}

static void
handle_exception(void *drcontext)
{
    cls_drmem_t *cpt = (cls_drmem_t *) drmgr_get_cls_field(drcontext, cls_idx_drmem);
    cpt->heap_critsec = NULL;
}

static void
handle_continue(void *drcontext)
{
    /* We rely on this running *before* alloc.c's so is_in_seh() is correct. */
    cls_drmem_t *cpt = (cls_drmem_t *) drmgr_get_cls_field(drcontext, cls_idx_drmem);
    if (is_in_seh(drcontext)) {
        cpt->heap_critsec = NULL;
    } /* else it was an APC */
}
#endif /* WINDOWS */

void
client_stack_alloc(byte *start, byte *end, bool defined)
{
    if (options.shadowing &&
        (options.check_uninitialized || options.check_stack_bounds)) {
        shadow_set_range(start, end, defined ? SHADOW_DEFINED : SHADOW_UNDEFINED);
        if (BEYOND_TOS_REDZONE_SIZE > 0) {
            shadow_set_range(start - BEYOND_TOS_REDZONE_SIZE,
                             end - BEYOND_TOS_REDZONE_SIZE, SHADOW_UNDEFINED);
        }
    }
}

void
client_stack_dealloc(byte *start, byte *end)
{
    if (options.shadowing &&
        (options.check_uninitialized || options.check_stack_bounds)) {
        if (BEYOND_TOS_REDZONE_SIZE > 0) {
            shadow_set_range(start, end, SHADOW_UNDEFINED);
            shadow_set_range(start - BEYOND_TOS_REDZONE_SIZE,
                             end - BEYOND_TOS_REDZONE_SIZE, SHADOW_UNADDRESSABLE);
        } else
            shadow_set_range(start, end, SHADOW_UNADDRESSABLE);
    }
    if (options.shadowing && options.check_uninitialized)
        register_shadow_set_ptrsz(DR_REG_PTR_RETURN, SHADOW_PTRSZ_DEFINED);
}

/* Non-interpreted code about to write to app-visible memory */
bool
client_write_memory(byte *start, size_t size, dr_mcontext_t *mc)
{
    if (options.shadowing) {
        app_loc_t loc;
        pc_to_loc(&loc, mc->pc);
        return handle_mem_ref(MEMREF_WRITE, &loc, start, size, mc);
    }
    return true;
}

/* Non-interpreted code about to read to app-visible memory */
bool
client_read_memory(byte *start, size_t size, dr_mcontext_t *mc)
{
    if (options.shadowing) {
        app_loc_t loc;
        pc_to_loc(&loc, mc->pc);
        return handle_mem_ref(MEMREF_CHECK_ADDRESSABLE|MEMREF_IS_READ, &loc,
                              start, size, mc);
    }
    return true;
}

#ifdef DEBUG
void
client_print_callstack(void *drcontext, dr_mcontext_t *mc, app_pc pc)
{
    print_callstack_to_file(drcontext, mc, pc, INVALID_FILE/*use pt->f*/,
                            options.callstack_max_frames);
}
#endif

/***************************************************************************
 * SIGNALS AND SYSTEM CALLS
 */

#ifdef WINDOWS
static void
adjust_stack_to_context(dr_mcontext_t *mc, reg_t cxt_xsp _IF_DEBUG(const char *prefix))
{
    if (cxt_xsp < mc->xsp) {
        if (mc->xsp - cxt_xsp < options.stack_swap_threshold) {
            shadow_set_range((byte *) cxt_xsp, (byte *) mc->xsp, SHADOW_UNDEFINED);
            LOG(2, "%s: marked stack "PFX"-"PFX" as undefined\n",
                prefix, cxt_xsp, mc->xsp);
        } else
            LOG(2, "%s: assuming stack swap "PFX" => "PFX"\n", prefix, mc->xsp, cxt_xsp);
    } else if (cxt_xsp - mc->xsp < options.stack_swap_threshold) {
        shadow_set_range((byte *) mc->xsp, (byte *) cxt_xsp, SHADOW_UNADDRESSABLE);
        LOG(2, "%s: marked stack "PFX"-"PFX" as unaddressable\n",
            prefix, mc->xsp, cxt_xsp);
    } else
        LOG(2, "%s: assuming stack swap "PFX" => "PFX"\n", prefix, mc->xsp, cxt_xsp);
}
#endif

void
client_pre_syscall(void *drcontext, int sysnum)
{
#ifdef WINDOWS
    DWORD cxt_flags;
    reg_t cxt_xsp;
#endif
    dr_mcontext_t mc; /* do not init whole thing: memset is expensive */
    mc.size = sizeof(mc);
    mc.flags = DR_MC_CONTROL|DR_MC_INTEGER; /* don't need xmm */
    if (!options.shadowing)
        return;
    dr_get_mcontext(drcontext, &mc);
#ifdef WINDOWS
    if (!options.check_stack_bounds)
        return;
    if (sysnum == sysnum_continue) {
        /* XXX: we could move this to the kernel xfer event */
        CONTEXT *cxt = (CONTEXT *) dr_syscall_get_param(drcontext, 0);
        umbra_shadow_memory_info_t info;
        umbra_shadow_memory_info_init(&info);
        if (cxt != NULL &&
            safe_read(&cxt->ContextFlags, sizeof(cxt_flags), &cxt_flags) &&
            safe_read(&cxt->Xsp, sizeof(cxt_xsp), &cxt_xsp)) {
            /* FIXME: what if the syscall fails? */
            if (TESTALL(CONTEXT_CONTROL/*2 bits so ALL*/, cxt_flags)) {
                register_shadow_set_ptrsz(REG_XSP,
                                          shadow_get_ptrsz(&info, (app_pc)&cxt->Xsp));
# ifndef X64
                register_shadow_set_ptrsz(REG_XBP,
                                          shadow_get_ptrsz(&info, (app_pc)&cxt->Xbp));
# endif
            }
            if (TESTALL(CONTEXT_INTEGER/*2 bits so ALL*/, cxt_flags)) {
                register_shadow_set_ptrsz(REG_XAX,
                                          shadow_get_ptrsz(&info, (app_pc)&cxt->Xax));
                register_shadow_set_ptrsz(REG_XCX,
                                          shadow_get_ptrsz(&info, (app_pc)&cxt->Xcx));
                register_shadow_set_ptrsz(REG_XDX,
                                          shadow_get_ptrsz(&info, (app_pc)&cxt->Xdx));
                register_shadow_set_ptrsz(REG_XBX,
                                          shadow_get_ptrsz(&info, (app_pc)&cxt->Xbx));
# ifdef X64
                register_shadow_set_ptrsz(REG_XBP,
                                          shadow_get_ptrsz(&info, (app_pc)&cxt->Xbp));
# endif
                register_shadow_set_ptrsz(REG_XSI,
                                          shadow_get_ptrsz(&info, (app_pc)&cxt->Xsi));
                register_shadow_set_ptrsz(REG_XDI,
                                          shadow_get_ptrsz(&info, (app_pc)&cxt->Xdi));
            }
            /* Mark stack AFTER reading cxt since cxt may be on stack! */
            if (TESTALL(CONTEXT_CONTROL/*2 bits so ALL*/, cxt_flags)) {
                adjust_stack_to_context(&mc, cxt_xsp _IF_DEBUG("NtContinue"));
            }
        } else {
            WARN("WARNING: NtContinue: failed to adjust stack\n");
        }
    } else if (sysnum == sysnum_setcontext) {
        /* FIXME PR 575434: we need to know whether the thread is in this
         * process or not, and then get its current context so we can
         * change the esp between old and new values and set the register
         * shadow values.
         */
        ASSERT(false, "NtSetContextThread NYI");
    } else if (sysnum == sysnum_RaiseException) {
        /* i#87: the kernel will place the args to KiUserExceptionDispatcher on
         * the stack at the stack pointer in the CONTEXT, not the current stack
         * pointer.
         */
        CONTEXT *cxt = (CONTEXT *) dr_syscall_get_param(drcontext, 1);
        if (cxt != NULL &&
            safe_read(&cxt->ContextFlags, sizeof(cxt_flags), &cxt_flags) &&
            TESTALL(CONTEXT_CONTROL/*2 bits so ALL*/, cxt_flags) &&
            safe_read(&cxt->Xsp, sizeof(cxt_xsp), &cxt_xsp)) {
            /* FIXME: what if the syscall fails? */
            adjust_stack_to_context(&mc, cxt_xsp _IF_DEBUG("NtRaiseException"));
        } else {
            WARN("WARNING: NtRaiseException: failed to adjust stack\n");
        }
    }
#else
    cls_drmem_t *cpt = (cls_drmem_t *) drmgr_get_cls_field(drcontext, cls_idx_drmem);
    if (sysnum == SYS_sigaltstack) {
        /* PR 406333: linux signal delivery */
        stack_t stk;
        cpt->prev_sigaltstack = cpt->sigaltstack;
        cpt->prev_sigaltsize = cpt->sigaltsize;
        if (safe_read((void *)syscall_get_param(drcontext, 0), sizeof(stk), &stk)) {
            if (stk.ss_flags == SS_DISABLE) {
                cpt->sigaltstack = NULL;
                cpt->sigaltsize = 0;
                /* Mark the old stack as addressable in case used as data now? */
            } else {
                /* We want the base (== highest addr) */
                cpt->sigaltstack = ((byte *) stk.ss_sp) + stk.ss_size;
                cpt->sigaltsize = stk.ss_size;
                ASSERT((cpt->sigaltstack < (byte*)mc.xsp ||
                        (ptr_int_t)cpt->sigaltstack - cpt->sigaltsize - mc.xsp >
                        options.stack_swap_threshold) &&
                       (cpt->sigaltstack > (byte*)mc.xsp ||
                        mc.xsp - ((ptr_int_t)cpt->sigaltstack + cpt->sigaltsize) >
                        options.stack_swap_threshold),
                       "sigaltstack within swap threshold of esp");
                /* We assume this memory will not be used for any other data */
                LOG(2, "marking sigaltstack "PFX"-"PFX" unaddressable\n",
                    stk.ss_sp, cpt->sigaltstack);
                shadow_set_range((app_pc)stk.ss_sp, cpt->sigaltstack,
                                 options.check_stack_bounds ? SHADOW_DEFINED :
                                 SHADOW_UNADDRESSABLE);
            }
            LOG(2, "new sigaltstack "PFX"\n", cpt->sigaltstack);
        } else {
            LOG(2, "WARNING: can't read sigaltstack param "PFX"\n",
                syscall_get_param(drcontext, 0));
        }
    }
#endif /* WINDOWS */
}

void
client_post_syscall(void *drcontext, int sysnum)
{
#ifdef UNIX
    ptr_int_t result = dr_syscall_get_result(drcontext);
    cls_drmem_t *cpt = (cls_drmem_t *) drmgr_get_cls_field(drcontext, cls_idx_drmem);
    if (!options.shadowing)
        return;
    if (sysnum == SYS_sigaltstack) {
        if (result != 0) {
            /* We can't query the OS since DR is hiding the real sigaltstack,
             * so we record the prev value
             */
            cpt->sigaltstack = cpt->prev_sigaltstack;
            cpt->sigaltsize = cpt->prev_sigaltsize;
            LOG(2, "sigaltstack failed, reverting to "PFX"\n", cpt->sigaltstack);
        }
    }
#endif
}

#ifdef UNIX
dr_signal_action_t
event_signal_alloc(void *drcontext, dr_siginfo_t *info)
{
    if (options.shadowing) {
        /* no longer trying to store the interrupted xsp b/c it
         * gets too complicated (xref PR 620746)
         */
        LOG(2, "signal interrupted app at xsp="PFX"\n", info->mcontext->xsp);
    }
    return DR_SIGNAL_DELIVER;
}

static void
handle_signal_delivery(void *drcontext, reg_t dst_xsp)
{
    /* PR 406333: linux signal delivery.
     * Need to know extent of frame: could record xsp in signal event,
     * and record SYS_sigaltstack.
     * However, we can't tie together the signal event and handler
     * invocation, b/c of ignored and default actions, nested signals,
     * pseudo-nested signals (new signals coming in after the frame
     * copy but before executing the handler), etc. (xref PR 620746).
     * The most robust solution would be to have DR provide an event
     * "adjust_app_stack_for_signal" and call it whenever copying a
     * frame to the app stack or processing a sigreturn, providing us
     * w/ the old and new xsp: but that doesn't fit w/ the rest of the
     * DR API, so we're walking unaddr until we hit either addr,
     * the max frame size, or the top of the alt stack.
     * There is a pathological case where the app gets a signal while
     * at the very base of a stack and we could walk off onto
     * adjacent memory: we ignore that.
     */
    cls_drmem_t *cpt = (cls_drmem_t *) drmgr_get_cls_field(drcontext, cls_idx_drmem);
    dr_mcontext_t mc; /* do not init whole thing: memset is expensive */
    byte *sp, *stop;
    umbra_shadow_memory_info_t info;
    umbra_shadow_memory_info_init(&info);

    ASSERT(options.shadowing, "shadowing disabled");
    mc.size = sizeof(mc);
    mc.flags = DR_MC_CONTROL; /* only need xsp */
    dr_get_mcontext(drcontext, &mc);
    sp = (byte *)mc.xsp;
    stop = sp + MAX_SIGNAL_FRAME_SIZE;
    if (cpt->sigaltstack != NULL &&
        cpt->sigaltstack > (app_pc) mc.xsp &&
        (size_t)(cpt->sigaltstack - (app_pc) mc.xsp) < cpt->sigaltsize &&
        stop > cpt->sigaltstack)
        stop = cpt->sigaltstack;
    /* XXX: we could probably assume stack alignment at start of handler */
    while (sp < stop && shadow_get_byte(&info, sp) == SHADOW_UNADDRESSABLE) {
        /* Assume whole frame is defined (else would need DR to identify
         * which parts are padding).
         */
        shadow_set_byte(&info, sp, SHADOW_DEFINED);
        sp++;
    }
    if (BEYOND_TOS_REDZONE_SIZE > 0) {
        shadow_set_range((byte *)mc.xsp - BEYOND_TOS_REDZONE_SIZE, (byte *)mc.xsp,
                         SHADOW_UNDEFINED);
    }
    LOG(2, "signal handler: marked new frame defined "PFX"-"PFX"\n", mc.xsp, sp);
}

static void
handle_signal_return(void *drcontext, const dr_mcontext_t *src_mc, byte *new_sp)
{
    ASSERT(options.shadowing && options.check_stack_bounds, "incorrectly called");
    ASSERT(src_mc != NULL && TEST(DR_MC_CONTROL, src_mc->flags),
           "src_mc should always exist for sigreturn");
    cls_drmem_t *cpt = (cls_drmem_t *) drmgr_get_cls_field(drcontext, cls_idx_drmem);
    byte *sp = (byte *)src_mc->xsp;
    byte *unaddr_top = NULL;
    if (new_sp > sp && (size_t)(new_sp - sp) < MAX_SIGNAL_FRAME_SIZE) {
        unaddr_top = new_sp;
    } else if (cpt->sigaltstack != NULL && cpt->sigaltstack > sp &&
               (size_t)(cpt->sigaltstack - sp) < cpt->sigaltsize) {
        /* transitioning from sigaltstack to regular stack */
        unaddr_top = cpt->sigaltstack;
    } else {
        LOG(2, "at sigreturn but new sp "PFX" irregular vs "PFX"\n", new_sp, sp);
    }
    if (unaddr_top != NULL) {
        LOG(2, "at sigreturn: marking frame "PFX"-"PFX" unaddressable\n",
            sp, unaddr_top);
        shadow_set_range(sp, unaddr_top, SHADOW_UNADDRESSABLE);
    }
}
#endif /* UNIX */

void
event_kernel_xfer(void *drcontext, const dr_kernel_xfer_info_t *info)
{
#ifdef UNIX
    if (!options.shadowing || !options.check_stack_bounds)
        return;
    if (info->type == DR_XFER_SIGNAL_DELIVERY)
        handle_signal_delivery(drcontext, info->target_xsp);
    else if (info->type == DR_XFER_SIGNAL_RETURN)
        handle_signal_return(drcontext, info->source_mcontext, (byte *)info->target_xsp);
#else
    if (info->type == DR_XFER_CALLBACK_DISPATCHER) {
        handle_Ki(drcontext, info->target_pc, (byte*)info->target_xsp, true);
        handle_callback(drcontext);
    }
    else if (info->type == DR_XFER_CALLBACK_RETURN)
        handle_cbret(drcontext, info);
    else if (info->type == DR_XFER_APC_DISPATCHER ||
             info->type == DR_XFER_RAISE_DISPATCHER)
        handle_Ki(drcontext, info->target_pc, (byte*)info->target_xsp, false);
    else if (info->type == DR_XFER_EXCEPTION_DISPATCHER) {
        handle_exception(drcontext);
        handle_Ki(drcontext, info->target_pc, (byte*)info->target_xsp, false);
    }
    else if (info->type == DR_XFER_CONTINUE)
        handle_continue(drcontext);
#endif
}

/***************************************************************************
 * ADDRESSABILITY
 */

#ifdef X86 /* replacement should avoid needing to port this to ARM */
static bool
is_rawmemchr_pattern(void *drcontext, bool write, app_pc pc, app_pc next_pc,
                     app_pc addr, uint sz, instr_t *inst, bool *now_addressable OUT)
{
    /* PR 406535: glibc's rawmemchr does some bit tricks that can end
     * up using unaddressable or undefined values.  The erroneous load
     * is one of these:
     *   +0  8b 08                mov    (%eax) -> %ecx
     *   +0  8b 48 04             mov    0x4(%eax),%ecx
     *   +0  8b 48 08             mov    0x08(%eax) -> %ecx
     *   +0  8b 48 0c             mov    0x0c(%eax) -> %ecx
     * followed by the magic constant:
     *   +2  ba ff fe fe fe       mov    $0xfefefeff -> %edx
     * followed by an add, or an xor and then an add, and then a jcc:
     *   +7  01 ca                add    %ecx %edx -> %edx
     *   +9  73 59                jnb    $0x009041c7
     * since the particular registers and mem sources vary, we don't do
     * raw bit comparisons and instead do high-level operand comparisons.
     * in fact, we try to also match very similar patterns in strcat,
     * strlen, strrchr, and memchr.
     *
     * strchr and strchrnul have an xor in between the load and the magic
     * constant which we also match:
     *   +0  8b 08                mov    (%eax),%ecx
     *   +2  31 d1                xor    %edx,%ecx
     *   +4  bf ff fe fe fe       mov    $0xfefefeff,%edi
     *
     * on Windows we have __from_strstr_to_strchr in intel/strchr.asm:
     *   +11  8b 0a               mov    (%edx) -> %ecx
     *   +13  bf ff fe fe 7e      mov    $0x7efefeff -> %edi
     *
     * xref PR 485131: propagate partial-unaddr on loads?  but would still
     * complain on the jnb.
     *
     * FIXME: share code w/ check_undefined_reg_exceptions() in slowpath.c.
     */
    instr_t next;
    app_pc dpc = next_pc;
    bool match = false;
    instr_init(drcontext, &next);
    if (!safe_decode(drcontext, dpc, &next, &dpc))
        return false;
    /* We want to only allow the end of the search to be suppressed, to
     * avoid suppressing a real positive, so only unaligned addresses.
     */
    if (!ALIGNED(addr, 4) &&
        instr_get_opcode(inst) == OP_mov_ld &&
        opnd_is_reg(instr_get_dst(inst, 0)) &&
        opnd_get_size(instr_get_dst(inst, 0)) == OPSZ_PTR) {
        if (instr_valid(&next) &&
            instr_get_opcode(&next) == OP_xor &&
            opnd_is_reg(instr_get_src(&next, 0)) &&
            opnd_is_reg(instr_get_dst(&next, 0)) &&
            opnd_get_size(instr_get_dst(&next, 0)) == OPSZ_PTR) {
            /* Skip the strchr/strchnul xor */
            instr_reset(drcontext, &next);
            if (!safe_decode(drcontext, dpc, &next, &dpc))
                goto is_rawmemchr_pattern_done;
        }
        if (instr_valid(&next) &&
            instr_get_opcode(&next) == OP_mov_imm &&
            (opnd_get_immed_int(instr_get_src(&next, 0)) == 0xfefefeff ||
             opnd_get_immed_int(instr_get_src(&next, 0)) == 0x7efefeff) &&
            opnd_is_reg(instr_get_dst(&next, 0))) {
            STATS_INC(strmem_unaddr_exception);
            *now_addressable = false;
            match = true;
        }
    }
 is_rawmemchr_pattern_done:
    instr_free(drcontext, &next);
    return match;
}
#endif /* X86 */

bool
is_alloca_pattern(void *drcontext, app_pc pc, app_pc next_pc, instr_t *inst,
                  bool *now_addressable OUT)
{
    /* Check for alloca probes to trigger guard pages.
     * So far we've seen just a handful of different sequences:
         UNADDRESSABLE ACCESS: pc @0x0040db67 reading 0x0012ef80
         UNADDRESSABLE ACCESS: pc @0x0040db67 reading 0x0012ef81
         UNADDRESSABLE ACCESS: pc @0x0040db67 reading 0x0012ef82
         UNADDRESSABLE ACCESS: pc @0x0040db67 reading 0x0012ef83
         UNADDRESSABLE ACCESS: pc @0x0040db74 reading 0x0012ed48
         UNADDRESSABLE ACCESS: pc @0x0040db74 reading 0x0012ed49
         UNADDRESSABLE ACCESS: pc @0x0040db74 reading 0x0012ed4a
         UNADDRESSABLE ACCESS: pc @0x0040db74 reading 0x0012ed4b

         hello!_alloca_probe+0xc [intel\chkstk.asm @ 76]:
            76 0040db5c 81e900100000     sub     ecx,0x1000
            77 0040db62 2d00100000       sub     eax,0x1000
            79 0040db67 8501             test    [ecx],eax
            81 0040db69 3d00100000       cmp     eax,0x1000
            82 0040db6e 73ec             jnb     hello!_alloca_probe+0xc (0040db5c)
         hello!_alloca_probe+0x20 [intel\chkstk.asm @ 85]:
            85 0040db70 2bc8             sub     ecx,eax
            86 0040db72 8bc4             mov     eax,esp
            88 0040db74 8501             test    [ecx],eax
            90 0040db76 8be1             mov     esp,ecx
            92 0040db78 8b08             mov     ecx,[eax]
            93 0040db7a 8b4004           mov     eax,[eax+0x4]
            95 0040db7d 50               push    eax
            97 0040db7e c3               ret

         ntdll!_alloca_probe+0x15:
           7d61042d f7d8             neg     eax
           7d61042f 03c4             add     eax,esp
           7d610431 83c004           add     eax,0x4
           7d610434 8500             test    [eax],eax
           7d610436 94               xchg    eax,esp
           7d610437 8b00             mov     eax,[eax]
           7d610439 50               push    eax
           7d61043a c3               ret
         in this instance the probe goes 4 bytes into the stack instead
         of extending it, and then after shortening esp reads beyond TOS
         to move the retaddr to the new TOS!
           memref: read @0x7d610434 0x0007e2f0 0x4
           esp adjust esp=0x0007e2ec => 0x0007e2f0
           set range 0x0007e2ec-0x0007e2f0 => 0x0
           memref: read @0x7d610437 0x0007e2ec 0x4
           UNADDRESSABLE ACCESS: pc @0x7d610437 reading 0x0007e2ec
         though this also occurs as ntdll!_chkstk where the probe does go beyond TOS:
         depends on value of eax == amount checking/probing by

        cygwin1!alloca:
          610fc670 51               push    ecx
          610fc671 89e1             mov     ecx,esp
          610fc673 83c108           add     ecx,0x8
          610fc676 3d00100000       cmp     eax,0x1000
          610fc67b 7210             jb      cygwin1!alloca+0x1d (610fc68d)
          610fc67d 81e900100000     sub     ecx,0x1000
          610fc683 830900           or      dword ptr [ecx],0x0
          610fc686 2d00100000       sub     eax,0x1000
          610fc68b ebe9             jmp     cygwin1!alloca+0x6 (610fc676)
          610fc68d 29c1             sub     ecx,eax
          610fc68f 830900           or      dword ptr [ecx],0x0
          610fc692 89e0             mov     eax,esp
          610fc694 89cc             mov     esp,ecx
          610fc696 8b08             mov     ecx,[eax]
          610fc698 8b4004           mov     eax,[eax+0x4]
          610fc69b ffe0             jmp     eax

        gap.exe:
          00444bf2 2d00100000       sub     eax,0x1000
          00444bf7 8500             test    [eax],eax
          00444bf9 ebe9             jmp     gap+0x44be4 (00444be4)
          00444bfb cc               int     3
          0:000> U 00444be4
          00444be4 3bc8             cmp     ecx,eax
          00444be6 720a             jb      gap+0x44bf2 (00444bf2)

        Compaq Visual Fortran alloca (i#449) is very similar to the
        _alloca_probe sequences above, but uses edi or sometimes esi:
          0040108a 0507000000       add     eax,0x7
          0040108f 25f8ffffff       and     eax,0xfffffff8
          00401094 3d00100000       cmp     eax,0x1000
          00401099 7e14             jle     A+0x10af (004010af)
          0040109b 81ef00100000     sub     edi,0x1000
          004010a1 2d00100000       sub     eax,0x1000
          004010a6 8507             test    [edi],eax
          004010a8 3d00100000       cmp     eax,0x1000
          004010ad 7fec             jg      A+0x109b (0040109b)
          004010af 2bf8             sub     edi,eax
          004010b1 8507             test    [edi],eax
          004010b3 8be7             mov     esp,edi

        We also see handle!_chkstk:
          00a6cc52 2d00100000       sub     eax,0x1000
          00a6cc57 8500             test    [eax],eax
          00a6cc59 ebe9             jmp     handle!_chkstk+0x14 (00a6cc44)
        the pattern is the same as gap.exe.

      x64:
        varstack!__chkstk+0x30 [f:\dd\vctools\crt\crtw32\startup\amd64\chkstk.asm @ 108]:
          00007ff7`a8071710 4d8d9b00f0ffff  lea     r11,[r11-1000h]
          00007ff7`a8071717 41c60300        mov     byte ptr [r11],0
          00007ff7`a807171b 4d3bd3          cmp     r10,r11

    */
    /* For now we do an exact pattern match but of course this
     * won't generalize well for other versions of alloca: OTOH we
     * don't want any false negatives.
     */
#ifdef X86
    instr_t next;
    app_pc dpc = next_pc;
    bool match = false;
    byte prev_byte;
    instr_init(drcontext, &next);

    if (instr_get_opcode(inst) == OP_test &&
        opnd_is_base_disp(instr_get_src(inst, 0)) &&
        /* base varies: I've seen eax, ecx, edi, esi */
        opnd_get_index(instr_get_src(inst, 0)) == REG_NULL &&
        opnd_get_scale(instr_get_src(inst, 0)) == 0 &&
        opnd_get_disp(instr_get_src(inst, 0)) == 0 &&
        opnd_is_reg(instr_get_src(inst, 1)) &&
        opnd_get_reg(instr_get_src(inst, 1)) == REG_EAX) {
        reg_id_t test_base = opnd_get_base(instr_get_src(inst, 0));
        instr_reset(drcontext, &next);
        if (!safe_decode(drcontext, dpc, &next, &dpc))
            return match;
        if (instr_valid(&next) &&
            ((instr_get_opcode(&next) == OP_cmp &&
              opnd_is_reg(instr_get_src(&next, 0)) &&
              opnd_get_reg(instr_get_src(&next, 0)) == REG_EAX &&
              opnd_is_immed_int(instr_get_src(&next, 1))) ||
             ((instr_get_opcode(&next) == OP_mov_ld ||
               instr_get_opcode(&next) == OP_mov_st) &&
              opnd_is_reg(instr_get_src(&next, 0)) &&
              opnd_get_reg(instr_get_src(&next, 0)) == test_base &&
              opnd_is_reg(instr_get_dst(&next, 0)) &&
              opnd_get_reg(instr_get_dst(&next, 0)) == REG_ESP) ||
             (instr_get_opcode(&next) == OP_xchg &&
              opnd_is_reg(instr_get_src(&next, 0)) &&
              opnd_get_reg(instr_get_src(&next, 0)) == REG_ESP) ||
             (instr_get_opcode(&next) == OP_jmp ||
              instr_get_opcode(&next) == OP_jmp_short))) {
            match = true;
            /* this is a probe to commit the page: does not change range of
             * stack pointer
             */
            *now_addressable = false;
        }
    }
    /* ntdll!_chkstk retaddr shift */
    else if (instr_get_opcode(inst) == OP_mov_ld &&
             opnd_is_base_disp(instr_get_src(inst, 0)) &&
             opnd_get_base(instr_get_src(inst, 0)) == REG_EAX &&
             opnd_get_index(instr_get_src(inst, 0)) == REG_NULL &&
             opnd_get_scale(instr_get_src(inst, 0)) == 0 &&
             opnd_get_disp(instr_get_src(inst, 0)) == 0 &&
             opnd_is_reg(instr_get_dst(inst, 0)) &&
             opnd_get_reg(instr_get_dst(inst, 0)) == REG_EAX &&
             /* prev instr is "xchg esp, eax" */
             safe_read(pc-1, sizeof(prev_byte), &prev_byte) &&
             prev_byte == 0x94) {
        match = true;
        /* do NOT mark addressable as the next instr, a push, will do so */
        *now_addressable = false;
    }
    /* cygwin alloca */
    else if (instr_get_opcode(inst) == OP_or &&
             opnd_is_base_disp(instr_get_dst(inst, 0)) &&
             opnd_get_base(instr_get_dst(inst, 0)) == REG_ECX &&
             opnd_get_index(instr_get_dst(inst, 0)) == REG_NULL &&
             opnd_get_scale(instr_get_dst(inst, 0)) == 0 &&
             opnd_get_disp(instr_get_dst(inst, 0)) == 0 &&
             opnd_is_immed_int(instr_get_src(inst, 0)) &&
             opnd_get_immed_int(instr_get_src(inst, 0)) == 0) {
        /* or of memory with 0 unusual enough that we look only at that instr */
        match = true;
        /* this is a probe to commit the page: does not change range of
         * stack pointer
         */
        *now_addressable = false;
    }
# ifdef X64
    else if (instr_get_opcode(inst) == OP_mov_st &&
             opnd_is_base_disp(instr_get_dst(inst, 0)) &&
             opnd_get_base(instr_get_dst(inst, 0)) == DR_REG_R11 &&
             opnd_get_index(instr_get_dst(inst, 0)) == REG_NULL &&
             opnd_get_scale(instr_get_dst(inst, 0)) == 0 &&
             opnd_get_disp(instr_get_dst(inst, 0)) == 0 &&
             opnd_is_immed_int(instr_get_src(inst, 0)) &&
             opnd_get_immed_int(instr_get_src(inst, 0)) == 0 &&
             /* prev instr is "lea r11,[r11-1000h]" */
             safe_read(pc-1, sizeof(prev_byte), &prev_byte) &&
             prev_byte == 0xff) {
        match = true;
        /* do NOT mark addressable as the next instr, a push, will do so */
        *now_addressable = false;
    }
# endif
    instr_free(drcontext, &next);

    return match;
#elif defined(ARM)
    /* FIXME i#1726: add ARM patterns */
    return false;
#endif
}

#ifdef X86 /* replacement should avoid needing to port this to ARM */
static bool
is_strlen_pattern(void *drcontext, bool write, app_pc pc, app_pc next_pc,
                  app_pc addr, uint sz, instr_t *inst, bool *now_addressable OUT)
{
    /* Check for intel\strlen.asm case where it reads 4 bytes for efficiency:
     * it only does so if aligned, so no danger of touching next page, and
     * though it does look at the extra bytes the string should terminate
     * in the valid bytes.  So, while ugly, technically it's an ok bug to suppress.
     *    hello!strlen+0x30 [F:\SP\vctools\crt_bld\SELF_X86\crt\src\intel\strlen.asm @ 81]:
     *       81 00405f80 8b01             mov     eax,[ecx]
     *       82 00405f82 bafffefe7e       mov     edx,0x7efefeff
     *       83 00405f87 03d0             add     edx,eax
     *       84 00405f89 83f0ff           xor     eax,0xffffffff
     *       85 00405f8c 33c2             xor     eax,edx
     *       86 00405f8e 83c104           add     ecx,0x4
     *       87 00405f91 a900010181       test    eax,0x81010100
     *       88 00405f96 74e8             jz      hello!strlen+0x30 (00405f80)
     *    hello!strlen+0x48 [F:\SP\vctools\crt_bld\SELF_X86\crt\src\intel\strlen.asm @ 90]:
     *       90 00405f98 8b41fc           mov     eax,[ecx-0x4]
     *       91 00405f9b 84c0             test    al,al
     *       92 00405f9d 7432             jz      hello!strlen+0x81 (00405fd1)
     *
     * variant:
     *    gap+0x4516e:
     *    0044516e bafffefe7e       mov     edx,0x7efefeff
     *    00445173 8b06             mov     eax,[esi]
     *    00445175 03d0             add     edx,eax
     *    00445177 83f0ff           xor     eax,0xffffffff
     *    0044517a 33c2             xor     eax,edx
     *    0044517c 8b16             mov     edx,[esi]
     *    0044517e 83c604           add     esi,0x4
     *    00445181 a900010181       test    eax,0x81010100
     */
    instr_t next;
    app_pc dpc = next_pc;
    bool match = false;
    instr_init(drcontext, &next);
    /* FIXME PR 406718: for this, and exceptions below, we should ensure that only
     * the final byte(s) are unaddressable, and not allow middle bytes or
     * any other real positive to slip through
     */
    if (!ALIGNED(addr, 4) &&
        instr_get_opcode(inst) == OP_mov_ld &&
        opnd_is_base_disp(instr_get_src(inst, 0)) &&
        opnd_get_base(instr_get_src(inst, 0)) == REG_ECX &&
        opnd_get_index(instr_get_src(inst, 0)) == REG_NULL &&
        opnd_get_scale(instr_get_src(inst, 0)) == 0 &&
        (opnd_get_disp(instr_get_src(inst, 0)) == 0 ||
         opnd_get_disp(instr_get_src(inst, 0)) == -4) &&
        opnd_is_reg(instr_get_dst(inst, 0)) &&
        opnd_get_reg(instr_get_dst(inst, 0)) == REG_EAX) {
        int raw = *(int *)dpc;
        instr_reset(drcontext, &next);
        if (!safe_decode(drcontext, dpc, &next, &dpc))
            return match;
        if (instr_valid(&next) &&
            (raw == 0x3274c084 /*84c0 7432*/ ||
             (instr_get_opcode(&next) == OP_mov_imm &&
              opnd_is_immed_int(instr_get_src(&next, 0)) &&
              opnd_get_immed_int(instr_get_src(&next, 0)) == 0x7efefeff &&
              opnd_is_reg(instr_get_dst(&next, 0)) &&
              opnd_get_reg(instr_get_dst(&next, 0)) == REG_EDX))) {
            match = true;
            STATS_INC(strlen_exception);
            *now_addressable = false;
        }
    }
    /* strlen variation:
     *    gap+0x4516e:
     *    0044516e bafffefe7e       mov     edx,0x7efefeff
     *    00445173 8b06             mov     eax,[esi]
     *    00445175 03d0             add     edx,eax
     *    00445177 83f0ff           xor     eax,0xffffffff
     *    0044517a 33c2             xor     eax,edx
     *    0044517c 8b16             mov     edx,[esi]
     *    0044517e 83c604           add     esi,0x4
     *    00445181 a900010181       test    eax,0x81010100
     */
    else if (!ALIGNED(addr, 4) &&
             instr_get_opcode(inst) == OP_mov_ld &&
             opnd_is_base_disp(instr_get_src(inst, 0)) &&
             opnd_get_base(instr_get_src(inst, 0)) == REG_ESI &&
             opnd_get_index(instr_get_src(inst, 0)) == REG_NULL &&
             opnd_get_scale(instr_get_src(inst, 0)) == 0 &&
             opnd_get_disp(instr_get_src(inst, 0)) == 0 &&
             opnd_is_reg(instr_get_dst(inst, 0)) &&
             (opnd_get_reg(instr_get_dst(inst, 0)) == REG_EAX ||
              opnd_get_reg(instr_get_dst(inst, 0)) == REG_EDX)) {
        int raw;
        if (safe_read(pc - 4, sizeof(int), &raw) &&
            (raw == 0x7efefeff || raw == 0xc233fff0 /*f0ff 33c2*/)) {
            match = true;
            STATS_INC(strlen_exception);
            *now_addressable = false;
        }
    }
    instr_free(drcontext, &next);
    return match;
}

static bool
is_strcpy_pattern(void *drcontext, bool write, app_pc pc, app_pc next_pc,
                  app_pc addr, uint sz, instr_t *inst, bool *now_addressable OUT)
{
    instr_t next;
    app_pc dpc = next_pc;
    bool match = false;
    instr_init(drcontext, &next);

    /* Check for cygwin1!strcpy case where it reads 4 bytes for efficiency:
     * it only does so if aligned, like strlen above.
     *     cygwin1!strcpy:
     *     610deb60 55               push    ebp
     *     610deb61 89e5             mov     ebp,esp
     *     610deb63 8b550c           mov     edx,[ebp+0xc]
     *     610deb66 57               push    edi
     *     610deb67 8b7d08           mov     edi,[ebp+0x8]
     *     610deb6a 89d0             mov     eax,edx
     *     610deb6c 56               push    esi
     *     610deb6d 09f8             or      eax,edi
     *     610deb6f 53               push    ebx
     *     610deb70 a803             test    al,0x3
     *     610deb72 89f9             mov     ecx,edi
     *     610deb74 753a             jnz     cygwin1!strcpy+0x50 (610debb0)
     *     610deb76 89fe             mov     esi,edi
     *     610deb78 89d3             mov     ebx,edx
     *     610deb7a eb0c             jmp     cygwin1!strcpy+0x28 (610deb88)
     *     610deb7c 8d742600         lea     esi,[esi]
     *     610deb80 890e             mov     [esi],ecx
     *     610deb82 83c304           add     ebx,0x4
     *     610deb85 83c604           add     esi,0x4
     *     610deb88 8b0b             mov     ecx,[ebx]
     *     610deb8a 89ca             mov     edx,ecx
     *     610deb8c 8d81fffefefe     lea     eax,[ecx+0xfefefeff]
     *     610deb92 f7d2             not     edx
     *     610deb94 21d0             and     eax,edx
     *     610deb96 a980808080       test    eax,0x80808080
     *     610deb9b 74e3             jz      cygwin1!strcpy+0x20 (610deb80)
     */
    if (!ALIGNED(addr, 4) &&
        instr_get_opcode(inst) == OP_mov_ld &&
        opnd_is_base_disp(instr_get_src(inst, 0)) &&
        opnd_get_base(instr_get_src(inst, 0)) == REG_EBX &&
        opnd_get_index(instr_get_src(inst, 0)) == REG_NULL &&
        opnd_get_scale(instr_get_src(inst, 0)) == 0 &&
        opnd_get_disp(instr_get_src(inst, 0)) == 0 &&
        opnd_is_reg(instr_get_dst(inst, 0)) &&
        opnd_get_reg(instr_get_dst(inst, 0)) == REG_ECX) {
        instr_reset(drcontext, &next);
        if (!safe_decode(drcontext, dpc, &next, &dpc))
            return match;
        if (instr_valid(&next)) {
            instr_reset(drcontext, &next);
            if (!safe_decode(drcontext, dpc, &next, &dpc))
                return match;
            if (instr_valid(&next) &&
                instr_get_opcode(&next) == OP_lea &&
                opnd_get_base(instr_get_src(&next, 0)) == REG_ECX &&
                opnd_get_index(instr_get_src(&next, 0)) == REG_NULL &&
                opnd_get_scale(instr_get_src(&next, 0)) == 0 &&
                opnd_get_disp(instr_get_src(&next, 0)) == 0xfefefeff &&
                opnd_is_reg(instr_get_dst(&next, 0)) &&
                opnd_get_reg(instr_get_dst(&next, 0)) == REG_EAX) {
                match = true;
                STATS_INC(strcpy_exception);
                *now_addressable = false;
            }
        }
    }
    instr_free(drcontext, &next);
    return match;
}
#endif /* X86 */

static bool
is_prefetch(void *drcontext, bool write, app_pc pc, app_pc next_pc,
            app_pc addr, uint sz, instr_t *inst, bool *now_addressable OUT,
            app_loc_t *loc, dr_mcontext_t *mc)
{
    /* i#585: prefetch should not raise an unaddr error, only a warning */
    if (instr_is_prefetch(inst)) {
        if (options.check_prefetch) {
            char msg[64];
            dr_snprintf(msg, BUFFER_SIZE_ELEMENTS(msg),
                        "prefetching unaddressable memory "PFX"-"PFX,
                        addr, addr+sz);
            NULL_TERMINATE_BUFFER(msg);
            /* include instruction= line for max info and suppress flexibility */
            report_warning(loc, mc, msg, addr, sz, true);
        }
        *now_addressable = false;
        return true;
    }
    return false;
}

#ifdef WINDOWS
static bool
is_heap_seh(void *drcontext, bool write, app_pc pc, app_pc next_pc,
            app_pc addr, uint sz, instr_t *inst, bool *now_addressable OUT,
            app_loc_t *loc, dr_mcontext_t *mc)
{
    /* i#689: Rtl*Heap SEH finalizer reads Heap to unlock the Heap's critsec.
     * There's no good way to find the finalizer, or auto-suppress, so we
     * pattern-match the code, which seems fairly stable:
     *
     * xp64:
     *   ntdll!RtlAllocateHeap+0xe87:
     *   7d629bb6 ffb778050000     push    dword ptr [edi+0x578]
     *   7d629bbc e81656ffff       call    ntdll!RtlLeaveCriticalSection (7d61f1d7)
     *   7d629bc1 e98c7affff       jmp     ntdll!RtlAllocateHeap+0xe92 (7d621652)
     *
     * win7:
     *   ntdll!RtlpAllocateHeap+0xe7f:
     *   770024f8 ffb3cc000000     push    dword ptr [ebx+0xcc]
     *   770024fe e86dfdfdff       call    ntdll!RtlLeaveCriticalSection (76fe2270)
     *   77002503 e9ad17ffff       jmp     ntdll!RtlpAllocateHeap+0xe8a (76ff3cb5)
     */
    cls_drmem_t *cpt = (cls_drmem_t *) drmgr_get_cls_field(drcontext, cls_idx_drmem);
    bool match = false;
    if (!is_in_seh(drcontext) || !is_in_heap_region(addr))
        return false;
    /* If in SEH and addr is in heap region and addr matches the critsec
     * we recorded earlier on pattern-matched code that looks like a
     * finalizer for Rtl*Heap, allow the ref.  We could further check that
     * pc is inside RtlLeaveCriticalSection as that routine is contiguous
     * but that makes it more fragile IMHO.
     */
    if (addr >= (byte*)cpt->heap_critsec &&
        addr < (byte*)cpt->heap_critsec + sizeof(*cpt->heap_critsec)) {
        LOG(2, "SEH Heap CritSec field exception: "PFX" accessing "PFX"\n", pc, addr);
        return true;
    }
    /* See if code looks like Rtl*Heap finalizer */
    if (instr_get_opcode(inst) == OP_push &&
        opnd_is_memory_reference(instr_get_src(inst, 0))) {
        instr_t next;
        app_pc dpc = next_pc;
        instr_init(drcontext, &next);
        if (!safe_decode(drcontext, dpc, &next, &dpc))
            return false;
        if (instr_is_call(&next) &&
            opnd_is_pc(instr_get_target(&next)) &&
            opnd_get_pc(instr_get_target(&next)) == addr_RtlLeaveCrit) {
            byte *ptr = opnd_compute_address(instr_get_src(inst, 0), mc);
            if (safe_read(ptr, sizeof(cpt->heap_critsec), &cpt->heap_critsec)) {
                LOG(2, "SEH Heap CritSec exception: "PFX" accessing "PFX"\n", pc, addr);
                match = true;
            }
        }
        instr_free(drcontext, &next);
    }
    return match;
}
#endif /* WINDOWS */

/* i#91: For some apps there are so many alloca probes that it's a perf hit to
 * come to the slowpath, so we note the address, flush the fragment, and ignore
 * unaddrs there in the future.  To prevent false negatives if the code changes,
 * we check if the alloca pattern still matches in the bb creation event.
 */
static void
add_alloca_exception(void *drcontext, app_pc pc)
{
    bool success;
    STATS_INC(alloca_exception);
    success = hashtable_add(&ignore_unaddr_table, pc, (void *)1);
    LOG(2, "adding "PFX" to ignore_unaddr_table from thread "SZFMT
        ", exists: %d\n", pc, dr_get_thread_id(drcontext), !success);
    if (!success) {
        /* This can happen on concurrent execution prior to the flush.
         * In fact, with the delayed flush, these message tend to clutter
         * the log, so downgrading.
         */
        LOG(1, "ignore_unaddr_table entry came to slowpath: likely no problem"
            " (delay flush just hasn't started yet)\n");
    } else {
        success = dr_delay_flush_region(pc, 1, 0, NULL);
        ASSERT(success, "ignore_unaddr_table flush failed");
    }
}

static bool
is_ok_unaddressable_pattern(bool write, app_loc_t *loc, app_pc addr, uint sz,
                            dr_mcontext_t *mc)
{
    void *drcontext = dr_get_current_drcontext();
    app_pc pc, dpc;
    instr_t inst;
    bool match = false, now_addressable = false;
    bool unreadable_ok = false;
    if (loc->type != APP_LOC_PC) /* ignore syscalls (PR 488793) */
        return false;
    pc = loc_to_pc(loc);
    instr_init(drcontext, &inst);
    if (!safe_decode(drcontext, pc, &inst, &dpc))
        return false;
    ASSERT(instr_valid(&inst), "unknown suspect instr");

    if (!match) {
        match = is_alloca_pattern(drcontext, pc, dpc, &inst, &now_addressable);
        if (match) {
            /* it's ok for the target addr to be unreadable if stack guard page (i#538) */
            unreadable_ok = true;
            add_alloca_exception(drcontext, pc);
        }
    }
#ifdef X86 /* replacement should avoid needing to port this to ARM */
    if (!match) {
        match = is_strlen_pattern(drcontext, write, pc, dpc, addr, sz,
                                  &inst, &now_addressable);
    }
    if (!match) {
        match = is_strcpy_pattern(drcontext, write, pc, dpc, addr, sz,
                                  &inst, &now_addressable);
    }
    if (!match) {
        match = is_rawmemchr_pattern(drcontext, write, pc, dpc, addr, sz,
                                     &inst, &now_addressable);
    }
#endif
    if (!match) {
        match = is_prefetch(drcontext, write, pc, dpc, addr, sz,
                            &inst, &now_addressable, loc, mc);
        if (match)
            unreadable_ok = true;
    }
#ifdef WINDOWS
    if (!match) {
        match = is_heap_seh(drcontext, write, pc, dpc, addr, sz,
                            &inst, &now_addressable, loc, mc);
    }
#endif
    if (match) {
        /* PR 503779: be sure to not do this readability check before
         * the heap header/tls checks, else we have big perf hits!
         * Needs to be on a rare path.
         */
        if (!unreadable_ok && !dr_memory_is_readable(addr, 1)) {
            /* matched pattern, but target is actually unreadable! */
            return false;
        }
        LOG(3, "matched is_ok_unaddressable_pattern\n");
    }

    if (now_addressable) {
        umbra_shadow_memory_info_t info;
        umbra_shadow_memory_info_init(&info);
        shadow_set_byte(&info, addr, SHADOW_UNDEFINED);
    }
    instr_free(drcontext, &inst);
    return match;
}

#ifdef UNIX
/* Until we have a private loader, we have to have exceptions for the
 * loader reading our own libraries.  Xref PR
 */
static bool
is_loader_exception(app_loc_t *loc, app_pc addr, uint sz)
{
    /* Allow the loader to read .dynamic section of DR or DrMem libs.
     * Also allow lib itself to access its own lib.
     */
    bool res = false;
    if (is_in_client_or_DR_lib(addr)) {
        app_pc pc = loc_to_pc(loc);
        module_data_t *data = dr_lookup_module(pc);
        if (data != NULL) {
            const char *modname = dr_module_preferred_name(data);
            if (modname != NULL &&
                (strncmp(modname, IF_MACOS_ELSE("dyld", "ld-linux"),
                         IF_MACOS_ELSE(4, 8)) == 0 ||
                 /* i#1703: dyld also accesses DR through these two libs */
                 IF_MACOS(strcmp(modname, "libmacho.dylib") == 0 ||
                          strcmp(modname, "libobjc.A.dylib") == 0 ||
                          strcmp(modname, "libdyld.dylib") == 0 ||)
                 is_in_client_or_DR_lib(pc))) {
                /* If this happens too many times we may want to go back to
                 * marking our libs as defined and give up on catching wild
                 * app writes to those regions
                 */
                STATS_INC(loader_DRlib_exception);
                res = true;
                LOG(2, "ignoring unaddr for loader accessing DR/DrMem lib\n");
            }
            else if (modname != NULL &&
                     strncmp(modname, "libgcc_s.so", 11) == 0) {
                /* C++ exception unwind using dl_iterate_phdr examines our libs
                 * (PR 623701).  Will go away once we have our own private loader.
                 */
                STATS_INC(cppexcept_DRlib_exception);
                res = true;
                LOG(2, "ignoring unaddr for C++ exception accessing DR/DrMem lib\n");
            }
            dr_free_module_data(data);
        }
    }
    return res;
}
#endif /* UNIX */

bool
check_unaddressable_exceptions(bool write, app_loc_t *loc, app_pc addr, uint sz,
                               bool addr_on_stack, dr_mcontext_t *mc)
{
    void *drcontext = dr_get_current_drcontext();
#ifdef WINDOWS
    TEB *teb = get_TEB();
    /* We can't use teb->ProcessEnvironmentBlock b/c i#249 points it at private PEB */
    PEB *peb = get_app_PEB();
#endif
    bool addr_in_heap = is_in_heap_region(addr);
    /* It's important to handle the very-common heap-header w/o translating
     * loc's pc field which is a perf hit
     */
    if (addr_in_heap && alloc_in_heap_routine(drcontext)) {
        /* FIXME: ideally we would know exactly which fields were header
         * fields and which ones were ok to write to, to avoid heap corruption
         * by bugs in heap routines (and avoid allowing bad reads by other
         * ntdll routines like memcpy).
         * For glibc we do know the header size, but on an alloc the block
         * is not yet in our malloc table (it is on a free).
         */
        DOLOG(3, {
            if (options.shadowing) {
                umbra_shadow_memory_info_t info;
                umbra_shadow_memory_info_init(&info);
                LOG(3, "ignoring unaddr %s by heap routine "PFX" to "PFX
                    " tls=%d shadow=0x%x\n",
                    write ? "write" : "read", loc_to_print(loc), addr,
                    get_shadow_inheap(), shadow_get_byte(&info, addr));
            } else {
                LOG(3, "ignoring unaddr %s by heap routine "PFX" to "PFX" \n",
                    write ? "write" : "read", loc_to_print(loc), addr);
            }
        });
        /* with options.check_ignore_unaddr, we should only come here if:
         * 1) !get_shadow_inheap() -- but should be on for all alloc routines
         * 2) part of unaligned word access -- but unlikely for alloc routine
         * 3) access used shared xl8 and went off end of shadow block
         */
        STATS_INC(heap_header_exception);
        /* leave as unaddressable */
        return true;
    }
#ifdef WINDOWS
    /* For TLS, rather than proactively track sets and unsets, we check
     * on fault for whether set and we never mark as addressable.
     * FIXME i#537: for performance we should proactively track so we can mark
     * as addressable.  Should just watch the API and let people who
     * bypass to set the bits themselves deal w/ the false positives instead
     * of adding checks to all writes to catch tls bitmask writes.
     */
    if ((addr >= (app_pc)&teb->TlsSlots[0] && addr < (app_pc)&teb->TlsSlots[64]) ||
        (teb->TlsExpansionSlots != NULL &&
         addr >= (app_pc)teb->TlsExpansionSlots &&
         addr < (app_pc)teb->TlsExpansionSlots +
         TLS_EXPANSION_BITMAP_SLOTS*sizeof(byte))) {
#ifdef DEBUG
        umbra_shadow_memory_info_t info;
#endif
        bool tls_ok = false;
        if (addr >= (app_pc)&teb->TlsSlots[0] && addr < (app_pc)&teb->TlsSlots[64]) {
            uint slot = (addr - (app_pc)&teb->TlsSlots[0]) / sizeof(void*);
            LOG(3, "checking unaddressable TLS slot "PFX" => %d\n",
                 addr, slot);
            tls_ok = ((peb->TlsBitmap->Buffer[slot/32] & (1 << (slot % 32))) != 0);
        } else {
            uint slot = (addr - (app_pc)teb->TlsExpansionSlots) / sizeof(void*);
            ASSERT(peb->TlsExpansionBitmap != NULL, "TLS mismatch");
            LOG(3, "checking unaddressable expansion TLS slot "PFX" => %d\n",
                 addr, slot);
            tls_ok = ((peb->TlsExpansionBitmap->Buffer[slot/32] & (1 << (slot % 32)))
                      != 0);
        }
#ifdef DEBUG
        umbra_shadow_memory_info_init(&info);
#endif
        LOG(3, "%s unaddr %s by "PFX" to TLS slot "PFX" shadow=%x\n",
            tls_ok ? "ignoring" : "reporting", write ? "write" : "read",
            loc_to_print(loc), addr, shadow_get_byte(&info, addr));
        STATS_INC(tls_exception);
        /* We leave as unaddressable since we're not tracking the unset so we
         * can't safely mark as addressable */
        return tls_ok;
    }
#else
    if (is_loader_exception(loc, addr, sz)) {
        return true;
    }
#endif
    if (is_ok_unaddressable_pattern(write, loc, addr, sz, mc)) {
        return true;
    } else if (options.shadowing &&
               options.define_unknown_regions && !addr_in_heap &&
               (!options.check_stack_bounds || !addr_on_stack)
               /* i#579: leave kernel regions as unaddr */
               IF_WINDOWS(&& addr < get_highest_user_address())) {
        /* i#352 (and old PR 464106): handle memory allocated by other
         * processes by treating as fully defined, without any UNADDR.
         * This is Windows and there are cases where csrss allocates
         * things like activation contexts.
         *
         * XXX: limit this to MEM_MAPPED/MEM_IMAGE and for MEM_PRIVATE mark as
         * uninit, or maybe just a louder warning, or old idea of reporting
         * initial unaddr (though that seems silly), since could be a heap alloc
         * we missed or some other allocation (PR 464106 mentions gdi32 bitmaps)
         * that should start out uninit?
         */
        app_pc base;
        size_t sz = allocation_size(addr, &base);
        if (sz > 0 && base != NULL) {
            LOG(1, "WARNING: unknown region " PFX " => " PFX "-" PFX
                ": marking as defined\n", addr, base, base+sz);
            ASSERT(!dr_memory_is_dr_internal(addr) &&
                   !dr_memory_is_in_client(addr),
                   "App is using tool's memory: please report this!");
            /* There can be reserved-only regions inside, which can be quite large,
             * so be sure to skip them (i#2184).
             */
            mmap_walk(base, sz, IF_WINDOWS_(NULL) true/*add*/);
            return true;
        }
    }
    return false;
}

/***************************************************************************
 * HEAP REGION
 */

#ifdef WINDOWS
void
client_remove_malloc_on_destroy(HANDLE heap, byte *start, byte *end)
{
    leak_remove_malloc_on_destroy(heap, start, end);
}
#endif

void
handle_new_heap_region(app_pc start, app_pc end, dr_mcontext_t *mc)
{
    report_heap_region(true/*add*/, start, end, mc);
}

void
handle_removed_heap_region(app_pc start, app_pc end, dr_mcontext_t *mc)
{
    report_heap_region(false/*remove*/, start, end, mc);
}

/***************************************************************************
 * LEAK CHECKING
 */

void
client_found_leak(app_pc start, app_pc end, size_t indirect_bytes,
                  bool pre_us, bool reachable,
                  bool maybe_reachable, void *client_data,
                  bool count_reachable, bool show_reachable)
{
    packed_callstack_t *pcs = (packed_callstack_t *) client_data;
    if (!options.count_leaks) {
        ASSERT(false, "shouldn't get here");
        return;
    }
    report_leak(true, start, end - start, indirect_bytes, pre_us, reachable,
                maybe_reachable, SHADOW_UNKNOWN, pcs, count_reachable, show_reachable);
}

static byte *
next_defined_ptrsz(byte *start, byte *end)
{
    return shadow_next_ptrsz((byte *)ALIGN_FORWARD(start, sizeof(void*)),
                             end, SHADOW_DEFINED);
}

static byte *
end_of_defined_region(byte *start, byte *end)
{
    byte *res;
    if (shadow_check_range(start, end - start, SHADOW_DEFINED, &res, NULL, NULL))
        res = end;
    return res;
}

static bool
is_register_defined(void *drcontext, reg_id_t reg)
{
    return is_shadow_register_defined(get_thread_shadow_register(drcontext, reg));
}

void
check_reachability(bool at_exit)
{
    /* no leak scan if we do not memory alloc (could have bailed for PR 574018) */
    if (!options.track_allocs)
        return;
    if (!options.count_leaks)
        return;
    if (!options.leak_scan)
        return;
    leak_scan_for_leaks(at_exit);
}

/***************************************************************************
 * malloc table iterate data
 */

typedef struct _malloc_iter_data_t {
    /* query [addr..addr + size) */
    byte *addr;
    size_t size;
    /* alloc block info if found */
    app_pc start;
    app_pc end;
    app_pc real_end;
    packed_callstack_t *alloc_pcs;
    bool   pre_us;
    /* found block in malloc table */
    bool found;
} malloc_iter_data_t;

/***************************************************************************/

/* iterate callback for finding block overlapping with [addr, addr + size) */
static bool
malloc_iterate_cb(malloc_info_t *mal, void *iter_data)
{
    malloc_iter_data_t *data = (malloc_iter_data_t *) iter_data;
    byte *rz_start = mal->base - (mal->has_redzone ? options.redzone_size : 0);
    size_t tot_sz = mal->pad_size + (mal->has_redzone ? options.redzone_size*2 : 0);
    ASSERT(iter_data != NULL, "invalid iteration data");
    ASSERT(mal != NULL, "invalid params");
    LOG(4, "malloc iter: "PFX"-"PFX"%s\n", mal->base, mal->base + mal->request_size,
        mal->pre_us ? ", pre-us" : "");
    ASSERT(!data->found, "the iteration should be short-circuited");
    if (data->addr < rz_start + tot_sz &&
        (data->addr + data->size) > rz_start) {
        data->start     = mal->base;
        data->end       = mal->base + mal->request_size;
        data->real_end  = rz_start + tot_sz;
        data->alloc_pcs = (packed_callstack_t *) mal->client_data;
        data->pre_us    = mal->pre_us;
        data->found     = true;
        return false; /* stop iteration */
    }
    return true; /* continue iteration */
}

/* XXX: this could be used in report_heap_info() in report.c when we don't have
 * shadow info, to find overlapping malloc, and it could be adapted to find
 * the nearest neighbor.
 */
static bool
region_overlap_with_malloc_block(malloc_iter_data_t *iter_data)
{
    ASSERT(iter_data != NULL, "invalid iteration data");
    /* expensive hashtable walk */
    LOG(2, "expensive lookup for region_overlap_with_malloc_block@["
        PFX".."PFX")\n", iter_data->addr, iter_data->addr + iter_data->size);
    malloc_iterate(malloc_iterate_cb, iter_data);
    return iter_data->found;
}

/* check if region [addr, addr + size) overlaps with any malloc redzone
 * or padding.
 * - if overlaps, return true and fill all the passed in parameters,
 * - otherwise, return false and NO parameters is filled.
 */
bool
region_in_redzone(byte *addr, size_t size,
                  packed_callstack_t **alloc_pcs OUT,
                  app_pc *app_start OUT,
                  app_pc *app_end OUT,
                  app_pc *redzone_start OUT,
                  app_pc *redzone_end OUT)
{
    malloc_iter_data_t iter_data = {addr, size, NULL, NULL, NULL, false, false};
    if (options.replace_malloc) {
        /* Faster than full iteration, in presence of multiple arenas */
        malloc_info_t mal;
        mal.struct_size = sizeof(mal);
        if (alloc_replace_overlaps_malloc(addr, addr + size, &mal)) {
            iter_data.start = mal.base;
            iter_data.end = mal.base + mal.request_size;
            iter_data.real_end = mal.base + mal.pad_size +
                (mal.has_redzone ? options.redzone_size*2 : 0);
            iter_data.alloc_pcs = (packed_callstack_t *) mal.client_data;
            iter_data.pre_us = false; /* we don't know, but won't match bounds checks */
            iter_data.found = true;
        }
    } else if (region_overlap_with_malloc_block(&iter_data)) {
        ASSERT(iter_data.found, "should be set already");
    }
    if (iter_data.found) {
        LOG(3, "%s "PFX"-"PFX": match "PFX"-"PFX"-"PFX", checking redzones\n",
            __FUNCTION__, addr, addr+size, iter_data.start, iter_data.end,
            iter_data.real_end);
        if (iter_data.pre_us)
            return false; /* pre_us */
        /* in head redzone */
        /* For -replace_malloc w/ shared redzones, we'll pick head over tail:
         * shouldn't matter.
         */
        if (addr <  iter_data.start &&
            addr + size > iter_data.start - options.redzone_size) {
            if (app_start != NULL)
                *app_start = iter_data.start;
            if (app_end != NULL)
                *app_end = iter_data.end;
            if (redzone_start != NULL)
                *redzone_start = iter_data.start - options.redzone_size;
            if (redzone_end != NULL)
                *redzone_end = iter_data.start;
            if (alloc_pcs != NULL)
                *alloc_pcs = iter_data.alloc_pcs;
            LOG(3, "\tin pre-redzone\n");
            return true;
        }
        /* in tail redzone */
        if (addr < iter_data.real_end && addr + size > iter_data.end) {
            if (app_start != NULL)
                *app_start = iter_data.start;
            if (app_end != NULL)
                *app_end = iter_data.end;
            if (redzone_start != NULL)
                *redzone_start = iter_data.end;
            if (redzone_end != NULL)
                *redzone_end = iter_data.real_end;
            if (alloc_pcs != NULL)
                *alloc_pcs = iter_data.alloc_pcs;
            LOG(3, "\tin post-redzone\n");
            return true;
        }
    }
    return false;
}

