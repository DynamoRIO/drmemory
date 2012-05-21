/* **********************************************************
 * Copyright (c) 2012 Google, Inc.  All rights reserved.
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
 * malloc.c: application allocator replacement routines for both
 * Dr. Memory and Dr. Heapstat
 */

/* Requirements beyond regular allocator:
 * + add redzones (configurable)
 * + delay frees (configurable): thus unlike most allocators we do
 *   not want to re-use a block immediately even with same-size
 *   repeated alloc-free in order to detect use-after-free
 * + callbacks for custom actions like updating shadow memory
 *   or heap profiling
 * + provide iterator over all chunks
 * + given pointer, know whether the start of a live chunk,
 *   the start of a freed chunk, or neither
 * + store both requested size and allocated size
 * + store type: malloc, new or new[]
 * + store custom flags per chunk (for use during leak scan)
 * + store callstack
 * + optional: given pointer, know whether *inside* a live chunk,
 *   a freed chunk, or neither.  required during leak scan, but can
 *   build new data structure at that point.
 *   nice-to-have when reporting neighbors of unaddr, and can
 *   use shadow mem heuristics instead.
 *
 * Differences vs wrap-based implementation wrt client_ callouts:
 * + redzones are built-in rather than added by the client, to
 *   facilitate both storing headers in them and sharing adjacent
 * + delay free lists are built-in rather than maintained by client
 *
 * Design:
 * + for !alloc_ops.external_headers, header sits inside redzone;
 *   for alloc_ops.external_headers, header is in a hashtable
 * + redzones are shared among adjacent allocs:
 *
 *  | request sz|     |   redzone size   | request size |   |   redzone size   |
 *  | app chunk | pad | redzone | header | app chunk    |pad| redzone | header |
 *                                                                             ^
 *                                                                 arena_next _|
 *
 * + arena_next always has a redzone + header space (if co-located, i.e.,
 *   !alloc_ops.external_headers) to its left
 * + free lists are kept in buckets by size.  larger is preferred over
 *   searching.  final bucket is var-sized and is always searched.
 *   frees are appended to make the lists FIFO for better delaying
 *   (though worse alloc re-use), and searches start at the front and
 *   take the first fit.
 *   we can add fancier algorithms in the future.
 * + for alloc_ops.external_headers, free list entries are allocated
 *   externally and point at their heap chunks
 */

#include "dr_api.h"
#include "drwrap.h"
#include "utils.h"
#include "alloc.h"
#include "alloc_private.h"
#include "heap.h"
#include <string.h> /* memcpy */

#ifdef LINUX
# include "sysnum_linux.h"
# define __USE_GNU /* for mremap */
# include <sys/mman.h>
#endif

/***************************************************************************
 * header and free list data structures
 */

#define CHUNK_ALIGNMENT 8
#define CHUNK_MIN_SIZE  8
#define CHUNK_MIN_MMAP  128*1024
/* initial commit has to hold at least one non-mmap chunk */
#define ARENA_INITIAL_COMMIT  CHUNK_MIN_MMAP
#define ARENA_INITIAL_SIZE  4*1024*1024

/* we only support allocation sizes under 4GB */
typedef uint heapsz_t;

/* each free list bucket contains freed chunks of at least its bucket size
 * XXX: add stats on searches to help in tuning these
 */
static const uint free_list_sizes[] = {
    8, 16, 24, 32, 40, 64, 96, 128, 192, 256, 384, 512, 1024, 2048, 4096
};
#define NUM_FREE_LISTS (sizeof(free_list_sizes)/sizeof(free_list_sizes[0]))

enum {
    CHUNK_FREED       = MALLOC_RESERVED_1,
    CHUNK_MMAP        = MALLOC_RESERVED_2,
    /* MALLOC_RESERVED_{3,4} are used for types */
    CHUNK_PRE_US      = MALLOC_RESERVED_5,
    /* to support iteration */
    CHUNK_ARENA_FINAL = MALLOC_RESERVED_6,
    /* MALLOC_RESERVED_7 could be used to indicate presence of prev
     * free chunk for coalescing
     */
};

#define HEADER_MAGIC 0x5244 /* "DR" */

/* This header struct is used in both a traditional co-located header
 * and as a hashtable payload (for alloc_ops.external_headers).  Note
 * that when using redzones there's no problem with a large header as
 * it sits inside the redzone.  But with the hashtable, and for
 * Dr. Heapstat where we have no redzone, we want to make the header
 * as compact as is reasonable.
 */
typedef struct _chunk_header_t {
    /* if we wanted to save space we could hand out sizes only equal to the buckets
     * and remove one of these.  we'd use a separate header for the largest bucket
     * that had the alloc_size.
     */
    heapsz_t request_size;
    heapsz_t alloc_size;
    ushort flags;
    ushort magic;
#ifdef X64
    /* compiler will add anyawy: just making explicit.  we need the header
     * size to be aligned to 8 so we can't pack.  for alloc_ops.external_headers
     * we eat this overhead to provide runtime flexibility w/ the same
     * data struct as we don't need it there.
     */
    uint pad;
#endif
    void *user_data;
} chunk_header_t;

#define HEADER_SIZE sizeof(chunk_header_t)

/* if redzone is too small, header sticks beyond it */
static heapsz_t header_beyond_redzone;

/* free list header for both regular and var-size chunk.  each chunk
 * is at least 8 bytes so we can fit both the next pointer and the
 * only-used-for-alloc_ops.external_headers chunk pointer, simplifying
 * the code by having one header type.
 *
 * FIXME: for x64 chunk ptr doesn't fit: so either need a separate
 * struct used for hashtable only that has the chunk ptr, or need
 * to set CHUNK_MIN_SIZE to 16 for x64
 */
typedef struct _free_header_t {
    chunk_header_t head;
    struct _free_header_t *next;
    byte *chunk; /* only used for alloc_ops.external_headers */
} free_header_t;

/* a normal free list can be LIFO, but for more effective delayed frees
 * we want FIFO.  FIFO-per-bucket-size is sufficient.
 */
static free_header_t *free_list_front[NUM_FREE_LISTS];
static free_header_t *free_list_last[NUM_FREE_LISTS];

/* counters for delayed frees.  protected by malloc lock. */
static uint delayed_chunks;
static size_t delayed_bytes;

static void *allocator_lock;

#ifdef LINUX
/* we assume we're the sole users of the brk (after pre-us allocs) */
static byte *pre_us_brk;
static byte *cur_brk;
#endif

/* these describe the current heap arena */
static byte *arena_start;
/* the end of reserved memory in the current heap arena */
static byte *arena_next;
static byte *arena_commit_end;
static byte *arena_reserve_end;
/* the furthest chunk in the current heap arena */
static chunk_header_t *last_chunk;

/* For handling pre-us mallocs for non-earlist injection or delayed/attach
 * instrumentation.  Contains chunk_header_t entries.
 * We assume this table is only added to at init and only removed from
 * at exit time and thus needs no external lock.
 */
#define PRE_US_TABLE_HASH_BITS 8
static hashtable_t pre_us_table;

/* XXX i#879: for pattern mode we don't want co-located headers and
 * instead want a hashtable of live allocs (free are in free lists
 * and/or rbtree).
 * Cleaner to have own table here and not try to use the alloc.c malloc-wrap table
 * though we do want the same hash tuning.
 */

/***************************************************************************
 * utility routines
 */

static void *
enter_client_code(void)
{
    void *drcontext = dr_get_current_drcontext();
    /* while we are using the app's stack and registers, we need to
     * switch to the private peb/teb to avoid asserts in symbol
     * routines.
     * XXX: is it safe to do away w/ this and relax the asserts?
     */
    dr_switch_to_dr_state(drcontext);
    return drcontext;
}

static void
exit_client_code(void *drcontext)
{
    dr_switch_to_app_state(drcontext);
}

static void
initialize_mcontext_for_report(dr_mcontext_t *mc)
{
    /* assumption: we only need xsp and xbp initialized */
    mc->size = sizeof(*mc);
    mc->flags = DR_MC_CONTROL | DR_MC_INTEGER;
    /* FIXME i#794: add asm support and asm routine to get xsp and xbp:
     *   get_stack_registers(&mc->xsp, &mc->xbp);
     * I don't see any cl intrinsic to get xbp (gcc has one): if there were
     * could assume these routines don't have FPO and set xsp=xbp
     */
    mc->xsp = 0;
    mc->xbp = 0;
}

static byte *
os_large_alloc(size_t commit_size _IF_WINDOWS(size_t reserve_size))
{
    /* FIXME DRi#199: how notify DR about app mem alloc?
     * provide general raw_syscall() interface,
     * or dr_mmap_as_app() or sthg.
     * for now using our own raw syscall...
     */
#ifdef LINUX
    byte *map = (byte *) raw_syscall_6args
        (IF_X64_ELSE(SYS_mmap, SYS_mmap2), (ptr_int_t)NULL, commit_size,
         PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    ASSERT(ALIGNED(commit_size, PAGE_SIZE), "must align to at least page size");
    if ((ptr_int_t)map < 0 && (ptr_int_t)map > -PAGE_SIZE) {
        LOG(2, "os_large_alloc FAILED with return value "PFX"\n", map);
        return NULL;
    }
    return map;
#else
    byte *loc = NULL;
    ASSERT(ALIGNED(commit_size, PAGE_SIZE), "must align to at least page size");
    ASSERT(ALIGNED(reserve_size, PAGE_SIZE), "must align to at least page size");
    ASSERT(reserve_size >= commit_size, "must reserve more than commit");
    if (!virtual_alloc(&loc, reserve_size, MEM_RESERVE, PAGE_NOACCESS))
        return NULL;
    if (!virtual_alloc(&loc, commit_size, MEM_COMMIT, PAGE_READWRITE)) {
        virtual_free(loc);
        return NULL;
    }
    return loc;
#endif
}

/* For Windows, up to caller to ensure new_commit_size <= previously reserved size */
static bool
os_large_alloc_extend(byte *map, size_t cur_commit_size, size_t new_commit_size)
{
    ASSERT(ALIGNED(cur_commit_size, PAGE_SIZE), "must align to at least page size");
    ASSERT(ALIGNED(new_commit_size, PAGE_SIZE), "must align to at least page size");
#ifdef LINUX
    byte *newmap = (byte *) raw_syscall_4args
        (SYS_mremap, (ptr_int_t)map, cur_commit_size, new_commit_size, 0/*can't move*/);
    if ((ptr_int_t)newmap < 0 && (ptr_int_t)newmap > -PAGE_SIZE)
        return false;
    return true;
#else
    return virtual_alloc(&map, new_commit_size, MEM_COMMIT, PAGE_READWRITE);
#endif
}

/* For Windows, map_size is ignored and the whole allocation is freed */
static bool
os_large_free(byte *map, size_t map_size)
{
#ifdef LINUX
    int success;
    ASSERT(ALIGNED(map, PAGE_SIZE), "invalid mmap base");
    ASSERT(ALIGNED(map_size, PAGE_SIZE), "invalid mmap size");
    success = (int) raw_syscall_2args(SYS_munmap, (ptr_int_t)map, map_size);
    return (success == 0);
#else
    return virtual_free(map);
#endif
}

static void
notify_client_alloc(bool call_handle, void *drcontext, byte *ptr,
                    chunk_header_t *head, dr_mcontext_t *mc,
                    bool zeroed, bool realloc, app_pc caller)
{
    head->user_data = client_add_malloc_pre(ptr, ptr + head->request_size,
                                            ptr + head->alloc_size,
                                            head->user_data, mc, caller);
    client_add_malloc_post(ptr, ptr + head->request_size,
                           ptr + head->alloc_size, head->user_data);
    if (call_handle) {
        ASSERT(drcontext != NULL, "invalid arg");
        client_handle_malloc(drcontext, ptr, head->request_size,
                             /* XXX: pattern wants us to subtract redzone
                              * size for real_base but that would result in it clobbering
                              * our header: so we're just incompatible w/ pattern mode
                              * (checked up front in alloc_ops.c).
                              * xref i#879 on an allocator for pattern mode.
                              */
                             ptr, head->alloc_size, zeroed, realloc, mc);
    }
}

/***************************************************************************
 * core allocation routines
 */

static inline chunk_header_t *
header_from_ptr(void *ptr)
{
    if (alloc_ops.external_headers) {
        /* XXX i#879: hashtable lookup */
        ASSERT(false, "NYI");
        return NULL;
    } else {
        if ((ptr_uint_t)ptr < HEADER_SIZE)
            return NULL;
        else
            return (chunk_header_t *) ((byte *)ptr - HEADER_SIZE);
    }
}

/* Pass in result of header_from_ptr() as 2nd arg, but don't de-reference it!
 * Returns true for both live mallocs and chunks in delay free lists
 */
static inline bool
is_valid_chunk(void *ptr, chunk_header_t *head)
{
    /* Note that we can't be sure w/o using a hashtable, but for performance
     * it's worth it to risk not identifying an invalid free so we use
     * heuristics.
     * XXX improvements:
     * + should we have an option of using a hashtable to be sure,
     *   even when !alloc_ops.external_headers?
     *   app corrupting our allocator would be bad.
     * + check whether in heap memory region(s) if that's cheap: if
     *   need rbtree lookup then don't
     * + could check that next header is a real header, or at end of arena
     * + could have client_ callout that checks shadow memory
     */
    if (alloc_ops.external_headers) {
        /* XXX i#879: need to look in delay free rbtree too */
        return head != NULL;
    } else {
        /* XXX: we don't want to crash de-referencing head, but
         * a TRY here has a noticeable perf hit!  live w/ risk of app
         * crashing our allocator?  have a top-level crash handler
         * that bails out w/ an error report about invalid arg?
         * note that we do have a TRY in malloc_replace_size() (b/c rest of
         * drmem passes us bad pointers during neighbor discovery)
         * which should be removed if we put a TRY here.
         */
        return (ptr != NULL &&
                ALIGNED(ptr, CHUNK_ALIGNMENT) &&
                head->magic == HEADER_MAGIC);
    }
}

static bool
is_live_alloc(void *ptr, chunk_header_t *head)
{
    if (alloc_ops.external_headers) {
        return head != NULL;
    } else {
        return (is_valid_chunk(ptr, head) &&
                !TEST(CHUNK_FREED, head->flags));
    }
}

static bool
arena_extend(heapsz_t add_size)
{
    heapsz_t aligned_add = (heapsz_t) ALIGN_FORWARD(add_size, PAGE_SIZE);
#ifdef LINUX
    if (arena_commit_end == cur_brk) {
        byte *new_brk = set_brk(cur_brk + aligned_add);
        if (new_brk >= cur_brk + add_size) {
            LOG(2, "\tincreased brk from "PFX" to "PFX"\n", cur_brk, new_brk);
            cur_brk = new_brk;
            arena_commit_end = new_brk;
            heap_region_adjust(arena_start, new_brk);
            return true;
        } else
            LOG(1, "brk cannot expand: switching to mmap\n");
    } else
#else
    if (arena_commit_end + aligned_add <= arena_reserve_end)
#endif
    { /* here to not confuse brace matching */
        size_t cur_size = arena_commit_end - arena_start;
        size_t new_size = cur_size + aligned_add;
        if (os_large_alloc_extend(arena_start, cur_size, new_size)) {
            arena_commit_end = arena_start + new_size;
#ifdef LINUX /* windows already added whole reservation */
            heap_region_adjust(arena_start, arena_start + new_size);
#endif
            return true;
        }
    }
    /* XXX: add stranded space at end of arena to free list: but have to
     * update last_chunk properly
     */
    LOG(1, "cur arena "PFX"-"PFX" out of space: creating new one\n",
        arena_start, arena_reserve_end);
    arena_start = os_large_alloc(IF_WINDOWS_(ARENA_INITIAL_COMMIT) ARENA_INITIAL_SIZE);
    if (arena_start == NULL)
        return false;
#ifdef LINUX
    arena_commit_end = arena_start + ARENA_INITIAL_SIZE;
#else
    arena_commit_end = arena_start + ARENA_INITIAL_COMMIT;
#endif
    arena_reserve_end = arena_start + ARENA_INITIAL_SIZE;
    heap_region_add(arena_start, arena_reserve_end, HEAP_ARENA, NULL);
    /* need to start with a redzone */
    arena_next = arena_start + alloc_ops.redzone_size + header_beyond_redzone;
    return true;
}

static chunk_header_t *
search_free_list_bucket(heapsz_t aligned_size, uint bucket)
{
    /* search for large enough chunk */
    free_header_t *cur, *prev;
    chunk_header_t *head = NULL;
    ASSERT(dr_recurlock_self_owns(allocator_lock), "caller must hold lock");
    ASSERT(bucket < NUM_FREE_LISTS, "invalid param");
    for (cur = free_list_front[bucket], prev = NULL;
         cur != NULL && cur->head.alloc_size < aligned_size;
         prev = cur, cur = cur->next)
        ; /* nothing */
    if (cur != NULL) {
        if (prev == NULL)
            free_list_front[bucket] = cur->next;
        else
            prev->next = cur->next;
        if (cur == free_list_last[bucket])
            free_list_last[bucket] = prev;
        head = (chunk_header_t *) cur;
    }
    return head;
}

static chunk_header_t *
find_free_list_entry(heapsz_t request_size, heapsz_t aligned_size)
{
    chunk_header_t *head = NULL;
    uint bucket;
    ASSERT(dr_recurlock_self_owns(allocator_lock), "caller must hold lock");

    /* don't use free list unless we hit max delay */
    if (delayed_chunks < alloc_ops.delay_frees &&
        delayed_bytes < alloc_ops.delay_frees_maxsz)
        return NULL;

    /* b/c we're delaying, we're not able to re-use a just-freed chunk.
     * thus we go for time over space and use the guaranteed-size bucket
     * before searching the maybe-big-enough bucket.
     */
    for (bucket = 0;
         bucket < NUM_FREE_LISTS - 1 && aligned_size > free_list_sizes[bucket];
         bucket++)
        ; /* nothing */
    if (free_list_front[bucket] == NULL && bucket > 0 &&
        aligned_size < free_list_sizes[bucket]) {
        /* next-bigger is not avail: search maybe-big-enough bucket before
         * possibly going to even bigger buckets
         */
        bucket--;
        head = search_free_list_bucket(aligned_size, bucket);
        if (head == NULL)
            bucket++;
    }
    
    /* if delay frees are piling up, use a larger bucket to avoid
     * delaying a ton of allocs of a certain size and never re-using
     * them for pathological app alloc sequences
     */
    if (head == NULL && free_list_front[bucket] == NULL &&
        (delayed_chunks >= 2*alloc_ops.delay_frees ||
         delayed_bytes >= 2*alloc_ops.delay_frees_maxsz)) {
        LOG(2, "\tallocating from larger bucket size to reduce delayed frees\n");
        while (bucket < NUM_FREE_LISTS - 1 && free_list_front[bucket] == NULL)
            bucket++;
    }

    if (head == NULL && free_list_front[bucket] != NULL) {
        if (bucket == NUM_FREE_LISTS - 1) {
            /* var-size bucket: have to search */
            head = search_free_list_bucket(aligned_size, bucket);
        } else {
            /* guaranteed to be big enough so take from front */
            ASSERT(aligned_size <= free_list_sizes[bucket], "logic error");
            head = (chunk_header_t *) free_list_front[bucket];
            free_list_front[bucket] = free_list_front[bucket]->next;
            if (head == (chunk_header_t *) free_list_last[bucket])
                free_list_last[bucket] = free_list_front[bucket];
        }
    }

    if (head != NULL) {
        LOG(2, "\tusing free list size=%d for request=%d align=%d from bucket %d\n",
            head->alloc_size, request_size, aligned_size, bucket);
        ASSERT(delayed_chunks > 0, "delay counter off");
        delayed_chunks--;
        ASSERT(delayed_bytes >= head->alloc_size, "delay bytes counter off");
        delayed_bytes -= head->alloc_size;
        if (head->user_data != NULL)
            client_malloc_data_free(head->user_data);
        head->flags &= ~CHUNK_FREED;
    }
    return head;
}

static byte *
replace_alloc_common(size_t request_size, bool zeroed, bool realloc,
                     void *drcontext, dr_mcontext_t *mc, app_pc caller)
{
    heapsz_t aligned_size;
    byte *res = NULL;
    chunk_header_t *head = NULL;

    if (request_size > UINT_MAX) {
        /* rather than have larger headers for 64-bit we just don't support
         * enormous allocations
         */
        client_handle_alloc_failure(request_size, zeroed, realloc, caller, mc);
        return NULL;
    }

    aligned_size = ALIGN_FORWARD(request_size, CHUNK_ALIGNMENT);
    if (aligned_size < CHUNK_MIN_SIZE)
        aligned_size = CHUNK_MIN_SIZE;

    /* XXX: use per-thread free lists to avoid lock in common case */
    dr_recurlock_lock(allocator_lock);

    /* for large requests we do direct mmap with own redzones.
     * we use the large malloc table to track them for iteration.
     * XXX: for simplicity, not delay-freeing these for now
     */
    if (aligned_size + HEADER_SIZE >= CHUNK_MIN_MMAP) {
        size_t map_size = (size_t)
            ALIGN_FORWARD(aligned_size + alloc_ops.redzone_size*2 +
                          header_beyond_redzone, PAGE_SIZE);
        byte *map = os_large_alloc(map_size _IF_WINDOWS(map_size));
        LOG(2, "\tlarge alloc %d => mmap\n", request_size);
        if (map == NULL) {
            client_handle_alloc_failure(request_size, zeroed, realloc, caller, mc);
            return NULL;
        }
        ASSERT(!alloc_ops.external_headers, "NYI");
        head = (chunk_header_t *) (map + alloc_ops.redzone_size +
                                   header_beyond_redzone - HEADER_SIZE);
        head->flags |= CHUNK_MMAP;
        head->magic = HEADER_MAGIC;
        head->alloc_size = map_size - alloc_ops.redzone_size*2 - header_beyond_redzone;
        heap_region_add(map, map + map_size, 0, mc);
    } else {
        /* look for free list entry */
        head = find_free_list_entry(request_size, aligned_size);
    }

    /* if no free list entry, get new memory */
    if (head == NULL) {
        heapsz_t add_size = aligned_size + alloc_ops.redzone_size + header_beyond_redzone;
        if (arena_next + add_size > arena_commit_end) {
            if (!arena_extend(add_size)) {
                client_handle_alloc_failure(request_size, zeroed, realloc, caller, mc);
                return NULL;
            }
        }
        /* remember that arena_next always has a redzone preceding it */
        head = (chunk_header_t *) (arena_next - HEADER_SIZE);
        LOG(2, "\tcarving out new chunk @"PFX"\n", head);
        head->alloc_size = aligned_size;
        head->magic = HEADER_MAGIC;
        head->user_data = NULL; /* b/c we pass the old to client */
        head->flags = 0;
        arena_next += add_size;
        /* ensure we know where to stop when iterating */
        if (last_chunk != NULL)
            last_chunk->flags &= ~CHUNK_ARENA_FINAL;
        head->flags |= CHUNK_ARENA_FINAL;
        last_chunk = head;
    }

    /* head->alloc_size, head->magic, and head->flags (except type) are already set */
    ASSERT(head->magic == HEADER_MAGIC, "corrupted header");
    head->request_size = request_size;
    /* FIXME i#794: need to pass in TLS to get type since still wrapping.
     * XXX i#882: replace operators.
     * Need to move the MALLOC_ALLOCATOR_* defines to alloc_private.h.
     */
    res = (byte *)(head + 1);
    LOG(2, "\treplace_alloc_common request=%d, alloc=%d => "PFX"\n",
        head->request_size, head->alloc_size, res);

    ASSERT(head->alloc_size >= request_size, "chunk too small");

    notify_client_alloc(true/*handle*/, drcontext, (byte *)res, head, mc,
                        zeroed, realloc, caller);

    if (head->request_size >= LARGE_MALLOC_MIN_SIZE)
        malloc_large_add(res, request_size);

    dr_recurlock_unlock(allocator_lock);

    return res;
}

static void
replace_free_common(void *ptr, void *drcontext, dr_mcontext_t *mc, app_pc caller)
{
    chunk_header_t *head = header_from_ptr(ptr);
    free_header_t *cur;
    uint bucket;

    if (!is_live_alloc(ptr, head)) { /* including NULL */
        /* w/o early inject, or w/ delayed instru, there are allocs in place
         * before we took over
         */
        head = hashtable_lookup(&pre_us_table, (void *)ptr);
        if (head != NULL && !TEST(CHUNK_FREED, head->flags)) {
            /* XXX: need to call the app's free routine.
             * Xref DRi#497 for a mechanism to do this; or, we could call
             * it natively (after swapping TLS back).
             * For Windows we can assume Rtl since that's where we iterated.
             * For now we're just leaking these, which we claim is a feature
             * b/c we'll catch use-after-free :)
             * FIXME: That's fine for the small # at late inject, but for
             * attach at a random point that's not good enough: probably
             * better to free immediately rather than have some extra code
             * to delay pre-us frees.  If we do that we may need an
             * external table lock.
             */
        } else {
            client_invalid_heap_arg(caller, (byte *)ptr, mc,
                                    /* XXX: we might be replacing RtlHeapFree or
                                     * _free_dbg but it's not worth trying to
                                     * store the exact name
                                     */
                                    "free", true/*free*/);
        }
        return;
    }

    dr_recurlock_lock(allocator_lock);

    if (!TEST(CHUNK_MMAP, head->flags))
        head->flags |= CHUNK_FREED;
    if (!TESTANY(CHUNK_MMAP | CHUNK_PRE_US, head->flags)) {
        cur = (free_header_t *) head;
        /* our buckets guarantee that all allocs in that bucket have at least that size */
        for (bucket = NUM_FREE_LISTS - 1; head->alloc_size < free_list_sizes[bucket];
             bucket--)
            ; /* nothing */
        ASSERT(head->alloc_size >= free_list_sizes[bucket], "bucket invariant violated");
        LOG(2, "\treplace_free_common "PFX" == request=%d, alloc=%d\n",
            ptr, head->request_size, head->alloc_size);

        /* add to the end for delayed free FIFO */
        cur->next = NULL;
        if (free_list_last[bucket] == NULL) {
            ASSERT(free_list_front[bucket] == NULL, "inconsistent free list");
            free_list_front[bucket] = cur;
        } else
            free_list_last[bucket]->next = cur;
        free_list_last[bucket] = cur;

        delayed_chunks++;
        delayed_bytes += head->alloc_size;

        /* XXX: could add more sophisticated features like coalescing adjacent
         * free entries which we may actually need for apps with corner-case
         * alloc patterns.  We may also want to implement negative sbrk to
         * give memory back.
         */
    }

    /* current model is to throw the data away when we put on free list.
     * would we ever want to keep the alloc callstack for freed entries,
     * or we always want to replace w/ free callstack?
     */
    client_remove_malloc_pre((byte *)ptr, (byte *)ptr + head->request_size,
                             (byte *)ptr + head->alloc_size, head->user_data);
    if (TESTANY(CHUNK_MMAP | CHUNK_PRE_US, head->flags)) {
        if (head->user_data != NULL)
            client_malloc_data_free(head->user_data);
        head->user_data = NULL;
    } else
        head->user_data = client_malloc_data_to_free_list(head->user_data, mc, caller);
    client_remove_malloc_post((byte *)ptr, (byte *)ptr + head->request_size,
                             (byte *)ptr + head->alloc_size);

    /* we ignore the return value */
    client_handle_free((byte *)ptr, head->request_size,
                       /* XXX: real_base is regular base for us => no pattern */
                       (byte *)ptr, head->alloc_size,
                       mc, caller, head->user_data _IF_WINDOWS(NULL));

    if (head->request_size >= LARGE_MALLOC_MIN_SIZE && !TEST(CHUNK_PRE_US, head->flags))
        malloc_large_remove(ptr);

    if (TEST(CHUNK_MMAP, head->flags)) {
        /* see comments in alloc routine about not delaying the free */
        byte *map = (byte *)ptr - alloc_ops.redzone_size - header_beyond_redzone;
        size_t map_size = head->alloc_size + alloc_ops.redzone_size*2 +
            header_beyond_redzone;
        heap_region_remove(map, map + map_size, mc);
        if (!os_large_free(map, map_size))
            ASSERT(false, "munmap failed");
    }

    dr_recurlock_unlock(allocator_lock);
}

/***************************************************************************
 * iterator
 */

typedef struct _alloc_iter_data_t {
    bool only_live;
    malloc_iter_cb_t cb;
    void *data;
} alloc_iter_data_t;

static bool
alloc_large_iter_cb(byte *start, size_t size, void *iter_data)
{
    alloc_iter_data_t *data = (alloc_iter_data_t *) iter_data;
    chunk_header_t *head = header_from_ptr(start);
    if (TEST(CHUNK_MMAP, head->flags)) {
        return data->cb(start, start + head->request_size, start + head->alloc_size, false,
                        head->flags & MALLOC_POSSIBLE_CLIENT_FLAGS, head->user_data,
                        data->data);
    } /* else already covered in main heap walk */
    return true;
}

static bool
alloc_iter_own_arena(byte *iter_arena_start, byte *iter_arena_end, uint flags
                     _IF_WINDOWS(HANDLE heap), void *iter_data)
{
    alloc_iter_data_t *data = (alloc_iter_data_t *) iter_data;
    chunk_header_t *head;
    byte *cur;

    if (TEST(HEAP_PRE_US, flags) || !TEST(HEAP_ARENA, flags))
        return true;

    LOG(2, "%s: "PFX"-"PFX"\n", __FUNCTION__, iter_arena_start, iter_arena_end);
    cur = iter_arena_start + alloc_ops.redzone_size + header_beyond_redzone;
    /* the current arena may not have any chunk at all and thus no CHUNK_ARENA_FINAL */
    if (iter_arena_start == arena_start)
        iter_arena_end = arena_next;
    while (cur < iter_arena_end) {
        head = header_from_ptr(cur);
        LOG(3, "\tchunk %s "PFX"-"PFX"\n", TEST(CHUNK_FREED, head->flags) ? "freed" : "",
            (head + 1), (byte *)(head + 1) + head->alloc_size);
        if (!data->only_live || !TEST(CHUNK_FREED, head->flags)) {
            byte *start = (byte *)(head + 1);
            if (!data->cb(start, start + head->request_size, start + head->alloc_size,
                          false/*!pre_us*/, head->flags & MALLOC_POSSIBLE_CLIENT_FLAGS,
                          head->user_data, data->data))
                return false;
        }
        /* don't try to walk over un-allocated extra space at end of arena */
        if (TEST(CHUNK_ARENA_FINAL, head->flags))
            break;
        cur += head->alloc_size + alloc_ops.redzone_size + header_beyond_redzone;
    }
    ASSERT(cur < iter_arena_end || iter_arena_start == arena_start, "invalid iter");
    return true;
}


static void
alloc_iterate(malloc_iter_cb_t cb, void *iter_data, bool only_live)
{
    /* Strategy:
     * + can iterate arenas via heap rbtree
     *   - each arena of ours can be walked straight through
     * + ignore pre-us arenas and instead iterate pre_us_table
     * + for large mallocs can iterate the large_malloc_tree
     */
    alloc_iter_data_t data = {only_live, cb, iter_data};
    uint i;

    LOG(2, "%s\n", __FUNCTION__);

    ASSERT(!alloc_ops.external_headers, "NYI: walk malloc table");

    heap_region_iterate(alloc_iter_own_arena, &data);

    /* our mmapped chunks should be in heap region tree too but it's easier
     * to get the headers from the large malloc tree
     */
    malloc_large_iterate(alloc_large_iter_cb, &data);

    /* XXX: should add hashtable_iterate() to drcontainers */
    for (i = 0; i < HASHTABLE_SIZE(pre_us_table.table_bits); i++) {
        /* we do NOT support removal while iterating.  we don't even hold a lock. */
        hash_entry_t *he;
        for (he = pre_us_table.table[i]; he != NULL; he = he->next) {
            chunk_header_t *head = (chunk_header_t *) he->payload;
            byte *start = he->key;
            if (!only_live || !TEST(CHUNK_FREED, head->flags)) {
                if (!cb(start, start + head->request_size, start + head->alloc_size,
                        true/*pre_us*/, head->flags & MALLOC_POSSIBLE_CLIENT_FLAGS,
                        head->user_data, iter_data))
                    break;
            }
        }
    }
}

bool
alloc_replace_overlaps_delayed_free(byte *start, byte *end,
                                    byte **free_start OUT,
                                    byte **free_end OUT,
                                    void **client_data OUT)
{
    /* Maintaining an rbtree is expensive, particularly b/c in order to keep
     * freed blocks in there until actual re-alloc we need to have rbtree
     * operations on every free and every malloc.
     * Since this query should only be when reporting an unaddr, we go ahead
     * do an expensive lookup, avoiding any maintenance on malloc or free.
     *
     * XXX: pattern mode may need a more performant lookup
     *
     * XXX: Note that this is not a true overlap of [start,end) and instead only
     * looks up start for now.  But, it's pretty unlikely to have the start be before
     * a heap arena and still overlap a free chunk.  For the large malloc lookup, it
     * will fall through to heap arena for non-mmap, and mmap has similar arg about
     * being unlikely to overlap w/o overlapping start.  But if we want to we could
     * add a heap_region_overlaps() routine.
     */
    byte *found_start = NULL;
    chunk_header_t *found_head = NULL;
    byte *found_arena_start, *found_arena_end;
    uint flags;
    size_t size;
    if (malloc_large_lookup(start, &found_arena_start, &size)) {
        found_head = header_from_ptr(found_arena_start);
        found_start = found_arena_start;
        ASSERT(found_arena_start + size == found_start + found_head->request_size,
               "inconsistent");
    } else if (heap_region_bounds(start, &found_arena_start, &found_arena_end, &flags)) {
        if (TEST(HEAP_PRE_US, flags)) {
            /* walk pre-us table */
            uint i;
            for (i = 0; i < HASHTABLE_SIZE(pre_us_table.table_bits); i++) {
                /* see notes in alloc_iterate() about no lock */
                hash_entry_t *he;
                for (he = pre_us_table.table[i]; he != NULL; he = he->next) {
                    chunk_header_t *head = (chunk_header_t *) he->payload;
                    byte *chunk_start = he->key;
                    if (start < chunk_start + head->request_size && end >= chunk_start) {
                        found_head = head;
                        found_start = chunk_start;
                    }
                }
                if (found_head != NULL)
                    break;
            }
        } else if (TEST(HEAP_ARENA, flags)) {
            /* walk arena */
            /* XXX: make a shared internal iterator for this? */
            byte *cur = found_arena_start + alloc_ops.redzone_size + header_beyond_redzone;
            while (cur < found_arena_end) {
                byte *chunk_start;
                chunk_header_t *head = header_from_ptr(cur);
                chunk_start = (byte *)(head + 1);
                if (start < chunk_start + head->request_size && end >= chunk_start) {
                    found_head = head;
                    found_start = chunk_start;
                    break;
                }
                /* don't try to walk over un-allocated extra space at end of arena */
                if (TEST(CHUNK_ARENA_FINAL, head->flags))
                    break;
                cur += head->alloc_size + alloc_ops.redzone_size + header_beyond_redzone;
            }
        } else
            ASSERT(false, "large lookup should have found it");
    }
    if (found_head != NULL && TEST(CHUNK_FREED, found_head->flags)) {
        if (free_start != NULL)
            *free_start = found_start;
        if (free_end != NULL)
            *free_end = found_start + found_head->request_size;
        if (client_data != NULL)
            *client_data = found_head->user_data;
        return true;
    } else
        return false;
}

/***************************************************************************
 * app-facing interface
 */

static void *
replace_malloc(size_t size)
{
    void *res;
    void *drcontext = enter_client_code();
    dr_mcontext_t mc;
    /* XXX: should we make mc a debug-only param for perf? */
    initialize_mcontext_for_report(&mc);
    LOG(2, "replace_malloc %d\n", size);
    res = (void *) replace_alloc_common(size, false/*!zeroed*/, false/*!realloc*/,
                                        drcontext, &mc, (app_pc)replace_malloc);
    LOG(2, "\treplace_malloc %d => "PFX"\n", size, res);
    exit_client_code(drcontext);
    return res;
}

static void *
replace_calloc(size_t nmemb, size_t size)
{
    void *drcontext = enter_client_code();
    byte *res;
    dr_mcontext_t mc;
    initialize_mcontext_for_report(&mc);
    LOG(2, "replace_calloc %d %d\n", nmemb, size);
    res = replace_alloc_common(nmemb * size, true/*zeroed*/, false/*!realloc*/,
                               drcontext, &mc, (app_pc)replace_calloc);
    memset(res, 0, nmemb*size);
    LOG(2, "\treplace_calloc %d %d => "PFX"\n", nmemb, size, res);
    exit_client_code(drcontext);
    return (void *) res;
}

static void *
replace_realloc(void *ptr, size_t size)
{
    void *drcontext = enter_client_code();
    void *res = NULL;
    dr_mcontext_t mc;
    chunk_header_t *head = header_from_ptr(ptr);
    initialize_mcontext_for_report(&mc);
    LOG(2, "replace_realloc "PFX" %d\n", ptr, size);
    if (ptr == NULL) {
        client_handle_realloc_null((app_pc)replace_realloc, &mc);
        res = (void *) replace_alloc_common(size, false/*!zeroed*/, true/*realloc*/,
                                            drcontext, &mc, (app_pc)replace_realloc);
    } else if (size == 0) {
        replace_free_common(ptr, drcontext, &mc, (app_pc)replace_realloc);
    } else if (!is_live_alloc(ptr, head)) {
        client_invalid_heap_arg((app_pc)replace_realloc, (byte *)ptr, &mc,
                                /* XXX: we might be replacing RtlReallocateHeap or
                                 * _realloc_dbg but it's not worth trying to
                                 * store the exact name
                                 */
                                "realloc", false/*!free*/);
    } else {
        if (head->alloc_size >= size && !TEST(CHUNK_PRE_US, head->flags)) {
            /* XXX: if shrinking a lot, should free and re-malloc to save space */
            client_handle_realloc(drcontext, (byte *)ptr, head->request_size,
                                  (byte *)ptr, size,
                                  /* XXX: real_base is regular base for us => no pattern */
                                  (byte *)ptr, &mc);
            if (head->request_size >= LARGE_MALLOC_MIN_SIZE)
                malloc_large_remove(ptr);
            head->request_size = size;
            if (head->request_size >= LARGE_MALLOC_MIN_SIZE)
                malloc_large_add(ptr, head->request_size);
            res = ptr;
        } else {
            /* XXX: use mremap for mmapped alloc! */
            /* XXX: if final chunk in arena, extend in-place */
            res = (void *) replace_alloc_common(size, false/*!zeroed*/, true/*realloc*/,
                                                drcontext, &mc, (app_pc)replace_realloc);
            if (res != NULL) {
                memcpy(res, ptr, head->request_size);
                replace_free_common(ptr, drcontext, &mc, (app_pc)replace_realloc);
            }
        }
    }
    LOG(2, "\treplace_realloc %d => "PFX"\n", size, res);
    exit_client_code(drcontext);
    return res;
}

static void
replace_free(void *ptr)
{
    void *drcontext = enter_client_code();
    dr_mcontext_t mc;
    initialize_mcontext_for_report(&mc);
    LOG(2, "replace_free "PFX"\n", ptr);
    replace_free_common(ptr, drcontext, &mc, (app_pc)replace_free);
    exit_client_code(drcontext);
}

static size_t
replace_malloc_usable_size(void *ptr)
{
    void *drcontext = enter_client_code();
    chunk_header_t *head = header_from_ptr(ptr);
    size_t res;
    dr_mcontext_t mc;
    initialize_mcontext_for_report(&mc);
    LOG(2, "replace_malloc_usable_size "PFX"\n", ptr);
    if (!is_live_alloc(ptr, head)) {
        client_invalid_heap_arg((app_pc)replace_malloc_usable_size, (byte *)ptr, &mc,
                                IF_WINDOWS_ELSE("_msize", "malloc_usable_size"),
                                false/*!free*/);
        return 0;
    }
    res = head->request_size; /* we do not allow using padding */
    LOG(2, "\treplace_malloc_usable_size "PFX" => "PIFX"\n", ptr, res);
    exit_client_code(drcontext);
    return res;
}

/* XXX i#882: replace operator new/delete known to be non-placement to
 * avoid wrap cost and to support redzones on debug CRT.
 * We will also be able to pass in the allocation type rather than
 * reading it from CLS.
 */

/* XXX i#94: replace mallopt(), mallinfo(), valloc(), memalign(), etc. */

/***************************************************************************
 * drmem-facing interface
 */

#ifdef LINUX
byte *
alloc_replace_orig_brk(void)
{
    ASSERT(alloc_ops.replace_malloc, "shouldn't call");
    return pre_us_brk;
}
#endif

bool
alloc_replace_in_cur_arena(byte *addr)
{
    ASSERT(alloc_ops.replace_malloc, "shouldn't call");
    return (addr >= arena_start && addr < arena_reserve_end);
}

bool
alloc_entering_replace_routine(app_pc pc)
{
    return drwrap_is_replaced_native(pc);
}

static void *
func_interceptor(routine_type_t type)
{
    if (is_malloc_routine(type))
        return (void *) replace_malloc;
    else if (is_calloc_routine(type))
        return (void *) replace_calloc;
    else if (is_realloc_routine(type))
        return (void *) replace_realloc;
    else if (is_free_routine(type))
        return (void *) replace_free;
    else if (is_size_routine(type))
        return (void *) replace_malloc_usable_size;
    else
        return NULL;
}

static void
malloc_replace__intercept(app_pc pc, routine_type_t type, alloc_routine_entry_t *e)
{
    void *interceptor = func_interceptor(type);
    if (interceptor != NULL) {
        if (!drwrap_replace_native(pc, interceptor, false))
            ASSERT(false, "failed to replace alloc routine");
    } else {
        /* else wrap: operators in particular.
         * XXX i#882: replace operators. 
         */
        /* FIXME i#794: Windows NYI: want to replace
         * create/destroy/validate/etc., along with all other
         * heap-related routines currenly not intercepted, w/ nops
         */
       malloc_wrap__intercept(pc, type, e);
    }
}

static void
malloc_replace__unintercept(app_pc pc, routine_type_t type, alloc_routine_entry_t *e)
{
    void *interceptor = func_interceptor(type);
    if (interceptor != NULL) {
        if (!drwrap_replace_native(pc, NULL, true))
            ASSERT(false, "failed to un-replace alloc routine");
    } else {
        malloc_wrap__unintercept(pc, type, e);
    }
}

static void
malloc_replace__add(app_pc start, app_pc end, app_pc real_end,
                   bool pre_us, uint client_flags, dr_mcontext_t *mc, app_pc post_call)
{
    IF_DEBUG(bool new_entry;)
    chunk_header_t *head = global_alloc(sizeof(*head), HEAPSTAT_HASHTABLE);
    head->request_size = (end - start);
    if (head->request_size >= LARGE_MALLOC_MIN_SIZE)
        malloc_large_add(start, head->request_size);
    head->alloc_size = (real_end - start);
    head->flags = CHUNK_PRE_US;
    head->magic = HEADER_MAGIC;
    head->user_data = NULL;
    /* we assume only called for pre_us and only during init when no lock is needed */
    ASSERT(pre_us, "malloc add from outside must be pre_us");
    IF_DEBUG(new_entry =)
        hashtable_add(&pre_us_table, (void *)start, (void *)head);
    ASSERT(new_entry, "should be no pre-us dups");
    notify_client_alloc(false/*no handle: caller can do that on its own*/,
                        NULL, start, head, mc,
                        false/*zeroed?  dunno*/, false/*!realloc*/, post_call);
}

static bool
malloc_replace__is_pre_us_ex(app_pc start, bool ok_if_invalid)
{
    /* see notes up top about not needing an external lock */
    chunk_header_t *head = hashtable_lookup(&pre_us_table, (void *)start);
    return (head != NULL && (ok_if_invalid || !TEST(CHUNK_FREED, head->flags)));
}

static bool
malloc_replace__is_pre_us(app_pc start)
{
    return malloc_replace__is_pre_us_ex(start, false);
}

static app_pc
malloc_replace__end(app_pc start)
{
    chunk_header_t *head = header_from_ptr(start);
    if (!is_live_alloc(start, head))
        return NULL;
    else
        return start + head->request_size;
}

/* Returns -1 on failure */
static ssize_t
malloc_replace__size(app_pc start)
{
    chunk_header_t *head = header_from_ptr(start);
    /* avoid crashing when drmem does neighbor discovery queries.
     * see comment under is_valid_chunk() on why TRY isn't up there.
     */
    ssize_t res = -1;
    DR_TRY_EXCEPT(dr_get_current_drcontext(), {
        if (is_live_alloc(start, head))
            res = head->request_size;
    }, { /* EXCEPT */
        res = -1;
    });
    return res;
}

static ssize_t
malloc_replace__size_invalid_only(app_pc start)
{
    chunk_header_t *head = header_from_ptr(start);
    if (!is_valid_chunk(start, head) || !TEST(CHUNK_FREED, head->flags))
        return -1;
    else
        return head->request_size;
}

static void *
malloc_replace__get_client_data(app_pc start)
{
    chunk_header_t *head = header_from_ptr(start);
    if (!is_valid_chunk(start, head))
        return NULL;
    return head->user_data;
}

static uint
malloc_replace__get_client_flags(app_pc start)
{
    chunk_header_t *head = header_from_ptr(start);
    if (!is_valid_chunk(start, head))
        return 0;
    return (head->flags & MALLOC_POSSIBLE_CLIENT_FLAGS);
}

static bool
malloc_replace__set_client_flag(app_pc start, uint client_flag)
{
    chunk_header_t *head = header_from_ptr(start);
    if (!is_valid_chunk(start, head))
        return false;
    head->flags |= (client_flag & MALLOC_POSSIBLE_CLIENT_FLAGS);
    return true;
}

static bool
malloc_replace__clear_client_flag(app_pc start, uint client_flag)
{
    chunk_header_t *head = header_from_ptr(start);
    if (!is_valid_chunk(start, head))
        return false;
    head->flags &= ~(client_flag & MALLOC_POSSIBLE_CLIENT_FLAGS);
    return true;
}

static void
malloc_replace__iterate(bool (*cb)(app_pc start, app_pc end, app_pc real_end,
                                  bool pre_us, uint client_flags,
                                  void *client_data, void *iter_data), void *iter_data)
{
    alloc_iterate(cb, iter_data, true/*live only*/);
}

static void
malloc_replace__lock(void)
{
    dr_recurlock_lock(allocator_lock);
}

static void
malloc_replace__unlock(void)
{
    dr_recurlock_unlock(allocator_lock);
}

void
alloc_replace_init(void)
{
    ASSERT(sizeof(free_header_t) <=
           (alloc_ops.external_headers ? 0 : sizeof(chunk_header_t)) + CHUNK_MIN_SIZE,
           "min size too small");
    ASSERT(ALIGNED(sizeof(chunk_header_t), CHUNK_ALIGNMENT), "alignment off");

    ASSERT(CHUNK_MIN_MMAP >= LARGE_MALLOC_MIN_SIZE,
           "we rely on mmapped chunks being in large malloc table");

    ASSERT(ARENA_INITIAL_SIZE >= CHUNK_MIN_MMAP, "arena must hold at least 1 chunk");

    ASSERT(ALIGNED(alloc_ops.redzone_size, CHUNK_ALIGNMENT), "redzone alignment off");

    if (alloc_ops.redzone_size < HEADER_SIZE)
        header_beyond_redzone = HEADER_SIZE - alloc_ops.redzone_size;

    allocator_lock = dr_recurlock_create();

    hashtable_init(&pre_us_table, PRE_US_TABLE_HASH_BITS, HASH_INTPTR, false/*!strdup*/);

#ifdef LINUX
    /* we waste pre-brk space of pre-us allocator, and we assume we're
     * now completely replacing the pre-us allocator.
     * XXX: better to not use brk and solely use mmap instead?
     */
    cur_brk = get_brk(false);
    pre_us_brk = cur_brk;
    arena_start = pre_us_brk;
    cur_brk = set_brk(cur_brk + PAGE_SIZE);
    arena_commit_end = cur_brk;
    arena_reserve_end = arena_commit_end;
    /* XXX: for delayed instru we will need to handle this; for now we assert */
    ASSERT(cur_brk > arena_start, "failed to increase brk at init");
    LOG(2, "heap orig brk="PFX"\n", pre_us_brk);
#else
    arena_start = os_large_alloc(ARENA_INITIAL_COMMIT, ARENA_INITIAL_SIZE);
    ASSERT(arena_start != NULL, "can't allocate initial heap: fatal");
    arena_commit_end = arena_start + ARENA_INITIAL_COMMIT;
    arena_reserve_end = arena_start + ARENA_INITIAL_SIZE;
#endif
    heap_region_add(arena_start, arena_reserve_end, HEAP_ARENA, NULL);
    /* need to start with a redzone */
    arena_next = arena_start + alloc_ops.redzone_size + header_beyond_redzone;

    /* set up pointers for per-malloc API */
    malloc_interface.malloc_lock = malloc_replace__lock;
    malloc_interface.malloc_unlock = malloc_replace__unlock;
    malloc_interface.malloc_end = malloc_replace__end;
    malloc_interface.malloc_add = malloc_replace__add;
    malloc_interface.malloc_is_pre_us = malloc_replace__is_pre_us;
    malloc_interface.malloc_is_pre_us_ex = malloc_replace__is_pre_us_ex;
    malloc_interface.malloc_size = malloc_replace__size;
    malloc_interface.malloc_size_invalid_only = malloc_replace__size_invalid_only;
    malloc_interface.malloc_get_client_data = malloc_replace__get_client_data;
    malloc_interface.malloc_get_client_flags = malloc_replace__get_client_flags;
    malloc_interface.malloc_set_client_flag = malloc_replace__set_client_flag;
    malloc_interface.malloc_clear_client_flag = malloc_replace__clear_client_flag;
    malloc_interface.malloc_iterate = malloc_replace__iterate;
    malloc_interface.malloc_intercept = malloc_replace__intercept;
    malloc_interface.malloc_unintercept = malloc_replace__unintercept;
}

static bool
free_arena_at_exit(byte *start, byte *end, uint flags
                   _IF_WINDOWS(HANDLE heap), void *iter_data)
{
    if (TEST(HEAP_ARENA, flags) && !TEST(HEAP_PRE_US, flags)) {
#ifdef LINUX
        if (end != cur_brk)
#endif
            os_large_free(start, end - start);
    }
    return true;
}

static bool
free_user_data_at_exit(app_pc start, app_pc end, app_pc real_end,
                       bool pre_us, uint client_flags,
                       void *client_data, void *iter_data)
{
    if (!pre_us) {
        chunk_header_t *head = header_from_ptr(start);
        if (head->user_data != NULL)
            client_malloc_data_free(head->user_data);
    }
    return true; /* keep iterating */
}

void
alloc_replace_exit(void)
{
    uint i;
    alloc_iterate(free_user_data_at_exit, NULL, false/*free too*/);
    /* XXX: should add hashtable_iterate() to drcontainers */
    for (i = 0; i < HASHTABLE_SIZE(pre_us_table.table_bits); i++) {
        hash_entry_t *he, *next;
        for (he = pre_us_table.table[i]; he != NULL; he = next) {
            chunk_header_t *head = (chunk_header_t *) he->payload;
            next = he->next;
            if (head->user_data != NULL)
                client_malloc_data_free(head->user_data);
            global_free(head, sizeof(*head), HEAPSTAT_HASHTABLE);
        }
    }
    hashtable_delete_with_stats(&pre_us_table, "pre_us");

    heap_region_iterate(free_arena_at_exit, NULL);

    dr_recurlock_destroy(allocator_lock);
}
