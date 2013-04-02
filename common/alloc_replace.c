/* **********************************************************
 * Copyright (c) 2012-2013 Google, Inc.  All rights reserved.
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
 * + redzones are shared among adjacent allocs and are centered to
 *   reduce the likelihood of corruption from over/underflow:
 *
 *  | request sz|     |   redzone size   | request size |   |   redzone size   |
 *  | app chunk | pad |rz/2| header |rz/2| app chunk    |pad|rz/2| header /rz/2|
 *                                                                             ^
 *                                                                 next_chunk _|
 *
 * + arena->next_chunk always has a redzone + header space (if co-located, i.e.,
 *   !alloc_ops.external_headers) to its left
 * + free lists are kept in buckets by size.  larger is preferred over
 *   searching.  final bucket is var-sized and is always searched.
 *   frees are appended to make the lists FIFO for better delaying
 *   (though worse alloc re-use), and searches start at the front and
 *   take the first fit.
 *   we can add fancier algorithms in the future.
 * + for alloc_ops.external_headers, free list entries use headers that
 *   are co-located with the chunk headers
 * + for !alloc_ops.external_headers, free list entry headers begin where
 *   regular headers begin, in the middle of the redzone.
 */

#include "dr_api.h"
#include "drwrap.h"
#include "drmgr.h"
#include "utils.h"
#include "asm_utils.h"
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
/* initial commit on linux has to hold at least one non-mmap chunk */
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

/* Values stored in chunk header flags */
enum {
    CHUNK_FREED       = MALLOC_RESERVED_1,
    CHUNK_MMAP        = MALLOC_RESERVED_2,
    /* MALLOC_RESERVED_{3,4} are used for types */
    CHUNK_PRE_US      = MALLOC_RESERVED_5,
    /* MALLOC_RESERVED_6 could be used to indicate presence of prev
     * free chunk for coalescing (i#948)
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
    void *user_data;
    /* if we wanted to save space we could hand out sizes only equal to the buckets
     * and remove one of these.  we'd use a separate header for the largest bucket
     * that had the alloc_size.
     */
    heapsz_t request_size;
    heapsz_t alloc_size;
    ushort flags;
    /* Put magic last for a greater chance of surviving underflow, esp when our
     * header has no redzone buffer (when redzone_size <= HEADER_SIZE, which
     * unfortunately is true by default as both are 16 for 32-bit).
     */
    ushort magic;
#ifdef X64
    /* compiler will add anyawy: just making explicit.  we need the header
     * size to be aligned to 8 so we can't pack.  for alloc_ops.external_headers
     * we eat this overhead to provide runtime flexibility w/ the same
     * data struct as we don't need it there.
     */
    uint pad;
#endif
} chunk_header_t;

#define HEADER_SIZE sizeof(chunk_header_t)

/* if redzone is too small, header sticks beyond it */
static heapsz_t header_beyond_redzone;
/* we place header in the middle */
static heapsz_t redzone_beyond_header;

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

typedef struct _free_lists_t {
    /* a normal free list can be LIFO, but for more effective delayed frees
     * we want FIFO.  FIFO-per-bucket-size is sufficient.
     */
    free_header_t *front[NUM_FREE_LISTS];
    free_header_t *last[NUM_FREE_LISTS];
} free_lists_t;

/* counters for delayed frees.  protected by malloc lock. */
static uint delayed_chunks;
static size_t delayed_bytes;

#ifdef LINUX
/* we assume we're the sole users of the brk (after pre-us allocs) */
static byte *pre_us_brk;
static byte *cur_brk;
#endif

/* header at the top of each arena (an "arena" for this code is a contiguous
 * piece of memory parceled out into individual malloc "chunks")
 */
typedef struct _arena_header_t {
    byte *start_chunk;
    byte *next_chunk;
    byte *commit_end;
    byte *reserve_end;
    free_lists_t *free_list;
    void *lock;
    uint flags;
#ifdef WINDOWS
    uint magic;
    /* we need to iterate arenas belonging to one (non-default) Heap */
    struct _arena_header_t *next_arena;
#endif
    /* for main arena of each Heap, we inline free_lists_t here */
} arena_header_t;

#ifdef WINDOWS
/* pick a flag that can't be passed on the Heap level to identify whether
 * a Heap or a regular arena
 */
# define ARENA_MAIN HEAP_ZERO_MEMORY  /* 0x8 */
/* another non-Heap flag to identify libc-default Heaps (i#939) */
# define ARENA_LIBC_DEFAULT HEAP_REALLOC_IN_PLACE_ONLY /* 0x10 */
/* flags that we support being passed to HeapCreate:
 * HEAP_CREATE_ENABLE_EXECUTE | HEAP_GENERATE_EXCEPTIONS | HEAP_NO_SERIALIZE
 */
# define HEAP_CREATE_POSSIBLE_FLAGS 0x40005
static HANDLE process_heap;
#else
# define ARENA_MAIN 0x0001
#endif

/* Linux current arena, or Windows default Heap */
static arena_header_t *cur_arena;

/* For handling pre-us mallocs for non-earliest injection or delayed/attach
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

static inline void *
enter_client_code(void)
{
    void *drcontext = dr_get_current_drcontext();

    /* For our callstack walk we need the frame ptr of our replacement
     * functions to be marked defined.  By using our replace xbp we
     * have the malloc frame in the callstack (i#639).
     * Note that we do not want to, say, pass in the mcontext and
     * mark defined through get_stack_registers()'s xsp, as that
     * will mark a bunch of uninitialized slots on the stack.
     */
    byte *final_app_xsp = (byte *)
        dr_read_saved_reg(drcontext, DRWRAP_REPLACE_NATIVE_SP_SLOT);
    client_stack_alloc((byte *)final_app_xsp - sizeof(void*), (byte *)final_app_xsp,
                       true/*defined*/);

    /* while we are using the app's stack and registers, we need to
     * switch to the private peb/teb to avoid asserts in symbol
     * routines.
     * XXX: is it safe to do away w/ this and relax the asserts?
     * if perf becomes an issue we could do a lazy swap on symbol
     * queries (and hope no other private lib calls occur).
     *
     * On Linux we don't need to swap b/c we (and our priv libs) won't
     * examine the selectors or descriptors: -mangle_app_seg ensures
     * we don't need to swap.  Which is good b/c a swap involves a
     * system call which kills performance: i#941.
     */
#ifdef WINDOWS
    dr_switch_to_dr_state(drcontext);
#endif
    return drcontext;
}

static void
exit_client_code(void *drcontext, bool in_app_mode)
{
    byte *final_app_xsp = (byte *)
        dr_read_saved_reg(drcontext, DRWRAP_REPLACE_NATIVE_SP_SLOT);
    client_stack_dealloc((byte *)final_app_xsp - sizeof(void*), (byte *)final_app_xsp);

#if WINDOWS
    if (!in_app_mode)
        dr_switch_to_app_state(drcontext);
#endif

    drwrap_replace_native_fini(drcontext);
}


/* i#900: we need to mark an app lock acquisition as a safe spot.
 * This is made possible by drwrap_replace_native() using a continuation
 * strategy rather than returning to the code cache.
 * N.B.: no DR lock can be held by the caller!
 */
static void
app_heap_lock(void *drcontext, void *recur_lock)
{
    dr_mark_safe_to_suspend(drcontext, true/*enter safe region*/);
    dr_recurlock_lock(recur_lock);
    dr_mark_safe_to_suspend(drcontext, false/*exit safe region*/);
}

static void
app_heap_unlock(void *drcontext, void *recur_lock)
{
    /* Nothing special, just for symmetry */
    dr_recurlock_unlock(recur_lock);
}

/* This must be inlined to get an xsp that's in the call chain */
#define INITIALIZE_MCONTEXT_FOR_REPORT(mc) do {            \
    /* assumption: we only need xsp and xbp initialized */ \
    (mc)->size = sizeof(*(mc));                            \
    (mc)->flags = DR_MC_CONTROL | DR_MC_INTEGER;           \
    get_stack_registers(&(mc)->xsp, &(mc)->xbp);           \
} while (0)

#ifdef WINDOWS
static inline uint
arena_page_prot(uint flags)
{
    return TEST(HEAP_CREATE_ENABLE_EXECUTE, flags) ?
        PAGE_EXECUTE_READWRITE : PAGE_READWRITE;
}
#endif

static byte *
os_large_alloc(size_t commit_size _IF_WINDOWS(size_t reserve_size) _IF_WINDOWS(uint prot))
{
    /* FIXME DRi#199: how notify DR about app mem alloc?
     * provide general raw_syscall() interface,
     * or dr_mmap_as_app() or sthg.
     * for now using our own raw syscall...
     */
#ifdef LINUX
    byte *map = (byte *) raw_syscall
        (IF_X64_ELSE(SYS_mmap, SYS_mmap2), 6, (ptr_int_t)NULL, commit_size,
         PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    ASSERT(ALIGNED(commit_size, PAGE_SIZE), "must align to at least page size");
    if ((ptr_int_t)map < 0 && (ptr_int_t)map > -PAGE_SIZE) {
        LOG(2, "os_large_alloc FAILED with return value "PFX"\n", map);
        return NULL;
    }
    LOG(3, "%s commit="PIFX" => "PFX"\n", __FUNCTION__, commit_size, map);
    return map;
#else
    byte *loc = NULL;
    ASSERT(ALIGNED(commit_size, PAGE_SIZE), "must align to at least page size");
    ASSERT(ALIGNED(reserve_size, PAGE_SIZE), "must align to at least page size");
    ASSERT(reserve_size >= commit_size, "must reserve more than commit");
    if (!virtual_alloc(&loc, reserve_size, MEM_RESERVE, PAGE_NOACCESS))
        return NULL;
    if (!virtual_alloc(&loc, commit_size, MEM_COMMIT, prot)) {
        virtual_free(loc);
        return NULL;
    }
    LOG(3, "%s commit="PIFX" reserve="PIFX" prot="PIFX" => "PFX"\n",
        __FUNCTION__, commit_size, reserve_size, prot, loc);
    return loc;
#endif
}

/* For Windows, up to caller to ensure new_commit_size <= previously reserved size */
static bool
os_large_alloc_extend(byte *map, size_t cur_commit_size, size_t new_commit_size
                      _IF_WINDOWS(uint prot))
{
    ASSERT(ALIGNED(cur_commit_size, PAGE_SIZE), "must align to at least page size");
    ASSERT(ALIGNED(new_commit_size, PAGE_SIZE), "must align to at least page size");
#ifdef LINUX
    byte *newmap = (byte *) raw_syscall
        (SYS_mremap, 4, (ptr_int_t)map, cur_commit_size, new_commit_size, 0/*can't move*/);
    if ((ptr_int_t)newmap < 0 && (ptr_int_t)newmap > -PAGE_SIZE)
        return false;
    return true;
#else
    return virtual_alloc(&map, new_commit_size, MEM_COMMIT, prot);
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
    success = (int) raw_syscall(SYS_munmap, 2, (ptr_int_t)map, map_size);
    LOG(3, "%s "PFX" size="PIFX" => %d\n",  __FUNCTION__, map, map_size, success);
    return (success == 0);
#else
    LOG(3, "%s "PFX" size="PIFX"\n", __FUNCTION__, map, map_size);
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
        else {
            return (chunk_header_t *) ((byte *)ptr - redzone_beyond_header - HEADER_SIZE);
        }
    }
}

static inline byte *
ptr_from_header(chunk_header_t *head)
{
    if (alloc_ops.external_headers) {
        /* XXX i#879: hashtable lookup */
        ASSERT(false, "NYI");
        return NULL;
    } else
        return (byte *)head + redzone_beyond_header + HEADER_SIZE;
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
        /* Unlike a regular malloc library, we cannot afford to crash on
         * a bogus arg from the app b/c Dr. Memory is supposed to detect
         * invalid args and crashes.  We use DR's new, fast dr_safe_read()
         * (via safe_read()) to have low overhead yet stability.
         * An alternative might be a top-level crash handler
         * that bails out w/ an error report about invalid args.
         */
        ushort magic;
        /* App heap corruption can touch our magic field (deliberately
         * nearest the app alloc), causing us to report as an invalid
         * heap arg (after reporting the unaddr access) and later as a
         * leak, which doesn't seem ideal: but it's hard to do better.
         * Xref i#950.
         */
        return (ptr != NULL &&
                ALIGNED(ptr, CHUNK_ALIGNMENT) &&
                safe_read(&head->magic, sizeof(magic), &magic) &&
                magic == HEADER_MAGIC);
    }
}

/* This is called on every free, so keep it efficient.
 * However, esp on Windows, we must pay the overhead to avoid crashes
 * from callers causing us to mix our free lists across Heaps.
 *
 * Up to caller to check for large allocs, which are not inside arenas!
 * (Yes, this means that on Windows the app can pass any Heap it likes: so
 * far that hasn't been an issue but one could imagine a Heap flag that
 * needs to apply to a large alloc free or size query.)
 */
static inline bool
ptr_is_in_arena(byte *ptr, arena_header_t *arena)
{
#ifdef WINDOWS
    arena_header_t *a;
    for (a = arena; a != NULL; a = a->next_arena) {
        if (ptr >= a->start_chunk && ptr < a->commit_end)
            return true;
    }
    return false;
#else
    return (ptr >= arena->start_chunk && ptr < arena->commit_end);
#endif
}

/* Returns true iff ptr is a live alloc inside arena.  Thus, will return
 * false for pre-us allocs from other arenas.
 */
static bool
is_live_alloc(void *ptr, arena_header_t *arena, chunk_header_t *head)
{
    bool live = false;
    if (alloc_ops.external_headers) {
        live = (head != NULL);
    } else {
        live = (is_valid_chunk(ptr, head) &&
                !TEST(CHUNK_FREED, head->flags));
    }
    return (live &&
            /* large allocs are their own arenas */
            (TEST(CHUNK_MMAP, head->flags) || ptr_is_in_arena(ptr, arena)));
}

/* returns NULL if an invalid ptr, but will return a freed chunk */
static inline chunk_header_t *
header_from_ptr_include_pre_us(void *ptr)
{
    chunk_header_t *head = header_from_ptr(ptr);
    if (!is_valid_chunk(ptr, head))
        head = hashtable_lookup(&pre_us_table, (void *)ptr);
    return head;
}

/* assumes caller initialized commit_end and reserve_end fields */
static void
arena_init(arena_header_t *arena, arena_header_t *parent)
{
    size_t header_size = sizeof(*arena);
    if (parent != NULL) {
        arena->flags = parent->flags;
        arena->lock = parent->lock;
        arena->free_list = parent->free_list;
    } else {
        arena->flags = ARENA_MAIN;
        arena->lock = dr_recurlock_create();
        /* We only grab this DR lock as the app and we mark it with
         * dr_recurlock_mark_as_app(), as well as using dr_mark_safe_to_suspend(),
         * to ensure proper DR behavior
         */
        dr_recurlock_mark_as_app(arena->lock);
        /* to avoid complications of storing and freeing DR heap we inline these
         * in the main arena's header
         */
        arena->free_list = (free_lists_t *) ((byte *)arena + header_size);
        header_size += sizeof(*arena->free_list);
    }
    /* need to start with a redzone */
    arena->start_chunk = (byte *)arena +
        ALIGN_FORWARD(header_size, CHUNK_ALIGNMENT) +
        alloc_ops.redzone_size + header_beyond_redzone;
    arena->next_chunk = arena->start_chunk;
#ifdef WINDOWS
    arena->magic = HEADER_MAGIC;
    arena->next_arena = NULL;
    if (parent != NULL) {
        ASSERT(parent->next_arena == NULL, "should only append to end");
        parent->next_arena = arena;
    }
#endif
}

/* up to caller to call heap_region_remove() before calling here,
 * as we can't call it here b/c we're invoked from heap_region_iterate()
 */
static void
arena_free(arena_header_t *arena)
{
    if (TEST(ARENA_MAIN, arena->flags))
        dr_recurlock_destroy(arena->lock);
#ifdef LINUX
    if (arena->reserve_end != cur_brk)
#endif
        os_large_free((byte *)arena, arena->reserve_end - (byte *)arena);
}

/* either extends arena in-place and returns it, or allocates a new arena
 * and returns that.  returns NULL on failure to do either.
 */
static arena_header_t *
arena_extend(arena_header_t *arena, heapsz_t add_size)
{
    heapsz_t aligned_add = (heapsz_t) ALIGN_FORWARD(add_size, PAGE_SIZE);
    arena_header_t *new_arena;
#ifdef LINUX
    if (arena->commit_end == cur_brk) {
        byte *new_brk = set_brk(cur_brk + aligned_add);
        if (new_brk >= cur_brk + add_size) {
            LOG(2, "\tincreased brk from "PFX" to "PFX"\n", cur_brk, new_brk);
            cur_brk = new_brk;
            arena->commit_end = new_brk;
            heap_region_adjust((byte *)arena, new_brk);
            return arena;
        } else
            LOG(1, "brk cannot expand: switching to mmap\n");
    } else
#else
    if (arena->commit_end + aligned_add <= arena->reserve_end)
#endif
    { /* here to not confuse brace matching */
        size_t cur_size = arena->commit_end - (byte *)arena;
        size_t new_size = cur_size + aligned_add;
        if (os_large_alloc_extend((byte *)arena, cur_size, new_size
                                  _IF_WINDOWS(arena_page_prot(arena->flags)))) {
            arena->commit_end = (byte *)arena + new_size;
#ifdef LINUX /* windows already added whole reservation */
            heap_region_adjust((byte *)arena, (byte *)arena + new_size);
#endif
            return arena;
        }
    }
#ifdef WINDOWS
    if (!TEST(HEAP_GROWABLE, arena->flags))
        return NULL;
#endif
    /* XXX: add stranded space at end of arena to free list */
    LOG(1, "cur arena "PFX"-"PFX" out of space: creating new one\n",
        (byte *)arena, arena->reserve_end);
    new_arena = (arena_header_t *)
        os_large_alloc(IF_WINDOWS_(ARENA_INITIAL_COMMIT) ARENA_INITIAL_SIZE
                       _IF_WINDOWS(arena_page_prot(arena->flags)));
    if (new_arena == NULL)
        return NULL;
#ifdef LINUX
    new_arena->commit_end = (byte *)new_arena + ARENA_INITIAL_SIZE;
#else
    new_arena->commit_end = (byte *)new_arena + ARENA_INITIAL_COMMIT;
#endif
    new_arena->reserve_end = (byte *)new_arena + ARENA_INITIAL_SIZE;
    heap_region_add((byte *)new_arena, new_arena->reserve_end, HEAP_ARENA, NULL);
    arena_init(new_arena, arena);
    return new_arena;
}

static chunk_header_t *
search_free_list_bucket(arena_header_t *arena, heapsz_t aligned_size, uint bucket)
{
    /* search for large enough chunk */
    free_header_t *cur, *prev;
    chunk_header_t *head = NULL;
#ifdef LINUX
    /* On Windows we have HEAP_NO_SERIALIZE.  Not worth passing the flags in. */
    ASSERT(dr_recurlock_self_owns(arena->lock), "caller must hold lock");
#endif
    ASSERT(bucket < NUM_FREE_LISTS, "invalid param");
    for (cur = arena->free_list->front[bucket], prev = NULL;
         cur != NULL && cur->head.alloc_size < aligned_size;
         prev = cur, cur = cur->next)
        ; /* nothing */
    if (cur != NULL) {
        if (prev == NULL)
            arena->free_list->front[bucket] = cur->next;
        else
            prev->next = cur->next;
        if (cur == arena->free_list->last[bucket])
            arena->free_list->last[bucket] = prev;
        head = (chunk_header_t *) cur;
    }
    LOG(3, "arena "PFX" bucket %d free front="PFX" last="PFX"\n",
        arena, bucket, arena->free_list->front[bucket],
        arena->free_list->last[bucket]);
    return head;
}

static chunk_header_t *
find_free_list_entry(arena_header_t *arena, heapsz_t request_size, heapsz_t aligned_size)
{
    chunk_header_t *head = NULL;
    uint bucket;
#ifdef LINUX
    /* On Windows we have HEAP_NO_SERIALIZE.  Not worth passing the flags in. */
    ASSERT(dr_recurlock_self_owns(arena->lock), "caller must hold lock");
#endif

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
    if (arena->free_list->front[bucket] == NULL && bucket > 0 &&
        aligned_size < free_list_sizes[bucket]) {
        /* next-bigger is not avail: search maybe-big-enough bucket before
         * possibly going to even bigger buckets
         */
        bucket--;
        head = search_free_list_bucket(arena, aligned_size, bucket);
        if (head == NULL)
            bucket++;
    }
    
    /* if delay frees are piling up, use a larger bucket to avoid
     * delaying a ton of allocs of a certain size and never re-using
     * them for pathological app alloc sequences
     */
    if (head == NULL && arena->free_list->front[bucket] == NULL &&
        (delayed_chunks >= 2*alloc_ops.delay_frees ||
         delayed_bytes >= 2*alloc_ops.delay_frees_maxsz)) {
        LOG(2, "\tallocating from larger bucket size to reduce delayed frees\n");
        while (bucket < NUM_FREE_LISTS - 1 && arena->free_list->front[bucket] == NULL)
            bucket++;
    }

    if (head == NULL && arena->free_list->front[bucket] != NULL) {
        if (bucket == NUM_FREE_LISTS - 1) {
            /* var-size bucket: have to search */
            head = search_free_list_bucket(arena, aligned_size, bucket);
        } else {
            /* guaranteed to be big enough so take from front */
            ASSERT(aligned_size <= free_list_sizes[bucket], "logic error");
            head = (chunk_header_t *) arena->free_list->front[bucket];
            arena->free_list->front[bucket] = arena->free_list->front[bucket]->next;
            if (head == (chunk_header_t *) arena->free_list->last[bucket])
                arena->free_list->last[bucket] = arena->free_list->front[bucket];
            LOG(3, "arena "PFX" bucket %d free front="PFX" last="PFX"\n",
                arena, bucket, arena->free_list->front[bucket],
                arena->free_list->last[bucket]);
        }
    }

    if (head != NULL) {
        LOG(2, "\tusing free list size=%d for request=%d align=%d from bucket %d\n",
            head->alloc_size, request_size, aligned_size, bucket);
        ASSERT(delayed_chunks > 0, "delay counter off");
        delayed_chunks--;
        ASSERT(delayed_bytes >= head->alloc_size, "delay bytes counter off");
        delayed_bytes -= head->alloc_size;
        if (head->user_data != NULL) {
            client_malloc_data_free(head->user_data);
            head->user_data = NULL;
        }
        head->flags &= ~(CHUNK_FREED | MALLOC_ALLOCATOR_FLAGS);
    }
    return head;
}

/* invoke_client only applies to successful allocation and only client_handle_malloc():
 * client is still notified on failure, and is notified of post-malloc.
 */
static byte *
replace_alloc_common(arena_header_t *arena, size_t request_size,
                     /* XXX: turn these 4 bools into flags? */
                     bool synch, bool zeroed, bool realloc, bool invoke_client,
                     void *drcontext, dr_mcontext_t *mc, app_pc caller,
                     uint alloc_type)
{
    heapsz_t aligned_size;
    byte *res = NULL;
    chunk_header_t *head = NULL;
    ASSERT((alloc_type & ~(MALLOC_ALLOCATOR_FLAGS)) == 0, "invalid type flags");

    if (request_size > UINT_MAX ||
        /* catch overflow in chunk or mmap alignment: no need to support really
         * large sizes within a page of UINT_MAX (i#944)
         */
        ALIGN_FORWARD(request_size, PAGE_SIZE) < request_size) {
        /* rather than have larger headers for 64-bit we just don't support
         * enormous allocations
         */
        client_handle_alloc_failure(request_size, zeroed, realloc, caller, mc);
        return NULL;
    }

    aligned_size = ALIGN_FORWARD(request_size, CHUNK_ALIGNMENT);
    ASSERT(aligned_size >= request_size, "overflow should have been caught");
    if (aligned_size < CHUNK_MIN_SIZE)
        aligned_size = CHUNK_MIN_SIZE;

    /* XXX i#948: use per-thread free lists to avoid lock in common case */
    if (synch)
        app_heap_lock(drcontext, arena->lock);

    /* for large requests we do direct mmap with own redzones.
     * we use the large malloc table to track them for iteration.
     * XXX: for simplicity, not delay-freeing these for now
     */
    if (aligned_size + HEADER_SIZE >= CHUNK_MIN_MMAP) {
        size_t map_size = (size_t)
            ALIGN_FORWARD(aligned_size + alloc_ops.redzone_size*2 +
                          header_beyond_redzone, PAGE_SIZE);
        byte *map = os_large_alloc(map_size _IF_WINDOWS(map_size)
                                   _IF_WINDOWS(arena_page_prot(arena->flags)));
        ASSERT(map_size >= aligned_size, "overflow should have been caught");
        LOG(2, "\tlarge alloc %d => mmap @"PFX"\n", request_size, map);
        if (map == NULL) {
            client_handle_alloc_failure(request_size, zeroed, realloc, caller, mc);
            goto replace_alloc_common_done;
        }
        ASSERT(!alloc_ops.external_headers, "NYI");
        head = (chunk_header_t *) (map + alloc_ops.redzone_size +
                                   header_beyond_redzone - redzone_beyond_header -
                                   HEADER_SIZE);
        head->flags |= CHUNK_MMAP;
        head->magic = HEADER_MAGIC;
        head->alloc_size = map_size - alloc_ops.redzone_size*2 - header_beyond_redzone;
        heap_region_add(map, map + map_size, HEAP_MMAP, mc);
    } else {
        /* look for free list entry */
        head = find_free_list_entry(arena, request_size, aligned_size);
    }

    /* if no free list entry, get new memory */
    if (head == NULL) {
        heapsz_t add_size = aligned_size + alloc_ops.redzone_size + header_beyond_redzone;
        if (arena->next_chunk + add_size > arena->commit_end) {
            arena = arena_extend(arena, add_size);
            if (arena == NULL) {
                client_handle_alloc_failure(request_size, zeroed, realloc, caller, mc);
                goto replace_alloc_common_done;
            }
        }
        /* remember that arena->next_chunk always has a redzone preceding it */
        head = (chunk_header_t *)
            (arena->next_chunk - redzone_beyond_header - HEADER_SIZE);
        LOG(2, "\tcarving out new chunk @"PFX" => head="PFX", res="PFX"\n",
            arena->next_chunk - alloc_ops.redzone_size, head, ptr_from_header(head));
        head->alloc_size = aligned_size;
        head->magic = HEADER_MAGIC;
        head->user_data = NULL; /* b/c we pass the old to client */
        head->flags = 0;
        arena->next_chunk += add_size;
    }

    /* head->alloc_size, head->magic, and head->flags (except type) are already set */
    ASSERT(head->magic == HEADER_MAGIC, "corrupted header");
    head->request_size = request_size;
    head->flags |= alloc_type;
    res = ptr_from_header(head);
    LOG(2, "\treplace_alloc_common flags="PIFX" request=%d, alloc=%d => "PFX"\n",
        head->flags, head->request_size, head->alloc_size, res);
    if (zeroed)
        memset(res, 0, request_size);

    ASSERT(head->alloc_size >= request_size, "chunk too small");

    notify_client_alloc(invoke_client, drcontext, (byte *)res, head, mc,
                        zeroed, realloc, caller);

    if (head->request_size >= LARGE_MALLOC_MIN_SIZE)
        malloc_large_add(res, request_size);
    else
        STATS_INC(num_mallocs);

 replace_alloc_common_done:
    if (synch)
        app_heap_unlock(drcontext, arena->lock);

    return res;
}

static void
check_type_match(void *ptr, chunk_header_t *head, uint free_type,
                 dr_mcontext_t *mc, app_pc caller)
{
    uint alloc_type = (head->flags & MALLOC_ALLOCATOR_FLAGS);
    LOG(3, "\tcheck_type_match: alloc flags="PIFX" vs free="PIFX"\n",
        head->flags, free_type);
    ASSERT((free_type & ~(MALLOC_ALLOCATOR_FLAGS)) == 0, "invalid type flags");
    if ((alloc_type != MALLOC_ALLOCATOR_UNKNOWN &&
         free_type != MALLOC_ALLOCATOR_UNKNOWN) &&
        alloc_type != free_type) {
        client_mismatched_heap(caller, (byte *)ptr, mc,
                               malloc_alloc_type_name(alloc_type),
                               malloc_free_type_name(free_type),
                               head->user_data);
    }
}

/* Up to caller to verify that ptr is inside arena.
 * invoke_client controls whether client_handle_free() is called.
 */
static bool
replace_free_common(arena_header_t *arena, void *ptr, bool synch, bool invoke_client,
                    void *drcontext, dr_mcontext_t *mc, app_pc caller, uint free_type)
{
    chunk_header_t *head = header_from_ptr(ptr);
    free_header_t *cur;
    uint bucket;

    if (!is_live_alloc(ptr, arena, head)) { /* including NULL */
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
            /* We do not report mismatches on pre-us allocs: we never saw the alloc! */
            return true;
        } else {
            /* try to report mismatches on common invalid ptr cases */
            byte *p = (byte *) ptr;
            /* try 4 bytes back, in case this is an array w/ size passed to delete */
            head = header_from_ptr(p - sizeof(int));
            if (is_live_alloc(p - sizeof(int), arena, head))
                check_type_match(p - sizeof(int), head, free_type, mc, caller);
            else {
                /* try 4 bytes in, in case this is a non-array passed to delete[] */
                head = header_from_ptr(p + sizeof(int));
                if (is_live_alloc(p + sizeof(int), arena, head))
                    check_type_match(p + sizeof(int), head, free_type, mc, caller);
            }

            client_invalid_heap_arg(caller, (byte *)ptr, mc,
                                    /* XXX: we might be replacing RtlHeapFree or
                                     * _free_dbg but it's not worth trying to
                                     * store the exact name
                                     */
                                    "free", true/*free*/);
            return false;
        }
    }

    if (synch)
        app_heap_lock(drcontext, arena->lock);

    check_type_match(ptr, head, free_type, mc, caller);

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
        if (arena->free_list->last[bucket] == NULL) {
            ASSERT(arena->free_list->front[bucket] == NULL, "inconsistent free list");
            arena->free_list->front[bucket] = cur;
        } else
            arena->free_list->last[bucket]->next = cur;
        arena->free_list->last[bucket] = cur;
        LOG(3, "arena "PFX" bucket %d free front="PFX" last="PFX"\n",
            arena, bucket, arena->free_list->front[bucket],
            arena->free_list->last[bucket]);

        delayed_chunks++;
        delayed_bytes += head->alloc_size;

        /* XXX i#948: could add more sophisticated features like coalescing adjacent
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
    if (invoke_client) {
        client_handle_free((byte *)ptr, head->request_size,
                           /* XXX: real_base is regular base for us => no pattern */
                           (byte *)ptr, head->alloc_size,
                           mc, caller, head->user_data _IF_WINDOWS(NULL));
    }

    if (head->request_size >= LARGE_MALLOC_MIN_SIZE && !TEST(CHUNK_PRE_US, head->flags))
        malloc_large_remove(ptr);

    if (TEST(CHUNK_MMAP, head->flags)) {
        /* see comments in alloc routine about not delaying the free */
        byte *map = (byte *)ptr - alloc_ops.redzone_size - header_beyond_redzone;
        size_t map_size = head->alloc_size + alloc_ops.redzone_size*2 +
            header_beyond_redzone;
        LOG(2, "\tlarge alloc %d freed => munmap @"PFX"\n", head->request_size, map);
        heap_region_remove(map, map + map_size, mc);
        if (!os_large_free(map, map_size))
            ASSERT(false, "munmap failed");
    }

    STATS_INC(num_frees);

    if (synch)
        app_heap_unlock(drcontext, arena->lock);
    return true;
}

static byte *
replace_realloc_common(arena_header_t *arena, byte *ptr, size_t size,
                       bool lock, bool zeroed, bool in_place_only, bool allow_null,
                       void *drcontext, dr_mcontext_t *mc, app_pc caller)
{
    byte *res = NULL;
    chunk_header_t *head = header_from_ptr(ptr);
    if (ptr == NULL) {
        if (allow_null) {
            client_handle_realloc_null(caller, mc);
            res = (void *) replace_alloc_common(arena, size, lock, zeroed,
                                                true/*realloc*/, true/*client*/,
                                                drcontext, mc, caller,
                                                MALLOC_ALLOCATOR_MALLOC);
        } else {
            client_handle_alloc_failure(size, zeroed, true/*realloc*/, caller, mc);
            res = NULL;
        }
        return res;
    } else if (size == 0) {
        replace_free_common(arena, ptr, lock, true/*client*/, drcontext, mc, caller,
                            MALLOC_ALLOCATOR_MALLOC);
        return NULL;
    } else if (!is_live_alloc(ptr, arena, head)) {
        /* w/o early inject, or w/ delayed instru, there are allocs in place
         * before we took over
         */
        head = hashtable_lookup(&pre_us_table, (void *)ptr);
        if (head == NULL || TEST(CHUNK_FREED, head->flags)) {
            client_invalid_heap_arg(caller, (byte *)ptr, mc,
                                    /* XXX: we might be replacing RtlReallocateHeap or
                                     * _realloc_dbg but it's not worth trying to
                                     * store the exact name
                                     */
                                    "realloc", false/*!free*/);
            return NULL;
        }
    }
    /* if we reach here, this is a regular realloc */
    ASSERT(head != NULL, "should return before here");
    if (head->alloc_size >= size && !TEST(CHUNK_PRE_US, head->flags)) {
        /* XXX: if shrinking a lot, should free and re-malloc to save space */
        client_handle_realloc(drcontext, (byte *)ptr, head->request_size,
                              (byte *)ptr, size,
                              /* XXX: real_base is regular base for us => no pattern */
                              (byte *)ptr, mc);
        if (head->request_size >= LARGE_MALLOC_MIN_SIZE)
            malloc_large_remove(ptr);
        if (head->request_size < size && zeroed)
            memset(ptr + head->request_size, 0, size - head->request_size);
        head->request_size = size;
        if (head->request_size >= LARGE_MALLOC_MIN_SIZE)
            malloc_large_add(ptr, head->request_size);
        res = ptr;
    } else if (!in_place_only) {
        size_t old_size = head->request_size;
        /* XXX: use mremap for mmapped alloc! */
        /* XXX: if final chunk in arena, extend in-place */
        res = (void *) replace_alloc_common(arena, size, lock, zeroed,
                                            true/*realloc*/, false/*no client*/,
                                            drcontext, mc, caller,
                                            MALLOC_ALLOCATOR_MALLOC);
        if (res != NULL) {
            memcpy(res, ptr, head->request_size);
            replace_free_common(arena, ptr, lock, false/*no client */,
                                drcontext, mc, caller, MALLOC_ALLOCATOR_MALLOC);
            client_handle_realloc(drcontext, (byte *)ptr, old_size, res, size,
                                  /* XXX: pattern mode wants base - redzone */
                                  (byte *)ptr, mc);
        }
    }
    return res;
}

/* returns -1 on failure */
static size_t
replace_size_common(arena_header_t *arena, byte *ptr,
                    void *drcontext, dr_mcontext_t *mc, app_pc caller)
{
    chunk_header_t *head = header_from_ptr(ptr);
    if (!is_live_alloc(ptr, arena, head)) {
        /* w/o early inject, or w/ delayed instru, there are allocs in place
         * before we took over
         */
        head = hashtable_lookup(&pre_us_table, (void *)ptr);
        if (head == NULL || TEST(CHUNK_FREED, head->flags)) {
            client_invalid_heap_arg(caller, (byte *)ptr, mc,
                                    IF_WINDOWS_ELSE("_msize", "malloc_usable_size"),
                                    false/*!free*/);
            return (size_t)-1;
        }
    }
    return head->request_size; /* we do not allow using padding */
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
alloc_iter_own_arena(byte *iter_arena_start, byte *iter_arena_end, uint flags
                     _IF_WINDOWS(HANDLE heap), void *iter_data)
{
    alloc_iter_data_t *data = (alloc_iter_data_t *) iter_data;
    chunk_header_t *head;
    byte *cur;
    arena_header_t *arena = (arena_header_t *) iter_arena_start;

    /* We use the HEAP_MMAP flag to find our mmapped chunks.  We can't easily
     * use the large malloc tree b/c it has pre_us allocs too (i#1051).
     */
    if (TEST(HEAP_MMAP, flags)) {
        chunk_header_t *head = (chunk_header_t *) iter_arena_start;
        byte *start = iter_arena_start + HEADER_SIZE + redzone_beyond_header;
        ASSERT(TEST(CHUNK_MMAP, head->flags), "mmap chunk inconsistent");
        LOG(2, "%s: "PFX"-"PFX"\n", __FUNCTION__, start, start + head->request_size);
        if (!data->cb(start, start + head->request_size, start + head->alloc_size,
                      false/*!pre_us*/, head->flags & MALLOC_POSSIBLE_CLIENT_FLAGS,
                      head->user_data, data->data))
            return false;
    }

    if (TEST(HEAP_PRE_US, flags) || !TEST(HEAP_ARENA, flags))
        return true;

    LOG(2, "%s: "PFX"-"PFX"\n", __FUNCTION__, iter_arena_start, iter_arena_end);
    cur = arena->start_chunk;
    while (cur < arena->next_chunk) {
        head = header_from_ptr(cur);
        LOG(3, "\tchunk %s "PFX"-"PFX"\n", TEST(CHUNK_FREED, head->flags) ? "freed" : "",
            ptr_from_header(head), ptr_from_header(head) + head->alloc_size);
        if (!data->only_live || !TEST(CHUNK_FREED, head->flags)) {
            byte *start = ptr_from_header(head);
            if (!data->cb(start, start + head->request_size, start + head->alloc_size,
                          false/*!pre_us*/, head->flags & MALLOC_POSSIBLE_CLIENT_FLAGS,
                          head->user_data, data->data))
                return false;
        }
        cur += head->alloc_size + alloc_ops.redzone_size + header_beyond_redzone;
    }
    return true;
}


static void
alloc_iterate(malloc_iter_cb_t cb, void *iter_data, bool only_live)
{
    /* Strategy:
     * + can iterate arenas via heap rbtree
     *   - each arena of ours can be walked straight through
     *   - for mmap chunks, we can't use the large_malloc_tree b/c it has
     *     pre-us, so we store a new flag in heap regions: HEAP_MMAP (i#1051)
     * + ignore pre-us arenas and instead iterate pre_us_table
     */
    alloc_iter_data_t data = {only_live, cb, iter_data};
    uint i;

    LOG(2, "%s\n", __FUNCTION__);

    ASSERT(!alloc_ops.external_headers, "NYI: walk malloc table");

    LOG(3, "%s: iterating heap regions\n", __FUNCTION__);
    heap_region_iterate(alloc_iter_own_arena, &data);

    LOG(3, "%s: iterating pre-us allocs\n", __FUNCTION__);
    /* XXX: should add hashtable_iterate() to drcontainers */
    for (i = 0; i < HASHTABLE_SIZE(pre_us_table.table_bits); i++) {
        /* we do NOT support removal while iterating.  we don't even hold a lock. */
        hash_entry_t *he;
        for (he = pre_us_table.table[i]; he != NULL; he = he->next) {
            chunk_header_t *head = (chunk_header_t *) he->payload;
            byte *start = he->key;
            if (!only_live || !TEST(CHUNK_FREED, head->flags)) {
                LOG(3, "\tpre-us "PFX"-"PFX"-"PFX"\n",
                    start, start + head->request_size, start + head->alloc_size);
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
            arena_header_t *arena = (arena_header_t *) found_arena_start;
            byte *cur = arena->start_chunk;
            ASSERT(!alloc_ops.external_headers, "NYI: walk malloc table");
            while (cur < arena->next_chunk) {
                byte *chunk_start;
                chunk_header_t *head = header_from_ptr(cur);
                chunk_start = ptr_from_header(head);
                if (start < chunk_start + head->request_size && end >= chunk_start) {
                    found_head = head;
                    found_start = chunk_start;
                    break;
                }
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

static arena_header_t *
arena_for_libc_alloc(void *drcontext)
{
#ifdef WINDOWS
    /* i#939: we need to wrap the libc alloc routines, but at that outer
     * point we don't know what Heap they'll pass to the Rtl routines.
     * Thus we ourselves create a single Heap per libc alloc routine set
     * and we pass it in drwrap's data slot.
     * We can't use our default heap (cur_arena) b/c we need a private
     * Heap for each library that we can destroy when it unloads.
     *
     * XXX: this is not purely transparent and makes some assumptions
     * about there only being one Heap per libc set, a libc set's
     * lifetime never exceeding its library, and a libc set never
     * destroying its own Heap (which remains empty in our impl unless
     * a non-libc-set routine uses that Heap) before its library exits.
     * But, it's not clear that we can do any better.
     */
    arena_header_t *arena;
    alloc_routine_entry_t *e = (alloc_routine_entry_t *)
        dr_read_saved_reg(drcontext, DRWRAP_REPLACE_NATIVE_DATA_SLOT);
    ASSERT(e != NULL, "invalid stored arg");
    arena = (arena_header_t *) alloc_routine_set_get_user_data(e);
    ASSERT(arena != NULL && TEST(ARENA_LIBC_DEFAULT, arena->flags),
           "invalid per-set arena");
    return arena;
#else
    /* we assume that pre-us (which doesn't use cur_arena) is checked by caller */
    return cur_arena;
#endif
}

static void *
replace_malloc(size_t size)
{
    void *res;
    void *drcontext = enter_client_code();
    arena_header_t *arena = arena_for_libc_alloc(drcontext);
    dr_mcontext_t mc;
    INITIALIZE_MCONTEXT_FOR_REPORT(&mc);
    LOG(2, "replace_malloc %d\n", size);
    res = (void *) replace_alloc_common(arena, size, true/*lock*/, false/*!zeroed*/,
                                        false/*!realloc*/, true/*client*/,
                                        drcontext, &mc, (app_pc)replace_malloc,
                                        MALLOC_ALLOCATOR_MALLOC);
    LOG(2, "\treplace_malloc %d => "PFX"\n", size, res);
    exit_client_code(drcontext, false/*need swap*/);
    return res;
}

static void *
replace_calloc(size_t nmemb, size_t size)
{
    void *drcontext = enter_client_code();
    arena_header_t *arena = arena_for_libc_alloc(drcontext);
    byte *res;
    dr_mcontext_t mc;
    INITIALIZE_MCONTEXT_FOR_REPORT(&mc);
    LOG(2, "replace_calloc %d %d\n", nmemb, size);
    res = replace_alloc_common(arena, nmemb * size, true/*lock*/, true/*zeroed*/,
                               false/*!realloc*/, true/*client*/,
                               drcontext, &mc, (app_pc)replace_calloc,
                               MALLOC_ALLOCATOR_MALLOC);
    LOG(2, "\treplace_calloc %d %d => "PFX"\n", nmemb, size, res);
    exit_client_code(drcontext, false/*need swap*/);
    return (void *) res;
}

static void *
replace_realloc(void *ptr, size_t size)
{
    void *drcontext = enter_client_code();
    arena_header_t *arena = arena_for_libc_alloc(drcontext);
    void *res = NULL;
    dr_mcontext_t mc;
    INITIALIZE_MCONTEXT_FOR_REPORT(&mc);
    LOG(2, "replace_realloc "PFX" %d\n", ptr, size);
    res = replace_realloc_common(arena, ptr, size, true/*lock*/, false/*!zeroed*/,
                                 false/*!in-place only*/, true/*allow null*/,
                                 drcontext, &mc, (app_pc)replace_realloc);
    LOG(2, "\treplace_realloc %d => "PFX"\n", size, res);
    exit_client_code(drcontext, false/*need swap*/);
    return res;
}

static void
replace_free(void *ptr)
{
    void *drcontext = enter_client_code();
    arena_header_t *arena = arena_for_libc_alloc(drcontext);
    dr_mcontext_t mc;
    INITIALIZE_MCONTEXT_FOR_REPORT(&mc);
    LOG(2, "replace_free "PFX"\n", ptr);
    replace_free_common(arena, ptr, true/*lock*/, true/*client*/, drcontext,
                        &mc, (app_pc)replace_free, MALLOC_ALLOCATOR_MALLOC);
    exit_client_code(drcontext, false/*need swap*/);
}

static size_t
replace_malloc_usable_size(void *ptr)
{
    void *drcontext = enter_client_code();
    size_t res;
    arena_header_t *arena = arena_for_libc_alloc(drcontext);
    dr_mcontext_t mc;
    INITIALIZE_MCONTEXT_FOR_REPORT(&mc);
    LOG(2, "replace_malloc_usable_size "PFX"\n", ptr);
    res = replace_size_common(arena, ptr, drcontext, &mc,
                              (app_pc)replace_malloc_usable_size);
    if (res == (size_t)-1)
        res = 0; /* 0 on failure */
    LOG(2, "\treplace_malloc_usable_size "PFX" => "PIFX"\n", ptr, res);
    exit_client_code(drcontext, false/*need swap*/);
    return res;
}

/* XXX i#94: replace mallopt(), mallinfo(), valloc(), memalign(), etc. */

/***************************************************************************
 * Operators
 */

/* i#882: replace operator new/delete known to be non-placement to
 * avoid wrap cost and to support redzones on debug CRT.
 * We will also be able to pass in the allocation type rather than
 * reading it from CLS.
 */
static inline void *
replace_operator_new_common(size_t size, bool abort_on_oom, uint alloc_type, app_pc caller)
{
    void *res;
    void *drcontext = enter_client_code();
    /* b/c we replace at the operator level and we don't analyze the
     * replaced operator to see which libc it's using we have to assume
     * our stored default is ok (xref i#964, i#939)
     */
    arena_header_t *arena = arena_for_libc_alloc(drcontext);
    dr_mcontext_t mc;
    INITIALIZE_MCONTEXT_FOR_REPORT(&mc);
    LOG(2, "replace_operator_new size=%d abort_on_oom=%d type=%d\n",
        size, abort_on_oom, alloc_type);
    res = (void *) replace_alloc_common(arena, size, true/*lock*/, false/*!zeroed*/,
                                        false/*!realloc*/, true/*client*/,
                                        drcontext, &mc, caller, alloc_type);
    LOG(2, "\treplace_operator_new %d => "PFX"\n", size, res);
    if (abort_on_oom && res == NULL) {
        /* XXX i#957: we should throw a C++ exception but for now we just abort */
        ELOGF(0, f_global, "ABORTING ON OOM\n");
        dr_exit_process(1);
        ASSERT(false, "should not reach here");
    }
    exit_client_code(drcontext, false/*need swap*/);
    return res;
}

static void *
replace_operator_new(size_t size)
{
    return replace_operator_new_common(size, true, MALLOC_ALLOCATOR_NEW,
                                       (app_pc)replace_operator_new);
}

static void *
replace_operator_new_nothrow(size_t size, int /*std::nothrow_t*/ ignore)
{
    return replace_operator_new_common(size, false, MALLOC_ALLOCATOR_NEW,
                                       (app_pc)replace_operator_new_nothrow);
}

/* we need separate array versions for type mismatch detection (NYI) */
static void *
replace_operator_new_array(size_t size)
{
    return replace_operator_new_common(size, true, MALLOC_ALLOCATOR_NEW_ARRAY,
                                       (app_pc)replace_operator_new_array);
}

static void *
replace_operator_new_array_nothrow(size_t size, int /*std::nothrow_t*/ ignore)
{
    return replace_operator_new_common(size, false, MALLOC_ALLOCATOR_NEW_ARRAY,
                                       (app_pc)replace_operator_new_array_nothrow);
}

static inline void
replace_operator_delete_common(void *ptr, uint alloc_type, app_pc caller)
{
    void *drcontext = enter_client_code();
    arena_header_t *arena = arena_for_libc_alloc(drcontext);
    dr_mcontext_t mc;
    INITIALIZE_MCONTEXT_FOR_REPORT(&mc);
    LOG(2, "replace_operator_delete "PFX"\n", ptr);
    replace_free_common(arena, ptr, true/*lock*/, true/*client*/, drcontext,
                        &mc, caller, alloc_type);
    exit_client_code(drcontext, false/*need swap*/);
}

/* We do not bother to report mismatches on nothrow vs regular so we
 * don't need to distinguish nothrow vs regular delete
 */
static void
replace_operator_delete(void *ptr)
{
    replace_operator_delete_common(ptr, MALLOC_ALLOCATOR_NEW,
                                   (app_pc)replace_operator_delete);
}

static void
replace_operator_delete_nothrow(void *ptr, int /*std::nothrow_t*/ ignore)
{
    replace_operator_delete_common(ptr, MALLOC_ALLOCATOR_NEW,
                                   (app_pc)replace_operator_delete);
}

static void
replace_operator_delete_array(void *ptr)
{
    replace_operator_delete_common(ptr, MALLOC_ALLOCATOR_NEW_ARRAY,
                                   (app_pc)replace_operator_delete_array);
}

static void
replace_operator_delete_array_nothrow(void *ptr, int /*std::nothrow_t*/ ignore)
{
    replace_operator_delete_common(ptr, MALLOC_ALLOCATOR_NEW_ARRAY,
                                   (app_pc)replace_operator_delete_array_nothrow);
}

#ifdef WINDOWS
static void
replace_operator_combined_delete(void *ptr)
{
    /* See i#722 for background, and i#965.
     * This routine is called for both delete and delete[] so we must disable
     * mismatch checking.
     * XXX: it would be nice to check malloc vs delete*
     */
    LOG(2, "%s "PFX"\n", __FUNCTION__, ptr);
    replace_operator_delete_common(ptr, MALLOC_ALLOCATOR_UNKNOWN,
                                   (app_pc)replace_operator_combined_delete);
}
#endif /* WINDOWS */

#ifdef WINDOWS
/***************************************************************************
 * Windows RTL Heap API
 */

/* XXX: are the BOOL return values really NTSTATUS? */

/* Forwards */
static BOOL WINAPI
replace_RtlDestroyHeap(HANDLE heap);


static arena_header_t *
create_Rtl_heap(size_t commit_sz, size_t reserve_sz, uint flags)
{
    arena_header_t *new_arena = (arena_header_t *)
        os_large_alloc(commit_sz, reserve_sz, arena_page_prot(flags));
    if (new_arena != NULL) {
        LOG(2, "%s commit="PIFX" reserve="PIFX" flags="PIFX" => "PFX"\n",
            __FUNCTION__, commit_sz, reserve_sz, flags, new_arena);
        new_arena->commit_end = (byte *)new_arena + commit_sz;
        new_arena->reserve_end = (byte *)new_arena + reserve_sz;
        heap_region_add((byte *)new_arena, new_arena->reserve_end, HEAP_ARENA, NULL);
        /* this will create the lock even if TEST(HEAP_NO_SERIALIZE, flags) */
        arena_init(new_arena, NULL);
        new_arena->flags |= (flags & HEAP_CREATE_POSSIBLE_FLAGS);
    }
    return new_arena;
}

static void
destroy_Rtl_heap(arena_header_t *arena, dr_mcontext_t *mc, bool free_chunks)
{
    arena_header_t *a, *next_a;
    chunk_header_t *head;
    LOG(2, "%s heap="PFX"\n", __FUNCTION__, arena);
    for (a = arena; a != NULL; a = next_a) {
        next_a = a->next_arena;
        if (free_chunks) {
            byte *cur = a->start_chunk;
            while (cur < a->next_chunk) {
                head = header_from_ptr(cur);
                if (!TEST(CHUNK_FREED, head->flags)) {
                    /* XXX: like mmaps for large allocs, we assume the OS
                     * re-using the memory won't be immediate, so we go w/
                     * a simple no-delay policy on the frees
                     */
                    byte *start = ptr_from_header(head);
                    client_handle_free(start, head->request_size,
                                       start, head->alloc_size,
                                       mc, (app_pc)replace_RtlDestroyHeap,
                                       head->user_data _IF_WINDOWS((HANDLE)arena));
                }
                cur += head->alloc_size + alloc_ops.redzone_size + header_beyond_redzone;
            }
        }
        heap_region_remove((byte *)a, a->reserve_end, mc);
        arena_free(a);
    }
}

/* returns NULL if not a valid Heap handle */
static arena_header_t *
heap_to_arena(HANDLE heap)
{
    arena_header_t *arena = (arena_header_t *) heap;
    uint magic;
    /* we assume that pre-us will be detected and handled by caller */
    /* FIXME i#959: handle additional pre-us Heaps from dlls before we took over */
    if (heap == process_heap)
        return cur_arena;
#ifdef USE_DRSYMS
    ASSERT(heap != get_private_heap_handle(), "app using private heap");
#endif
    if (arena != NULL &&
        safe_read(&arena->magic, sizeof(magic), &magic) &&
        magic == HEADER_MAGIC &&
        /* XXX: safe_read flags too?  magic passed though */
        TEST(ARENA_MAIN, arena->flags))
        return arena;
    else
        return NULL;
}

static HANDLE WINAPI
replace_RtlCreateHeap(ULONG flags, void *base, size_t reserve_sz,
                      size_t commit_sz, void *lock, void *params)
{
    arena_header_t *new_arena = NULL;
    void *drcontext = enter_client_code();
    LOG(2, "%s\n", __FUNCTION__);
    if (lock != NULL || params != NULL || base != NULL) {
        /* as of win7, CreateHeap always passes NULL for these 3 */
        ASSERT(false, "NYI params to RtlCreateHeap");
        /* we continue on and ignore params for release build */
    }
    flags &= ~(HEAP_CREATE_POSSIBLE_FLAGS);
    if (reserve_sz == 0) {
        flags |= HEAP_GROWABLE;
        reserve_sz = ARENA_INITIAL_SIZE;
    } else /* XXX: is max really non-page-aligned?  we align it */
        reserve_sz = ALIGN_FORWARD(reserve_sz, PAGE_SIZE);
    commit_sz = ALIGN_FORWARD(commit_sz, PAGE_SIZE);
    if (commit_sz == 0)
        commit_sz = PAGE_SIZE;
    new_arena = (arena_header_t *) create_Rtl_heap(commit_sz, reserve_sz, flags);
    LOG(2, "  => "PFX"\n", new_arena);
    dr_switch_to_app_state(drcontext);
    if (new_arena == NULL) {
        /* XXX: most of our errors are invalid params so that's all we set.
         * We deliberately wait until in app mode to make this more efficient.
         */
        set_app_error_code(drcontext, ERROR_INVALID_PARAMETER);
    }
    exit_client_code(drcontext, true/*already swapped*/);
    return (HANDLE) new_arena;    
}

static BOOL WINAPI
replace_RtlDestroyHeap(HANDLE heap)
{
    void *drcontext = enter_client_code();
    arena_header_t *arena = heap_to_arena(heap);
    BOOL res = FALSE;
    dr_mcontext_t mc;
    INITIALIZE_MCONTEXT_FOR_REPORT(&mc);
    LOG(2, "%s heap="PFX"\n", __FUNCTION__, heap);
    if (arena != NULL && heap != process_heap) {
        destroy_Rtl_heap(arena, &mc, true/*free indiv chunks*/);
        res = TRUE;
    }
    dr_switch_to_app_state(drcontext);
    if (!res) {
        /* XXX: for now blindly seting the one errno.
         * We deliberately wait until in app mode to make this more efficient.
         */
        set_app_error_code(drcontext, ERROR_INVALID_PARAMETER);
    }
    exit_client_code(drcontext, true/*already swapped*/);
    return res;
}

static void
handle_Rtl_alloc_failure(void *drcontext, arena_header_t *arena, ULONG flags)
{
    /* N.B.: neither HeapAlloc nor HeapReAlloc set the last error */

    if ((arena != NULL && TEST(HEAP_GENERATE_EXCEPTIONS, arena->flags)) ||
        TEST(HEAP_GENERATE_EXCEPTIONS, flags)) {
        ASSERT(false, "HEAP_GENERATE_EXCEPTIONS NYI");
        /* FIXME: need to call RtlRaiseException or sthg
         * But, have to be careful: will it work calling it natively or will
         * we need to dr_redirect_execution() to get the call interpreted?
         */
        /* FIXME: for invalid params or heap corruption, raise STATUS_ACCESS_VIOLATION;
         * for OOM, raise STATUS_NO_MEMORY.  need caller to tell us which it is!
         */
    }
}

static void * WINAPI
replace_RtlAllocateHeap(HANDLE heap, ULONG flags, SIZE_T size)
{
    void *drcontext = enter_client_code();
    arena_header_t *arena = heap_to_arena(heap);
    void *res = NULL;
    dr_mcontext_t mc;
    INITIALIZE_MCONTEXT_FOR_REPORT(&mc);
    LOG(2, "%s heap="PFX" (=> "PFX") flags="PIFX" size="PIFX"\n",
        __FUNCTION__, heap, arena, flags, size);
    if (arena != NULL) {
        res = replace_alloc_common(arena, size,
                                   !TEST(HEAP_NO_SERIALIZE, arena->flags) &&
                                   !TEST(HEAP_NO_SERIALIZE, flags),
                                   TEST(HEAP_ZERO_MEMORY, flags),
                                   false/*!realloc*/, true/*client*/, drcontext,
                                   &mc, (app_pc)replace_RtlAllocateHeap,
                                   MALLOC_ALLOCATOR_MALLOC);
    }
    dr_switch_to_app_state(drcontext);
    if (res == NULL)
        handle_Rtl_alloc_failure(drcontext, arena, flags);
    exit_client_code(drcontext, true/*already swapped*/);
    return res;
}

static void * WINAPI
replace_RtlReAllocateHeap(HANDLE heap, ULONG flags, PVOID ptr, SIZE_T size)
{
    void *drcontext = enter_client_code();
    arena_header_t *arena = heap_to_arena(heap);
    void *res = NULL;
    dr_mcontext_t mc;
    INITIALIZE_MCONTEXT_FOR_REPORT(&mc);
    LOG(2, "%s heap="PFX" (=> "PFX") flags="PIFX" ptr="PFX" size="PIFX"\n",
        __FUNCTION__, heap, arena, flags, ptr, size);
    if (arena != NULL) {
        /* unlike libc realloc(), HeapReAlloc fails when ptr==NULL */
        res = replace_realloc_common(arena, ptr, size,
                                     !TEST(HEAP_NO_SERIALIZE, arena->flags) &&
                                     !TEST(HEAP_NO_SERIALIZE, flags),
                                     TEST(HEAP_ZERO_MEMORY, flags),
                                     TEST(HEAP_REALLOC_IN_PLACE_ONLY, flags),
                                     false/*fail on null*/, drcontext,
                                     &mc, (app_pc)replace_RtlReAllocateHeap);
    }
    dr_switch_to_app_state(drcontext);
    if (res == NULL)
        handle_Rtl_alloc_failure(drcontext, arena, flags);
    exit_client_code(drcontext, true/*already swapped*/);
    return res;
}

static BOOL WINAPI
replace_RtlFreeHeap(HANDLE heap, ULONG flags, PVOID ptr)
{
    void *drcontext = enter_client_code();
    arena_header_t *arena = heap_to_arena(heap);
    BOOL res = FALSE;
    dr_mcontext_t mc;
    INITIALIZE_MCONTEXT_FOR_REPORT(&mc);
    LOG(2, "%s heap="PFX" flags="PIFX" ptr="PFX"\n", __FUNCTION__, heap, flags, ptr);
    if (arena != NULL) {
        bool ok = replace_free_common(arena, ptr,
                                      !TEST(HEAP_NO_SERIALIZE, arena->flags) &&
                                      !TEST(HEAP_NO_SERIALIZE, flags), true/*client*/,
                                      drcontext, &mc, (app_pc)replace_RtlFreeHeap,
                                      MALLOC_ALLOCATOR_MALLOC);
        res = !!ok; /* convert from bool to BOOL */
    }
    dr_switch_to_app_state(drcontext);
    if (!res) {
        /* XXX: all our errors are invalid params so that's all we set.
         * We deliberately wait until in app mode to make this more efficient.
         */
        set_app_error_code(drcontext, ERROR_INVALID_PARAMETER);
    }
    exit_client_code(drcontext, true/*already swapped*/);
    return res;
}

static SIZE_T WINAPI
replace_RtlSizeHeap(HANDLE heap, ULONG flags, PVOID ptr)
{
    void *drcontext = enter_client_code();
    arena_header_t *arena = heap_to_arena(heap);
    SIZE_T res = (SIZE_T) -1;
    dr_mcontext_t mc;
    INITIALIZE_MCONTEXT_FOR_REPORT(&mc);
    LOG(2, "%s\n", __FUNCTION__);
    if (arena != NULL) {
        res = replace_size_common(arena, ptr, drcontext,
                                  &mc, (app_pc)replace_RtlSizeHeap);
    }
    dr_switch_to_app_state(drcontext);
    if (!res) {
        /* XXX: all our errors are invalid params so that's all we set.
         * We deliberately wait until in app mode to make this more efficient.
         */
        set_app_error_code(drcontext, ERROR_INVALID_PARAMETER);
    }
    exit_client_code(drcontext, true/*already swapped*/);
    return res;
}

/* FIXME i#893: allowing the app to hold a lock we'll wait for in our
 * code that needs to return to a cache fragment is unsafe b/c a flusher
 * could hold the lock as the app.
 * We need to refactor all the code here to interpret the initial
 * code that acquires locks, and only then go native (for perf).
 * There are more complex schemes to handle this but none I've come up
 * with are appealing so far.
 */
static BOOL WINAPI
replace_RtlLockHeap(HANDLE heap)
{
    void *drcontext = enter_client_code();
    arena_header_t *arena = heap_to_arena(heap);
    BOOL res = FALSE;
    LOG(2, "%s\n", __FUNCTION__);
    if (arena != NULL) {
        /* We only grab this DR lock as the app and we mark it with
         * dr_recurlock_mark_as_app(), as well as using dr_mark_safe_to_suspend(),
         * to ensure proper DR behavior
         */
        app_heap_lock(drcontext, arena->lock);
        res = TRUE;
    }
    exit_client_code(drcontext, false/*need swap*/);
    return res;
}

static BOOL WINAPI
replace_RtlUnlockHeap(HANDLE heap)
{
    void *drcontext = enter_client_code();
    arena_header_t *arena = heap_to_arena(heap);
    BOOL res = FALSE;
    LOG(2, "%s\n", __FUNCTION__);
    if (arena != NULL && dr_recurlock_self_owns(arena->lock)) {
        app_heap_unlock(drcontext, arena->lock);
        res = TRUE;
    }
    exit_client_code(drcontext, false/*need swap*/);
    return res;
}

static BOOL WINAPI
replace_RtlValidateHeap(HANDLE heap, DWORD flags, void *ptr)
{
    void *drcontext = enter_client_code();
    ASSERT(false, "NYI");
    exit_client_code(drcontext, false/*need swap*/);
    return TRUE;
}

static BOOL WINAPI
replace_RtlSetHeapInformation(HANDLE HeapHandle,
                              HEAP_INFORMATION_CLASS HeapInformationClass,
                              PVOID HeapInformation, SIZE_T HeapInformationLength)
{
    void *drcontext = enter_client_code();
    /* FIXME: NYI.  No assert in order to get replace_malloc test going. */
    exit_client_code(drcontext, false/*need swap*/);
    return TRUE;
}

static BOOL WINAPI
replace_RtlQueryHeapInformation(HANDLE HeapHandle,
                                HEAP_INFORMATION_CLASS HeapInformationClass,
                                PVOID HeapInformation OPTIONAL,
                                SIZE_T HeapInformationLength OPTIONAL,
                                PSIZE_T ReturnLength OPTIONAL)
{
    void *drcontext = enter_client_code();
    ASSERT(false, "NYI");
    exit_client_code(drcontext, false/*need swap*/);
    return TRUE;
}

static SIZE_T WINAPI
replace_RtlCompactHeap(HANDLE Heap, ULONG Flags)
{
    void *drcontext = enter_client_code();
    ASSERT(false, "NYI");
    exit_client_code(drcontext, false/*need swap*/);
    return TRUE;
}

static ULONG WINAPI
replace_RtlGetProcessHeaps(ULONG count, HANDLE *heaps)
{
    void *drcontext = enter_client_code();
    ASSERT(false, "NYI");
    exit_client_code(drcontext, false/*need swap*/);
    return 0;
}

static BOOL WINAPI
replace_RtlWalkHeap(HANDLE HeapHandle, PVOID HeapEntry)
{
    void *drcontext = enter_client_code();
    ASSERT(false, "NYI");
    exit_client_code(drcontext, false/*need swap*/);
    return TRUE;
}

static BOOL WINAPI
replace_RtlEnumProcessHeaps(PVOID /*XXX PHEAP_ENUMERATION_ROUTINE*/ HeapEnumerationRoutine,
                            PVOID lParam)
{
    void *drcontext = enter_client_code();
    ASSERT(false, "NYI");
    exit_client_code(drcontext, false/*need swap*/);
    return TRUE;
}

static BOOL WINAPI
replace_ignore_arg0(void)
{
    void *drcontext = enter_client_code();
    LOG(2, "%s: ignoring\n", __FUNCTION__);
    exit_client_code(drcontext, false/*need swap*/);
    return TRUE;
}

static BOOL WINAPI
replace_ignore_arg1(void *arg1)
{
    void *drcontext = enter_client_code();
    LOG(2, "%s: ignoring\n", __FUNCTION__);
    exit_client_code(drcontext, false/*need swap*/);
    return TRUE;
}

static BOOL WINAPI
replace_ignore_arg2(void *arg1, void *arg2)
{
    void *drcontext = enter_client_code();
    LOG(2, "%s: ignoring\n", __FUNCTION__);
    exit_client_code(drcontext, false/*need swap*/);
    return TRUE;
}

static BOOL WINAPI
replace_ignore_arg3(void *arg1, void *arg2, void *arg3)
{
    void *drcontext = enter_client_code();
    LOG(2, "%s: ignoring\n", __FUNCTION__);
    exit_client_code(drcontext, false/*need swap*/);
    return TRUE;
}

static BOOL WINAPI
replace_ignore_arg4(void *arg1, void *arg2, void *arg3, void *arg4)
{
    void *drcontext = enter_client_code();
    LOG(2, "%s: ignoring\n", __FUNCTION__);
    exit_client_code(drcontext, false/*need swap*/);
    return TRUE;
}

static BOOL WINAPI
replace_ignore_arg5(void *arg1, void *arg2, void *arg3, void *arg4, void *arg5)
{
    void *drcontext = enter_client_code();
    LOG(2, "%s: ignoring\n", __FUNCTION__);
    exit_client_code(drcontext, false/*need swap*/);
    return TRUE;
}

#endif /* WINDOWS */

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
    return (addr >= (byte *)cur_arena && addr < cur_arena->reserve_end);
}

bool
alloc_entering_replace_routine(app_pc pc)
{
    return drwrap_is_replaced_native(pc);
}

static bool
func_interceptor(routine_type_t type, void **routine OUT, bool *at_entry OUT,
                 uint *stack OUT)
{
    /* almost everything is at the callee entry */
    *at_entry = true;
#ifdef WINDOWS
    if (is_rtl_routine(type)) {
        switch (type) {
        case RTL_ROUTINE_MALLOC:
            *routine = (void *) replace_RtlAllocateHeap;
            *stack = sizeof(void*) * 3;
            return true;
        case RTL_ROUTINE_REALLOC:
            *routine = (void *) replace_RtlReAllocateHeap;
            *stack = sizeof(void*) * 4;
            return true;
        case RTL_ROUTINE_FREE:
            *routine = (void *) replace_RtlFreeHeap;
            *stack = sizeof(void*) * 3;
            return true;
        case RTL_ROUTINE_SIZE:
            *routine = (void *) replace_RtlSizeHeap;
            *stack = sizeof(void*) * 3;
            return true;
        case RTL_ROUTINE_CREATE:
            *routine = (void *) replace_RtlCreateHeap;
            *stack = sizeof(void*) * 6;
            return true;
        case RTL_ROUTINE_DESTROY:
            *routine = (void *) replace_RtlDestroyHeap;
            *stack = sizeof(void*) * 1;
            return true;
        case RTL_ROUTINE_LOCK:
            *routine = (void *) replace_RtlLockHeap;
            *stack = sizeof(void*) * 1;
            return true;
        case RTL_ROUTINE_UNLOCK:
            *routine = (void *) replace_RtlUnlockHeap;
            *stack = sizeof(void*) * 1;
            return true;
        case RTL_ROUTINE_HEAPINFO:
            *routine = (void *) replace_RtlSetHeapInformation;
            *stack = sizeof(void*) * 4;
            return true;
        /* XXX: NYI.  Warn or assert if we hit them? */
        case RTL_ROUTINE_GETINFO:
            *routine = (void *) replace_ignore_arg5;
            *stack = sizeof(void*) * 5;
            return true;
        case RTL_ROUTINE_SETINFO:
            *routine = (void *) replace_ignore_arg4;
            *stack = sizeof(void*) * 4;
            return true;
        case RTL_ROUTINE_SETFLAGS:
            *routine = (void *) replace_ignore_arg5;
            *stack = sizeof(void*) * 5;
            return true;
# ifdef X64
        /* FIXME i#995-c#3: we need replace NtdllpFreeStringRoutine in win-x64,
         * which takes the first arg as the ptr to be freed.
         */
        case RTL_ROUTINE_FREE_STRING:
            ASSERT(false, "replace RtlFreeStringRoutine NYI");
            *routine = NULL; /* wrapping instead though it probably won't work */
            return true;
#endif
        /* FIXME i#893: we need to split up RTL_ROUTINE_QUERY, along with replacing
         * other routines not currently wrapped.  We don't need special
         * fast sym lookup or to treat as heap layers so we should do drwrap
         * calls from here rather than adding to alloc.c's list, and suppress
         * alloc.c wrapping.
         */
        /* note that replacing malloc does NOT eliminate the need to
         * wrap LdrShutdownProcess b/c it calls RtlpHeapIsLocked,
         * unless we wanted to treat pre-us Heap header as addressable
         */
        default:
            *routine = NULL; /* wrap it */
            return true;
        }
    }
#endif
    /* nothing below here is stdcall */
    *stack = 0;
    if (is_malloc_routine(type))
        *routine = (void *) replace_malloc;
    else if (is_calloc_routine(type))
        *routine = (void *) replace_calloc;
    else if (is_realloc_routine(type))
        *routine = (void *) replace_realloc;
    else if (is_free_routine(type))
        *routine = (void *) replace_free;
    else if (is_size_routine(type))
        *routine = (void *) replace_malloc_usable_size;
    else if (type == HEAP_ROUTINE_NEW)
        *routine = (void *) replace_operator_new;
    else if (type == HEAP_ROUTINE_NEW_ARRAY)
        *routine = (void *) replace_operator_new_array;
    else if (type == HEAP_ROUTINE_NEW_NOTHROW)
        *routine = (void *) replace_operator_new_nothrow;
    else if (type == HEAP_ROUTINE_NEW_ARRAY_NOTHROW)
        *routine = (void *) replace_operator_new_array_nothrow;
    else if (type == HEAP_ROUTINE_DELETE)
        *routine = (void *) replace_operator_delete;
    else if (type == HEAP_ROUTINE_DELETE_ARRAY)
        *routine = (void *) replace_operator_delete_array;
    else if (type == HEAP_ROUTINE_DELETE_NOTHROW)
        *routine = (void *) replace_operator_delete_nothrow;
    else if (type == HEAP_ROUTINE_DELETE_ARRAY_NOTHROW)
        *routine = (void *) replace_operator_delete_array_nothrow;
#ifdef WINDOWS
    else if (type == HEAP_ROUTINE_DebugHeapDelete) {
        *routine = (void *) replace_operator_combined_delete;
        /* i#965: we must replace at the call site, but drwrap now handles that
         * and saves us a lot of work
         */
        *at_entry = false;
    }
#endif
    else
        *routine = NULL; /* but go ahead and wrap */
    return true;
}

static void
malloc_replace__intercept(app_pc pc, routine_type_t type, alloc_routine_entry_t *e)
{
    void *interceptor = NULL;
    bool at_entry = true;
    uint stack_adjust = 0;
    if (!func_interceptor(type, &interceptor, &at_entry, &stack_adjust)) {
        /* we'll replace it ourselves elsewhere: alloc.c should ignore it */
        return;
    }
    if (interceptor != NULL) {
        /* optimization: only pass where needed, for Windows libc */
        void *user_data = IF_WINDOWS_ELSE(is_rtl_routine(type) ? NULL : (void *) e, NULL);
        if (!drwrap_replace_native(pc, interceptor, at_entry, stack_adjust,
                                   user_data, false))
            ASSERT(false, "failed to replace alloc routine");
    } else {
        /* else wrap */
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
    void *interceptor = NULL;
    bool at_entry;
    uint stack_adjust = 0;
    if (!func_interceptor(type, &interceptor, &at_entry, &stack_adjust)) {
        /* we'll un-replace it ourselves elsewhere: alloc.c should ignore it */
        return;
    }
    if (interceptor != NULL) {
        if (!drwrap_replace_native(pc, NULL, at_entry, stack_adjust, NULL, true))
            ASSERT(false, "failed to un-replace alloc routine");
    } else {
        malloc_wrap__unintercept(pc, type, e);
    }
}

static void *
malloc_replace__set_init(heapset_type_t type, app_pc pc, void *libc_data)
{
#ifdef WINDOWS
    if (type == HEAPSET_RTL) {
        return NULL;
    } else if (libc_data != NULL) {
        /* dbg crt and regular crt and cpp routines share a Heap (i#964) */
        LOG(2, "shared default Heap for libc set type=%d @"PFX" is "PFX"\n",
            type, pc, libc_data);
        return libc_data;
    } else {
        /* Create the Heap for this libc alloc routine set (i#939) */
        arena_header_t *arena = (arena_header_t *)
            create_Rtl_heap(PAGE_SIZE, ARENA_INITIAL_SIZE, HEAP_GROWABLE);
        LOG(2, "new default Heap for libc set type=%d @"PFX" is "PFX"\n",
            type, pc, arena);
        arena->flags |= ARENA_LIBC_DEFAULT;
        return arena;
    }
    /* cpp set does not need its own Heap (i#964) */
#endif
    return NULL;
}

static void
malloc_replace__set_exit(heapset_type_t type, app_pc pc, void *user_data,
                         void *libc_data)
{
#ifdef WINDOWS
    if ((type != HEAPSET_RTL && libc_data == NULL) || type == HEAPSET_LIBC) {
        /* Destroy the Heap for this libc alloc routine set (i#939) */
        arena_header_t *arena = (arena_header_t *) user_data;
        ASSERT(arena != NULL, "stored Heap disappeared?");
        LOG(2, "destroying default Heap "PFX" for libc set @"PFX"\n", arena, pc);
        /* i#939: we assume the Heap used by a libc routine set is not destroyed
         * mid-run (pool-style) and is simply torn down at the end without any
         * desire to free the individual chunks.
         * XXX if we do free indiv chunks, we have no mcxt: should be rare, but
         * can imagine an app bug involving memory freed when a
         * library w/ libc routine unloads
         */
        destroy_Rtl_heap(arena, NULL, false/*do not free indiv chunks*/);
    }
#endif
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
    LOG(3, "new pre-us alloc "PFX"-"PFX"-"PFX"\n", start, end, real_end);
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
    chunk_header_t *head = header_from_ptr_include_pre_us(start);
    if (head == NULL || TEST(CHUNK_FREED, head->flags))
        return NULL;
    else
        return start + head->request_size;
}

/* Returns -1 on failure */
static ssize_t
malloc_replace__size(app_pc start)
{
    chunk_header_t *head;
    ssize_t res = -1;
    head = header_from_ptr_include_pre_us(start);
    if (head != NULL && !TEST(CHUNK_FREED, head->flags))
        res = head->request_size;
    return res;
}

static ssize_t
malloc_replace__size_invalid_only(app_pc start)
{
    chunk_header_t *head = header_from_ptr_include_pre_us(start);
    if (head == NULL || !TEST(CHUNK_FREED, head->flags))
        return -1;
    else
        return head->request_size;
}

static void *
malloc_replace__get_client_data(app_pc start)
{
    chunk_header_t *head = header_from_ptr_include_pre_us(start);
    /* following alloc.c's lead and not failing on a freed chunk.
     * ditto on routines below.  not sure if anyone relies on that though.
     */
    if (head == NULL)
        return NULL;
    return head->user_data;
}

static uint
malloc_replace__get_client_flags(app_pc start)
{
    chunk_header_t *head = header_from_ptr_include_pre_us(start);
    if (head == NULL)
        return 0;
    return (head->flags & MALLOC_POSSIBLE_CLIENT_FLAGS);
}

static bool
malloc_replace__set_client_flag(app_pc start, uint client_flag)
{
    chunk_header_t *head = header_from_ptr_include_pre_us(start);
    if (head == NULL)
        return false;
    head->flags |= (client_flag & MALLOC_POSSIBLE_CLIENT_FLAGS);
    return true;
}

static bool
malloc_replace__clear_client_flag(app_pc start, uint client_flag)
{
    chunk_header_t *head = header_from_ptr_include_pre_us(start);
    if (head == NULL)
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
    /* FIXME i#949: we can't mark safe to suspend here (in app_heap_lock())
     * b/c it's called from clean calls, etc.  Currently this is unsafe
     * and can deadlock.
     */
    dr_recurlock_lock(cur_arena->lock);
}

static void
malloc_replace__unlock(void)
{
    dr_recurlock_unlock(cur_arena->lock);
}

void
alloc_replace_init(void)
{
    ASSERT(sizeof(free_header_t) <=
           (alloc_ops.external_headers ? 0 : sizeof(chunk_header_t)) + CHUNK_MIN_SIZE,
           "min size too small");
    /* we could pad but it's simpler to have struct already have right size */
    ASSERT(ALIGNED(sizeof(chunk_header_t), CHUNK_ALIGNMENT), "alignment off");

    ASSERT(CHUNK_MIN_MMAP >= LARGE_MALLOC_MIN_SIZE,
           "we rely on mmapped chunks being in large malloc table");

    ASSERT(ARENA_INITIAL_SIZE >= CHUNK_MIN_MMAP, "arena must hold at least 1 chunk");

    ASSERT(ALIGNED(alloc_ops.redzone_size, CHUNK_ALIGNMENT), "redzone alignment off");

    if (alloc_ops.redzone_size < HEADER_SIZE) {
        header_beyond_redzone = HEADER_SIZE - alloc_ops.redzone_size;
        redzone_beyond_header = 0;
    } else {
        redzone_beyond_header = (alloc_ops.redzone_size - HEADER_SIZE)/2;
        ASSERT(redzone_beyond_header*2 + HEADER_SIZE <= alloc_ops.redzone_size,
               "redzone or header size not aligned properly");
    }

    hashtable_init(&pre_us_table, PRE_US_TABLE_HASH_BITS, HASH_INTPTR, false/*!strdup*/);

#ifdef LINUX
    /* we waste pre-brk space of pre-us allocator, and we assume we're
     * now completely replacing the pre-us allocator.
     * XXX: better to not use brk and solely use mmap instead?
     */
    cur_brk = get_brk(false);
    pre_us_brk = cur_brk;
    cur_arena = (arena_header_t *) pre_us_brk;
    cur_brk = set_brk(cur_brk + PAGE_SIZE);
    /* XXX: for delayed instru we will need to handle this; for now we assert */
    ASSERT(cur_brk > (byte *)cur_arena, "failed to increase brk at init");
    cur_arena->commit_end = cur_brk;
    cur_arena->reserve_end = cur_arena->commit_end;
    LOG(2, "heap orig brk="PFX"\n", pre_us_brk);
#else
    cur_arena = (arena_header_t *)
        os_large_alloc(ARENA_INITIAL_COMMIT, ARENA_INITIAL_SIZE, arena_page_prot(0));
    ASSERT(cur_arena != NULL, "can't allocate initial heap: fatal");
    cur_arena->commit_end = (byte *)cur_arena + ARENA_INITIAL_COMMIT;
    cur_arena->reserve_end = (byte *)cur_arena + ARENA_INITIAL_SIZE;
    process_heap = get_app_PEB()->ProcessHeap;
#endif
    heap_region_add((byte *)cur_arena, cur_arena->reserve_end, HEAP_ARENA, NULL);
    arena_init(cur_arena, NULL);

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
    malloc_interface.malloc_set_init = malloc_replace__set_init;
    malloc_interface.malloc_set_exit = malloc_replace__set_exit;
}

static bool
free_arena_at_exit(byte *start, byte *end, uint flags
                   _IF_WINDOWS(HANDLE heap), void *iter_data)
{
    LOG(2, "%s: "PFX"-"PFX" "PIFX"\n", __FUNCTION__, start, end, flags);
    if (TEST(HEAP_ARENA, flags) && !TEST(HEAP_PRE_US, flags)) {
        arena_header_t *arena = (arena_header_t *) start;
#ifdef WINDOWS
        /* freed when libc routine set exits */
        if (!TEST(ARENA_LIBC_DEFAULT, arena->flags))
#endif
            arena_free(arena);
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
}
