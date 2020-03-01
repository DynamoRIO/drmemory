/* **********************************************************
 * Copyright (c) 2012-2020 Google, Inc.  All rights reserved.
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
 * alloc_replace.c: application allocator replacement routines for both
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
 *  | app chunk | pad | rz | header | rz | app chunk    |pad| rz | header | rz |
 *                                                                             ^
 *                                                                 next_chunk _|
 *
 * + for !alloc_ops.shared_redzones, there are two redzones in between
 *   each chunk, with the header in between and separate from the redzones
 *   (geared toward modes that want to fill the redzones)
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
#include "drsymcache.h"
#include <string.h> /* memcpy */

#ifdef MACOS
# include <sys/syscall.h>
# include <sys/mman.h>
# include <malloc/malloc.h>
#elif defined(LINUX)
# include "sysnum_linux.h"
# define __USE_GNU /* for mremap */
# include <sys/mman.h>
#else
# include "../wininc/crtdbg.h"
#endif

#ifdef UNIX
# include <errno.h>
#endif

/***************************************************************************
 * header and free list data structures
 */

/* 64-bit malloc impls generally align to 16, and in fact some Windows code
 * assumes this (i#1219).
 */
#define CHUNK_ALIGNMENT IF_X64_ELSE(16, 8)
#define CHUNK_MIN_SIZE  IF_X64_ELSE(16, 8)
#define CHUNK_MIN_MMAP  128*1024
/* initial commit on linux has to hold at least one non-mmap chunk */
#define ARENA_INITIAL_COMMIT  CHUNK_MIN_MMAP
#define ARENA_INITIAL_SIZE  4*1024*1024

#define REQUEST_DIFF_MAX USHRT_MAX

/* we only support allocation sizes under 4GB */
typedef uint heapsz_t;

/* each free list bucket contains freed chunks of at least its bucket size
 * XXX: add stats on searches to help in tuning these
 */
static const uint free_list_sizes[] = {
    IF_NOT_X64_(8) 16, 24, 32, 40, 64, 96, 128, 192, 256, 384, 512, 1024, 2048,
    4096, 8192, 16384, 32768,
};
#define NUM_FREE_LISTS (sizeof(free_list_sizes)/sizeof(free_list_sizes[0]))

/* Values stored in chunk header flags */
enum {
    CHUNK_FREED       = MALLOC_RESERVED_1,          /* 0x0001 */
    CHUNK_MMAP        = MALLOC_RESERVED_2,          /* 0x0002 */
    /* MALLOC_RESERVED_{3,4} are used for types */  /* 0x000C */
    CHUNK_PRE_US      = MALLOC_RESERVED_5,          /* 0x0100 */
    CHUNK_PREV_FREE   = MALLOC_RESERVED_6,          /* 0x0200 */
    CHUNK_DELAY_FREE  = MALLOC_RESERVED_7,          /* 0x0400 */
#ifdef WINDOWS
    CHUNK_LAYER_RTL   = MALLOC_RESERVED_8,          /* 0x0800 */
#endif
    /* i#1532: only check for non-static libc.  This is Windows-only but it's
     * cleaner to avoid all the ifdefs down below.
     */
    CHUNK_LAYER_NOCHECK = MALLOC_RESERVED_9,
    CHUNK_SKIP_ITER   =   MALLOC_RESERVED_10,

    /* meta-flags */
#ifdef WINDOWS
    ALLOCATOR_TYPE_FLAGS  = (MALLOC_ALLOCATOR_FLAGS | CHUNK_LAYER_RTL |
                             CHUNK_LAYER_NOCHECK),
#else
    ALLOCATOR_TYPE_FLAGS  = (MALLOC_ALLOCATOR_FLAGS),
#endif
};

#define HEADER_MAGIC 0x5244 /* "DR" */

/* This header struct is used in both a traditional co-located header
 * and as a hashtable payload (for alloc_ops.external_headers).  Note
 * that when using redzones there's no problem with a large header as
 * it sits inside the redzone.  But with the hashtable, and for
 * pattern mode with co-located headers, and for Dr. Heapstat where we
 * have no redzone, we want to make the header as compact as is
 * reasonable.
 */
typedef struct _chunk_header_t {
    void *user_data;
    /* If we wanted to save space we could hand out sizes only equal to the buckets
     * and shrink the alloc_size field.  We'd use a separate header for the largest
     * bucket that had the alloc_size.
     */
    heapsz_t alloc_size;
    /* Bitmask of CHUNK_ flags */
    ushort flags;
    /* Put magic last for a greater chance of surviving underflow, esp when our
     * header has no redzone buffer (when redzone_size <= HEADER_SIZE, which
     * unfortunately is true by default as both are 16 for 32-bit).
     */
    ushort magic;
    union {
        /* A live or delay-free chunk does not need a prev pointer, while a truly
         * free chunk does not need the request size nor the prev size (b/c
         * we always coalesce, and we don't set prev size if prev is delay-free).
         */
        struct {
            /* Difference between alloc_size and requested size.  We currently always
             * split re-used large free chunks, so 64K as the max diff works out.
             */
            ushort request_diff;
            /* The size of the previous free chunk / CHUNK_ALIGNMENT (i.e., >>3).  Only
             * valid if CHUNK_PREV_FREE is set in flags.  We get away with only a 512KB
             * max because larger elements, which are always mmaps, are not put on the
             * free list or coalesced.  We assert on the various constants all lining up
             * in our init routine.  After coalescing we can reach a larger size than
             * 512KB, in which case we place 0 here and store the size immediately
             * prior to the redzone.
             *
             * If CHUNK_MMAP is set in flags, this holds the padding at the start
             * of the mmap base put in place for alignment of the returned alloc,
             * / CHUNK_ALIGNMENT (i.e., >> 3).
             */
            ushort prev_size_shr;
#ifdef X64
            /* Compiler will add anyway: just making explicit.  we need the header
             * size to be aligned to 8 so we can't pack.  for alloc_ops.external_headers
             * we eat this overhead to provide runtime flexibility w/ the same
             * data struct as we don't need it there.
             * Update: actually we need to align to 16.
             */
            uint pad;
#endif
        } unfree;
        struct _free_header_t *prev;
    } u;
} chunk_header_t;

/* Header at the top of an mmap used for large allocs.  If we didn't need to
 * support memalign() & co, we could get away without this.
 */
typedef struct _mmap_header_t {
    chunk_header_t *head;
    size_t map_size;
} mmap_header_t;

/* To support pattern mode, which wants to fill the redzone with its pattern,
 * we don't want the next pointer in the redzone.  For now we pay the cost
 * of extra memory rather than complicate the interface to pattern mode
 * to have it skip the next pointer (we'd need a call when we move from delay
 * queueu to free lists, and we'd need to adjust real_base on several calls:
 * and ensure client isn't storing things by real base!).
 * Thus, we indirect the live header size through here.
 */
static heapsz_t header_size;

/* if redzone is too small, header sticks beyond it */
static heapsz_t header_beyond_redzone;
/* we place header in the middle */
static heapsz_t redzone_beyond_header;

/* Free list header for both regular and var-size chunk.  Each chunk
 * is at least 8 bytes so we can fit the next pointer here even for
 * x64.  We squish the prev pointer into fields of the chunk header we
 * no longer need, for a true free; for a delay free we don't use a
 * prev pointer.
 *
 * FIXME: for alloc_ops.external_headers do we need a chunk pointer
 * here?  or will it be in the head struct?
 */
typedef struct _free_header_t {
    chunk_header_t head;
    struct _free_header_t *next;
} free_header_t;

typedef struct _free_lists_t {
    /* Delayed frees are kept here for more fair delaying across sizes
     * than if we put them into the per-size lists.
     */
    free_header_t *delay_front;
    free_header_t *delay_last;
    /* The delay threshold is per-arena */
    uint delayed_chunks;
    size_t delayed_bytes;
    /* A normal free list can be LIFO, but for more effective delayed frees
     * we want FIFO.  FIFO-per-bucket-size is sufficient.
     */
    free_header_t *front[NUM_FREE_LISTS];
    free_header_t *last[NUM_FREE_LISTS];
} free_lists_t;

#ifdef LINUX
/* we assume we're the sole users of the brk (after pre-us allocs) */
static byte *pre_us_brk;
static byte *cur_brk;
#endif

#ifdef WINDOWS
/* For alloc_ops.global_lock (xref i#949).  Each arena's dr_lock points
 * at this lock when alloc_ops.global_lock is true.
 */
static void *global_lock;
#endif

/* header at the top of each arena (an "arena" for this code is a contiguous
 * piece of memory parceled out into individual malloc "chunks")
 */
typedef struct _arena_header_t {
#ifdef MACOS
    /* Placed at the start for easy conversion back and forth.
     * We ignore the function pointers inside here.
     * Xref i#1699.
     */
    malloc_zone_t zone_inlined;
    /* Some apps write to zone_inlined.zone_name and then mark the page read-only. */
    char padding[PAGE_SIZE-sizeof(malloc_zone_t)];
    /* For child arenas to point at the parent */
    malloc_zone_t *zone;
#endif
    byte *start_chunk;
    byte *next_chunk;
    byte *commit_end;
    byte *reserve_end;
    free_lists_t *free_list;
#ifdef WINDOWS
    /* i#949: We need two locks.  The lock field is the app lock, which can
     * be acquired while in app code.  This field is a pure DR lock, and
     * it's used to synchronize free chunk splitting and coalescing with
     * malloc iteration.  (Regular mallocs and frees that do not split
     * or coalesce do not need to synchronize with malloc iteration.)
     * We always acquire the app lock first if we acquire both.
     */
    void *dr_lock;
#endif
    void *lock; /* app lock for Windows */
    uint flags;
    /* If we free the final chunk before the brk we need to know to mark the
     * next carved-out chunk w/ the prev free size.
     */
    heapsz_t prev_free_sz;
    uint magic;
#ifdef WINDOWS
    /* A member of the alloc set for which this arena is the default heap */
    app_pc alloc_set_member;
    /* Base of the module for which this is the default Heap */
    app_pc modbase;
    /* HANDLE of Heap, for pre-us Heap */
    HANDLE handle;
#endif
    /* we need to iterate arenas belonging to one (non-default) Heap */
    struct _arena_header_t *next_arena;
    /* for main arena of each Heap, we inline free_lists_t here */
} arena_header_t;

#ifdef WINDOWS
/* pick a flag that can't be passed on the Heap level to identify whether
 * a Heap or a regular arena
 */
# define ARENA_MAIN HEAP_ZERO_MEMORY  /* 0x8 */
# define ARENA_PRE_US_MAPPED   0x100  /* unused by Windows */
/* another non-Heap flag to identify libc-default Heaps (i#939) */
# define ARENA_LIBC_DEFAULT HEAP_REALLOC_IN_PLACE_ONLY /* 0x10 */
/* identify whether a static libc heap is the process heap (i#1223) */
# define ARENA_LIBC_SPECULATIVE  0x200  /* unused by Windows */
/* flags that we support being passed to HeapCreate:
 * HEAP_CREATE_ENABLE_EXECUTE | HEAP_GENERATE_EXCEPTIONS | HEAP_NO_SERIALIZE |
 * HEAP_GROWABLE
 */
# define HEAP_CREATE_POSSIBLE_FLAGS 0x40007
static HANDLE process_heap;
/* i#1754: for pre-us mapped memory, in particular the shared-memory CsrPortHeap,
 * we do not attempt to detect uninitialized reads as it very difficult to
 * track writes by csrss.  The simplest way to accomplish this is to mark
 * all allocs as defined by zeroing them.
 */
# define WINDOWS_ZERO_MEMORY(arena, alloc_flags) \
    (TEST(ARENA_PRE_US_MAPPED, (arena)->flags) || TEST(HEAP_ZERO_MEMORY, (alloc_flags)))
#else
# define ARENA_MAIN 0x0001
#endif

/* Linux current arena, or Windows default Heap.  We always use this main
 * pointer as the arena, even though there can be extra sub-arena regions that
 * belong to this Heap linked in the next_arena field.
 */
static arena_header_t *cur_arena;

/* For handling pre-us mallocs for non-earliest injection or delayed/attach
 * instrumentation.  Contains chunk_header_t entries.
 * We assume this table is only added to at init and only removed from
 * at exit time and thus needs no external lock.
 */
#define PRE_US_TABLE_HASH_BITS 8
static hashtable_t pre_us_table;

/* XXX i#879: for pattern mode we ideally don't want any co-located
 * headers and instead want a hashtable of live allocs (free are in
 * free lists and/or rbtree).
 * Cleaner to have own table here and not try to use the alloc.c malloc-wrap table
 * though we do want the same hash tuning.
 * Currently we have a much simpler implementation for pattern mode
 * that uses non-shared redzones and a header in between (so it looks
 * like wrapping, and like wrapping won't detect a bug that clobbers
 * the header prior to corruption and possible crash).
 */

#ifdef STATISTICS
static uint heap_capacity;
static uint peak_heap_capacity;
static uint num_arenas;
static uint peak_num_arenas;
static uint num_splits;
static uint num_coalesces;
static uint num_dealloc;
static uint dbgcrt_mismatch;
static uint allocs_left_native;
#endif

#ifdef DEBUG
/* used to allow use of app stack on abort */
static bool aborting;
#endif

/* Indicates whether process initialization is fully complete, including
 * iteration of modules.  Thus, we don't set this until we get the
 * first bb event.
 */
static bool process_initialized;

#ifdef WINDOWS
static app_pc executable_base;

static arena_header_t *
check_libc_vs_process_heap(alloc_routine_entry_t *e, arena_header_t *arena);
#endif

#ifdef MACOS
static void
malloc_zone_init(arena_header_t *arena);
#endif

/* Flags controlling allocation behavior */
typedef enum {
    ALLOC_SYNCHRONIZE      = 0x0001, /* malloc, free, and realloc */
    ALLOC_ZERO             = 0x0002, /* malloc and realloc */
    ALLOC_IS_REALLOC       = 0x0004, /* malloc and free */
    /* Routines that free the client_data (client_malloc_data_free(),
     * client_handle_free_reuse()) and routines reporting on invalid
     * heap args or OOM are called regardless of these flags' values.
     */
    /* Whether to invoke client_{add,remove}_malloc_{pre,post} */
    ALLOC_INVOKE_CLIENT_DATA   = 0x0008, /* malloc and free */
    /* Whether to invoke client_handle_{malloc,free} */
    ALLOC_INVOKE_CLIENT_ACTION = 0x0010, /* malloc and free */
    ALLOC_INVOKE_CLIENT    = ALLOC_INVOKE_CLIENT_DATA | ALLOC_INVOKE_CLIENT_ACTION,
    ALLOC_IN_PLACE_ONLY    = 0x0020, /* realloc */
    ALLOC_ALLOW_NULL       = 0x0040, /* realloc: do not fail on NULL */
    ALLOC_ALLOW_EMPTY      = 0x0080, /* realloc: size==0 does re-allocate */
    ALLOC_IGNORE_MISMATCH  = 0x0100, /* free, realloc, size */
    ALLOC_IS_QUERY         = 0x0200, /* check_type_match */
} alloc_flags_t;

/***************************************************************************
 * utility routines
 */

#define DR_STATE_TO_SWAP (DR_STATE_ALL & (~DR_STATE_STACK_BOUNDS))

#ifdef WINDOWS
static inline const char *
malloc_layer_name(uint flags)
{
    if (TEST(CHUNK_LAYER_RTL, flags))
        return "Windows API layer";
    else
        return "C library layer";
}
#endif

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
    dr_switch_to_dr_state_ex(drcontext, DR_STATE_TO_SWAP);
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
        dr_switch_to_app_state_ex(drcontext, DR_STATE_TO_SWAP);
#endif

    drwrap_replace_native_fini(drcontext);

    /* i#1217: yet another point where we zero out data to avoid stale retaddrs
     * on our callstacks.  For 32-bit, dr_write_saved_reg() called by
     * drwrap_replace_native_fini() has the app retaddr on the stack.  We clear
     * it here.
     * For 32-bit, we assume it's safe to write beyond TOS.
     * For 64-bit, this is not a leaf routine, so we similarly assume it's safe:
     * but it's more fragile (xref i#1278).
     * drwrap_replace_native_fini() currently uses 12 bytes of stack for 32-bit
     * and 56 for 64-bit (and dr_write_saved_reg() uses 32, but we
     * only care about its param slots).
     *
     * XXX: if we knew whether we had DrMem definedness info we could avoid
     * this work for full mode.
     */
#   define ZERO_APP_STACK_SZ   IF_X64_ELSE(64, 32)
    /* We can't call memset() or any regular function b/c it will clobber its
     * own stack, nor can we have a loop here as we can clobber our own locals.
     * Thus we must use an asm routine.
     */
    zero_pointers_on_stack(ZERO_APP_STACK_SZ);
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

/* Locking for any alloc or free operation */
static void
arena_lock(void *drcontext, arena_header_t *arena, bool app_synch)
{
    /* XXX i#948: use per-thread free lists to avoid lock in common case,
     * for Linux or Windows libc at least (where heap synch is not part
     * of app API), and when !alloc_ops.global_lock.
     */
    if (app_synch)
        app_heap_lock(drcontext, arena->lock);
#ifdef WINDOWS
    /* i#949: regardless of app synch, we need to synchronize our own
     * operations.  We must grab this after the app lock.  We don't need
     * this to be a safe spot as it's only grabbed in our own code.
     */
    if (alloc_ops.global_lock)
        dr_recurlock_lock(arena->dr_lock);
#else
    /* We assume every top-level caller synchronizes (can't check here b/c
     * this can be called via realloc calling free or malloc).
     * If synch becomes optional on Linux, need to use dr_lock too.
     */
#endif
}

static void
arena_unlock(void *drcontext, arena_header_t *arena, bool app_synch)
{
#ifdef WINDOWS
    if (alloc_ops.global_lock)
        dr_recurlock_unlock(arena->dr_lock);
#else
    /* We assume every top-level caller synchronizes (can't check here b/c
     * this can be called via realloc calling free or malloc).
     * If synch becomes optional on Linux, need to use dr_lock too.
     */
#endif
    if (app_synch)
        app_heap_unlock(drcontext, arena->lock);
}

/* i#949: locking for alloc or free operations that affect concurrent
 * iteration: splitting or coalescing of free chunks.  Changing header
 * flags concurrently with iteration is ok.  If the iterator wants to
 * look for certain flags across multiple iterations, the user needs
 * to set alloc_ops.global_lock.
 */
static void
iterator_lock(arena_header_t *arena, bool in_alloc)
{
    /* We could blindly lock (it's a recursive lock) but more performant this way */
#ifdef WINDOWS
    if (!in_alloc || !alloc_ops.global_lock)
        dr_recurlock_lock(arena->dr_lock);
    else
        ASSERT(dr_recurlock_self_owns(arena->dr_lock), "lock error");
#else
    if (!in_alloc)
        dr_recurlock_lock(arena->lock);
    else
        ASSERT(dr_recurlock_self_owns(arena->lock), "lock error");
#endif
}

static void
iterator_unlock(arena_header_t *arena, bool in_alloc)
{
#ifdef WINDOWS
    ASSERT(dr_recurlock_self_owns(arena->dr_lock), "lock error");
    if (!in_alloc || !alloc_ops.global_lock)
        dr_recurlock_unlock(arena->dr_lock);
#else
    ASSERT(dr_recurlock_self_owns(arena->lock), "lock error");
    if (!in_alloc)
        dr_recurlock_unlock(arena->lock);
#endif
}

#if defined(WINDOWS) && defined(X64)
static app_pc
get_replace_native_caller(void *drcontext)
{
    /* drwrap saved the retaddr slot for us */
    byte *app_xsp = (byte *) dr_read_saved_reg(drcontext, DRWRAP_REPLACE_NATIVE_SP_SLOT);
    return *(app_pc *)app_xsp;
}
#endif

/* This must be inlined to get an xsp that's in the call chain */
#define INITIALIZE_MCONTEXT_FOR_REPORT(mc) do {            \
    /* assumption: we only need xsp and xbp initialized */ \
    (mc)->size = sizeof(*(mc));                            \
    (mc)->flags = DR_MC_CONTROL | DR_MC_INTEGER;           \
    get_stack_registers(&MC_SP_REG(mc), &MC_FP_REG(mc)); \
} while (0)

#ifdef WINDOWS
static inline uint
arena_page_prot(uint flags)
{
    return DR_MEMPROT_READ | DR_MEMPROT_WRITE |
        (TEST(HEAP_CREATE_ENABLE_EXECUTE, flags) ? DR_MEMPROT_EXEC : 0);
}
#endif

/* We used to call raw_syscall() and virtual_alloc(), but for DRi#199 we
 * now have DR routines we can use, which avoids DR asserts (mainly on
 * Linux allmem, but possible to have problems everywhere if the app
 * puts code in the heap).
 */
static byte *
os_large_alloc(size_t commit_size _IF_WINDOWS(size_t reserve_size) _IF_WINDOWS(uint prot))
{
#ifdef UNIX
    byte *map = (byte *)
        dr_raw_mem_alloc(commit_size, DR_MEMPROT_READ | DR_MEMPROT_WRITE, NULL);
    ASSERT(ALIGNED(commit_size, PAGE_SIZE), "must align to at least page size");
    /* dr_raw_mem_alloc returns NULL on failure, but I'm keeping the range for
     * raw syscall.
     */
    if ((ptr_int_t)map <= 0 && (ptr_int_t)map > -PAGE_SIZE) {
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
    loc = dr_custom_alloc(NULL, DR_ALLOC_NON_HEAP | DR_ALLOC_NON_DR |
                          DR_ALLOC_RESERVE_ONLY, reserve_size,
                          DR_MEMPROT_NONE, NULL);
    if (loc == NULL)
        return NULL;
    loc = dr_custom_alloc(NULL, DR_ALLOC_NON_HEAP | DR_ALLOC_NON_DR |
                          DR_ALLOC_COMMIT_ONLY | DR_ALLOC_FIXED_LOCATION, commit_size,
                          prot, loc);
    if (loc == NULL) {
        dr_custom_free(NULL, DR_ALLOC_NON_HEAP | DR_ALLOC_NON_DR, loc, reserve_size);
        return NULL;
    }
    LOG(3, "%s commit="PIFX" reserve="PIFX" prot=0x%x => "PFX"\n",
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
    ASSERT(new_commit_size > cur_commit_size, "this routine does not support shrinking");
#ifdef LINUX
    byte *newmap = (byte *) dr_raw_mremap(map, cur_commit_size, new_commit_size,
                                          0/*can't move*/, NULL/*ignored*/);
    if ((ptr_int_t)newmap <= 0 && (ptr_int_t)newmap > -PAGE_SIZE)
        return false;
    return true;
#elif defined(MACOS)
    /* There is no mremap on Mac so we try to do a new mmap at the right spot.
     * We can still free both with one munmap.
     * We don't dare do DR_ALLOC_FIXED_LOCATION as it may clobber something.
     */
    byte *newmap = (byte *)
        dr_raw_mem_alloc(new_commit_size - cur_commit_size,
                         DR_MEMPROT_READ | DR_MEMPROT_WRITE,
                         map + cur_commit_size);
    if ((ptr_int_t)newmap <= 0 && (ptr_int_t)newmap > -PAGE_SIZE)
        return false;
    if (newmap != map + cur_commit_size) {
        /* Didn't get the subsequent spot: bail. */
        dr_raw_mem_free(newmap, new_commit_size - cur_commit_size);
        return false;
    }
    return true;
#else /* WINDOWS */
    /* i#1258: we have to tweak [map + cur_commit_size, map + new_commit_size)
     * and not re-commit [map, map + new_commit_size) b/c the latter will
     * modify the prot bits on existing pages, which the app might have
     * changed from the arena default!
     */
    return (dr_custom_alloc(NULL, DR_ALLOC_NON_HEAP | DR_ALLOC_NON_DR |
                            DR_ALLOC_COMMIT_ONLY | DR_ALLOC_FIXED_LOCATION,
                            new_commit_size - cur_commit_size, prot,
                            map + cur_commit_size) != NULL);
#endif
}

/* For Windows, map_size is ignored and the whole allocation is freed */
static bool
os_large_free(byte *map, size_t map_size)
{
#ifdef UNIX
    bool success;
    ASSERT(ALIGNED(map, PAGE_SIZE), "invalid mmap base");
    ASSERT(ALIGNED(map_size, PAGE_SIZE), "invalid mmap size");
    success = dr_raw_mem_free(map, map_size);
    LOG(3, "%s "PFX" size="PIFX" => %d\n",  __FUNCTION__, map, map_size, success);
    return success;
#else
    LOG(3, "%s "PFX" size="PIFX"\n", __FUNCTION__, map, map_size);
    return dr_custom_free(NULL, DR_ALLOC_NON_HEAP | DR_ALLOC_NON_DR, map, map_size);
#endif
}

static inline heapsz_t
chunk_request_size(chunk_header_t *head)
{
    return (head->alloc_size - head->u.unfree.request_diff);
}

static void
notify_client_alloc(void *drcontext, byte *ptr, chunk_header_t *head,
                    alloc_flags_t flags, dr_mcontext_t *mc, app_pc caller)
{
    malloc_info_t info = { sizeof(info), ptr, chunk_request_size(head),
                           head->alloc_size, false/*!pre_us*/, true/*redzone*/,
                           TEST(ALLOC_ZERO, flags), TEST(ALLOC_IS_REALLOC, flags),
                           0, head->user_data };
    if (TEST(ALLOC_INVOKE_CLIENT_DATA, flags)) {
        head->user_data = client_add_malloc_pre(&info, mc, caller);
        info.client_data = head->user_data;
        client_add_malloc_post(&info);
    }
    if (TEST(ALLOC_INVOKE_CLIENT_ACTION, flags)) {
        ASSERT(drcontext != NULL, "invalid arg");
        client_handle_malloc(drcontext, &info, mc);
    }
}

/***************************************************************************
 * core allocation routines
 */

static inline chunk_header_t *
header_from_ptr(const void *ptr)
{
    if (alloc_ops.external_headers) {
        /* XXX i#879: hashtable lookup */
        ASSERT(false, "NYI");
        return NULL;
    } else {
        if ((ptr_uint_t)ptr < header_size)
            return NULL;
        else {
            return (chunk_header_t *) ((byte *)ptr - redzone_beyond_header - header_size);
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
    } else {
        ASSERT(!TEST(CHUNK_PRE_US, head->flags), "caller must handle pre-us");
        return (byte *)head + redzone_beyond_header + header_size;
    }
}

static inline chunk_header_t *
header_from_mmap_base(void *map)
{
    if (alloc_ops.external_headers) {
        /* XXX i#879: hashtable lookup */
        ASSERT(false, "NYI");
        return NULL;
    } else {
        if ((ptr_uint_t)map < header_size)
            return NULL;
        else {
            mmap_header_t *mhead = (mmap_header_t *) map;
            return mhead->head;
        }
    }
}

/* Distance from the end of one chunk (its start pointer plus alloc_size) to
 * the start of the user memory for the subsequent chunk
 */
static inline size_t
inter_chunk_space(void)
{
    return alloc_ops.redzone_size + header_beyond_redzone +
        (alloc_ops.shared_redzones ? 0 : alloc_ops.redzone_size);
}

/* Pass in result of header_from_ptr() as 2nd arg, but don't de-reference it!
 * Returns true for both live mallocs and chunks in delay free lists
 */
static inline bool
is_valid_chunk(const void *ptr, chunk_header_t *head)
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
    arena_header_t *a;
    for (a = arena; a != NULL; a = a->next_arena) {
        if (ptr >= a->start_chunk && ptr < a->commit_end)
            return true;
    }
    LOG(2, "%s: "PFX" not found in arena "PFX"\n", __FUNCTION__, ptr, arena);
    return false;
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

/* The base param must be non-NULL for pre-us; else, it can be NULL */
static inline void
header_to_info(chunk_header_t *head, malloc_info_t *info, byte *pre_us_base,
               alloc_flags_t flags /* pass 0 if not a new alloc notification */)
{
    info->struct_size = sizeof(*info);
    info->pre_us = TEST(CHUNK_PRE_US, head->flags);
    info->base = (info->pre_us ? pre_us_base : ptr_from_header(head));
    ASSERT(!info->pre_us || pre_us_base != NULL, "need base for pre-us!");
    info->request_size = chunk_request_size(head);
    info->pad_size = head->alloc_size;
    info->has_redzone = !info->pre_us;
    info->zeroed = TEST(ALLOC_ZERO, flags);
    info->realloc = TEST(ALLOC_IS_REALLOC, flags);
    info->client_flags = head->flags & MALLOC_POSSIBLE_CLIENT_FLAGS;
    info->client_data = head->user_data;
}

/* Assumes caller zeroed the full struct and initialized the commit_end and
 * reserve_end fields.
 */
static void
arena_init(arena_header_t *arena, arena_header_t *parent)
{
    size_t header_size = sizeof(*arena);
    if (parent != NULL) {
        /* XXX: maybe we should have two different headers for parents vs children */
        arena->flags = (parent->flags & (~ARENA_MAIN));
        arena->lock = parent->lock;
#ifdef WINDOWS
        arena->dr_lock = parent->dr_lock;
#endif
        arena->free_list = parent->free_list;
#ifdef WINDOWS
        arena->alloc_set_member = parent->alloc_set_member;
        arena->modbase = parent->modbase;
        arena->handle = parent->handle;
#endif
#ifdef MACOS
        arena->zone = parent->zone;
#endif
    } else {
        arena->flags = ARENA_MAIN;
        arena->lock = dr_recurlock_create();
        /* We only grab this DR lock as the app and we mark it with
         * dr_recurlock_mark_as_app(), as well as using dr_mark_safe_to_suspend(),
         * to ensure proper DR behavior
         */
        dr_recurlock_mark_as_app(arena->lock);
#ifdef WINDOWS
        if (alloc_ops.global_lock)
            arena->dr_lock = global_lock;
        else
            arena->dr_lock = dr_recurlock_create();
#endif
        /* to avoid complications of storing and freeing DR heap we inline these
         * in the main arena's header
         */
        arena->free_list = (free_lists_t *) ((byte *)arena + header_size);
        header_size += sizeof(*arena->free_list);
#ifdef WINDOWS
        arena->alloc_set_member = NULL;
        arena->modbase = NULL;
        arena->handle = NULL;
#endif
#ifdef MACOS
        malloc_zone_init(arena);
#endif
    }
    /* need to start with a redzone */
    arena->start_chunk = (byte *)arena +
        /* XXX: this wastes the initial redzone for !shared_redzones */
        ALIGN_FORWARD(header_size, CHUNK_ALIGNMENT) + inter_chunk_space();
    arena->next_chunk = arena->start_chunk;
    arena->magic = HEADER_MAGIC;
    arena->next_arena = NULL;
    arena->prev_free_sz = 0;
    STATS_ADD(heap_capacity, (uint)(arena->commit_end - (byte *)arena));
    STATS_PEAK(heap_capacity);
    STATS_INC(num_arenas);
    STATS_PEAK(num_arenas);
    if (parent != NULL) {
        ASSERT(parent->next_arena == NULL, "should only append to end");
        parent->next_arena = arena;
    }
}

/* up to caller to call heap_region_remove() */
static void
arena_deallocate(arena_header_t *arena)
{
#ifdef LINUX
    if (arena->reserve_end != cur_brk)
#elif defined(WINDOWS)
    /* For pre-us mapped we just never free */
    if (!TEST(ARENA_PRE_US_MAPPED, arena->flags))
#endif
        os_large_free((byte *)arena, arena->reserve_end - (byte *)arena);
}

/* up to caller to call heap_region_remove() before calling here,
 * as we can't call it here b/c we're invoked from heap_region_iterate()
 */
static void
arena_free(arena_header_t *arena)
{
    if (TEST(ARENA_MAIN, arena->flags)) {
        dr_recurlock_destroy(arena->lock);
#ifdef WINDOWS
        if (!alloc_ops.global_lock)
            dr_recurlock_destroy(arena->dr_lock);
#endif
    }
    arena_deallocate(arena);
}

static arena_header_t *
arena_create(arena_header_t *parent, size_t initial_size)
{
    size_t init_size = (initial_size == 0) ? ARENA_INITIAL_SIZE : initial_size;
    arena_header_t *new_arena = (arena_header_t *)
        os_large_alloc(IF_WINDOWS_(ARENA_INITIAL_COMMIT) init_size
                       _IF_WINDOWS(arena_page_prot(parent->flags)));
    if (new_arena == NULL)
        return NULL;
#ifdef UNIX
    new_arena->commit_end = (byte *)new_arena + init_size;
#else
    new_arena->commit_end = (byte *)new_arena + ARENA_INITIAL_COMMIT;
#endif
    new_arena->reserve_end = (byte *)new_arena + init_size;
    heap_region_add((byte *)new_arena, new_arena->reserve_end, HEAP_ARENA, NULL);
    arena_init(new_arena, parent);
    return new_arena;
}

/* Either extends arena in-place and returns it, or allocates a new arena
 * and returns that.  Returns NULL on failure to do either.
 * Expects to be passed the final sub-arena, not the master arena.
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
            STATS_ADD(heap_capacity, (uint)(new_brk - cur_brk));
            STATS_PEAK(heap_capacity);
            cur_brk = new_brk;
            arena->commit_end = new_brk;
            arena->reserve_end = arena->commit_end;
            heap_region_adjust((byte *)arena, new_brk);
            return arena;
        } else {
            LOG(1, "brk @"PFX"-"PFX" cannot expand: switching to mmap\n",
                pre_us_brk, cur_brk);
        }
    } else
#else
    if (arena->commit_end + aligned_add <= arena->reserve_end)
#endif
    { /* here to not confuse brace matching */
        size_t cur_size = arena->commit_end - (byte *)arena;
        size_t new_size = cur_size + aligned_add;
        if (os_large_alloc_extend((byte *)arena, cur_size, new_size
                                  _IF_WINDOWS(arena_page_prot(arena->flags)))) {
            LOG(2, "\textended arena to "PFX"-"PFX"\n", arena, (byte*)arena + new_size);
            STATS_ADD(heap_capacity, (uint)(new_size - cur_size));
            STATS_PEAK(heap_capacity);
            arena->commit_end = (byte *)arena + new_size;
#ifdef UNIX /* windows already added whole reservation */
            arena->reserve_end = arena->commit_end;
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
    new_arena = arena_create(arena, 0/*default*/);
    LOG(1, "cur arena "PFX"-"PFX" out of space: created new one @"PFX"\n",
        (byte *)arena, arena->reserve_end, new_arena);
    return new_arena;
}

static inline bool
arena_delayed_list_full(arena_header_t *arena)
{
    return (arena->free_list->delayed_chunks >= alloc_ops.delay_frees ||
            arena->free_list->delayed_bytes >= alloc_ops.delay_frees_maxsz);
}

static inline chunk_header_t *
next_chunk_forward(arena_header_t *arena, chunk_header_t *head,
                   arena_header_t **container_out OUT)
{
    arena_header_t *container;
    byte *start = ptr_from_header(head);
    /* XXX: this arena walk is showing up in too many places.  We may need
     * to optimize this.
     */
    for (container = arena; container != NULL; container = container->next_arena) {
        if (start >= container->start_chunk && start < container->commit_end) {
            start += head->alloc_size + inter_chunk_space();
            if (start < container->next_chunk) {
                chunk_header_t *next = header_from_ptr(start);
                ASSERT(is_valid_chunk(start, next), "next_chunk_forward error");
                return next;
            } else if (container_out != NULL)
                *container_out = container;
            break;
        }
    }
    return NULL;
}

/* updates the prev size field of the next chunk, if any */
static void
set_prev_size_field(arena_header_t *arena, chunk_header_t *head)
{
    arena_header_t *container = NULL;
    chunk_header_t *next = next_chunk_forward(arena, head, &container);
    ASSERT(!TEST(CHUNK_DELAY_FREE, head->flags), "no need/room for prev size for delay");
    if (next != NULL) {
        ASSERT(!TEST(CHUNK_FREED, next->flags) || TEST(CHUNK_DELAY_FREE, next->flags),
               "can't set prev size on true free");
        next->flags |= CHUNK_PREV_FREE;
        if (head->alloc_size / CHUNK_MIN_SIZE <= USHRT_MAX) {
            next->u.unfree.prev_size_shr = head->alloc_size / CHUNK_MIN_SIZE;
            LOG(3, "set prev_size_shr of "PFX" to "PIFX"\n",
                next, next->u.unfree.prev_size_shr);
        } else {
            /* We don't want to increase the header size, so we store
             * in the prev chunk.  This takes away one slot from pattern
             * mode but we can live with that.
             */
            byte *redzone_start = (byte *)next - inter_chunk_space();
            next->u.unfree.prev_size_shr = 0;
            LOG(3, "writing prev size "PIFX" to "PFX"\n", head->alloc_size,
                redzone_start - sizeof(heapsz_t));
            *(heapsz_t*)(redzone_start - sizeof(heapsz_t)) = head->alloc_size;
        }
    } else {
        ASSERT(container != NULL, "couldn't find containing sub-arena");
        container->prev_free_sz = head->alloc_size;
    }
}

static heapsz_t
get_prev_size_field(chunk_header_t *head)
{
    ASSERT(TEST(CHUNK_PREV_FREE, head->flags), "only call if prev free exists");
    if (head->u.unfree.prev_size_shr == 0) {
        byte *redzone_start = (byte *)head - inter_chunk_space();
        LOG(3, "reading prev size "PIFX" from "PFX"\n",
            *(heapsz_t*)(redzone_start - sizeof(heapsz_t)),
            redzone_start - sizeof(heapsz_t));
        return *(heapsz_t*)(redzone_start - sizeof(heapsz_t));
    } else
        return head->u.unfree.prev_size_shr * CHUNK_MIN_SIZE;
}

#define GCC_VERSION (__GNUC__ * 10000 + __GNUC_MINOR__ * 100 + __GNUC_PATCHLEVEL__)

/* XXX: i#1269 index above array bounds warning on x64 build using gcc 4.8.1 */
#if defined(X64) && GCC_VERSION > 40801
#  define IF_GCC_WARN(x)
#else
#  define IF_GCC_WARN(x) x
#endif

static inline uint
bucket_index(chunk_header_t *head)
{
    uint bucket;
    /* pivot around small vs large first to avoid walking whole list for small: */
    uint start = (head->alloc_size > free_list_sizes[6]) ? (NUM_FREE_LISTS - 1) : 6;
    /* our buckets guarantee that all allocs in that bucket have at least that size */
    for (bucket = start; head->alloc_size < free_list_sizes[bucket]
         /* if bucket is 0 this cond breaks to avoid free_list_sizes[-1] */
         IF_GCC_WARN(&& bucket > 0);
         bucket--)
        ; /* nothing */
    ASSERT(head->alloc_size >= free_list_sizes[bucket], "bucket invariant violated");
    return bucket;
}

/* Pass UINT_MAX if the bucket is not known */
static void
remove_from_free_list(arena_header_t *arena, free_header_t *target, uint bucket)
{
    if (target->head.u.prev == NULL) {
        if (bucket == UINT_MAX)
            bucket = bucket_index(&target->head);
        ASSERT(target == arena->free_list->front[bucket], "free list corrupted");
        arena->free_list->front[bucket] = target->next;
    } else {
        target->head.u.prev->next = target->next;
    }
    if (target->next == NULL) {
        if (bucket == UINT_MAX)
            bucket = bucket_index(&target->head);
        ASSERT(target == arena->free_list->last[bucket], "free list corrupted");
        arena->free_list->last[bucket] = target->head.u.prev;
    } else {
        target->next->head.u.prev = target->head.u.prev;
    }
}

static void
add_to_free_list(arena_header_t *arena, chunk_header_t *head)
{
    free_header_t *cur = (free_header_t *) head;
    uint bucket = bucket_index(head);
    cur->next = NULL;
    if (arena->free_list->last[bucket] == NULL) {
        ASSERT(arena->free_list->front[bucket] == NULL, "inconsistent free list");
        arena->free_list->front[bucket] = cur;
        cur->head.u.prev = NULL;
    } else {
        cur->head.u.prev = arena->free_list->last[bucket];
        arena->free_list->last[bucket]->next = cur;
    }
    arena->free_list->last[bucket] = cur;
    LOG(3, "%s: arena "PFX" bucket %d free front="PFX" last="PFX"\n", __FUNCTION__,
        arena, bucket, arena->free_list->front[bucket],
        arena->free_list->last[bucket]);
}

static free_header_t *
consider_giving_back_memory(arena_header_t *arena, chunk_header_t *tofree)
{
    /* If we've accumulated enough, consider giving it back to the OS.
     * We won't give back a new arena in which we haven't allocated at
     * least half of it, even if it's now all free.
     */
    if (tofree->alloc_size >= ARENA_INITIAL_SIZE/2) {
        arena_header_t *sub, *prev = NULL;
        byte *ptr = ptr_from_header(tofree);
#ifdef LINUX
        if (arena->reserve_end == cur_brk) {
            sub = NULL; /* don't search */
            if (ptr + tofree->alloc_size + inter_chunk_space() == arena->next_chunk) {
                /* Shrink the brk */
                byte *new_brk = set_brk((byte *)ALIGN_FORWARD(ptr, PAGE_SIZE));
                if (new_brk <= cur_brk) {
                    LOG(2, "shrinking brk "PFX"-"PFX" to "PFX"-"PFX"\n",
                        pre_us_brk, cur_brk, pre_us_brk, new_brk);
                    STATS_ADD(heap_capacity, (int)(new_brk - cur_brk));
                    STATS_INC(num_dealloc);
                    heap_region_remove(new_brk, cur_brk, NULL);
                    cur_brk = new_brk;
                    arena->commit_end = new_brk;
                    arena->reserve_end = new_brk;
                    arena->next_chunk = ptr;
                    arena->prev_free_sz = 0; /* can't end in free: would be coalesced */
                    return NULL;
                } else {
                    LOG(1, "brk @"PFX"-"PFX" failed to shrink to "PFX"\n",
                        pre_us_brk, cur_brk, ptr);
                }
            }
        }
#endif
        for (sub = arena; sub != NULL; prev = sub, sub = sub->next_arena) {
            if (ptr == sub->start_chunk &&
                ptr + tofree->alloc_size + inter_chunk_space() == sub->next_chunk) {
                if (prev == NULL) {
                    /* If there's a next_arena, we could try to
                     * de-allocate the main region and copy the free
                     * lists over, but for now we don't do anything.
                     */
                } else {
                    LOG(2, "de-allocating arena "PFX"-"PFX"\n", sub, sub->reserve_end);
                    prev->next_arena = sub->next_arena;
                    STATS_ADD(heap_capacity, -(int)(sub->commit_end - (byte *)sub));
                    STATS_INC(num_dealloc);
                    STATS_DEC(num_arenas);
                    heap_region_remove((byte *)sub, sub->reserve_end, NULL);
                    arena_deallocate(sub);
                    return NULL;
                }
            }
        }
    }
    return (free_header_t *) tofree;
}

/* Returns the header of the newly coalesced entry, or cur unchanged
 * if no coalescing was done.  Does not add cur to the free lists.
 */
static free_header_t *
coalesce_adjacent_frees(arena_header_t *arena, free_header_t *cur)
{
    chunk_header_t *tofree = &cur->head, *next;
    if (TEST(CHUNK_PREV_FREE, cur->head.flags)) {
        /* Coalesce with prior block */
        size_t prev_sz = get_prev_size_field(&cur->head);
        byte *cur_ptr = ptr_from_header(tofree);
        byte *prev_ptr = cur_ptr - inter_chunk_space() - prev_sz;
        free_header_t *prev = (free_header_t *) header_from_ptr(prev_ptr);
        ASSERT(TEST(CHUNK_FREED, prev->head.flags), "header flags inconsistent");
        ASSERT(prev->head.alloc_size == prev_sz, "prev size inconsistent");
        ASSERT(is_valid_chunk(prev_ptr, &prev->head), "prev chunk inconsistent");
        /* Synchronize with iterators (i#949) */
        iterator_lock(arena, true/*in alloc*/);
        /* We can't merge with a delayed free b/c we'd lose the callstack, so we
         * don't even set CHUNK_PREV_FREE (we don't have space anyway in a true-free
         * header to store prev_size_shr: so we can't store for a delay, and we rely
         * on always coalescing).
         */
        ASSERT(!TEST(CHUNK_DELAY_FREE, prev->head.flags), "prev free must be true free");
        /* Remove prev from free list and merge w/ head.  We'll add the
         * newly combined chunk to the delay list below.  Yes, this delays
         * re-use of the no-longer-delayed prev, but the size delay
         * threshold should prevent OOM.
         */
        remove_from_free_list(arena, prev, UINT_MAX);
        if (cur->head.user_data != NULL)
            client_malloc_data_free(cur->head.user_data);
        /* We don't want misleading data so we throw out prev as well */
        if (prev->head.user_data != NULL) {
            client_malloc_data_free(prev->head.user_data);
            prev->head.user_data = NULL;
        }
        tofree = &prev->head;
        tofree->alloc_size += cur->head.alloc_size + inter_chunk_space();
        iterator_unlock(arena, true/*in alloc*/);
        LOG(3, "coalescing with prev chunk "PFX" => "PFX"-"PFX"\n",
            prev, prev_ptr, prev_ptr + tofree->alloc_size);
        STATS_INC(num_coalesces);
        /* We can't call set_prev_size_field() here b/c it will assert if
         * next is free, so we wait until we've possibly merged w/ next
         */
        /* Let client fill/mark midpoint header, if desired */
        if (!alloc_ops.shared_redzones)
            client_new_redzone((byte *)cur, header_size);
    }
    next = next_chunk_forward(arena, tofree, NULL);
    if (next != NULL && TEST(CHUNK_FREED, next->flags) &&
        !TEST(CHUNK_DELAY_FREE, next->flags) ) {
        /* Synchronize with iterators (i#949) */
        iterator_lock(arena, true/*in alloc*/);
        /* Coalesce with next block */
        remove_from_free_list(arena, (free_header_t *)next, UINT_MAX);
        if (next->user_data != NULL)
            client_malloc_data_free(next->user_data);
        /* We don't want misleading data so we throw out cur as well */
        if (tofree->user_data != NULL) {
            client_malloc_data_free(tofree->user_data);
            tofree->user_data = NULL;
        }
        tofree->alloc_size += next->alloc_size + inter_chunk_space();
        LOG(3, "coalescing with next chunk "PFX" => "PFX"-"PFX"\n",
            next, ptr_from_header(tofree), ptr_from_header(tofree) +
            tofree->alloc_size);
        STATS_INC(num_coalesces);
        /* Let client fill/mark midpoint header, if desired */
        if (!alloc_ops.shared_redzones)
            client_new_redzone((byte *)next, header_size);
        set_prev_size_field(arena, tofree); /* update */
        iterator_unlock(arena, true/*in alloc*/);
    } else if (tofree != &cur->head) {
        /* Delayed from above: see comment in merge-prev */
        set_prev_size_field(arena, tofree); /* update */
    }
    return consider_giving_back_memory(arena, tofree);
}

static bool
shift_from_delay_list_to_free_list(arena_header_t *arena)
{
    free_header_t *cur = arena->free_list->delay_front;
    if (cur == NULL)
        return false;
    LOG(3, "%s: shifting "PFX" to regular free list\n", __FUNCTION__, cur);
    cur->head.flags &= ~CHUNK_DELAY_FREE;
    arena->free_list->delay_front = cur->next;
    if (cur == arena->free_list->delay_last)
        arena->free_list->delay_last = NULL;
    ASSERT(arena->free_list->delayed_chunks > 0, "delay counter off");
    arena->free_list->delayed_chunks--;
    ASSERT(arena->free_list->delayed_bytes >= cur->head.alloc_size,
           "delay bytes counter off");
    arena->free_list->delayed_bytes -= cur->head.alloc_size;
    LOG(3, "%s: updated delayed chunks=%d, bytes="PIFX"\n", __FUNCTION__,
        arena->free_list->delayed_chunks, arena->free_list->delayed_bytes);

    /* We coalesce here, rather than on initial free, b/c only now
     * can we throw away the user_data
     */
    cur = coalesce_adjacent_frees(arena, cur);
    if (cur != NULL) {
        set_prev_size_field(arena, &cur->head);
        add_to_free_list(arena, &cur->head);
        ASSERT(!TEST(CHUNK_PREV_FREE, cur->head.flags), "no adjacent frees");
        DOLOG(2, {
            chunk_header_t *next = next_chunk_forward(arena, &cur->head, NULL);
            ASSERT(next == NULL || TEST(CHUNK_PREV_FREE, next->flags),
                   "missing prev free pointer");
        });
    }
    return true;
}

static void
add_to_delay_list(arena_header_t *arena, chunk_header_t *head)
{
    free_header_t *cur = (free_header_t *) head;
    /* add to the end for delayed free FIFO */
    cur->next = NULL;
    head->flags |= CHUNK_DELAY_FREE;
    if (arena->free_list->delay_last == NULL) {
        ASSERT(arena->free_list->delay_front == NULL, "inconsistent free list");
        arena->free_list->delay_front = cur;
    } else
        arena->free_list->delay_last->next = cur;
    arena->free_list->delay_last = cur;

    arena->free_list->delayed_chunks++;
    arena->free_list->delayed_bytes += head->alloc_size;
    LOG(3, "%s: updated delayed chunks=%d, bytes="PIFX"\n", __FUNCTION__,
        arena->free_list->delayed_chunks, arena->free_list->delayed_bytes);

    while (arena_delayed_list_full(arena)) {
        /* Keep shifting first delayed entry to the free lists, until we're
         * below both thresholds.
         */
        if (!shift_from_delay_list_to_free_list(arena))
            break;
    }
}

static chunk_header_t *
search_free_list_bucket(arena_header_t *arena, heapsz_t aligned_size, uint bucket)
{
    /* search for large enough chunk */
    free_header_t *cur;
    chunk_header_t *head = NULL;
#ifdef UNIX
    /* On Windows we have HEAP_NO_SERIALIZE.  Not worth passing the flags in. */
    ASSERT(dr_recurlock_self_owns(arena->lock), "caller must hold lock");
#endif
    ASSERT(bucket < NUM_FREE_LISTS, "invalid param");
    for (cur = arena->free_list->front[bucket];
         cur != NULL && cur->head.alloc_size < aligned_size;
         cur = cur->next)
        ; /* nothing */
    if (cur != NULL) {
        remove_from_free_list(arena, cur, bucket);
        head = (chunk_header_t *) cur;
    }
    LOG(3, "arena "PFX" taking cur="PFX" => bucket %d free front="PFX" last="PFX"\n",
        arena, cur, bucket, arena->free_list->front[bucket],
        arena->free_list->last[bucket]);
    return head;
}

/* Caller needs only to point free_hdr at the right point: this routine will fill it in.
 */
static void
split_piece_for_free_list(arena_header_t *arena, chunk_header_t *head,
                          free_header_t *free_hdr, size_t free_sz,
                          size_t head_new_sz)
{
    free_header_t *coalesced;
    byte *free_ptr;
    /* Synchronize with iterators (i#949) */
    iterator_lock(arena, true/*in alloc*/);

    head->alloc_size = head_new_sz;

    free_hdr->head.user_data = client_malloc_data_free_split(head->user_data);
    free_hdr->head.u.unfree.request_diff = 0;
    free_hdr->head.alloc_size = free_sz;
    free_hdr->head.magic = HEADER_MAGIC;
    free_hdr->head.flags = head->flags | CHUNK_FREED;

    free_ptr = ptr_from_header(&free_hdr->head);
    LOG(3, "splitting off "PFX"-"PFX" (hdr "PFX") from "PFX"-"PFX" (hdr "PFX")\n",
        free_ptr, free_ptr+free_sz, free_hdr, ptr_from_header(head),
        ptr_from_header(head) + head->alloc_size, head);
    /* Let client fill/mark new redzones, if desired.
     * We currently have our next free ptr in the redzone:
     */
    client_new_redzone(free_ptr - alloc_ops.redzone_size, alloc_ops.redzone_size);
    if (!alloc_ops.shared_redzones) {
        client_new_redzone(free_ptr + free_sz, alloc_ops.redzone_size);
    }

    coalesced = coalesce_adjacent_frees(arena, free_hdr);
    if (coalesced != NULL) {
        set_prev_size_field(arena, (chunk_header_t *)coalesced);
        /* XXX: this adds it to the end, even though maybe it
         * should stay at the front for FIFO for the case where we split
         * it off a free list entry in the first place.
         */
        add_to_free_list(arena, (chunk_header_t *)coalesced);
    }
    iterator_unlock(arena, true/*in alloc*/);
}

static chunk_header_t *
find_free_list_entry(arena_header_t *arena, heapsz_t request_size, heapsz_t aligned_size)
{
    chunk_header_t *head = NULL;
    uint bucket;
#ifdef UNIX
    /* On Windows we have HEAP_NO_SERIALIZE.  Not worth passing the flags in. */
    ASSERT(dr_recurlock_self_owns(arena->lock), "caller must hold lock");
#endif

    /* b/c we're delaying, we're not able to re-use a just-freed chunk.
     * thus we go for time over space and use the guaranteed-size bucket
     * before searching the maybe-big-enough bucket.
     */
    for (bucket = 0;
         bucket < NUM_FREE_LISTS - 1 && aligned_size > free_list_sizes[bucket];
         bucket++)
        ; /* nothing */

    /* I tried searching the maybe-big-enough bucket (bucket - 1) before
     * going to bigger buckets but it's a huge time sink for some benchmarks
     * and doesn't seem to help much on others so I removed it.
     */

    /* Use a larger bucket to avoid delaying a ton of allocs of a
     * certain size and never re-using them for pathological app alloc
     * sequences.  I used to do this only when delayed frees were piling
     * up (delayed_chunks or delayed_bytes at 2x the threshold) but
     * it seems worth doing every time, even at the risk of fragmentation,
     * since we have coalescing in place.
     */
    if (head == NULL && arena->free_list->front[bucket] == NULL) {
        while (bucket < NUM_FREE_LISTS - 1 && arena->free_list->front[bucket] == NULL)
            bucket++;
    }

    if (head == NULL && arena->free_list->front[bucket] != NULL) {
        LOG(2, "\tallocating from larger bucket size to reduce delayed frees\n");
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
            else {
                free_header_t *cur = (free_header_t *) head;
                ASSERT(cur->next != NULL, "free list corrupted");
                cur->next->head.u.prev = NULL;
            }
            LOG(3, "arena "PFX" bucket %d taking "PFX" => free front="PFX" last="PFX"\n",
                arena, bucket, head, arena->free_list->front[bucket],
                arena->free_list->last[bucket]);
        }
    }

    if (head != NULL) {
        chunk_header_t *next;
        arena_header_t *container = NULL;
        LOG(2, "\tusing free list size=%d for request=%d align=%d from bucket %d\n",
            head->alloc_size, request_size, aligned_size, bucket);

        /* if there's a lot of extra room, split it off as a separate free entry */
        if (head->alloc_size > aligned_size + CHUNK_MIN_SIZE + inter_chunk_space()) {
            byte *split = ptr_from_header(head) + aligned_size +
                (alloc_ops.shared_redzones ? 0 : alloc_ops.redzone_size);
            size_t rest_size = head->alloc_size - (aligned_size + inter_chunk_space());
            byte *chunk2_start = split + inter_chunk_space() -
                (alloc_ops.shared_redzones ? 0 : alloc_ops.redzone_size);
            free_header_t *rest = (free_header_t *) header_from_ptr(chunk2_start);
            ASSERT(!TEST(CHUNK_MMAP, head->flags), "mmap not expected on free list");
            STATS_INC(num_splits);
            split_piece_for_free_list(arena, head, rest, rest_size, aligned_size);
            ASSERT(is_valid_chunk(chunk2_start, &rest->head), "rest chunk inconsistent");
        }

        if (head->user_data != NULL) {
            client_malloc_data_free(head->user_data);
            head->user_data = NULL;
        }
        head->flags &= ~(CHUNK_FREED | ALLOCATOR_TYPE_FLAGS);

        next = next_chunk_forward(arena, head, &container);
        if (next != NULL)
            next->flags &= ~CHUNK_PREV_FREE;
        else if (container != NULL)
            container->prev_free_sz = 0;
    }
    return head;
}

/* i#1581: to avoid retaddr local vars from callstack walks messing up app
 * callstacks, we invoke the 2nd layer on a clean dstack (this lets us keep
 * just the outer layer as stdcall, and avoids complicating drwrap further).
 */
#define ONDSTACK_REPLACE_ALLOC_COMMON(arena, sz, align, flags, dc, mc, \
                                      caller, alloc_type) \
    dr_call_on_clean_stack(dc, (void* (*)(void)) replace_alloc_common, arena, \
                           (void *)(ptr_uint_t)(sz), (void *)(ptr_uint_t)(align), \
                           (void *)(ptr_uint_t)(flags), \
                           dc, mc, caller, (void *)(ptr_uint_t)(alloc_type))

/* As noted in the flag definitions, ALLOC_INVOKE_CLIENT_* in flags
 * only applies to successful allocation: client is still notified on failure
 * and when client user data is freed or shifted.
 *
 * If invoked from an outer drwrap_replace_native() layer, this should be invoked
 * via ONDSTACK_REPLACE_ALLOC_COMMON().
 *
 * Pass 0 if no special alignment is needed.
 */
static byte *
replace_alloc_common(arena_header_t *arena, size_t request_size, size_t alignment,
                     alloc_flags_t flags, void *drcontext, dr_mcontext_t *mc,
                     app_pc caller, uint alloc_type)
{
    heapsz_t aligned_size;
    byte *res = NULL;
    chunk_header_t *head = NULL;
    ASSERT((alloc_type & ~(ALLOCATOR_TYPE_FLAGS)) == 0, "invalid type flags");

    if (request_size > UINT_MAX ||
        /* catch overflow in chunk or mmap alignment: no need to support really
         * large sizes within a page of UINT_MAX (i#944)
         */
        ALIGN_FORWARD(request_size, PAGE_SIZE) < request_size) {
        /* rather than have larger headers for 64-bit we just don't support
         * enormous allocations
         */
        client_handle_alloc_failure(request_size, caller, mc);
        return NULL;
    }

    /* alignment must be power of 2, or 0 (== default) */
    if (alignment != 0 && !IS_POWER_OF_2(alignment)) {
        client_handle_alloc_failure(request_size, caller, mc);
        return NULL;
    }
    if (alignment < CHUNK_ALIGNMENT)
        alignment = CHUNK_ALIGNMENT;

    aligned_size = ALIGN_FORWARD(request_size, CHUNK_ALIGNMENT);
    if (alignment > CHUNK_ALIGNMENT) {
        /* We brute-force and alloc enough space to ensure we can back the
         * pre-aligned-padding as a free slot, to avoid any complexity of
         * having pre-header padding.
         */
        aligned_size += alignment + CHUNK_MIN_SIZE + inter_chunk_space();
    }
    ASSERT(aligned_size >= request_size, "overflow should have been caught");
    if (aligned_size < CHUNK_MIN_SIZE)
        aligned_size = CHUNK_MIN_SIZE;

    arena_lock(drcontext, arena, TEST(ALLOC_SYNCHRONIZE, flags));

    /* for large requests we do direct mmap with own redzones.
     * we use the large malloc table to track them for iteration.
     * XXX: for simplicity, not delay-freeing these for now
     */
    if (aligned_size + header_size >= CHUNK_MIN_MMAP) {
        mmap_header_t *mhead;
        size_t map_size = (size_t)
            ALIGN_FORWARD(aligned_size + sizeof(mmap_header_t) +
                          alloc_ops.redzone_size*2 + header_beyond_redzone, PAGE_SIZE);
        byte *map = os_large_alloc(map_size _IF_WINDOWS(map_size)
                                   _IF_WINDOWS(arena_page_prot(arena->flags)));
        size_t dist_to_map;
        ASSERT(map_size >= aligned_size, "overflow should have been caught");
        LOG(2, "\tlarge alloc %d => mmap @"PFX"\n", request_size, map);
        if (map == NULL) {
            client_handle_alloc_failure(request_size, caller, mc);
            goto replace_alloc_common_done;
        }
        ASSERT(!alloc_ops.external_headers, "NYI");
        mhead = (mmap_header_t *) map;
        mhead->map_size = map_size;
        head = (chunk_header_t *)
            ((byte *)map + sizeof(mmap_header_t) + alloc_ops.redzone_size +
             header_beyond_redzone - redzone_beyond_header - header_size);
        res = ptr_from_header(head);
        if (!ALIGNED(res, alignment)) {
            res = (byte *) ALIGN_FORWARD(res, alignment);
            head = header_from_ptr(res);
        }
        dist_to_map = (byte *)head - map;
        if (dist_to_map > USHRT_MAX) {
            os_large_free(map, map_size);
            client_handle_alloc_failure(request_size, caller, mc);
            goto replace_alloc_common_done;
        }
        head->u.unfree.prev_size_shr = dist_to_map;
        mhead->head = head;
        head->flags |= CHUNK_MMAP;
        head->magic = HEADER_MAGIC;
        head->alloc_size = (map + map_size - alloc_ops.redzone_size - res);
        heap_region_add(map, map + map_size, HEAP_MMAP, mc);
    } else {
        /* look for free list entry */
        head = find_free_list_entry(arena, request_size, aligned_size);
        if (head != NULL) {
            malloc_info_t info;
            header_to_info(head, &info, NULL, 0);
            client_handle_free_reuse(drcontext, &info, mc);
        }
    }

    /* if no free list entry, get new memory */
    if (head == NULL) {
        heapsz_t add_size = aligned_size + inter_chunk_space();
        /* We deliberately walk every arena each time.  This helps use empty
         * space at the bottom that was too small for larger allocs that triggered
         * creating a new arena.  However, it is extra overhead, especially if
         * we ever end up with many arenas, where we should probably keep a pointer
         * to the last one around to avoid this walk.  But, even artificially
         * forcing allocs among 28 arenas on cfrac, the overhead isn't egregious,
         * so I'm sticking with this simple design for now.
         */
        arena_header_t *last_arena = arena;
        byte *orig_next_chunk;
        while (arena != NULL) {
            if (arena->next_chunk + add_size <= arena->commit_end)
                break;
            last_arena = arena;
            arena = arena->next_arena;
        }
        if (arena == NULL)
            arena = arena_extend(last_arena, add_size);
        if (arena == NULL) {  /* ignore ALLOC_INVOKE_CLIENT */
            /* i#1829: better to abandon the delayed frees (yes, all of them) to
             * avoid OOM in the app.  This is rare so we can afford the simple
             * solution of re-checking the free list after each shift, so we'll
             * be able to use a coalesced pair rather than searching the delay
             * list for a singleton that's large enough.
             */
            arena = last_arena;
            while (arena->free_list->delayed_bytes >= aligned_size) {
                if (!shift_from_delay_list_to_free_list(arena))
                    break;
                head = find_free_list_entry(arena, request_size, aligned_size);
                if (head != NULL)
                    break;
            }
            if (head == NULL) {
                client_handle_alloc_failure(request_size, caller, mc);
                goto replace_alloc_common_done;
            }
        }
        if (head == NULL) {
            /* remember that arena->next_chunk always has a redzone preceding it */
            head = (chunk_header_t *)
                (arena->next_chunk - redzone_beyond_header - header_size);
            head->alloc_size = aligned_size;
            head->magic = HEADER_MAGIC;
            head->user_data = NULL; /* b/c we pass the old to client */
            head->flags = 0;
            LOG(2, "\tcarving out new chunk @"PFX" => head="PFX", res="PFX"\n",
                arena->next_chunk - alloc_ops.redzone_size, head, ptr_from_header(head));
            orig_next_chunk = arena->next_chunk;
            arena->next_chunk += add_size;
            if (arena->prev_free_sz != 0) {
                /* There's a prior free, so we need to mark this new chunk with
                 * prev-free info.
                 */
                byte *prev_ptr = orig_next_chunk - inter_chunk_space() -
                    arena->prev_free_sz;
                chunk_header_t *prev = header_from_ptr(prev_ptr);
                ASSERT(is_valid_chunk(prev_ptr, prev), "arena prev free corrupted");
                ASSERT(TEST(CHUNK_FREED, prev->flags), "arena prev free inconsistent");
                set_prev_size_field(arena, prev);
                arena->prev_free_sz = 0;
            }
        }
    }

    /* head->alloc_size, head->magic, and head->flags (except type) are already set */
    ASSERT(head->magic == HEADER_MAGIC, "corrupted header");
    ASSERT(head->alloc_size - request_size <= REQUEST_DIFF_MAX,
           "illegally large chunk padding");
    head->u.unfree.request_diff = head->alloc_size - request_size;
    head->flags |= alloc_type;
    res = ptr_from_header(head);
    if (!ALIGNED(res, alignment)) {
        /* Place the pre-aligned padding onto the free list */
        chunk_header_t *orig = head;
        byte *orig_res = res;
        free_header_t *pre = (free_header_t *) head;
        size_t pre_sz;
        res += CHUNK_MIN_SIZE + inter_chunk_space();
        res = (byte *) ALIGN_FORWARD(res, alignment);
        head = header_from_ptr(res);
        *head = *orig;
        pre_sz = (byte *)head - (byte *)orig - inter_chunk_space();
        LOG(2, "\torig alloc %d bytes, shrinking by %d to align\n",
            head->alloc_size, res - orig_res);
        split_piece_for_free_list(arena, head, pre, pre_sz,
                                  head->alloc_size - (res - orig_res));
        ASSERT(head->alloc_size > request_size, "pre-align miscalculation");
        head->u.unfree.request_diff = head->alloc_size - request_size;
    }
    LOG(2, "\treplace_alloc_common arena="PFX" flags=0x%x request=%d, align=%d alloc=%d "
        "=> "PFX"\n", arena, head->flags,
        chunk_request_size(head), alignment, head->alloc_size, res);
    if (TEST(ALLOC_ZERO, flags))
        memset(res, 0, request_size);

    ASSERT(head->alloc_size >= request_size, "chunk too small");

    notify_client_alloc(drcontext, (byte *)res, head, flags, mc, caller);

    if (chunk_request_size(head) >= LARGE_MALLOC_MIN_SIZE)
        malloc_large_add(res, request_size);
    else
        STATS_INC(num_mallocs);

 replace_alloc_common_done:
    arena_unlock(drcontext, arena, TEST(ALLOC_SYNCHRONIZE, flags));

    return res;
}

static void
check_type_match(void *ptr, chunk_header_t *head, uint free_type,
                 alloc_flags_t flags, dr_mcontext_t *mc, app_pc caller)
{
    uint alloc_main_type = (head->flags & MALLOC_ALLOCATOR_FLAGS);
    uint free_main_type = (free_type & MALLOC_ALLOCATOR_FLAGS);
    const char *action = (TEST(ALLOC_IS_REALLOC, flags) ? "realloc" :
                          (TEST(ALLOC_IS_QUERY, flags) ? "queried" : "freed"));
    if (TEST(ALLOC_IGNORE_MISMATCH, flags))
        return;
    LOG(3, "\tcheck_type_match: alloc flags=0x%x vs free=0x%x\n",
        head->flags, free_type);
    ASSERT((free_type & ~(ALLOCATOR_TYPE_FLAGS)) == 0, "invalid type flags");
    if ((alloc_main_type != MALLOC_ALLOCATOR_UNKNOWN &&
         free_main_type != MALLOC_ALLOCATOR_UNKNOWN) &&
        alloc_main_type != free_main_type) {
        /* i#1533: ensure we're not in a private std::_DebugHeapDelete that we missed
         * up front.  We want the app caller, so the caller of our "caller" here
         * (which is our replace_* routine).
         */
        app_pc app_caller = callstack_next_retaddr(mc);
        if (!check_for_private_debug_delete(app_caller)) {
            client_mismatched_heap(caller, (byte *)ptr, mc,
                                   malloc_alloc_type_name(alloc_main_type),
                                   malloc_free_type_name(free_main_type), action,
                                   head->user_data, true/*C vs C++*/);
        }
    }
#ifdef WINDOWS
    /* For pre-us we don't know whether Rtl or libc layer */
    else if (!TEST(CHUNK_PRE_US, head->flags) &&
             (free_type & CHUNK_LAYER_RTL) != (head->flags & CHUNK_LAYER_RTL) &&
             !TEST(CHUNK_LAYER_NOCHECK, free_type | head->flags)) {
        /* i#1197: report libc/Rtl mismatches */
        client_mismatched_heap(caller, (byte *)ptr, mc,
                               malloc_layer_name(head->flags),
                               malloc_layer_name(free_type), action,
                               head->user_data, false/*!C vs C++*/);
    }
#endif
}

/* See i#1581 notes above.
 * Unfortunately we can't easily cast to the bool return type (from void*) here
 * as gcc then complains about the calls that ignore the return value: so each
 * caller who needs the return value must cast.
 */
#define ONDSTACK_REPLACE_FREE_COMMON(arena, ptr, flags, dc, mc, caller, free_type) \
    dr_call_on_clean_stack(dc, (void* (*)(void)) replace_free_common, arena, ptr,  \
                           (void *)(ptr_uint_t)(flags), dc, mc, caller,            \
                           (void *)(ptr_uint_t)(free_type), NULL)

/* Up to caller to verify that ptr is inside arena.
 * invoke_client controls whether client_handle_free() is called.
 *
 * If invoked from an outer drwrap_replace_native() layer, this should be invoked
 * via ONDSTACK_REPLACE_FREE_COMMON().
 */
static bool
replace_free_common(arena_header_t *arena, void *ptr, alloc_flags_t flags,
                    void *drcontext, dr_mcontext_t *mc, app_pc caller, uint free_type)
{
    chunk_header_t *head = header_from_ptr(ptr);
    malloc_info_t info;

    if (!is_live_alloc(ptr, arena, head)) { /* including NULL */
        /* w/o early inject, or w/ delayed instru, there are allocs in place
         * before we took over
         */
        head = hashtable_lookup(&pre_us_table, (void *)ptr);
        if (head != NULL && !TEST(CHUNK_FREED, head->flags)) {
            /* XXX i#1195: need to call the app's free routine.
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
            bool identified = false;
            bool valid = false;
            if (p != NULL) {
                const size_t slot_sz = sizeof(size_t);
                /* try one slot back, in case this is an array w/ size passed to delete */
                head = header_from_ptr(p - slot_sz);
                if (is_live_alloc(p - slot_sz, arena, head)) {
                    check_type_match(p - slot_sz, head, free_type,
                                     flags, mc, caller);
                    identified = true;
                }
                if (!identified) {
                    /* try one slot in, in case this is a non-array passed to delete[] */
                    head = header_from_ptr(p + slot_sz);
                    if (is_live_alloc(p + slot_sz, arena, head)) {
                        check_type_match(p + slot_sz, head, free_type,
                                         flags, mc, caller);
                        identified = true;
                    }
                }
            }
#ifdef WINDOWS
            if (!identified && (ptr_uint_t)p > DBGCRT_PRE_REDZONE_SIZE) {
                /* i#607 part A: debug CRT code sometimes allocates via an internal
                 * routine like _calloc_dbg_impl() which adds a redzone and
                 * calls RtlAllocateHeap; the same object is later freed by
                 * passing the inside-redzone pointer to free().
                 * With symbols, we simply intercept the internal routine;
                 * without, it's too complex to try and retroactively add our redzone
                 * instead of the CRT redzone and skip over some callers, so we
                 * live w/o our own redzone for this handful of allocs and simply
                 * try to avoid reporting invalid args on the free (the Rtl
                 * vs libc layer mismatch, which happens w/ release CRT too,
                 * is suppressed as part of i#960).
                 * But, this no longer happens with DR > r1728+ (it was an FLS
                 * transparency bug that caused _getptd_noexit() to call
                 * _calloc_dbg_impl(): and it's the only code I see that does so!).
                 */
                head = header_from_ptr(p - DBGCRT_PRE_REDZONE_SIZE);
                if (is_live_alloc(p - DBGCRT_PRE_REDZONE_SIZE, arena, head) &&
                    chunk_request_size(head) > DBGCRT_PRE_REDZONE_SIZE +
                    DBGCRT_POST_REDZONE_SIZE) {
                    identified = true;
                    valid = true;
                    ptr = (void *) (p - DBGCRT_PRE_REDZONE_SIZE);
                    LOG(2, "inner-redzone pointer "PFX" => real alloc "PFX"\n", p, ptr);
                    STATS_INC(dbgcrt_mismatch);
                }
            }
#endif
            if (!valid) { /* call regardless of ALLOC_INVOKE_CLIENT */
                client_invalid_heap_arg(caller, (byte *)ptr, mc,
                                        /* XXX: we might be replacing RtlHeapFree or
                                         * _free_dbg but it's not worth trying to
                                         * store the exact name
                                         */
                                        "free", true/*free*/);
                return false;
            }
        }
    }

    arena_lock(drcontext, arena, TEST(ALLOC_SYNCHRONIZE, flags));

    check_type_match(ptr, head, free_type, flags, mc, caller);

    /* current model is to throw the data away when we put on free list.
     * would we ever want to keep the alloc callstack for freed entries,
     * or we always want to replace w/ free callstack?
     */
    header_to_info(head, &info, NULL, 0);
    if (TEST(ALLOC_INVOKE_CLIENT_DATA, flags))
        client_remove_malloc_pre(&info);
    if (TESTANY(CHUNK_MMAP | CHUNK_PRE_US, head->flags)) {
        if (head->user_data != NULL)
            client_malloc_data_free(head->user_data); /* ignores ALLOC_INVOKE_CLIENT */
        head->user_data = NULL;
    } else
        head->user_data = client_malloc_data_to_free_list(head->user_data, mc, caller);

    /* Mark this after client_remove_malloc_pre so client can iterate
     * and see the alloc as currently-live, matching wrapping behavior.
     */
    head->flags |= CHUNK_FREED; /* even if CHUNK_MMAP, so a client iter will skip */

    if (TEST(ALLOC_INVOKE_CLIENT_DATA, flags))
        client_remove_malloc_post(&info);
    if (TEST(ALLOC_INVOKE_CLIENT_ACTION, flags)) {
        /* we ignore the return value */
        client_handle_free(&info, (byte *)ptr, mc, caller, NULL,
                           false/*reuse delayed*/ _IF_WINDOWS(NULL));
    }

    if (chunk_request_size(head) >= LARGE_MALLOC_MIN_SIZE &&
        !TEST(CHUNK_PRE_US, head->flags))
        malloc_large_remove(ptr);

    if (!TESTANY(CHUNK_MMAP | CHUNK_PRE_US, head->flags)) {
        LOG(2, "\treplace_free_common "PFX" == request=%d, alloc=%d, arena="PFX"\n",
            ptr, chunk_request_size(head), head->alloc_size, arena);
        add_to_delay_list(arena, head);
        /* At this point head may be invalid to de-ref, if coalesced or freed (this
         * will only happen if -delay_frees is 0)
         */
    } else if (TEST(CHUNK_MMAP, head->flags)) {
        /* see comments in alloc routine about not delaying the free */
        byte *map = (byte *)head - head->u.unfree.prev_size_shr;
        mmap_header_t *mhead = (mmap_header_t *) map;
        size_t map_size = mhead->map_size;
        ASSERT(mhead->head == head, "mmap header corrupted");
        LOG(2, "\tlarge alloc %d freed => munmap @"PFX"\n", chunk_request_size(head), map);
        heap_region_remove(map, map + map_size, mc);
        if (!os_large_free(map, map_size))
            ASSERT(false, "munmap failed");
    }

    STATS_INC(num_frees);

    arena_unlock(drcontext, arena, TEST(ALLOC_SYNCHRONIZE, flags));
    return true;
}

/* See i#1581 notes above */
#define ONDSTACK_REPLACE_REALLOC_COMMON(arena, ptr, size, flags, dc, mc, caller, type) \
    dr_call_on_clean_stack(dc, (void* (*)(void)) replace_realloc_common, arena, ptr,   \
                           (void *)(ptr_uint_t)(size), (void *)(ptr_uint_t)(flags), \
                           dc, mc, caller, (void *)(ptr_uint_t)(type))

/* If invoked from an outer drwrap_replace_native() layer, this should be invoked
 * via ONDSTACK_REPLACE_REALLOC_COMMON().
 */
static byte *
replace_realloc_common(arena_header_t *arena, byte *ptr, size_t size,
                       alloc_flags_t flags, void *drcontext, dr_mcontext_t *mc,
                       app_pc caller, uint alloc_type)
{
    byte *res = NULL;
    chunk_header_t *head = header_from_ptr(ptr);
    malloc_info_t old_info;
    malloc_info_t new_info;
    alloc_flags_t sub_flags = flags;
    LOG(2, "  %s: "PFX" %d bytes arena="PFX"\n", __FUNCTION__, ptr, size, arena);
    if (ptr == NULL) {
        if (TEST(ALLOC_ALLOW_NULL, flags)) {
            client_handle_realloc_null(caller, mc);
            res = (void *) replace_alloc_common(arena, size, 0,
                                                flags | ALLOC_IS_REALLOC |
                                                ALLOC_INVOKE_CLIENT,
                                                drcontext, mc, caller, alloc_type);
        } else {
            client_handle_alloc_failure(size, caller, mc);
            res = NULL;
        }
        return res;
    } else if (size == 0 && !TEST(ALLOC_ALLOW_EMPTY, flags)) {
        replace_free_common(arena, ptr,
                            flags | ALLOC_IS_REALLOC | ALLOC_INVOKE_CLIENT,
                            drcontext, mc, caller, alloc_type);
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
    arena_lock(drcontext, arena, TEST(ALLOC_SYNCHRONIZE, flags));
    sub_flags &= ~ALLOC_SYNCHRONIZE; /* sub-calls don't need synch */
    ASSERT(head != NULL, "should return before here");
#ifdef WINDOWS
    check_type_match(ptr, head, alloc_type, flags, mc, caller);
#endif
    header_to_info(head, &old_info, ptr, 0);
    if (head->alloc_size >= size &&
        head->alloc_size - size <= REQUEST_DIFF_MAX &&
        !TEST(CHUNK_PRE_US, head->flags)) {
        LOG(2, "\t%s: in-place realloc from %d to %d bytes\n", __FUNCTION__,
            chunk_request_size(head), size);
        /* XXX: if shrinking a lot, should free and re-malloc, or split, to save space */
        if (chunk_request_size(head) >= LARGE_MALLOC_MIN_SIZE)
            malloc_large_remove(ptr);
        if (chunk_request_size(head) < size && TEST(ALLOC_ZERO, flags))
            memset(ptr + chunk_request_size(head), 0, size - chunk_request_size(head));
        head->u.unfree.request_diff = head->alloc_size - size;
        if (chunk_request_size(head) >= LARGE_MALLOC_MIN_SIZE)
            malloc_large_add(ptr, chunk_request_size(head));
        res = ptr;
        header_to_info(head, &new_info, NULL, flags | ALLOC_IS_REALLOC);
        client_handle_realloc(drcontext, &old_info, &new_info, false, mc);
    } else if (!TEST(ALLOC_IN_PLACE_ONLY, flags) || head->alloc_size >= size) {
        size_t old_request_size = chunk_request_size(head);
        bool was_mmap = TEST(CHUNK_MMAP, head->flags);
        LOG(2, "\t%s: malloc-and-free realloc from %d to %d bytes\n", __FUNCTION__,
            old_request_size, size);
        /* XXX: use mremap for mmapped alloc! */
        /* XXX: if final chunk in arena, extend in-place */
        res = (void *) replace_alloc_common(arena, size, 0,
                                            sub_flags | ALLOC_IS_REALLOC /*no client*/,
                                            drcontext, mc, caller, alloc_type);
        if (res != NULL) {
            head = header_from_ptr(res);
            memcpy(res, ptr, MIN(size, old_request_size));
            /* Prevent client iteration in client_remove_malloc_{pre,post} from
             * seeing the new alloc and complaining that it has not yet had
             * client_add_malloc_{pre,post} called on it yet.
             */
            head->flags |= CHUNK_SKIP_ITER;
            replace_free_common(arena, ptr,
                                sub_flags | ALLOC_IS_REALLOC |
                                /* we do want client_remove_malloc_{pre,post} as they
                                 * must be called around the actual free -- but
                                 * no client_handle_free()
                                 */
                                ALLOC_INVOKE_CLIENT_DATA /* not _ACTION */ |
                                ALLOC_IGNORE_MISMATCH,
                                drcontext, mc, caller, alloc_type);
            head->flags &= ~CHUNK_SKIP_ITER;
            header_to_info(head, &new_info, NULL, flags | ALLOC_IS_REALLOC);
            /* We delay client_add_malloc_{pre,post} until here, to avoid a client
             * iterating inside the event and seeing both the new and old allocs!
             */
            notify_client_alloc(drcontext, (byte *)res, head,
                                flags | ALLOC_IS_REALLOC | ALLOC_INVOKE_CLIENT_DATA,
                                mc, caller);
            client_handle_realloc(drcontext, &old_info, &new_info, was_mmap, mc);
        }
    }
    arena_unlock(drcontext, arena, TEST(ALLOC_SYNCHRONIZE, flags));
    return res;
}

/* Returns -1 on failure.
 * We don't bother to swap stacks here as we do not expect to walk the
 * callstack.
 */
static size_t
replace_size_common(arena_header_t *arena, byte *ptr, alloc_flags_t flags,
                    void *drcontext, dr_mcontext_t *mc, app_pc caller,
                    uint alloc_type)
{
    chunk_header_t *head = header_from_ptr(ptr);
    size_t res;
    LOG(2, "%s: "PFX", flags 0x%x, arena "PFX"\n", __FUNCTION__, ptr, flags, arena);
    arena_lock(drcontext, arena, TEST(ALLOC_SYNCHRONIZE, flags));
    if (!is_live_alloc(ptr, arena, head)) {
        /* w/o early inject, or w/ delayed instru, there are allocs in place
         * before we took over
         */
        head = hashtable_lookup(&pre_us_table, (void *)ptr);
        if (head == NULL || TEST(CHUNK_FREED, head->flags)) {
            client_invalid_heap_arg(caller, (byte *)ptr, mc,
                                    IF_WINDOWS_ELSE("_msize", "malloc_usable_size"),
                                    false/*!free*/);
            arena_unlock(drcontext, arena, TEST(ALLOC_SYNCHRONIZE, flags));
            return (size_t)-1;
        }
    }
#ifdef WINDOWS
    check_type_match(ptr, head,
                     /* i#1207: malloc_usable_size() on operator new memory
                      * should not be an error.  We only want to check for Rtl
                      * vs libc mismatches.
                      */
                     MALLOC_ALLOCATOR_UNKNOWN |
                     (TEST(CHUNK_LAYER_RTL, alloc_type) ? CHUNK_LAYER_RTL : 0),
                     flags | ALLOC_IS_QUERY, mc, caller);
#endif
    res = chunk_request_size(head); /* we do not allow using padding */
    arena_unlock(drcontext, arena, TEST(ALLOC_SYNCHRONIZE, flags));
    return res;
}

#if defined(WINDOWS) || defined(MACOS)
/* Caller should hold any required locks, though we are probably assuming
 * no synch is needed here.
 */
static void
destroy_arena_family(arena_header_t *arena, dr_mcontext_t *mc, bool free_chunks,
                     app_pc caller)
{
    arena_header_t *a, *next_a;
    chunk_header_t *head;
    malloc_info_t info;
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
                    header_to_info(head, &info, NULL, 0);
                    client_remove_malloc_pre(&info);
                    client_remove_malloc_post(&info);
                    if (head->user_data != NULL)
                        client_malloc_data_free(head->user_data);
                    client_handle_free(&info, info.base, mc, caller, NULL,
                                       true/*not delayed*/ _IF_WINDOWS((HANDLE)arena));
                }
                cur += head->alloc_size + inter_chunk_space();
            }
        }
        heap_region_remove((byte *)a, a->reserve_end, mc);
        arena_free(a);
    }
}
#endif

/***************************************************************************
 * iterator
 */

typedef struct _alloc_iter_data_t {
    bool only_live;
    malloc_iter_cb_t cb;
    void *data;
} alloc_iter_data_t;

static inline bool
skip_chunk_in_iter(alloc_iter_data_t *data, chunk_header_t *head)
{
    return (data->only_live && TEST(CHUNK_FREED, head->flags)) ||
        TEST(CHUNK_SKIP_ITER, head->flags);
}

static bool
alloc_iter_own_arena(byte *iter_arena_start, byte *iter_arena_end, uint flags
                     _IF_WINDOWS(HANDLE heap), void *iter_data)
{
    alloc_iter_data_t *data = (alloc_iter_data_t *) iter_data;
    chunk_header_t *head;
    byte *cur;
    arena_header_t *arena = (arena_header_t *) iter_arena_start;
    malloc_info_t info;

    /* We use the HEAP_MMAP flag to find our mmapped chunks.  We can't easily
     * use the large malloc tree b/c it has pre_us allocs too (i#1051).
     */
    /* We rely on the heap region lock to avoid races accessing this */
    if (TEST(HEAP_MMAP, flags)) {
        chunk_header_t *head = header_from_mmap_base(iter_arena_start);
        if (!skip_chunk_in_iter(data, head)) {
            header_to_info(head, &info, NULL, 0);
            ASSERT(TEST(CHUNK_MMAP, head->flags), "mmap chunk inconsistent");
            LOG(2, "%s: "PFX"-"PFX"\n", __FUNCTION__, info.base,
                info.base + chunk_request_size(head));
            if (!data->cb(&info, data->data))
                return false;
        }
    }

    if (TEST(HEAP_PRE_US, flags) || !TEST(HEAP_ARENA, flags))
        return true;

    LOG(2, "%s: "PFX"-"PFX"\n", __FUNCTION__, iter_arena_start, iter_arena_end);
    /* Synchronize with splits or coalesces (i#949) */
    iterator_lock(arena, false/*!in alloc*/);
    cur = arena->start_chunk;
    while (cur < arena->next_chunk) {
        head = header_from_ptr(cur);
        LOG(3, "\tchunk %s "PFX"-"PFX"\n", TEST(CHUNK_FREED, head->flags) ? "freed" : "",
            ptr_from_header(head), ptr_from_header(head) + head->alloc_size);
        if (!skip_chunk_in_iter(data, head)) {
            header_to_info(head, &info, NULL, 0);
            if (!data->cb(&info, data->data)) {
                iterator_unlock(arena, false/*!in alloc*/);
                return false;
            }
        }
        cur += head->alloc_size + inter_chunk_space();
    }
    iterator_unlock(arena, false/*!in alloc*/);
    return true;
}

/* This will end up grabbing DR locks (iterator_lock()) but that's fine even
 * in an app context, as it's not while we're marked safe-to-suspend and
 * it's only in our own code.
 */
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
    malloc_info_t info;

    LOG(2, "%s\n", __FUNCTION__);

    ASSERT(!alloc_ops.external_headers, "NYI: walk malloc table");

    LOG(3, "%s: iterating heap regions\n", __FUNCTION__);
    heap_region_iterate(alloc_iter_own_arena, &data);

    LOG(3, "%s: iterating pre-us allocs\n", __FUNCTION__);
    /* XXX: should add hashtable_iterate() to drcontainers */
    /* See notes at top: this table is only modified at init or teardown
     * and thus needs no external lock.
     */
    for (i = 0; i < HASHTABLE_SIZE(pre_us_table.table_bits); i++) {
        hash_entry_t *he;
        for (he = pre_us_table.table[i]; he != NULL; he = he->next) {
            chunk_header_t *head = (chunk_header_t *) he->payload;
            byte *start = he->key;
            if (!skip_chunk_in_iter(&data, head)) {
                LOG(3, "\tpre-us "PFX"-"PFX"-"PFX"\n",
                    start, start + chunk_request_size(head), start + head->alloc_size);
                header_to_info(head, &info, start, 0);
                if (!cb(&info, iter_data))
                    break;
            }
        }
    }
}

static bool
overlap_helper(chunk_header_t *head,
               malloc_info_t *info INOUT,
               uint positive_flags,
               uint negative_flags)
{
    /* XXX: this is the one INOUT case of this structure.  Once we extend it,
     * we need to handle back-compat struct size here.  For now, header_to_info()
     * is used here and by above internal code that doesn't set struct-size.
     */
    if (info->struct_size != sizeof(*info))
        ASSERT(false, "size is wrong");
    LOG(4, "overlap_helper for "PFX": 0x%x vs pos=0x%x neg=0x%x\n",
        ptr_from_header(head), head->flags, positive_flags, negative_flags);
    if (TESTALL(positive_flags, head->flags) &&
        !TEST(negative_flags, head->flags)) {
        LOG(4, "overlap_helper match for "PFX"\n", ptr_from_header(head));
        if (info != NULL)
            header_to_info(head, info, NULL, 0);
        return true;
    }
    return false;
}

/* Considers alloc_size to overlap, but returns request size in *found_end */
static bool
alloc_replace_overlaps_region(byte *start, byte *end,
                              malloc_info_t *info INOUT,
                              uint positive_flags,
                              uint negative_flags)
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
    bool found = false;
    byte *found_arena_start, *found_arena_end;
    uint flags;
    size_t size;
    LOG(4, "%s: looking for "PFX"-"PFX"\n", __FUNCTION__, start, end);
    if (malloc_large_lookup(start, &found_arena_start, &size)) {
        /* XXX: potentially racy!  Would need to find the containing
         * arena and grab its lock to safely access the header.
         */
        chunk_header_t *head = header_from_ptr(found_arena_start);
        found = overlap_helper(head, info, positive_flags, negative_flags);
        ASSERT(size == chunk_request_size(head), "inconsistent");
    } else if (heap_region_bounds(start, &found_arena_start, &found_arena_end, &flags)) {
        if (TEST(HEAP_PRE_US, flags)) {
            /* walk pre-us table.
             * See notes at top: this table is only modified at init or teardown
             * and thus needs no external lock.
             */
            uint i;
            for (i = 0; i < HASHTABLE_SIZE(pre_us_table.table_bits); i++) {
                hash_entry_t *he;
                for (he = pre_us_table.table[i]; he != NULL; he = he->next) {
                    chunk_header_t *head = (chunk_header_t *) he->payload;
                    byte *chunk_start = he->key;
                    if (start < chunk_start + head->alloc_size && end >= chunk_start) {
                        found = overlap_helper(head, info,
                                               positive_flags, negative_flags);
                        goto overlap_inner_loop_break;
                    }
                }
            }
        overlap_inner_loop_break:
            ; /* nothing */
        } else if (TEST(HEAP_ARENA, flags)) {
            /* walk arena */
            /* XXX: make a shared internal iterator for this? */
            arena_header_t *arena = (arena_header_t *) found_arena_start;
            byte *cur = arena->start_chunk;
            ASSERT(!alloc_ops.external_headers, "NYI: walk malloc table");
            /* Synchronize with splits or coalesces (i#949) */
            iterator_lock(arena, false/*!in alloc*/);
            while (cur < arena->next_chunk) {
                byte *chunk_start;
                chunk_header_t *head = header_from_ptr(cur);
                chunk_start = ptr_from_header(head);
                /* Check vs alloc_size + redzones.  Even if we've coalesced, or
                 * if beyond requested size, still considered to overlap freed
                 * area.  Don't check vs inter_chunk_space: callers don't want a
                 * match if beyond redzone.
                 */
                LOG(4, "\tchunk "PFX"-"PFX"\n", chunk_start,
                    chunk_start + head->alloc_size);
                if (start < chunk_start + head->alloc_size + alloc_ops.redzone_size &&
                    end >= chunk_start - alloc_ops.redzone_size) {
                    found = overlap_helper(head, info, positive_flags, negative_flags);
                    break;
                }
                cur += head->alloc_size + inter_chunk_space();
            }
            iterator_unlock(arena, false/*!in alloc*/);
        } else if (TEST(HEAP_MMAP, flags)) {
            /* i#1210: the large malloc tree stores only the requested size, so
             * a padding-size overlap will end up here.
             */
            chunk_header_t *head = header_from_mmap_base(found_arena_start);
            found = overlap_helper(head, info, positive_flags, negative_flags);
        } else
            ASSERT(false, "large lookup should have found it");
    }
    return found;
}

bool
alloc_replace_overlaps_delayed_free(byte *start, byte *end,
                                    malloc_info_t *info OUT)
{
    return alloc_replace_overlaps_region(start, end, info, CHUNK_DELAY_FREE, 0);
}

bool
alloc_replace_overlaps_any_free(byte *start, byte *end,
                                malloc_info_t *info OUT)
{
    return alloc_replace_overlaps_region(start, end, info, CHUNK_FREED, 0);
}

bool
alloc_replace_overlaps_malloc(byte *start, byte *end,
                              malloc_info_t *info OUT)
{
    return alloc_replace_overlaps_region(start, end, info, 0, CHUNK_FREED);
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
    ASSERT(arena != NULL &&
           (arena == cur_arena || TEST(ARENA_LIBC_DEFAULT, arena->flags)),
           "invalid per-set arena");
    if (TEST(ARENA_LIBC_SPECULATIVE, arena->flags)) {
        arena->flags &= ~ARENA_LIBC_SPECULATIVE;
        if (arena != cur_arena)
            arena = check_libc_vs_process_heap(e, arena);
    }
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
    res = ONDSTACK_REPLACE_ALLOC_COMMON(arena, size, 0,
                                        ALLOC_SYNCHRONIZE | ALLOC_INVOKE_CLIENT,
                                        drcontext, &mc, (app_pc)replace_malloc,
                                        MALLOC_ALLOCATOR_MALLOC);
    LOG(2, "\treplace_malloc %d => "PFX"\n", size, res);
    exit_client_code(drcontext, false/*need swap*/);
    return res;
}

/* Unfortunately there's no easy way to share code here.  We do not want an
 * extra frame.  We could use macros.
 */
static void *
replace_malloc_nomatch(size_t size)
{
    void *res;
    void *drcontext = enter_client_code();
    arena_header_t *arena = arena_for_libc_alloc(drcontext);
    dr_mcontext_t mc;
    INITIALIZE_MCONTEXT_FOR_REPORT(&mc);
    LOG(2, "replace_malloc (nomatch) %d\n", size);
    res = ONDSTACK_REPLACE_ALLOC_COMMON(arena, size, 0,
                                        ALLOC_SYNCHRONIZE | ALLOC_INVOKE_CLIENT,
                                        drcontext, &mc,
                                        (app_pc)replace_malloc/*avoid confusion*/,
                                        MALLOC_ALLOCATOR_MALLOC | CHUNK_LAYER_NOCHECK);
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
    if (unsigned_multiply_will_overflow(nmemb, size)) {
        LOG(2, "calloc size will overflow => returning NULL\n");
        client_handle_alloc_failure(UINT_MAX, (app_pc)replace_calloc, &mc);
        res = NULL;
    } else {
        res = ONDSTACK_REPLACE_ALLOC_COMMON
            (arena, nmemb * size, 0,
             ALLOC_SYNCHRONIZE | ALLOC_ZERO | ALLOC_INVOKE_CLIENT,
             drcontext, &mc, (app_pc)replace_calloc,
             MALLOC_ALLOCATOR_MALLOC);
    }
    LOG(2, "\treplace_calloc %d %d => "PFX"\n", nmemb, size, res);
    exit_client_code(drcontext, false/*need swap*/);
    return (void *) res;
}

/* See comment on replace_malloc_nomatch about sharing code */
static void *
replace_calloc_nomatch(size_t nmemb, size_t size)
{
    void *drcontext = enter_client_code();
    arena_header_t *arena = arena_for_libc_alloc(drcontext);
    byte *res;
    dr_mcontext_t mc;
    INITIALIZE_MCONTEXT_FOR_REPORT(&mc);
    LOG(2, "replace_calloc %d %d\n", nmemb, size);
    if (unsigned_multiply_will_overflow(nmemb, size)) {
        LOG(2, "calloc size will overflow => returning NULL\n");
        client_handle_alloc_failure(UINT_MAX, (app_pc)replace_calloc, &mc);
        res = NULL;
    } else {
        res = ONDSTACK_REPLACE_ALLOC_COMMON
            (arena, nmemb * size, 0,
             ALLOC_SYNCHRONIZE | ALLOC_ZERO | ALLOC_INVOKE_CLIENT,
             drcontext, &mc,
             (app_pc)replace_calloc/*avoid confusion*/,
             MALLOC_ALLOCATOR_MALLOC | CHUNK_LAYER_NOCHECK);
    }
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
    res = ONDSTACK_REPLACE_REALLOC_COMMON(arena, ptr, size,
                                          ALLOC_SYNCHRONIZE | ALLOC_ALLOW_NULL,
                                          drcontext, &mc, (app_pc)replace_realloc,
                                          MALLOC_ALLOCATOR_MALLOC);
    LOG(2, "\treplace_realloc %d => "PFX"\n", size, res);
    exit_client_code(drcontext, false/*need swap*/);
    return res;
}

/* See comment on replace_malloc_nomatch about sharing code */
static void *
replace_realloc_nomatch(void *ptr, size_t size)
{
    void *drcontext = enter_client_code();
    arena_header_t *arena = arena_for_libc_alloc(drcontext);
    void *res = NULL;
    dr_mcontext_t mc;
    INITIALIZE_MCONTEXT_FOR_REPORT(&mc);
    LOG(2, "replace_realloc "PFX" %d\n", ptr, size);
    res = ONDSTACK_REPLACE_REALLOC_COMMON(arena, ptr, size,
                                          ALLOC_SYNCHRONIZE | ALLOC_ALLOW_NULL,
                                          drcontext, &mc,
                                          (app_pc)replace_realloc/*avoid confusion*/,
                                          MALLOC_ALLOCATOR_MALLOC | CHUNK_LAYER_NOCHECK);
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
    ONDSTACK_REPLACE_FREE_COMMON(arena, ptr, ALLOC_SYNCHRONIZE | ALLOC_INVOKE_CLIENT,
                                 drcontext, &mc, (app_pc)replace_free,
                                 MALLOC_ALLOCATOR_MALLOC);
    exit_client_code(drcontext, false/*need swap*/);
}

/* See comment on replace_malloc_nomatch about sharing code */
static void
replace_free_nomatch(void *ptr)
{
    void *drcontext = enter_client_code();
    arena_header_t *arena = arena_for_libc_alloc(drcontext);
    dr_mcontext_t mc;
    INITIALIZE_MCONTEXT_FOR_REPORT(&mc);
    LOG(2, "replace_free "PFX"\n", ptr);
    ONDSTACK_REPLACE_FREE_COMMON(arena, ptr, ALLOC_SYNCHRONIZE | ALLOC_INVOKE_CLIENT,
                                 drcontext, &mc,
                                 (app_pc)replace_free/*deliberate: avoid confusion*/,
                                 MALLOC_ALLOCATOR_MALLOC | CHUNK_LAYER_NOCHECK);
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
    res = replace_size_common(arena, ptr, ALLOC_SYNCHRONIZE, drcontext, &mc,
                              (app_pc)replace_malloc_usable_size,
                              MALLOC_ALLOCATOR_MALLOC);
    if (res == (size_t)-1)
        res = 0; /* 0 on failure */
    LOG(2, "\treplace_malloc_usable_size "PFX" => "PIFX"\n", ptr, res);
    exit_client_code(drcontext, false/*need swap*/);
    return res;
}

/* See comment on replace_malloc_nomatch about sharing code */
static size_t
replace_malloc_usable_size_nomatch(void *ptr)
{
    void *drcontext = enter_client_code();
    size_t res;
    arena_header_t *arena = arena_for_libc_alloc(drcontext);
    dr_mcontext_t mc;
    INITIALIZE_MCONTEXT_FOR_REPORT(&mc);
    LOG(2, "replace_malloc_usable_size "PFX"\n", ptr);
    res = replace_size_common(arena, ptr, ALLOC_SYNCHRONIZE, drcontext, &mc,
                              (app_pc)replace_malloc_usable_size/*avoid confusion*/,
                              MALLOC_ALLOCATOR_MALLOC | CHUNK_LAYER_NOCHECK);
    if (res == (size_t)-1)
        res = 0; /* 0 on failure */
    LOG(2, "\treplace_malloc_usable_size "PFX" => "PIFX"\n", ptr, res);
    exit_client_code(drcontext, false/*need swap*/);
    return res;
}

#ifdef UNIX
static int
replace_posix_memalign(void **out, size_t align, size_t size)
{
    void *drcontext = enter_client_code();
    arena_header_t *arena = arena_for_libc_alloc(drcontext);
    dr_mcontext_t mc;
    int res = 0;
    byte *alloc;
    INITIALIZE_MCONTEXT_FOR_REPORT(&mc);
    LOG(2, "%s align=%d size=%d\n", __FUNCTION__, align, size);
    /* alignment must be power of 2 */
    if (!IS_POWER_OF_2(align) || out == NULL) {
        client_handle_alloc_failure(size, (app_pc)replace_posix_memalign, &mc);
        res = EINVAL;
    } else {
        alloc = ONDSTACK_REPLACE_ALLOC_COMMON
            (arena, size, align, ALLOC_SYNCHRONIZE | ALLOC_INVOKE_CLIENT,
             drcontext, &mc, (app_pc)replace_posix_memalign, MALLOC_ALLOCATOR_MALLOC);
        if (!dr_safe_write(out, sizeof(alloc), &alloc, NULL)) {
            client_handle_alloc_failure(size, (app_pc)replace_posix_memalign, &mc);
            res = EINVAL;
        }
    }
    LOG(2, "\t%s %d %d => "PFX"\n", __FUNCTION__, align, size, res);
    exit_client_code(drcontext, false/*need swap*/);
    return res;
}

static void *
replace_memalign(size_t align, size_t size)
{
    void *drcontext = enter_client_code();
    arena_header_t *arena = arena_for_libc_alloc(drcontext);
    dr_mcontext_t mc;
    byte *res = NULL;
    INITIALIZE_MCONTEXT_FOR_REPORT(&mc);
    LOG(2, "%s align=%d size=%d\n", __FUNCTION__, align, size);
    if (!IS_POWER_OF_2(align))
        client_handle_alloc_failure(size, (app_pc)replace_memalign, &mc);
    else {
        res = ONDSTACK_REPLACE_ALLOC_COMMON
            (arena, size, align, ALLOC_SYNCHRONIZE | ALLOC_INVOKE_CLIENT,
             drcontext, &mc, (app_pc)replace_memalign, MALLOC_ALLOCATOR_MALLOC);
    }
    LOG(2, "\t%s %d %d => "PFX"\n", __FUNCTION__, align, size, res);
    exit_client_code(drcontext, false/*need swap*/);
    return res;
}

static void *
replace_valloc(size_t size)
{
    void *drcontext = enter_client_code();
    arena_header_t *arena = arena_for_libc_alloc(drcontext);
    dr_mcontext_t mc;
    byte *res = NULL;
    INITIALIZE_MCONTEXT_FOR_REPORT(&mc);
    LOG(2, "%s size=%d\n", __FUNCTION__, size);
    res = ONDSTACK_REPLACE_ALLOC_COMMON
        (arena, size, PAGE_SIZE,
         ALLOC_SYNCHRONIZE | ALLOC_INVOKE_CLIENT,
         drcontext, &mc, (app_pc)replace_valloc, MALLOC_ALLOCATOR_MALLOC);
    LOG(2, "\t%s %d => "PFX"\n", __FUNCTION__, size, res);
    exit_client_code(drcontext, false/*need swap*/);
    return res;
}

static void *
replace_pvalloc(size_t size)
{
    void *drcontext = enter_client_code();
    arena_header_t *arena = arena_for_libc_alloc(drcontext);
    dr_mcontext_t mc;
    byte *res = NULL;
    INITIALIZE_MCONTEXT_FOR_REPORT(&mc);
    LOG(2, "%s size=%d\n", __FUNCTION__, size);
    res = ONDSTACK_REPLACE_ALLOC_COMMON
        (arena, ALIGN_FORWARD(size, PAGE_SIZE), PAGE_SIZE,
         ALLOC_SYNCHRONIZE | ALLOC_INVOKE_CLIENT,
         drcontext, &mc, (app_pc)replace_pvalloc, MALLOC_ALLOCATOR_MALLOC);
    LOG(2, "\t%s %d => "PFX"\n", __FUNCTION__, size, res);
    exit_client_code(drcontext, false/*need swap*/);
    return res;
}
#endif

/* XXX i#94: replace mallopt(), mallinfo(), etc. */

/***************************************************************************
 * Operators
 */

/* i#882: replace operator new/delete known to be non-placement to
 * avoid wrap cost and to support redzones on debug CRT.
 * We will also be able to pass in the allocation type rather than
 * reading it from CLS.
 */
static inline void *
replace_operator_new_common(void *drcontext, dr_mcontext_t *mc, size_t size,
                            bool abort_on_oom, uint alloc_type, app_pc caller)
{
    void *res;
    /* b/c we replace at the operator level and we don't analyze the
     * replaced operator to see which libc it's using we have to assume
     * our stored default is ok (xref i#964, i#939)
     */
    arena_header_t *arena = arena_for_libc_alloc(drcontext);
    LOG(2, "replace_operator_new size=%d abort_on_oom=%d type=%d\n",
        size, abort_on_oom, alloc_type);
    res = ONDSTACK_REPLACE_ALLOC_COMMON(arena, size, 0,
                                        ALLOC_SYNCHRONIZE | ALLOC_INVOKE_CLIENT,
                                        drcontext, mc, caller, alloc_type);
    LOG(2, "\treplace_operator_new %d => "PFX"\n", size, res);
    if (abort_on_oom && res == NULL) {
        /* XXX i#957: we should throw a C++ exception but for now we just abort */
        ELOGF(0, f_global, "ABORTING ON OOM\n");
        IF_DEBUG(aborting = true;)
        dr_exit_process(1);
        ASSERT(false, "should not reach here");
    }
    return res;
}

static void *
replace_operator_new(size_t size)
{
    void *res;
    void *drcontext = enter_client_code();
    dr_mcontext_t mc;
    INITIALIZE_MCONTEXT_FOR_REPORT(&mc);
    LOG(2, "%s "PIFX"\n", __FUNCTION__, size);
    res = replace_operator_new_common(drcontext, &mc, size, true, MALLOC_ALLOCATOR_NEW,
                                      (app_pc)replace_operator_new);
    exit_client_code(drcontext, false/*need swap*/);
    return res;
}

static void *
replace_operator_new_nothrow(size_t size, int /*std::nothrow_t*/ ignore)
{
    void *res;
    void *drcontext = enter_client_code();
    dr_mcontext_t mc;
    INITIALIZE_MCONTEXT_FOR_REPORT(&mc);
    LOG(2, "%s "PIFX"\n", __FUNCTION__, size);
    res = replace_operator_new_common(drcontext, &mc, size, false, MALLOC_ALLOCATOR_NEW,
                                      (app_pc)replace_operator_new_nothrow);
    exit_client_code(drcontext, false/*need swap*/);
    return res;
}

/* we need separate array versions for type mismatch detection (NYI) */
static void *
replace_operator_new_array(size_t size)
{
    void *res;
    void *drcontext = enter_client_code();
    dr_mcontext_t mc;
    INITIALIZE_MCONTEXT_FOR_REPORT(&mc);
    LOG(2, "%s "PIFX"\n", __FUNCTION__, size);
    res = replace_operator_new_common(drcontext, &mc, size, true,
                                      MALLOC_ALLOCATOR_NEW_ARRAY,
                                      (app_pc)replace_operator_new_array);
    exit_client_code(drcontext, false/*need swap*/);
    return res;
}

static void *
replace_operator_new_array_nothrow(size_t size, int /*std::nothrow_t*/ ignore)
{
    void *res;
    void *drcontext = enter_client_code();
    dr_mcontext_t mc;
    INITIALIZE_MCONTEXT_FOR_REPORT(&mc);
    LOG(2, "%s "PIFX"\n", __FUNCTION__, size);
    res = replace_operator_new_common(drcontext, &mc, size, false,
                                      MALLOC_ALLOCATOR_NEW_ARRAY,
                                      (app_pc)replace_operator_new_array_nothrow);
    exit_client_code(drcontext, false/*need swap*/);
    return res;
}

/* caller must call enter_client_code() + get mc to ensure a single cstack frame */
static inline void
replace_operator_delete_common(void *drcontext, dr_mcontext_t *mc, void *ptr,
                               uint alloc_type, app_pc caller, bool ignore_mismatch)
{
    arena_header_t *arena = arena_for_libc_alloc(drcontext);
    LOG(2, "replace_operator_delete "PFX"%s\n", ptr,
        ignore_mismatch ? " (ignore mismatches)" : "");
    ONDSTACK_REPLACE_FREE_COMMON(arena, ptr, ALLOC_SYNCHRONIZE | ALLOC_INVOKE_CLIENT |
                                 (ignore_mismatch ? ALLOC_IGNORE_MISMATCH : 0),
                                 drcontext, mc, caller, alloc_type);
}

/* We do not bother to report mismatches on nothrow vs regular so we
 * don't need to distinguish nothrow vs regular delete
 */
static void
replace_operator_delete(void *ptr)
{
    void *drcontext = enter_client_code();
    dr_mcontext_t mc;
    INITIALIZE_MCONTEXT_FOR_REPORT(&mc);
    LOG(2, "%s "PFX"\n", __FUNCTION__, ptr);
    replace_operator_delete_common(drcontext, &mc, ptr, MALLOC_ALLOCATOR_NEW,
                                   (app_pc)replace_operator_delete, false);
    exit_client_code(drcontext, false/*need swap*/);
}

static void
replace_operator_delete_nothrow(void *ptr, int /*std::nothrow_t*/ ignore)
{
    void *drcontext = enter_client_code();
    dr_mcontext_t mc;
    INITIALIZE_MCONTEXT_FOR_REPORT(&mc);
    LOG(2, "%s "PFX"\n", __FUNCTION__, ptr);
    replace_operator_delete_common(drcontext, &mc, ptr, MALLOC_ALLOCATOR_NEW,
                                   (app_pc)replace_operator_delete, false);
    exit_client_code(drcontext, false/*need swap*/);
}

static void
replace_operator_delete_array(void *ptr)
{
    void *drcontext = enter_client_code();
    dr_mcontext_t mc;
    INITIALIZE_MCONTEXT_FOR_REPORT(&mc);
    LOG(2, "%s "PFX"\n", __FUNCTION__, ptr);
    replace_operator_delete_common(drcontext, &mc, ptr, MALLOC_ALLOCATOR_NEW_ARRAY,
                                   (app_pc)replace_operator_delete_array, false);
    exit_client_code(drcontext, false/*need swap*/);
}

static void
replace_operator_delete_array_nothrow(void *ptr, int /*std::nothrow_t*/ ignore)
{
    void *drcontext = enter_client_code();
    dr_mcontext_t mc;
    INITIALIZE_MCONTEXT_FOR_REPORT(&mc);
    LOG(2, "%s "PFX"\n", __FUNCTION__, ptr);
    replace_operator_delete_common(drcontext, &mc, ptr, MALLOC_ALLOCATOR_NEW_ARRAY,
                                   (app_pc)replace_operator_delete_array_nothrow, false);
    exit_client_code(drcontext, false/*need swap*/);
}

static void *
replace_operator_new_nomatch(size_t size)
{
    void *res;
    void *drcontext = enter_client_code();
    dr_mcontext_t mc;
    INITIALIZE_MCONTEXT_FOR_REPORT(&mc);
    LOG(2, "%s "PIFX"\n", __FUNCTION__, size);
    res = replace_operator_new_common(drcontext, &mc, size, true,
                                      MALLOC_ALLOCATOR_UNKNOWN,
                                      (app_pc)replace_operator_new_nomatch);
    exit_client_code(drcontext, false/*need swap*/);
    return res;
}

static void *
replace_operator_new_nothrow_nomatch(size_t size, int /*std::nothrow_t*/ ignore)
{
    void *res;
    void *drcontext = enter_client_code();
    dr_mcontext_t mc;
    INITIALIZE_MCONTEXT_FOR_REPORT(&mc);
    LOG(2, "%s "PIFX"\n", __FUNCTION__, size);
    res = replace_operator_new_common(drcontext, &mc, size, false,
                                      MALLOC_ALLOCATOR_UNKNOWN,
                                      (app_pc)replace_operator_new_nothrow);
    exit_client_code(drcontext, false/*need swap*/);
    return res;
}

static void
replace_operator_delete_nomatch(void *ptr)
{
    void *drcontext = enter_client_code();
    dr_mcontext_t mc;
    INITIALIZE_MCONTEXT_FOR_REPORT(&mc);
    LOG(2, "%s "PFX"\n", __FUNCTION__, ptr);
    replace_operator_delete_common(drcontext, &mc, ptr, MALLOC_ALLOCATOR_NEW,
                                   (app_pc)replace_operator_delete_nomatch, true);
    exit_client_code(drcontext, false/*need swap*/);
}

static void
replace_operator_delete_nothrow_nomatch(void *ptr, int /*std::nothrow_t*/ ignore)
{
    void *drcontext = enter_client_code();
    dr_mcontext_t mc;
    INITIALIZE_MCONTEXT_FOR_REPORT(&mc);
    LOG(2, "%s "PFX"\n", __FUNCTION__, ptr);
    replace_operator_delete_common(drcontext, &mc, ptr, MALLOC_ALLOCATOR_NEW,
                                   (app_pc)replace_operator_delete_nothrow_nomatch, true);
    exit_client_code(drcontext, false/*need swap*/);
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
    void *drcontext = enter_client_code();
    dr_mcontext_t mc;
    INITIALIZE_MCONTEXT_FOR_REPORT(&mc);
    LOG(2, "%s "PFX"\n", __FUNCTION__, ptr);
    replace_operator_delete_common(drcontext, &mc, ptr, MALLOC_ALLOCATOR_UNKNOWN,
                                   (app_pc)replace_operator_combined_delete, true);
    exit_client_code(drcontext, false/*need swap*/);
}
#endif /* WINDOWS */

#ifdef WINDOWS
/***************************************************************************
 * Windows RTL Heap API
 */

/* i#1572: Rtl*Heap return BOOLEAN up through win7, but BOOL on win8+.
 * There's no downside to returning BOOL instead of BOOLEAN if our value
 * is either 0 or 1 (i.e., no weird != 1 true values) so we always do that.
 * Our code either uses A) TRUE or FALSE constants or B) !!bool.
 */
typedef BOOL RTL_HEAP_BOOL_TYPE;

/* Table mapping a module base to arena_header_t, for post-us libc Heaps (i#960).
 * This stores the default Heap for the module and thus we assume the
 * lifetime of the arena matches the module lifetime.
 */
static hashtable_t crtheap_mod_table;
#define CRTHEAP_MOD_TABLE_HASH_BITS 8

/* Table mapping Heap HANDLE to arena_header_t, for pre-us Heaps (i#959). */
static hashtable_t crtheap_handle_table;
#define CRTHEAP_HANDLE_TABLE_HASH_BITS 8

/* Forwards */
static NTSTATUS WINAPI
replace_RtlDestroyHeap(HANDLE heap);


static arena_header_t *
create_Rtl_heap(size_t commit_sz, size_t reserve_sz, uint flags)
{
    arena_header_t *new_arena = (arena_header_t *)
        os_large_alloc(commit_sz, reserve_sz, arena_page_prot(flags));
    if (new_arena != NULL) {
        LOG(2, "%s commit="PIFX" reserve="PIFX" flags=0x%x => "PFX"\n",
            __FUNCTION__, commit_sz, reserve_sz, flags, new_arena);
        new_arena->commit_end = (byte *)new_arena + commit_sz;
        new_arena->reserve_end = (byte *)new_arena + reserve_sz;
        heap_region_add((byte *)new_arena, new_arena->reserve_end, HEAP_ARENA, NULL);
        /* Even if this is the post-us arena for a pre-us Heap, we store the new
         * arena as the Heap for easier RtlWalkHeap implementation.  We skip
         * pre-us heaps during app iteration.
         * Earlier injection would eliminate the complexity.
         */
        heap_region_set_heap((byte *)new_arena, (HANDLE)new_arena);
        /* this will create the lock even if TEST(HEAP_NO_SERIALIZE, flags) */
        arena_init(new_arena, NULL);
        new_arena->flags |= (flags & HEAP_CREATE_POSSIBLE_FLAGS);
    }
    return new_arena;
}

/* If !free_chunks, we assume called at process exit */
static void
destroy_Rtl_heap(arena_header_t *arena, dr_mcontext_t *mc, bool free_chunks)
{
    LOG(2, "%s heap="PFX"\n", __FUNCTION__, arena);
    if (arena->modbase != NULL) {
        IF_DEBUG(bool found =)
            hashtable_remove(&crtheap_mod_table, (void *)arena->modbase);
        ASSERT(found, "inconsistent default Heap");
    }
    if (arena->handle != NULL) {
        IF_DEBUG(bool found =)
            hashtable_remove(&crtheap_handle_table, (void *)arena->handle);
        ASSERT(found, "inconsistent default Heap");
    }
    /* If not at process exit (else we'll deadlock on alloc_routine_table lock),
     * clear this from the alloc set
     */
    if (free_chunks && arena->alloc_set_member != NULL) {
        IF_DEBUG(bool success =)
            alloc_routine_set_update_user_data(arena->alloc_set_member, NULL);
        ASSERT(success, "failed to invalidate default Heap on its destruction");
    }
    destroy_arena_family(arena, mc, free_chunks, (app_pc)replace_RtlDestroyHeap);
}

/* Returns NULL if not a valid Heap handle.  Caller may want to call
 * report_invalid_heap() once mc is available to report NULL.
 */
static arena_header_t *
heap_to_arena(HANDLE heap)
{
    arena_header_t *arena = (arena_header_t *) heap;
    uint magic;
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
    else {
        arena = hashtable_lookup(&crtheap_handle_table, (void *)heap);
        if (arena != NULL)
            return arena;
        LOG(2, "%s: "PFX" => NULL!\n", __FUNCTION__, heap);
        return NULL;
    }
}

/* Called at process init, prior to any module events */
static void
pre_existing_heap_init(HANDLE heap)
{
    /* Create an arena for this pre-existing Heap (i#959) */
    arena_header_t *arena;
    MEMORY_BASIC_INFORMATION mbi;
    uint prot;
    bool mapped = false;
    IF_DEBUG(bool unique;)
    if (heap == process_heap)
        return;
    if (dr_virtual_query((byte *)heap, &mbi, sizeof(mbi)) == sizeof(mbi) &&
        (mbi.Type == MEM_MAPPED || mbi.Type == MEM_IMAGE)) {
        /* i#1221: ntdll!CsrPortHeap passed in shared memory here.
         * We can't use our own memory.
         */
        byte *alloc_base = (byte *) mbi.AllocationBase;
        byte *alloc_end = heap_allocated_end(heap);
        /* Go to next page to be safe */
        /* FIXME i#1882: on x64 we have the endpoint computed incorrectly, or
         * something is open-ended, so we skip one more page.
         */
        alloc_end = (byte *) ALIGN_FORWARD(alloc_end + IF_X64(2*)PAGE_SIZE, PAGE_SIZE);
        /* FIXME: for this case we'd have to fall back to native calls */
        ASSERT(alloc_end < (byte *)heap + mbi.RegionSize,
               "pre-us mapped heap has no room left");
        arena = (arena_header_t *) alloc_end;
        /* Be sure to initialize everything as there could be stale data here (i#1823) */
        memset(arena, 0, sizeof(*arena) + sizeof(*arena->free_list));
        arena->commit_end = (byte *)heap + mbi.RegionSize;

        /* i#1282: we may need to extend the committed part of the heap */
        if (dr_virtual_query(arena->commit_end, &mbi, sizeof(mbi)) == sizeof(mbi) &&
            (byte *)mbi.AllocationBase == alloc_base &&
            mbi.State == MEM_RESERVE)
            arena->reserve_end = (byte *)mbi.BaseAddress + mbi.RegionSize;
        else
            arena->reserve_end = arena->commit_end;

        arena_init(arena, NULL);
        arena->flags |= ARENA_PRE_US_MAPPED;
        LOG(2, "new arena inside mmapped pre-us Heap "PFX" is "PFX"-"PFX"-"PFX"\n",
            heap, arena, arena->commit_end, arena->reserve_end);
    } else {
        arena = (arena_header_t *)
            create_Rtl_heap(PAGE_SIZE, ARENA_INITIAL_SIZE, HEAP_GROWABLE);
        LOG(2, "new arena for pre-us Heap "PFX" is "PFX"\n", heap, arena);
    }
    IF_DEBUG(unique =)
        hashtable_add(&crtheap_handle_table, (void *)heap, (void *)arena);
    ASSERT(unique, "duplicate pre-us Heap");
    arena->handle = heap;
    if (dr_query_memory((byte *)heap, NULL, NULL, &prot) && TEST(DR_MEMPROT_EXEC, prot)) {
        arena->flags |= HEAP_CREATE_ENABLE_EXECUTE;
    }
    /* XXX: we don't know about HEAP_GROWABLE or HEAP_GENERATE_EXCEPTIONS
     * or HEAP_NO_SERIALIZE!  Best to be conservative on HEAP_GROWABLE.
     */
    if (!TEST(ARENA_PRE_US_MAPPED, arena->flags))
        arena->flags |= HEAP_GROWABLE;
}

static HANDLE
libc_heap_handle(const module_data_t *mod)
{
    HANDLE pre_us_heap = NULL;
    ptr_uint_t (*get_heap)(void) = (ptr_uint_t (*)(void))
        dr_get_proc_address(mod->handle, "_get_heap_handle");
    LOG(3, "%s: for "PFX" func is "PFX"\n", __FUNCTION__, mod->start, get_heap);
    if (get_heap != NULL) {
        void *drcontext = dr_get_current_drcontext();
        DR_TRY_EXCEPT(drcontext, {
            pre_us_heap = (HANDLE) (*get_heap)();
        }, { /* EXCEPT */
        });
    } else {
        /* For static libc, we don't want to call _get_heap_handle(), as it
         * asserts if the heap is not initialized yet.  Since we need syms to find
         * it anyway, we just go straight for _crtheap.
         */
        byte *addr = lookup_internal_symbol(mod, "_crtheap");
        /* i#1864: VS2015 changed the name to "__acrt_heap" */
        if (addr == NULL)
            addr = lookup_internal_symbol(mod, "__acrt_heap");
        if (addr != NULL) {
            if (!safe_read(addr, sizeof(pre_us_heap), &pre_us_heap))
                pre_us_heap = NULL;
            LOG(3, "%s: _crtheap @"PFX" => "PFX"\n", __FUNCTION__, addr, pre_us_heap);
            /* i#1766: Chromium sets their _crtheap to 1! */
            if (pre_us_heap < (HANDLE)PAGE_SIZE) {
                LOG(3, "%s: clamping _crtheap from "PFX" to NULL\n", __FUNCTION__,
                    pre_us_heap);
                pre_us_heap = NULL;
            }
            if (alloc_ops.use_symcache)
                drsymcache_add(mod, "_crtheap", addr - mod->start);
        }
    }
    return pre_us_heap;
}

static arena_header_t *
check_libc_vs_process_heap(alloc_routine_entry_t *e, arena_header_t *arena)
{
    /* On first use, we must check whether the arena we created prior
     * to the module initializing its _crtheap should in fact exist,
     * or whether the module is using ProcessHeap as its libc heap
     * (happens on VS2012: i#1223).
     */
    HANDLE pre_us_heap;
    app_pc modbase = alloc_routine_get_module_base(e);
    module_data_t *mod = dr_lookup_module(modbase);
    ASSERT(mod != NULL, "libc set must have module");
    pre_us_heap = libc_heap_handle(mod);
    dr_free_module_data(mod);
    LOG(2, "%s: modbase "PFX" arena "PFX" heap "PFX"\n", __FUNCTION__,
        modbase, arena, pre_us_heap);
    if (pre_us_heap == process_heap) {
        /* win8 libc uses process heap (i#1223) */
        bool success = alloc_routine_set_update_user_data
            (arena->alloc_set_member, cur_arena);
        LOG(2, "replacing arena for modbase "PFX" w/ default arena for set "PFX"\n",
            modbase, arena->alloc_set_member);
        ASSERT(arena->next_chunk == arena->start_chunk && arena->next_arena == NULL,
               "arena should be unused");
        ASSERT(success, "failed to update set arena");
        IF_DEBUG(success =)
            heap_region_remove((byte *)arena, arena->reserve_end, NULL);
        ASSERT(success, "missing heap region for default Heap");
        IF_DEBUG(success =)
            hashtable_remove(&crtheap_mod_table, (void *)arena->modbase);
        ASSERT(success, "inconsistent default Heap");
        arena_free(arena);
        return cur_arena;
    } else {
        ASSERT(pre_us_heap == NULL /* lib w/ just cpp stubs, using msvcr*.dll */ ||
               hashtable_lookup(&crtheap_handle_table, (void *)pre_us_heap) != NULL,
               "failed to find pre-us heap");
        return arena;
    }
}

static inline void
report_invalid_heap(HANDLE heap, dr_mcontext_t *mc, app_pc caller)
{
    client_invalid_heap_arg(caller, (byte *)heap, mc,
                            "Windows API routine: invalid heap HANDLE", false/*!free*/);
}

/* i#960/i#607.A: identify a new Heap for CRT */
static void
check_for_CRT_heap(void *drcontext, arena_header_t *new_arena)
{
    dr_mcontext_t mc;
    packed_callstack_t *pcs;
    symbolized_callstack_t scs;
    uint i;
    app_pc modbase;
#   define CRT_HEAP_INIT_ROUTINE "_heap_init"
#   define CRT_HEAP_INIT_FRAMES 12
    INITIALIZE_MCONTEXT_FOR_REPORT(&mc);
    DOLOG(2, { report_callstack(drcontext, &mc); });
    packed_callstack_record(&pcs, &mc, NULL/*skip replace_ frame*/, CRT_HEAP_INIT_FRAMES);
    packed_callstack_to_symbolized(pcs, &scs);
    /* Look for 2 frames of ntdll (trying to rule out qsort or
     * other callback) calling entry point of dll, some other
     * frames of that dll, and then kernel*!HeapCreate.
     */
    LOG(2, "symbolized callstack:\n");
    for (i = 0; i < scs.num_frames; i++)
        LOG(2, "  #%d = %s!%s\n", i, symbolized_callstack_frame_modname(&scs, i),
            symbolized_callstack_frame_func(&scs, i));
    i = 0;
    /* Sometimes the replace_RtlCreateHeap still ends up on the stack */
    if (text_matches_pattern(symbolized_callstack_frame_modname(&scs, i),
                             DRMEMORY_LIBNAME, FILESYS_CASELESS))
        i++;
    if (scs.num_frames >= 3 &&
        text_matches_pattern(symbolized_callstack_frame_modname(&scs, i++),
                             "kernel*.dll", FILESYS_CASELESS)) {
        bool crt_init = false;
        IF_DEBUG(const char *modname = symbolized_callstack_frame_modname(&scs, i);)
        modbase = symbolized_callstack_frame_modbase(&scs, i++);
        LOG(2, "checking for CRT heap created by %s base="PFX"\n", modname, modbase);
        if (modbase == executable_base &&
            strcmp(symbolized_callstack_frame_func(&scs, i-1), CRT_HEAP_INIT_ROUTINE)
            == 0) {
            /* CRT in executable */
            crt_init = true;
        } else {
            /* Check for CRT in a DLL */
            while (i < scs.num_frames &&
                   symbolized_callstack_frame_modbase(&scs, i) == modbase)
                i++;
            if (i < scs.num_frames - 1 &&
                text_matches_pattern(symbolized_callstack_frame_modname(&scs, i++),
                                     "ntdll.dll", FILESYS_CASELESS) &&
                text_matches_pattern(symbolized_callstack_frame_modname(&scs, i++),
                                     "ntdll.dll", FILESYS_CASELESS)) {
                crt_init = true;
            }
        }
        if (crt_init) {
            /* Match => destroy the arena we made at lib load event time and
             * replace with the one here, as this one has specific params.
             */
            arena_header_t *set_arena = (arena_header_t *)
                hashtable_lookup(&crtheap_mod_table, (void *)modbase);
            LOG(2, "arena for CRT in %s is "PFX"\n", modname, set_arena);
            if (set_arena != NULL) {
                bool success = alloc_routine_set_update_user_data
                    (set_arena->alloc_set_member, new_arena);
                LOG(2, "replacing arena for %s w/ app arena "PFX" for set "PFX"\n",
                    modname, new_arena, set_arena->alloc_set_member);
                ASSERT(set_arena->alloc_set_member != NULL, "mis-initialized arena");
                ASSERT(set_arena->next_chunk == set_arena->start_chunk &&
                       set_arena->next_arena == NULL,
                       "arena should be unused");
                ASSERT(success, "failed to update set arena");
                if (success) {
                    new_arena->flags |= ARENA_LIBC_DEFAULT;
                    new_arena->modbase = set_arena->modbase;
                    set_arena->modbase = NULL; /* xfer, no free */
                    new_arena->alloc_set_member = set_arena->alloc_set_member;
                    heap_region_remove((byte *)set_arena, set_arena->reserve_end,
                                       NULL);
                    hashtable_add_replace(&crtheap_mod_table, (void *)modbase,
                                          (void *)new_arena);
                    arena_free(set_arena);
                }
            }
        }
    }
    symbolized_callstack_free(&scs);
    packed_callstack_free(pcs);
}

static HANDLE WINAPI
replace_RtlCreateHeap(ULONG flags, void *base, size_t reserve_sz,
                      size_t commit_sz, void *lock, void *params)
{
    arena_header_t *new_arena = NULL;
    void *drcontext = enter_client_code();
    LOG(2, "%s\n", __FUNCTION__);
    if (lock != NULL || params != NULL || base != NULL) {
        /* As of win7, CreateHeap always passes NULL for these 3.
         * XXX: once we have early injection, we'll see ntdll!CsrPortHeap created,
         * and it passes in a base (xref i#1221) to RtlCreateHeap.
         */
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

    if (new_arena != NULL)
        check_for_CRT_heap(drcontext, new_arena);

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

static NTSTATUS WINAPI
replace_RtlDestroyHeap(HANDLE heap)
{
    void *drcontext = enter_client_code();
    arena_header_t *arena = heap_to_arena(heap);
    NTSTATUS res = STATUS_INVALID_PARAMETER;
    dr_mcontext_t mc;
    INITIALIZE_MCONTEXT_FOR_REPORT(&mc);
    LOG(2, "%s heap="PFX"\n", __FUNCTION__, heap);
    if (arena == NULL)
        report_invalid_heap(heap, &mc, (app_pc)replace_RtlDestroyHeap);
    else if (heap != process_heap) {
        destroy_Rtl_heap(arena, &mc, true/*free indiv chunks*/);
        res = STATUS_SUCCESS;
    }
    exit_client_code(drcontext, false/*need swap*/);
    return res;
}

# ifdef X64
/***************************************************************************
 * i#1565: 64-bit win7/win8 RtlGetThreadPreferredUILanguages and several private
 * helper routines it calls (LdrpMergeLangFallbackLists and
 * RtlpMuiRegAddMultiSzToLangFallbackList, at the least) perform
 * abstraction-violating tests on precise heap block header fields which of course
 * our replacement headers do not match.  I'm calling this being "nosy".  Worse, they
 * allocate using RtlAllocateHeap yet free using RtlpFreeHeap.  In some cases they
 * seem to not even use the heap block they allocate for anything but these checks.
 * The checks are very similar for each routine, with particular patterns of checks
 * involving prefetch fields and other things we could pattern-match (limiting the
 * checks to only when inside RtlGetThreadPreferredUILanguages for accuracy and
 * perf), but we would still have to identify RtlpFreeHeap if we want to replace
 * these allocs.  Thus for now we go with the simplest solution we have that works:
 * we let all allocs inside RtlGetThreadPreferredUILanguages that pass
 * HEAP_ZERO_MEMORY go native.
 *
 * XXX: the current solution works for pattern mode but we might hit false positives
 * in shadow mode on accesses to these native allocs.  We'll have to revisit at that
 * point and perhaps try to do what's mentioned above: pattern-match the heap header
 * accesses (in shadow mode we can wait for the unaddr reports), and locate the call
 * to RtlpFreeHeap.
 *
 * XXX i#1720: a win7 ntdll patch changed some of this code to free using RtlFreeHeap
 * instead of RtlpFreeHeap as we saw before.  That causes invalid heap arg errors.
 * If all such code now calls RtlFreeHeap, we could consider going back to a
 * pattern-match approach, which was only abandoned b/c of RtlpFreeHeap: but it would
 * have to be contingent on this recent ntdll.dll.
 */

/* If we add more fields, we should move this up top-level */
static int cls_idx_replace = -1;

typedef struct _cls_replace_t {
    uint in_nosy_heap_region; /* are we inside RtlGetThreadPreferredUILanguages */
} cls_replace_t;

typedef NTSYSAPI PVOID (NTAPI *RtlAllocateHeap_t)(HANDLE, ULONG, SIZE_T);
static RtlAllocateHeap_t native_RtlAllocateHeap;

typedef NTSYSAPI RTL_HEAP_BOOL_TYPE (NTAPI *RtlFreeHeap_t)(HANDLE, ULONG, PVOID);
static RtlFreeHeap_t native_RtlFreeHeap;

static app_pc addr_RtlGetThreadPreferredUILanguages;
/* i#1822: we also need to make allocs in the Set routine native */
static app_pc addr_RtlSetThreadPreferredUILanguages;

static app_pc ntdll_base;
static app_pc ntdll_end;

/* We avoid invalid heap arg complaints on free by remembering the native allocs */
#define NOSY_TABLE_HASH_BITS 8
static hashtable_t nosy_table;

static void
replace_context_init(void *drcontext, bool new_depth)
{
    cls_replace_t *data;
    if (new_depth) {
        data = (cls_replace_t *) thread_alloc(drcontext, sizeof(*data), HEAPSTAT_WRAP);
        drmgr_set_cls_field(drcontext, cls_idx_replace, data);
    } else
        data = (cls_replace_t *) drmgr_get_cls_field(drcontext, cls_idx_replace);
    memset(data, 0, sizeof(*data));
}

static void
replace_context_exit(void *drcontext, bool thread_exit)
{
    if (thread_exit) {
        cls_replace_t *data = (cls_replace_t *)
            drmgr_get_cls_field(drcontext, cls_idx_replace);
        thread_free(drcontext, data, sizeof(*data), HEAPSTAT_WRAP);
    }
    /* else, nothing to do: we leave the struct for re-use on next callback */
}

static void
replace_start_nosy_sequence(void *wrapcxt, OUT void **user_data)
{
    cls_replace_t *data = (cls_replace_t *)
        drmgr_get_cls_field(dr_get_current_drcontext(), cls_idx_replace);
    data->in_nosy_heap_region++;
    LOG(4, "%s: counter=%d\n", __FUNCTION__, data->in_nosy_heap_region);
    DOLOG(4, {
        dr_mcontext_t *mc = drwrap_get_mcontext_ex(wrapcxt, DR_MC_INTEGER);
        client_print_callstack(drwrap_get_drcontext(wrapcxt), mc,
                               (app_pc)addr_RtlGetThreadPreferredUILanguages);
    });
}

static void
replace_stop_nosy_sequence(void *wrapcxt, OUT void **user_data)
{
    cls_replace_t *data = (cls_replace_t *)
        drmgr_get_cls_field(dr_get_current_drcontext(), cls_idx_replace);
    ASSERT(data->in_nosy_heap_region > 0, "missed in_native stop");
    if (data->in_nosy_heap_region > 0) /* try to recover */
        data->in_nosy_heap_region--;
    LOG(4, "%s: counter=%d\n", __FUNCTION__, data->in_nosy_heap_region);
    DOLOG(4, {
        dr_mcontext_t *mc = drwrap_get_mcontext_ex(wrapcxt, DR_MC_INTEGER);
        client_print_callstack(drwrap_get_drcontext(wrapcxt), mc,
                               (app_pc)addr_RtlGetThreadPreferredUILanguages);
    });
}

static void
replace_nosy_init(void)
{
    module_data_t *ntdll = dr_lookup_module_by_name("ntdll.dll");
    ASSERT(ntdll != NULL, "cannot find ntdll.dll");
    ntdll_base = ntdll->start;
    ASSERT(ntdll_base != NULL, "internal error finding ntdll.dll base");
    ntdll_end = ntdll->end;

    native_RtlAllocateHeap = (RtlAllocateHeap_t)
        dr_get_proc_address(ntdll->handle, "RtlAllocateHeap");
    ASSERT(native_RtlAllocateHeap != NULL, "internal error finding RtlAllocateHeap");

    addr_RtlGetThreadPreferredUILanguages = (app_pc)
        dr_get_proc_address(ntdll->handle, "RtlGetThreadPreferredUILanguages");
    addr_RtlSetThreadPreferredUILanguages = (app_pc)
        dr_get_proc_address(ntdll->handle, "RtlSetThreadPreferredUILanguages");
    ASSERT((addr_RtlGetThreadPreferredUILanguages != NULL &&
            addr_RtlSetThreadPreferredUILanguages != NULL) ||
           get_windows_version() < DR_WINDOWS_VERSION_VISTA,
           "failed to find RtlGetThreadPreferredUILanguages");
    if (addr_RtlGetThreadPreferredUILanguages != NULL) {
        if (!drwrap_wrap(addr_RtlGetThreadPreferredUILanguages,
                         replace_start_nosy_sequence, replace_stop_nosy_sequence))
            ASSERT(false, "failed to wrap");
    }
    if (addr_RtlSetThreadPreferredUILanguages != NULL) {
        if (!drwrap_wrap(addr_RtlSetThreadPreferredUILanguages,
                         replace_start_nosy_sequence, replace_stop_nosy_sequence))
            ASSERT(false, "failed to wrap");
    }
    native_RtlFreeHeap = (RtlFreeHeap_t)
        dr_get_proc_address(ntdll->handle, "RtlFreeHeap");
    ASSERT(native_RtlFreeHeap != NULL, "failed to find RtlFreeHeap");
    dr_free_module_data(ntdll);

    cls_idx_replace =
        drmgr_register_cls_field(replace_context_init, replace_context_exit);
    ASSERT(cls_idx_replace > -1, "unable to reserve CLS field");

    hashtable_init(&nosy_table, NOSY_TABLE_HASH_BITS, HASH_INTPTR, false/*!strdup*/);
}

static void
replace_nosy_exit(void)
{
    if (addr_RtlGetThreadPreferredUILanguages != NULL) {
        if (!drwrap_unwrap(addr_RtlGetThreadPreferredUILanguages,
                           replace_start_nosy_sequence, replace_stop_nosy_sequence))
            ASSERT(false, "failed to unwrap");
    }
    if (addr_RtlSetThreadPreferredUILanguages != NULL) {
        if (!drwrap_unwrap(addr_RtlSetThreadPreferredUILanguages,
                           replace_start_nosy_sequence, replace_stop_nosy_sequence))
            ASSERT(false, "failed to unwrap");
    }
    drmgr_unregister_cls_field(replace_context_init, replace_context_exit,
                               cls_idx_replace);
    hashtable_delete_with_stats(&nosy_table, "nosy");
}

/* Returns whether an RtlAllocateHeap call should go native */
static bool
replace_leave_native(void *drcontext, dr_mcontext_t *mc, HANDLE heap,
                     ULONG flags, SIZE_T size)
{
    /* i#1565: ntdll!RtlpMuiRegAddMultiSzToLangFallbackList on 64-bit win7 and
     * win8 allocates a heap object and then performs quite a few sanity checks
     * on it, directly reading the object's header as well as the header of
     * PEB->ProcessHeap.  It xors in some cookies and de-references the result,
     * ending up in a crash, so we have to do more than just ignore/suppress the
     * unaddrs.  Plus, it frees it via RtlpFreeHeap.
     */
    cls_replace_t *data;
    if (alloc_ops.replace_nosy_allocs)
        return false;
    if (get_windows_version() != DR_WINDOWS_VERSION_7 &&
        get_windows_version() != DR_WINDOWS_VERSION_8)
        return false;
    if (heap != process_heap ||
        /* every instance so far has this and only this flag set */
        flags != HEAP_ZERO_MEMORY)
        return false;
    data = (cls_replace_t *) drmgr_get_cls_field(drcontext, cls_idx_replace);
    if (data->in_nosy_heap_region > 0) {
        /* We perform one more check: to rule out a regular alloc in
         * RtlpMuiRegTryToAppendLanguageName (for which we then raise an invalid
         * heap arg potential error) we decode forward and look for a call to
         * RtlFreeHeap.  On Win7x64 that call is 195 bytes away.
         * XXX: if we end up having even more regular allocs that we made native, we
         * may want to put in a hashtable of native allocs so we can ignore them in
         * replace_RtlFreeHeap.
         */
        bool found_normal_free = false;
        instr_t inst;
        app_pc pc;
#       define NOSY_MAX_DECODE 512
        instr_init(drcontext, &inst);
        DR_TRY_EXCEPT(dr_get_current_drcontext(), {
            /* i#1833: we used to call callstack_next_retaddr(mc) but it can produce
             * bogus frames w/o unwind data, so we go with the more robust drwrap
             * retaddr slot:
             */
            app_pc app_caller = get_replace_native_caller(drcontext);
            if (app_caller >= ntdll_base && app_caller < ntdll_end) { /* sanity check */
                for (pc = app_caller; pc < app_caller + NOSY_MAX_DECODE; ) {
                    pc = decode(drcontext, pc, &inst);
                    if (instr_valid(&inst) && instr_is_call_direct(&inst)) {
                        if (opnd_get_pc(instr_get_target(&inst)) ==
                            (app_pc)native_RtlFreeHeap) {
                            LOG(3, "%s: found RtlFreeHeap call => not a native alloc\n",
                                __FUNCTION__);
                            DOLOG(3, {
                                client_print_callstack(dr_get_current_drcontext(), mc,
                                                       (app_pc)native_RtlAllocateHeap);
                            });
                            found_normal_free = true;
                            break;
                        }
                    }
                    instr_reset(drcontext, &inst);
                }
            }
        }, { /* EXCEPT */
            found_normal_free = false;
        });
        instr_free(drcontext, &inst);
        if (!found_normal_free) {
            LOG(3, "%s: inside RtlGetThreadPreferredUILanguages => native alloc\n",
                __FUNCTION__);
            DOLOG(3, {
                client_print_callstack(dr_get_current_drcontext(), mc,
                                       (app_pc)native_RtlAllocateHeap);
            });
            STATS_INC(allocs_left_native);
            return true;
        }
    }
    return false;
}
# endif /* X64 */

/***************************************************************************
 * Continue RtlHeap API replacement routines:
 */

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
    LOG(2, "%s heap="PFX" (=> "PFX") flags=0x%x size="PIFX"\n",
        __FUNCTION__, heap, arena, flags, size);
    if (arena == NULL)
        report_invalid_heap(heap, &mc, (app_pc)replace_RtlAllocateHeap);
# ifdef X64
    else if (replace_leave_native(drcontext, &mc, heap, flags, size)) {
        /* We can't directly invoke RtlAllocateHeap as DR's private loader
         * will redirect it.
         */
        IF_DEBUG(void *existing;)
        res = (*native_RtlAllocateHeap)(heap, flags, size);
        IF_DEBUG(existing =)
            hashtable_add_replace(&nosy_table, (void *)res, (void *)res);
        /* This better not touch an mmapped heap as that could corrupt our data */
        ASSERT(!TEST(ARENA_PRE_US_MAPPED, arena->flags),
               "native alloc in mmapped heap is not supported");
        LOG(2, "\tnative alloc => "PFX" (%s)\n",  res,
            existing == NULL ? "new" : "replacing -- likely missed RtlpFreeHeap");
    }
# endif
    else {
        res = ONDSTACK_REPLACE_ALLOC_COMMON
            (arena, size, 0,
             ((!TEST(HEAP_NO_SERIALIZE, arena->flags) &&
               !TEST(HEAP_NO_SERIALIZE, flags)) ?
              ALLOC_SYNCHRONIZE : 0) |
             (WINDOWS_ZERO_MEMORY(arena, flags) ? ALLOC_ZERO : 0) |
             ALLOC_INVOKE_CLIENT, drcontext,
             &mc, (app_pc)replace_RtlAllocateHeap,
             MALLOC_ALLOCATOR_MALLOC | CHUNK_LAYER_RTL);
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
    LOG(2, "%s heap="PFX" (=> "PFX") flags=0x%x ptr="PFX" size="PIFX"\n",
        __FUNCTION__, heap, arena, flags, ptr, size);
    if (arena == NULL)
        report_invalid_heap(heap, &mc, (app_pc)replace_RtlReAllocateHeap);
    else {
        /* unlike libc realloc(), HeapReAlloc fails when ptr==NULL */
        res = ONDSTACK_REPLACE_REALLOC_COMMON
            (arena, ptr, size,
             ((!TEST(HEAP_NO_SERIALIZE, arena->flags) &&
               !TEST(HEAP_NO_SERIALIZE, flags)) ?
              ALLOC_SYNCHRONIZE : 0) |
             (WINDOWS_ZERO_MEMORY(arena, flags) ? ALLOC_ZERO : 0) |
             (TEST(HEAP_REALLOC_IN_PLACE_ONLY, flags) ?
              ALLOC_IN_PLACE_ONLY : 0) |
             ALLOC_ALLOW_EMPTY
             /* fails on NULL */,
             drcontext, &mc, (app_pc)replace_RtlReAllocateHeap,
             MALLOC_ALLOCATOR_MALLOC | CHUNK_LAYER_RTL);
    }
    dr_switch_to_app_state(drcontext);
    if (res == NULL)
        handle_Rtl_alloc_failure(drcontext, arena, flags);
    exit_client_code(drcontext, true/*already swapped*/);
    return res;
}

static RTL_HEAP_BOOL_TYPE WINAPI
replace_RtlFreeHeap(HANDLE heap, ULONG flags, PVOID ptr)
{
    void *drcontext = enter_client_code();
    arena_header_t *arena = heap_to_arena(heap);
    RTL_HEAP_BOOL_TYPE res = FALSE;
    dr_mcontext_t mc;
    INITIALIZE_MCONTEXT_FOR_REPORT(&mc);
    LOG(2, "%s heap="PFX" flags=0x%x ptr="PFX"\n", __FUNCTION__, heap, flags, ptr);
    if (ptr == NULL) {
        /* for -warn_null_ptr */
        client_invalid_heap_arg((app_pc)replace_RtlFreeHeap, ptr, &mc,
                                "RtlFreeHeap", true /* is_free */);
        /* i#1644: ntdll!RtlFreeHeap returns TRUE if ptr is NULL */
        res = TRUE;
    } else if (arena == NULL)
        report_invalid_heap(heap, &mc, (app_pc)replace_RtlFreeHeap);
#ifdef X64
    else if (hashtable_lookup(&nosy_table, (void *)ptr) != NULL) {
        IF_DEBUG(bool found;)
        res = (*native_RtlFreeHeap)(heap, flags, ptr);
        IF_DEBUG(found =)
            hashtable_remove(&nosy_table, (void *)ptr);
        /* This better not touch an mmapped heap as that could corrupt our data */
        ASSERT(!TEST(ARENA_PRE_US_MAPPED, arena->flags),
               "native free in mmapped heap is not supported");
        LOG(2, "\tnative free "PFX" => %d\n",  ptr, res);
        ASSERT(found, "could this be an app race?");
    }
#endif
    else {
        bool ok = (bool)(ptr_uint_t) ONDSTACK_REPLACE_FREE_COMMON
            (arena, ptr,
             ((!TEST(HEAP_NO_SERIALIZE, arena->flags) &&
               !TEST(HEAP_NO_SERIALIZE, flags)) ?
              ALLOC_SYNCHRONIZE : 0) |
             ALLOC_INVOKE_CLIENT,
             drcontext, &mc, (app_pc)replace_RtlFreeHeap,
             MALLOC_ALLOCATOR_MALLOC | CHUNK_LAYER_RTL);
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
    if (arena == NULL)
        report_invalid_heap(heap, &mc, (app_pc)replace_RtlSizeHeap);
    else {
        res = replace_size_common(arena, ptr,
                                  ((!TEST(HEAP_NO_SERIALIZE, arena->flags) &&
                                    !TEST(HEAP_NO_SERIALIZE, flags)) ?
                                   ALLOC_SYNCHRONIZE : 0),
                                  drcontext, &mc, (app_pc)replace_RtlSizeHeap,
                                  MALLOC_ALLOCATOR_MALLOC | CHUNK_LAYER_RTL);
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

/* i#900: allowing the app to hold a lock we'll wait for in our
 * code that needs to return to a cache fragment is unsafe b/c a flusher
 * could hold the lock as the app.  Thus, we mark the lock acquisition
 * as a safe spot, and we redirect our return to the code cache
 * via DRi#849.
 */
static RTL_HEAP_BOOL_TYPE WINAPI
replace_RtlLockHeap(HANDLE heap)
{
    void *drcontext = enter_client_code();
    arena_header_t *arena = heap_to_arena(heap);
    RTL_HEAP_BOOL_TYPE res = FALSE;
    LOG(2, "%s heap="PFX" (arena="PFX")\n", __FUNCTION__, heap, arena);
    if (arena == NULL) {
        dr_mcontext_t mc;
        INITIALIZE_MCONTEXT_FOR_REPORT(&mc);
        report_invalid_heap(heap, &mc, (app_pc)replace_RtlLockHeap);
    } else {
        /* We only grab this DR lock as the app and we mark it with
         * dr_recurlock_mark_as_app(), as well as using dr_mark_safe_to_suspend(),
         * to ensure proper DR behavior
         */
        app_heap_lock(drcontext, arena->lock);
        res = TRUE;
    }
    dr_switch_to_app_state(drcontext);
    if (!res) /* see above about setting errno in app mode */
        set_app_error_code(drcontext, ERROR_INVALID_PARAMETER);
    exit_client_code(drcontext, true/*already swapped*/);
    return res;
}

static RTL_HEAP_BOOL_TYPE WINAPI
replace_RtlUnlockHeap(HANDLE heap)
{
    void *drcontext = enter_client_code();
    arena_header_t *arena = heap_to_arena(heap);
    RTL_HEAP_BOOL_TYPE res = FALSE, invalid = FALSE;;
    LOG(2, "%s heap="PFX" (arena="PFX")\n", __FUNCTION__, heap, arena);
    if (arena == NULL) {
        dr_mcontext_t mc;
        INITIALIZE_MCONTEXT_FOR_REPORT(&mc);
        report_invalid_heap(heap, &mc, (app_pc)replace_RtlUnlockHeap);
        invalid = TRUE;
    } else if (dr_recurlock_self_owns(arena->lock)) {
        app_heap_unlock(drcontext, arena->lock);
        res = TRUE;
    }
    dr_switch_to_app_state(drcontext);
    if (invalid) /* see above about setting errno in app mode */
        set_app_error_code(drcontext, ERROR_INVALID_PARAMETER);
    exit_client_code(drcontext, true/*already swapped*/);
    return res;
}

static RTL_HEAP_BOOL_TYPE WINAPI
replace_RtlValidateHeap(HANDLE heap, DWORD flags, void *ptr)
{
    void *drcontext = enter_client_code();
    arena_header_t *arena = heap_to_arena(heap);
    RTL_HEAP_BOOL_TYPE res = FALSE, invalid = FALSE;
    if (arena == NULL) {
        dr_mcontext_t mc;
        INITIALIZE_MCONTEXT_FOR_REPORT(&mc);
        report_invalid_heap(heap, &mc, (app_pc)replace_RtlValidateHeap);
        invalid = TRUE;
    } else {
        chunk_header_t *head = header_from_ptr(ptr);
        if (is_live_alloc(ptr, arena, head)) /* checks for NULL */
            res = TRUE;
    }
    LOG(2, "%s: heap "PFX"=>"PFX" arena, ptr "PFX" => %d\n",
        __FUNCTION__, heap, arena, ptr, res);
    dr_switch_to_app_state(drcontext);
    if (invalid) /* see above about setting errno in app mode */
        set_app_error_code(drcontext, ERROR_INVALID_PARAMETER);
    exit_client_code(drcontext, true/*already swapped*/);
    return res;
}

static NTSTATUS WINAPI
replace_RtlQueryHeapInformation(HANDLE heap,
                                HEAP_INFORMATION_CLASS info_class,
                                PVOID buf OPTIONAL,
                                SIZE_T buflen OPTIONAL,
                                PSIZE_T outlen OPTIONAL)
{
    void *drcontext = enter_client_code();
    arena_header_t *arena = heap_to_arena(heap);
    NTSTATUS res = STATUS_SUCCESS;
    dr_mcontext_t mc;
    INITIALIZE_MCONTEXT_FOR_REPORT(&mc);
    /* In MSDN only HeapCompatibilityInformation is supported.  It returns a ULONG
     * that we want to set to 0 to indicate neither look-aside lists nor
     * low-fragmentation heap support.
     */
    if (arena == NULL) {
        report_invalid_heap(heap, &mc, (app_pc)replace_RtlQueryHeapInformation);
        res = STATUS_INVALID_PARAMETER;
    } else if (info_class != HeapCompatibilityInformation) {
        res = STATUS_INVALID_PARAMETER;
    } else if (buflen < sizeof(ULONG)) {
        res = STATUS_BUFFER_TOO_SMALL;
    } else {
        mc.pc = (app_pc) replace_RtlQueryHeapInformation;
        if (client_write_memory(buf, buflen, &mc))
            *(ULONG *)buf = 0;
        if (outlen != NULL) {
            if (client_write_memory((byte *)outlen, sizeof(ULONG), &mc))
                *outlen = sizeof(ULONG);
        }
        res = STATUS_SUCCESS;
    }
    exit_client_code(drcontext, false/*need swap*/);
    return res;
}

static NTSTATUS WINAPI
replace_RtlSetHeapInformation(HANDLE heap, HEAP_INFORMATION_CLASS info_class,
                              PVOID buf, SIZE_T buflen)
{
    void *drcontext = enter_client_code();
    /* MSDN examples, and crt0.c, allow NULL to presumably mean the process heap */
    arena_header_t *arena = heap_to_arena(heap == NULL ? process_heap : heap);
    NTSTATUS res = STATUS_SUCCESS;
    if (arena == NULL) {
        dr_mcontext_t mc;
        INITIALIZE_MCONTEXT_FOR_REPORT(&mc);
        report_invalid_heap(heap, &mc, (app_pc)replace_RtlSetHeapInformation);
        res = STATUS_INVALID_PARAMETER;
    } else if (info_class == HeapCompatibilityInformation) {
        if (buflen < sizeof(ULONG)) {
            res = STATUS_BUFFER_TOO_SMALL;
        } else {
            /* Just turn into a nop (xref i#280) as we don't care if they request LFH */
            res = STATUS_SUCCESS;
        }
    } else if (info_class == HeapEnableTerminationOnCorruption) {
        /* XXX: should we turn into -crash_at_error or sthg, i.e.,
         * treat as an annotation?  For now making a nop.
         */
        res = STATUS_SUCCESS;
    } else {
        res = STATUS_INVALID_PARAMETER;
    }
    exit_client_code(drcontext, false/*need swap*/);
    return res;
}

static SIZE_T WINAPI
replace_RtlCompactHeap(HANDLE heap, ULONG flags)
{
    void *drcontext = enter_client_code();
    SIZE_T res = 0;
    BOOL success = FALSE;
    arena_header_t *arena = heap_to_arena(heap);
    if (arena == NULL) {
        dr_mcontext_t mc;
        INITIALIZE_MCONTEXT_FOR_REPORT(&mc);
        report_invalid_heap(heap, &mc, (app_pc)replace_RtlCompactHeap);
    } else {
        arena_lock(drcontext, arena, !TEST(HEAP_NO_SERIALIZE, arena->flags) &&
                   !TEST(HEAP_NO_SERIALIZE, flags));
        success = TRUE;
        if (arena->next_chunk < arena->commit_end)
            res = arena->commit_end - arena->next_chunk;
        arena_unlock(drcontext, arena, !TEST(HEAP_NO_SERIALIZE, arena->flags) &&
                     !TEST(HEAP_NO_SERIALIZE, flags));
    }
    dr_switch_to_app_state(drcontext);
    if (!success) /* see above about setting errno in app mode */
        set_app_error_code(drcontext, ERROR_INVALID_PARAMETER);
    else if (res == 0) /* actually out of space */
        set_app_error_code(drcontext, NO_ERROR);
    exit_client_code(drcontext, true/*already swapped*/);
    return res;
}


#ifdef X64
/* See i#907, i#995, i#1032.  For x64, strings are allocated via exported
 * heap routines, but freed via internal.
 */
static RTL_HEAP_BOOL_TYPE WINAPI
replace_NtdllpFreeStringRoutine(PVOID ptr)
{
    void *drcontext = enter_client_code();
    /* This routine calls RtlpFreeHeap(PEB->ProcessHeap, 0x2, ptr - 0x10, ptr).
     * I have no idea what the 0x2 is: is it really HEAP_GROWABLE?!?.
     * We ignore it here.
     */
    arena_header_t *arena = heap_to_arena(process_heap);
    RTL_HEAP_BOOL_TYPE res = FALSE;
    bool ok;
    dr_mcontext_t mc;
    INITIALIZE_MCONTEXT_FOR_REPORT(&mc);
    LOG(2, "%s ptr="PFX"\n", __FUNCTION__, ptr);
    ASSERT(arena != NULL, "process_heap should always have an arena");
    if (arena != NULL) {
        ok = (bool)(ptr_uint_t) ONDSTACK_REPLACE_FREE_COMMON
            (arena, ptr, (!TEST(HEAP_NO_SERIALIZE, arena->flags) ?
                          ALLOC_SYNCHRONIZE : 0) | ALLOC_INVOKE_CLIENT,
             drcontext, &mc, (app_pc)replace_NtdllpFreeStringRoutine,
             MALLOC_ALLOCATOR_MALLOC | CHUNK_LAYER_RTL);
        res = !!ok; /* convert from bool to BOOL */
    }
    dr_switch_to_app_state(drcontext);
    if (!res)
        set_app_error_code(drcontext, ERROR_INVALID_PARAMETER);
    exit_client_code(drcontext, true/*already swapped*/);
    return res;
}
#endif

static RTL_HEAP_BOOL_TYPE WINAPI
replace_ignore_arg0(void)
{
    void *drcontext = enter_client_code();
    LOG(2, "%s: ignoring\n", __FUNCTION__);
    exit_client_code(drcontext, false/*need swap*/);
    return TRUE;
}

static RTL_HEAP_BOOL_TYPE WINAPI
replace_ignore_arg1(void *arg1)
{
    void *drcontext = enter_client_code();
    LOG(2, "%s: ignoring\n", __FUNCTION__);
    exit_client_code(drcontext, false/*need swap*/);
    return TRUE;
}

static RTL_HEAP_BOOL_TYPE WINAPI
replace_ignore_arg2(void *arg1, void *arg2)
{
    void *drcontext = enter_client_code();
    LOG(2, "%s: ignoring\n", __FUNCTION__);
    exit_client_code(drcontext, false/*need swap*/);
    return TRUE;
}

static RTL_HEAP_BOOL_TYPE WINAPI
replace_ignore_arg3(void *arg1, void *arg2, void *arg3)
{
    void *drcontext = enter_client_code();
    LOG(2, "%s: ignoring\n", __FUNCTION__);
    exit_client_code(drcontext, false/*need swap*/);
    return TRUE;
}

static RTL_HEAP_BOOL_TYPE WINAPI
replace_ignore_arg4(void *arg1, void *arg2, void *arg3, void *arg4)
{
    void *drcontext = enter_client_code();
    LOG(2, "%s: ignoring\n", __FUNCTION__);
    exit_client_code(drcontext, false/*need swap*/);
    return TRUE;
}

static RTL_HEAP_BOOL_TYPE WINAPI
replace_ignore_arg5(void *arg1, void *arg2, void *arg3, void *arg4, void *arg5)
{
    void *drcontext = enter_client_code();
    LOG(2, "%s: ignoring\n", __FUNCTION__);
    exit_client_code(drcontext, false/*need swap*/);
    return TRUE;
}

/***************************************************************************
 * RtlHeap iteration replacement routines
 */

typedef NTSTATUS (*PHEAP_ENUMERATION_ROUTINE)(IN PVOID HeapHandle, IN PVOID UserParam);

typedef struct _getheaps_data_t {
    ULONG actual_len;
    ULONG user_len;
    HANDLE *user_heaps;
    dr_mcontext_t *mc;
} getheaps_data_t;

#define STATUS_NO_MORE_ENTRIES ((NTSTATUS)0x8000001a)

static bool
heap_iter_getheaps(byte *start, byte *end, uint flags
                   _IF_WINDOWS(HANDLE heap), void *iter_data)
{
    getheaps_data_t *data = (getheaps_data_t *) iter_data;
    /* We do not attempt to walk pre-us heaps.  We'd have to mix wrap and
     * replace in a strange way, and pre-us should be system lib allocs unrelated
     * to the app (XXX: except for delayed init or attach: though those are
     * non-default modes).
     */
    if (TEST(HEAP_ARENA, flags) && !TEST(HEAP_PRE_US, flags)) {
        arena_header_t *arena = (arena_header_t *) start;
        if (TEST(ARENA_MAIN, arena->flags)) {
            LOG(2, "%s: "PFX"-"PFX" heap="PFX"\n", __FUNCTION__, start, end, heap);
            if (data->user_len > data->actual_len) {
                /* We avoid crashing (reported as internal error) if a problem w/ this
                 * write.
                 */
                if (client_write_memory((byte *)&data->user_heaps[data->actual_len],
                                        sizeof(data->user_heaps[0]), data->mc))
                    data->user_heaps[data->actual_len] = heap;
            }
            data->actual_len++;
        }
    }
    return true;
}

static ULONG WINAPI
replace_RtlGetProcessHeaps(ULONG count, HANDLE *heaps)
{
    void *drcontext = enter_client_code();
    dr_mcontext_t mc;
    getheaps_data_t data = {0, count, heaps, &mc};
    LOG(2, "%s\n", __FUNCTION__);
    INITIALIZE_MCONTEXT_FOR_REPORT(&mc);
    mc.pc = (app_pc) replace_RtlGetProcessHeaps;
    /* No input validation needed: the real API crashes if passed NULL */
    heap_region_iterate(heap_iter_getheaps, &data);
    exit_client_code(drcontext, false/*need swap*/);
    return data.actual_len;
}

static NTSTATUS WINAPI
replace_RtlEnumProcessHeaps(PHEAP_ENUMERATION_ROUTINE HeapEnumerationRoutine,
                            PVOID UserParam)
{
    void *drcontext = enter_client_code();
    /* FIXME i#1719: NYI.  This one is difficult, as we need to run app code.
     * We probably need an outer drwrap_replace() layer that calls an inner
     * drwrap_replace_native() layer.  The inner layer does what GetProcessHeaps does
     * and passes the array (allocated where?) to the outer layer, which is
     * interpreted and can safely run the callback routine.
     */
    ASSERT(false, "NYI");
    exit_client_code(drcontext, false/*need swap*/);
    return STATUS_SUCCESS;
}

static NTSTATUS WINAPI
replace_RtlWalkHeap(HANDLE heap, PVOID entry)
{
    void *drcontext = enter_client_code();
    arena_header_t *arena = heap_to_arena(heap);
    NTSTATUS res = STATUS_SUCCESS;
    dr_mcontext_t mc;
    rtl_process_heap_entry_t *e = (rtl_process_heap_entry_t *) entry;
    INITIALIZE_MCONTEXT_FOR_REPORT(&mc);
    mc.pc = (app_pc) replace_RtlWalkHeap;
    LOG(2, "%s heap="PFX" entry="PFX"\n", __FUNCTION__, heap, entry);
    /* XXX i#1719: we do not bother to try and iterate pre-us heaps */
    if (arena == NULL) {
        report_invalid_heap(heap, &mc, (app_pc)replace_RtlWalkHeap);
        res = STATUS_INVALID_PARAMETER;
    } else if (!client_read_memory((byte *)&e->lpData, sizeof(e->lpData), &mc)) {
        res = STATUS_INVALID_PARAMETER;
    } else {
        arena_header_t *a;
        byte *cur;
        chunk_header_t *head = NULL;
        bool region = false;
        /* client_read_memory will complain that the arena is unaddr so we safe_read */
        arena_header_t safe_a;
        /* We're supposed to have a PROCESS_HEAP_REGION entry with e->Region filled
         * out prior to the first chunk in each region.
         */
        if (e->lpData == NULL) {
            a = arena;
            region = true;
        } else if (!client_read_memory((byte *)e, sizeof(*e), &mc) ||
                   !safe_read((byte *)e->Block.hMem, sizeof(safe_a), &safe_a)) {
            res = STATUS_INVALID_PARAMETER;
        } else {
            if (TEST(RTL_PROCESS_HEAP_REGION, e->wFlags)) {
                a = (arena_header_t *) e->lpData;
                cur = a->start_chunk;
            } else {
                cur = (byte *) e->lpData;
                for (a = arena; a != NULL; a = a->next_arena) {
                    if (cur >= a->start_chunk && cur < a->next_chunk)
                        break;
                }
                if (a == NULL)
                    res = STATUS_INVALID_PARAMETER;
                else {
                    /* advance to next chunk */
                    head = header_from_ptr(cur);
                    if (head == NULL) {
                        cur = a->next_chunk;
                        res = STATUS_INVALID_PARAMETER;
                    } else
                        cur += head->alloc_size + inter_chunk_space();
                }
            }
            if (cur >= a->next_chunk) {
                a = a->next_arena;
                region = true;
            }
        }
        if (res == STATUS_SUCCESS && region &&
            !client_write_memory((byte *)e, sizeof(*e), &mc))
            res = STATUS_INVALID_PARAMETER;
        if (res != STATUS_SUCCESS) {
            /* error already set */
        } else if (a == NULL) {
            res = STATUS_NO_MORE_ENTRIES;
        } else {
            e->iRegionIndex = 0;
            e->cbOverhead = sizeof(chunk_header_t);
            if (region) {
                e->wFlags = RTL_PROCESS_HEAP_REGION;
                e->Region.dwCommittedSize = (DWORD) (a->commit_end - (byte *)a);
                e->Region.dwUnCommittedSize = (DWORD) (a->reserve_end - a->commit_end);
                e->Region.lpFirstBlock = (LPVOID) a->start_chunk;
                e->Region.lpLastBlock = (LPVOID) a->next_chunk;
                /* Store for use on the next query */
                e->lpData = (PVOID) a;
            } else {
                head = header_from_ptr(cur);
                if (TEST(CHUNK_FREED, head->flags))
                    e->wFlags = RTL_PROCESS_HEAP_UNCOMMITTED_RANGE;
                else
                    e->wFlags = RTL_PROCESS_HEAP_ENTRY_BUSY;
                e->lpData = cur;
                e->cbData = head->alloc_size;
                /* We can't use unused fields like e->Block.hMem to store the arena
                 * for use on the next query, as the HeapWalk layer has its own
                 * copy of this data struct and it doesn't copy all fields out.
                 */
            }
        }
    }
    exit_client_code(drcontext, false/*need swap*/);
    return res;
}

#endif /* WINDOWS */

#ifdef MACOS
/***************************************************************************
 * Malloc zone API (i#1699)
 *
 * We ignore the indirection through the function pointers in the
 * malloc_zone_t struct.  Natively, applications can replace individual
 * routines with their own versions, but for DrMem we want everything here.
 */

typedef struct _zone_iter_data_t {
    const void *ptr;
    malloc_zone_t *zone;
} zone_iter_data_t;

static arena_header_t *
zone_to_arena(malloc_zone_t *zone)
{
    arena_header_t *arena = (arena_header_t *) zone;
    uint magic;
    if (arena != NULL &&
        safe_read(&arena->magic, sizeof(magic), &magic) &&
        magic == HEADER_MAGIC &&
        TEST(ARENA_MAIN, arena->flags))
        return arena;
    return NULL;
}

static inline void
report_invalid_zone(malloc_zone_t *zone, dr_mcontext_t *mc, app_pc caller)
{
    client_invalid_heap_arg(caller, (byte *)zone, mc,
                            "malloc zone API: invalid zone", false/*!free*/);
}

static malloc_zone_t *
replace_malloc_create_zone(vm_size_t start_size, unsigned flags)
{
    arena_header_t *arena = NULL;
    void *drcontext = enter_client_code();
    LOG(2, "%s %d %d\n", __FUNCTION__, start_size, flags);
    /* Only 0 is supported for flags but we ignore it to match native behavior */
    arena = arena_create(NULL, ALIGN_FORWARD(start_size, PAGE_SIZE));
    LOG(2, "\t%s %d %d => "PFX"\n", __FUNCTION__, start_size, flags, arena);
    exit_client_code(drcontext, false/*need swap*/);
    return (malloc_zone_t *) arena;
}

static void
replace_malloc_destroy_zone(malloc_zone_t *zone)
{
    void *drcontext = enter_client_code();
    arena_header_t *arena = zone_to_arena(zone);
    dr_mcontext_t mc;
    INITIALIZE_MCONTEXT_FOR_REPORT(&mc);
    LOG(2, "%s "PFX"\n", __FUNCTION__, arena);
    if (arena == NULL)
        report_invalid_zone(zone, &mc, (app_pc)replace_malloc_destroy_zone);
    else {
        destroy_arena_family(arena, &mc, true/*free chunks*/,
                             (app_pc)replace_malloc_destroy_zone);
    }
    exit_client_code(drcontext, false/*need swap*/);
}

static malloc_zone_t *
replace_malloc_default_zone(void)
{
    void *drcontext = enter_client_code();
    malloc_zone_t *res = cur_arena->zone;
    exit_client_code(drcontext, false/*need swap*/);
    return res;
}

static bool
zone_from_ptr_iter(byte *start, byte *end, uint flags
                   _IF_WINDOWS(HANDLE heap), void *iter_data)
{
    zone_iter_data_t *data = (zone_iter_data_t *) iter_data;
    LOG(3, "%s: "PFX"-"PFX" 0x%x\n", __FUNCTION__, start, end, flags);
    if (TEST(HEAP_ARENA, flags) &&
        (byte *)data->ptr >= start && (byte *)data->ptr < end) {
        data->zone = (malloc_zone_t *) start;
        return false; /* stop iterating */
    }
    return true;
}

static malloc_zone_t *
replace_malloc_zone_from_ptr(const void *ptr)
{
    void *drcontext = enter_client_code();
    zone_iter_data_t data = {ptr, NULL};
    chunk_header_t *head = header_from_ptr(ptr);
    if (is_valid_chunk(ptr, head)) {
        /* XXX: do we have any better way to go from a chunk to containing arena? */
        heap_region_iterate(zone_from_ptr_iter, &data);
    }
    LOG(2, "\t%s "PFX" => "PIFX"\n", __FUNCTION__, ptr, data.zone);
    exit_client_code(drcontext, false/*need swap*/);
    return data.zone;
}

static size_t
replace_malloc_zone_size(malloc_zone_t *zone, const void *ptr)
{
    void *drcontext = enter_client_code();
    size_t res = 0;
    arena_header_t *arena = zone_to_arena(zone);
    dr_mcontext_t mc;
    INITIALIZE_MCONTEXT_FOR_REPORT(&mc);
    LOG(2, "%s: "PFX"\n", __FUNCTION__, ptr);
    if (arena == NULL)
        report_invalid_zone(zone, &mc, (app_pc)replace_malloc_zone_size);
    else {
        /* The API promises to return 0 if ptr is not in zone */
        arena_header_t *a;
        arena_lock(drcontext, arena, true);
        for (a = arena; a != NULL; a = a->next_arena) {
            if ((byte *)ptr >= a->start_chunk && (byte *)ptr < a->reserve_end)
                break;
        }
        arena_unlock(drcontext, arena, true);
        if (a == NULL)
            res = 0;
        else {
            res = replace_size_common(arena, (byte *)ptr, ALLOC_SYNCHRONIZE, drcontext,
                                      &mc, (app_pc)replace_malloc_zone_size,
                                      MALLOC_ALLOCATOR_MALLOC);
            if (res == (size_t)-1)
                res = 0; /* 0 on failure */
        }
    }
    LOG(2, "\t%s "PFX" => "PIFX"\n", __FUNCTION__, ptr, res);
    exit_client_code(drcontext, false/*need swap*/);
    return res;
}

static void *
replace_malloc_zone_malloc(malloc_zone_t *zone, size_t size)
{
    void *drcontext = enter_client_code();
    arena_header_t *arena = zone_to_arena(zone);
    void *res = NULL;
    dr_mcontext_t mc;
    INITIALIZE_MCONTEXT_FOR_REPORT(&mc);
    LOG(2, "%s zone="PFX" (=> "PFX") size="PIFX"\n",
        __FUNCTION__, zone, arena, size);
    if (arena == NULL)
        report_invalid_zone(zone, &mc, (app_pc)replace_malloc_zone_malloc);
    else {
        res = ONDSTACK_REPLACE_ALLOC_COMMON
            (arena, size, 0, ALLOC_SYNCHRONIZE | ALLOC_INVOKE_CLIENT,
             drcontext, &mc, (app_pc)replace_malloc_zone_malloc, MALLOC_ALLOCATOR_MALLOC);
    }
    LOG(2, "\t%s "PFX" %d => "PIFX"\n", __FUNCTION__, zone, size, res);
    exit_client_code(drcontext, false/*need swap*/);
    return res;
}

static void *
replace_malloc_zone_calloc(malloc_zone_t *zone, size_t num_items, size_t size)
{
    void *drcontext = enter_client_code();
    arena_header_t *arena = zone_to_arena(zone);
    void *res = NULL;
    dr_mcontext_t mc;
    INITIALIZE_MCONTEXT_FOR_REPORT(&mc);
    LOG(2, "%s zone="PFX" (=> "PFX") %d X %d\n",
        __FUNCTION__, zone, arena, num_items, size);
    if (arena == NULL)
        report_invalid_zone(zone, &mc, (app_pc)replace_malloc_zone_calloc);
    else if (unsigned_multiply_will_overflow(num_items, size)) {
        LOG(2, "calloc size will overflow => returning NULL\n");
        client_handle_alloc_failure(UINT_MAX, (app_pc)replace_malloc_zone_calloc, &mc);
        res = NULL;
    } else {
        res = ONDSTACK_REPLACE_ALLOC_COMMON
            (arena, num_items * size, 0,
             ALLOC_SYNCHRONIZE | ALLOC_ZERO | ALLOC_INVOKE_CLIENT, drcontext,
             &mc, (app_pc)replace_malloc_zone_calloc, MALLOC_ALLOCATOR_MALLOC);
    }
    LOG(2, "\t%s "PFX" %d X %d => "PIFX"\n", __FUNCTION__, zone, num_items, size, res);
    exit_client_code(drcontext, false/*need swap*/);
    return res;
}

static void *
replace_malloc_zone_realloc(malloc_zone_t *zone, void *ptr, size_t size)
{
    void *drcontext = enter_client_code();
    arena_header_t *arena = zone_to_arena(zone);
    void *res = NULL;
    dr_mcontext_t mc;
    INITIALIZE_MCONTEXT_FOR_REPORT(&mc);
    LOG(2, "%s "PFX" %d\n", __FUNCTION__, ptr, size);
    if (arena == NULL)
        report_invalid_zone(zone, &mc, (app_pc)replace_malloc_zone_realloc);
    else {
        res = ONDSTACK_REPLACE_REALLOC_COMMON(arena, ptr, size,
                                              ALLOC_SYNCHRONIZE | ALLOC_ALLOW_NULL,
                                              drcontext, &mc,
                                              (app_pc)replace_malloc_zone_realloc,
                                              MALLOC_ALLOCATOR_MALLOC);
    }
    LOG(2, "\t%s %d => "PFX"\n", __FUNCTION__, size, res);
    exit_client_code(drcontext, false/*need swap*/);
    return res;
}

static void
replace_malloc_zone_free(malloc_zone_t *zone, void *ptr)
{
    void *drcontext = enter_client_code();
    arena_header_t *arena = zone_to_arena(zone);
    dr_mcontext_t mc;
    INITIALIZE_MCONTEXT_FOR_REPORT(&mc);
    LOG(2, "%s "PFX"\n", __FUNCTION__, ptr);
    if (arena == NULL)
        report_invalid_zone(zone, &mc, (app_pc)replace_malloc_zone_realloc);
    else {
        ONDSTACK_REPLACE_FREE_COMMON(arena, ptr, ALLOC_SYNCHRONIZE | ALLOC_INVOKE_CLIENT,
                                     drcontext, &mc, (app_pc)replace_malloc_zone_free,
                                     MALLOC_ALLOCATOR_MALLOC);
    }
    exit_client_code(drcontext, false/*need swap*/);
}

static void *
replace_malloc_zone_valloc(malloc_zone_t *zone, size_t size)
{
    void *drcontext = enter_client_code();
    arena_header_t *arena = zone_to_arena(zone);
    void *res = NULL;
    dr_mcontext_t mc;
    INITIALIZE_MCONTEXT_FOR_REPORT(&mc);
    LOG(2, "%s zone="PFX" (=> "PFX") size="PIFX"\n",
        __FUNCTION__, zone, arena, size);
    if (arena == NULL)
        report_invalid_zone(zone, &mc, (app_pc)replace_malloc_zone_valloc);
    else {
        res = ONDSTACK_REPLACE_ALLOC_COMMON
            (arena, size, PAGE_SIZE, ALLOC_SYNCHRONIZE | ALLOC_INVOKE_CLIENT,
             drcontext, &mc, (app_pc)replace_malloc_zone_valloc, MALLOC_ALLOCATOR_MALLOC);
    }
    LOG(2, "\t%s "PFX" %d => "PIFX"\n", __FUNCTION__, zone, size, res);
    exit_client_code(drcontext, false/*need swap*/);
    return res;
}

static void *
replace_malloc_zone_memalign(malloc_zone_t *zone, size_t alignment, size_t size)
{
    void *drcontext = enter_client_code();
    arena_header_t *arena = zone_to_arena(zone);
    void *res = NULL;
    dr_mcontext_t mc;
    INITIALIZE_MCONTEXT_FOR_REPORT(&mc);
    LOG(2, "%s zone="PFX" (=> "PFX") size="PIFX"\n",
        __FUNCTION__, zone, arena, size);
    if (!IS_POWER_OF_2(alignment))
        client_handle_alloc_failure(size, (app_pc)replace_malloc_zone_memalign, &mc);
    else if (arena == NULL)
        report_invalid_zone(zone, &mc, (app_pc)replace_malloc_zone_memalign);
    else {
        res = ONDSTACK_REPLACE_ALLOC_COMMON
            (arena, size, alignment, ALLOC_SYNCHRONIZE | ALLOC_INVOKE_CLIENT,
             drcontext, &mc, (app_pc)replace_malloc_zone_memalign,
             MALLOC_ALLOCATOR_MALLOC);
    }
    LOG(2, "\t%s "PFX" %d => "PIFX"\n", __FUNCTION__, zone, size, res);
    exit_client_code(drcontext, false/*need swap*/);
    return res;
}

static void
malloc_zone_init(arena_header_t *arena)
{
    /* i#1699: we do not support apps replacing the func ptrs but we do
     * fill in the fields with initial values.
     */
    arena->zone = &arena->zone_inlined;
    arena->zone_inlined.size = replace_malloc_zone_size;
    arena->zone_inlined.malloc = replace_malloc_zone_malloc;
    arena->zone_inlined.calloc = replace_malloc_zone_calloc;
    arena->zone_inlined.valloc = replace_malloc_zone_valloc;
    arena->zone_inlined.free = replace_malloc_zone_free;
    arena->zone_inlined.realloc = replace_malloc_zone_realloc;
    arena->zone_inlined.destroy = replace_malloc_destroy_zone;
    arena->zone_inlined.batch_malloc = NULL;
    arena->zone_inlined.batch_free = NULL;
    arena->zone_inlined.introspect = NULL;
    /* I'm making the version 5 to avoid having to fill in free_definite_size
     * or pressure_relief.
     */
    arena->zone_inlined.version = 5;
    arena->zone_inlined.memalign = replace_malloc_zone_memalign;
    arena->zone_inlined.free_definite_size = NULL;
    arena->zone_inlined.pressure_relief = NULL;
}

#endif /* MACOS */

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
    return ptr_is_in_arena(addr, cur_arena);
}

bool
alloc_entering_replace_routine(app_pc pc)
{
    return drwrap_is_replaced_native(pc);
}

static bool
func_interceptor(routine_type_t type, bool check_mismatch, bool check_winapi_match,
                 void **routine OUT, bool *at_entry OUT, uint *stack OUT)
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
        case RTL_ROUTINE_HEAPINFO_GET:
            *routine = (void *) replace_RtlQueryHeapInformation;
            *stack = sizeof(void*) * 5;
            return true;
        case RTL_ROUTINE_HEAPINFO_SET:
            *routine = (void *) replace_RtlSetHeapInformation;
            *stack = sizeof(void*) * 4;
            return true;
        case RTL_ROUTINE_VALIDATE:
            *routine = (void *) replace_RtlValidateHeap;
            *stack = sizeof(void*) * 3;
            return true;
# ifdef X64
        /* i#995-c#3: we need to replace NtdllpFreeStringRoutine in win-x64,
         * which takes the first arg as the ptr to be freed.
         */
        case RTL_ROUTINE_FREE_STRING:
            *routine = (void *) replace_NtdllpFreeStringRoutine;
            *stack = sizeof(void*);
            return true;
# endif
        case RTL_ROUTINE_COMPACT:
            *routine = (void *) replace_RtlCompactHeap;
            *stack = sizeof(void*) * 2;
            return true;
        /* XXX i#1202: NYI.  Warn or assert if we hit them? */
        case RTL_ROUTINE_USERINFO_GET:
            *routine = (void *) replace_ignore_arg5;
            *stack = sizeof(void*) * 5;
            return true;
        case RTL_ROUTINE_USERINFO_SET:
            *routine = (void *) replace_ignore_arg4;
            *stack = sizeof(void*) * 4;
            return true;
        case RTL_ROUTINE_SETFLAGS:
            *routine = (void *) replace_ignore_arg5;
            *stack = sizeof(void*) * 5;
            return true;
        case RTL_ROUTINE_GET_HEAPS:
            *routine = (void *) replace_RtlGetProcessHeaps;
            *stack = sizeof(void*) * 2;
            return true;
        case RTL_ROUTINE_WALK:
            *routine = (void *) replace_RtlWalkHeap;
            *stack = sizeof(void*) * 2;
            return true;
#if 0 /* FIXME i#1719: NYI */
        case RTL_ROUTINE_ENUM:
            *routine = (void *) replace_RtlEnumProcessHeaps;
            *stack = sizeof(void*) * 2;
            return true;
#endif
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
#ifdef MACOS
    switch (type) {
    case ZONE_ROUTINE_CREATE:
        *routine = (void *) replace_malloc_create_zone;
        return true;
    case ZONE_ROUTINE_DESTROY:
        *routine = (void *) replace_malloc_destroy_zone;
        return true;
    case ZONE_ROUTINE_DEFAULT:
        *routine = (void *) replace_malloc_default_zone;
        return true;
    case ZONE_ROUTINE_QUERY:
        *routine = (void *) replace_malloc_zone_from_ptr;
        return true;
    case ZONE_ROUTINE_MALLOC:
        *routine = (void *) replace_malloc_zone_malloc;
        return true;
    case ZONE_ROUTINE_CALLOC:
        *routine = (void *) replace_malloc_zone_calloc;
        return true;
    case ZONE_ROUTINE_VALLOC:
        *routine = (void *) replace_malloc_zone_valloc;
        return true;
    case ZONE_ROUTINE_REALLOC:
        *routine = (void *) replace_malloc_zone_realloc;
        return true;
    case ZONE_ROUTINE_MEMALIGN:
        *routine = (void *) replace_malloc_zone_memalign;
        return true;
    case ZONE_ROUTINE_FREE:
        *routine = (void *) replace_malloc_zone_free;
        return true;
    default: break; /* continue below */
    }
#endif
    switch (type) {
#ifdef  UNIX
    case HEAP_ROUTINE_POSIX_MEMALIGN:
        *routine = (void *) replace_posix_memalign;
        return true;
    case HEAP_ROUTINE_MEMALIGN:
        *routine = (void *) replace_memalign;
        return true;
    case HEAP_ROUTINE_VALLOC:
        *routine = (void *) replace_valloc;
        return true;
    case HEAP_ROUTINE_PVALLOC:
        *routine = (void *) replace_pvalloc;
        return true;
#endif
    default: break; /* continue below */
    }
    if (is_malloc_routine(type)) {
        *routine = (void *)
            (check_winapi_match ? replace_malloc : replace_malloc_nomatch);
    }
    else if (is_calloc_routine(type)) {
        *routine = (void *)
            (check_winapi_match ? replace_calloc : replace_calloc_nomatch);
    }
    else if (is_realloc_routine(type)) {
        *routine = (void *)
            (check_winapi_match ? replace_realloc : replace_realloc_nomatch);
    }
    else if (is_free_routine(type))
        *routine = (void *) (check_winapi_match ? replace_free : replace_free_nomatch);
    else if (is_size_routine(type)) {
        *routine = (void *)
            (check_winapi_match ? replace_malloc_usable_size :
             replace_malloc_usable_size_nomatch);
    }
    else if (type == HEAP_ROUTINE_NEW) {
        *routine = (void *)
            (check_mismatch ? replace_operator_new : replace_operator_new_nomatch);
    }
    else if (type == HEAP_ROUTINE_NEW_ARRAY) {
        *routine = (void *)
            (check_mismatch ? replace_operator_new_array : replace_operator_new_nomatch);
    }
    else if (type == HEAP_ROUTINE_NEW_NOTHROW) {
        *routine = (void *)
            (check_mismatch ? replace_operator_new_nothrow :
             replace_operator_new_nothrow_nomatch);
    }
    else if (type == HEAP_ROUTINE_NEW_ARRAY_NOTHROW) {
        *routine = (void *)
            (check_mismatch ? replace_operator_new_array_nothrow :
             replace_operator_new_nothrow_nomatch);
    }
    else if (type == HEAP_ROUTINE_DELETE) {
        *routine = (void *)
            (check_mismatch ? replace_operator_delete : replace_operator_delete_nomatch);
    }
    else if (type == HEAP_ROUTINE_DELETE_ARRAY) {
        *routine = (void *)
            (check_mismatch ? replace_operator_delete_array :
             replace_operator_delete_nomatch);
    }
    else if (type == HEAP_ROUTINE_DELETE_NOTHROW) {
        *routine = (void *)
            (check_mismatch ? replace_operator_delete_nothrow :
             replace_operator_delete_nothrow_nomatch);
    }
    else if (type == HEAP_ROUTINE_DELETE_ARRAY_NOTHROW) {
        *routine = (void *)
            (check_mismatch ? replace_operator_delete_array_nothrow :
             replace_operator_delete_nothrow_nomatch);
    }
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
malloc_replace__intercept(app_pc pc, routine_type_t type, alloc_routine_entry_t *e,
                          bool check_mismatch, bool check_winapi_match)
{
    void *interceptor = NULL;
    bool at_entry = true;
    uint stack_adjust = 0;
#ifndef WINDOWS
    check_winapi_match = true; /* always use the match versions */
#endif
    if (!func_interceptor(type, check_mismatch, check_winapi_match,
                          &interceptor, &at_entry, &stack_adjust)) {
        /* we'll replace it ourselves elsewhere: alloc.c should ignore it */
        return;
    }
    if (interceptor != NULL) {
        /* optimization: only pass where needed, for Windows libc */
        void *user_data = IF_WINDOWS_ELSE(is_rtl_routine(type) ? NULL : (void *) e, NULL);
        if (!drwrap_replace_native(pc, interceptor, at_entry,
                                   IF_X64_ELSE(0, stack_adjust), user_data, false))
            ASSERT(false, "failed to replace alloc routine");
    } else {
        LOG(2, "wrapping, not replacing, "PFX"\n", pc);
        /* else wrap */
        /* XXX i#1202: Windows NYI: want to replace
         * _Crt* / RtlMultipleAllocateHeap / etc., along with all other
         * heap-related routines currenly not intercepted, w/ nops
         */
        malloc_wrap__intercept(pc, type, e, check_mismatch, check_winapi_match);
    }
}

static void
malloc_replace__unintercept(app_pc pc, routine_type_t type, alloc_routine_entry_t *e,
                            bool check_mismatch, bool check_winapi_match)
{
    void *interceptor = NULL;
    bool at_entry;
    uint stack_adjust = 0;
#ifndef WINDOWS
    check_winapi_match = true; /* always use the match versions */
#endif
    if (!func_interceptor(type, check_mismatch, check_winapi_match,
                          &interceptor, &at_entry, &stack_adjust)) {
        /* we'll un-replace it ourselves elsewhere: alloc.c should ignore it */
        return;
    }
    if (interceptor != NULL) {
        if (!drwrap_replace_native(pc, NULL, at_entry, IF_X64_ELSE(0, stack_adjust),
                                   NULL, true))
            ASSERT(false, "failed to un-replace alloc routine");
    } else {
        malloc_wrap__unintercept(pc, type, e, check_mismatch, check_winapi_match);
    }
}

static void *
malloc_replace__set_init(heapset_type_t type, app_pc pc, const module_data_t *mod,
                         void *libc_data)
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
        arena_header_t *arena = NULL;
        HANDLE pre_us_heap = NULL;
        bool in_table;
        IF_DEBUG(bool unique;)

        /* Determine the pre-us Heap for this pre-existing module, if
         * any (i#959).
         */
        if (!process_initialized) {
            pre_us_heap = libc_heap_handle(mod);
            LOG(2, "pre-existing Heap for libc set type=%d module=%s is "PFX"\n",
                type, (dr_module_preferred_name(mod) == NULL) ? "<null>" :
                dr_module_preferred_name(mod), pre_us_heap);
            if (pre_us_heap != NULL) {
                if (pre_us_heap == process_heap) {
                    /* win8 msvcr*.dll uses process heap (i#1223) */
                    LOG(2, "pre-existing libc Heap for module=%s == process heap!\n",
                        (dr_module_preferred_name(mod) == NULL) ? "<null>" :
                        dr_module_preferred_name(mod));
                    return cur_arena;
                }
                /* We should have already added in pre_existing_heap_init() */
                arena = (arena_header_t *)
                    hashtable_lookup(&crtheap_handle_table, (void *)pre_us_heap);
                in_table = (arena != NULL);
                ASSERT(in_table, "pre-us libc missed in heap walk");
            }
        }

        /* Create the Heap for this libc alloc routine set (i#939) */
        if (arena == NULL) {
            arena = (arena_header_t *)
                create_Rtl_heap(PAGE_SIZE, ARENA_INITIAL_SIZE, HEAP_GROWABLE);
        }
        LOG(2, "new default Heap for libc set type=%d @"PFX" modbase="PFX" is "PFX"\n",
            type, pc, mod->start, arena);
        arena->flags |= ARENA_LIBC_DEFAULT;
        /* Mark as speculative: for VS2012+, libc uses ProcessHeap, so we never
         * see RtlCreateHeap and we must instead wait for the 1st malloc set use
         * to see whether we want this separate arena.
         */
        arena->flags |= ARENA_LIBC_SPECULATIVE;
        arena->alloc_set_member = pc;
        IF_DEBUG(unique =)
            hashtable_add(&crtheap_mod_table, (void *)mod->start, (void *)arena);
        ASSERT(unique, "duplicate default Heap");
        arena->modbase = mod->start;

        /* Just in case: should be present from pre_existing_heap_init() */
        if (pre_us_heap != NULL && !in_table) {
            IF_DEBUG(unique =)
                hashtable_add(&crtheap_handle_table, (void *)pre_us_heap, (void *)arena);
            ASSERT(unique, "duplicate default Heap");
            arena->handle = pre_us_heap;
        }

        return arena;
    }
    /* cpp set does not need its own Heap (i#964) */
#endif
    return NULL;
}

static void
malloc_replace__set_exit(heapset_type_t type, app_pc pc, void *user_data)
{
#ifdef WINDOWS
    if (type != HEAPSET_RTL && user_data != NULL) {
        /* Destroy the Heap for this libc alloc routine set (i#939) */
        arena_header_t *arena = (arena_header_t *) user_data;
        /* For non-pre-us /MT module, we see the HeapDestroy, so arena can be NULL */
        if (arena != NULL && arena != cur_arena) {
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
    }
#endif
}

static void
malloc_replace__add(app_pc start, app_pc end, app_pc real_end,
                    bool pre_us, uint client_flags, dr_mcontext_t *mc, app_pc post_call)
{
    IF_DEBUG(bool new_entry;)
    chunk_header_t *head = global_alloc(sizeof(*head), HEAPSTAT_WRAP);
    head->alloc_size = (real_end - start);
    ASSERT(real_end - end <= REQUEST_DIFF_MAX, "too-large padding on pre-us malloc");
    head->u.unfree.request_diff = (real_end - end);
    if (chunk_request_size(head) >= LARGE_MALLOC_MIN_SIZE)
        malloc_large_add(start, chunk_request_size(head));
    head->flags = CHUNK_PRE_US;
    head->magic = HEADER_MAGIC;
    head->user_data = NULL;
    /* we assume only called for pre_us and only during init when no lock is needed */
    ASSERT(pre_us, "malloc add from outside must be pre_us");
    IF_DEBUG(new_entry =)
        hashtable_add(&pre_us_table, (void *)start, (void *)head);
    LOG(3, "new pre-us alloc "PFX"-"PFX"-"PFX"\n", start, end, real_end);
    ASSERT(new_entry, "should be no pre-us dups");
    notify_client_alloc(NULL, start, head,
                        /* no client action: caller can do that on its own */
                        ALLOC_INVOKE_CLIENT_DATA, mc, post_call);
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
        return start + chunk_request_size(head);
}

/* Returns -1 on failure */
static ssize_t
malloc_replace__size(app_pc start)
{
    chunk_header_t *head;
    ssize_t res = -1;
    head = header_from_ptr_include_pre_us(start);
    if (head != NULL && !TEST(CHUNK_FREED, head->flags))
        res = chunk_request_size(head);
    return res;
}

static ssize_t
malloc_replace__size_invalid_only(app_pc start)
{
    chunk_header_t *head = header_from_ptr_include_pre_us(start);
    if (head == NULL || !TEST(CHUNK_FREED, head->flags))
        return -1;
    else
        return chunk_request_size(head);
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
malloc_replace__iterate(bool (*cb)(malloc_info_t *info, void *iter_data), void *iter_data)
{
    alloc_iterate(cb, iter_data, true/*live only*/);
}

static void
malloc_replace__lock(void)
{
#ifdef WINDOWS
    /* i#949: we can't mark safe to suspend here (in app_heap_lock())
     * b/c it's called from clean calls, etc, and thus grabbing the app
     * lock here is unsafe.  Thus we require the global_lock option in order
     * to call this routine.
     * We don't need to grab the app lock as we don't need to synchronize
     * with app actions: only with our own allocator.
     */
    ASSERT(alloc_ops.global_lock, "must set global_lock to use malloc_lock()");
    dr_recurlock_lock(cur_arena->dr_lock);
#else
    dr_recurlock_lock(cur_arena->lock);
#endif
}

static void
malloc_replace__unlock(void)
{
#ifdef WINDOWS
    /* i#949: see comments above */
    ASSERT(alloc_ops.global_lock, "must set global_lock to use malloc_lock()");
    dr_recurlock_unlock(cur_arena->dr_lock);
#else
    dr_recurlock_unlock(cur_arena->lock);
#endif
}

static dr_emit_flags_t
bb_event(void *drcontext, void *tag, instrlist_t *bb,
         bool for_trace, bool translating)
{
    /* process and pre-existing modules are all initialized */
    process_initialized = true;

    /* reduce overhead by removing this event now */
    if (!drmgr_unregister_bb_app2app_event(bb_event))
        ASSERT(false, "drmgr unregistration failed");

    return DR_EMIT_DEFAULT;
}

void
alloc_replace_init(void)
{
#ifdef WINDOWS
    module_data_t *exe;
#endif

    if (!drmgr_register_bb_app2app_event(bb_event, NULL))
        ASSERT(false, "drmgr registration failed");

    if (alloc_ops.shared_redzones) {
        /* For x64 we have to add 8 extra bytes to align this */
        header_size = ALIGN_FORWARD(sizeof(chunk_header_t), CHUNK_ALIGNMENT);
    } else {
        /* See comment up top: we pay in extra space for simplicity of keeping
         * the free list next pointer out of the redzone.
         */
        header_size = ALIGN_FORWARD(sizeof(free_header_t), CHUNK_ALIGNMENT);
    }

    ASSERT(sizeof(free_header_t) <=
           (alloc_ops.external_headers ? 0 : sizeof(chunk_header_t)) + CHUNK_MIN_SIZE,
           "min size too small");
    /* we could pad but it's simpler to have struct already have right size */
    ASSERT(ALIGNED(header_size, CHUNK_ALIGNMENT), "alignment off");
    ASSERT(ALIGNED(inter_chunk_space(), CHUNK_ALIGNMENT), "alignment off");

    ASSERT(CHUNK_MIN_MMAP >= LARGE_MALLOC_MIN_SIZE,
           "we rely on mmapped chunks being in large malloc table");

    ASSERT(ARENA_INITIAL_SIZE >= CHUNK_MIN_MMAP, "arena must hold at least 1 chunk");

    ASSERT(ALIGNED(alloc_ops.redzone_size, CHUNK_ALIGNMENT), "redzone alignment off");

    ASSERT(USHRT_MAX*CHUNK_ALIGNMENT >= CHUNK_MIN_MMAP, "prev_size_shr field too small");

    if (!alloc_ops.shared_redzones) {
        header_beyond_redzone = header_size;
        redzone_beyond_header = alloc_ops.redzone_size;
    } else if (alloc_ops.redzone_size < header_size) {
        header_beyond_redzone = header_size - alloc_ops.redzone_size;
        redzone_beyond_header = 0;
    } else {
        redzone_beyond_header = (alloc_ops.redzone_size - header_size)/2;
        ASSERT(redzone_beyond_header*2 + header_size <= alloc_ops.redzone_size,
               "redzone or header size not aligned properly");
    }

    hashtable_init(&pre_us_table, PRE_US_TABLE_HASH_BITS, HASH_INTPTR, false/*!strdup*/);

#ifdef WINDOWS
    if (alloc_ops.global_lock)
        global_lock = dr_recurlock_create();

# ifdef X64
    replace_nosy_init();
# endif
#endif

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
    heap_region_add((byte *)cur_arena, cur_arena->reserve_end, HEAP_ARENA, NULL);
    arena_init(cur_arena, NULL);
#elif defined(MACOS)
    cur_arena = arena_create(NULL, 0/*default*/);
    ASSERT(cur_arena != NULL, "can't allocate initial heap: fatal");
    LOG(2, "initial arena="PFX"\n", cur_arena);
#else /* WINDOWS */
    process_heap = get_app_PEB()->ProcessHeap;
    LOG(2, "process heap="PFX"\n", process_heap);
    cur_arena = create_Rtl_heap(ARENA_INITIAL_COMMIT, ARENA_INITIAL_SIZE, HEAP_GROWABLE);
    ASSERT(cur_arena != NULL, "can't allocate initial heap: fatal");

    hashtable_init(&crtheap_mod_table, CRTHEAP_MOD_TABLE_HASH_BITS, HASH_INTPTR,
                   false/*!strdup*/);
    hashtable_init(&crtheap_handle_table, CRTHEAP_HANDLE_TABLE_HASH_BITS, HASH_INTPTR,
                   false/*!strdup*/);

    exe = dr_get_main_module();
    ASSERT(exe != NULL, "should find exe base");
    if (exe != NULL) {
        executable_base = exe->start;
        dr_free_module_data(exe);
    }

    heap_iterator(NULL, NULL _IF_WINDOWS(pre_existing_heap_init));
#endif

    /* set up pointers for per-malloc API */
    malloc_interface.malloc_lock = malloc_replace__lock;
    malloc_interface.malloc_unlock = malloc_replace__unlock;
    malloc_interface.malloc_end = malloc_replace__end;
    malloc_interface.malloc_add = malloc_replace__add;
    malloc_interface.malloc_is_pre_us = malloc_replace__is_pre_us;
    malloc_interface.malloc_is_pre_us_ex = malloc_replace__is_pre_us_ex;
    malloc_interface.malloc_chunk_size = malloc_replace__size;
    malloc_interface.malloc_chunk_size_invalid_only = malloc_replace__size_invalid_only;
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
    LOG(2, "%s: "PFX"-"PFX" 0x%x\n", __FUNCTION__, start, end, flags);
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
free_user_data_at_exit(malloc_info_t *info, void *iter_data)
{
    if (!info->pre_us) {
        chunk_header_t *head = header_from_ptr(info->base);
        if (head->user_data != NULL)
            client_malloc_data_free(head->user_data);
    }
    return true; /* keep iterating */
}

void
alloc_replace_exit(void)
{
    uint i;
#ifdef STATISTICS
    LOG(1, "alloc_replace statistics:\n");
    LOG(1, "  arenas:             %9d\n", num_arenas);
    LOG(1, "  peak arenas:        %9d\n", peak_num_arenas);
    LOG(1, "  heap capacity:      %9d\n", heap_capacity);
    LOG(1, "  peak heap capacity: %9d\n", peak_heap_capacity);
    LOG(1, "  splits:             %9d\n", num_splits);
    LOG(1, "  coalesces:          %9d\n", num_coalesces);
    LOG(1, "  deallocs:           %9d\n", num_dealloc);
    LOG(1, "  dbgcrt mismatches:  %9d\n", dbgcrt_mismatch);
    LOG(1, "  allocs left native: %9d\n", allocs_left_native);
#endif

    /* On Win10 at process exit, RtlLockHeap is called but the private
     * RtlUnlockProcessHeapOnProcessTerminate does the unlock and so
     * we don't see it.  This exiting thread should be the one who owns the lock.
     */
    if (dr_recurlock_self_owns(cur_arena->lock)) {
        LOG(2, "Process heap (arena="PFX") is locked at exit: unlocking\n", cur_arena);
        app_heap_unlock(dr_get_current_drcontext(), cur_arena->lock);
    }

    alloc_iterate(free_user_data_at_exit, NULL, false/*free too*/);
    /* XXX: should add hashtable_iterate() to drcontainers */
    for (i = 0; i < HASHTABLE_SIZE(pre_us_table.table_bits); i++) {
        hash_entry_t *he, *next;
        for (he = pre_us_table.table[i]; he != NULL; he = next) {
            chunk_header_t *head = (chunk_header_t *) he->payload;
            next = he->next;
            if (head->user_data != NULL)
                client_malloc_data_free(head->user_data);
            global_free(head, sizeof(*head), HEAPSTAT_WRAP);
        }
    }
    hashtable_delete_with_stats(&pre_us_table, "pre_us");

#ifdef WINDOWS
# ifdef X64
    replace_nosy_exit();
# endif

    /* Free any pre-us heaps that are still around */
    for (i = 0; i < HASHTABLE_SIZE(crtheap_handle_table.table_bits); i++) {
        hash_entry_t *he, *next;
        for (he = crtheap_handle_table.table[i]; he != NULL; he = next) {
            arena_header_t *arena = (arena_header_t *) he->payload;
            next = he->next;
            destroy_Rtl_heap(arena, NULL, false/*do not free indiv chunks*/);
        }
    }
#endif

    heap_region_iterate(free_arena_at_exit, NULL);

#ifdef WINDOWS
    if (alloc_ops.global_lock)
        dr_recurlock_destroy(global_lock);

    hashtable_delete_with_stats(&crtheap_mod_table, "crtheap");
    hashtable_delete_with_stats(&crtheap_handle_table, "crtheap handles");
#endif
}

/* Allocate application memory for clients.
 * This function can only be used with -replace_malloc and
 * does not work with malloc wrapping mode.
 */
byte *
client_app_malloc(void *drcontext, size_t size, app_pc caller)
{
    void *res;
    arena_header_t *arena = cur_arena;
    dr_mcontext_t mc;
    ASSERT(alloc_ops.replace_malloc, "-replace_malloc is not enabled");
    /* FIXME i#1837: provide better callstack */
    mc.size = sizeof(mc);
    mc.flags = DR_MC_CONTROL | DR_MC_INTEGER; /* xsp and xbp */
    dr_get_mcontext(drcontext, &mc);
    LOG(2, "client_app_malloc %d\n", size);
    /* we are on clean call stack already */
    res = replace_alloc_common(arena, size, 0, ALLOC_SYNCHRONIZE | ALLOC_INVOKE_CLIENT,
                               drcontext, &mc, caller,
                               MALLOC_ALLOCATOR_MALLOC);
    LOG(2, "client_app_malloc %d => "PFX"\n", size, res);
    return res;
}

/* Free application memory allocated from client_app_malloc.
 * This function can only be used with -replace_malloc and
 * does not work with malloc wrapping mode.
 */
void
client_app_free(void *drcontext, void *ptr, app_pc caller)
{
    arena_header_t *arena = cur_arena;
    dr_mcontext_t mc;
    ASSERT(alloc_ops.replace_malloc, "-replace_malloc is not enabled");
    /* FIXME i#1837: provide better callstack */
    mc.size = sizeof(mc);
    mc.flags = DR_MC_CONTROL | DR_MC_INTEGER; /* xsp and xbp */
    dr_get_mcontext(drcontext, &mc);
    LOG(2, "client_app_free "PFX"\n", ptr);
    /* we are on clean call stack already */
    replace_free_common(arena, ptr, ALLOC_SYNCHRONIZE | ALLOC_INVOKE_CLIENT,
                        drcontext, &mc, caller,
                        MALLOC_ALLOCATOR_MALLOC);
}
