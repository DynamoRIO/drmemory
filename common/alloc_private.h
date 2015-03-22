/* **********************************************************
 * Copyright (c) 2012-2015 Google, Inc.  All rights reserved.
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
 * alloc_private.h: Dr. Memory heap tracking internal header
 */

#ifndef _ALLOC_PRIVATE_H_
#define _ALLOC_PRIVATE_H_ 1

extern alloc_options_t alloc_ops;

/***************************************************************************
 * MALLOC ROUTINE TYPES
 */

typedef enum {
    HEAPSET_LIBC,
    HEAPSET_CPP,
#ifdef WINDOWS
    HEAPSET_LIBC_DBG,
    HEAPSET_CPP_DBG,
    HEAPSET_RTL,
#endif
    HEAPSET_NUM_TYPES,
} heapset_type_t;

typedef enum {
    /* For Linux and for Cygwin, and for any other allocator connected via
     * a to-be-implemented API (PR 406756)
     */
    /* Typically only one of these size routines is provided */
    HEAP_ROUTINE_SIZE_USABLE,
    HEAP_ROUTINE_SIZE_REQUESTED,
    HEAP_ROUTINE_MALLOC,
    HEAP_ROUTINE_REALLOC,
    HEAP_ROUTINE_FREE,
    /* BSD libc calloc simply calls malloc and then zeroes out
     * the resulting memory: thus, nothing special for us to watch.
     * But glibc calloc does its own allocating.
     */
    HEAP_ROUTINE_CALLOC,
    HEAP_ROUTINE_POSIX_MEMALIGN,
    HEAP_ROUTINE_MEMALIGN,
    HEAP_ROUTINE_VALLOC,
    HEAP_ROUTINE_PVALLOC,
    /* On Windows, we must watch debug operator delete b/c it reads
     * malloc's headers (i#26).  On both platforms we want to watch
     * the operators to find mismatches (i#123).
     */
    HEAP_ROUTINE_NEW,
    HEAP_ROUTINE_NEW_ARRAY,
    HEAP_ROUTINE_DELETE,
    HEAP_ROUTINE_DELETE_ARRAY,
    /* Malloc replacement needs to distinguish these */
    HEAP_ROUTINE_NEW_NOTHROW,
    HEAP_ROUTINE_NEW_ARRAY_NOTHROW,
    HEAP_ROUTINE_DELETE_NOTHROW,
    HEAP_ROUTINE_DELETE_ARRAY_NOTHROW,
    /* Group label for routines that might read heap headers but
     * need no explicit argument modification
     */
    HEAP_ROUTINE_STATS,
    /* Group label for un-handled routine */
    HEAP_ROUTINE_NOT_HANDLED,
    /* Should collapse these two once have aligned-malloc routine support */
    HEAP_ROUTINE_NOT_HANDLED_NOTIFY,
#ifdef UNIX
    HEAP_ROUTINE_LAST = HEAP_ROUTINE_NOT_HANDLED_NOTIFY,
# ifdef MACOS
    ZONE_ROUTINE_CREATE,
    ZONE_ROUTINE_DESTROY,
    ZONE_ROUTINE_DEFAULT,
    ZONE_ROUTINE_QUERY,
    ZONE_ROUTINE_MALLOC,
    ZONE_ROUTINE_CALLOC,
    ZONE_ROUTINE_VALLOC,
    ZONE_ROUTINE_REALLOC,
    ZONE_ROUTINE_MEMALIGN,
    ZONE_ROUTINE_FREE,
# endif
#else
    /* Debug CRT routines, which take in extra params */
    HEAP_ROUTINE_SIZE_REQUESTED_DBG,
    HEAP_ROUTINE_MALLOC_DBG,
    HEAP_ROUTINE_REALLOC_DBG,
    HEAP_ROUTINE_FREE_DBG,
    HEAP_ROUTINE_CALLOC_DBG,
    /* Free wrapper used in place of real delete or delete[] operators (i#722,i#655) */
    HEAP_ROUTINE_DebugHeapDelete,
    /* To avoid debug CRT checks (i#51) */
    HEAP_ROUTINE_SET_DBG,
    HEAP_ROUTINE_DBG_NOP_FALSE,
    HEAP_ROUTINE_DBG_NOP_TRUE,
    /* Just to get in_heap_routine set b/c calls internal heap routine directly (i#997) */
    HEAP_ROUTINE_GETPTD,
    /* FIXME PR 595798: for cygwin allocator we have to track library call */
    HEAP_ROUTINE_SBRK,
    HEAP_ROUTINE_LAST = HEAP_ROUTINE_SBRK,
    /* The primary routines we hook are the Rtl*Heap routines, in addition
     * to malloc routines in each library since some either do their own
     * internal parceling (PR 476805) or add padding for debug purposes
     * which we want to treat as unaddressable (DRi#284)
     */
    RTL_ROUTINE_MALLOC,
    RTL_ROUTINE_REALLOC,
    RTL_ROUTINE_FREE,
# ifdef X64
    /* i#995-c#3, RtlFreeStringRoutine is a pointer pointing to
     * NtdllpFreeStringRoutine, which may free memory by directly
     * calling RtlpFreeHeap.
     */
    RTL_ROUTINE_FREE_STRING,
# endif
    RTL_ROUTINE_VALIDATE,
    RTL_ROUTINE_SIZE,
    RTL_ROUTINE_CREATE,
    RTL_ROUTINE_DESTROY,
    RTL_ROUTINE_USERINFO_GET,
    RTL_ROUTINE_USERINFO_SET,
    RTL_ROUTINE_SETFLAGS,
    RTL_ROUTINE_HEAPINFO_GET,
    RTL_ROUTINE_HEAPINFO_SET,
    RTL_ROUTINE_CREATE_ACTCXT, /* for csrss-allocated memory: i#352 */
    RTL_ROUTINE_LOCK,
    RTL_ROUTINE_UNLOCK,
    RTL_ROUTINE_COMPACT,
    RTL_ROUTINE_ENUM,
    RTL_ROUTINE_GET_HEAPS,
    RTL_ROUTINE_WALK,
    RTL_ROUTINE_NYI,
    RTL_ROUTINE_SHUTDOWN,
    RTL_ROUTINE_LAST = RTL_ROUTINE_SHUTDOWN,
#endif
    HEAP_ROUTINE_COUNT,
    HEAP_ROUTINE_INVALID,
} routine_type_t;

#ifdef WINDOWS
static inline bool
is_rtl_routine(routine_type_t type)
{
    return (type > HEAP_ROUTINE_LAST && type <= RTL_ROUTINE_LAST);
}
#endif

static inline bool
is_size_routine(routine_type_t type)
{
    return (type == HEAP_ROUTINE_SIZE_USABLE || type == HEAP_ROUTINE_SIZE_REQUESTED
            IF_WINDOWS(|| type == RTL_ROUTINE_SIZE
                       || type == HEAP_ROUTINE_SIZE_REQUESTED_DBG));
}

static inline bool
is_size_requested_routine(routine_type_t type)
{
    return (type == HEAP_ROUTINE_SIZE_REQUESTED
            IF_WINDOWS(|| type == RTL_ROUTINE_SIZE
                       || type == HEAP_ROUTINE_SIZE_REQUESTED_DBG));
}

static inline bool
is_free_routine(routine_type_t type)
{
    return (type == HEAP_ROUTINE_FREE
            IF_WINDOWS(|| type == RTL_ROUTINE_FREE
                       || type == HEAP_ROUTINE_FREE_DBG
                       IF_X64(|| type == RTL_ROUTINE_FREE_STRING)));
}

static inline bool
is_malloc_routine(routine_type_t type)
{
    return (type == HEAP_ROUTINE_MALLOC
            IF_WINDOWS(|| type == RTL_ROUTINE_MALLOC|| type == HEAP_ROUTINE_MALLOC_DBG));
}

static inline bool
is_realloc_routine(routine_type_t type)
{
    return (type == HEAP_ROUTINE_REALLOC
            IF_WINDOWS(|| type == RTL_ROUTINE_REALLOC|| type == HEAP_ROUTINE_REALLOC_DBG));
}

static inline bool
is_calloc_routine(routine_type_t type)
{
    return (type == HEAP_ROUTINE_CALLOC IF_WINDOWS(|| type == HEAP_ROUTINE_CALLOC_DBG));
}

static inline bool
is_new_routine(routine_type_t type)
{
    return (type == HEAP_ROUTINE_NEW || type == HEAP_ROUTINE_NEW_ARRAY ||
            type == HEAP_ROUTINE_NEW_NOTHROW || type == HEAP_ROUTINE_NEW_ARRAY_NOTHROW);
}

static inline bool
is_delete_routine(routine_type_t type)
{
    return (type == HEAP_ROUTINE_DELETE || type == HEAP_ROUTINE_DELETE_ARRAY ||
            type == HEAP_ROUTINE_DELETE_NOTHROW ||
            type == HEAP_ROUTINE_DELETE_ARRAY_NOTHROW);
}

static inline bool
is_operator_nothrow_routine(routine_type_t type)
{
    return (type == HEAP_ROUTINE_NEW_NOTHROW ||
            type == HEAP_ROUTINE_NEW_ARRAY_NOTHROW ||
            type == HEAP_ROUTINE_DELETE_NOTHROW ||
            type == HEAP_ROUTINE_DELETE_ARRAY_NOTHROW);
}

static inline routine_type_t
convert_operator_to_nothrow(routine_type_t type)
{
    switch (type) {
    case HEAP_ROUTINE_NEW: return HEAP_ROUTINE_NEW_NOTHROW;
    case HEAP_ROUTINE_NEW_ARRAY: return HEAP_ROUTINE_NEW_ARRAY_NOTHROW;
    case HEAP_ROUTINE_DELETE: return HEAP_ROUTINE_DELETE_NOTHROW;
    case HEAP_ROUTINE_DELETE_ARRAY: return HEAP_ROUTINE_DELETE_ARRAY_NOTHROW;
    default: ASSERT(false, "not an (non-nothrow) operator type");
    }
    return type; /* fail gracefully */
}

/***************************************************************************
 * Allocation types
 */

enum {
    /* These are to distinguish whether from malloc, new, or new[] (i#123).
     * 4 states using MALLOC_RESERVED_3 and MALLOC_RESERVED_4.
     * XXX: I tried also distinguishing HeapAlloc/RtlAllocateHeap
     * but I hit a lot of false positives w/ even a small test app
     * where free() would free: did not investigate (for one thing,
     * HeapAlloc just forwards to RtlAllocateHeap).
     *
     * XXX: we could report mismatches on operator regular vs nothrow
     * but it doesn't seem worth it.
     */
    /* N.B.: MALLOC_RESERVED_[1-2] and MALLOC_RESERVED_[5-8] are defined in
     * alloc.c for wrapping and alloc_replace.c for replacing
     */
    MALLOC_ALLOCATOR_FLAGS     = (MALLOC_RESERVED_3 | MALLOC_RESERVED_4),
    MALLOC_ALLOCATOR_UNKNOWN   = 0x0,
    MALLOC_ALLOCATOR_MALLOC    = MALLOC_RESERVED_3,
    MALLOC_ALLOCATOR_NEW       = MALLOC_RESERVED_4,
    MALLOC_ALLOCATOR_NEW_ARRAY = (MALLOC_RESERVED_3 | MALLOC_RESERVED_4),
};

static inline const char *
malloc_alloc_type_name(uint flags)
{
    if (flags == MALLOC_ALLOCATOR_NEW) /* yes, == not TEST */
        return "operator new";
    else if (flags == MALLOC_ALLOCATOR_NEW_ARRAY)
        return "operator new[]";
    else {
        /* We could store the actual name ("HeapAlloc", "calloc", _malloc_dbg",
         * "memalign", etc.) but that would cost too much memory to keep per
         * malloc, and this should be clear enough for most users.
         */
        return "malloc";
    }
}

static inline const char *
malloc_free_type_name(uint flags)
{
    if (flags == MALLOC_ALLOCATOR_NEW) /* yes, == not TEST */
        return "operator delete";
    else if (flags == MALLOC_ALLOCATOR_NEW_ARRAY)
        return "operator delete[]";
    else {
        /* We could store the actual name ("HeapAlloc", "calloc", _malloc_dbg",
         * "memalign", etc.) but that would cost too much memory to keep per
         * malloc, and this should be clear enough for most users.
         */
        return "free";
    }
}

/***************************************************************************
 * Malloc tracking API
 */

struct _alloc_routine_entry_t;
typedef struct _alloc_routine_entry_t alloc_routine_entry_t;

typedef struct _malloc_interface_t {
    void (*malloc_lock)(void);
    void (*malloc_unlock)(void);
    app_pc (*malloc_end)(app_pc start);
    void (*malloc_add)(app_pc start, app_pc end, app_pc real_end, bool pre_us,
                       uint client_flags, dr_mcontext_t *mc, app_pc post_call);
    bool (*malloc_is_pre_us)(app_pc start);
    bool (*malloc_is_pre_us_ex)(app_pc start, bool ok_if_invalid);
    ssize_t (*malloc_chunk_size)(app_pc start);
    ssize_t (*malloc_chunk_size_invalid_only)(app_pc start);
    void * (*malloc_get_client_data)(app_pc start);
    uint (*malloc_get_client_flags)(app_pc start);
    bool (*malloc_set_client_flag)(app_pc start, uint client_flag);
    bool (*malloc_clear_client_flag)(app_pc start, uint client_flag);
    void (*malloc_iterate)(malloc_iter_cb_t cb, void *iter_data);
    void (*malloc_intercept)(app_pc pc, routine_type_t type, alloc_routine_entry_t *e,
                             bool check_mismatch, bool check_winapi_match);
    void (*malloc_unintercept)(app_pc pc, routine_type_t type, alloc_routine_entry_t *e,
                               bool check_mismatch, bool check_winapi_match);
    /* For storing data per malloc routine set.  The pc is one routine from the set.
     * When type == HEAPSET_LIBC_DBG, libc_data points at the data (returned from an
     * earlier call) for the corresponding HEAPSET_LIBC for that module.
     * HEAPSET_LIBC is guaranteed to be called before HEAPSET_LIBC_DBG.
     */
    void * (*malloc_set_init)(heapset_type_t type, app_pc pc, const module_data_t *mod,
                              void *libc_data);
    /* Returns the new libc data */
    void (*malloc_set_exit)(heapset_type_t type, app_pc pc, void *user_data);
} malloc_interface_t;

extern malloc_interface_t malloc_interface;

/* XXX i#882: remove from header once malloc replacement replaces operators */
void
malloc_wrap__intercept(app_pc pc, routine_type_t type, alloc_routine_entry_t *e,
                       bool check_mismatch, bool check_winapi_match);

void
malloc_wrap__unintercept(app_pc pc, routine_type_t type, alloc_routine_entry_t *e,
                         bool check_mismatch, bool check_winapi_match);

/* Retrieves the libc set data, if the libc sets exists; else the individual set */
void *
alloc_routine_set_get_user_data(alloc_routine_entry_t *e);

/* Updates the libc set data, if the libc sets exists; else the individual set */
bool
alloc_routine_set_update_user_data(app_pc member_func, void *new_data);

app_pc
alloc_routine_get_module_base(alloc_routine_entry_t *e);

bool
check_for_private_debug_delete(app_pc caller);

/***************************************************************************
 * Large malloc tree
 */

/* PR 525807: to handle malloc-based stacks we need an interval tree
 * for large mallocs.  Putting all mallocs in a tree instead of a table
 * is too expensive (PR 535568).
 */
#define LARGE_MALLOC_MIN_SIZE 12*1024

void
malloc_large_add(byte *start, size_t size);

void
malloc_large_remove(byte *start);

void
malloc_large_iterate(bool (*iter_cb)(byte *start, size_t size, void *data),
                     void *iter_data);

#endif /* _ALLOC_PRIVATE_H_ */
