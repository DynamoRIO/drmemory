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
 * alloc_private.h: Dr. Memory heap tracking internal header
 */

#ifndef _ALLOC_PRIVATE_H_
#define _ALLOC_PRIVATE_H_ 1

extern alloc_options_t alloc_ops;

/***************************************************************************
 * MALLOC ROUTINE TYPES
 */

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
    /* Group label for routines that might read heap headers but
     * need no explicit argument modification
     */
    HEAP_ROUTINE_STATS,
    /* Group label for un-handled routine */
    HEAP_ROUTINE_NOT_HANDLED,
    /* Should collapse these two once have aligned-malloc routine support */
    HEAP_ROUTINE_NOT_HANDLED_NOTIFY,
#ifdef LINUX
    HEAP_ROUTINE_LAST = HEAP_ROUTINE_NOT_HANDLED_NOTIFY,
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
    HEAP_ROUTINE_DBG_NOP,
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
    RTL_ROUTINE_VALIDATE,
    RTL_ROUTINE_SIZE,
    RTL_ROUTINE_CREATE,
    RTL_ROUTINE_DESTROY,
    RTL_ROUTINE_GETINFO,
    RTL_ROUTINE_SETINFO,
    RTL_ROUTINE_SETFLAGS,
    RTL_ROUTINE_HEAPINFO,
    RTL_ROUTINE_CREATE_ACTCXT, /* for csrss-allocated memory: i#352 */
    RTL_ROUTINE_LOCK,
    RTL_ROUTINE_UNLOCK,
    RTL_ROUTINE_QUERY,
    RTL_ROUTINE_NYI,
    RTL_ROUTINE_SHUTDOWN,
    RTL_ROUTINE_LAST = RTL_ROUTINE_SHUTDOWN,
#endif
    HEAP_ROUTINE_COUNT,
} routine_type_t;

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
            IF_WINDOWS(|| type == RTL_ROUTINE_FREE || type == HEAP_ROUTINE_FREE_DBG));
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
    return (type == HEAP_ROUTINE_NEW || type == HEAP_ROUTINE_NEW_ARRAY);
}

static inline bool
is_delete_routine(routine_type_t type)
{
    return (type == HEAP_ROUTINE_DELETE || type == HEAP_ROUTINE_DELETE_ARRAY);
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
    ssize_t (*malloc_size)(app_pc start);
    ssize_t (*malloc_size_invalid_only)(app_pc start);
    void * (*malloc_get_client_data)(app_pc start);
    uint (*malloc_get_client_flags)(app_pc start);
    bool (*malloc_set_client_flag)(app_pc start, uint client_flag);
    bool (*malloc_clear_client_flag)(app_pc start, uint client_flag);
    void (*malloc_iterate)(malloc_iter_cb_t cb, void *iter_data);
    void (*malloc_intercept)(app_pc pc, routine_type_t type, alloc_routine_entry_t *e);
    void (*malloc_unintercept)(app_pc pc, routine_type_t type, alloc_routine_entry_t *e);
} malloc_interface_t;

extern malloc_interface_t malloc_interface;

/* XXX i#882: remove from header once malloc replacement replaces operators */
void
malloc_wrap__intercept(app_pc pc, routine_type_t type, alloc_routine_entry_t *e);

void
malloc_wrap__unintercept(app_pc pc, routine_type_t type, alloc_routine_entry_t *e);

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
