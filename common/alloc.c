/* **********************************************************
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
 * alloc.c: Dr. Memory heap tracking
 */

/* Malloc/free replacement w/ own routines vs using original versions: 
 * 
 * Pro original: 
 * * Must use original versions to apply to replayed execution 
 *   Note that the headers can function as mini-redzones for replay as well
 * * Don't have to duplicate all of the flags, alignment, features of 
 *   Windows heap allocators that apps might be depending on! 
 *   Windows heaps are more complex than Unix: multiple heaps, 
 *   extra features like zeroing, etc. 
 *   And never know whether some other part of system is going to 
 *   make calls into heap subsystem beyond just malloc+free. 
 * 
 * Con original: 
 * * Alloc code is instrumented but must ignore its accesses to headers 
 * * Harder to delay frees 
 * * Don't know header flags: but can find sizes by storing in redzone 
 *   or (replay-compatible) calling malloc_usable_size() (Linux only)
 *   (RtlSizeHeap returns asked-for size)
 */

/*
System call and library routines we need to watch:

* NtMapViewOfSection => addressable and defined, whether image or data file
* NtUnmapViewOfSection => no longer addressable
* NtAllocateVirtualMemory: if for VirtualAlloc, then addressable and defined;
  if for HeapAlloc, then neither.  I'm using my reserve-then-commit heuristic
  to distinguish, combined w/ the currently-in-heap-routine var.
* MapUserPhysicalPages: NYI for now

* kernel32!Heap* calls ntdll!Rtl*Heap; can probably ignore everything
  the kernel32 routines do

* RtlAllocateHeap => addressable; if pass HEAP_ZERO_MEMORY then defined as well.
* RtlReAllocateHeap => transfer current addressability and definedness state
* RtlFreeHeap => no longer defined or addressable
* alloca => just adjusts esp so we need do nothing special except for its
  guard page probes

* RtlCreateHeap, RtlDestroyHeap: to suppress false positives where
  heap routines that aren't exported (like RtlpHeapIsLocked) read from
  heap headers, we track the heap regions.  We also track all exported
  heap routine entry and exits to suppress their heap reads and
  writes.  We also use these to distinguish VirtualAlloc from HeapAlloc.
  How track heaps?  RtlCreateHeap => single reservation, so can
  use return value and query to find the extent: but can have subheaps
  chained together, so we watch the syscalls for both reserving and freeing.

  FIXME: verify that RtlDestroyHeap calls NtFreeVirtualMemory and I
  catch its heap region removal: for sub-heaps have to be there,
  unless reverse-engineer heap format.  Ask Sam if he did sub-heaps.

* RtlCompactHeap: should be able to ignore:
  "compacts the heap by coalescing adjacent free blocks of memory and
  decommitting large free blocks of memory"
* RtlExtendHeap: no msdn pages on it: probably just increases maximum size of
  heap itself, not of individual allocations
* RtlWalkHeap: could use that plus GetProcessHeaps to walk all heaps at
  init time

* LocalAlloc: LMEM_ZEROINIT = 0x0040
  FIXME: LMEM_MOVEABLE is strange: LocalLock locks it to an address, and LocalReAlloc 
  makes it moveable again: what's the purpose? 
  It looks like it ends up calling RtlAllocateHeap, and LocalReAlloc calls
  RtlReAllocateHeap, so we can probably just watch the Rtl routines.
  FIXME: I don't see how 0x40 is translated to 0x8 for zeroing.
  I do see 0x140000 being or-ed in: so it asks for +x, and some secret flag.
* ditto with GlobalAlloc

* STL strings use custom allocation but there is a flag to turn that
  off at compile time?

* TLS slots: keep unaddressable until kernel32!TlsAlloc.
  Or, at unaddressable exception time, check the bit.

* outer layers sometimes add debug features including their own redzones:
  so we need to intercept the outermost layer (PR 476805)

* cygwin malloc uses its own heap (PR 476805, PR 595798)

* various additional heap routines (PR 406323: memalign, valloc, pvalloc, etc.,
  PR 595802: _recalloc, _aligned_offset_malloc, etc.)

msvcrt!malloc =>
msvcrt!_heap_alloc+0xd1:
77c2c3c3 ff15f410c177     call  dword ptr [msvcrt!_imp__HeapAlloc (77c110f4)]
0:001> U @@(*(int *)0x77c110f4)
ntdll!RtlAllocateHeap:

HeapAlloc: http://msdn2.microsoft.com/en-us/library/aa366597.aspx
RtlAllocateHeap is presumably identical since we have forwarders:
  LPVOID WINAPI HeapAlloc(
    __in          HANDLE hHeap,
    __in          DWORD dwFlags,
    __in          SIZE_T dwBytes
  );
flag to pay attention to is HEAP_ZERO_MEMORY = 0x00000008
If the function succeeds, the return value is a pointer to the allocated memory block.

See ~/extsw/wine-0.9.44/dlls/ntdll/heap.c
See ~/extsw/ReactOS-0.3.1/lib/rtl/heap.c
 */

/* Interception strategy for routines where we want to change the
 * return value (Rtl{,Re}AllocateHeap, RtlSizeHeap) as well as know
 * when we're in there (Rtl{Create,Allocate}Heap):
 *
 * --------------------------------------------------
 * Solution #1: As it is difficult to find all return points from a
 * function, we watch the call sites.  We use the callee entry point
 * as our pre-call instrumentation point.  There we also look at the
 * retaddr and add it to a list of post-call instrumentation points.
 * If a fragment already exists at that point we flush it.
 * We used to try and avoid flushes for post-call by watching for
 * direct calls and calls/jmps through IAT or PLT but it ended up
 * causing problems (PR 406714), and in most cases there should be no
 * flush as the retaddr should only be reached after the call.
 *
 * Note that there are recursive calls
 *  sam: instrumenting RtlAllocHeap directly is becoming a huge pain because it looks like it calls itself recursively 
 * => we have in_heap_routine as a counter, but we use in_heap_adjusted to
 * avoid adjusting heap routine arguments twice
 *
 * --------------------------------------------------
 * Solution #2: do depth-first or breadth-first search and find return point:
 * they all seem to have a single return instruction.  But can't really rely
 * on that.  OTOH, even if multiple rets, unless there's a switch or other jmp*
 * should be able to find all the rets.
 * 
 */

/* When RtlAllocateHeap/malloc pad the asked-for size to a certain alignment,
 * better to use the size the app asked for since it shouldn't write to the
 * extra space anyway.  RtlSizeHeap returns the asked-for space, but
 * malloc_usable_size returns the padded size.
 */

#include "dr_api.h"
#include "alloc.h"
#include "heap.h"
#include "callstack.h"
#include "redblack.h"
#ifdef LINUX
# include "sysnum_linux.h"
# include <sys/mman.h>
#else
# include "windefs.h"
# include "drsyms.h"
#endif
#include <string.h>

#ifdef LINUX
typedef struct {
    unsigned long addr;
    unsigned long len;
    unsigned long prot;
    unsigned long flags;
    unsigned long fd;
    unsigned long offset;
} mmap_arg_struct_t;
#endif

/* Options */
static bool op_track_allocs;
static bool op_track_heap;
static size_t op_redzone_size;
static bool op_size_in_redzone;
static bool op_record_allocs;
/* Should we try to figure out the padded size of allocs?
 * It's not easy on Windows.
 */
static bool op_get_padded_size;

#ifdef WINDOWS
/* system calls we want to intercept */
int sysnum_mmap;
int sysnum_munmap;
int sysnum_valloc;
int sysnum_vfree;
int sysnum_cbret;
int sysnum_continue;
int sysnum_setcontext;
#endif

#ifdef STATISTICS
uint post_call_flushes;
uint num_mallocs;
uint num_large_mallocs;
uint num_frees;
#endif

/* only used if op_track_heap */
static void
handle_alloc_pre_ex(app_pc call_site, app_pc expect, bool indirect,
                    app_pc actual, bool inside);

#ifdef LINUX
app_pc
get_brk(void)
{
    return (app_pc) raw_syscall_1arg(SYS_brk, 0);
}
#endif

/***************************************************************************
 * MALLOC ROUTINES
 */

#ifdef WINDOWS
/* ntdll kernel-entry hook points */
app_pc addr_KiAPC;
app_pc addr_KiCallback;
app_pc addr_KiException;
app_pc addr_KiRaise;
#endif /* WINDOWS */

/* We need to track multiple sets of library routines and multiple layers
 * (xref PR 476805, DRi#284) so we need a hashtable of entry points
 */
#define ALLOC_ROUTINE_TABLE_HASH_BITS 6
static hashtable_t alloc_routine_table;
static void *alloc_routine_lock; /* protects alloc_routine_table */

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
#ifdef LINUX
    HEAP_ROUTINE_LAST = HEAP_ROUTINE_CALLOC,
#else
    /* Debug CRT routines, which take in extra params */
    HEAP_ROUTINE_SIZE_REQUESTED_DBG,
    HEAP_ROUTINE_MALLOC_DBG,
    HEAP_ROUTINE_REALLOC_DBG,
    HEAP_ROUTINE_FREE_DBG,
    HEAP_ROUTINE_CALLOC_DBG,
    /* We must watch debug operator delete b/c it reads malloc's headers (i#26)! */
    HEAP_ROUTINE_DELETE,
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
    RTL_ROUTINE_LOCK,
    RTL_ROUTINE_UNLOCK,
    RTL_ROUTINE_SHUTDOWN,
    RTL_ROUTINE_LAST = RTL_ROUTINE_SHUTDOWN,
#endif
    HEAP_ROUTINE_INVALID,
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

typedef struct _possible_alloc_routine_t {
    const char *name;
    routine_type_t type;
} possible_alloc_routine_t;

static const possible_alloc_routine_t possible_libc_routines[] = {
    /* we rely on size entries being first, in preference order */
    { "malloc_usable_size", HEAP_ROUTINE_SIZE_USABLE },
#ifdef WINDOWS
    { "_msize", HEAP_ROUTINE_SIZE_REQUESTED },
#endif
    { "malloc", HEAP_ROUTINE_MALLOC },
    { "realloc", HEAP_ROUTINE_REALLOC }, 
    { "free", HEAP_ROUTINE_FREE },
    { "calloc", HEAP_ROUTINE_CALLOC },
    /* FIXME PR 406323: memalign, valloc, pvalloc, etc. */
#ifdef WINDOWS
    /* the _impl versions are sometimes called directly 
     * XXX: there are also _base versions but they always call _impl?
     */
    { "malloc_impl", HEAP_ROUTINE_MALLOC },
    { "realloc_impl", HEAP_ROUTINE_REALLOC }, 
    { "free_impl", HEAP_ROUTINE_FREE },
    { "calloc_impl", HEAP_ROUTINE_CALLOC },
    /* for cygwin */
    { "sbrk", HEAP_ROUTINE_SBRK },
    /* FIXME PR 595802: _recalloc, _aligned_offset_malloc, etc. */
#endif
};
#define POSSIBLE_LIBC_ROUTINE_NUM \
    (sizeof(possible_libc_routines)/sizeof(possible_libc_routines[0]))

#ifdef WINDOWS
static const possible_alloc_routine_t possible_dbgcrt_routines[] = {
    /* we rely on size entries being first, in preference order */
    { "_msize_dbg", HEAP_ROUTINE_SIZE_REQUESTED_DBG },
    { "_malloc_dbg", HEAP_ROUTINE_MALLOC_DBG },
    { "_realloc_dbg", HEAP_ROUTINE_REALLOC_DBG }, 
    { "_free_dbg", HEAP_ROUTINE_FREE_DBG },
    { "_calloc_dbg", HEAP_ROUTINE_CALLOC_DBG },
    /* the _impl versions are sometimes called directly 
     * XXX: there are also _base versions but they always call _impl?
     */
    { "_malloc_dbg_impl", HEAP_ROUTINE_MALLOC_DBG },
    { "_realloc_dbg_impl", HEAP_ROUTINE_REALLOC_DBG }, 
    { "_free_dbg_impl", HEAP_ROUTINE_FREE_DBG },
    { "_calloc_dbg_impl", HEAP_ROUTINE_CALLOC_DBG },
    /* FIXME PR 595802: _recalloc_dbg, _aligned_offset_malloc_dbg, etc. */
};
#define POSSIBLE_DBGCRT_ROUTINE_NUM \
    (sizeof(possible_dbgcrt_routines)/sizeof(possible_dbgcrt_routines[0]))

static const possible_alloc_routine_t possible_rtl_routines[] = {
    /* we rely on size entries being first, in preference order */
    { "RtlSizeHeap", RTL_ROUTINE_SIZE },
    { "RtlAllocateHeap", RTL_ROUTINE_MALLOC },
    { "RtlReAllocateHeap", RTL_ROUTINE_REALLOC },
    { "RtlFreeHeap", RTL_ROUTINE_FREE },
    { "RtlValidateHeap", RTL_ROUTINE_VALIDATE },
    { "RtlCreateHeap", RTL_ROUTINE_CREATE },
    { "RtlDestroyHeap", RTL_ROUTINE_DESTROY },
    { "RtlGetUserInfoHeap", RTL_ROUTINE_GETINFO },
    { "RtlSetUserValueHeap", RTL_ROUTINE_SETINFO },
    { "RtlSetUserFlagsHeap", RTL_ROUTINE_SETFLAGS },
    { "RtlSetHeapInformation", RTL_ROUTINE_HEAPINFO },
    /* kernel32!LocalFree calls these.  these call RtlEnterCriticalSection
     * and ntdll!RtlpCheckHeapSignature and directly touch heap headers.
     */
    { "RtlLockHeap", RTL_ROUTINE_LOCK },
    { "RtlUnlockHeap", RTL_ROUTINE_UNLOCK },
    /* RtlpHeapIsLocked is a non-exported routine that is called directly
     * from LdrShutdownProcess: so we treat the latter as a heap routine
     * XXX: now that we have online symbols can we replace w/ RtlpHeapIsLocked?
     */
    { "LdrShutdownProcess", RTL_ROUTINE_SHUTDOWN },
};
#define POSSIBLE_RTL_ROUTINE_NUM \
    (sizeof(possible_rtl_routines)/sizeof(possible_rtl_routines[0]))

static bool
is_rtl_routine(routine_type_t type)
{
    return (type > HEAP_ROUTINE_LAST && type <= RTL_ROUTINE_LAST);
}
#endif

/* Each entry in the alloc_routine_table */
typedef struct _alloc_routine_entry_t {
    app_pc pc;
    routine_type_t type;
    const char *name;
    /* The malloc_usable_size() from the same library */
    struct _alloc_routine_entry_t *size_func;
    /* Whether redzones are used: we don't for msvcrtdbg (i#26) */
    bool use_redzone;
    /* Let user store a field per malloc set, kept in each entry of malloc
     * set for convenience
     */
    void *client;
    /* Easiest way to clean up client field is to have ref count: we hide
     * it from client
     */
    uint *client_refcnt;
    /* Once we have an API for custom allocators (PR 406756) will we need a
     * separate name field, or we'll just call them by their type names?
     */
} alloc_routine_entry_t;

/* lock is held when this is called */
static void
alloc_routine_entry_free(void *p)
{
    alloc_routine_entry_t *e = (alloc_routine_entry_t *) p;
    if (e->client_refcnt != NULL) {
        ASSERT(e->client_refcnt != NULL && *e->client_refcnt > 0, "invalid refcnt");
        (*e->client_refcnt)--;
        if ((*e->client_refcnt) == 0) {
            client_remove_malloc_routine(e->client);
            global_free(e->client_refcnt, sizeof(*e->client_refcnt), HEAPSTAT_HASHTABLE);
        }
    }
    global_free(e, sizeof(*e), HEAPSTAT_HASHTABLE);
}

static bool
is_alloc_routine(app_pc pc)
{
    bool found = false;
    dr_mutex_lock(alloc_routine_lock);
    found = (hashtable_lookup(&alloc_routine_table, (void *)pc) != NULL);
    dr_mutex_unlock(alloc_routine_lock);
    return found;
}

#if defined(WINDOWS) || defined(DEBUG)
static const char *
get_alloc_routine_name(app_pc pc)
{
    alloc_routine_entry_t *e;
    const char *name = "<not found>";
    dr_mutex_lock(alloc_routine_lock);
    e = hashtable_lookup(&alloc_routine_table, (void *)pc);
    if (e != NULL)
        name = e->name;
    dr_mutex_unlock(alloc_routine_lock);
    return name;
}
#endif

/* Rather than requiring the caller to hold the hashtable lock, we
 * return a copy of the data.  These entries have lifetimes equal to
 * the app's libraries, so really no entry should become invalid while
 * processing an app call into that library, but our call into the
 * size routine could fail if the app library is racily unloaded.
 */
static bool
get_alloc_entry(app_pc pc, alloc_routine_entry_t *entry)
{
    alloc_routine_entry_t *e;
    bool found = false;
    dr_mutex_lock(alloc_routine_lock);
    e = hashtable_lookup(&alloc_routine_table, (void *)pc);
    if (e != NULL) {
        memcpy(entry, e, sizeof(*entry));
        found = true;
    }
    dr_mutex_unlock(alloc_routine_lock);
    return found;
}

#ifdef WINDOWS
static bool
is_alloc_sysroutine(app_pc pc)
{
    /* Should switch to table if add many more syscalls */
    return (pc == addr_KiAPC || pc == addr_KiCallback ||
            pc == addr_KiException || pc == addr_KiRaise);
}
#endif

static app_pc
lookup_symbol_or_export(const module_data_t *mod, const char *name)
{
#ifdef USE_DRSYMS
    if (mod->full_path != NULL) {
        app_pc res = lookup_symbol(mod, name);
        if (res != NULL)
            return res;
    }
#endif
    return (app_pc) dr_get_proc_address(mod->handle, name);
}

/* caller must hold alloc routine lock */
static alloc_routine_entry_t *
add_alloc_routine(app_pc pc, routine_type_t type, const char *name, bool use_redzone,
                  alloc_routine_entry_t *size_func, bool size_func_self,
                  void *client, uint *client_refcnt)
{
    alloc_routine_entry_t *e;
    IF_DEBUG(bool is_new;)
    e = global_alloc(sizeof(*e), HEAPSTAT_HASHTABLE);
    e->pc = pc;
    e->type = type;
    e->name = name;
    e->use_redzone = (use_redzone && op_redzone_size > 0);
    e->size_func = (size_func_self ? e : size_func);
    e->client = client;
    e->client_refcnt = client_refcnt;
    if (e->client_refcnt != NULL)
        (*e->client_refcnt)++;
    IF_DEBUG(is_new = )
        hashtable_add(&alloc_routine_table, (void *)pc, (void *)e);
    ASSERT(is_new, "alloc entry should not already exist");
    return e;
}

/* caller must hold alloc routine lock */
static void
find_alloc_routines(const module_data_t *mod, const possible_alloc_routine_t *possible,
                    uint num_possible, bool use_redzone, bool expect_all)
{
    alloc_routine_entry_t *size_func = NULL;
    void *client = NULL;
    uint *client_refcnt = NULL;
    int i;
    bool new_set = false;
#ifdef DEBUG
    const char *modname = dr_module_preferred_name(mod);
#endif
    for (i = 0; i < num_possible; i++) {
        alloc_routine_entry_t *e;
        app_pc pc = lookup_symbol_or_export(mod, possible[i].name);
        ASSERT(!expect_all || pc != NULL, "expect to find all alloc routines");
#ifdef LINUX
        /* PR 604274: sometimes undefined symbol has a value pointing at PLT:
         * we do not want to try and intercept that.
         * Ideally DR should exclude these weird symbols: that's i#341.
         * XXX: at least check whether in PLT: but would want i#76 (elf
         * section iterator) for that.
         * For now using a hack by decoding and looking for jmp*.
         * Someone hooking one of our targets would presumably use direct jmp.
         */
        if (pc != NULL) {
            char buf[16];
            if (safe_read(pc, sizeof(buf), buf)) {
                instr_t inst;
                void *drcontext = dr_get_current_drcontext();
                instr_init(drcontext, &inst);
                decode(drcontext, pc, &inst);
                if (!instr_valid(&inst) || instr_get_opcode(&inst) == OP_jmp_ind)
                    pc = NULL;
                instr_free(drcontext, &inst);
            } else
                pc = NULL;
            if (pc == NULL) {
                LOG(1, "NOT intercepting PLT or invalid %s in module %s\n",
                    possible[i].name, (modname == NULL) ? "<noname>" : modname);
            }
        }
#endif
        if (pc != NULL) {
            if (!new_set) {
                client = client_add_malloc_routine(pc);
                client_refcnt = (uint *)
                    global_alloc(sizeof(*client_refcnt), HEAPSTAT_HASHTABLE);
                *client_refcnt = 0;
            }
            e = add_alloc_routine(pc, possible[i].type, possible[i].name, use_redzone,
                                  size_func, !new_set, client, client_refcnt);
            LOG(1, "intercepting %s @"PFX" size_func="PFX" in module %s\n",
                possible[i].name, pc, (size_func == NULL) ? NULL : size_func->pc,
                (modname == NULL) ? "<noname>" : modname);
            if (!new_set) {
                new_set = true;
                size_func = e;
                ASSERT(e->size_func == size_func, "add_alloc_routine changed?");
            }
        }
        if (i == HEAP_ROUTINE_SIZE_USABLE) {
            ASSERT(i == 0, "usable size must be first routine");
#ifdef LINUX
            /* libc's malloc_usable_size() is used during initial heap walk */
            if (mod->start == get_libc_base()) {
                ASSERT(pc != NULL, "no malloc_usable_size in libc!");
                malloc_usable_size = (size_t(*)(void *)) pc;
            }
#endif
        }
    }
}

static size_t
redzone_size(alloc_routine_entry_t *routine)
{
    return (routine->use_redzone ? op_redzone_size : 0);
}

/***************************************************************************
 * MALLOC SIZE
 */

#ifdef WINDOWS
typedef size_t (__stdcall *rtl_size_func_t)(IN reg_t /*really HANDLE*/ Heap,
                                            IN ULONG flags,
                                            IN PVOID ptr);
typedef size_t (*dbg_size_func_t)(IN byte *pc, int blocktype);
#else
/* points at libc's version, used in initial heap walk */
alloc_size_func_t malloc_usable_size;
#endif

/* malloc_usable_size exported, so declared in alloc.h */

static ssize_t
get_size_from_app_routine(IF_WINDOWS_(reg_t auxarg) app_pc real_base,
                          alloc_routine_entry_t *routine)
{
    ssize_t sz;
#ifdef WINDOWS
    if (is_rtl_routine(routine->type)) {
        /* auxarg is heap */
        reg_t heap = auxarg;
        ASSERT(heap != (reg_t)INVALID_HANDLE_VALUE && real_base != NULL, "invalid params");
        /* I used to use GET_NTDLL(RtlSizeHeap...)
         * but DR's private loader turned it into redirect_RtlSizeHeap
         * so going w/ what we stored from lookup
         */
        ASSERT(routine->size_func != NULL, "invalid size func");
        /* 0 is an invalid value for a heap handle */
        if (heap == 0)
            return -1;
        else
            return (*(rtl_size_func_t)(routine->size_func->pc))(heap, 0, real_base);
    }
#endif
    if (routine->size_func != NULL) {
        /* WARNING: this is dangerous and a transparency violation since we're
         * calling an app library routine here, which can acquire an app lock.
         * We try to only do real handling in pre- and post- of outermost malloc
         * layers, where the app lock should NOT already be held, so we won't
         * have any conflicts with, say, malloc_lock.  We avoid asking for
         * malloc lock on inner layers by using
         * malloc_entry_exists_racy_nolock() for recursive handle_free_pre()
         * (I have seen a deadlock when acquiring malloc lock there for
         * RtlFreeHeap while holding app lock, and another thread has malloc
         * lock at _free_dbg() and wants app lock while calling _size_dbg()).
         */
#ifdef WINDOWS
        if (routine->size_func->type == HEAP_ROUTINE_SIZE_REQUESTED_DBG) {
            /* auxarg is blocktype */
            sz = (*(dbg_size_func_t)(routine->size_func->pc))(real_base, auxarg);
        } else
#endif
            sz = (*(alloc_size_func_t)(routine->size_func->pc))(real_base);
        /* Note that malloc(0) has usable size > 0 */
        if (routine->size_func->type == HEAP_ROUTINE_SIZE_USABLE && sz == 0)
            return -1;
        else
            return sz;
    }
    return -1;
}

/* Returns the size of an allocation as known to the underlying system
 * allocator (libc's malloc(), etc. for Linux, ntdll's Rtl*Heap for
 * Windows).  Unfortunately the interface exposed by the two return
 * different notions of size: for Linux we can only get the padded size,
 * while for Windows we can only get the requested size.
 * We'd prefer the requested size for all uses, and we use our hashtable
 * (which we now use for all mallocs by default) if possible.
 * Only if the hashtable lookup fails (e.g., during malloc prior to adding
 * to table) do we call the app size routine: and even then, users of this routine
 * simply need an upper bound on the requested size and a lower bound on the
 * padded size.
 * We can get the padded size for Windows via get_alloc_real_size().
 * Returns -1 on failure.
 */
static ssize_t
get_alloc_size(IF_WINDOWS_(reg_t auxarg) app_pc real_base, alloc_routine_entry_t *routine)
{
    ssize_t sz;
    /* i#30: if op_record_allocs, prefer hashtable to avoid app lock
     * which can lead to deadlock
     */
    /* This will fail at post-malloc point before we've added to hashtable:
     * though currently it's debug msvcrt operator delete that's the only
     * problem, so we're ok w/ alloc calling app routine
     */
    sz = malloc_size(real_base);
    if (sz != -1)
        return sz + 2*redzone_size(routine);
    return get_size_from_app_routine(IF_WINDOWS_(auxarg) real_base, routine);
}

/* Returns the full usable footprint of the allocation at real_base.
 * Returns -1 on error.
 */
static ssize_t
get_padded_size(IF_WINDOWS_(reg_t auxarg) app_pc real_base, alloc_routine_entry_t *routine)
{
#ifdef LINUX
    /* malloc_usable_size() includes padding */
    ASSERT(routine->size_func != NULL &&
           routine->size_func->type == HEAP_ROUTINE_SIZE_USABLE,
           "assuming linux has usable size avail");
    return get_size_from_app_routine(real_base, routine);
#else
    /* FIXME: this is all fragile: any better way, besides using our
     * own malloc() instead of intercepting system's?
     */
# define HEAP_MAGIC_OFFS 0x50
    reg_t heap = auxarg;
    ssize_t result;
    ushort pad_size;
# ifdef DEBUG
    ssize_t req_size;
# endif
# ifdef X64
#  error NYI
# endif
    if (!is_rtl_routine(routine->type) || auxarg == 0/*invalid heap for Rtl*/) {
        if (routine->size_func == NULL ||
            is_size_requested_routine(routine->size_func->type)) {
            /* FIXME PR 595800: should look at headers and try to
             * figure out padded size.  For now we just guess by aligning.
             */
            size_t sz = get_alloc_size(auxarg, real_base, routine);
            return ALIGN_FORWARD(sz, MALLOC_CHUNK_ALIGNMENT);
        } else {
            /* malloc_usable_size() includes padding */
            return get_size_from_app_routine(auxarg, real_base, routine);
        }
    }
# ifdef DEBUG
    req_size = get_alloc_size(heap, real_base, routine);
# endif
    if (running_on_Vista_or_later()) {
        /* Some obfuscation is used to make exploits harder:
         * The first header dword must be xor-ed with a cookie
         * at heap+0x50.
         * The delta seems to be the 1st byte of 2nd header dword
         * instead of the 2nd byte: but we don't need it unless we add
         * a sanity check vs real_size.
         */
        size_t dw1, dw2;
        if (!safe_read((void *)(real_base-2*sizeof(size_t)), sizeof(dw1), &dw1) ||
            !safe_read((void *)(heap+HEAP_MAGIC_OFFS), sizeof(dw2), &dw2))
            ASSERT(false, "unable to access Rtl heap headers");
        pad_size = (ushort) (dw1 ^ dw2);
    } else {
        /* Rtl heap headers: blocksize/8 is 1st 16 bits of header */
        if (!safe_read((void *)(real_base-2*sizeof(size_t)), sizeof(pad_size), &pad_size))
            ASSERT(false, "unable to access Rtl heap headers");
    }
    if (!is_in_heap_region_arena(real_base) &&
        /* There seem to be two extra heap header dwords, the first holding
         * the full size.  pad_size seems to hold the padding amount.
         */
        safe_read((void *)(real_base-4*sizeof(size_t)), sizeof(result), &result)) {
        /* Out-of-heap large alloc.  During execution we could
         * record the NtAllocateVirtualMemory but this routine
         * could be called at other times.
         */
        ASSERT(result - pad_size == req_size, "Rtl large heap invalid assumption");
    } else {
        result = pad_size << 3;
        ASSERT(result >= req_size && result - req_size < 64*1024,
               "padded size has suspicious value: probably wrong!");
    }
    return result;
#endif /* LINUX -> WINDOWS */
}

/***************************************************************************
 * MALLOC TRACKING
 *
 * We record the callstack and when allocated so we can report leaks.
 */

/* Hashtable so we can remember post-call pcs (since
 * post-cti-instrumentation is not supported by DR).
 * Synchronized externally to safeguard the externally-allocated payload.
 */
#define POST_CALL_TABLE_HASH_BITS 10
static hashtable_t post_call_table;

typedef struct _post_call_entry_t {
    /* PR 454616: we need two flags in the post_call_table: one that
     * says "please add instru for this callee" and one saying "all
     * existing fragments have instru"
     */
    app_pc callee;
    bool existing_instrumented;
} post_call_entry_t;

static void
post_call_entry_free(void *v)
{
    post_call_entry_t *e = (post_call_entry_t *) v;
    ASSERT(e != NULL, "invalid hashtable deletion");
    global_free(e, sizeof(*e), HEAPSTAT_HASHTABLE);
}

static app_pc
post_call_lookup(app_pc pc)
{
    post_call_entry_t *e;
    app_pc res = NULL;
    hashtable_lock(&post_call_table);
    e = (post_call_entry_t *) hashtable_lookup(&post_call_table, (void*)pc);
    if (e != NULL)
        res = e->callee;
    hashtable_unlock(&post_call_table);
    return res;
}

/* We need to know whether we've inserted instrumentation at the call site .
 * The post_call_table tells us whether we've set up the return site for instrumentation.
 */
#define CALL_SITE_TABLE_HASH_BITS 10
static hashtable_t call_site_table;

/* we need to know which heap allocations were there before we took
 * control (so we know whether size is stored in redzone) and for leak
 * reporting we also track the callstack for each alloc.
 * Synchronized externally to safeguard the externally-allocated payload.
 */
/* There are several cases where having an interval tree instead of a
 * hashtable would be useful:
 * - leak scanning wouldn't have to create its own interval tree by
 *   walking the entire hashtable on each nudge/exit
 * - locating nearby mallocs (PR 535568) would be more accurate and efficient
 * - locating live mallocs inside an unmapped heap arena would be
 *   more accurate and efficient (xref PR 520916)
 * - locating bounds of mallocs used as stack regions (PR 525807)
 * For PR 535568 I measured replacing the malloc hashtable with an
 * interval tree and the cost is noticeable on heap-intensive
 * benchmarks (and there aren't substantially more lookups than
 * insertions and deletions), so sticking with a hashtable!
 */
#define ALLOC_TABLE_HASH_BITS 12
static hashtable_t malloc_table;
/* we could switch to a full-fledged known-owner lock, or a recursive lock.
 * xref i#129.
 */
#define THREAD_ID_INVALID ((thread_id_t)0) /* invalid thread id on Linux+Windows */
static thread_id_t malloc_lock_owner = THREAD_ID_INVALID;
/* PR 525807: to handle malloc-based stacks we need an interval tree
 * for large mallocs.  Putting all mallocs in a tree instead of a table
 * is too expensive (PR 535568).  This is protected by the hashtable lock.
 */
#define LARGE_MALLOC_MIN_SIZE 12*1024
static rb_tree_t *large_malloc_tree;

enum {
    MALLOC_VALID  = MALLOC_RESERVED_1,
    MALLOC_PRE_US = MALLOC_RESERVED_2,
    /* The other two are reserved for future use */
    MALLOC_POSSIBLE_CLIENT_FLAGS = (MALLOC_CLIENT_1 | MALLOC_CLIENT_2 |
                                    MALLOC_CLIENT_3 | MALLOC_CLIENT_4),
};

/* We could save space by storing this in the redzone, if big enough,
 * though we'd have to squash app writes there (on that note we're not
 * preventing app from clobbering our size stored in redzone)
 */
typedef struct _malloc_entry_t {
    app_pc start;
    app_pc end;
    /* Dr. Heapstat needs to know the usable size.  To look it up needs the Heap
     * handle on Windows.  We could store that in the heap_region list but we'd
     * need some work to identify it for large mallocs that use
     * NtAllocateVirtualMemory.  For now we avoid that lookup by storing the
     * extra size as a diff to save space.
     * Update: we now have the Heap handle in the rbtree so we could use that.
     */
    ushort usable_extra;
    ushort flags; /* holds MALLOC_* flags */
    void *data;
} malloc_entry_t;

static void
malloc_entry_free(void *v)
{
    malloc_entry_t *e = (malloc_entry_t *) v;
    client_malloc_data_free(e->data);
    global_free(e, sizeof(*e), HEAPSTAT_HASHTABLE);
}

/* If track_allocs is false, only callbacks and callback returns are tracked.
 * Else: if track_heap is false, only syscall allocs are tracked;
 *       else, syscall allocs and mallocs are tracked.
 */
void
alloc_init(bool track_allocs, bool track_heap,
           size_t redzone_size, bool size_in_redzone,
           bool record_allocs, bool get_padded_size)
{
#ifdef WINDOWS
    void *drcontext = dr_get_current_drcontext();
    app_pc ntdll_lib;
#endif
    op_track_allocs = track_allocs;
    ASSERT(track_allocs || !track_heap, "track_heap requires track_allocs");
    op_track_heap = track_allocs && track_heap;
    op_redzone_size = redzone_size;
    op_size_in_redzone = size_in_redzone;
    op_record_allocs = record_allocs;
    op_get_padded_size = get_padded_size;

    if (op_track_allocs) {
        hashtable_init_ex(&alloc_routine_table, ALLOC_ROUTINE_TABLE_HASH_BITS,
                          HASH_INTPTR, false/*!str_dup*/, false/*!synch*/,
                          alloc_routine_entry_free, NULL, NULL);
        alloc_routine_lock = dr_mutex_create();
    }

#ifdef WINDOWS
    ntdll_lib = get_ntdll_base();
    addr_KiCallback = (app_pc) dr_get_proc_address(ntdll_lib,
                                                   "KiUserCallbackDispatcher");
    if (op_track_allocs) {
        addr_KiAPC = (app_pc) dr_get_proc_address(ntdll_lib,
                                                  "KiUserApcDispatcher");
        addr_KiException = (app_pc) dr_get_proc_address(ntdll_lib,
                                                        "KiUserExceptionDispatcher");
        addr_KiRaise = (app_pc) dr_get_proc_address(ntdll_lib,
                                                    "KiRaiseUserExceptionDispatcher");
        /* Assuming that KiUserCallbackExceptionHandler,
         * KiUserApcExceptionHandler, and the Ki*SystemCall* routines are not
         * entered from the kernel.
         */

        sysnum_mmap = sysnum_from_name(drcontext, ntdll_lib, "NtMapViewOfSection");
        ASSERT(sysnum_mmap != -1, "error finding alloc syscall #");
        sysnum_munmap = sysnum_from_name(drcontext, ntdll_lib, "NtUnmapViewOfSection");
        ASSERT(sysnum_munmap != -1, "error finding alloc syscall #");
        sysnum_valloc = sysnum_from_name(drcontext, ntdll_lib, "NtAllocateVirtualMemory");
        ASSERT(sysnum_valloc != -1, "error finding alloc syscall #");
        sysnum_vfree = sysnum_from_name(drcontext, ntdll_lib, "NtFreeVirtualMemory");
        ASSERT(sysnum_vfree != -1, "error finding alloc syscall #");
        sysnum_continue = sysnum_from_name(drcontext, ntdll_lib, "NtContinue");
        ASSERT(sysnum_continue != -1, "error finding alloc syscall #");
        sysnum_cbret = sysnum_from_name(drcontext, ntdll_lib, "NtCallbackReturn");
        ASSERT(sysnum_cbret != -1, "error finding alloc syscall #");
        sysnum_setcontext = sysnum_from_name(drcontext, ntdll_lib, "NtSetContextThread");
        ASSERT(sysnum_setcontext != -1, "error finding alloc syscall #");

        if (op_track_heap) {
            module_data_t mod = {0,};
            mod.handle = ntdll_lib;
            dr_mutex_lock(alloc_routine_lock);
            find_alloc_routines(&mod, possible_rtl_routines,
                                POSSIBLE_RTL_ROUTINE_NUM, true, true);
            dr_mutex_unlock(alloc_routine_lock);
        }
    }
#endif

    if (op_track_allocs) {
        hashtable_init_ex(&malloc_table, ALLOC_TABLE_HASH_BITS, HASH_INTPTR,
                          false/*!str_dup*/, false/*!synch*/, malloc_entry_free,
                          NULL, NULL);
        large_malloc_tree = rb_tree_create(NULL);
        hashtable_init_ex(&post_call_table, POST_CALL_TABLE_HASH_BITS, HASH_INTPTR,
                          false/*!str_dup*/, false/*!synch*/, post_call_entry_free,
                          NULL, NULL);
        hashtable_init(&call_site_table, CALL_SITE_TABLE_HASH_BITS, HASH_INTPTR,
                       false/*!strdup*/);
    }
}

void
alloc_exit(void)
{
    /* Check for leaks.
     * FIXME: provide a hashtable iterator instead of breaking abstraction
     * barrier here.
     */
    uint i;
    if (!op_track_allocs)
        return;

    LOG(1, "final alloc routine table size: %u bits, %u entries\n",
        alloc_routine_table.table_bits, alloc_routine_table.entries);
    hashtable_delete(&alloc_routine_table);
    dr_mutex_destroy(alloc_routine_lock);

    LOG(1, "final malloc table size: %u bits, %u entries\n",
        malloc_table.table_bits, malloc_table.entries);
    /* we can't hold malloc_table.lock b/c report_leak() acquires it
     * for malloc_get_caller()
     */
    for (i = 0; i < HASHTABLE_SIZE(malloc_table.table_bits); i++) {
        hash_entry_t *he;
        for (he = malloc_table.table[i]; he != NULL; he = he->next) {
            malloc_entry_t *e = (malloc_entry_t *) he->payload;
            if (TEST(MALLOC_VALID, e->flags)) {
                client_exit_iter_chunk(e->start, e->end, TEST(MALLOC_PRE_US, e->flags),
                                       e->flags, e->data);
            }
        }
    }

    hashtable_delete(&malloc_table);
    rb_tree_destroy(large_malloc_tree);
    hashtable_delete(&post_call_table);
    hashtable_delete(&call_site_table);
}

#ifdef WINDOWS
bool
enumerate_syms_cb(const char *name, size_t modoffs, void *data)
{
    const char *opdel = "operator delete";
    const module_data_t *mod = (const module_data_t *) data;
    ASSERT(mod != NULL, "invalid param");
    LOG(5, "enum syms %s: "PFX" %s\n",
        (dr_module_preferred_name(mod) == NULL) ? "<noname>" :
        dr_module_preferred_name(mod),
        modoffs, name);
    if (strcmp(name, opdel) == 0) {
        /* not part of any mallc routine set */
        add_alloc_routine(mod->start + modoffs, HEAP_ROUTINE_DELETE,
                          opdel, false, NULL, false, NULL, NULL);
        LOG(1, "intercepting operator delete @"PFX" in module %s\n",
            mod->start + modoffs,
            (dr_module_preferred_name(mod) == NULL) ? "<noname>" :
            dr_module_preferred_name(mod));
    }
    return true; /* keep iterating */
}
#endif

void
alloc_module_load(void *drcontext, const module_data_t *info, bool loaded)
{
    if (op_track_heap) {
        const char *modname = dr_module_preferred_name(info);
        bool use_redzone = true;
        if (modname != NULL && 
            (strcmp(modname, "drmemorylib.dll") == 0 ||
             strcmp(modname, "dynamorio.dll") == 0))
            return;
        dr_mutex_lock(alloc_routine_lock);
#ifdef USE_DRSYMS
        if (lookup_symbol_or_export(info, "_malloc_dbg") != NULL) {
            /* i#26: msvcrtdbg adds its own redzone that contains a debugging
             * data structure.  The problem is that operator delete() assumes
             * this data struct is placed immediately prior to the ptr
             * returned by malloc.  We aren't intercepting new or delete
             * so we simply skip our redzone for msvcrtdbg: after all there's
             * already a redzone there.
             */
            use_redzone = false;
            LOG(1, "NOT using redzones for routines in %s "PFX"\n",
                (modname == NULL) ? "<noname>" : modname, info->start);
            /* We watch debug operator delete b/c it reads malloc's headers (i#26)! */
            if (drsym_enumerate_symbols(info->full_path, enumerate_syms_cb,
                                        (void *) info) != DRSYM_SUCCESS) {
                LOG(1, "error enumerating symbols for %s\n",
                    (modname == NULL) ? "<noname>" : modname);
            }
        }
#endif
        find_alloc_routines(info, possible_libc_routines,
                            POSSIBLE_LIBC_ROUTINE_NUM, use_redzone, false);
#ifdef WINDOWS
        find_alloc_routines(info, possible_dbgcrt_routines,
                            POSSIBLE_DBGCRT_ROUTINE_NUM, use_redzone, false);
#endif
        dr_mutex_unlock(alloc_routine_lock);
    }
}

void
alloc_module_unload(void *drcontext, const module_data_t *info)
{
    if (op_track_heap) {
        int i;
        dr_mutex_lock(alloc_routine_lock);
        for (i = 0; i < POSSIBLE_LIBC_ROUTINE_NUM; i++) {
            app_pc pc = lookup_symbol_or_export(info, possible_libc_routines[i].name);
            if (pc != NULL) {
                IF_DEBUG(bool found = )
                    hashtable_remove(&alloc_routine_table, (void *)pc);
                ASSERT(found, "alloc entry should be in table");
            }
        }
#ifdef WINDOWS
        for (i = 0; i < POSSIBLE_DBGCRT_ROUTINE_NUM; i++) {
            app_pc pc = lookup_symbol_or_export(info, possible_dbgcrt_routines[i].name);
            if (pc != NULL) {
                IF_DEBUG(bool found = )
                    hashtable_remove(&alloc_routine_table, (void *)pc);
                ASSERT(found, "alloc entry should be in table");
            }
        }
#endif
        dr_mutex_unlock(alloc_routine_lock);
    }
}

/* We need to support our malloc routines being called either on their
 * own or from within malloc_iterate(), so we need self-recursion support
 * of one level.  We do not need general recursion support.
 */
static bool
malloc_lock_held_by_self(void)
{
    /* reading this variable should be atomic */
    void *drcontext = dr_get_current_drcontext();
    if (drcontext == NULL) {
        ASSERT(false, "should always have dcontext w/ PR 536058");
        return false;
    }
    return (dr_get_thread_id(drcontext) == malloc_lock_owner);
}

void
malloc_lock(void)
{
    void *drcontext = dr_get_current_drcontext();
    hashtable_lock(&malloc_table);
    if (drcontext != NULL) /* paranoid even w/ PR 536058 */
        malloc_lock_owner = dr_get_thread_id(drcontext);
}

void
malloc_unlock(void)
{
    malloc_lock_owner = THREAD_ID_INVALID;
    hashtable_unlock(&malloc_table);
}

static bool
malloc_lock_if_not_held_by_me(void)
{
    if (malloc_lock_held_by_self())
        return false;
    malloc_lock();
    return true;
}

static void
malloc_unlock_if_locked_by_me(bool by_me)
{
    if (by_me)
        malloc_unlock();
}

/* If a client needs the real (usable) end, for pre_us mallocs the client can't
 * use get_alloc_real_size() via pt->auxarg as there is no pt and would need
 * the Heap handle passed in: instead we just pass in the real_end.  We don't
 * need real_base; we do pass real_base to client_handle_malloc() but we don't
 * need to store it, only real_end, driven by Dr. Heapstat's usage.
 */
static void
malloc_add_common(app_pc start, app_pc end, app_pc real_end,
                  bool pre_us, uint client_flags, dr_mcontext_t *mc, app_pc post_call)
{
    malloc_entry_t *e = (malloc_entry_t *) global_alloc(sizeof(*e), HEAPSTAT_HASHTABLE);
    malloc_entry_t *old_e;
    bool locked_by_me;
    ASSERT((op_redzone_size > 0 && pre_us) || op_record_allocs, 
           "internal inconsistency on when doing detailed malloc tracking");
    e->start = start;
    e->end = end;
    ASSERT(real_end != NULL && real_end - end <= USHRT_MAX, "real_end suspicously big");
    e->usable_extra = (real_end - end);
    e->flags = MALLOC_VALID;
    if (pre_us)
        e->flags |= MALLOC_PRE_US;
    e->flags |= (client_flags & MALLOC_POSSIBLE_CLIENT_FLAGS);
    /* grab lock around client call and hashtable operations */
    locked_by_me = malloc_lock_if_not_held_by_me();

    e->data = client_add_malloc_pre(e->start, e->end, e->end + e->usable_extra,
                                    NULL, mc, post_call);

    ASSERT(is_entirely_in_heap_region(start, end), "heap data struct inconsistency");
    /* We invalidate rather than remove on a free and finalize the remove
     * when the free succeeds, so a race can hit a conflict.
     * Update: we no longer do this but leaving code for now
     */
    old_e = hashtable_add_replace(&malloc_table, (void *) start, (void *)e);

    if (end - start >= LARGE_MALLOC_MIN_SIZE) {
        IF_DEBUG(rb_node_t *node =)
            rb_insert(large_malloc_tree, e->start, e->end - e->start, NULL);
        ASSERT(node == NULL, "error in large malloc tree");
        STATS_INC(num_large_mallocs);
    }

    /* PR 567117: client event with entry in hashtable */
    client_add_malloc_post(e->start, e->end, e->end + e->usable_extra, e->data);

    malloc_unlock_if_locked_by_me(locked_by_me);
    if (old_e != NULL) {
        ASSERT(!TEST(MALLOC_VALID, old_e->flags), "internal error in malloc tracking");
        malloc_entry_free(old_e);
    }
    DOLOG(2, {
        LOG(2, "MALLOC "PFX"-"PFX"\n", start, end);
        print_callstack_to_file(dr_get_current_drcontext(), mc, post_call,
                                INVALID_FILE/*use pt->f*/);
    });
    STATS_INC(num_mallocs);
}

void
malloc_add(app_pc start, app_pc end, app_pc real_end,
           bool pre_us, uint client_flags, dr_mcontext_t *mc, app_pc post_call)
{
    malloc_add_common(start, end, real_end, pre_us, client_flags, mc, post_call);
}

/* up to caller to lock and unlock */
static malloc_entry_t *
malloc_lookup(app_pc start)
{
    return hashtable_lookup(&malloc_table, (void *) start);
}

/* Note that this also frees the entry.  Caller should be holding lock. */
static void
malloc_entry_remove(malloc_entry_t *e)
{
    app_pc start, end, real_end;
    ASSERT(e != NULL, "invalid arg");
    /* cache values for post-event */
    start = e->start;
    end = e->end;
    real_end = e->end + e->usable_extra;
    client_remove_malloc_pre(e->start, e->end, e->end + e->usable_extra, e->data);
    if (e->end - e->start >= LARGE_MALLOC_MIN_SIZE) {
        rb_node_t *node = rb_find(large_malloc_tree, e->start);
        ASSERT(node != NULL, "error in large malloc tree");
        if (node != NULL)
            rb_delete(large_malloc_tree, node);
    }
    if (hashtable_remove(&malloc_table, e->start))
        STATS_INC(num_frees);
    /* PR 567117: client event with entry removed from hashtable */
    client_remove_malloc_post(start, end, real_end);
}

void
malloc_remove(app_pc start)
{
    malloc_entry_t *e;
    bool locked_by_me = malloc_lock_if_not_held_by_me();
    e = malloc_lookup(start);
    if (e != NULL)
        malloc_entry_remove(e);
    malloc_unlock_if_locked_by_me(locked_by_me);
}

void
malloc_set_valid(app_pc start, bool valid)
{
    malloc_entry_t *e;
    bool locked_by_me = malloc_lock_if_not_held_by_me();
    e = (malloc_entry_t *) hashtable_lookup(&malloc_table, (void *) start);
    if (e != NULL) {
        /* cache values for post-event */
        app_pc start = e->start, end = e->end, real_end = e->end + e->usable_extra;
        /* FIXME: should we tell client whether undoing false call failure prediction? */
        /* Call client BEFORE updating hashtable, to be consistent w/
         * other add/remove calls, so that any hashtable iteration will
         * NOT find the changes yet (PR 560824)
         */
        if (valid) {
            e->data = client_add_malloc_pre(e->start, e->end, e->end + e->usable_extra,
                                            e->data, NULL, NULL);
        } else {
            client_remove_malloc_pre(e->start, e->end, e->end + e->usable_extra, e->data);
        }
        ASSERT((TEST(MALLOC_VALID, e->flags) && !valid) ||
               (!TEST(MALLOC_VALID, e->flags) && valid),
               "internal error in malloc tracking");
        if (valid) {
            e->flags |= MALLOC_VALID;
            if (e->end - e->start >= LARGE_MALLOC_MIN_SIZE) {
                /* large malloc tree removes and re-adds rather than marking invalid
                 * b/c can recover data from hashtable on failure
                 */
                IF_DEBUG(rb_node_t *node =)
                    rb_insert(large_malloc_tree, e->start, e->end - e->start, NULL);
                ASSERT(node == NULL, "error in large malloc tree");
            }
            /* PR 567117: client event with entry in hashtable */
            client_add_malloc_post(e->start, e->end, e->end + e->usable_extra, e->data);
        } else {
            e->flags &= ~MALLOC_VALID;
            if (e->end - e->start >= LARGE_MALLOC_MIN_SIZE) {
                /* large malloc tree removes and re-adds rather than marking invalid */
                rb_node_t *node = rb_find(large_malloc_tree, e->start);
                ASSERT(node != NULL, "error in large malloc tree");
                if (node != NULL)
                    rb_delete(large_malloc_tree, node);
            }
            /* PR 567117: client event with entry removed from hashtable */
            client_remove_malloc_post(start, end, real_end);
        }
    } /* ok to be NULL: a race where re-used in malloc and then freed already */
    malloc_unlock_if_locked_by_me(locked_by_me);
}

bool
malloc_large_lookup(byte *addr, byte **start OUT, size_t *size OUT)
{
    bool locked_by_me = malloc_lock_if_not_held_by_me();
    bool res = false;
    rb_node_t *node = rb_in_node(large_malloc_tree, addr);
    if (node != NULL) {
        rb_node_fields(node, start, size, NULL);
        res = true;
    }
    malloc_unlock_if_locked_by_me(locked_by_me);
    return res;
}

static bool
malloc_entry_is_pre_us(malloc_entry_t *e, bool ok_if_invalid)
{
    return (TEST(MALLOC_PRE_US, e->flags) &&
            (TEST(MALLOC_VALID, e->flags) || ok_if_invalid));
}

bool
malloc_is_pre_us_ex(app_pc start, bool ok_if_invalid)
{
    bool res = false;
    malloc_entry_t *e;
    bool locked_by_me = malloc_lock_if_not_held_by_me();
    e = (malloc_entry_t *) hashtable_lookup(&malloc_table, (void *) start);
    if (e != NULL)
        res = malloc_entry_is_pre_us(e, ok_if_invalid);
    malloc_unlock_if_locked_by_me(locked_by_me);
    return res;
}

bool
malloc_is_pre_us(app_pc start)
{
    return malloc_is_pre_us_ex(start, false/*only valid*/);
}

static void
malloc_set_pre_us(app_pc start)
{
    malloc_entry_t *e;
    bool locked_by_me = malloc_lock_if_not_held_by_me();
    e = (malloc_entry_t *) hashtable_lookup(&malloc_table, (void *) start);
    if (e != NULL)
        e->flags |= MALLOC_PRE_US;
    malloc_unlock_if_locked_by_me(locked_by_me);
}

#ifdef DEBUG
/* WARNING: unsafe routine!  Could crash accessing memory that gets freed,
 * so only call when caller can assume entry should exist.
 */
static bool
malloc_entry_exists_racy_nolock(app_pc start)
{
    malloc_entry_t *e = (malloc_entry_t *) hashtable_lookup(&malloc_table, (void *) start);
    return (e != NULL && TEST(MALLOC_VALID, e->flags));
}
#endif

app_pc
malloc_end(app_pc start)
{
    app_pc end = NULL;
    malloc_entry_t *e;
    bool locked_by_me = malloc_lock_if_not_held_by_me();
    e = (malloc_entry_t *) hashtable_lookup(&malloc_table, (void *) start);
    if (e != NULL && TEST(MALLOC_VALID, e->flags))
        end = e->end;
    malloc_unlock_if_locked_by_me(locked_by_me);
    return end;
}

/* Returns -1 on failure */
ssize_t
malloc_size(app_pc start)
{
    ssize_t sz = -1;
    malloc_entry_t *e;
    bool locked_by_me = malloc_lock_if_not_held_by_me();
    e = (malloc_entry_t *) hashtable_lookup(&malloc_table, (void *) start);
    if (e != NULL && TEST(MALLOC_VALID, e->flags))
        sz = (e->end - start);
    malloc_unlock_if_locked_by_me(locked_by_me);
    return sz;
}

/* Returns -1 on failure.  Only looks at invalid malloc regions. */
ssize_t
malloc_size_invalid_only(app_pc start)
{
    ssize_t sz = -1;
    malloc_entry_t *e;
    bool locked_by_me = malloc_lock_if_not_held_by_me();
    e = (malloc_entry_t *) hashtable_lookup(&malloc_table, (void *) start);
    if (e != NULL && !TEST(MALLOC_VALID, e->flags))
        sz = (e->end - start);
    malloc_unlock_if_locked_by_me(locked_by_me);
    return sz;
}

void *
malloc_get_client_data(app_pc start)
{
    void *res = NULL;
    malloc_entry_t *e;
    bool locked_by_me = malloc_lock_if_not_held_by_me();
    e = (malloc_entry_t *) hashtable_lookup(&malloc_table, (void *) start);
    if (e != NULL)
        res = e->data;
    malloc_unlock_if_locked_by_me(locked_by_me);
    return res;
}

uint
malloc_get_client_flags(app_pc start)
{
    uint res = 0;
    malloc_entry_t *e;
    bool locked_by_me = malloc_lock_if_not_held_by_me();
    e = (malloc_entry_t *) hashtable_lookup(&malloc_table, (void *) start);
    if (e != NULL)
        res = (e->flags & MALLOC_POSSIBLE_CLIENT_FLAGS);
    malloc_unlock_if_locked_by_me(locked_by_me);
    return res;
}

bool
malloc_set_client_flag(app_pc start, uint client_flag)
{
    malloc_entry_t *e;
    bool found = false;
    bool locked_by_me = malloc_lock_if_not_held_by_me();
    e = (malloc_entry_t *) hashtable_lookup(&malloc_table, (void *) start);
    if (e != NULL) {
        e->flags |= (client_flag & MALLOC_POSSIBLE_CLIENT_FLAGS);
        found = true;
    }
    malloc_unlock_if_locked_by_me(locked_by_me);
    return found;
}

bool
malloc_clear_client_flag(app_pc start, uint client_flag)
{
    malloc_entry_t *e;
    bool found = false;
    bool locked_by_me = malloc_lock_if_not_held_by_me();
    e = (malloc_entry_t *) hashtable_lookup(&malloc_table, (void *) start);
    if (e != NULL) {
        e->flags &= ~(client_flag & MALLOC_POSSIBLE_CLIENT_FLAGS);
        found = true;
    }
    malloc_unlock_if_locked_by_me(locked_by_me);
    return found;
}

void
malloc_iterate(void (*cb)(app_pc start, app_pc end, app_pc real_end,
                          bool pre_us, uint client_flags,
                          void *client_data, void *iter_data), void *iter_data)
{
    uint i;
    /* we do support being called while malloc lock is held but caller should
     * be careful that table is in a consistent state (staleness does this)
     */
    bool locked_by_me = malloc_lock_if_not_held_by_me();
    for (i = 0; i < HASHTABLE_SIZE(malloc_table.table_bits); i++) {
        hash_entry_t *he, *nxt;
        for (he = malloc_table.table[i]; he != NULL; he = nxt) {
            malloc_entry_t *e = (malloc_entry_t *) he->payload;
            /* support malloc_remove() while iterating */
            nxt = he->next;
            if (TEST(MALLOC_VALID, e->flags)) {
                cb(e->start, e->end, e->end + e->usable_extra,
                   TEST(MALLOC_PRE_US, e->flags), e->flags,
                   e->data, iter_data);
            }
        }
    }
    malloc_unlock_if_locked_by_me(locked_by_me);
}

/*
 ***************************************************************************/

#ifdef WINDOWS
# ifdef DEBUG
static int callback_depth;
# endif

static void
handle_cbret(bool syscall)
{
    void *drcontext = dr_get_current_drcontext();
    per_thread_t *pt_child = (per_thread_t *) dr_get_tls_field(drcontext);
    /* Our callback interception is AFTER DR's, but our cbret is BEFORE. */
    per_thread_t *pt_parent = pt_child->prev;
    /* pt_parent can be NULL if we took over in the middle of a callback
     * (one reason we don't support AppInit injection: PR 408521).
     */
    ASSERT(pt_parent != NULL, "callback stack off: is AppInit on?");

    DOLOG(2, {
        ASSERT(callback_depth > 0, "callback stack off");
        callback_depth--;
        LOG(2, "after cbret depth=%d pt="PFX" prev="PFX" next="PFX"\n",
            callback_depth, pt_parent, pt_parent->prev, pt_parent->next);
    });

    client_handle_cbret(drcontext, pt_parent, pt_child);

    /* swap in as the current structure */
    dr_set_tls_field(drcontext, (void *)pt_parent);
}

static void
handle_callback(void *drcontext, per_thread_t *pt)
{
    /* Our syscall data needs to be preserved so we use a stack of
     * data structures.  Since the client field is indirected inside
     * the client_data pointer in the dcontext, we're safe from
     * dcontext swaps changing anything underneath us.
     */
    per_thread_t *pt_parent = (per_thread_t *) dr_get_tls_field(drcontext);
    per_thread_t *pt_child = pt_parent->next;
    per_thread_t *tmp;
    void *tmp_data;
    bool new_depth = false;
    /* We re-use to avoid churn */
    if (pt_child == NULL) {
        pt_child = thread_alloc(drcontext, sizeof(*pt_child), HEAPSTAT_MISC);
        memset(pt_child, 0, sizeof(*pt_child));
        pt_parent->next = pt_child;
        pt_child->next = NULL;
        new_depth = true;
        LOG(2, "created new per_thread_t "PFX" for callback depth %d\n",
            pt_child, callback_depth+1);
    }
    tmp = pt_child->next;
    /* by default re-use the old client_data pointer */
    tmp_data = pt_child->client_data;
    memset(pt_child, 0, sizeof(*pt_child));
    pt_child->next = tmp;
    pt_child->prev = pt_parent;
    pt_child->client_data = tmp_data;
    /* preserve certain fields */
    pt_child->f = pt_parent->f;
    pt_child->errbuf = pt_parent->errbuf;
    pt_child->errbufsz = pt_parent->errbufsz;
    pt_child->stack_lowest_frame = pt_parent->stack_lowest_frame;
    /* let client fine-tune, in particular client_data field */
    client_handle_callback(drcontext, pt_parent, pt_child, new_depth);
    /* swap in as the current structure */
    dr_set_tls_field(drcontext, (void *)pt_child);

    DOLOG(2, {
        callback_depth++;
        LOG(2, "after callback depth=%d pt="PFX" prev="PFX" next="PFX"\n",
            callback_depth, pt_child, pt_child->prev, pt_child->next);
    });
}
#endif

bool
alloc_syscall_filter(void *drcontext, int sysnum)
{
    /* improve performance by not intercepting everything.  makes a difference
     * on linux in particular where ignorable syscalls are inlined.
     */
#ifdef WINDOWS
    if (sysnum == sysnum_mmap || sysnum == sysnum_munmap ||
        sysnum == sysnum_valloc || sysnum == sysnum_vfree ||
        sysnum == sysnum_cbret || sysnum == sysnum_continue ||
        sysnum == sysnum_setcontext) {
        return true;
    } else
        return false;
#else
    switch (sysnum) {
    case SYS_mmap:
    case SYS_munmap:
    IF_X86_32(case SYS_mmap2:)
    case SYS_mremap:
    case SYS_brk:
    case SYS_clone:
        return true;
    default:
        return false;
    }
#endif
}

void
handle_pre_alloc_syscall(void *drcontext, int sysnum, dr_mcontext_t *mc, per_thread_t *pt)
{
#ifdef WINDOWS
    if (sysnum == sysnum_mmap || sysnum == sysnum_munmap ||
        sysnum == sysnum_valloc || sysnum == sysnum_vfree ||
        sysnum == sysnum_cbret || sysnum == sysnum_continue ||
        sysnum == sysnum_setcontext) {
        HANDLE process;
        pt->expect_sys_to_fail = false;
        if (sysnum == sysnum_mmap || sysnum == sysnum_munmap ||
            sysnum == sysnum_valloc || sysnum == sysnum_vfree) {
            process = (HANDLE)
                dr_syscall_get_param(drcontext, (sysnum == sysnum_mmap) ? 1 : 0);
            pt->syscall_this_process = is_current_process(process);
        }
        if (sysnum == sysnum_valloc) {
            uint type = (uint) dr_syscall_get_param(drcontext, 4);
            pt->valloc_type = type;
            pt->valloc_commit = false;
            if (op_track_heap) {
                if (pt->syscall_this_process && TEST(MEM_COMMIT, type)) {
                    app_pc *base_ptr = (app_pc *) dr_syscall_get_param(drcontext, 1);
                    /* FIXME: safe_read */
                    app_pc base = *base_ptr;
                    MEMORY_BASIC_INFORMATION mbi;
                    /* We distinguish HeapAlloc from VirtualAlloc b/c the former
                     * reserves a big region and then commits pieces of it.
                     * We assume that anything w/ that behavior should be treated
                     * as a heap where its pieces are NOT addressable at commit time,
                     * but only at sub-page parcel-out time.
                     */
                    if (dr_virtual_query(base, &mbi, sizeof(mbi)) == sizeof(mbi)) {
                        pt->valloc_commit = (base == NULL /* no prior reservation */ ||
                                             (TEST(MEM_RESERVE, type) &&
                                              mbi.State == MEM_FREE) ||
                                             /* We require in_heap_routine to allow
                                              * RtlAllocateHandle, which does reserve and
                                              * then commit pieces but is NOT heap
                                              */
                                             pt->in_heap_routine == 0);
                    }
                }
            }
        } else if (sysnum == sysnum_vfree) {
            pt->valloc_type = (uint) dr_syscall_get_param(drcontext, 3);
            if (pt->syscall_this_process) {
                app_pc *base_ptr = (app_pc *) dr_syscall_get_param(drcontext, 1);
                size_t *size_ptr = (size_t *) dr_syscall_get_param(drcontext, 2);
                app_pc arg_base, base;
                size_t sz = 0;
                if (safe_read(size_ptr, sizeof(sz), &sz))
                    LOG(2, "NtFreeVirtualMemory pre-size="PFX"\n", sz);
                if (safe_read(base_ptr, sizeof(arg_base), &arg_base)) {
                    sz = allocation_size(arg_base, &base);
                    LOG(2, "NtFreeVirtualMemory alloc size of "PFX" is "PFX"\n",
                        arg_base, sz);
                }
                /* FIXME: check whether size exceeds malloc-recorded size */
                if (sz == 0 || base == NULL) {
                    pt->expect_sys_to_fail = true;
                    /* If our failure predictions aren't accurate enough we
                     * may have to implement the complex scheme in my notes
                     * for handling failed frees
                     */
                    client_invalid_heap_arg((app_pc)sysnum/*use sysnum as pc*/,
                                            base, mc, "HeapFree", true);
                } else {
                    pt->expect_sys_to_fail = false;
                }
            }
        } else if (sysnum == sysnum_munmap) {
            pt->munmap_base = (app_pc) dr_syscall_get_param(drcontext, 1);
            /* we have to walk now (post-syscall nothing to walk): we'll restore
             * if the syscall fails */
            if (pt->syscall_this_process) {
                /* syscall still works when not passed alloc base, but mmap_walk
                 * looks up the base so we don't need to call allocation_size() */
                LOGPT(2, pt, "NtUnmapViewOfSection: "PFX"\n", pt->munmap_base);
                client_handle_munmap(pt->munmap_base,
                                     allocation_size(pt->munmap_base, NULL),
                                     false/*file-backed*/);
            }
        } else if (sysnum == sysnum_cbret) {
            handle_cbret(true/*syscall*/);
        }
    }
#else /* WINDOWS */
    if (sysnum == SYS_munmap) {
        app_pc base = (app_pc) dr_syscall_get_param(drcontext, 0);
        size_t size = (size_t) dr_syscall_get_param(drcontext, 1);
        /* If it fails, we restore post-syscall.
         * FIXME: need to store shadow values here so can restore.
         * Also need to handle races: xref race handling for malloc.
         */
        LOGPT(2, pt, "SYS_munmap "PFX"-"PFX"\n", base, base+size);
        client_handle_munmap(base, size, false/*up to caller to determine*/);
        /* if part of heap remove it from list */
        if (op_track_heap)
            heap_region_remove(base, base+size, mc);
    }
# ifdef DEBUG
    else if (sysnum == SYS_brk) {
        pt->sbrk = (app_pc) dr_syscall_get_param(drcontext, 0);
    }
# endif
#endif /* WINDOWS */
    client_pre_syscall(drcontext, sysnum, pt);
}

void
handle_post_alloc_syscall(void *drcontext, int sysnum, dr_mcontext_t *mc, per_thread_t *pt)
{
#ifdef WINDOWS
    /* we access up to param#3 */
    ASSERT(SYSCALL_NUM_ARG_STORE >= 4, "need to up #sysargs stored");
    if (sysnum == sysnum_mmap) {
        /* FIXME: provide a memory tracking interface? */
        bool success = NT_SUCCESS(dr_syscall_get_result(drcontext));
        if (success && pt->syscall_this_process) {
            app_pc *base_ptr = (app_pc *) pt->sysarg[2];
            /* FIXME: do a safe_read? */
            app_pc base = *base_ptr;
            LOGPT(2, pt, "NtMapViewOfSection: "PFX"\n", base);
            client_handle_mmap(pt, base, allocation_size(base, NULL),
                               false/*file-backed*/);
        }
    } else if (sysnum == sysnum_munmap) {
        bool success = NT_SUCCESS(dr_syscall_get_result(drcontext));
        if (!success && pt->syscall_this_process) {
            /* restore */
            LOGPT(2, pt, "NtUnmapViewOfSection failed: restoring "PFX"\n",
                   pt->munmap_base);
            client_handle_munmap_fail(pt->munmap_base,
                                      allocation_size(pt->munmap_base, NULL),
                                      false/*file-backed*/);
        }
    } else if (sysnum == sysnum_valloc) {
        bool success = NT_SUCCESS(dr_syscall_get_result(drcontext));
        if (success && pt->syscall_this_process) {
            app_pc *base_ptr = (app_pc *) pt->sysarg[1];
            size_t *size_ptr = (size_t *) pt->sysarg[3];
            /* FIXME: safe_read */
            app_pc base = *base_ptr;
            size_t size = *size_ptr;
            LOGPT(2, pt, "NtAllocateVirtualMemory: "PFX"-"PFX" %s%s%s%s\n",
                  base, base+size, pt->valloc_commit ? "vcommit " : "",
                  TEST(MEM_RESERVE, pt->valloc_type) ? "reserve " : "",
                  TEST(MEM_COMMIT, pt->valloc_type) ? "commit " : "",
                  pt->in_heap_routine > 0 ? "in-heap " : "");
            if (op_track_heap) {
                /* if !valloc_commit, we assume it's part of a heap */
                if (pt->valloc_commit) {
                    /* FIXME: really want to test overlap of two regions! */
                    ASSERT(!is_in_heap_region(base),
                           "HeapAlloc vs VirtualAlloc: error distinguishing");
                    if (pt->in_heap_routine == 0) {
                        LOGPT(2, pt,
                               "NtAllocateVirtualMemory non-heap alloc "PFX"-"PFX"\n",
                               base, base+size);
                        client_handle_mmap(pt, base, size, true/*anon*/);
                    } else {
                        /* We assume this is a very large malloc, which is allocated
                         * straight from the OS instead of the heap pool.
                         * FIXME: our red zone here will end up wasting an entire 64KB
                         * if the request size + headers would have been 64KB-aligned.
                         */
                        LOGPT(2, pt,
                               "NtAllocateVirtualMemory big heap alloc "PFX"-"PFX"\n",
                               base, base+size);
                        /* there are headers on this one */
                        heap_region_add(base, base+size, false/*!arena*/, mc);
                    }
                } else if (TEST(MEM_RESERVE, pt->valloc_type) &&
                           !TEST(MEM_COMMIT, pt->valloc_type) &&
                           pt->in_heap_routine > 0) {
                    /* we assume this is a new Heap reservation */
                    heap_region_add(base, base+size, true/*arena*/, mc);
                }
            } else {
                if (TEST(MEM_COMMIT, pt->valloc_type)) {
                    LOGPT(2, pt, "NtAllocateVirtualMemory commit "PFX"-"PFX"\n",
                           base, base+size);
                    client_handle_mmap(pt, base, size, true/*anon*/);
                }
            }
        }
    } else if (sysnum == sysnum_vfree && pt->syscall_this_process) {
        bool success = NT_SUCCESS(dr_syscall_get_result(drcontext));
        app_pc *base_ptr = (app_pc *) pt->sysarg[1];
        size_t *size_ptr = (size_t *) pt->sysarg[2];
        /* FIXME: safe_read */
        app_pc base = *base_ptr;
        size_t size = *size_ptr;
        if (success) {
            LOGPT(2, pt, "NtFreeVirtualMemory: "PFX"-"PFX", %s%s%s\n",
                  base, base+size,
                  TEST(MEM_DECOMMIT, pt->valloc_type) ? "decommit " : "",
                  TEST(MEM_RELEASE, pt->valloc_type) ? "release " : "",
                  pt->in_heap_routine > 0 ? "in-heap " : "");
            ASSERT(!pt->expect_sys_to_fail, "expected NtFreeVirtualMemory to succeed");
            if (op_track_heap) {
                /* Are we freeing an entire region? */
                if (((pt->valloc_type == MEM_DECOMMIT && size == 0) ||
                     pt->valloc_type == MEM_RELEASE) &&
                    pt->in_heap_routine > 0 && is_in_heap_region(base)) {
                    /* all these separate lookups are racy */
                    app_pc heap_end = heap_region_end(base);
                    bool found;
                    if (size == 0)
                        size = allocation_size(base, NULL);
                    found = heap_region_remove(base, base+size, mc);
                    ASSERT(found, "heap region tracking bug");
                    /* FIXME: this is racy, doing this post-syscall; should
                     * switch to interval tree to look up base pre-syscall
                     */
                    /* PR 469229: in some cases a large heap reservation
                     * is made and then all but the last page is freed; that
                     * page is then used as the heap.  Makes no sense.
                     */
                    if (heap_end > base+size) {
                        LOG(2, "left "PFX"-"PFX" at end of heap region\n",
                            base+size, heap_end);
                        /* heap_region_remove leaves the remaining piece there */
                    }
                    client_handle_munmap(base, size, true/*anon*/);
                } else {
                    /* we ignore decommits from inside heap regions.
                     * we shouldn't see any releases from inside heap regions
                     * that bypass our check above, though.
                     */
                    ASSERT(pt->valloc_type == MEM_DECOMMIT ||
                           !is_in_heap_region(base), "heap region tracking bug");
                    if (op_record_allocs) {
                        malloc_remove(base);
                    }
                }
            } else {
                client_handle_munmap(base, size, true/*anon*/);
            }
        } else {
            ASSERT(pt->expect_sys_to_fail, "expected NtFreeVirtualMemory to fail");
        }
    }
#else /* WINDOWS */
    ptr_int_t result = dr_syscall_get_result(drcontext);
    bool success = (result >= 0);
    ASSERT(SYSCALL_NUM_ARG_STORE >= 4, "need to up #sysargs stored");
    if (sysnum == SYS_mmap IF_X86_32(|| sysnum == SYS_mmap2)) {
        unsigned long flags = 0;
        size_t size = 0;
        /* libc interprests up to -PAGE_SIZE as an error */
        bool mmap_success = (result > 0 || result < -PAGE_SIZE);
        if (mmap_success) {
            app_pc base = (app_pc) result;
            if (sysnum == IF_X64_ELSE(SYS_mmap, SYS_mmap2)) {
                /* long sys_mmap2(unsigned long addr, unsigned long len,
                 *                unsigned long prot, unsigned long flags,
                 *                unsigned long fd, unsigned long pgoff)
                 */
                flags = (unsigned long) pt->sysarg[3];
                size = (size_t) pt->sysarg[1];
            }
# ifdef X86_32
            if (sysnum == SYS_mmap) {
                mmap_arg_struct_t arg;
                if (!safe_read((void *)pt->sysarg[0], sizeof(arg), &arg)) {
                    ASSERT(false, "failed to read successful mmap arg struct");
                    /* fallback is to walk as though an image */
                    memset(&arg, 0, sizeof(arg));
                }
                flags = arg.flags;
                size = arg.len;
            }
# endif
            LOGPT(2, pt, "SYS_mmap: "PFX"-"PFX" %d\n", base, base+size, flags);
            client_handle_mmap(pt, base, size, TEST(MAP_ANONYMOUS, flags));
            if (TEST(MAP_ANONYMOUS, flags)) {
                if (pt->in_heap_routine > 0) {
                    /* We don't know whether a new arena or a one-off large
                     * malloc: doesn't matter too much since we don't
                     * really distinguish inside our heap list anyway.
                     */
                    if (op_track_heap)
                        heap_region_add(base, base+size, true/*FIXME:guessing*/, mc);
                }
            }
        } else {
            LOGPT(2, pt, "SYS_mmap failed "PIFX"\n", result);
        }
        /* FIXME: races: could be unmapped already */
    }
    else if (sysnum == SYS_munmap) {
        if (!success) {
            /* we already marked unaddressable: restore */
            app_pc base = (app_pc) pt->sysarg[0];
            size_t size = (size_t) pt->sysarg[1];
            dr_mem_info_t info;
            LOGPT(2, pt, "SYS_munmap "PFX"-"PFX" failed\n", base, base+size);
            if (!dr_query_memory_ex(base, &info))
                ASSERT(false, "mem query failed");
            client_handle_munmap_fail(base, size, info.type != DR_MEMTYPE_IMAGE);
            if (op_track_heap && pt->in_heap_routine > 0)
                heap_region_add(base, base+size, true/*FIXME:guessing*/, mc);
        }
    } 
    else if (sysnum == SYS_mremap) {
        app_pc old_base = (app_pc) pt->sysarg[0];
        size_t old_size = (size_t) pt->sysarg[1];
        app_pc new_base = (app_pc) result;
        size_t new_size = (size_t) pt->sysarg[2];
        /* libc interprets up to -PAGE_SIZE as an error */
        bool mmap_success = (result > 0 || result < -PAGE_SIZE);
        if (mmap_success) {
            /* FIXME: we're waiting to invalidate, as opposed to munmap where we
             * invalidate in pre-syscall: one reason is that mremap is much more
             * likely to fail.  However, waiting means races where a new alloc
             * comes in are much more likely.  Need to put in place a master
             * race handler.  For now we just want common cases working.
             */
            dr_mem_info_t info;
            LOGPT(2, pt, "SYS_mremap from "PFX"-"PFX" to "PFX"-"PFX"\n",
                  old_base, old_base+old_size, new_base, new_base+new_size);
            if (!dr_query_memory_ex(new_base, &info))
                ASSERT(false, "mem query failed");
            client_handle_mremap(old_base, old_size, new_base, new_size,
                                 info.type == DR_MEMTYPE_IMAGE);
            /* Large realloc may call mremap (PR 488643) */
            if (op_track_heap && pt->in_heap_routine > 0 &&
                is_in_heap_region(old_base)) {
                ASSERT(is_entirely_in_heap_region(old_base, old_base + old_size),
                       "error in large malloc tracking");
                heap_region_remove(old_base, old_base + old_size, mc);
                heap_region_add(new_base, new_base + new_size, true/*FIXME:guessing*/,
                                mc);
            }
        }
    }
    else if (sysnum == SYS_brk) {
        /* We can mostly ignore SYS_brk since we treat heap as unaddressable
         * until sub-allocated, though we do want the bounds for suppressing
         * header accesses by malloc code.
         */
        LOG(2, "SYS_brk "PFX" => "PFX"\n", pt->sbrk, result);
        heap_region_adjust(get_heap_start(), (app_pc) result);
    }
#endif /* WINDOWS */
    client_post_syscall(drcontext, sysnum, pt);
}

static app_pc
get_retaddr_at_entry(dr_mcontext_t *mc)
{
    app_pc retaddr = NULL;
    if (!safe_read((void *)mc->xsp, sizeof(retaddr), &retaddr))
        ASSERT(false, "error reading retaddr at func entry");
    return retaddr;
}

/* These take 1-based arg numbers */
#define APP_ARG_ADDR(mc, num, retaddr_yet) \
    ((mc)->esp + ((num)-1+((retaddr_yet)?1:0))*sizeof(reg_t))
#define APP_ARG(mc, num, retaddr_yet) \
    (*((reg_t *)(APP_ARG_ADDR(mc, num, retaddr_yet))))

/* RtlAllocateHeap(HANDLE heap, ULONG flags, ULONG size) */
/* void *malloc(size_t size) */
#define ARGNUM_MALLOC_SIZE(type) (IF_WINDOWS((type == RTL_ROUTINE_MALLOC) ? 3 :) 1)
/* RtlReAllocateHeap(HANDLE heap, ULONG flags, PVOID ptr, SIZE_T size) */
/* void *realloc(void *ptr, size_t size) */
#define ARGNUM_REALLOC_PTR(type) (IF_WINDOWS((type == RTL_ROUTINE_REALLOC) ? 3 :) 1)
#define ARGNUM_REALLOC_SIZE(type) (IF_WINDOWS((type == RTL_ROUTINE_REALLOC) ? 4 :) 2)
/* RtlFreeHeap(HANDLE heap, ULONG flags, PVOID ptr) */
/* void free(void *ptr) */
#define ARGNUM_FREE_PTR(type) (IF_WINDOWS((type == RTL_ROUTINE_FREE) ? 3 :) 1)
/* ULONG NTAPI RtlSizeHeap(HANDLE Heap, ULONG Flags, PVOID Block) */
/* void malloc_usable_size(void *ptr) */
#define ARGNUM_SIZE_PTR(type) (IF_WINDOWS((type == RTL_ROUTINE_SIZE) ? 3 :) 1)

/* As part of PR 578892 we must report invalid heap block args to all routines,
 * since we ignore unaddr inside the routines.
 * Caller should check for NULL separately if it's not an invalid arg.
 */
static bool
check_valid_heap_block(byte *block, dr_mcontext_t *mc, bool inside, app_pc call_site,
                       const char *routine, bool is_free)
{
    if (malloc_end(block) == NULL) {
        /* call_site for call;jmp will be jmp, so retaddr better even if post-call */
        client_invalid_heap_arg(inside ? get_retaddr_at_entry(mc) : call_site,
                                block, mc, routine, is_free);
        return false;
    }
    return true;
}

/**************************************************
 * FREE
 */

static void
handle_free_pre(void *drcontext, dr_mcontext_t *mc, bool inside, app_pc call_site,
                alloc_routine_entry_t *routine)
{
#if defined(WINDOWS) || defined(DEBUG)
    routine_type_t type = routine->type;
#endif
    per_thread_t *pt = (per_thread_t *) dr_get_tls_field(drcontext);
    /* FIXME: safe_read */
    app_pc base = (app_pc) APP_ARG(mc, ARGNUM_FREE_PTR(type), inside);
    app_pc real_base = base;
#ifdef WINDOWS
    HANDLE heap = (type == RTL_ROUTINE_FREE) ? ((HANDLE) APP_ARG(mc, 1, inside)) : NULL;
#endif
    bool size_in_zone = (routine->use_redzone && op_size_in_redzone);
    size_t size = 0;
    malloc_entry_t *entry;
    if (pt->in_heap_routine > 1 && pt->in_heap_adjusted > 0) {
        /* we assume we're called from RtlReAllocateheap, who will handle
         * all adjustments and shadow updates */
        LOGPT(2, pt, "free of "PFX" recursive: not adjusting\n", base);
        /* try to catch errors like PR 406714 */
        ASSERT(/* don't crash calling size routine so first see whether
                * entry exists: but don't use lock, since we can deadlock
                * due to our use of app lock to get size combined with
                * using malloc lock on both outer and inner malloc layers
                */
               base == NULL ||
               !malloc_entry_exists_racy_nolock(base) ||
               get_alloc_size(IF_WINDOWS_((reg_t)heap) base, routine) != -1,
               "free recursion count incorrect");
        return;
    }
    pt->in_heap_adjusted = pt->in_heap_routine;
    /* We avoid worrying about races between our pre & post free instru
     * by assuming we can always predict when free will fail.  This
     * requires always tracking mallocs even when not counting leaks.
     * We can get off after an invalid free due to a corner case race, but
     * we require user to fix invalid frees before trusting all later errors.
     */
    /* We must have synchronized access to avoid races and ensure we report
     * an error on the 2nd free to the same base
     */
    malloc_lock();
    entry = malloc_lookup(base);
    if (entry != NULL && redzone_size(routine) > 0 &&
        !malloc_entry_is_pre_us(entry, false))
        real_base = base - redzone_size(routine);
    if (entry == NULL
        /* call will fail if heap handle does not match.
         * it will not fail if flags are invalid.
         * instead of tracking the heap handle we could call RtlValidateHeap here?
         */
        IF_WINDOWS(|| (type == RTL_ROUTINE_FREE && heap_region_get_heap(base) != heap))) {
        if (pt->in_realloc) {
            /* when realloc calls free we've already invalidated the heap */
            ASSERT(pt->in_heap_routine > 1, "realloc calling free inconsistent");
        } else {
            pt->expect_lib_to_fail = true;
            /* call_site for call;jmp will be jmp, so retaddr better even if post-call */
            client_invalid_heap_arg(inside ? get_retaddr_at_entry(mc) : call_site,
                                    base, mc, routine->name, true);
        }
    } else {
        app_pc change_base;
        pt->expect_lib_to_fail = false;
        if (redzone_size(routine) > 0) {
            ASSERT(redzone_size(routine) >= sizeof(size_t),
                   "redzone < 4 not supported");
            if (malloc_entry_is_pre_us(entry, false)) {
                /* was allocated before we took control, so no redzone */
                size_in_zone = false;
                LOGPT(2, pt, "free of pre-control "PFX"-"PFX"\n", base, base+size);
            } else {
                *((app_pc *)(APP_ARG_ADDR(mc, ARGNUM_FREE_PTR(type), inside))) = real_base;
            }
        }
        /* We don't know how to read the Rtl headers, so we must
         * either use our redzone to store the size or call RtlSizeHeap.
         * When we use our redzone or RtlSizeHeap, we treat extra space beyond
         * the requested as unaddressable, which seems the right way to go;
         * on linux w/o a redzone we do not have the requested size as
         * malloc_usable_size() returns the padded size (as opposed to
         * RtlSizeHeap which returns the requested size).
         */
        if (size_in_zone)
            size = *((size_t *)(base - redzone_size(routine)));
        else {
            size = get_alloc_size(IF_WINDOWS_((reg_t)heap) real_base, routine);
            ASSERT((ssize_t)size != -1, "error determining heap block size");
            size -= redzone_size(routine)*2;
        }
        LOG(2, "free-pre" IF_WINDOWS(" heap="PFX)" ptr="PFX" size="PIFX" => "PFX"\n",
            IF_WINDOWS_(heap) base, size, real_base);

        change_base = client_handle_free
            (base, size, real_base, mc, routine->client
             _IF_WINDOWS((type == RTL_ROUTINE_FREE) ?
                         ((ptr_int_t *) APP_ARG_ADDR(mc, 1, inside)) : 
                         ((type == HEAP_ROUTINE_FREE_DBG) ?
                          ((ptr_int_t *) APP_ARG_ADDR(mc, 2, inside)) : NULL)));
        if (change_base != real_base) {
            LOG(2, "free-pre client %d changing base from "PFX" to "PFX"\n",
                type, real_base, change_base);
            *((app_pc *)(APP_ARG_ADDR(mc, ARGNUM_FREE_PTR(type), inside))) = change_base;
        }

        malloc_entry_remove(entry);
    }
    malloc_unlock();

    /* Note that these do not reflect what's really being freed if -delay_frees > 0 */
    pt->alloc_base = base;
    pt->alloc_size = size;
}

static void
handle_free_post(void *drcontext, dr_mcontext_t *mc, alloc_routine_entry_t *routine)
{
#ifdef WINDOWS
    if (routine->type == RTL_ROUTINE_FREE) {
        per_thread_t *pt = (per_thread_t *) dr_get_tls_field(drcontext);
        if (mc->eax == 0/*FALSE==failure*/) {
            /* If our prediction is wrong, we can't undo the shadow memory
             * changes since we've lost which were defined vs undefined,
             * along with whether this malloc was pre-us or not.  We
             * also can't undo any report of an invalid free.  See notes for a
             * solution other than holding a lock in the code cache: it requires
             * being able to restore shadow memory values and malloc
             * struct, using a nonce to know which malloc it went with.
             */
            ASSERT(pt->expect_lib_to_fail, "free() failure unexpected");
        } else {
            ASSERT(!pt->expect_lib_to_fail || pt->alloc_base == NULL,
                   "free() success unexpected");
        }
    }
#endif
    /* free() has no return value */
}

/**************************************************
 * SIZE
 */

static void
handle_size_pre(void *drcontext, dr_mcontext_t *mc, bool inside, app_pc call_site,
                alloc_routine_entry_t *routine)
{
    routine_type_t type = routine->type;
    per_thread_t *pt = (per_thread_t *) dr_get_tls_field(drcontext);
    pt->in_heap_adjusted = pt->in_heap_routine;
    if (redzone_size(routine) > 0 &&
        /* non-recursive: else we assume base already adjusted */
        pt->in_heap_routine == 1) {
        /* store the block being asked about, in case routine changes the param */
        pt->alloc_base = (app_pc) APP_ARG(mc, ARGNUM_SIZE_PTR(type), inside);
        /* ensure wasn't allocated before we took control (so no redzone) */
        if (check_valid_heap_block(pt->alloc_base, mc, inside, call_site,
                                   /* FIXME: should have caller invoke and use
                                    * alloc_routine_name?  kernel32 names better
                                    * than Rtl though
                                    */
                                   routine->name, is_free_routine(type)) &&
            pt->alloc_base != NULL &&
            !malloc_is_pre_us(pt->alloc_base)) {
            LOG(2, "size query: changing "PFX" to "PFX"\n",
                pt->alloc_base, pt->alloc_base - redzone_size(routine));
            /* FIXME: safe_write? */
            *((app_pc *)(APP_ARG_ADDR(mc, ARGNUM_SIZE_PTR(type), inside))) -=
                redzone_size(routine);
        }
    }
}

static void
handle_size_post(void *drcontext, dr_mcontext_t *mc, alloc_routine_entry_t *routine)
{
    per_thread_t *pt = (per_thread_t *) dr_get_tls_field(drcontext);
    uint failure = IF_WINDOWS_ELSE((routine->type == RTL_ROUTINE_SIZE) ? ~0UL : 0, 0);
    if (mc->eax != failure) {
        /* we want to return the size without the redzone */
        if (redzone_size(routine) > 0 &&
            !malloc_is_pre_us(pt->alloc_base) &&
            /* non-recursive: else we assume it's another Rtl routine calling
             * and we should use the real size anyway (e.g., RtlReAllocateHeap
             * calls RtlSizeHeap: xref i#259
             */
            pt->in_heap_routine == 0/*already decremented*/) {
            if (pt->alloc_base != NULL) {
                LOG(2, "size query: changing "PFX" to "PFX"\n",
                    mc->eax, mc->eax - redzone_size(routine)*2);
                mc->eax -= redzone_size(routine)*2;
                dr_set_mcontext(drcontext, mc, NULL);
#ifdef WINDOWS
                /* RtlSizeHeap returns exactly what was asked for, while
                 * malloc_usable_size includes padding which is hard to predict
                 */
                ASSERT(routine->type == HEAP_ROUTINE_SIZE_USABLE ||
                       !op_size_in_redzone ||
                       mc->eax == *((size_t *)(pt->alloc_base - redzone_size(routine))),
                       "size mismatch");
#endif
            } else {
                ASSERT(false, "unexpected NULL succeeding for size query");
            }
        }
    }
}

/**************************************************
 * MALLOC
 */

static size_t
size_plus_redzone_overflow(alloc_routine_entry_t *routine, size_t asked_for)
{
    /* avoid overflow (we expect to fail anyway): PR 531262 */
    return (asked_for + redzone_size(routine)*2 < asked_for);
}

/* If realloc is true, this is realloc(NULL, size) */
static void
handle_malloc_pre(void *drcontext, dr_mcontext_t *mc, bool inside,
                  alloc_routine_entry_t *routine)
{
    routine_type_t type = routine->type;
    per_thread_t *pt = (per_thread_t *) dr_get_tls_field(drcontext);
    bool realloc = is_realloc_routine(type);
    uint argnum = realloc ? ARGNUM_REALLOC_SIZE(type) : ARGNUM_MALLOC_SIZE(type);
    pt->alloc_size = (size_t) APP_ARG(mc, argnum, inside);
    if (redzone_size(routine) > 0) {
        /* FIXME: if app asks for 0 bytes should we not add our redzone in
         * case the app never frees the memory?  We'd need a way to record
         * which allocations have redzones: which we need anyway to tell
         * which ones were allocated before we took control.
         * Note that glibc malloc allocates a chunk w/ header even
         * for malloc(0).
         */
        if (size_plus_redzone_overflow(routine, pt->alloc_size)) {
            /* We assume malloc() will fail on this so we don't handle this
             * scenario in free(), etc. (PR 531262)
             */
            LOG(1, "WARNING: asked-for size "PIFX" too big to fit redzone\n",
                pt->alloc_size);
        } else {
            *((size_t *)(APP_ARG_ADDR(mc, argnum, inside))) =
                pt->alloc_size + redzone_size(routine)*2;
        }
    }
    /* FIXME PR 406742: handle HEAP_GENERATE_EXCEPTIONS windows flag */
    LOGPT(2, pt, "malloc-pre" IF_WINDOWS(" heap="PFX)
          " size="PIFX IF_WINDOWS(" flags="PIFX) "%s\n",
          IF_WINDOWS_(APP_ARG(mc, 1, inside))
          pt->alloc_size _IF_WINDOWS(pt->alloc_flags),
          realloc ? "(realloc(NULL,sz))" : "");
}

/* Returns the actual allocated size.  This can be either the
 * requested size that Dr. Memory passed to the system allocator
 * (including any redzones added) or that requested size padded to
 * some alignment.  For the exact padded size, use padded_size_out.
 * Returns -1 on error.
 * In order to export this we'd need to have either the malloc
 * hashtable or the heap regions store info to get the
 * alloc_routine_entry_t.
 */
static size_t
get_alloc_real_size(IF_WINDOWS_(reg_t auxarg) app_pc real_base, size_t app_size,
                    size_t *padded_size_out, alloc_routine_entry_t *routine)
{
    size_t real_size;
    if (routine->size_func != NULL) {
        real_size = get_alloc_size(IF_WINDOWS_(auxarg) real_base, routine);
        if (op_get_padded_size && padded_size_out != NULL) {
            *padded_size_out = get_padded_size(IF_WINDOWS_(auxarg)
                                               real_base, routine);
            if (*padded_size_out == -1)
                *padded_size_out = ALIGN_FORWARD(real_size, 8);
        } else if (padded_size_out != NULL) {
            *padded_size_out = ALIGN_FORWARD(real_size, 8);
        }
    } else {
        /* FIXME: if no malloc_usable_size() (and can't call malloc_size()
         * as this malloc is not yet in the hashtable), then for now we
         * ignore any extra padding.  We may have to figure out which malloc
         * it is and know the header layout and/or min alloc sizes for
         * common mallocs.
         */
        ASSERT(!size_plus_redzone_overflow(routine, app_size),
               "overflow should have failed");
        real_size = app_size + 2*redzone_size(routine);
        /* Unless re-using a larger free chunk, aligning to 8 should do it */
        if (padded_size_out != NULL)
            *padded_size_out = ALIGN_FORWARD(real_size, 8);
    }
    return real_size;
}

static app_pc
adjust_alloc_result(void *drcontext, dr_mcontext_t *mc, size_t *padded_size_out,
                    bool used_redzone, alloc_routine_entry_t *routine)
{
    per_thread_t *pt = (per_thread_t *) dr_get_tls_field(drcontext);
    if (mc->eax != 0) {
        app_pc app_base = (app_pc) mc->eax;
        size_t real_size =
            get_alloc_real_size(IF_WINDOWS_(pt->auxarg) app_base,
                                pt->alloc_size, padded_size_out, routine);
        ASSERT(real_size != -1, "error getting real size");
        /* If recursive we assume called by RtlReAllocateHeap where we
         * already adjusted the size */
        if (used_redzone && redzone_size(routine) > 0)
            app_base += redzone_size(routine);
        /* We have to be consistent: if we don't store the requested size for use
         * on free() we have to use the real size here
         */
        if (used_redzone && !op_size_in_redzone && redzone_size(routine) > 0) {
            LOGPT(2, pt, "adjusting alloc size "PIFX" to match real size "PIFX"\n",
                  pt->alloc_size, real_size - redzone_size(routine)*2);
            pt->alloc_size = real_size - redzone_size(routine)*2;
        }
        LOGPT(2, pt, "%s-post "PFX"-"PFX" = "PIFX" (really "PFX"-"PFX" "PIFX")\n",
              routine->name,
              app_base, app_base+pt->alloc_size, pt->alloc_size,
              app_base - (used_redzone ? redzone_size(routine) : 0),
              app_base - (used_redzone ? redzone_size(routine) : 0) + real_size,
              real_size);
        if (used_redzone && redzone_size(routine) > 0) {
            if (op_size_in_redzone) {
                ASSERT(redzone_size(routine) >= sizeof(size_t), "redzone size too small");
                /* store the size for our own use */
                *((size_t *)mc->eax) = pt->alloc_size;
            }
            /* FIXME: could there be alignment guarantees provided
             * by RtlAllocateHeap that we're messing up?
             * Should we preserve any obvious alignment we see?
             */
            LOGPT(2, pt, "%s-post changing from "PFX" to "PFX"\n",
                  routine->name, mc->eax, app_base);
            mc->eax = (reg_t) app_base;
            dr_set_mcontext(drcontext, mc, NULL);
        }
#ifdef WINDOWS
        /* it's simplest to do Heap tracking here instead of correlating
         * syscalls w/ RtlCreateHeap vs large heap chunks
         */
        if (is_rtl_routine(routine->type) && pt->auxarg != 0)
            heap_region_set_heap(app_base, (app_pc)pt->auxarg);
#endif
        return app_base;
    } else {
        return NULL;
    }
}

static void
handle_alloc_failure(size_t sz, bool zeroed, bool realloc,
                     app_pc pc, dr_mcontext_t *mc)
{
    client_handle_alloc_failure(sz, zeroed, realloc, pc, mc);
}

static void
handle_malloc_post(void *drcontext, dr_mcontext_t *mc, bool realloc, app_pc post_call,
                   alloc_routine_entry_t *routine)
{
    per_thread_t *pt = (per_thread_t *) dr_get_tls_field(drcontext);
    app_pc real_base = (app_pc) mc->eax;
    size_t pad_size;
    app_pc app_base = adjust_alloc_result(drcontext, mc, &pad_size, true, routine);
    bool zeroed = IF_WINDOWS_ELSE(is_rtl_routine(routine->type) ?
                                  TEST(HEAP_ZERO_MEMORY, pt->alloc_flags) :
                                  pt->in_calloc, pt->in_calloc);
    if (pt->in_calloc) {
        /* calloc called malloc, so instruct post-calloc to NOT do anything */
        pt->malloc_from_calloc = true;
    }
#ifdef WINDOWS
    if (pt->in_realloc) {
        /* realloc called malloc, so instruct post-realloc to NOT do anything */
        pt->malloc_from_realloc = true;
    }
#endif
    if (app_base == NULL) {
        handle_alloc_failure(pt->alloc_size, zeroed, realloc, post_call, mc);
    } else {
        if (op_record_allocs) {
            malloc_add(app_base, app_base + pt->alloc_size, real_base+pad_size, false,
                       0, mc, post_call);
        }
        client_handle_malloc(pt, app_base, pt->alloc_size, real_base,
                             zeroed, realloc, mc);
    }
}

/**************************************************
 * REALLOC
 */

static void
handle_realloc_pre(void *drcontext, dr_mcontext_t *mc, bool inside, app_pc call_site,
                   alloc_routine_entry_t *routine)
{
    routine_type_t type = routine->type;
    per_thread_t *pt = (per_thread_t *) dr_get_tls_field(drcontext);
    app_pc real_base;
    bool size_in_zone = redzone_size(routine) > 0 && op_size_in_redzone;
    bool invalidated = false;
    pt->alloc_base = (app_pc) APP_ARG(mc, ARGNUM_REALLOC_PTR(type), inside);
    if (pt->alloc_base == NULL) {
        /* realloc(NULL, size) == malloc(size) (PR 416535) */
        /* call_site for call;jmp will be jmp, so retaddr better even if post-call */
        client_handle_realloc_null(inside ? get_retaddr_at_entry(mc) : call_site, mc);
        handle_malloc_pre(drcontext, mc, inside, routine);
        return;
    }
    pt->in_realloc = true;
    pt->alloc_size = (size_t) APP_ARG(mc, ARGNUM_REALLOC_SIZE(type), inside);
    real_base = pt->alloc_base;
    if (!check_valid_heap_block(pt->alloc_base, mc, inside, call_site,
                                routine->name, is_free_routine(type))) {
        pt->expect_lib_to_fail = true;
        return;
    }
    if (redzone_size(routine) > 0) {
        ASSERT(redzone_size(routine) >= 4, "redzone < 4 not supported");
        if (malloc_is_pre_us(pt->alloc_base)) {
            /* was allocated before we took control, so no redzone */
            pt->realloc_old_size =
                get_alloc_size(IF_WINDOWS_(APP_ARG(mc, 1, inside))
                               pt->alloc_base, routine);
            ASSERT(pt->realloc_old_size != -1,
                   "error getting pre-us size");
            /* if we wait until post-free to check failure, we'll have
             * races, so we invalidate here: see comments for free */
            malloc_set_valid(pt->alloc_base, false);
            invalidated = true;
            size_in_zone = false;
            LOGPT(2, pt, "realloc of pre-control "PFX"-"PFX"\n",
                   pt->alloc_base, pt->alloc_base + pt->realloc_old_size);
        } else {
            real_base -= redzone_size(routine);
            *((app_pc *)(APP_ARG_ADDR(mc, ARGNUM_REALLOC_PTR(type), inside))) =
                real_base;
        }
        /* realloc(non-NULL, 0) == free(non-NULL) (PR 493870, PR 493880) 
         * However, on some malloc impls it does re-alloc a 0-sized chunk:
         * - for dlmalloc in glibc, depending on REALLOC_ZERO_BYTES_FREES
         *   define, which is set on linux and visor, but not cygwin
         * - msvcrt does free, but HeapReAlloc does not
         *
         * Unfortunately we have to decide ahead of time whether to add
         * our redzone to the size (if we add the redzone and the app
         * assumes it's going to free, we can introduce a memory leak).
         * Rather than hardcoding which realloc does what we give up our
         * redzone.
         */
        if (pt->alloc_size > 0) {
            if (size_plus_redzone_overflow(routine, pt->alloc_size)) {
                /* We assume realloc() will fail on this so we don't handle this
                 * scenario in free(), etc. (PR 531262)
                 */
                LOG(1, "WARNING: asked-for size "PIFX" too big to fit redzone\n",
                    pt->alloc_size);
            } else {
                *((size_t *)(APP_ARG_ADDR(mc, ARGNUM_REALLOC_SIZE(type), inside))) =
                    pt->alloc_size + redzone_size(routine)*2;
            }
        }
    }
    /* We don't know how to read the Rtl headers, so we must
     * either use our redzone to store the size or call RtlSizeHeap.
     */
    if (size_in_zone)
        pt->realloc_old_size = *((size_t *)(pt->alloc_base - redzone_size(routine)));
    else {
        pt->realloc_old_size =
            get_alloc_size(IF_WINDOWS_(APP_ARG(mc, 1, inside)) real_base, routine);
        ASSERT((ssize_t)pt->realloc_old_size != -1, "error determining heap block size");
        pt->realloc_old_size -= redzone_size(routine)*2;
    }
    ASSERT((ssize_t)pt->realloc_old_size != -1,
           "error determining heap block size");
    LOGPT(2, pt, "realloc-pre "IF_WINDOWS("heap="PFX)
          " base="PFX" oldsz="PIFX" newsz="PIFX"\n",
          IF_WINDOWS_(APP_ARG(mc, 1, inside))
          pt->alloc_base, pt->realloc_old_size, pt->alloc_size);
    if (op_record_allocs && !invalidated)
        malloc_set_valid(pt->alloc_base, false);
}

static void
handle_realloc_post(void *drcontext, dr_mcontext_t *mc, app_pc post_call,
                    alloc_routine_entry_t *routine)
{
    per_thread_t *pt = (per_thread_t *) dr_get_tls_field(drcontext);
    if (pt->alloc_base == NULL) {
        /* realloc(NULL, size) == malloc(size) (PR 416535) */
        handle_malloc_post(drcontext, mc, true/*realloc*/, post_call, routine);
        return;
    }
    pt->in_realloc = false;
#ifdef WINDOWS
    if (pt->malloc_from_realloc) {
        /* post-malloc handled everything */
        pt->malloc_from_realloc = false;
        return;
    }
#endif
    if (mc->eax != 0) {
        app_pc real_base = (app_pc) mc->eax;
        size_t pad_size;
        app_pc app_base = adjust_alloc_result(drcontext, mc, &pad_size,
                                              /* no redzone for sz==0 */
                                              pt->alloc_size != 0, routine);
        app_pc old_end = pt->alloc_base + pt->realloc_old_size;
        /* realloc sometimes calls free, but shouldn't be any conflicts */
        if (op_record_allocs) {
            /* we can't remove the old one since it could have been
             * re-used already: so we leave it as invalid */
            malloc_add(app_base, app_base + pt->alloc_size, real_base+pad_size, false,
                       0, mc, post_call);
            if (pt->alloc_size == 0) {
                /* PR 493870: if realloc(non-NULL, 0) did allocate a chunk, mark
                 * as pre-us since we did not put a redzone on it
                 */
                ASSERT(real_base == app_base, "no redzone on realloc(,0)");
                malloc_set_pre_us(app_base);
                LOGPT(2, pt, "realloc-post "PFX" sz=0 no redzone padsz="PIFX"\n",
                      app_base, pad_size);
            }
        }
        client_handle_realloc(pt, pt->alloc_base, old_end - pt->alloc_base,
                              app_base, pt->alloc_size, real_base, mc);
    } else if (pt->alloc_size != 0) /* for sz==0 normal to return NULL */ {
        /* if someone else already replaced that's fine */
        if (malloc_is_pre_us_ex(pt->alloc_base, true/*check invalid too*/) ||
            op_record_allocs) {
            /* still there, and still pre-us if it was before */
            malloc_set_valid(pt->alloc_base, true);
            LOGPT(2, pt, "re-instating failed realloc as pre-control "PFX"-"PFX"\n",
                   pt->alloc_base, pt->alloc_base + pt->realloc_old_size);
        }
        handle_alloc_failure(pt->alloc_size, false, true, post_call, mc);
    }
}

/**************************************************
 * CALLOC
 */

static void
handle_calloc_pre(void *drcontext, dr_mcontext_t *mc, bool inside,
                  alloc_routine_entry_t *routine)
{
    per_thread_t *pt = (per_thread_t *) dr_get_tls_field(drcontext);
    /* void *calloc(size_t nmemb, size_t size) */
    size_t count = APP_ARG(mc, 1, inside);
    size_t each = APP_ARG(mc, 2, inside);
    /* we need to handle calloc allocating by itself, or calling malloc */
    ASSERT(!pt->in_calloc, "recursive calloc not handled");
    pt->in_calloc = true;
    pt->alloc_size = (size_t) (count * each);
    ASSERT((count == 0 || each == 0) ||
           (count * each >= count && count * each >= each), "calloc overflow");
    if (redzone_size(routine) > 0) {
        /* we may end up with more extra than we need, but it should be
         * fine: we'll only get off if we can't obtain the actual
         * malloc size post-malloc/calloc.
         * we'll keep exactly redzone_size prior to app's base,
         * so any stored size will be locatable, w/ the extra
         * all after the app's requested size.
         */
        if (count == 0 || each == 0) {
            *((size_t *)(APP_ARG_ADDR(mc, 1, inside))) = 1;
            *((size_t *)(APP_ARG_ADDR(mc, 2, inside))) = redzone_size(routine)*2;
        } else if (count < each) {
            /* More efficient to increase size of each (PR 474762) since
             * any extra due to no fractions will be multiplied by a
             * smaller number
             */
            size_t extra_each = (redzone_size(routine)*2 + count -1) / count;
            if (each + extra_each < each) {
                /* We assume calloc() will fail on this so we don't handle this
                 * scenario in free(), etc. (PR 531262)
                 * count*each could overflow: we assert above but don't handle.
                 */
                LOG(1, "WARNING: asked-for "PIFX"x"PIFX" too big to fit redzone\n",
                    count, each);
            } else
                *((size_t *)(APP_ARG_ADDR(mc, 2, inside))) = each + extra_each;
        } else {
            /* More efficient to increase the count */
            size_t extra_count = (redzone_size(routine)*2 + each - 1) / each;
            if (count + extra_count < count) {
                /* We assume calloc() will fail on this so we don't handle this
                 * scenario in free(), etc. (PR 531262).
                 * count*each could overflow: we assert above but don't handle.
                 */
                LOG(1, "WARNING: asked-for "PIFX"x"PIFX" too big to fit redzone\n",
                    count, each);
            } else
                *((size_t *)(APP_ARG_ADDR(mc, 1, inside))) = count + extra_count;
        }
    }
    LOGPT(2, pt, "calloc-pre "PIFX" x "PIFX"\n", count, each);
}

static void
handle_calloc_post(void *drcontext, dr_mcontext_t *mc, app_pc post_call,
                   alloc_routine_entry_t *routine)
{
    per_thread_t *pt = (per_thread_t *) dr_get_tls_field(drcontext);
    app_pc real_base = (app_pc) mc->eax;
    size_t pad_size;
    app_pc app_base;
    ASSERT(pt->in_calloc, "calloc tracking messed up");
    pt->in_calloc = false;
    if (pt->malloc_from_calloc) {
        /* post-malloc handled everything */
        pt->malloc_from_calloc = false;
        return;
    }
    app_base = adjust_alloc_result(drcontext, mc, &pad_size, true, routine);
    if (app_base == NULL) {
        handle_alloc_failure(pt->alloc_size, true, false, post_call, mc);
    } else {
        if (op_record_allocs) {
            malloc_add(app_base, app_base + pt->alloc_size, real_base+pad_size, false,
                       0, mc, post_call);
        }
        client_handle_malloc(pt, app_base, pt->alloc_size, real_base,
                             true/*zeroed*/, false/*!realloc*/, mc);
    }
}

#ifdef WINDOWS
/**************************************************
 * CREATE
 */

static void
handle_create_pre(void *drcontext, dr_mcontext_t *mc, bool inside)
{
    /* RtlCreateHeap(ULONG Flags,
     *               PVOID HeapBase OPTIONAL,
     *               SIZE_T ReserveSize OPTIONAL,
     *               SIZE_T CommitSize OPTIONAL,
     *               PVOID Lock OPTIONAL,
     *               PRTL_HEAP_PARAMETERS Parameters OPTIONAL);
     */
    per_thread_t *pt = (per_thread_t *) dr_get_tls_field(drcontext);
    LOG(2, "RtlCreateHeap flags="PFX", base="PFX", res="PFX", commit="PFX"\n",
        APP_ARG(mc, 1, inside), APP_ARG(mc, 2, inside),
        APP_ARG(mc, 3, inside), APP_ARG(mc, 4, inside));
    pt->in_create = true;
}

static void
handle_create_post(void *drcontext, dr_mcontext_t *mc)
{
    /* RtlCreateHeap(ULONG Flags,
     *               PVOID HeapBase OPTIONAL,
     *               SIZE_T ReserveSize OPTIONAL,
     *               SIZE_T CommitSize OPTIONAL,
     *               PVOID Lock OPTIONAL,
     *               PRTL_HEAP_PARAMETERS Parameters OPTIONAL);
     */
    per_thread_t *pt = (per_thread_t *) dr_get_tls_field(drcontext);
    pt->in_create = false;
}

/**************************************************
 * DESTROY
 */

typedef struct _heap_destroy_info_t {
    HANDLE heap;
    byte *start;
    byte *end;
} heap_destroy_info_t;

static void
heap_destroy_iter_cb(app_pc start, app_pc end, app_pc real_end,
                     bool pre_us, uint client_flags,
                     void *client_data, void *iter_data)
{
    heap_destroy_info_t *info = (heap_destroy_info_t *) iter_data;
    if (start < info->end && end >= info->start) {
        ASSERT(start >= info->start && end <= info->end,
               "alloc should be entirely inside Heap");
        /* we already called client_handle_heap_destroy() for whole-heap handling.
         * we also call a special cb for individual handling.
         * additionally, client_remove_malloc_*() will be called by malloc_remove().
         */
        client_remove_malloc_on_destroy(info->heap, start, end);
        /* yes the iteration can handle this.  this involves another lookup but
         * that's ok: RtlDestroyHeap is rare.
         */
        LOG(2, "removing chunk "PFX"-"PFX" in removed arena "PFX"-"PFX"\n",
            start, end, info->start, info->end);
        malloc_remove(start);
    }
}

static void
handle_destroy_pre(void *drcontext, dr_mcontext_t *mc, bool inside,
                   alloc_routine_entry_t *routine)
{
    /* RtlDestroyHeap(PVOID HeapHandle)
     *
     * The app does not have to free individual allocs first.
     * For removing the heap region, we should already handle that at
     * the syscall level.  We assume that such removal, other than
     * when preceded by this Windows-only routine, always frees
     * individual allocs first.
     */
    per_thread_t *pt = (per_thread_t *) dr_get_tls_field(drcontext);
    HANDLE heap = (HANDLE) APP_ARG(mc, 1, inside);
    heap_destroy_info_t info;
    info.heap = heap;
    info.start = (byte *) heap;
    info.end = heap_region_end(info.start);
    ASSERT(info.end != NULL, "cannot find heap being destroyed");
    LOG(2, "RtlDestroyHeap handle="PFX"\n", heap);
    /* FIXME: a heap interval tree would be much more efficient but
     * it slows down the common case too much (xref PR 535568) and we
     * assume RtlDestroyHeap is pretty rare.
     * If there are many mallocs and the heap is small we could instead
     * walk the heap like we used to using either shadow info (though
     * xref PR 539402 on accuracy issues) or just every 8 bytes (like
     * -leaks_only used to do).
     */
    malloc_iterate(heap_destroy_iter_cb, (void *) &info);
    /* i#264: client needs to clean up any data related to allocs inside this heap */
    client_handle_heap_destroy(drcontext, pt, heap, routine->client);
}

static void
handle_destroy_post(void *drcontext, dr_mcontext_t *mc)
{
    /* RtlDestroyHeap(ULONG Flags,
     *               PVOID HeapBase OPTIONAL,
     *               SIZE_T ReserveSize OPTIONAL,
     *               SIZE_T CommitSize OPTIONAL,
     *               PVOID Lock OPTIONAL,
     *               PRTL_HEAP_PARAMETERS Parameters OPTIONAL);
     */
    per_thread_t *pt = (per_thread_t *) dr_get_tls_field(drcontext);
}

/**************************************************
 * GETINFO
 */

static void
handle_userinfo_pre(void *drcontext, dr_mcontext_t *mc, bool inside, app_pc call_site,
                    alloc_routine_entry_t *routine)
{
    /* 3 related routines here:
     *   BOOLEAN NTAPI
     *   RtlGetUserInfoHeap(
     *       IN PVOID HeapHandle,
     *       IN ULONG Flags,
     *       IN PVOID BaseAddress,
     *       OUT PVOID *UserValue,
     *       OUT PULONG UserFlags);
     *   BOOLEAN NTAPI
     *   RtlSetUserValueHeap(
     *       IN PVOID HeapHandle,
     *       IN ULONG Flags,
     *       IN PVOID BaseAddress,
     *       IN PVOID UserValue);
     *   BOOLEAN NTAPI
     *   RtlSetUserFlagsHeap(
     *       IN PVOID HeapHandle,
     *       IN ULONG Flags,
     *       IN PVOID BaseAddress,
     *       IN ULONG UserFlags);
     */
    per_thread_t *pt = (per_thread_t *) dr_get_tls_field(drcontext);
    if (pt->in_heap_routine > 1 && pt->in_heap_adjusted > 0) {
        LOGPT(2, pt, "%s recursive call: no adjustments\n", routine->name);
        return;
    }
    pt->in_heap_adjusted = pt->in_heap_routine;
    LOG(2, "Rtl*User*Heap "PFX", "PFX", "PFX"\n",
        APP_ARG(mc, 1, inside), APP_ARG(mc, 2, inside), APP_ARG(mc, 3, inside));
    pt->alloc_base = (app_pc) APP_ARG(mc, 3, inside);
    if (check_valid_heap_block(pt->alloc_base, mc, inside, call_site,
                               routine->name, false) &&
        redzone_size(routine) > 0) {
        /* ensure wasn't allocated before we took control (so no redzone) */
        if (pt->alloc_base != NULL &&
            !malloc_is_pre_us(pt->alloc_base) &&
            /* non-recursive: else we assume base already adjusted */
            pt->in_heap_routine == 1) {
            LOG(2, "Rtl*User*Heap: changing "PFX" to "PFX"\n",
                pt->alloc_base, pt->alloc_base - redzone_size(routine)*2);
            /* FIXME: safe_write? */
            *((app_pc *)(APP_ARG_ADDR(mc, 3, inside))) -=
                redzone_size(routine);
        }
    }
}

static void
handle_userinfo_post(void *drcontext, dr_mcontext_t *mc)
{
    /* FIXME: do we need to adjust the uservalue result? */
}

/**************************************************
 * VALIDATE
 */

static void
handle_validate_pre(void *drcontext, dr_mcontext_t *mc, bool inside, app_pc call_site,
                    alloc_routine_entry_t *routine)
{
    /* we need to adjust the pointer to take into account our redzone
     * (otherwise the validate code calls ntdll!DbgPrint, DR complains
     * about int3, and the process exits)
     */
    per_thread_t *pt = (per_thread_t *) dr_get_tls_field(drcontext);
    if (pt->in_heap_routine > 1 && pt->in_heap_adjusted > 0) {
        LOGPT(2, pt, "RtlValidateHeap recursive call: no adjustments\n");
        return;
    }
    if (redzone_size(routine) > 0) {
        /* BOOLEAN NTAPI RtlValidateHeap(HANDLE Heap, ULONG Flags, PVOID Block)
         * Block is optional
         */
        app_pc block = (app_pc) APP_ARG(mc, 3, inside);
        if (block == NULL) {
            ASSERT(false, "RtlValidateHeap on entire heap not supported");
        } else if (check_valid_heap_block(block, mc, inside, call_site, "HeapValidate",
                                          false)) {
            if (!malloc_is_pre_us(block)) {
                LOG(2, "RtlValidateHeap: changing "PFX" to "PFX"\n",
                    block, block - redzone_size(routine));
                *((app_pc *)(APP_ARG_ADDR(mc, 3, inside))) =
                    block - redzone_size(routine);
            }
        }
    } 
}

#endif /* WINDOWS */

/**************************************************
 * SHARED HOOK CODE
 */

static void
alloc_hook(app_pc pc)
{
    void *drcontext = dr_get_current_drcontext();
#if defined(WINDOWS) || defined(DEBUG)
    per_thread_t *pt = (per_thread_t *) dr_get_tls_field(drcontext);
#endif
    dr_mcontext_t mc;
    int app_errno;
    dr_get_mcontext(drcontext, &mc, &app_errno);
    ASSERT(pc != NULL, "alloc_hook: pc is NULL!");
    if (op_track_heap && is_alloc_routine(pc)) {
        /* if the entry was a jmp* and we didn't see the call prior to it,
         * we did not know the retaddr, so add it now 
         */
        app_pc retaddr = get_retaddr_at_entry(&mc);
        post_call_entry_t *e;
        IF_DEBUG(bool has_entry;)
        /* We will come here again after the flush-redirect.
         * FIXME: should we try to flush the call instr itself: don't
         * know size though but can be pretty sure.
         */
        LOG(3, "alloc_hook retaddr="PFX"\n", retaddr);
        /* If we did not detect that this was an alloc call at the call site,
         * then we need to dynamically flush and mark the retaddr
         */
        hashtable_lock(&post_call_table);
        e = (post_call_entry_t *) hashtable_lookup(&post_call_table, (void*)retaddr);
        IF_DEBUG(has_entry = (e != NULL));
        /* PR 454616: we may have added an entry and started a flush
         * but not finished the flush, so we check not just the entry
         * but also the existing_instrumented flag.
         */
        if (e == NULL || !e->existing_instrumented) {
            /* PR 406714: we no longer add retaddrs statically so it's
             * normal to come here
             */
            LOG(2, "found new retaddr: call to %s from "PFX"\n",
                get_alloc_routine_name(pc), retaddr);
            if (e == NULL) {
                e = (post_call_entry_t *)
                    global_alloc(sizeof(*e), HEAPSTAT_HASHTABLE);
                e->callee = pc;
                e->existing_instrumented = false;
                hashtable_add(&post_call_table, (void*)retaddr, (void*)e);
            }
            /* now that we have an entry in the synchronized post_call_table
             * any new code coming in will be instrumented
             */
            if (dr_fragment_exists_at(drcontext, (void *)retaddr)) {
                /* I'd use dr_unlink_flush_region but it requires -enable_full_api */
                LOG(2, "flushing "PFX", should re-appear at "PFX"\n", retaddr, pc);
                STATS_INC(post_call_flushes);
                /* unlock for the flush */
                hashtable_unlock(&post_call_table);
                dr_flush_region(retaddr, 1);
                /* now we are guaranteed no thread is inside the fragment */
                /* another thread may have done a racy competing flush: should be fine */
                hashtable_lock(&post_call_table);
                e = (post_call_entry_t *)
                    hashtable_lookup(&post_call_table, (void*)retaddr);
                if (e != NULL) /* selfmod could disappear once have PR 408529 */
                    e->existing_instrumented = true;
                hashtable_unlock(&post_call_table);
                /* Since the flush will remove the fragment we're already in,
                 * we have to redirect execution to the callee again.
                 */
                mc.eip = pc;
                dr_redirect_execution(&mc, app_errno);
                ASSERT(false, "dr_redirect_execution should not return");
            }
            e->existing_instrumented = true;
        }
        hashtable_unlock(&post_call_table);
        /* If we did not yet do the pre-call instrumentation (i.e., we
         * came here via indirect call/jmp) then do it now.  Note that
         * we can't use "in_heap_routine==0 || !has_entry" as the test
         * here since we want to repeat the pre-instru for a recursive
         * invocation of a call* for which we did identify the
         * retaddr.  An example of a recursive call is glibc's
         * double-free check calling strdup and calloc.
         */
        if (hashtable_lookup(&call_site_table, (void*)retaddr) == NULL) {
            LOG(2, "in callee "PFX" %s w/o call-site pre-instru since %s from "PFX"\n",
                pc, get_alloc_routine_name(pc),
                has_entry ? "indirect caller" : "missed call site",
                retaddr);
            handle_alloc_pre_ex(retaddr, pc, true/*indirect*/, pc, true/*inside callee*/);
        } else
            ASSERT(pt->in_heap_routine > 0, "in call_site_table but missed pre");

    } 
#ifdef WINDOWS
    else if (pc == addr_KiAPC || pc == addr_KiCallback ||
             pc == addr_KiException || pc == addr_KiRaise) {
        /* our per-thread data is private per callback so we're already handling
         * cbs (though we don't expect callbacks to interrupt heap routines).
         * we handle exceptions interrupting heap routines here.
         */
        if (pc == addr_KiException) {
            /* XXX PR 408545: preserve pre-fault values and watch NtContinue and
             * longjmp (unless longjmp from top handler still invokes
             * NtContinue) and determine whether returning to heap routine.  For
             * now assuming heap routines do not handle faults.
             */
            pt->in_heap_routine = 0;
            pt->in_heap_adjusted = 0;
        }
        client_handle_Ki(drcontext, pc, &mc);
        if (pc == addr_KiCallback) {
            handle_callback(drcontext, pt);
        }
    }
#endif
    else
        ASSERT(false, "unknown reason in alloc hook");
}

static void
insert_hook(void *drcontext, instrlist_t *bb, instr_t *inst, byte *pc)
{
    dr_prepare_for_call(drcontext, bb, inst);
    PRE(bb, inst, INSTR_CREATE_push_imm(drcontext, OPND_CREATE_INT32((uint)pc)));
    PRE(bb, inst, INSTR_CREATE_call(drcontext, opnd_create_pc((app_pc)alloc_hook)));
    dr_cleanup_after_call(drcontext, bb, inst, sizeof(reg_t));
}

/* only used if op_track_heap */
static void
handle_alloc_pre_ex(app_pc call_site, app_pc expect, bool indirect,
                    app_pc actual, bool inside)
{
    void *drcontext = dr_get_current_drcontext();
    per_thread_t *pt = (per_thread_t *) dr_get_tls_field(drcontext);
    dr_mcontext_t mc;
    /* get a copy of the routine so don't need lock */
    alloc_routine_entry_t routine;
    routine_type_t type;
    if (!get_alloc_entry(expect, &routine)) {
        ASSERT(false, "fatal: can't find alloc entry");
        return; /* maybe release build will limp along */
    }
    type = routine.type;

    ASSERT(expect != NULL, "handle_alloc_pre: expect is NULL!");
    if (indirect) {
        if (expect != actual) {
            /* really a curiosity assert */
            LOG(2, "indirect call/jmp: expected "PFX", got "PFX"\n", expect, actual);
            return;
        }
    }
    LOG(2, "entering alloc routine "PFX" %s %s%s %s\n",
        expect, get_alloc_routine_name(expect),
        indirect ? "indirect" : "direct",
        pt->in_heap_routine > 0 ? " recursive" : "",
        inside ? "post-retaddr" : "pre-retaddr");
    if (pt->in_heap_routine == 0)
        client_entering_heap_routine();
    pt->in_heap_routine++;
    /* Exceed array depth => just don't record: only needed on jmp-to-post-call-bb */
    if (pt->in_heap_routine < MAX_HEAP_NESTING)
        pt->last_alloc_routine[pt->in_heap_routine] = expect;
    else {
        LOG(0, "WARNING: %s exceeded heap nesting %d >= %d\n",
            get_alloc_routine_name(expect), pt->in_heap_routine, MAX_HEAP_NESTING);
    }
    dr_get_mcontext(drcontext, &mc, NULL);
    if (is_free_routine(type)) {
#ifdef WINDOWS
        if (type == RTL_ROUTINE_FREE) {
            /* FIXME: safe_read */
            /* Note that these do not reflect what's really being freed if
             * -delay_frees > 0 
             */
            pt->alloc_flags = (uint) APP_ARG(&mc, 2, inside);
            pt->auxarg = APP_ARG(&mc, 1, inside);
        } else if (type == HEAP_ROUTINE_FREE_DBG) {
            pt->alloc_flags = 0;
            pt->auxarg = APP_ARG(&mc, 2, inside);
        } else {
            pt->alloc_flags = 0;
            pt->auxarg = 0;
        }
#endif
        handle_free_pre(drcontext, &mc, inside, call_site, &routine);
    }
    else if (is_size_routine(type)) {
#ifdef WINDOWS
        if (type == RTL_ROUTINE_SIZE) {
            /* FIXME: safe_read */
            pt->alloc_flags = (uint) APP_ARG(&mc, 2, inside);
            pt->auxarg = APP_ARG(&mc, 1, inside);
        } else if (type == HEAP_ROUTINE_SIZE_REQUESTED_DBG) {
            pt->alloc_flags = 0;
            pt->auxarg = APP_ARG(&mc, 2, inside);
        } else {
            pt->alloc_flags = 0;
            pt->auxarg = 0;
        }
#endif
        handle_size_pre(drcontext, &mc, inside, call_site, &routine);
    }
    else if (is_malloc_routine(type) ||
             is_realloc_routine(type) ||
             is_calloc_routine(type)) {
#ifdef WINDOWS
        /* RtlAllocateHeap(HANDLE heap, ULONG flags, ULONG size)
         * RtlReAllocateHeap(HANDLE heap, ULONG flags, PVOID ptr, SIZE_T size)
         */
#endif
        /* We assume that any nested call to an alloc routine (malloc, realloc,
         * calloc) is working on the same allocation and not a separate one.
         * We do our adjustments in the outer pre and the outer post.
         */
        if (pt->in_heap_routine > 1 && pt->in_heap_adjusted > 0) {
            LOGPT(2, pt, "%s recursive call: no adjustments\n",
                  get_alloc_routine_name(expect));
            return;
        }
        pt->in_heap_adjusted = pt->in_heap_routine;
#ifdef WINDOWS
        if (is_rtl_routine(type)) {
            /* FIXME: safe_read */
            pt->alloc_flags = (uint) APP_ARG(&mc, 2, inside);
            pt->auxarg = APP_ARG(&mc, 1, inside);
        } else if (type == HEAP_ROUTINE_MALLOC_DBG) {
            pt->alloc_flags = 0;
            pt->auxarg = APP_ARG(&mc, 2, inside);
        } else if (type == HEAP_ROUTINE_REALLOC_DBG || type == HEAP_ROUTINE_CALLOC_DBG) {
            pt->alloc_flags = 0;
            pt->auxarg = APP_ARG(&mc, 3, inside);
        } else {
            pt->alloc_flags = 0;
            pt->auxarg = 0;
        }
#endif
        if (is_malloc_routine(type)) {
            handle_malloc_pre(drcontext, &mc, inside, &routine);
        } else if (is_realloc_routine(type)) {
            handle_realloc_pre(drcontext, &mc, inside, call_site, &routine);
        } else {
            handle_calloc_pre(drcontext, &mc, inside, &routine);
        }
    }
#ifdef WINDOWS
    else if (type == RTL_ROUTINE_CREATE) {
        handle_create_pre(drcontext, &mc, inside);
    }
    else if (type == RTL_ROUTINE_DESTROY) {
        handle_destroy_pre(drcontext, &mc, inside, &routine);
    }
    else if (type == RTL_ROUTINE_VALIDATE) {
        handle_validate_pre(drcontext, &mc, inside, call_site, &routine);
    }
    else if (type == RTL_ROUTINE_GETINFO ||
             type == RTL_ROUTINE_SETINFO ||
             type == RTL_ROUTINE_SETFLAGS) {
        handle_userinfo_pre(drcontext, &mc, inside, call_site, &routine);
    }
    else if (type == RTL_ROUTINE_HEAPINFO) {
        /* i#280: turn both HeapEnableTerminationOnCorruption and
         * HeapCompatibilityInformation (xref i#63)
         * into no-ops.  We have the routine fail: seems better to
         * have app know than to pretend it worked?
         * I fail via invalid param rather than replacing routine
         * and making up some errno.
         */
        *((int *)APP_ARG_ADDR(&mc, 2, inside)) = -1;
    }
#endif
}

/* only used if op_track_heap */
static void
handle_alloc_pre(app_pc call_site, app_pc expect, bool indirect, app_pc actual)
{
    ASSERT(op_track_heap, "requires track_heap");
    handle_alloc_pre_ex(call_site, expect, indirect, actual,
                        false/*not inside callee yet*/);
}

/* only used if op_track_heap */
static void
handle_alloc_post(app_pc func, app_pc post_call)
{
    void *drcontext = dr_get_current_drcontext();
    per_thread_t *pt = (per_thread_t *) dr_get_tls_field(drcontext);
    dr_mcontext_t mc;
    /* get a copy of the routine so don't need lock */
    alloc_routine_entry_t routine;
    routine_type_t type;
    if (!get_alloc_entry(func, &routine)) {
        ASSERT(false, "fatal: can't find alloc entry");
        return; /* maybe release build will limp along */
    }
    type = routine.type;
    ASSERT(op_track_heap, "requires track_heap");
    ASSERT(func != NULL, "handle_alloc_post: func is NULL!");
    dr_get_mcontext(drcontext, &mc, NULL);
    if (pt->in_heap_routine == 0) {
        /* jump or other method of targeting post-call site w/o executing
         * call; or, did an indirect call that no longer matches */
        LOG(2, "post-call-site w/o executing alloc call "PFX" %s\n",
            func, get_alloc_routine_name(func));
        return;
    }
    /* We must check tailcall_target BEORE last_alloc_routine */
    if (pt->tailcall_target != NULL) {
        /* We've missed the return from a tailcalled alloc routine,
         * so process that now before this "outer" return.  PR 418138.
         */
        app_pc inner_func = pt->tailcall_target;
        app_pc inner_post = pt->tailcall_post_call;
        pt->tailcall_target = NULL;
        pt->tailcall_post_call = NULL;
        ASSERT(pt->in_heap_routine > 1, "tailcall mistake");
        handle_alloc_post(inner_func, inner_post);
    }
    if (pt->in_heap_routine < MAX_HEAP_NESTING &&
        pt->last_alloc_routine[pt->in_heap_routine] != func) {
        /* a jump or other transfer to a post-call site, where the
         * transfer happens inside a heap routine and so we can't use
         * the in_heap_routine==0 check above.  we distinguish
         * from a real post-call by comparing the last_alloc_routine.
         * this was hit in PR 465516.
         */
        LOG(2, "post-call-site inside "PFX" %s w/o executing alloc call "PFX" %s\n",
            pt->last_alloc_routine[pt->in_heap_routine],
            get_alloc_routine_name(pt->last_alloc_routine[pt->in_heap_routine]),
            func, get_alloc_routine_name(func));
        return;
    }
    /* We speculatively place our post-alloc instru, and if once in_heap_routine
     * is > 0 there are call sites that do not always call alloc routines,
     * we can decrement when we should wait -- but no such scenario should
     * exist in regular alloc code.
     */
    LOG(2, "leaving alloc routine "PFX" %s\n", func, get_alloc_routine_name(func));
    if (pt->in_heap_routine == pt->in_heap_adjusted)
        pt->in_heap_adjusted = 0;
    pt->in_heap_routine--;
    if (pt->in_heap_adjusted > 0) {
        /* some outer level did the adjustment, so nop for us */
        LOG(2, "recursive post-alloc routine "PFX" %s: no adjustments\n",
            func, get_alloc_routine_name(func));
        return;
    }
    if (pt->in_heap_routine == 0)
        client_exiting_heap_routine();

    if (is_free_routine(type)) {
        handle_free_post(drcontext, &mc, &routine);
    }
    else if (is_size_routine(type)) {
        handle_size_post(drcontext, &mc, &routine);
    }
    else if (is_malloc_routine(type)) {
        handle_malloc_post(drcontext, &mc, false/*!realloc*/, post_call, &routine);
    } else if (is_realloc_routine(type)) {
        handle_realloc_post(drcontext, &mc, post_call, &routine);
    } else if (is_calloc_routine(type)) {
        handle_calloc_post(drcontext, &mc, post_call, &routine);
#ifdef WINDOWS
    } else if (type == RTL_ROUTINE_GETINFO ||
               type == RTL_ROUTINE_SETINFO ||
               type == RTL_ROUTINE_SETFLAGS) {
        handle_userinfo_post(drcontext, &mc);
    } else if (type == RTL_ROUTINE_CREATE) {
        handle_create_post(drcontext, &mc);
    } else if (type == RTL_ROUTINE_DESTROY) {
        handle_destroy_post(drcontext, &mc);
#endif
    }
}

static void
add_post_call_address(void *drcontext, app_pc post_call, app_pc callee)
{
    /* We could add to post_call_table here if no fragment exists yet, but it's racy,
     * and we can't easily flush from here (can't do a dr_delay_flush_region
     * like we used to: resulted in bug PR 406714), so we wait for the in-callee
     * alloc hook and do a real flush there.
     * We could clean up: remove this call, eliminate the PLT call;jmp*
     * auto-detection -- but leaving for now until have more large apps
     * under our belt and we're sure we don't have too many flushes and
     * we're not missing something (#flushes should be similar since if
     * doesn't exist here won't exist when reach callee).
     */
}

static void
handle_tailcall(app_pc callee, app_pc post_call)
{
    /* For a func that uses a tailcall to call an alloc routine, we have
     * to get the retaddr dynamically.
     */
    void *drcontext = dr_get_current_drcontext();
    per_thread_t *pt = (per_thread_t *) dr_get_tls_field(drcontext);
    app_pc retaddr = 0;
    dr_mcontext_t mc;
    if (pt->in_heap_routine > 0) {
        /* Store the target so we can process both this and the "outer"
         * alloc routine at the outer's post-call point (PR 418138).
         */
        pt->tailcall_target = callee;
        pt->tailcall_post_call = post_call;
    }
    dr_get_mcontext(drcontext, &mc, NULL);
    if (safe_read((void *)mc.esp, sizeof(retaddr), &retaddr)) {
        hashtable_lock(&post_call_table);
        if (hashtable_lookup(&post_call_table, (void*)retaddr) == NULL) {
            add_post_call_address(drcontext, retaddr, callee);
        }
        hashtable_unlock(&post_call_table);
    } else {
        LOG(1, "WARNING: handle_tailcall: can't read retaddr\n");
    }
}

/* only used if op_track_heap */
static void
instrument_alloc_site(void *drcontext, instrlist_t *bb, instr_t *inst,
                      bool indirect, app_pc target, app_pc post_call)
{
    /* The plan:
     * -- pre-cti, check ind target match & set flag;
     * -- in callee, check flag (to catch indirect ctis that didn't match
     *    on our first encounter)
     *    (in-callee is inserted via insert_hook, called from bb hook);
     * -- post-cti, process alloc & clear flag
     */
    app_pc handler = (app_pc)handle_alloc_pre;
    uint num_args = 4;
    ASSERT(op_track_heap, "requires track_heap");
    LOG(3, "instrumenting alloc site "PFX" targeting "PFX" %s\n",
        instr_get_app_pc(inst), target, get_alloc_routine_name(target));
    hashtable_add(&call_site_table, (void*)post_call, (void*)1);
    dr_prepare_for_call(drcontext, bb, inst);
    if (!instr_is_call(inst)) {
        /* we assume we've already done the call and this is jmp*, so we
         * call handle_alloc_pre_ex and pass 1 for the inside param
         */
        PRE(bb, inst, INSTR_CREATE_push_imm(drcontext, OPND_CREATE_INT32(1)));
        handler = (app_pc)handle_alloc_pre_ex;
        num_args = 5;
    }
    if (indirect) {
        /* eax is already saved */
        PRE(bb, inst, INSTR_CREATE_mov_ld(drcontext, opnd_create_reg(REG_EAX),
                                          instr_get_target(inst)));
        PRE(bb, inst, INSTR_CREATE_push(drcontext, opnd_create_reg(REG_EAX)));
        PRE(bb, inst, INSTR_CREATE_push_imm(drcontext, OPND_CREATE_INT32(1)));
    } else {
        PRE(bb, inst, INSTR_CREATE_push_imm(drcontext, OPND_CREATE_INT32(0)));
        PRE(bb, inst, INSTR_CREATE_push_imm(drcontext, OPND_CREATE_INT32(0)));
    }
    PRE(bb, inst, INSTR_CREATE_push_imm(drcontext, OPND_CREATE_INT32((int)target)));
    PRE(bb, inst, INSTR_CREATE_push_imm(drcontext, OPND_CREATE_INT32
                                        ((ptr_int_t)instr_get_app_pc(inst))));
    PRE(bb, inst, INSTR_CREATE_call(drcontext, opnd_create_pc(handler)));
    dr_cleanup_after_call(drcontext, bb, inst, num_args*sizeof(reg_t));
}

/* only used if op_track_heap */
static void
instrument_post_alloc_site(void *drcontext, instrlist_t *bb, instr_t *inst,
                           app_pc target, app_pc post_call)
{
    ASSERT(op_track_heap, "requires track_heap");
    dr_insert_clean_call(drcontext, bb, inst, (void *) handle_alloc_post,
                         false/*no fpstate*/, 2,
                         OPND_CREATE_INTPTR((ptr_int_t)target),
                         OPND_CREATE_INTPTR((ptr_int_t)post_call));
}

/* Used for op_track_heap.  Our strategy is to identify call sites,
 * where we can insert both pre and post instrumentation more easily
 * than only dealing with the callee.
 * We can speculatively insert post instrumentation and detect at
 * runtime whether it is indeed post-call (assuming alloc routines
 * themselves have consistent call sites: else can decrement in_heap_routine
 * too early), but for pre-instrumentation we can't tell so we need to
 * be sure the call's target won't vary.
 * Thus, for indirect calls we try to mark the return site, for
 * performance to avoid a flush, but we wait until inside the
 * callee to perform pre-instrumentation.
 * We store in the call_site_table whether pre-instrumentation has been done.
 *
 * We assume that each call site calls at most one alloc routine.
 * This can be violated by indirect calls that vary or by a direct
 * call to A that then tailcalls B.
 * PR 418138: the latter scenario actually happens on Fedora10's
 * glibc with realloc(NULL,) tailcalling malloc(): for now we rely
 * on identifying such a tailcall statically.  The only general
 * solution is to switch to providing our own malloc routines.
 *
 * FIXME: for PR 406714 I turned add_post_call_address() into a nop:
 * if we're sure we want that long-term we can remove a lot of the
 * code here that is only trying to find retaddr ahead of time
 *
 * FIXME PR 408529: we should remove from post_call_table and call_site_table
 * on library unload or selfmod changes: for now we assume no such
 * changes to app code.
 *
 * FIXME: would be nice for DR to support post-cti instrumentation!
 * Even if we had to do custom exit stubs here, still simpler than
 * hashtables.
 */
static void
check_potential_alloc_site(void *drcontext, instrlist_t *bb, instr_t *inst)
{
    app_pc post_call = NULL;
    app_pc target = NULL;
    uint opc = instr_get_opcode(inst);
    dr_mcontext_t mc;
    /* We use opnd_compute_address() to get any segment base included.
     * Since no registers are present, mc can just be empty.
     */
    memset(&mc, 0, sizeof(mc));
    ASSERT(op_track_heap, "requires track_heap");
    if (opc == OP_call_ind IF_WINDOWS(&& !instr_is_wow64_syscall(inst))) {
        /* we're post-rebind: get current dynamic target and see if
         * a malloc or realloc routine
         */
        /* FIXME: we could get the mcontext and try to emulate up to
         * the cti point: but for non-PIC should always be an
         * absolute address!
         */
        opnd_t opnd = instr_get_target(inst);
        if (opnd_is_base_disp(opnd) && opnd_get_base(opnd) == REG_NULL &&
            opnd_get_index(opnd) == REG_NULL) {
            if (!safe_read(opnd_compute_address(opnd, &mc), sizeof(target), &target))
                target = NULL;
            LOG(2, "call* @"PFX" tgt "PFX"\n", instr_get_app_pc(inst), target);
        }
        post_call = instr_get_app_pc(inst) + instr_length(drcontext, inst);
    } else if (opc == OP_call) {
        instr_t callee;
        ASSERT(opc == OP_call, "far call not supported");
        target = opnd_get_pc(instr_get_target(inst));
        post_call = instr_get_app_pc(inst) + instr_length(drcontext, inst);

        /* Look for call;jmp* to get retaddr ahead of time and avoid having
         * to flush from inside callee.
         * However, we don't speculatively put in pre-call instrumentation,
         * in case the indirect target changes.
         */
        instr_init(drcontext, &callee);
        if (decode(drcontext, target, &callee) != NULL &&
            instr_get_opcode(&callee) == OP_jmp_ind) {
            opnd_t opnd = instr_get_target(&callee);
            app_pc jmp_target;
            /* If jmp* is to absolute address, obtain it now. */
            if (opnd_is_base_disp(opnd) && opnd_get_base(opnd) == REG_NULL &&
                opnd_get_index(opnd) == REG_NULL) {
                if (!safe_read(opnd_compute_address(opnd, &mc), sizeof(jmp_target),
                               &jmp_target))
                    jmp_target = NULL;
                LOG(2, "call;jmp* @"PFX";"PFX" tgt "PFX"\n",
                    instr_get_app_pc(inst), target, jmp_target);
            } else if (opnd_is_base_disp(opnd) && opnd_get_base(opnd) == REG_EBX &&
                       opnd_get_index(opnd) == REG_NULL) {
                /* Find the first app instr */
                instr_t *in;
                for (in = instrlist_first(bb);
                     !instr_ok_to_mangle(in);
                     in = instr_get_next(in))
                    ;
                /* If jmp* is reg-rel for PIC PLT, try to handle the
                 * common case, where ebx is adjusted immediately after
                 * the thunk call:
                 *
                 *     0x0044e775  call   $0x0040551f %esp -> %esp (%esp)
                 *       0x0040551f  mov    (%esp) -> %ebx
                 *       0x00405522  ret    %esp (%esp) -> %esp
                 *     0x0044e77a  add    $0x0011087a %ebx -> %ebx
                 *     0x0044e780  sub    $0x00000014 %esp -> %esp
                 *     0x0044e783  mov    $0x00000160 -> (%esp)
                 *     0x0044e78a  call   $0x0040545c %esp -> %esp (%esp)
                 *       0x0040545c  jmp    0x00000014(%ebx)
                 */
                if (instr_get_opcode(in) == OP_add &&
                    opnd_is_immed_int(instr_get_src(in, 0))) {
                    int offs = opnd_get_immed_int(instr_get_src(in, 0));
                    dr_mcontext_t mc;
                    dr_get_mcontext(drcontext, &mc, NULL);
                    /* opnd_compute_address will get segment base and include the
                     * mc.ebx at bb start, and we add offs to get ebx at jmp*
                     */
                    if (!safe_read(opnd_compute_address(opnd, &mc) + offs,
                                   sizeof(jmp_target), &jmp_target))
                        jmp_target = NULL;
                    LOG(2, "call;jmp* via ebx @"PFX" tgt "PFX"\n", target, jmp_target);
                }
            }
            if (jmp_target != NULL && is_alloc_routine(jmp_target)) {
                post_call = instr_get_app_pc(inst) + instr_length(drcontext, inst);
                add_post_call_address(drcontext, post_call, jmp_target);
            }
        }
        instr_free(drcontext, &callee);
    } else if (opc == OP_jmp) {
        /* Look for tail call */
        bool is_tail_call = false;
        target = opnd_get_pc(instr_get_target(inst));
        if (is_alloc_routine(target)) {
            is_tail_call = true;
        } else {
            /* May jmp to plt jmp* */
            instr_t callee;
            instr_init(drcontext, &callee);
            if (decode(drcontext, target, &callee) != NULL &&
                instr_get_opcode(&callee) == OP_jmp_ind) {
                opnd_t opnd = instr_get_target(&callee);
                if (opnd_is_base_disp(opnd) && opnd_get_base(opnd) == REG_NULL &&
                    opnd_get_index(opnd) == REG_NULL) {
                    if (safe_read(opnd_compute_address(opnd, &mc), sizeof(target),
                                  &target) &&
                        is_alloc_routine(target))
                        is_tail_call = true;
                }
            }
            instr_free(drcontext, &callee);
        }
        if (is_tail_call) {
            /* We don't know return address statically */
            app_pc post_call = instr_get_app_pc(inst) + instr_length(drcontext, inst);
            LOG(2, "tail call @"PFX" tgt "PFX"\n", instr_get_app_pc(inst), target);
            dr_insert_clean_call(drcontext, bb, inst, (void *)handle_tailcall,
                                 false, 1, OPND_CREATE_INT32((int)target),
                                 OPND_CREATE_INT32((ptr_int_t)post_call));
        }
        return;
    } else if (opc == OP_jmp_ind) {
        /* We don't do anything: if we weren't able to recognize a
         * call;jmp* pattern when we saw the call, we don't add retaddr.
         * And we never put in pre-instru for indirect cti.
         */
    } else {
        ASSERT(false, "unknown cti at call site");
    }
    if (target != NULL && is_alloc_routine(target)) {
        LOG(2, "found %s to %s @"PFX" tgt "PFX"\n",
            opc == OP_jmp_ind ? "jmp" : "call",
            get_alloc_routine_name(target), instr_get_app_pc(inst), target);
        ASSERT(post_call != NULL, "need post_call for alloc site");
        instrument_alloc_site(drcontext, bb, inst, opc != OP_call, target, post_call);
    }
}

void
alloc_instrument(void *drcontext, instrlist_t *bb, instr_t *inst,
                 bool *entering_alloc, bool *exiting_alloc)
{
    app_pc pc = instr_get_app_pc(inst);
    ASSERT(pc != NULL, "can't get app pc for instr");
    if (entering_alloc != NULL)
        *entering_alloc = false;
    if (exiting_alloc != NULL)
        *exiting_alloc = false;
    if (op_track_heap) {
        app_pc callee = post_call_lookup(pc);
        if (callee != NULL) {
            instrument_post_alloc_site(drcontext, bb, inst, callee, pc);
            if (exiting_alloc != NULL)
                *exiting_alloc = true;
        }
    }
#ifdef WINDOWS
    if (is_alloc_sysroutine(pc)) {
        insert_hook(drcontext, bb, inst, pc);
    }
#endif
    if (op_track_heap) {
        if (is_alloc_routine(pc)) {
            insert_hook(drcontext, bb, inst, pc);
            if (entering_alloc != NULL)
                *entering_alloc = true;
        }
        if ((instr_is_call(inst)
             IF_WINDOWS(&& !instr_is_wow64_syscall(inst))) ||
            instr_get_opcode(inst) == OP_jmp_ind ||
            instr_get_opcode(inst) == OP_jmp) {
            check_potential_alloc_site(drcontext, bb, inst);
        }
    }
#ifdef WINDOWS
    if (instr_get_opcode(inst) == OP_int &&
        opnd_get_immed_int(instr_get_src(inst, 0)) == CBRET_INTERRUPT_NUM) {
        dr_insert_clean_call(drcontext, bb, inst, (void *)handle_cbret, false,
                             1, OPND_CREATE_INT32(0/*not syscall*/));
    }
#endif
}
