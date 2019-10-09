/* **********************************************************
 * Copyright (c) 2011-2019 Google, Inc.  All rights reserved.
 * Copyright (c) 2009-2010 VMware, Inc.  All rights reserved.
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
#include "utils.h"
#include "heap.h"
#include "alloc.h"
#include "redblack.h"
#ifdef UNIX
# include <string.h> /* strncmp */
#else
# include "../wininc/crtdbg.h"
#endif
#include <limits.h>
#ifdef MACOS
# include <mach/mach.h>
# include <malloc/malloc.h>
#endif

#ifdef MACOS
typedef struct _enum_data_t {
    void (*cb_region)(app_pc,app_pc _IF_WINDOWS(HANDLE));
    void (*cb_chunk)(app_pc,app_pc);
} enum_data_t;
#endif

/***************************************************************************
 * UTILS
 *
 */

#ifdef WINDOWS
static size_t
region_size(app_pc start)
{
    MEMORY_BASIC_INFORMATION mbi;
    if (dr_virtual_query(start, &mbi, sizeof(mbi)) != sizeof(mbi))
        return 0;
    return mbi.RegionSize;
}
#endif

size_t
allocation_size(app_pc start, app_pc *base)
{
#ifdef WINDOWS
    app_pc pc = start;
    MEMORY_BASIC_INFORMATION mbi;
    app_pc alloc_base;
    size_t size;

    if (dr_virtual_query(pc, &mbi, sizeof(mbi)) != sizeof(mbi))
        return 0;
    if (mbi.State == MEM_FREE) {
        if (base != NULL)
            *base = NULL;
        return mbi.RegionSize;
    }

    alloc_base = mbi.AllocationBase;
    pc = (app_pc) mbi.BaseAddress + mbi.RegionSize;
    size = pc - alloc_base;

    /* keep querying until reach next alloc base */
    do {
        if (dr_virtual_query(pc, &mbi, sizeof(mbi)) != sizeof(mbi))
            break;
        if (mbi.State == MEM_FREE || mbi.AllocationBase != alloc_base)
            break;
        ASSERT(mbi.RegionSize > 0, "error querying memory");
        size += mbi.RegionSize;
        if (POINTER_OVERFLOW_ON_ADD(pc, mbi.RegionSize))
            break;
        pc += mbi.RegionSize;
    } while (true);
    ASSERT(alloc_base + size > start || alloc_base + size == NULL, "query mem error");
    if (base != NULL)
        *base = alloc_base;
    return size;
#else /* WINDOWS */
    size_t size;
    if (dr_query_memory(start, base, &size, NULL))
        return size;
    else
        return 0;
#endif /* WINDOWS */
}

#ifdef LINUX
app_pc
get_heap_start(void)
{
    static app_pc heap_start; /* cached value */
    if (heap_start == NULL) {
        app_pc cur_brk = get_brk(true/*pre-us*/);
        dr_mem_info_t info;
        module_data_t *data;
        /* Locate the heap */
        if (!dr_query_memory_ex(cur_brk - 1, &info)) {
            ASSERT(false, "cannot find heap region");
            return NULL;
        }
        if (info.type == DR_MEMTYPE_FREE || info.type == DR_MEMTYPE_IMAGE ||
            !TEST(DR_MEMPROT_WRITE, info.prot)) {
            /* Heap is empty */
            heap_start = cur_brk;
        } else {
            ASSERT(!dr_memory_is_dr_internal(info.base_pc), "heap location error");
            /* we no longer assert that these are equal b/c -replace_malloc
             * has extended the brk already
             */
            ASSERT(info.base_pc + info.size >= cur_brk, "heap location error");
            heap_start = info.base_pc;
            /* workaround for PR 618178 where /proc/maps is wrong on suse
             * and lists last 2 pages of executable as heap!
             */
            /* On some old Linux kernel, the heap might be right after the bss
             * segment. DR's map iterator used by dr_query_memory_ex cannot
             * split bss out of heap.
             * We use dr_lookup_module to find the right bounds of bss so that
             * we can check whether the base is bss, existing heap, or merge of
             * the two.
             */
            /* XXX: we still cannot handle the case that the application creates
             * memory right before the heap.
             */
            data = dr_lookup_module(info.base_pc);
            if (data != NULL) {
                if (data->start < heap_start && data->end > heap_start) {
                    heap_start = (byte *) ALIGN_FORWARD(data->end, PAGE_SIZE);
                    LOG(1, "WARNING: workaround for invalid heap_start "PFX" => "PFX"\n",
                        info.base_pc, heap_start);
                }
                dr_free_module_data(data);
            }
        }
    }
    return heap_start;
}
#endif

#ifdef WINDOWS
app_pc
get_ntdll_base(void)
{
    static app_pc ntdll_base; /* cached value */
    if (ntdll_base == NULL) {
        module_data_t *data = dr_lookup_module_by_name("ntdll.dll");
        ASSERT(data != NULL, "cannot find ntdll.dll");
        ntdll_base = data->start;
        dr_free_module_data(data);
        ASSERT(ntdll_base != NULL, "internal error finding ntdll.dll base");
    }
    return ntdll_base;
}
#endif

/* On Windows, "msvcp*.dll" is the C++ runtime library, and "msvcr*.dll" is
 * the C runtime library.  Note that "msvcirt.dll" is the IO stream library.
 * C runtime library names include "msvcr71.dll", "msvcrt.dll", "msvcrt20.dll".
 *
 * XXX i#1059: this routine is not very reliable for two reasons: first, there
 * can be multiple libc routines; second, the app can load a libc module after
 * startup.  We could switch to an interval tree that tracks load and unload
 * events for pc_is_in_libc() and try to get rid of assumptions that there's
 * just one libc.
 */
app_pc
get_libc_base(app_pc *libc_end_out OUT)
{
    static app_pc libc_base, libc_end; /* cached values */
    if (libc_base == NULL) {
        dr_module_iterator_t *iter;
        module_data_t *data;
        iter = dr_module_iterator_start();
        while (dr_module_iterator_hasnext(iter)) {
            const char *modname;
            data = dr_module_iterator_next(iter);
            modname = dr_module_preferred_name(data);
            if (modname != NULL) {
                if (text_matches_pattern(modname,
                                         IF_WINDOWS_ELSE("msvcr*", "libc.*"),
                                         FILESYS_CASELESS)) {
#ifdef WINDOWS
                    /* If we see both msvcrt.dll and MSVCRNN.dll (e.g., MSVCR80.dll),
                     * we want the latter, as the former is only there b/c of a small
                     * number of imports from the latter.
                     */
                    if (libc_base == NULL ||
                        !text_matches_pattern(modname, "msvcrt.dll", true)) {
#endif
                        libc_base = data->start;
                        libc_end = data->end;
#ifdef WINDOWS
                    }
#endif
                }
            }
            dr_free_module_data(data);
#ifdef UNIX
            /* Just take first, in unlikely case there are multiple */
            if (libc_base != NULL)
                break;
#endif
        }
        dr_module_iterator_stop(iter);
        LOG(2, "libc is "PFX"-"PFX"\n", libc_base, libc_end);
    }
    if (libc_end_out != NULL)
        *libc_end_out = libc_end;
    return libc_base;
}

bool
pc_is_in_libc(app_pc pc)
{
    app_pc end;
    app_pc start = get_libc_base(&end);
    return (pc >= start && pc < end);
}

app_pc
get_libcpp_base(void)
{
    static app_pc libcpp_base; /* cached value */
    if (libcpp_base == NULL) {
        dr_module_iterator_t *iter;
        module_data_t *data;
        iter = dr_module_iterator_start();
        while (dr_module_iterator_hasnext(iter)) {
            const char *modname;
            data = dr_module_iterator_next(iter);
            modname = dr_module_preferred_name(data);
            if (modname != NULL) {
                if (text_matches_pattern(modname,
                                         IF_WINDOWS_ELSE("msvcp*", "libstdc++.*"),
                                         FILESYS_CASELESS)) {
                        libcpp_base = data->start;
                }
            }
            dr_free_module_data(data);
            /* Just take first, in unlikely case there are multiple */
            if (libcpp_base != NULL)
                break;
        }
        dr_module_iterator_stop(iter);
    }
    return libcpp_base;
}

/***************************************************************************
 * HEAP WALK
 *
 */

/* We support multiple sets of malloc routines (xref PR 476805).
 * Ideally we'd have early injection and then we wouldn't need any
 * heap walks.
 * For now we assume that on linux only libc's heap needs initial walk,
 * and on Windows that extra padding added by higher layers doesn't
 * matter for initial heap so that Rtl heap walks are all that's required
 * for layers that end up calling Rtl heap.
 * We assume that only cygwin malloc uses its own heap.
 * FIXME PR 595798: walk cygwin initial heap, using cygwin1!sbrk to
 * locate and using cygwin's malloc_usable_size during the walk
 */

#ifdef LINUX
/* i#1707: ld.so has a heap in its data segment and also does its own mmaps */
static app_pc ld_so_base;
static app_pc ld_so_end;
static app_pc ld_so_data_base;
static app_pc ld_so_data_end;
#endif

#ifdef WINDOWS
DECLARE_NTDLL(RtlLockHeap, (IN HANDLE Heap));
DECLARE_NTDLL(RtlUnlockHeap, (IN HANDLE Heap));
DECLARE_NTDLL(RtlGetProcessHeaps, (IN ULONG count,
                                   OUT HANDLE *Heaps));
DECLARE_NTDLL(RtlWalkHeap, (IN HANDLE Heap,
                            OUT rtl_process_heap_entry_t *Info));
DECLARE_NTDLL(RtlSizeHeap, (IN HANDLE Heap,
                            IN ULONG flags,
                            IN PVOID ptr));

static void
heap_walk_init(void)
{
    module_data_t *mod = dr_lookup_module_by_name("ntdll.dll");
    ASSERT(mod != NULL, "failed to look up ntdll");
    RtlLockHeap = (RtlLockHeap_t) dr_get_proc_address(mod->handle, "RtlLockHeap");
    ASSERT(RtlLockHeap != NULL, "failed to look up required ntdll routine");
    RtlUnlockHeap = (RtlUnlockHeap_t) dr_get_proc_address(mod->handle, "RtlUnlockHeap");
    ASSERT(RtlUnlockHeap != NULL, "failed to look up required ntdll routine");
    RtlGetProcessHeaps = (RtlGetProcessHeaps_t)
        dr_get_proc_address(mod->handle, "RtlGetProcessHeaps");
    ASSERT(RtlGetProcessHeaps != NULL, "failed to look up required ntdll routine");
    RtlWalkHeap = (RtlWalkHeap_t) dr_get_proc_address(mod->handle, "RtlWalkHeap");
    ASSERT(RtlWalkHeap != NULL, "failed to look up required ntdll routine");
    RtlSizeHeap = (RtlSizeHeap_t) dr_get_proc_address(mod->handle, "RtlSizeHeap");
    ASSERT(RtlSizeHeap != NULL, "failed to look up required ntdll routine");
    dr_free_module_data(mod);
}

/* allocated_end is the end of the last valid chunk seen.
 * If there are sub-regions, this will be in the final sub-region seen.
 */
static void
walk_individual_heap(byte *heap,
                     void (*cb_region)(app_pc,app_pc _IF_WINDOWS(HANDLE)),
                     void (*cb_chunk)(app_pc,app_pc),
                     byte **allocated_end OUT)
{
    rtl_process_heap_entry_t heap_info;
    size_t size, commit_size, sub_size;
    app_pc base, sub_base;
    byte *chunk_start, *chunk_end;
    byte *last_alloc = heap;
    HANDLE process_heap = get_process_heap_handle();
    LOG(2, "walking individual heap "PFX"\n", heap);
    memset(&heap_info, 0, sizeof(heap_info));
    /* While init time is assumed to be single-threaded there are
     * enough exceptions to that that we grab the lock: */
    RtlLockHeap(heap);
    /* For tracking heap regions we use full reservation region */
    size = allocation_size(heap, &base);
    ASSERT(base == heap, "heap not at allocation base");
    commit_size = region_size(heap);
    ASSERT(commit_size == size ||
           !dr_memory_is_readable(base+commit_size, size-commit_size),
           "heap not committed followed by reserved");
    if (cb_region != NULL)
        cb_region(base, base+size, heap);
    sub_base = base;
    sub_size = size;
    while (NT_SUCCESS(RtlWalkHeap(heap, &heap_info))) {
        /* What I see doesn't quite match my quick reading of MSDN HeapWalk
         * docs.  Not really clear where cbOverhead space is: before or after
         * lpData?  Seems to not be after.  And what's up with these wFlags=0
         * entries?  For wFlags=0, RtlSizeHeap gives a too-big # when
         * passed lpData.  Also, wFlags containing PROCESS_HEAP_REGION
         * should supposedly only happen for the first block in a region,
         * but it's on for all legit blocks, it seems.
         *
         * XXX update: the RtlWalkHeap routine uses different flags from HeapWalk:
         * see the RTL_PROCESS_* flags in heap.h.  We should update this routine
         * to use those.
         */
        /* I've seen bogus lpData fields => RtlSizeHeap crashes if free mem.
         * I've also seen bogus lpData pointing into not-yet-committed
         * end of a heap!  Ridiculous.
         */
        size_t sz;
        bool bad_chunk = false;
        /* some heaps have multiple regions.  not bothering to check
         * commit vs reserve on sub-regions.
         */
        if (((app_pc)heap_info.lpData < sub_base ||
             (app_pc)heap_info.lpData >= sub_base+sub_size) &&
            /* XXX: some of these have wFlags==0x100 and some point at free
             * regions or memory occupied by something else (like our own
             * replace_malloc arenas: i#961).  We should figure out what 0x100
             * really means.  For now, requiring non-zero cbData.
             */
            heap_info.cbData > 0) {
            /* a new region or large block inside this heap */
            byte *new_base;
            size_t new_size;
            new_size = allocation_size((app_pc)heap_info.lpData, &new_base);
            if (new_base == NULL) {
                LOG(2, "free region "PFX"-"PFX" for heap @"PFX"\n",
                    heap_info.lpData, (byte *)heap_info.lpData + new_size, heap);
            } else {
                sub_base = new_base;
                sub_size = new_size;
                if (cb_region != NULL)
                    cb_region(sub_base, sub_base+sub_size, heap);
                LOG(2, "new sub-heap region "PFX"-"PFX" for heap @"PFX"\n",
                    sub_base, sub_base+sub_size, heap);
            }
        }
        /* For UNCOMMITTED, RtlSizeHeap can crash: seen on Vista.
         * Yet a TRY/EXCEPT around RtlSizeHeap is not enough:
         * Vista calls RtlReportCriticalFailure on wFlags==0 chunks.
         */
        if (!TEST(PROCESS_HEAP_REGION, heap_info.wFlags) ||
            /* sanity check: outside of committed but within main sub-region? */
            ((app_pc)heap_info.lpData < base+size &&
             (app_pc)heap_info.lpData >= base+commit_size))
            bad_chunk = true;
        LOG(2, "heap %x "PFX"-"PFX"-"PFX" %d "PFX","PFX" %x %x %x\n",
            heap_info.wFlags, heap_info.lpData,
            (app_pc)heap_info.lpData + heap_info.cbOverhead,
            (app_pc)heap_info.lpData + heap_info.cbOverhead + heap_info.cbData,
            heap_info.iRegionIndex, heap_info.Region.lpFirstBlock,
            heap_info.Region.lpLastBlock,
            heap_info.cbData,
            (bad_chunk ? 0 : RtlSizeHeap(heap, 0, (app_pc)heap_info.lpData)),
            ((bad_chunk || running_on_Vista_or_later()) ? 0 :
             RtlSizeHeap(heap, 0, (app_pc)heap_info.lpData +
                         heap_info.cbOverhead)));
        if (bad_chunk)
            continue;
        last_alloc = (byte *)heap_info.lpData + heap_info.cbData;
        if (cb_chunk == NULL)
            continue;
        /* Seems like I should be able to ignore all but PROCESS_HEAP_REGION,
         * but that's not the case.  I also thought I might need to walk
         * the Region.lpFirstBlock for PROCESS_HEAP_REGION using
         * RtlSizeHeap, but can't skip headers that way, and all regions seem
         * to show up in the RtlWalkHeap anyway.
         */
        sz = RtlSizeHeap(heap, 0, (app_pc)heap_info.lpData);
        /* I'm skipping wFlags==0 if can't get valid size as I've seen such
         * regions given out in later mallocs
         */
        chunk_start = (byte *) heap_info.lpData;
        chunk_end = chunk_start + heap_info.cbData;
        if (sz != -1 && (heap_info.wFlags > 0 || sz == heap_info.cbData)) {
            /* i#607: is this a dbgcrt heap?  If so, these Rtl heap objects have
             * dbgcrt redzones around them, and later libc-level operations will
             * point inside the dbgcrt header at the app data.  If we had symbols
             * we could look up _crtheap to identify the Heap.  For now we rule
             * out the default heap and we check whether the header "looks like"
             * the dbgcrt header.  Earlier injection would avoid this problem.
             * i#1223: VS2012 uses the ProcessHeap so we have to check that too.
             */
            if (heap_info.cbData >= DBGCRT_PRE_REDZONE_SIZE +
                DBGCRT_POST_REDZONE_SIZE) {
                _CrtMemBlockHeader *head = (_CrtMemBlockHeader *) heap_info.lpData;
                /* Check several fields.  Unlikely to match for random chunk. */
                if (heap_info.cbData == head->nDataSize +
                    DBGCRT_PRE_REDZONE_SIZE + DBGCRT_POST_REDZONE_SIZE &&
                    _BLOCK_TYPE_IS_VALID(head->nBlockUse) &&
                    head->nLine < USHRT_MAX) {
                    /* Skip the dbgcrt header */
                    chunk_start += DBGCRT_PRE_REDZONE_SIZE;
                    chunk_end -= DBGCRT_POST_REDZONE_SIZE;
                    LOG(2, "  skipping dbgcrt header => "PFX"-"PFX"\n",
                        chunk_start, chunk_end);
                }
            }
            cb_chunk(chunk_start, chunk_end);
        }
    }
    RtlUnlockHeap(heap);
    if (allocated_end != NULL)
        *allocated_end = last_alloc;
}
#endif /* WINDOWS */

#ifdef MACOS
static kern_return_t
memory_reader(task_t task, vm_address_t remote_addr, vm_size_t size, void **local)
{
    ASSERT(task == mach_task_self(), "remote task not supported");
    *local = (void *) remote_addr;
    return KERN_SUCCESS;
}

static void
enum_cb(task_t task, void *user_data, unsigned type, vm_range_t *range, unsigned count)
{
    uint i;
    LOG(2, "heap chunk(s) type="PFX"\n", type);
    if (TEST(MALLOC_PTR_IN_USE_RANGE_TYPE, type)) {
        enum_data_t *data = (enum_data_t *) user_data;
        for (i = 0; i < count; i++) {
            LOG(2, "  chunk "PFX"-"PFX"\n",
                range[i].address, range[i].address + range[i].size);
            /* XXX: find more efficient way to do this: other types of iterators? */
            if (data->cb_region != NULL &&
                !is_in_heap_region((byte *)range[i].address)) {
                data->cb_region((byte *)range[i].address,
                                (byte *)range[i].address + range[i].size);
            }
            data->cb_chunk((byte *)range[i].address,
                           (byte *)range[i].address + range[i].size);
        }
    }
}
#endif

/* Walks the heap and calls the "cb_region" callback for each heap region or arena
 * and the "cb_chunk" callback for each malloc block.
 * For Windows, calls cb_heap for each heap (one heap can contain multiple regions).
 */
void
heap_iterator(void (*cb_region)(app_pc,app_pc _IF_WINDOWS(HANDLE)),
              void (*cb_chunk)(app_pc,app_pc)
              _IF_WINDOWS(void (*cb_heap)(HANDLE)))
{
#ifdef WINDOWS
    /* We have two choices: RtlEnumProcessHeaps or RtlGetProcessHeaps.
     * The results are identical: the former invokes a callback while
     * the latter requires a passed-in array.  I've also tried
     * RtlQueryProcessDebugInformation() and it produces the same
     * list of heaps.
     */
    uint cap_heaps = 10;
    byte **heaps = global_alloc(cap_heaps*sizeof(*heaps), HEAPSTAT_MISC);
    uint i;
    uint num_heaps;
    void *drcontext = dr_get_current_drcontext();

    /* Make sure we swap to the app PEB, especially if we're invoked
     * later on for -native_until_thread!
     *
     * XXX: we assume that the callbacks during this iterator we won't run any
     * significant privlib code for which we'd want the private PEB:
     * if that's not the case we'll have to swap back and forth around
     * the callbacks.
     */
    bool was_app_state = dr_using_app_state(drcontext);
    if (!was_app_state)
        dr_switch_to_app_state_ex(drcontext, DR_STATE_PEB);

    num_heaps = RtlGetProcessHeaps(cap_heaps, heaps);
    LOG(2, "walking %d heaps\n", num_heaps);
    if (num_heaps > cap_heaps) {
        global_free(heaps, cap_heaps*sizeof(*heaps), HEAPSTAT_MISC);
        cap_heaps = num_heaps;
        heaps = global_alloc(cap_heaps*sizeof(*heaps), HEAPSTAT_MISC);
        num_heaps = RtlGetProcessHeaps(cap_heaps, heaps);
        ASSERT(cap_heaps >= num_heaps, "heap walk error");
    }
    for (i = 0; i < num_heaps; i++) {
        LOG(2, "walking heap %d "PFX"\n", i, heaps[i]);
# ifdef USE_DRSYMS
        if (heaps[i] == (byte *) get_private_heap_handle()) {
            LOG(2, "skipping private heap "PFX"\n", heaps[i]);
            continue;
        }
# endif
        if (cb_heap != NULL)
            cb_heap(heaps[i]);
        if (cb_region == NULL && cb_chunk == NULL)
            continue;
        walk_individual_heap(heaps[i], cb_region, cb_chunk, NULL);
    }
    global_free(heaps, cap_heaps*sizeof(*heaps), HEAPSTAT_MISC);
    if (!was_app_state)
        dr_switch_to_dr_state_ex(drcontext, DR_STATE_PEB);
#elif defined(LINUX)
    /* Once we have early injection (PR 204554) we won't need this.
     * For now we assume Lea's dlmalloc, the Linux glibc malloc that uses the
     * "boundary tag" method with the size of a chunk at offset 4
     * and the 2 lower bits of the size marking mmap and prev-in-use.
     * FIXME: also support PHKmalloc (though mainly used in BSD libc).
     */
    app_pc cur_brk = get_brk(true/*pre-us*/);
    app_pc heap_start, pc;
    size_t sz;

    heap_start = get_heap_start();
    pc = heap_start;

    LOG(1, "\nwalking heap from "PFX" to "PFX"\n", heap_start, cur_brk);
    if (cb_region != NULL && cur_brk > heap_start)
        cb_region(heap_start, cur_brk);
    ASSERT(ALIGNED(cur_brk, MALLOC_CHUNK_ALIGNMENT) &&
           ALIGNED(pc, MALLOC_CHUNK_ALIGNMENT), "initial brk alignment is off");
    while (pc < cur_brk) {
        app_pc user_start = pc + sizeof(sz)*2;
        sz = *(size_t *)(pc + sizeof(sz));
        ASSERT(sz > 0, "invalid pre-existing heap block");
        if (sz == 0)
            break; /* better than infinite loop */
        /* mmapped heap chunks should be found by memory_walk().
         * shouldn't show up in the heap here.  FIXME: we won't add to
         * the malloc table though: but for now we'll wait until
         * we hit such a scenario.  Not sure how to fix: try and
         * guess whether mmap has a heap header I suppose.
         */
        ASSERT(!TEST(2, sz), "mmap chunk shouldn't be in middle of heap");
        sz &= ~3;
        LOG(3, "  heap chunk "PFX"-"PFX"\n", pc, pc+sz);
        if (POINTER_OVERFLOW_ON_ADD(pc, sz) || pc + sz >= cur_brk) {
            /* malloc_usable_size() will crash trying to read next chunk's
             * prev size field so just quit now
             */
            LOG(2, "    == 'top' of heap\n\n");
            ASSERT(pc + sz == cur_brk, "'top' of heap has unexpected size");
            break;
        }
        /* Whether this chunk is allocated or free is stored in the next
         * chunk's size field.  Xref PR 474912.
         */
        ASSERT(pc + sz + sizeof(sz)*2 < cur_brk, "'top' of heap missing!");
        if (TEST(1, *((size_t*)(pc + sz + sizeof(sz))))) {
            /* In-use */
            LOG(2, "  heap in-use chunk "PFX"-"PFX"\n", pc, pc+sz + sizeof(sz));
# ifdef DEBUG
            if (libc_malloc_usable_size != NULL) {
                size_t check_sz = libc_malloc_usable_size(user_start);
                /* The prev_size of next chunk is really a usable footer
                 * for this chunk
                 */
                ASSERT(check_sz - sizeof(sz) == (pc + sz - user_start),
                       "libc malloc doesn't match assumptions");
            }
# endif
            if (cb_chunk != NULL)
                cb_chunk(user_start, pc + sz + sizeof(sz));
        }
        pc += sz;
    }
    if (cb_region != NULL && ld_so_data_base != NULL) {
        /* i#1707: ld.so uses its own data segment for initial heap calls */
        cb_region(ld_so_data_base, ld_so_data_end);
    }
#else /* MACOS */
    /* XXX: switch to methods that don't invoke library routines */
    vm_address_t *zones;
    unsigned int num_zones, i;
# ifdef DEBUG
    malloc_statistics_t stats;
# endif
    enum_data_t data = {cb_region, cb_chunk};
    kern_return_t kr = malloc_get_all_zones(mach_task_self(), 0, &zones, &num_zones);
    if (kr != KERN_SUCCESS) {
        ASSERT(false, "malloc_get_all_zones failed");
        return;
    }
    for (i = 0; i < num_zones; i++) {
        malloc_zone_t *zone = (malloc_zone_t *) zones[i];
        LOG(2, "heap zone %d: %p %s\n", i, zone, malloc_get_zone_name(zone));
# ifdef DEBUG
        malloc_zone_statistics(zone, &stats);
        LOG(2, "\tblocks=%u, used=%zd, max used=%zd, reserved=%zd\n",
            stats.blocks_in_use, stats.size_in_use, stats.max_size_in_use,
            stats.size_allocated);
# endif
        kr = zone->introspect->enumerator
            (mach_task_self(), (void *) &data, MALLOC_PTR_IN_USE_RANGE_TYPE,
             (vm_address_t) zone, memory_reader, enum_cb);
        if (kr != KERN_SUCCESS) {
            ASSERT(false, "malloc enumeration failed");
        }
    }
#endif /* WINDOWS */
}

#ifdef WINDOWS
/* Returns in *end the end of the last valid chunk seen.
 * If there are sub-regions, this will be in the final sub-region seen.
 */
byte *
heap_allocated_end(HANDLE heap)
{
    byte *end = NULL;
    walk_individual_heap((byte *)heap, NULL, NULL, &end);
    return end;
}
#endif

#ifdef LINUX
bool
pc_is_in_ld_so(app_pc pc)
{
    if (ld_so_base == NULL) {
        module_data_t *data;
        dr_module_iterator_t *iter;
        iter = dr_module_iterator_start();
        while (dr_module_iterator_hasnext(iter)) {
            data = dr_module_iterator_next(iter);
            const char *modname = dr_module_preferred_name(data);
            if (modname != NULL && strncmp(modname, "ld-linux", 8) == 0) {
                int i;
                ld_so_base = data->start;
                ld_so_end = data->end;
                for (i = 0; i < data->num_segments; i++) {
                    if (TEST(DR_MEMPROT_WRITE, data->segments[i].prot)) {
                        LOG(2, "adding ld.so data segment heap "PFX"-"PFX"\n",
                            data->segments[i].start, data->segments[i].end);
                        ld_so_data_base = data->segments[i].start;
                        ld_so_data_end =  data->segments[i].end;
                    }
                }
            }
            dr_free_module_data(data);
        }
        dr_module_iterator_stop(iter);
    }
    return pc >= ld_so_base && pc < ld_so_end;
}
#endif

/***************************************************************************
 * HEAP REGION LIST
 *
 * For tracking the heap reservation regions, so we can suppress heap header
 * accesses from non-exported heap routines (like RtlpHeapIsLocked)
 */

/* We use a red-black tree so we can look up intervals efficiently.
 * We could use a sorted array-based binary tree instead, which
 * might be more efficient for most apps, since we have relatively
 * few insertions and deletions.
 * We store a "uint flags" as our custom field which identifies
 * pre-us regions and arenas.
 * An arena is a region used to dole out malloc chunks: versus
 * a single, oversized alloc allocated outside of the main arena.
 */
static rb_tree_t *heap_tree;
static void *heap_lock;

/* Payload stored in each node */
typedef struct _heap_info_t {
    uint flags;
#ifdef WINDOWS
    HANDLE heap;
#endif
} heap_info_t;

/* for iterating over all regions */
typedef struct _heap_iter_t {
    bool (*iter_cb)(byte *start, byte *end, uint flags
                    _IF_WINDOWS(HANDLE heap), void *data);
    void *cb_data;
} heap_iter_t;

#ifdef STATISTICS
uint heap_regions;
#endif

/* provided by user */
static void (*cb_add)(app_pc start, app_pc end, dr_mcontext_t *mc);
static void (*cb_remove)(app_pc start, app_pc end, dr_mcontext_t *mc);

static void
heap_info_delete(void *p)
{
    heap_info_t *info = (heap_info_t *) p;
    global_free(info, sizeof(*info), HEAPSTAT_RBTREE);
}

void
heap_region_init(void (*region_add_cb)(app_pc, app_pc, dr_mcontext_t *mc),
                 void (*region_remove_cb)(app_pc, app_pc, dr_mcontext_t *mc))
{
    heap_lock = dr_rwlock_create();
    cb_add = region_add_cb;
    cb_remove = region_remove_cb;
    heap_tree = rb_tree_create(heap_info_delete);
#ifdef WINDOWS
    heap_walk_init();
#endif
#ifdef LINUX
    pc_is_in_ld_so(NULL);
#endif
}

void
heap_region_exit(void)
{
    dr_rwlock_write_lock(heap_lock);
    rb_tree_destroy(heap_tree);
    dr_rwlock_write_unlock(heap_lock);
    dr_rwlock_destroy(heap_lock);
}

void
heap_region_add(app_pc start, app_pc end, uint flags, dr_mcontext_t *mc)
{
    heap_info_t *info = (heap_info_t *) global_alloc(sizeof(*info), HEAPSTAT_RBTREE);
    IF_DEBUG(rb_node_t *existing;)
    dr_rwlock_write_lock(heap_lock);
    LOG(2, "adding heap region "PFX"-"PFX" %s\n", start, end,
        TEST(HEAP_ARENA, flags) ? "arena" : "chunk");
    STATS_INC(heap_regions);
    if (cb_add != NULL)
        cb_add(start, end, mc);
    info->flags = flags;
    IF_WINDOWS(info->heap = INVALID_HANDLE_VALUE;)
    IF_DEBUG(existing =)
        rb_insert(heap_tree, start, (end - start), (void *) info);
    ASSERT(existing == NULL, "new heap region overlaps w/ existing");
    dr_rwlock_write_unlock(heap_lock);
}

static heap_info_t *
heap_info_clone(heap_info_t *info)
{
    heap_info_t *info2 = (heap_info_t *)
        global_alloc(sizeof(*info2), HEAPSTAT_RBTREE);
    ASSERT(info != NULL, "invalid param");
    memcpy(info2, info, sizeof(*info2));
    return info2;
}

bool
heap_region_remove(app_pc start, app_pc end, dr_mcontext_t *mc)
{
    rb_node_t *node = NULL;
    app_pc node_start;
    size_t node_size;
    dr_rwlock_write_lock(heap_lock);
    node = rb_overlaps_node(heap_tree, start, end);
    if (node != NULL) {
        heap_info_t *info, *clone = NULL;
        rb_node_fields(node, &node_start, &node_size, (void **)&info);
        LOG(2, "removing heap region "PFX"-"PFX" from "PFX"-"PFX"\n",
            start, end, node_start, node_start + node_size);
        STATS_DEC(heap_regions);
        /* we assume overlaps at most one node, and that the info field can
         * be cloned or reused for any remaining piece(s) after removal
         */
        ASSERT(node_start + node_size >= end, "shouldn't remove multiple regions");
        if (cb_remove != NULL)
            cb_remove(start, end, mc);
        if (node_start < start || node_start + node_size > end)
            clone = heap_info_clone(info);
        rb_delete(heap_tree, node); /* deletes info */
        if (node_start < start) {
            ASSERT(clone != NULL, "error in earlier clone cond");
            rb_insert(heap_tree, node_start, (start - node_start), (void *)clone);
            if (node_start + node_size > end)
                clone = heap_info_clone(clone);
            else
                clone = NULL;
            STATS_INC(heap_regions);
        }
        if (node_start + node_size > end) {
            ASSERT(clone != NULL, "error in earlier clone cond");
            rb_insert(heap_tree, end, (node_start + node_size - end), (void *)clone);
            clone = NULL;
            STATS_INC(heap_regions);
        }
        ASSERT(clone == NULL, "error in earlier clone cond");
    }
    dr_rwlock_write_unlock(heap_lock);
    return node != NULL;
}

bool
heap_region_adjust(app_pc start, app_pc new_end)
{
    rb_node_t *node = NULL;
    app_pc node_start;
    size_t node_size;
    dr_rwlock_write_lock(heap_lock);
    node = rb_in_node(heap_tree, start);
    if (node != NULL) {
        heap_info_t *info, *clone;
        rb_node_fields(node, &node_start, &node_size, (void **)&info);
        ASSERT(start == node_start, "adjust: invalid start");
        LOG(2, "adjusting heap region from "PFX"-"PFX" to "PFX"-"PFX"\n",
            start, node_start + node_size, node_start, new_end);
        /* FIXME: have cb take in a "modify" vs "add"? */
        if (cb_add != NULL)
            cb_add(node_start, new_end, 0);
        clone = heap_info_clone(info);
        rb_delete(heap_tree, node); /* deletes info */
        rb_insert(heap_tree, node_start, (new_end - node_start), (void *)clone);
    }
    dr_rwlock_write_unlock(heap_lock);
    return node != NULL;
}

bool
heap_region_bounds(app_pc pc, app_pc *start_out/*OPTIONAL*/,
                   app_pc *end_out/*OPTIONAL*/, uint *flags_out/*OPTIONAL*/)
{
    rb_node_t *node = NULL;
    heap_info_t *info;
    app_pc node_start;
    size_t node_size;
    bool res = false;
    dr_rwlock_read_lock(heap_lock);
    node = rb_in_node(heap_tree, pc);
    if (node != NULL) {
        res = true;
        rb_node_fields(node, &node_start, &node_size, (void **)&info);
        if (start_out != NULL)
            *start_out = node_start;
        if (end_out != NULL)
            *end_out = node_start + node_size;
        if (flags_out != NULL)
            *flags_out = info->flags;
    }
    dr_rwlock_read_unlock(heap_lock);
    return res;
}

bool
is_in_heap_region(app_pc pc)
{
    bool res = false;
    dr_rwlock_read_lock(heap_lock);
    res = (rb_in_node(heap_tree, pc) != NULL);
    dr_rwlock_read_unlock(heap_lock);
    return res;
}

bool
is_entirely_in_heap_region(app_pc start, app_pc end)
{
    rb_node_t *node = NULL;
    app_pc node_start;
    size_t node_size;
    bool res = false;
    dr_rwlock_read_lock(heap_lock);
    node = rb_overlaps_node(heap_tree, start, end);
    if (node != NULL) {
        /* we do not support passing in a range that include multiple
         * nodes, even when the nodes are adjacent (we don't do merging)
         */
        rb_node_fields(node, &node_start, &node_size, NULL);
        res = (start >= node_start && end <= node_start + node_size);
    }
    dr_rwlock_read_unlock(heap_lock);
    return res;
}

uint
get_heap_region_flags(app_pc pc)
{
    rb_node_t *node = NULL;
    uint res = 0;
    heap_info_t *info;
    dr_rwlock_read_lock(heap_lock);
    node = rb_in_node(heap_tree, pc);
    if (node != NULL) {
        rb_node_fields(node, NULL, NULL, (void **)&info);
        res = info->flags;
    }
    dr_rwlock_read_unlock(heap_lock);
    return res;
}

#ifdef WINDOWS
# ifdef DEBUG
static void
debug_walk_region(app_pc start, app_pc end _IF_WINDOWS(HANDLE heap))
{
    LOG(1, "heap "PFX" "PFX"-"PFX"\n", heap, start, end);
}
static void
debug_walk_chunk(app_pc start, app_pc end)
{
    LOG(1, "\tchunk "PFX"-"PFX"\n", start, end);
}
# endif

bool
heap_region_set_heap(app_pc pc, HANDLE heap)
{
    rb_node_t *node = NULL;
# ifdef USE_DRSYMS
    ASSERT(heap != get_private_heap_handle(), "app using priv heap");
# endif
    dr_rwlock_write_lock(heap_lock);
    node = rb_in_node(heap_tree, pc);
    if (node != NULL) {
        heap_info_t *info;
        app_pc node_start;
        size_t node_size;
        rb_node_fields(node, &node_start, &node_size, (void **)&info);
        if (info->heap != heap) {
            DOLOG(1, {
                if (info->heap != INVALID_HANDLE_VALUE) {
                    LOG(1, "\nHEAP WALK ON INCONSISTENCY\n");
                    heap_iterator(debug_walk_region, debug_walk_chunk _IF_WINDOWS(NULL));
                }
            });
            ASSERT(info->heap == INVALID_HANDLE_VALUE, "conflicts in Heap for region");
            info->heap = heap;
            LOG(2, "set heap region "PFX"-"PFX" Heap to "PFX"\n",
                node_start, node_start + node_size, heap);
        }
    }
    dr_rwlock_write_unlock(heap_lock);
    return node != NULL;
}

HANDLE
heap_region_get_heap(app_pc pc)
{
    rb_node_t *node = NULL;
    HANDLE res = INVALID_HANDLE_VALUE;
    heap_info_t *info;
    dr_rwlock_read_lock(heap_lock);
    node = rb_in_node(heap_tree, pc);
    if (node != NULL) {
        rb_node_fields(node, NULL, NULL, (void **)&info);
        res = info->heap;
    }
    dr_rwlock_read_unlock(heap_lock);
    return res;
}

#endif /* WINDOWS */

static bool
rb_iter_cb(rb_node_t *node, void *data)
{
    heap_iter_t *iter = (heap_iter_t *) data;
    heap_info_t *info;
    byte *node_start;
    size_t node_size;
    ASSERT(iter != NULL, "invalid iter param");
    rb_node_fields(node, &node_start, &node_size, (void **)&info);
    return (*iter->iter_cb)(node_start, node_start + node_size, info->flags
                            _IF_WINDOWS(info->heap), iter->cb_data);
}

void
heap_region_iterate(bool (*iter_cb)(byte *start, byte *end, uint flags
                                    _IF_WINDOWS(HANDLE heap), void *data),
                    void *data)
{
    heap_iter_t iter;
    iter.iter_cb = iter_cb;
    iter.cb_data = data;
    dr_rwlock_read_lock(heap_lock);
    rb_iterate(heap_tree, rb_iter_cb, (void *) &iter);
    dr_rwlock_read_unlock(heap_lock);
}

