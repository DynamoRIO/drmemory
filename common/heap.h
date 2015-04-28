/* **********************************************************
 * Copyright (c) 2011-2015 Google, Inc.  All rights reserved.
 * Copyright (c) 2007-2009 VMware, Inc.  All rights reserved.
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

#ifndef _HEAP_H_
#define _HEAP_H_ 1

/***************************************************************************
 * UTILS
 */

size_t
allocation_size(app_pc start, app_pc *base);

#ifdef LINUX
app_pc
get_heap_start(void);
#endif

#ifdef WINDOWS
app_pc
get_ntdll_base(void);
#endif

app_pc
get_libc_base(app_pc *libc_end OUT);

bool
pc_is_in_libc(app_pc pc);

app_pc
get_libcpp_base(void);

#ifdef LINUX
bool
pc_is_in_ld_so(app_pc pc);
#endif

/***************************************************************************
 * HEAP WALK
 */

/* Walks the heap and calls the "cb_region" callback for each heap region or arena
 * and the "cb_chunk" callback for each malloc block.
 */
void
heap_iterator(void (*cb_region)(app_pc start, app_pc end _IF_WINDOWS(HANDLE handle)),
              void (*cb_chunk)(app_pc start, app_pc end)
              _IF_WINDOWS(void (*cb_heap)(HANDLE)));

#ifdef WINDOWS
/* Returns the end of the last valid chunk seen.
 * If there are sub-regions, this will be in the final sub-region seen.
 */
byte *
heap_allocated_end(HANDLE heap);
#endif

#ifdef WINDOWS
/* Heap data type shared between heap.c and alloc_replace.c */
# ifdef X64
/* The actual convert from rtl_process_heap_entry_t to PROCESS_HEAP_ENTRY
 * is something like below:
 *   heap_entry->lpData = rtl_heap_entry->lpData;
 *   heap_entry->cbData = (DWORD)rtl_heap_entry->cbData;
 *   heap_entry->cbOverhead = rtl_heap_entry->cbOverhead;
 *   heap_entry->iRegionIndex = rtl_heap_entry->iRegionIndex;
 *   if (!TEST(rtl_heap_entry->flags, 1)) {
 *       // jmp 7fe`fda6321f
 *       ...
 *   } else if (TEST(rtl_heap_entry->flags, 2)) {
 *       // jmp 7fe`fda63263
 *       if (TEST(rtl_heap_entry->flags, 0x100)) {
 *           heap_entry->wFlags = 0;
 *       } else {
 *           heap_entry->wFlags = 2;
 *           heap_entry->Region = NULL;
 *       }
 *   } else {
 *       heap_entry->wFlags = 1;
 *       heap_entry.Region = rtl_heap_entry.Region;
 *   }
 * The major difference between the two is the size of cbData.
 * The rtl_process_heap_entry_t.flags also do not exactly match with
 * PROCESS_HEAP_ENTRY.wFlags (see the defines below).
 */
typedef struct _rtl_process_heap_entry_t {
    PVOID lpData;
    reg_t cbData;
    BYTE cbOverhead;
    BYTE iRegionIndex;
    WORD wFlags;
    union {
        struct {
            HANDLE hMem;
            DWORD dwReserved[ 3 ];
        } Block;
        struct {
            DWORD dwCommittedSize;
            DWORD dwUnCommittedSize;
            LPVOID lpFirstBlock;
            LPVOID lpLastBlock;
        } Region;
    };
} rtl_process_heap_entry_t;
# else
typedef PROCESS_HEAP_ENTRY rtl_process_heap_entry_t;
# endif

/* Different flags are used in RtlWalkHeap vs HeapWalk */
# define RTL_PROCESS_HEAP_REGION             0x0002
# define RTL_PROCESS_HEAP_UNCOMMITTED_RANGE  0x0100
# define RTL_PROCESS_HEAP_ENTRY_BUSY         0x0001
#endif

/***************************************************************************
 * HEAP REGION LIST
 */

#ifdef STATISTICS
extern uint heap_regions;
#endif

enum {
    HEAP_PRE_US   = 0x01,
    HEAP_ARENA    = 0x02,
    HEAP_MMAP     = 0x04,
};

void
heap_region_init(void (*region_add_cb)(app_pc, app_pc, dr_mcontext_t *mc),
                 void (*region_remove_cb)(app_pc, app_pc, dr_mcontext_t *mc));

void
heap_region_exit(void);

void
heap_region_add(app_pc start, app_pc end, uint flags, dr_mcontext_t *mc);

bool
heap_region_remove(app_pc start, app_pc end, dr_mcontext_t *mc);

bool
heap_region_adjust(app_pc base, app_pc new_end);

bool
heap_region_bounds(app_pc pc, app_pc *start_out/*OPTIONAL*/,
                   app_pc *end_out/*OPTIONAL*/, uint *flags_out/*OPTIONAL*/);

bool
is_in_heap_region(app_pc pc);

bool
is_entirely_in_heap_region(app_pc start, app_pc end);

uint
get_heap_region_flags(app_pc pc);

#ifdef WINDOWS
bool
heap_region_set_heap(app_pc pc, HANDLE heap);

HANDLE
heap_region_get_heap(app_pc pc);

#endif /* WINDOWS */

void
heap_region_iterate(bool (*iter_cb)(byte *start, byte *end, uint flags
                                    _IF_WINDOWS(HANDLE heap), void *data),
                    void *data);

#endif /* _HEAP_H_ */
