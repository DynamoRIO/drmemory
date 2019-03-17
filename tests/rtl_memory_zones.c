/* **********************************************************
 * Copyright (c) 2011-2019 Google, Inc.  All rights reserved.
 * **********************************************************/

/* Dr. Memory: the memory debugger
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation;
 * version 2.1 of the License, and no later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * Library General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

/* i#318: Test our understanding of ntdll's "memory zone" related functions.
 * This test verifies that the routines behave the way we expect them to, and
 * that the memory they provide doesn't show up when we iterate heaps.
 */

#include <windows.h>
#include <stdio.h>

#include "rtl_memory_zones.h"

NTSTATUS
(NTAPI *RtlGetProcessHeaps)(
    IN ULONG count,
    OUT HANDLE *Heaps
    );

static int
addr_not_in_heap(char *zone)
{
    /* 10 heaps should be enough.  By default we only have 2. */
    char *heaps[10];
    UINT num_heaps = RtlGetProcessHeaps(10, heaps);
    UINT i;
    MEMORY_BASIC_INFORMATION mbi;
    int found = 0;
    if (num_heaps > 10) {
        printf("more than 10 heaps, aborting\n");
        fflush(stdout);
        abort();
    }
    for (i = 0; i < num_heaps; i++) {
        char *start;
        char *end;
        VirtualQuery(heaps[i], &mbi, sizeof(mbi));
        start = (char*)mbi.AllocationBase;
        end = (char*)mbi.BaseAddress + mbi.RegionSize;
        if (start <= zone && zone < end)
            found = 1;
    }
    return !found;
}

/* Print the status if it's not zero.
 */
static void
check_status(const char *routine, NTSTATUS status)
{
    if (status < 0) {
        printf("unsuccessful status code when calling %s: 0x%lx\n", routine, status);
        fflush(stdout);
        abort();
    }
}

/* Shorthand for checking all ntdll calls.
 * Usage: CHECK(RtlCreateMemoryZone, &zone, 0, 4096)
 */
#define CHECK(routine, ...) check_status(#routine, routine(__VA_ARGS__))

#define BLOCK_SIZE 4096
#define NUM_BLOCKS 4

static void
use_memory_zones(void)
{
    PRTL_MEMORY_ZONE zone;
    PVOID block;
    int i;

    printf("\nTesting Rtl*MemoryZone:\n");

    CHECK(RtlCreateMemoryZone, &zone, NUM_BLOCKS * BLOCK_SIZE, 0);
    printf("zone: %p\n", zone);
    for (i = 0; i < NUM_BLOCKS; i++) {
        CHECK(RtlAllocateMemoryZone, zone, BLOCK_SIZE, &block);
        printf("block %d offset: 0x%05lx\n", i, (INT_PTR)block - (INT_PTR)zone);
        memset(block, 0xcc, BLOCK_SIZE);  /* Writes, should be addressable. */
    }
    CHECK(RtlAllocateMemoryZone, zone, BLOCK_SIZE - sizeof(*zone), &block);
    printf("can allocate from padding: %d\n", (block != NULL));
    RtlAllocateMemoryZone(zone, 1, &block);  /* Don't check, expect failure. */
    printf("cannot allocate beyond padding: %d\n", (block == NULL));
    CHECK(RtlResetMemoryZone, zone);
    CHECK(RtlAllocateMemoryZone, zone, BLOCK_SIZE, &block);
    printf("sizeof(*zone) == block - zone: %d\n",
           (sizeof(*zone) == (INT_PTR)block - (INT_PTR)zone));
    printf("Segment.NextSegment == NULL: %d\n",
           zone->Segment.NextSegment == NULL);
    printf("Segment.Size: %zu\n", zone->Segment.Size);
    printf("Segment.Next: 0x%05lx\n",
           (INT_PTR)zone->Segment.Next - (INT_PTR)zone);
    printf("Segment.Limit: 0x%05lx\n",
           (INT_PTR)zone->Segment.Limit - (INT_PTR)zone);
    printf("FirstSegment == zone: %d\n", (void*)zone->FirstSegment == (void*)zone);
    printf("zone is not in heap: %d\n", addr_not_in_heap((char*)zone));
    CHECK(RtlResetMemoryZone, zone);
    CHECK(RtlDestroyMemoryZone, zone);
}

static void
use_memory_lookaside_blocks(void)
{
    PVOID lookaside;
    PVOID block;
    int i;
    NTSTATUS sts;

    printf("\nTesting Rtl*MemoryBlockLookaside:\n");

    CHECK(RtlCreateMemoryBlockLookaside, &lookaside, 0,
          NUM_BLOCKS * BLOCK_SIZE, 256, BLOCK_SIZE);
    printf("lookaside: %p\n", lookaside);
    printf("lookaside is not in heap: %d\n", addr_not_in_heap((char*)lookaside));
    for (i = 0; i < NUM_BLOCKS; i++) {
        block = NULL;
        CHECK(RtlAllocateMemoryBlockLookaside, lookaside, BLOCK_SIZE, &block);
        memset(block, 0xcc, BLOCK_SIZE);  /* Writes, should be addressable. */
        printf("block %d is not in heap: %d\n",
               i, addr_not_in_heap((char*)block));
    }
    block = NULL;
    sts = RtlAllocateMemoryBlockLookaside(lookaside, BLOCK_SIZE, &block);
    printf("cannot allocate beyond size: %d\n", (int)(sts < 0));
    printf("block: %p\n", block);
    CHECK(RtlResetMemoryBlockLookaside, lookaside);
    block = NULL;
    CHECK(RtlAllocateMemoryBlockLookaside, lookaside, BLOCK_SIZE, &block);
    /* XXX: This usually comes out as 00000008 for me despite a successful
     * status code, which seems pretty broken.
     */
    printf("block after reset: %p\n", i, block);
    CHECK(RtlResetMemoryBlockLookaside, lookaside);
    CHECK(RtlDestroyMemoryBlockLookaside, lookaside);
}

/* Used to avoid writing out all the function pointer type casts. */
static void
get_proc_address_into(void **proc, HMODULE mod, const char *name)
{
    *proc = (void*)GetProcAddress(mod, name);
}

int
main(void)
{
    HMODULE ntdll = GetModuleHandle("ntdll.dll");
    printf("begin\n");

#define GET_PROC(rtl_name) \
    get_proc_address_into((void**)&rtl_name, ntdll, #rtl_name)

    GET_PROC(RtlGetProcessHeaps);
    /* Memory zone routines. */
    GET_PROC(RtlCreateMemoryZone);
    GET_PROC(RtlAllocateMemoryZone);
    GET_PROC(RtlResetMemoryZone);
    GET_PROC(RtlDestroyMemoryZone);
    /* Memory block lookaside routines. */
    GET_PROC(RtlCreateMemoryBlockLookaside);
    GET_PROC(RtlAllocateMemoryBlockLookaside);
    GET_PROC(RtlResetMemoryBlockLookaside);
    GET_PROC(RtlDestroyMemoryBlockLookaside);

#undef GET_PROC

    use_memory_zones();
    use_memory_lookaside_blocks();
    printf("done\n");
    return 0;
}
