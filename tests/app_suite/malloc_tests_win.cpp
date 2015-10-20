/* **********************************************************
 * Copyright (c) 2014-2015 Google, Inc.  All rights reserved.
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

#include "gtest/gtest.h"
#include "app_suite_utils.h"
#include <stdio.h>
#include <stdlib.h>
#include <windows.h>

TEST(MallocTests, HeapCompact) {
    HANDLE heap = GetProcessHeap();
    ASSERT_NE(heap, (HANDLE)NULL);
    SIZE_T largest = HeapCompact(heap, 0);
    ASSERT_GT(largest, 64);
}

TEST(MallocTests, HeapInformation) {
    HANDLE heap = GetProcessHeap();
    ASSERT_NE(heap, (HANDLE)NULL);
    ULONG heap_type;
    SIZE_T got;
    BOOL res = HeapQueryInformation(heap, HeapCompatibilityInformation, &heap_type,
                                    sizeof(heap_type), &got);
    ASSERT_EQ(res, TRUE);
    ASSERT_EQ(got, sizeof(heap_type));
    ASSERT_LT(heap_type, 3); /* 0, 1, 2 are the only valid values */

    heap_type = 2;
    res = HeapSetInformation(heap, HeapCompatibilityInformation, &heap_type,
                             sizeof(heap_type));
    ASSERT_EQ(res, TRUE);
    heap_type = 2;

    res = HeapSetInformation(heap, HeapEnableTerminationOnCorruption, NULL, 0);
    ASSERT_EQ(res, TRUE);
}

TEST(MallocTests, GetProcessHeaps) {
    DWORD max_heaps = 100;
    DWORD num_heaps;
    HANDLE *heaps = new HANDLE[max_heaps];
    num_heaps = GetProcessHeaps(max_heaps, heaps);
    while (num_heaps > max_heaps) {
        delete [] heaps;
        max_heaps = num_heaps;
        heaps = new HANDLE[max_heaps];
        num_heaps = GetProcessHeaps(max_heaps, heaps);
    }
    for (int i = 0; i < num_heaps; i++) {
        BOOL res = HeapLock(heaps[i]);
        ASSERT_EQ(res, TRUE);
        DWORD regions = 0;
        PROCESS_HEAP_ENTRY info;
        info.lpData = NULL;
        while (HeapWalk(heaps[i], &info)) {
            if ((info.wFlags & PROCESS_HEAP_ENTRY_BUSY) != 0) {
                ASSERT_NE(info.lpData, (PVOID)NULL);
            } else if ((info.wFlags & PROCESS_HEAP_REGION) != 0) {
                regions++;
                ASSERT_GT(info.Region.dwCommittedSize, 4095);
            }
        }
        ASSERT_GT(regions, 0);
        res = HeapUnlock(heaps[i]);
        ASSERT_EQ(res, TRUE);
    }
    delete [] heaps;
}

/* XXX i#1719: add an RtlEnumProcessHeaps test */
