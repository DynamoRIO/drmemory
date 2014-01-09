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

/* Tests Pattern Mode and Windows Guard Page Violation */

#include "gtest/gtest.h"

/* create bss segment */
static char bss_array[0x4000];

#ifdef WINDOWS
#include <windows.h>
#include <setjmp.h>

jmp_buf mark;
static int guard_cnt;
/* top-level exception handler */
static LONG
our_top_handler(struct _EXCEPTION_POINTERS * excpt)
{
    guard_cnt++;
    if (excpt->ExceptionRecord->ExceptionCode == EXCEPTION_GUARD_PAGE)
        longjmp(mark, 1);
    return EXCEPTION_EXECUTE_HANDLER; /* => global unwind and silent death */
}
#endif

#define PATTERN_VALUE 0xf1fdf1fd
#define PATTERN_BYTE0 ((char)0xfd)
#define PATTERN_BYTE1 ((char)0xf1)
#define COUNT 0x1000
static int
pattern_check(int *ptr)
{
    int i;
    *ptr = PATTERN_VALUE;
    for (i = 0; i < COUNT; i++) {
        if (*(char *)ptr       != PATTERN_BYTE0 ||
            *((char *)ptr + 1) != PATTERN_BYTE1)
            return i;
    }
    return i;
}

/* test if we can handle false postives in pattern mode */
TEST(PatternModeTests, FalsePositiveTest) {
    int i;
    int *ptr;

    ptr = (int *)calloc(20, sizeof(int));
    /* set pattern value in middle (ptr+10) to avoid slow table walk */
    i = pattern_check(ptr + 10);
    ASSERT_EQ(COUNT, i);
    /* now test the slow table walk, should not report any error */
    ((char *)ptr)[0] = bss_array[0x4000-4]; /* start */
    ((char *)ptr)[20*sizeof(int)-1] = 0; /* end */
    free(ptr);
}

#ifdef WINDOWS
TEST(PatternModeTests, GuardPageTest) {
    SYSTEM_INFO info;
    DWORD prot;
    BOOL res;
    char *ptr;
    int val;

    ptr = calloc(20, sizeof(int));
    val = pattern_check((int *)ptr + 10);
    ASSERT_EQ(COUNT, val);
    free(ptr);

    GetSystemInfo(&info);
    SetUnhandledExceptionFilter((LPTOP_LEVEL_EXCEPTION_FILTER) our_top_handler);
    ptr = VirtualAlloc(NULL, 3*info.dwPageSize,
                      MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    if (ptr == NULL) {
        printf("fail to alloc %d\n", 3*info.dwPageSize);
        return 0;
    }
    res = VirtualProtect(ptr, info.dwPageSize,
                         PAGE_READWRITE | PAGE_GUARD, &prot);
    if (!res || prot != PAGE_READWRITE) {
        printf("fail to set guard page at %p\n", ptr);
        return 0;
    }
    res = VirtualProtect(ptr + 2*info.dwPageSize, info.dwPageSize,
                         PAGE_READWRITE | PAGE_GUARD, &prot);
    if (!res || prot != PAGE_READWRITE) {
        printf("fail to set guard page at %p\n", ptr + 2*info.dwPageSize);
        return 0;
    }
    /* the instrumentation should trigger the Guard Page Violation,
     * but the app should not see it!
     */
    if (setjmp(mark) == 0)
        *(ptr + info.dwPageSize)     = 1;
    if (setjmp(mark) == 0)
        *(ptr + 2*info.dwPageSize-1) = 1;
    ASSERT_EQ(0, guard_cnt); /* no guard page violation should be triggerred */
    if (setjmp(mark) == 0)
        *(ptr + info.dwPageSize-1) = 1;
    if (setjmp(mark) == 0)
        *(ptr + 2*info.dwPageSize) = 1;
    ASSERT_EQ(2, guard_cnt); /* 2 guard page violations should be triggerred */
    res = VirtualFree(ptr, 3*info.dwPageSize,  MEM_RELEASE |  MEM_DECOMMIT);
}
#endif

