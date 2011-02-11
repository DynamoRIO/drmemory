/* **********************************************************
 * Copyright (c) 2009 VMware, Inc.  All rights reserved.
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

/* This is a test to see if different types of error are suppressed by
 * -suppress option.
 */
#include <stdio.h>
#include <stdlib.h>

#ifdef WINDOWS
  /* On Windows, msvcrt!malloc() ends up calling HeapAlloc(), so there is a 
   * malloc+0x## frame in the error in results.txt which is the same for all
   * leak tests, so just one leak suppression info of type mod+offs for malloc
   * suppress all leak errors preventing the ability to test all types of
   * suppression.  So we call HeapAlloc directly.  Also, we want to be
   * independent of system libraries (msvcrt.dll can be different in toolchain
   * vs. local Visual Studio.
   */
# include <windows.h>
# define ALLOC(sz) HeapAlloc(GetProcessHeap(), 0, sz)
# define FREE(p) HeapFree(GetProcessHeap(), 0, p)
#else
# define ALLOC(sz) malloc(sz)
# define FREE(p) free(p)
#endif

static int *int_p;
static int forcond;

static void do_uninit_read(int *val_p)
{
    int x = 1;
    printf("testing uninitialized access\n");
    if (*val_p & x)
        forcond = 1;
}

static void uninit_test1(int *val_p)
{
    do_uninit_read(val_p);
}

static void uninit_test2(int *val_p)
{
    do_uninit_read(val_p);
}

static void uninit_test3(int *val_p)
{
    do_uninit_read(val_p);
}

static void uninit_test4(int *val_p)
{
    do_uninit_read(val_p);
}

static void uninit_test5(int *val_p)
{
    do_uninit_read(val_p);
}

static void do_uninit_read_with_intermediate_frames(int depth, int *val_p)
{
    if (depth > 1)
        do_uninit_read_with_intermediate_frames(depth - 1, val_p);
    else
        do_uninit_read(val_p);
}

static void uninit_test6(int *val_p)
{
    do_uninit_read_with_intermediate_frames(5, val_p);
}

static void uninit_test7(int *val_p)
{
    do_uninit_read_with_intermediate_frames(5, val_p);
}

static int unaddr_test1(int *val_p)
{
    int x = 1;
    printf("testing access after free\n");
    return (*val_p & x) ? 1 : 0;
}

static int unaddr_test2(int *val_p)
{
    int x = 1;
    printf("testing access after free\n");
    return (*val_p & x) ? 1 : 0;
}

static int unaddr_test3(int *val_p)
{
    int x = 1;
    printf("testing access after free\n");
    return (*val_p & x) ? 1 : 0;
}

static int unaddr_test4(int *val_p)
{
    int x = 1;
    printf("testing access after free\n");
    return (*val_p & x) ? 1 : 0;
}

static void leak_test1(void)
{
    printf("testing leak\n");
    int_p = ALLOC(sizeof(int));    /* leak */
}

static void leak_test2(void)
{
    printf("testing leak\n");
    int_p = ALLOC(sizeof(int));    /* leak */
}

static void leak_test3(void)
{
    printf("testing leak\n");
    int_p = ALLOC(sizeof(int));    /* leak */
}

static void leak_test4(void)
{
    printf("testing leak\n");
    int_p = ALLOC(sizeof(int));    /* leak */
}

static void warning_test1(void)
{
    size_t *p;
    printf("testing warning\n");
    /* DrMem warns if malloc fails */
    p = ALLOC(~0);
}

/* set this to 0 to work natively */
#define REDZONE_SIZE 8
#define RZ_DIV (REDZONE_SIZE/sizeof(size_t))

static void invalid_free_test1(void)
{
    size_t *p = ALLOC(32);
    printf("testing invalid free\n");
    /* fool glibc's invalid free detection by duplicating the header
     * inside the allocation and reducing the size.
     * we rely on DrMem not adjusting base b/c the free ptr is not in
     * its table and it will raise invalid free but will pass through
     * to glibc free(): so we don't bother to make a copy of the redzone
     * inside the copied header.  we do avoid clobbering the redzone,
     * just to be safe.
     */
    *(p) = *(p-RZ_DIV-2);
    /* preserve bottom 2 bits of size */
    *(p+1) = ((*(p-RZ_DIV-1) & ~3) - (REDZONE_SIZE+8)) | (*(p-RZ_DIV-1) & 3);
#ifdef WINDOWS
    /* crashes Vista test (i#82) so we clear while preserving # unaddrs */
    *(p+1) -= *(p+1);
#endif
    /* this can corrupt the free list, so probably best to run this test last */
    FREE(p+2);
}

/* This function exists only to provide more than 2 frames in the error
 * callstack.
 * FIXME: PR 464804: suppression of invalid frees and errors at syscalls need
 * to be tested, but they haven't been implemented yet (PR 406739).
 */
static void test(void)
{
    /* Must have different function names otherwise one mod!func suppression 
     * will suppress all tests without room for testing other types.
     */
    uninit_test1(int_p+0);      /* 3 top frames based mod+offs suppression */
    uninit_test2(int_p+1);      /* 3 top frames based mod!func suppression */
    uninit_test3(int_p+2);      /* 4 top frames based mixed suppression + '?' */
    uninit_test4(int_p+3);      /* mixed suppression with ... (...=0 frames) */
    uninit_test5(int_p+4);      /* ... + mod!func suppression (...=1 frame) */
    uninit_test6(int_p+5);      /* ... + mod!func suppression (...=5 frames) */
    uninit_test7(int_p+6);      /* ... + ? + mod+offs suppression*/

    FREE(int_p);

    unaddr_test1(int_p+0);      /* full callstack based mod+func suppression */
    unaddr_test2(int_p+1);      /* top frame based mod+func suppression */
    unaddr_test3(int_p+2);      /* full callstack based mod!func suppression */
    unaddr_test4(int_p+3);      /* top frame based mod!func suppression */

    leak_test1();               /* full callstack based mod+func suppression */
    leak_test2();               /* top frame based mod+func suppression */
    leak_test3();               /* full callstack based mod!func suppression */
    leak_test4();               /* top frame based mod!func suppression */

    warning_test1();

    /* running this test last b/c it can corrupt the free list */
    invalid_free_test1();

    printf("done\n");
}

int main()
{
    int_p = (int *) ALLOC(7*sizeof(int));
    test();
    int_p = NULL;   /* to make the last leak to be truly unreachable */
    return 0;
}
