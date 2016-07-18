/* **********************************************************
 * Copyright (c) 2010-2016 Google, Inc.  All rights reserved.
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

#include <stdio.h>
#include <stdlib.h>
#include <assert.h>

#ifdef UNIX
# include <unistd.h>
# include <signal.h>
# ifdef MACOS
#  define _XOPEN_SOURCE 700 /* required to get POSIX, etc. defines out of ucontext.h */
#  define __need_struct_ucontext64 /* seems to be missing from Mac headers */
# endif
# include <ucontext.h>
# include <errno.h>
/* just use single-arg handlers */
typedef void (*handler_t)(int);
typedef void (*handler_3_t)(int, siginfo_t *, void *);
#endif

#include <setjmp.h>
jmp_buf mark;

#ifdef UNIX
static void
signal_handler(int sig)
{
    if (sig == SIGSEGV || sig == SIGBUS)
        longjmp(mark, 1);
    else
        exit(1);
}
static void
intercept_signal(int sig, handler_t handler)
{
    int rc;
    struct sigaction act;
    act.sa_sigaction = (handler_3_t) handler;
    rc = sigemptyset(&act.sa_mask); /* block no signals within handler */
    assert(rc == 0);
    act.sa_flags = SA_NODEFER | SA_SIGINFO | SA_ONSTACK;
    rc = sigaction(sig, &act, NULL);
    assert(rc == 0);
}
#else
/* sort of a hack to avoid the MessageBox of the unhandled exception spoiling
 * our batch runs
 */
# include <windows.h>
/* top-level exception handler */
static LONG
our_top_handler(struct _EXCEPTION_POINTERS * pExceptionInfo)
{
    if (pExceptionInfo->ExceptionRecord->ExceptionCode == EXCEPTION_ACCESS_VIOLATION) {
        longjmp(mark, 1);
    }
    return EXCEPTION_EXECUTE_HANDLER; /* => global unwind and silent death */
}

BOOL
is_pre_win8(void)
{
    OSVERSIONINFO info;
    info.dwOSVersionInfoSize = sizeof(info);
    if (GetVersionEx(&info)) {
        return (info.dwMajorVersion < 6 ||
                (info.dwMajorVersion == 6 && info.dwMinorVersion < 2));
    }
    return FALSE;
}
#endif

static void *p2;
static void *p3;

int
main()
{
    void *p1;
    int x, *arr;
    char c;

    p1 = malloc(64);
    free(p1);
    printf("malloc\n");

    for (x = 0; x < 20; x++) {
        /* ensure we flag an error if reading the padding even though it
         * is safe to access
         */
        p1 = malloc(3);
        c = *(((char *)p1)+3); /* error: unaddressable */
        free(p1);
    }
    printf("malloc small\n");

    p1 = malloc(0);
    free(p1);
    printf("malloc 0\n");

    p1 = malloc(512*1024);
    if (*(((char *)p1)+3) == 0) /* error: uninitialized */
        c = 2;
    /* PR 488643: test realloc via mremap */
    p1 = realloc(p1, 1024*1024);
    free(p1);
    printf("malloc big\n");

    p1 = calloc(3, sizeof(int));
    x = *((int *)p1); /* ok: initialized to 0 */
    free(p1);
    printf("calloc\n");

    p1 = malloc(64);
    if (*(((char *)p1)+3) == 0) /* error: uninitialized */
        c = 2;
    p1 = realloc(p1, 128);
    p1 = realloc(p1, sizeof(int)*2);
    arr = (int *) p1;
    arr[0] = 1;
    arr[1] = 2;
    p1 =  realloc(p1, sizeof(int)*3);
    arr = (int *) p1;
    arr[2] = 3;     /* shouldn't produce unaddr */
    if ((arr[0] + arr[1] + arr[2]) != 6)    /* shouldn't produce uninit */
        printf("realloc\n");
    free(p1);
    arr = NULL;

    /* PR 416535: test realloc(NULL, ), and on some linuxes, nested
     * tailcall (PR 418138)
     */
    p1 = realloc(NULL, 32);
    free(p1);

    /* PR 493870: test realloc(non-NULL, 0) */
    p1 = malloc(37);
    p1 = realloc(p1, 0);
    /* get a 2nd malloc at same spot to test PR 493880 */
    p1 = malloc(37);
    free(p1);
#ifdef WINDOWS
    /* HeapReAlloc has different behavior: (,0) does allocate a 0-sized chunk */
    p1 = HeapAlloc(GetProcessHeap(), 0, 0xab);
    p1 = HeapReAlloc(GetProcessHeap(), 0, p1, 0);
    HeapFree(GetProcessHeap(), 0, p1);
#endif
    printf("realloc\n");

    /* invalid free: crashes so we have a try/except.
     * glibc catches invalid free only at certain points near real mallocs.
     */
#ifdef UNIX
    intercept_signal(SIGSEGV, signal_handler);
    intercept_signal(SIGBUS, signal_handler); /* We see SIGBUS on Mac */
#else
    SetUnhandledExceptionFilter((LPTOP_LEVEL_EXCEPTION_FILTER) our_top_handler);
#endif
    if (setjmp(mark) == 0)
        free((void *)0x1230); /* i#916: addr must be 0x10 aligned */
    printf("invalid free\n");

#if 0 /* avoiding double free b/c glibc reports it and aborts */
    free(p1);
    printf("double free\n");
#endif

#ifdef WINDOWS
    p1 = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(int));
    x = *((int *)p1); /* ok: initialized to 0 */
    HeapFree(GetProcessHeap(), 0, p1);
    p1 = HeapReAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, NULL, sizeof(int));
    HeapFree(GetProcessHeap(), 0, p1);

    { /* test failure of HeapFree due to invalid params */
        HANDLE newheap = HeapCreate(0, 0, 0);
        BOOL ok = TRUE;
        char save[8]; /* to recover on win7 */
        p1 = HeapAlloc(newheap, HEAP_ZERO_MEMORY, sizeof(int));
        memcpy(save, (char *)p1 - sizeof(save), sizeof(save));
        if (setjmp(mark) == 0) { /* crashes on win7 (i#515) */
            /* i#1161: we cannot recover from a heap exception on win8 */
            if (is_pre_win8())
                ok = HeapFree(GetProcessHeap(), 0, p1);
            else
                ok = HeapFree(newheap, 0, (void*)0x300);
            if (!ok) /* invalid Heap fails w/ 87 "The parameter is incorrect." */
                printf("HeapFree failed %d\n", GetLastError());
        } else
            printf("HeapFree failed 87\n"); /* match non-crash error */
        /* restore so we can try to free (else crashes again on win7) */
        memcpy((char *)p1 - sizeof(save), save, sizeof(save));
        ok = HeapFree(newheap, 0xffffffff, p1);
        if (!ok) /* invalid flags do not cause failure */
            printf("HeapFree failed %d\n", GetLastError());
        HeapDestroy(newheap);
    }
#endif

    /* Test leaks.  Avoid non-determinism due to the order of drmem's hashtable walk:
     * for this test drmem's malloc table has 12 bits, so be sure to get the
     * following allocs all in order in the table by not wrapping around in the
     * bottom 12 bits.  We assume all the allocs below take < 512 bytes.  Note: this
     * isn't always sufficient, but .res matches out-of-order now
     */

    {
        static char *p;
        p = malloc(8); /* static so no leak */
        free(p);
        if (0xfff - ((int)(size_t)p & 0xfff) < 512) /* truncation ok in cast */
            p = calloc(1, 0xfff - ((int)(size_t)p & 0xfff)); /* calloc for i#927 */
        else
            p = NULL; /* prevent from pointing where p1 will be (i#340) */
    }

    /* error: both leaked, though one points to other neither is reachable
     * once p1 goes out of scope, so one direct and one indirect leak
     */
    p1 = calloc(1, 42); /* calloc for i#927 */
    *((void**)p1) = malloc(17);

    /* not a leak: still reachable through persistent pointer p2 */
    p2 = calloc(1, 8); /* calloc for i#927 */
    *((void**)p2) = malloc(19);

    /* PR 513954: app-added size field not a leak */
    p3 = calloc(1, 24); /* calloc for i#927 */
    *((size_t*)p3) = 24;
    p3 = (void *) (((char*)p3) + 8); /* align to 8 so matches malloc alignment */

    if (setjmp(mark) == 0) {
        c = *(char *)0x100; /* i#1015: unaddr on wild access */
    }
    printf("all done\n");
    return 0;
}
