/* **********************************************************
 * Copyright (c) 2011-2014 Google, Inc.  All rights reserved.
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

#ifndef ASM_CODE_ONLY /* C code ***********************************************/

#include <stdio.h>
#include <stdlib.h>
#include <assert.h>

#ifdef UNIX
# include <unistd.h>
# include <signal.h>
# include <errno.h>
/* just use single-arg handlers */
typedef void (*handler_t)(int);
typedef void (*handler_3_t)(int, siginfo_t *, void *);
#endif

void infloop_asm(void **p2);

#ifdef UNIX
static void
signal_handler(int sig)
{
    if (sig == SIGTERM)
        fprintf(stderr, "done\n");
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
    fprintf(stderr, "done\n");
    return EXCEPTION_EXECUTE_HANDLER; /* => global unwind and silent death */
}
#endif

static void *p2;

void
foo(void)
{
    int i;
    void *p1;

    /* error: both leaked, though one points to other neither is reachable
     * once p1 goes out of scope
     */
    p1 = malloc(42);
    *((void**)p1) = malloc(17);

    /* not a leak: still reachable through persistent pointer p2 */
    p2 = malloc(8);
    *((void**)p2) = malloc(19);

    /* Ensure duplicate leaks are counted properly (xref PR 578897) even
     * across multiple nudges
     */
    for (i = 0; i < 20; i++) {
        p1 = malloc(160);
    }
}

int
main()
{
#ifdef UNIX
    intercept_signal(SIGTERM, signal_handler);
#else
    /* for nudge handle leak test */
    HANDLE hEvent = CreateEvent(NULL, FALSE, FALSE, NULL);
    SetUnhandledExceptionFilter((LPTOP_LEVEL_EXCEPTION_FILTER) our_top_handler);
#endif

    /* PR 428709: test leak detection via nudge */
    foo();

    /* indicate we're ready for the nudge: well, really we want to
     * get to the infloop, but close enough
     */
    fprintf(stderr, "starting\n");
    fflush(stderr);

    infloop_asm(&p2);

    return 0;
}

#else /* asm code *************************************************************/
#include "cpp2asm_defines.h"
START_FILE

/* number of times to overflow 32-bit counter before exiting, since we don't
 * really want to spin forever if somehow the test wrapper fails to kill us.
 * overflowing a 32-bit counter takes betwee 2 and 3 seconds.
 * this value of 20 ends up taking 56 seconds on my laptop.
 * we want well over any time the test may take to complete.
 */
#define MAX_ITERS_DIV_4G HEX(14)

#define FUNCNAME infloop_asm
/* void infloop(void **p2); */
        DECLARE_FUNC_SEH(FUNCNAME)
GLOBAL_LABEL(FUNCNAME:)
        mov      REG_XDX, ARG1
        push     REG_XBP
        mov      REG_XBP, REG_XSP
        END_PROLOG

        /* test register as root: the only pointer to p2's malloc will be in eax: */
        mov      REG_XAX, PTRSZ [REG_XDX]
        mov      PTRSZ [REG_XDX], 0
        /* make sure no other registers point to p2 */
        mov      REG_XBX, 0
        mov      REG_XCX, 0
        mov      REG_XDX, 0
        mov      REG_XSI, 0
        mov      REG_XDI, 0

   infloop_repeat:
        inc      ecx
        cmp      ecx, 0 /* wraparound */
        jne      infloop_repeat
        inc      edx
        cmp      edx, MAX_ITERS_DIV_4G
        jne      infloop_repeat

        add      REG_XSP, 0 /* make a legal SEH64 epilog */
        mov      REG_XSP, REG_XBP
        pop      REG_XBP
        ret
        END_FUNC(FUNCNAME)
#undef FUNCNAME


END_FILE
#endif
