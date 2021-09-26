/* **********************************************************
 * Copyright (c) 2021 Google, Inc.  All rights reserved.
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
# include <signal.h>
typedef void (*handler_3_t)(int, siginfo_t *, void *);
#endif

#include <setjmp.h>
jmp_buf mark;

#ifdef X64
/* Use an address outside of any app region to test umbra's handling. */
#define BAD_ADDRESS 0x20000000000
#else
#define BAD_ADDRESS 0x100
#endif

static volatile int passed = 1;

#ifdef UNIX
static void
signal_handler(int sig, siginfo_t *info, void *ucxt)
{
    if (sig == SIGSEGV || sig == SIGBUS) {
        if (info->si_addr != (void*)BAD_ADDRESS) {
            fprintf(stderr, "Crash is at wrong address %p\n", info->si_addr);
            passed = 0;
        }
        longjmp(mark, 1);
    } else
        exit(1);
}
static void
intercept_signal(int sig, handler_3_t handler)
{
    int rc;
    struct sigaction act;
    act.sa_sigaction = handler;
    rc = sigemptyset(&act.sa_mask); /* block no signals within handler */
    assert(rc == 0);
    act.sa_flags = SA_NODEFER | SA_SIGINFO;
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
        if (pExceptionInfo->ExceptionRecord->ExceptionInformation[1] != BAD_ADDRESS) {
            fprintf(stderr, "Crash is at wrong address %p\n",
                    pExceptionInfo->ExceptionRecord->ExceptionInformation[1]);
            passed = 0;
        }
        longjmp(mark, 1);
    }
    return EXCEPTION_EXECUTE_HANDLER; /* => global unwind and silent death */
}
#endif

int
main()
{
#ifdef UNIX
    intercept_signal(SIGSEGV, signal_handler);
    intercept_signal(SIGBUS, signal_handler);
#else
    SetUnhandledExceptionFilter((LPTOP_LEVEL_EXCEPTION_FILTER) our_top_handler);
#endif

    if (setjmp(mark) == 0) {
        char c = *(char *)BAD_ADDRESS; /* i#1015: unaddr on wild access */
        if (c == 'a')
            fprintf(stderr, "got an a\n");
    }
    fprintf(stderr, "TEST %s\n", passed ? "PASSED" : "FAILED");
    return 0;
}
