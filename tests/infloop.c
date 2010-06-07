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

#include <stdio.h>
#include <stdlib.h>
#include <assert.h>

#ifdef LINUX
# include <unistd.h>
# include <signal.h>
# include <errno.h>
/* just use single-arg handlers */
typedef void (*handler_t)(int);
typedef void (*handler_3_t)(int, struct siginfo *, void *);
#endif

#ifdef LINUX
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
    act.sa_flags = SA_NOMASK | SA_SIGINFO | SA_ONSTACK;
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
    void *p1;

    /* error: both leaked, though one points to other neither is reachable
     * once p1 goes out of scope
     */
    p1 = malloc(42);
    *((void**)p1) = malloc(17);

    /* not a leak: still reachable through persistent pointer p2 */
    p2 = malloc(8);
    *((void**)p2) = malloc(19);
}

int
main()
{
#ifdef LINUX
    intercept_signal(SIGTERM, signal_handler);
#endif

    /* PR 428709: test leak detection via nudge */
    foo();

    /* indicate we're ready for the nudge: well, really we want to
     * get to the infloop, but close enough
     */
    fprintf(stderr, "starting\n");
    fflush(stderr);

#ifdef LINUX
    /* test register as root: the only pointer to p2's malloc will be in eax: */
    __asm("mov %0, %%eax" : : "g"(p2) : "%eax");
    __asm("movl $0, %0" : "=g"(p2));
    /* make sure no other registers point to p2 (I saw gcc impl 1st asm line
     * above as "mov p2, edx; mov edx, eax"!)
     */
    __asm("mov $0, %ebx; mov $0, %ecx; mov $0, %edx; mov $0, %esi; mov $0, %edi");
    __asm("infloop: jmp infloop");
#else
    __asm {
        mov eax, p2
        mov p2, 0
        mov ebx, 0
        mov ecx, 0
        mov edx, 0
        mov esi, 0
        mov edi, 0
      infloop:
        jmp infloop
    };
#endif

    return 0;
}
