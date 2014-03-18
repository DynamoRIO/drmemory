/* **********************************************************
 * Copyright (c) 2014 Google, Inc.  All rights reserved.
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
# include <ucontext.h>
typedef void (*handler_3_t)(int, siginfo_t *, void *);
#endif

int xax_val = 0xffffffff;

#ifdef UNIX
# define SIGCXT_FROM_UCXT(ucxt) (&((ucxt)->uc_mcontext))
# ifdef X64
#  define XAX rax
# else
#  define XAX eax
# endif

typedef struct sigcontext sigcontext_t;

static void
signal_handler(int sig, siginfo_t *siginfo, void *context)
{
    if (sig == SIGSEGV) {
        ucontext_t *ucxt = (ucontext_t *)context;
        sigcontext_t *sc = (sigcontext_t *)SIGCXT_FROM_UCXT(ucxt);
        if (sc->XAX != xax_val)
            fprintf(stderr, "eax is wrong\n");
        else
            fprintf(stderr, "eax is correct\n");
        fprintf(stderr, "done\n");
    }
    exit(1);
}
static void
intercept_signal(int sig, handler_3_t handler)
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
# ifdef X64
#  define XAX    Rax
# else
#  define XAX    Eax
# endif
/* top-level exception handler */
static LONG
our_top_handler(struct _EXCEPTION_POINTERS * pExceptionInfo)
{
    fprintf(stderr, "done\n");
    if (pExceptionInfo->ExceptionRecord->ExceptionCode == EXCEPTION_ACCESS_VIOLATION) {
        CONTEXT *context = pExceptionInfo->ContextRecord;
        if (context->XAX != xax_val)
            fprintf(stderr, "eax is wrong\n");
        else
            fprintf(stderr, "eax is correct\n");
    }
    fprintf(stderr, "done\n");
    fflush(stderr);
    return EXCEPTION_EXECUTE_HANDLER; /* => global unwind and silent death */
}
#endif

int
main()
{
#ifdef UNIX
    intercept_signal(SIGSEGV, signal_handler);
#else
    SetUnhandledExceptionFilter((LPTOP_LEVEL_EXCEPTION_FILTER) our_top_handler);
#endif

    fprintf(stderr, "starting\n");
    fprintf(stderr, "generating SIGSEGV\n");
    fflush(stderr);
    /* i#1466: the asm code below tests Dr.Memory state restore event on fault */
#ifdef UNIX
    __asm("label:");
    /* set %eax to be xax_val for the check in handler */
    __asm("  movl %0, %%eax" : : "g"(xax_val) : "%eax");
    __asm("  movl $0, %ecx");
    /* no aflags stealing for instrumenting this movb because of the cmp after */
    __asm("  movb $0, (%ecx)"); /* access violation */
    __asm("  cmp  $0, %ecx");
    /* aflags stealing for instrumenting this movb because of the jcc after */
    __asm("  movb $0, (%ecx)");
    /* jcc to end the bb, so %eax is live */
    __asm("  jnz label");
#else
    __asm {
      label:
        /* set %eax to be xax_val for the check in handler */
        mov eax, xax_val
        mov ecx, 0
        /* no aflags stealing for instrumenting this movb because of the cmp after */
        mov [ecx], 0 /* access violation */
        cmp ecx, 0
        /* aflags stealing for instrumenting this movb because of the jcc after */
        mov [ecx], 0
        /* jcc to end the bb, so %eax is live */
        jnz label
    };
#endif

    return 0;
}
