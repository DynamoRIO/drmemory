/* **********************************************************
 * Copyright (c) 2014-2019 Google, Inc.  All rights reserved.
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
# ifdef MACOS
#  define _XOPEN_SOURCE 700 /* required to get POSIX, etc. defines out of ucontext.h */
#  define __need_struct_ucontext64 /* seems to be missing from Mac headers */
# endif
# include <unistd.h>
# include <signal.h>
# include <ucontext.h>
typedef void (*handler_3_t)(int, siginfo_t *, void *);
#else
# include <windows.h>
#endif

int xax_val = 0x0dead420;

void test_fault_asm(int xax_val);

/* XXX: share with core/ */
#ifdef LINUX
typedef struct sigcontext sigcontext_t;
# define SIGCXT_FROM_UCXT(ucxt) (&((ucxt)->uc_mcontext))
# ifdef ARM
#  define XAX arm_r0
# elif defined(X64)
#  define XAX rax
# else
#  define XAX eax
# endif
#elif defined(MACOS)
# ifdef X64
/* XCode 10.1 (probably others too) toolchain wants _STRUCT_MCONTEXT
 * w/o _AVX64 and has a field named uc_mcontext with no 64.
 */
typedef _STRUCT_MCONTEXT64 sigcontext_t;
#  define SIGCXT_FROM_UCXT(ucxt) ((sigcontext_t*)((ucxt)->uc_mcontext))
#  define XAX __ss.__rax
# else
typedef _STRUCT_MCONTEXT_AVX32 sigcontext_t;
#  define SIGCXT_FROM_UCXT(ucxt) ((sigcontext_t*)((ucxt)->uc_mcontext))
#  define XAX __ss.__eax
# endif
#endif

#ifdef UNIX
static void
signal_handler(int sig, siginfo_t *siginfo, void *context)
{
    if (sig == SIGSEGV || sig == SIGBUS) {
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
    intercept_signal(SIGBUS, signal_handler);
#else
    SetUnhandledExceptionFilter((LPTOP_LEVEL_EXCEPTION_FILTER) our_top_handler);
#endif

    fprintf(stderr, "starting\n");
    fprintf(stderr, "generating SIGSEGV\n");
    fflush(stderr);

    test_fault_asm(xax_val);

    return 0;
}

#else /* asm code *************************************************************/
#include "cpp2asm_defines.h"
START_FILE

#define FUNCNAME test_fault_asm
/* void test_fault_asm(int xax_val); */
        DECLARE_FUNC_SEH(FUNCNAME)
GLOBAL_LABEL(FUNCNAME:)
#ifdef X86
        /* set %eax to be xax_val for the check in handler */
        mov      REG_XAX, ARG1
        push     REG_XBP
        mov      REG_XBP, REG_XSP
        END_PROLOG

        /* i#1466: the asm code below tests Dr.Memory state restore event on fault */
        jmp      new_bb
   new_bb:
        mov      REG_XCX, 0
        /* no aflags stealing for instrumenting this mov because of the cmp after */
        mov      BYTE [REG_XCX], 0 /* access violation */
        cmp      ecx, 0
        /* aflags stealing for instrumenting this mov because of the jcc after */
        mov      BYTE [REG_XCX], 0 /* access violation */
        /* jcc to end the bb, so %eax is live */
        jne      new_bb

        add      REG_XSP, 0 /* make a legal SEH64 epilog */
        mov      REG_XSP, REG_XBP
        pop      REG_XBP
        ret
#elif defined(ARM)
        /* set for the check in handler */
        mov      REG_R0, ARG1

        /* i#1466: the asm code below tests Dr.Memory state restore event on fault */
        b        1f
    1:
        mov      REG_R1, #0
        /* no aflags stealing for instrumenting this str because of the cmp after */
        str      REG_R1, BYTE [REG_R1] /* access violation */
        cmp      REG_R1, #0
        /* aflags stealing for instrumenting this str because of the jcc after */
        str      REG_R1, BYTE [REG_R1] /* access violation */
        /* jcc to end the bb, so %r0 is live */
        bne      1b

        bx       lr
#endif
        END_FUNC(FUNCNAME)
#undef FUNCNAME


END_FILE
#endif
