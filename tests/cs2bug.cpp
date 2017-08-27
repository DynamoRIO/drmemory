/* **********************************************************
 * Copyright (c) 2011-2017 Google, Inc.  All rights reserved.
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

#include <iostream>
#include "stdlib.h"

/* our delete mismatches can crash so we use fault handling for a more robust test */
#ifdef UNIX
# include <unistd.h>
# include <signal.h>
# ifdef MACOS
#  define _XOPEN_SOURCE 700 /* required to get POSIX, etc. defines out of ucontext.h */
#  define __need_struct_ucontext64 /* seems to be missing from Mac headers */
# endif
# include <ucontext.h>
# include <errno.h>
# include <assert.h>
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
    if (sig == SIGSEGV)
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
#endif

static void
test_basic()
{
    /* uninit error */
    int *p = new int;
    if (*p != 10)
        std::cout << "hi" << std::endl;

    /* unaddr error */
    int *a = new int[3];
    /* on xp64x2cpu vm, w/ VS2005 SP1, heap assert fires: detects
     * the overflow if do a[3], so doing a[4], which is not detected.
     */
    a[4] = a[4];
    if (setjmp(mark) == 0)
        delete a; /* also a mismatch */

    /* zero-sized (i#1145) and "prev malloc" reports */
    a = new int[0];
    *((char *)a + 0) = 4;
    delete [] a;

    a = new int[0];
    *((char *)a + 1) = 4;
    delete [] a;

    a = new int[8];
    *((char *)a + 8*sizeof(int)) = 4;
    delete [] a;
}

class hasdtr {
public:
    hasdtr() { x = new int[7]; }
    ~hasdtr() { delete[] x; }
    int *x;
    int y;
    char z;
};

class parA {
public:
    parA() { a = "parA"; };
    virtual ~parA() {}
    virtual const char *getval() const { return a; }
    const char *a;
};

class parB {
public:
    parB() { b = "parB"; }
    virtual ~parB() {}
    virtual const char *getval() const { return b; }
    virtual const char *myfunc() const { return b; }
    const char *b;
};

class childAB : public parA, public parB {
public:
    childAB() { ab = "childAB"; }
    virtual ~childAB() {}
    virtual const char *getval() const { return ab; }
    const char *ab;
};

static void
test_leaks()
{
    /* test mid-chunk std::string leak (PR 535344) */
    static std::string *str = new std::string("leak");
    std::cout << "size=" << str->size() <<
        " capacity=" << str->capacity() << std::endl;

    /* test mid-chunk pointer in leak due to new[] header (PR 484544)
     * (header is only present if class has destructor)
     */
    static hasdtr *leak = new hasdtr[4];
    leak[0].y = 0;

    /* test mid-chunk pointer in leak due to multiple inheritance by
     * casting to the 2nd of the two parent classes (PR 484544)
     */
    static parB *multi = (parB *) new childAB();
    std::cout << "getval: " << multi->getval() << std::endl;
    std::cout << "myfunc: " << multi->myfunc() << std::endl;

    /* test PR 576032 (dependent leaks): std::string shouldn't show up */
#ifndef WINDOWS
    /* FIXME PR 587093: disabling on Windows until figure out why callstack messed up */
    std::string onstack = "leakme";
    static std::string *outer = new std::string(onstack);
    outer = NULL;
#endif
}

static void
test_exception()
{
    try {
        std::cout << "throwing exception" << std::endl;
        throw std::exception();
    } catch (std::exception&) {
        std::cout << "caught exception" << std::endl;
    }
}

static void
test_mismatch_dtr()
{
#ifndef SKIP_MISMATCH_DTR
    /* /MTd, we skip the destructor mismatches, as they end up raising
     * heap assertions that we can't recover from
     */
    hasdtr *x = new hasdtr[7];
    if (setjmp(mark) == 0)
        delete x;
    x = new hasdtr[7];
    if (setjmp(mark) == 0)
        free(x);
    x = (hasdtr *) malloc(42); /* big enough for hasdtr but same size for x64 */
    if (setjmp(mark) == 0)
        delete x;
    x = (hasdtr *) malloc(42); /* big enough for hasdtr but same size for x64 */
    if (setjmp(mark) == 0)
        delete[] x; /* unaddr reading size + dtr calls might crash before mismatch */
    /* not a mismatch, but test debug operator del (i#500) */
    x = new hasdtr[7];
    delete[] x;
#endif
}

static void
test_mismatch_int()
{
    int *x = new int[7];
    if (setjmp(mark) == 0)
        delete x; /* technically no adverse effects since no destructor */
    x = new int[7];
    if (setjmp(mark) == 0)
        free(x);
    x = (int *) malloc(7);
    if (setjmp(mark) == 0)
        delete x;
    x = (int *) malloc(7);
    if (setjmp(mark) == 0)
        delete[] x;
    /* not a mismatch, but test debug operator del (i#500) */
    x = new int[7];
    delete[] x;
}

int main()
{
#ifdef UNIX
    intercept_signal(SIGSEGV, signal_handler);
#else
    SetUnhandledExceptionFilter((LPTOP_LEVEL_EXCEPTION_FILTER) our_top_handler);
#endif

    test_leaks();

    test_basic();

    test_exception();

    test_mismatch_dtr();
    test_mismatch_int();

    std::cout << "bye" << std::endl;

    /* mismatches above end up causing RtlpCoalesceFreeBlocks to crash resulting
     * in failing app exit code: simpler to just exit
     */
    exit(0);

    return 0;
}
