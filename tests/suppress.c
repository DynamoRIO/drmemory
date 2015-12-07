/* **********************************************************
 * Copyright (c) 2012-2015 Google, Inc.  All rights reserved.
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

/* This is a test to see if different types of error are suppressed by
 * -suppress option.
 */
#include <stdio.h>
#include <stdlib.h>
#ifdef UNIX
# include <sys/types.h>
# include <sys/stat.h>
# include <fcntl.h>
# include <unistd.h>
#endif

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

void call_buf_asm(int uninit, void *buf);

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

static char * pointer_in_the_middle1 = 0;

static void possible_leak_test1(void)
{
    printf("testing possible leak\n");
    pointer_in_the_middle1 = (char*)(ALLOC(16)) + 8;    /* possible leak */
}

static char * pointer_in_the_middle2 = 0;

static void possible_leak_test2(void)
{
    printf("testing possible leak\n");
    pointer_in_the_middle2 = (char*)(ALLOC(16)) + 8;    /* possible leak */
}

static void warning_test1(void)
{
    size_t *p;
    printf("testing warning\n");
    /* DrMem warns if malloc fails */
    p = ALLOC(~0);
}

/* set this to 0 to work natively */
#define REDZONE_SIZE 16
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

void
syscall_test(void)
{
#ifdef UNIX
    int fd = open("/dev/null", O_WRONLY);
    int *uninit = (int *) malloc(sizeof(*uninit));
    write(fd, uninit, sizeof(*uninit));
    free(uninit);
#else
    MEMORY_BASIC_INFORMATION mbi;
    void **uninit = (void **) malloc(sizeof(*uninit));
    VirtualQuery(*uninit, &mbi, sizeof(mbi));
    free(uninit);
#endif
}

static void
non_module_test(void)
{
    /* We put this code in our buffer:
     *
     *  83 f8 00             cmp    %eax $0x00000000
     *  c3                   ret
     *
     * XXX: this won't execute natively if NX/DEP is enabled!
     * We should mark it +x.
     * It works under DR b/c of a hole in DR where its code cache is +x (i#329).
     */
#ifdef X86
    char buf[] = { 0x83, 0xf8, 0x00, 0xc3 };
#elif defined(ARM)
    /* cmp r0, #0; bx lr */
    int buf[] = { 0xe3500000, 0xe12fff1e };
#endif
    int uninit[2];
    int x = 0; /* avoid compiler warning about uninit var use */
    call_buf_asm(uninit[x], (void *)buf);
}

/* Function pointers to exports. */
typedef void (*cb_n_frames_t)(void (*func)(void), unsigned n);
static cb_n_frames_t foo_cb_with_n_frames;
static cb_n_frames_t bar_cb_with_n_frames;

static void
do_uninit_cb(void)
{
    void *int_p = ALLOC(sizeof(int));
    do_uninit_read(int_p);
    FREE(int_p);
}

/* This uninit reached through suppress-mod-bar.dll will be suppressed. */
static void
call_into_bar(void)
{
    bar_cb_with_n_frames(do_uninit_cb, 4);
}

/* This uninit reached through suppress-mod-foo.dll will not be suppressed. */
static void
call_into_foo(void)
{
    foo_cb_with_n_frames(do_uninit_cb, 4);
}

/* Down here to avoid disturbing line numbers. */
#ifdef UNIX
# include <dlfcn.h>
# include <string.h>
#endif

static void
mod_ellipsis_test(const char *argv0)
{
#ifdef WINDOWS
    HANDLE foo = LoadLibrary("suppress-mod-foo.dll");
    HANDLE bar = LoadLibrary("suppress-mod-bar.dll");
    foo_cb_with_n_frames = (cb_n_frames_t)GetProcAddress(foo, "callback_with_n_frames");
    bar_cb_with_n_frames = (cb_n_frames_t)GetProcAddress(bar, "callback_with_n_frames");
#else /* UNIX */
    char exe_dir[/*MAX_PATH*/260];
    char libname[/*MAX_PATH*/260];
    char *last_sep;
    void *foo;
    void *bar;
    strncpy(exe_dir, argv0, sizeof(exe_dir));
    exe_dir[sizeof(exe_dir)-1] = '\0';
    last_sep = strrchr(exe_dir, '/');
    if (last_sep == NULL) {
        printf("can't find dir of argv[0]!\n");
        return;
    }
    *last_sep = '\0';
    snprintf(libname, sizeof(libname), "%s/%s", exe_dir, "libsuppress-mod-foo.so");
    libname[sizeof(libname)-1] = '\0';
    foo = dlopen(libname, RTLD_LAZY);
    snprintf(libname, sizeof(libname), "%s/%s", exe_dir, "libsuppress-mod-bar.so");
    libname[sizeof(libname)-1] = '\0';
    bar = dlopen(libname, RTLD_LAZY);
    foo_cb_with_n_frames = (cb_n_frames_t)dlsym(foo, "callback_with_n_frames");
    bar_cb_with_n_frames = (cb_n_frames_t)dlsym(bar, "callback_with_n_frames");
#endif

    if (foo == NULL ||
        bar == NULL ||
        foo_cb_with_n_frames == NULL ||
        bar_cb_with_n_frames == NULL) {
        printf("error loading suppress-mod-foo or bar library!\n");
        return;
    }

    foo_cb_with_n_frames(call_into_bar, 4);
    /* This will produce an uninit error that should *not* be suppressed,
     * because it goes through foo.dll and not bar.dll.
     */
    foo_cb_with_n_frames(call_into_foo, 4);

#ifdef WINDOWS
    FreeLibrary(foo);
    FreeLibrary(bar);
#else /* UNIX */
    dlclose(foo);
    dlclose(bar);
#endif
}

/* This function exists only to provide more than 2 frames in the error
 * callstack.
 * FIXME: PR 464804: suppression of invalid frees and errors at syscalls need
 * to be tested, but they haven't been implemented yet (PR 406739).
 */
static void test(int argc, char **argv)
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

    possible_leak_test1();      /* suppressed by 'POSSIBLE LEAK' suppression */
    possible_leak_test2();      /* suppressed by 'LEAK' suppression */

    warning_test1();

    syscall_test();

    non_module_test();

    mod_ellipsis_test(argv[0]);

    /* running this test last b/c it can corrupt the free list */
    invalid_free_test1();

    printf("done\n");
}

static void
run_some_again(void)
{
    /* hard to write such tests so we call twice w/ different callstacks */
    syscall_test();
    non_module_test();
}

int main(int argc, char **argv)
{
    int_p = (int *) ALLOC(7*sizeof(int));
    test(argc, argv);
    run_some_again();
    int_p = NULL;   /* to make the last leak to be truly unreachable */
    return 0;
}


#else /* asm code *************************************************************/
#include "cpp2asm_defines.h"
START_FILE

#define FUNCNAME call_buf_asm
/* void call_buf_asm(int uninit, void *buf); */
        DECLARE_FUNC_SEH(FUNCNAME)
GLOBAL_LABEL(FUNCNAME:)
# ifdef X86
        mov      REG_XAX, ARG1
        mov      REG_XDX, ARG2
        push     REG_XBP
        mov      REG_XBP, REG_XSP
        END_PROLOG

        /* we want to call ARG2 with ARG1 in xax */
        call     REG_XDX

        add      REG_XSP, 0 /* make a legal SEH64 epilog */
        mov      REG_XSP, REG_XBP
        pop      REG_XBP
        ret
# elif defined(ARM)
        /* call ARG2 passing ARG1 in r0 */
        blx      ARG2
        bx       lr
# endif
        END_FUNC(FUNCNAME)
#undef FUNCNAME


END_FILE
#endif
