/* **********************************************************
 * Copyright (c) 2011-2017 Google, Inc.  All rights reserved.
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

#ifndef ASM_CODE_ONLY /* C code ***********************************************/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void *orig_esi;
void *stack0;
void *stack1;
void *stack2;
static int *data;

#ifdef WINDOWS
# define IF_WINDOWS_ELSE(x,y) x
#else
# define IF_WINDOWS_ELSE(x,y) y
#endif

void test_cmovcc_asm(void);
void swap_stack_and_back_asm(void);

void
foo(void)
{
    char buf[1024];
    printf("in foo\n");
    memset(buf, 0, sizeof(buf));
}

void
test_swap(size_t sz1, size_t sz2)
{
    /* test swapping malloc-ed stacks w/ data in between (PR 525807) */

    stack1 = (char *) malloc(sz1) + sz1;
    /* put data in between */
    data = malloc(1024);
    memset(data, 0, 1024);
    stack2 = (char *) malloc(sz2) + sz2;

    swap_stack_and_back_asm();

    printf("data[10] = %d\n", data[10]);
    free(data);
    free((char *)stack1 - sz1);
    free((char *)stack2 - sz2);
}

void
test_alloca(void)
{
    /* test special shadow write from gencode */
    int *x = (int *) IF_WINDOWS_ELSE(_alloca,alloca)(128*1024);
    x[0] = 4;

    /* test special shadow write from code cache code */
    x = malloc(128*1024);
    x[64*1024/sizeof(int)] = 1;
    free(x);
}

void
wrong()
{
    printf("in wrong\n");
}

void
right()
{
    printf("in right\n");
}

int
main()
{
    /* same-size is easier to handle */
    test_swap(16*1024, 16*1024);
    /* this one is more difficult since if base threshold on 1st malloc size
     * will get unaddr on swapping to smaller higher stack
     */
    test_swap(32*1024, 24*1024);
    /* test giant alloca (will also test fault on special shadow write) */
    test_alloca();
    /* i#668 test esp adjusted by cmovcc */
    stack1 = (char *) malloc(16*1024) + 16*1024;
    test_cmovcc_asm();
    free((char *)stack1 - 16*1024);
    printf("all done\n");
    return 0;
}

#else /* asm code *************************************************************/
#include "cpp2asm_defines.h"
START_FILE

DECL_EXTERN(foo)
DECL_EXTERN(right)
DECL_EXTERN(wrong)

/* data, which we're ok being non-PIC for */
DECL_EXTERN(orig_esi)
DECL_EXTERN(stack0)
DECL_EXTERN(stack1)
DECL_EXTERN(stack2)

#define FUNCNAME swap_stack_and_back_asm
/* void swap_stack_and_back_asm(void); */
        DECLARE_FUNC_SEH(FUNCNAME)
GLOBAL_LABEL(FUNCNAME:)
        mov      REG_XDX, ARG1
        push     REG_XBP
        mov      REG_XBP, REG_XSP
        END_PROLOG

        mov      PTRSZ SYMREF(stack0), REG_XSP /* store orig stack */
        mov      REG_XSP, PTRSZ SYMREF(stack1)
        call     GLOBAL_REF(foo)
        /* this swap to stack2 looks like a big dealloc => will mark data as unaddr */
        mov      REG_XSP, PTRSZ SYMREF(stack2)
        call     GLOBAL_REF(foo)
        mov      REG_XSP, PTRSZ SYMREF(stack0) /* restore orig stack */

        add      REG_XSP, 0 /* make a legal SEH64 epilog */
        mov      REG_XSP, REG_XBP
        pop      REG_XBP
        ret
        END_FUNC(FUNCNAME)
#undef FUNCNAME


#define FUNCNAME test_cmovcc_asm
/* void test_cmovcc_asm(void); */
        DECLARE_FUNC_SEH(FUNCNAME)
GLOBAL_LABEL(FUNCNAME:)
        mov      REG_XDX, ARG1
        push     REG_XBP
        mov      REG_XBP, REG_XSP
        END_PROLOG

        mov      PTRSZ SYMREF(stack0), REG_XSP   /* store orig stack */
        mov      PTRSZ SYMREF(orig_esi), REG_XSI /* store orig esi */
        mov      REG_XSI, PTRSZ SYMREF(stack1)
        cmp      REG_XSI, REG_XSP
        cmovne   REG_XSP, REG_XSI /* test execute cmovcc */
        jne      correct1
        call     GLOBAL_REF(wrong)
        jmp      test2
    correct1:
        call     GLOBAL_REF(right)
        test2:
        mov      REG_XSI, PTRSZ SYMREF(stack1)
        cmp      REG_XSP, REG_XSI     /* they should be equal */
        cmovne   REG_XSP, REG_XSI  /* test skip cmovcc */
        je       correct2
        call     GLOBAL_REF(wrong)
        jmp      done
    correct2:
        call     GLOBAL_REF(right)
    done:
        mov      REG_XSI, PTRSZ SYMREF(orig_esi) /* restore orig REG_XSI */
        mov      REG_XSP, PTRSZ SYMREF(stack0) /* restore orig stack */

        add      REG_XSP, 0 /* make a legal SEH64 epilog */
        mov      REG_XSP, REG_XBP
        pop      REG_XBP
        ret
        END_FUNC(FUNCNAME)
#undef FUNCNAME


END_FILE
#endif
