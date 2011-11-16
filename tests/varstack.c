/* **********************************************************
 * Copyright (c) 2011 Google, Inc.  All rights reserved.
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
#include <string.h>

static void *orig_esi;
static void *stack0;
static void *stack1;
static void *stack2;
static int *data;

#ifdef WINDOWS
# define IF_WINDOWS_ELSE(x,y) x
#else
# define IF_WINDOWS_ELSE(x,y) y
#endif

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

#ifdef WINDOWS
    __asm {
        mov stack0, esp /* store orig stack */
        mov esp, stack1
        call foo
        /* this swap to stack2 looks like a big dealloc => will mark data as unaddr */
        mov esp, stack2
        call foo
        mov esp, stack0 /* restore orig stack */
    };
#else
    __asm("mov %%esp, %0" : "=m"(stack0)); /* store orig stack */
    __asm("mov %0, %%esp; call foo" : : "g"(stack1));
    /* this swap to stack2 looks like a big dealloc => will mark data as unaddr */
    __asm("mov %0, %%esp; call foo" : : "g"(stack2));
    __asm("mov %0, %%esp" : : "g"(stack0)); /* restore orig stack */
#endif

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

void
test_cmovcc(void)
{
#ifdef WINDOWS
    __asm {
        mov stack0, esp   /* store orig stack */
        mov orig_esi, esi /* store orig ebp */
        mov esi, stack1
        cmp esi, esp
        cmovne esp, esi /* test execute cmovcc */
        jne correct1
        call wrong
        jmp test2
        correct1:
        call right
        test2:
        mov esi, stack1
        cmp esp, esi     /* they should be equal */
        cmovne esp, esi  /* test skip cmovcc */
        je correct2
        call wrong
        jmp done
        correct2:
        call right
        done:
        mov esi, orig_esi /* restore orig esi */
        mov esp, stack0 /* restore orig stack */
    };
#else
    __asm("mov %%esp, %0" : "=m"(stack0)); /* store orig stack */
    __asm("mov %%esi, %0" : "=m"(orig_esi)); /* store orig esi */
    __asm("mov %0, %%esi" : : "g" (stack1));
    __asm("cmp %%esi, %%esp" :);
    __asm("cmovne %%esi, %%esp" :);
    __asm("jne correct1");
    __asm("call wrong");
    __asm("jmp test2");
    __asm("correct1:");
    __asm("call right");
    __asm("test2:");
    __asm("mov %0, %%esi" : : "g" (stack1));
    __asm("cmp %%esi, %%esp" :);
    __asm("cmovne %%esi, %%esp" : );
    __asm("je correct2");
    __asm("call wrong");
    __asm("jmp done");
    __asm("correct2:");
    __asm("call right");
    __asm("done:");
    __asm("mov %0, %%esi" : : "g"(orig_esi)); /* restore orig esi */
    __asm("mov %0, %%esp" : : "g"(stack0)); /* restore orig stack */
#endif
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
    test_cmovcc();
    printf("all done\n");
    return 0;
}
