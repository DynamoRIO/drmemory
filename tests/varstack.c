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
#include <string.h>

static void *stack0;
static void *stack1;
static void *stack2;
static int *data;

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

int
main()
{
    /* same-size is easier to handle */
    test_swap(16*1024, 16*1024);
    /* this one is more difficult since if base threshold on 1st malloc size
     * will get unaddr on swapping to smaller higher stack
     */
    test_swap(32*1024, 24*1024);
    printf("all done\n");
    return 0;
}
