/* **********************************************************
 * Copyright (c) 2011 Google, Inc.  All rights reserved.
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

/* Test our ability to understand valgrind annotations. */

#include "memcheck.h"

int
main(void)
{
    int *uninit = malloc(sizeof(*uninit));
    (void)VALGRIND_MAKE_MEM_DEFINED_IF_ADDRESSABLE(uninit, sizeof(*uninit));
    if (*uninit) {
        printf("*uninit != 0\n");
    } else {
        printf("*uninit == 0\n");
    }
    free(uninit);
    return 0;
}
