/* **********************************************************
 * Copyright (c) 2010 Google, Inc.  All rights reserved.
 * Copyright (c) 2010 VMware, Inc.  All rights reserved.
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
#include <malloc.h>

/* PR 406323: handle auxiliary alloc routines: memalign(), valloc(), etc. */

int main()
{
    void *p;
    struct mallinfo info;

    p = malloc(37);
    cfree(p);

    mallopt(M_MMAP_THRESHOLD, 32 * 1024);

    info = mallinfo();

    malloc_trim(16);

    malloc_stats();

    p = malloc_get_state();
    free(p);

    /* XXX PR 406323: add aligned-malloc tests once we have support */

    printf("success\n");
    return 0;
}
