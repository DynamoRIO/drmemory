/* **********************************************************
 * Copyright (c) 2020-2021 Google, Inc.  All rights reserved.
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

#include "drmemory_annotations.h"
#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <string.h>
#ifdef UNIX
# include <sys/mman.h>
# include <stdint.h>
# include <malloc.h>
#else
# include <windows.h>
#endif

#define ALIGN_FORWARD(x, alignment) \
    ((((uintptr_t)x) + ((alignment)-1)) & (~((uintptr_t)(alignment)-1)))

int
main()
{
    /* To reproduce i#2317, we need a large heap alloc that will use an mmap.
     * We then use annotations to mark it unaddr, and then touch the top.
     */
    static const int malloc_size = 1*1024*1024;
    void *ptr1 = NULL;
    int res = posix_memalign(&ptr1, 256*1024, malloc_size);
    assert(res == 0 && ptr1 != NULL);
    void *ptr2 = NULL;
    res = posix_memalign(&ptr2, 256*1024, malloc_size);
    assert(res == 0 && ptr2 != NULL);
    DRMEMORY_ANNOTATE_MAKE_UNADDRESSABLE(ptr2, malloc_size);
    char *end = (char*) ALIGN_FORWARD((char*)ptr2 + malloc_size, 256*1024);
    *(end - 1) = 1;
    free(ptr1);
    free(ptr2);
    printf("all done\n");
    return 0;
}
