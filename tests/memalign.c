/* **********************************************************
 * Copyright (c) 2010-2018 Google, Inc.  All rights reserved.
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
#ifdef MACOS
# include <malloc/malloc.h>
#else
# include <malloc.h>
#endif
#include <stdint.h>
#include <stdlib.h>
#include <assert.h>
#ifdef UNIX
# include <errno.h>
# include <unistd.h>
#endif

/* i#94: handle auxiliary alloc routines: memalign(), valloc(), etc. */

#define ALIGNED(x, alignment) ((((uintptr_t)x) & ((alignment)-1)) == 0)

int main()
{
    void *p;
    int i, res;
    char c;
#ifdef LINUX
    struct mallinfo info;

# if 0 /* Removing since cfree was removed from glibc 2.26+ */
    p = malloc(37);
    cfree(p);
# endif

    mallopt(M_MMAP_THRESHOLD, 32 * 1024);

    info = mallinfo();

    malloc_trim(16);

    malloc_stats();

# if 0 /* Removing since malloc_get_state was removed from glibc 2.25+ */
    p = malloc_get_state();
    free(p);
# endif
#elif defined(MACOS)
    /* Tests for malloc zones (i#1699) are in mac_zones.c */
#endif

    p = NULL;
    res = posix_memalign(&p, 256, 42);
    assert(res == 0 && p != NULL);
    assert(ALIGNED(p, 256));
    c = *((char *)p - 1); /* unaddr */
    c = *((char *)p + 42); /* unaddr */
    free(p);

    /* Test with pulling from free list (has to be run "-delay_frees 0").
     * First, prime the free list.
     */
    for (i = 0; i < 10; i++) {
        p = malloc(1U << i);
        free(p);
    }

    p = NULL;
    res = posix_memalign(&p, 128, 99);
    assert(res == 0 && p != NULL);
    assert(ALIGNED(p, 128));
    c = *((char *)p - 1); /* unaddr */
    c = *((char *)p + 99); /* unaddr */
    free(p);

    /* Test non-power-of-2 */
    res = posix_memalign(&p, 127, 99);
    assert(res == EINVAL);

    /* Test mmap */
    p = NULL;
    res = posix_memalign(&p, 512, 256*1024); /* 128K is our mmap min */
    assert(res == 0 && p != NULL);
    assert(ALIGNED(p, 512));
    c = *((char *)p - 1); /* unaddr */
    c = *((char *)p + 256*1024); /* unaddr */
    free(p);

#ifndef MACOS
    p = memalign(64, 3);
    assert(p != NULL);
    assert(ALIGNED(p, 64));
    c = *((char *)p - 1); /* unaddr */
    c = *((char *)p + 3); /* unaddr */
    free(p);
#endif

    p = valloc(643);
    assert(p != NULL);
    assert(ALIGNED(p, sysconf(_SC_PAGESIZE)));
    c = *((char *)p - 1); /* unaddr */
    c = *((char *)p + 643); /* unaddr */
    free(p);

#ifndef MACOS
    p = pvalloc(643);
    assert(p != NULL);
    assert(ALIGNED(p, sysconf(_SC_PAGESIZE)));
    c = *((char *)p - 1); /* unaddr */
    c = *((char *)p + 643); /* ok */
    c = *((char *)p + sysconf(_SC_PAGESIZE)); /* unaddr */
    free(p);
#endif

    printf("success\n");
    return 0;
}
