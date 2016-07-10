/* **********************************************************
 * Copyright (c) 2015-2016 Google, Inc.  All rights reserved.
 * **********************************************************/

/* Dr. Memory: the memory debugger
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation;
 * version 2.1 of the License, and no later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * Library General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

/* i#1699: Test MacOS malloc zones. */

#include <malloc/malloc.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <assert.h>
#include <unistd.h>

#define ALIGNED(x, alignment) ((((uintptr_t)x) & ((alignment)-1)) == 0)

int
main(void)
{
    malloc_zone_t *myzone;
    void *m1, *m2;
    printf("testing malloc zones\n");

    myzone = malloc_create_zone(4*1024*1024, 0);
    assert(myzone != NULL);
    assert(myzone != malloc_default_zone());

    m2 = malloc(58);
    assert(malloc_zone_from_ptr(m2) == malloc_default_zone());
    free(m2);

    m1 = malloc_zone_malloc(myzone, 58);
    assert(m1 != NULL);
    assert(malloc_zone_from_ptr(m1) == myzone);
    if (*(int *)m1 == 0) /* uninit error */
        *(int *)m1 = 1;

    m1 = malloc_zone_realloc(myzone, m1, 28);
    assert(m1 != NULL);
    assert(malloc_zone_from_ptr(m1) == myzone);
    m1 = malloc_zone_realloc(myzone, m1, 78);
    assert(m1 != NULL);
    assert(malloc_zone_from_ptr(m1) == myzone);

    malloc_zone_free(myzone, m1);
    if (*(int *)m1 == 0) /* use-after-free */
        m1 = NULL;

    m1 = malloc_zone_calloc(myzone, 4, 5);
    assert(m1 != NULL);
    assert(*(int *)m1 == 0);
    malloc_zone_free(myzone, m1);

    m1 = malloc_zone_valloc(myzone, 58);
    assert(m1 != NULL);
    assert(ALIGNED(m1, sysconf(_SC_PAGESIZE)));
    malloc_zone_free(myzone, m1);

    m1 = malloc_zone_memalign(myzone, 256, 58);
    assert(m1 != NULL);
    assert(ALIGNED(m1, 256));
    malloc_zone_free(myzone, m1);

    m1 = malloc_zone_malloc(myzone, 58);
    assert(m1 != NULL);
    malloc_destroy_zone(myzone);

    printf("done\n");
    return 0;
}
