/* **********************************************************
 * Copyright (c) 2013 Google, Inc.  All rights reserved.
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

#include "gtest/gtest.h"
#include <stdlib.h>

#define BUFFER_SIZE_BYTES(buf)      sizeof(buf)
#define BUFFER_SIZE_ELEMENTS(buf)   (BUFFER_SIZE_BYTES(buf) / sizeof((buf)[0]))

TEST(MallocTests, ReverseBrk) {
    unsigned int i, j;
    char *big[512];
    /* Allocate 64K*256=32MB, in small enough chunks (64K) to avoid
     * mmaps and stay in regular heap.  Do this 128 times.  If there's
     * reverse brk and -delay_frees 0 we should end up with brk just
     * about where it started.  With default options, it's still a
     * nice stress test of malloc coalescing and splitting.
     */
    for (j = 0; j < 128; j++) {
        for (i = 0; i < BUFFER_SIZE_ELEMENTS(big); i++)
            big[i] = (char *) malloc(64*1024);
        for (i = 0; i < BUFFER_SIZE_ELEMENTS(big); i++)
            free(big[i]);
    }
}
