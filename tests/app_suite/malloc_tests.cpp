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
#include "app_suite_utils.h"
#include <stdlib.h>

#ifdef TOOL_DR_MEMORY
# define ARRAY_SIZE 512
#else
/* For drheapstat, we clear the shadow memory on every malloc, which may cause
 * test timeout if the array is too large (i.e., too many malloc).
 * So we use a smaller array for drheapstat.
 */
# define ARRAY_SIZE 4
#endif

TEST(MallocTests, ReverseBrk) {
    unsigned int i = 0, j;
    char *big[ARRAY_SIZE];
    /* Allocate 64K*256=32MB, in small enough chunks (64K) to avoid
     * mmaps and stay in regular heap.  Do this 128 times.  If there's
     * reverse brk and -delay_frees 0 we should end up with brk just
     * about where it started.  With default options, it's still a
     * nice stress test of malloc coalescing and splitting.
     */
    for (j = 0; j < 128; j++) {
        /* have fewer malloc/free to avoid time out in drheapstat test */
        for (i = 0; i < BUFFER_SIZE_ELEMENTS(big); i++)
            big[i] = (char *) malloc(64*1024);
        for (i = 0; i < BUFFER_SIZE_ELEMENTS(big); i++)
            free(big[i]);
    }
}

TEST(MallocTests, CallocOverflow) {
    /* Ensure our calloc replacement or wrapping handles overflow */
#ifdef X64
    ASSERT_EQ(NULL, calloc(0x100000LLU, 0x100000000001LLU));
#else
    ASSERT_EQ(NULL, calloc(0x00067000U, 0x00002800U));
#endif
}
