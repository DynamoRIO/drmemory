/* **********************************************************
 * Copyright (c) 2013-2015 Google, Inc.  All rights reserved.
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
#include <sys/mman.h>
#include <unistd.h>
#include <errno.h>
#include <stdint.h>
#include "memcheck.h"

TEST(MmapTests, PointerOverflow) {
    void *p = mmap((void *)0xffff8000, 0x1000, PROT_READ|PROT_WRITE,
                   MAP_PRIVATE|MAP_ANON|MAP_FIXED, 0, 0);
    /* Best-effort: may fail */
    if (p != NULL) {
        *(int *)p = 0;
    }
}

TEST(MmapTests, SigBus) {
    /* Test i#1773 */
    FILE *tmpf = fopen("mmap_test_file", "w+");
    fprintf(tmpf, "MmapTests.SigBus test file\n");
    void *p = mmap(NULL, sysconf(_SC_PAGESIZE), PROT_READ, MAP_SHARED, fileno(tmpf),
                   /* Offset of 0 does not generate SIGBUS when accessing beyond
                    * EOF -- we need offset beyond EOF at start of mmap.
                    */
                   sysconf(_SC_PAGESIZE));
    if (p == (void *)(uintptr_t)-1)
        perror("mmap failed");
    ASSERT_NE(p, (void *)(uintptr_t)-1);

    /* Now do the leak scan, which will result in SIGBUS pre-i#1773 fix */
    VALGRIND_DO_LEAK_CHECK;

    munmap(p, sysconf(_SC_PAGESIZE));
    fclose(tmpf);
    unlink("mmap_test_file");
}
