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

/* Tests blacklist options */

#ifndef WINDOWS
# error Windows-only
#endif

#include <windows.h>
#include <stdio.h>

static void
test_system_lib()
{
    /* We run with -lib_blacklist_frames 0, where this should be marked "potential": */
    MEMORY_BASIC_INFORMATION mbi;
    void **uninit = (void **) malloc(sizeof(*uninit));
    VirtualQuery(*uninit, &mbi, sizeof(mbi));
    free(uninit);
}

int
main()
{
    test_system_lib();
    printf("all done\n");
    return 0;
}
