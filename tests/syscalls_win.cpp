/* **********************************************************
 * Copyright (c) 2014 Google, Inc.  All rights reserved.
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

/* Tests Windows system calls */

#ifndef WINDOWS
# error Windows-only
#endif

#include <windows.h>
#include <iostream>

using namespace std;

/* use GetCursorInfo, a wrapper for NtUserGetCursorInfo syscall,
 * to test SYSARG_SIZE_IN_FIELD handling
 */
static void
test_sysarg_size_in_field()
{
    int uninit;
    CURSORINFO cursor_info;
    /* We zero out the high 30-bit of cbSize (& 0x3) to avoid large value,
     * which may cause an extra unaddr error.
     * We cannot use 0xf due to a heuristic used by i#849.
     */
    cursor_info.cbSize &= 0x3;
    if (GetCursorInfo(&cursor_info) != 0) /* uninit on cbSize */
        cout << "GetCursorInfo succeeded unexpectedly." << endl;
    cursor_info.cbSize = sizeof(CURSORINFO);
    if (GetCursorInfo(&cursor_info) == 0)
        cout << "Unable to get cursor info. Error = " << GetLastError() << endl;
}

int
main()
{
    test_sysarg_size_in_field();
    cout << "done" << endl;
    return 0;
}
