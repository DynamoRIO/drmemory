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
    ICONINFO iinfo;
    /* We zero out the high bits of cbSize to avoid a large value,
     * which can cause an extra unaddr error.
     * We can't use & with a constant as that hits bitfield heuristics (i#849, i#1520).
     */
    memset(((byte *)&cursor_info.cbSize) + 1, 0, 3);
    if (GetCursorInfo(&cursor_info)) /* uninit on cbSize */
        cout << "GetCursorInfo succeeded unexpectedly." << endl;
    cursor_info.cbSize = sizeof(CURSORINFO);
    /* i#1494: GetCursorInfo clears the cbSize field in kernel */
    if (!GetCursorInfo(&cursor_info)) {
        /* XXX: i#1504: GetCursorInfo may fail on ERROR_ACCESS_DENIED
         * for unknown reasons, in which case we bail out.
         */
        return;
    }
    if (!GetIconInfo(cursor_info.hCursor, &iinfo))
        cout << "Unable to get icon info. Error = " << GetLastError() << endl;
}

int
main()
{
    test_sysarg_size_in_field();
    cout << "done" << endl;
    return 0;
}
