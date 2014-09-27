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
#include <Sddl.h>          /* for SID management */
#include <strsafe.h>
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

static void
test_GetKeyboardState()
{
    /* TODO: use USER_KEYBOARD_STATE_SIZE from wininc/ntuser.h for keyboard size */
    BYTE keyboard_states_uninit[256];
    BYTE keyboard_states_init[256];
    GetKeyboardState(&keyboard_states_init[0]);
    SetKeyboardState(&keyboard_states_uninit[0]); /* uninit error */
    SetKeyboardState(&keyboard_states_init[0]);
}

/* Use CreatePrivateNamespace wrapper for
 * NtCreatePrivateNamespace, to test handling.
 */
static void
test_CreatePrivateNamespace(void)
{
    HANDLE   boundary;
    /* Names of boundary and private namespaces */
    static PCTSTR   BOUNDARY_NAME = TEXT("3-Boundary");
    static PCTSTR   NAMESPACE_NAME = TEXT("3-Namespace");
    /* Create the boundary descriptor */
    boundary = CreateBoundaryDescriptor(BOUNDARY_NAME, 0);
    if (boundary == NULL) {
        /* unexpected fail */
        cout << "CreateBoundaryDescriptor failed. Error code is "
             << GetLastError() << endl;
        return;
    }
    /* Create a SID corresponding to the Local Administrator group */
    PSID plocal_admin;
    if (ConvertStringSidToSid(TEXT("S-1-1-0"), &plocal_admin) == 0) {
        /* unexpected fail */
        cout << "ConvertStringSidToSid failed. Error code is "
             << GetLastError() << endl;
        return;
    }
    if (AddSIDToBoundaryDescriptor(&boundary, plocal_admin) == 0) {
        /* unexpected fail */
        cout << "AddSIDToBoundaryDescriptor failed. Error code is "
             << GetLastError() << endl;
        return;
    }
    /* Create the namespace for Local Administrators only */
    SECURITY_ATTRIBUTES sa;
    sa.nLength = sizeof(sa);
    sa.bInheritHandle = FALSE;
    if (ConvertStringSecurityDescriptorToSecurityDescriptor(TEXT("D:(A;;GA;;;BA)"),
                                                            SDDL_REVISION_1,
                                                            &sa.lpSecurityDescriptor,
                                                            NULL) == 0) {
        /* unexpected fail */
        cout << "Security Descriptor creation failed. Error code is "
             << GetLastError() << endl;
        return;
    }
    SECURITY_ATTRIBUTES sa2;
    sa2.nLength = sizeof(sa2);
    sa2.bInheritHandle = FALSE;
    /* The routine calls NtCreatePrivateNamespace. */
    if (CreatePrivateNamespace(&sa2, NULL, NAMESPACE_NAME) != 0) { /* uninit error */
        cout << "CreatePrivateNamespace succeeded unexpectedly" << endl;
    }
    HANDLE hnamespace = CreatePrivateNamespace(&sa, boundary, NAMESPACE_NAME);
    if (hnamespace == NULL) {
        /* unexpected fail */
        cout << "CreatePrivateNamespace failed. Error code is "
             << GetLastError() << endl;
    }
    ClosePrivateNamespace(hnamespace,
                          PRIVATE_NAMESPACE_FLAG_DESTROY);
    DeleteBoundaryDescriptor(boundary);
    return;
}

static void
test_QueryVirtualMemory(void)
{
    MEMORY_BASIC_INFORMATION mbi;
    /* pick a "wild address" to test umbra on non-app addresses (i#1641) */
#ifdef X64
#   define WILD_ADDR 0x0000812300001234 /* non-canonical */
#else
#   define WILD_ADDR 0x4 /* umbra handles everything, so just ensure it's unaddr */
#endif
    VirtualQuery(NULL, (MEMORY_BASIC_INFORMATION *)WILD_ADDR, sizeof(mbi));
}

int
main()
{
    cout << "Test sysarg size in field: ";
    test_sysarg_size_in_field();
    cout << "done" << endl;
    cout << "Test NtUser[Set/Get]KeyboardState: ";
    test_GetKeyboardState();
    cout << "done" << endl;
    cout << "Test NtCreatePrivateNamespaces: ";
    test_CreatePrivateNamespace();
    cout << "done" << endl;
    cout << "Test NtQueryVirtualMemory: ";
    test_QueryVirtualMemory();
    cout << "done" << endl;
    return 0;
}
