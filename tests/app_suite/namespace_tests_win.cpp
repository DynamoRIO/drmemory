/* **********************************************************
 * Copyright (c) 2014-2016 Google, Inc.  All rights reserved.
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

/* Tests Windows namespace syscalls */

#include <windows.h>
#include <Sddl.h>          /* for SID management */
#include <stdio.h>
#include <time.h>
#include "gtest/gtest.h"

TEST(NamespaceTests, NtCreateOpenPrivateNamespace){
    HANDLE boundary;
    /* Names of boundary and private namespaces */
    static PCTSTR BOUNDARY_NAME = TEXT("3-Boundary");
    static PCTSTR NAMESPACE_NAME = TEXT("3-Namespace");
    static PCTSTR NAMESPACE2_NAME = TEXT("4-Namespace");
    /* Create the boundary descriptor */
    boundary = CreateBoundaryDescriptor(BOUNDARY_NAME, 0);
    /* Create a SID corresponding to the Local Administrator group */
    PSID plocal_admin;
    BOOL res;
    res = ConvertStringSidToSid(TEXT("S-1-1-0"), &plocal_admin);
    if (!res) {
        /* The routine may fail for some security reasons. */
        printf("ConvertStringSidToSid failed. Error code is %u\n", GetLastError());
    } else
        LocalFree(plocal_admin);
    ASSERT_NE(FALSE, res);
    res = ConvertStringSidToSid(TEXT("S-1-1-0"), &plocal_admin);
    if (!res) {
        /* The routine may fail for some security reasons. */
        printf("AddSIDToBoundaryDescriptor failed. Error code is %u\n", GetLastError());
    } else
        LocalFree(plocal_admin);
    ASSERT_NE(FALSE, res);
    /* Create the namespace for Local Administrators only */
    SECURITY_ATTRIBUTES sa;
    sa.nLength = sizeof(sa);
    sa.bInheritHandle = FALSE;
    res = ConvertStringSecurityDescriptorToSecurityDescriptor(TEXT("D:(A;;GA;;;BA)"),
                                                            SDDL_REVISION_1,
                                                            &sa.lpSecurityDescriptor,
                                                            NULL);
    if (!res) {
        printf("Security Descriptor creation failed. Error code is %u\n", GetLastError());
    }
    ASSERT_NE(FALSE, res);
    /* The routine calls NtCreatePrivateNamespace. */
    HANDLE hnamespace = CreatePrivateNamespace(&sa, boundary, NAMESPACE_NAME);
    if (hnamespace == NULL) {
        printf("CreatePrivateNamespace failed with error code: %u\n", GetLastError());
    }
    ASSERT_NE((HANDLE)NULL, hnamespace);
    /* The routine calls NtOpenPrivateNamespace. */
    HANDLE hnamespace_2 = OpenPrivateNamespace(boundary, NAMESPACE2_NAME);
    if (hnamespace_2 == NULL) {
        printf("OpenPrivateNamespace failed with error code: %u\n", GetLastError());
    }
    ASSERT_NE((HANDLE)NULL, hnamespace_2);
    /* The routine calls NtDeletePrivateNamespace. */
    ClosePrivateNamespace(hnamespace,
                          PRIVATE_NAMESPACE_FLAG_DESTROY);
    DeleteBoundaryDescriptor(boundary);
}
