/* **********************************************************
 * Copyright (c) 2012 Google, Inc.  All rights reserved.
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

#if _MSC_VER <= 1400
# undef  _WIN32_WINNT
# define _WIN32_WINNT 0x0400 /* == NT4 */ /* not set for VS2005 */
#endif

#include <windows.h>
#include <objbase.h>
#include <stdlib.h>

// For shell link stuff.
#include <shobjidl.h>
#include <shlguid.h>

#pragma comment(lib, "ole32.lib")

#include "gtest/gtest.h"

// Ensure that CoInitializeEx test comes first, because many of the leaks
// happen once per process, and the callstacks through CoInitializeEx are
// harder to suppress due its tail call.
TEST(OleTest, CoInitializeEx) {
    HRESULT hr = CoInitializeEx(NULL, COINIT_APARTMENTTHREADED);
    ASSERT_TRUE(SUCCEEDED(hr));
    CoUninitialize();
}

TEST(OleTest, CoInitialize) {
    HRESULT hr = CoInitialize(NULL);
    ASSERT_TRUE(SUCCEEDED(hr));
    CoUninitialize();
}

TEST(OleTest, CoCreateInstance) {
    HRESULT hr = CoInitialize(NULL);
    ASSERT_TRUE(SUCCEEDED(hr));

    // Some COM object for creating shortcut files.  We just use it as an
    // arbitrary object that we can create.
    IShellLink* shell_link = NULL;
    hr = CoCreateInstance(CLSID_ShellLink, NULL, CLSCTX_INPROC_SERVER,
                          IID_IShellLink, (LPVOID*)&shell_link);
    ASSERT_TRUE(SUCCEEDED(hr));
    shell_link->Release();

    CoUninitialize();
}

TEST(OleTest, CoCreateGuid) {
    HRESULT hr = CoInitialize(NULL);
    ASSERT_TRUE(SUCCEEDED(hr));

    GUID my_guid;
    /* i#511: Reads from my_guid to seed the PRNG. */
    hr = CoCreateGuid(&my_guid);
    ASSERT_TRUE(SUCCEEDED(hr));

    GUID zero_guid;
    memset(&zero_guid, 0, sizeof(zero_guid));
    ASSERT_NE(memcmp(&my_guid, &zero_guid, sizeof(my_guid)), 0);

    CoUninitialize();
}
