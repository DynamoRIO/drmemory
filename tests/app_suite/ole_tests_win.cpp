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
