/* **********************************************************
 * Copyright (c) 2011 Google, Inc.  All rights reserved.
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

#include <windows.h>

#include <commctrl.h>
#include <winuser.h>

#include "gtest/gtest.h"

#pragma comment(lib, "comctl32.lib")

TEST(NtUserTests, SystemParametersInfo) {
    // Was: http://code.google.com/p/drmemory/issues/detail?id=10
    NONCLIENTMETRICS metrics;
    ZeroMemory(&metrics, sizeof(NONCLIENTMETRICS));
    metrics.cbSize = sizeof(NONCLIENTMETRICS);
    SystemParametersInfo(SPI_GETNONCLIENTMETRICS, sizeof(NONCLIENTMETRICS),
                         &metrics, 0);
}

namespace Clipboard_Tests {
void WriteStringToClipboard(const std::string& str) {
    HWND hWnd = ::GetDesktopWindow();
    ASSERT_NE(0, ::OpenClipboard(hWnd));
    ::EmptyClipboard();
    HGLOBAL data = ::GlobalAlloc(2 /*GMEM_MOVABLE*/, str.size() + 1);
    ASSERT_NE((HGLOBAL)NULL, data);

    char* raw_data = (char*)::GlobalLock(data);
    memcpy(raw_data, str.data(), str.size() * sizeof(char));
    raw_data[str.size()] = '\0';
    ::GlobalUnlock(data);

    ASSERT_EQ(data, ::SetClipboardData(CF_TEXT, data));
    ::CloseClipboard();
}

void ReadAsciiStringFromClipboard(std::string *result) {
    assert(result != NULL);

    HWND hWnd = ::GetDesktopWindow();
    ASSERT_NE(0, ::OpenClipboard(hWnd));

    HANDLE data = ::GetClipboardData(CF_TEXT);
    ASSERT_NE((HANDLE)NULL, data);

    result->assign((const char*)::GlobalLock(data));

    ::GlobalUnlock(data);
    ::CloseClipboard();
}

TEST(NtUserTests, ClipboardPutGet) {
    // Was: http://code.google.com/p/drmemory/issues/detail?id=45
    std::string tmp, str = "ASCII";
    WriteStringToClipboard(str);
    ReadAsciiStringFromClipboard(&tmp);
    ASSERT_STREQ("ASCII", tmp.c_str());
}
}

TEST(NtUserTests, CoInitializeUninitialize) {
    // Was: http://code.google.com/p/drmemory/issues/detail?id=65
    CoInitialize(NULL);
    CoUninitialize();
}

TEST(NtUserTests, InitCommonControlsEx) {
    // Was: http://code.google.com/p/drmemory/issues/detail?id=362
    INITCOMMONCONTROLSEX InitCtrlEx;

    InitCtrlEx.dwSize = sizeof(INITCOMMONCONTROLSEX);
    InitCtrlEx.dwICC  = ICC_PROGRESS_CLASS;
    InitCommonControlsEx(&InitCtrlEx);  // initialize common control sex
}
