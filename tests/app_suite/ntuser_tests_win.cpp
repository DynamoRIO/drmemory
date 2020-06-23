/* **********************************************************
 * Copyright (c) 2011-2020 Google, Inc.  All rights reserved.
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

#include <winuser.h>

#include "os_version_win.h"
#include "gtest/gtest.h"
#include "app_suite_utils.h"

// For InitCommonControlsEx
#include <commctrl.h>
#pragma comment(lib, "comctl32.lib")

// For BuildPropList test
#include <shobjidl.h>
#include <propkey.h>
#include <propvarutil.h>
#include <propidl.h>
#pragma comment(lib, "user32.lib")
#pragma comment(lib, "shell32.lib")
#pragma comment(lib, "shlwapi.lib")
#pragma comment(lib, "ole32.lib")

// A potentially externally visible global.  Useful if you want to make a
// statement the compiler can't delete.
int global_for_side_effects;

// FIXME i#735: Re-enable once doesn't hang and passes on xp32.
TEST(NtUserTests, DISABLED_SystemParametersInfo) {
    // Was: http://https://github.com/DynamoRIO/drmemory/issues/10
    NONCLIENTMETRICS metrics;
    ZeroMemory(&metrics, sizeof(NONCLIENTMETRICS));
    metrics.cbSize = sizeof(NONCLIENTMETRICS);
    BOOL success = SystemParametersInfo(SPI_GETNONCLIENTMETRICS,
                                        sizeof(NONCLIENTMETRICS), &metrics, 0);
    ASSERT_EQ(TRUE, success);
    success = SystemParametersInfo(SPI_SETNONCLIENTMETRICS,
                                   sizeof(NONCLIENTMETRICS), &metrics, 0);
    ASSERT_EQ(TRUE, success);
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
    // FIXME i#734: Re-enable when no uninits.
    if (GetWindowsVersion() >= WIN_VISTA) {
        printf("WARNING: Disabling ClipboardPutGet on Win Vista+, see i#734.\n");
        return;
    }

    // Was: http://https://github.com/DynamoRIO/drmemory/issues/45
    std::string tmp, str = "ASCII";
    WriteStringToClipboard(str);
    ReadAsciiStringFromClipboard(&tmp);
    ASSERT_STREQ("ASCII", tmp.c_str());
}

TEST(NtUserTests, ClipboardFormat) {
    /* i#1824: test NtUserGetClipboardFormatName */
    WCHAR buf[257];
    int ret = GetClipboardFormatNameW(49283, buf, 256);
    EXPECT_GT(ret, 0);
    for (int i = 0; i < ret; ++i)
        EXPECT_NE(buf[i], '\0');
    EXPECT_EQ(buf[ret], '\0');
}

} /* Clipboard_Tests */

TEST(NtUserTests, CoInitializeUninitialize) {
    // Was: http://https://github.com/DynamoRIO/drmemory/issues/65
    CoInitialize(NULL);
    CoUninitialize();
}

TEST(NtUserTests, InitCommonControlsEx) {
    // Was: http://https://github.com/DynamoRIO/drmemory/issues/362
    INITCOMMONCONTROLSEX InitCtrlEx;

    InitCtrlEx.dwSize = sizeof(INITCOMMONCONTROLSEX);
    InitCtrlEx.dwICC  = ICC_PROGRESS_CLASS;
    InitCommonControlsEx(&InitCtrlEx);  // initialize common control sex
}

TEST(NtUserTests, CursorTest) {
    // test NtUserCall* GETCURSORPOS, SETCURSORPOS, SHOWCURSOR
    POINT point;
    BOOL success = GetCursorPos(&point);
    if (!success) {
        // FIXME i#755: This seems to happen when a user over RDP disconnected?
        // In any case, not worth the time to track down now.
        printf("WARNING: GetCursorPos failed with error %d\n", GetLastError());
    } else {
        // Check uninits
        MEMORY_BASIC_INFORMATION mbi;
        VirtualQuery((VOID*)(uintptr_t)(point.x + point.y), &mbi, sizeof(mbi));

        success = SetCursorPos(point.x, point.y);
        if (!success) {
            // FIXME i#755: This seems to happen when a user over RDP disconnected?
            // In any case, not worth the time to track down now.
            printf("WARNING: SetCursorPos failed with error %d\n", GetLastError());
        }
    }

    int display_count = ShowCursor(TRUE);
    if (display_count != 1) {
        printf("WARNING: display_count != 1, got %d\n", display_count);
    }
}

TEST(NtUserTests, WindowRgnTest) {
    // test NtUserCall* VALIDATERGN,
    HWND hwnd = ::GetDesktopWindow();
    HRGN hrgn = CreateRectRgn(0, 0, 0, 0);
    ASSERT_NE((HRGN)NULL, hrgn);
    BOOL success = ValidateRgn(hwnd, hrgn);
    ASSERT_EQ(TRUE, success);
    int type = GetWindowRgn(hwnd, hrgn);
    // FIXME: somehow type comes out as ERROR so skipping ASSERT_NE(ERROR, type)
}

TEST(NtUserTests, MenuTest) {
    // FIXME i#736: Re-enable on XP when passes.
    if (GetWindowsVersion() < WIN_VISTA) {
        printf("WARNING: Disabling MenuTest on Pre-Vista, see i#736.\n");
        return;
    }

    // test NtUserCall* DRAWMENUBAR
    HWND hwnd = ::GetDesktopWindow();
    BOOL success = DrawMenuBar(hwnd);
    ASSERT_EQ(FALSE, success); /* no menu on desktop window */

    // test NtUserCall* CREATEMENU + CREATEPOPUPMENU and NtUserDestroyMenu
    HMENU menu = CreateMenu();
    ASSERT_NE((HMENU)NULL, menu);
    success = DestroyMenu(menu);
    ASSERT_EQ(TRUE, success);
    menu = CreatePopupMenu();
    ASSERT_NE((HMENU)NULL, menu);
    success = DestroyMenu(menu);
    ASSERT_EQ(TRUE, success);
}

TEST(NtUserTests, BeepTest) {
    // test NtUserCall* MESSAGEBEEP
    BOOL success = MessageBeep(0xFFFFFFFF/*simple beep*/);
    ASSERT_EQ(TRUE, success);
}

TEST(NtUserTests, CaretTest) {
    // test NtUserGetCaretBlinkTime and NtUserCall* SETCARETBLINKTIME + DESTROY_CARET
    UINT blink = GetCaretBlinkTime();
    ASSERT_NE(0, blink);
    BOOL success = SetCaretBlinkTime(blink);
    ASSERT_EQ(TRUE, success);
    success = DestroyCaret();
    ASSERT_EQ(FALSE, success); // no caret to destroy
}

TEST(NtUserTests, DeferWindowPosTest) {
    // test NtUserCall* BEGINDEFERWINDOWPOS and NtUserDeferWindowPos
    HWND hwnd = ::GetDesktopWindow();
    HDWP hdwp = BeginDeferWindowPos(1);
    if (hdwp) {
        hdwp = DeferWindowPos(hdwp, hwnd, NULL, 0, 0, 5, 10,
                              SWP_NOZORDER | SWP_NOOWNERZORDER | SWP_NOACTIVATE);
    }
    if (hdwp) {
        // XXX: not getting here: need to set up a successful defer
        EndDeferWindowPos(hdwp);
    }
}

TEST(NtUserTests, EnumDisplayDevices) {
    DISPLAY_DEVICE device_info;
    device_info.cb = sizeof(device_info);
    BOOL success = EnumDisplayDevices(NULL, 0, /* display adapter #0 */
                                      &device_info, 0);
    ASSERT_EQ(TRUE, success);
}

TEST(NtUserTests, WindowStation) {
    BOOL success;
    HWINSTA def_ws = GetProcessWindowStation();
    HWINSTA ws = CreateWindowStation(NULL, 0, READ_CONTROL | DELETE, NULL);
    HWINSTA ws2 = OpenWindowStation("winsta0", FALSE, READ_CONTROL | WRITE_DAC);
    ASSERT_NE(ws, (HWINSTA)NULL);
    ASSERT_NE(ws2, (HWINSTA)NULL);

    success = SetProcessWindowStation(ws);
    ASSERT_EQ(success, TRUE);

    // XXX: I tried CreateDesktop but it fails with ERROR_NOT_ENOUGH_MEMORY
    // and I'm not sure we want to go tweaking the default desktop to
    // free memory.

    success = SetProcessWindowStation(def_ws);
    ASSERT_EQ(success, TRUE);

    success = CloseWindowStation(ws);
    ASSERT_EQ(success, TRUE);
    success = CloseWindowStation(ws2);
    ASSERT_EQ(success, TRUE);
}

static DWORD WINAPI
thread_func(void *arg)
{
    MessageBox(NULL, "<will be automatically closed>", "NtUserTests.MessageBox", MB_OK);
    return 0;
}

static BOOL CALLBACK
enum_windows(HWND hwnd, LPARAM param)
{
    DWORD target_tid = (DWORD) param;
    DWORD target_pid = GetCurrentProcessId();
    DWORD window_pid;
    DWORD window_tid = GetWindowThreadProcessId(hwnd, &window_pid);
    // We really only need to test tid but we test both:
    if (window_pid == target_pid && window_tid == target_tid) {
        // We're not allowed to call DestroyWindow() on another thread's window,
        // and calling TerminateThread() seems to destabilize our own
        // process shutdown, so we send a message:
        LRESULT res = SendMessageTimeout(hwnd, WM_CLOSE, 0, 0, SMTO_BLOCK,
                                         0, NULL);
        printf("Found msgbox window: closing.\n");
        if (res != 0)
            SetLastError(NO_ERROR);
        return FALSE;
    }
    return TRUE;
}

TEST(NtUserTests, Msgbox) {
    BOOL success;
    DWORD tid;
    DWORD res;

    // Strategy: have a separate thread open the msgbox so we can close
    // it automatically.
    HANDLE thread = CreateThread(NULL, 0, thread_func, NULL, 0, &tid);
    ASSERT_NE(thread, (HANDLE)NULL);

    Sleep(0); // Avoid initial spin
    do {
        // Close the window as soon as we can.  On an unloaded machine
        // this kills it even before it's visible to avoid an annoying
        // popup natively, though under DrMem full mode it is visible.
        // This exercises ~35 NtGdi and ~60 NtUser syscalls.
        // Unfortunately the timing makes it non-deterministic.
        // Ideally we would write our own tests of all 95 of those
        // syscalls but for now MessageBox is by far the easiest way
        // to run them.
        success = EnumWindows(enum_windows, (LPARAM) tid);
        ASSERT_EQ(GetLastError(), NO_ERROR);
    } while (success /* we went through all windows */);

    // I thought I could wait on thread INFINITE but that hangs so don't wait
    // at all.
    success = CloseHandle(thread);
    ASSERT_EQ(success, TRUE);
}

TEST(NtUserTests, WindowMessages) {
    const char *title = "Test Window";
    HWND hwnd = CreateWindowEx(0 /* style */, "Button" /* class */, title,
                               WS_OVERLAPPEDWINDOW,
                               CW_USEDEFAULT, CW_USEDEFAULT,
                               CW_USEDEFAULT, CW_USEDEFAULT,
                               (HWND) NULL, /* no parent */
                               (HMENU) NULL, (HINSTANCE) NULL, NULL);
    ASSERT_NE(hwnd, (HWND) NULL);

    char buf[64];
    LRESULT res = SendMessage(hwnd, WM_GETTEXT, (WPARAM) sizeof(buf), (LPARAM) buf);
    ASSERT_EQ(res, strlen(title));
    ASSERT_STREQ(buf, title);

    /* XXX: test more message types */

    DestroyWindow(hwnd);
}

TEST(NtUserTests, GetObjectInformation) {
    /* Test i#1553: NtUserGetObjectInformation parameter #4 */
    TCHAR buf[MAX_PATH];
    HDESK desk = GetThreadDesktop(GetCurrentThreadId());
    ASSERT_NE(desk, (HDESK)NULL);
    DWORD needed;
    BOOL res = GetUserObjectInformation(desk, UOI_NAME, buf,
                                        BUFFER_SIZE_BYTES(buf), &needed);
    ASSERT_EQ(res, TRUE);
}

TEST(NtUserTests, ScrollDC) {
    /* Test i#1555: NtUserScrollDC parameter #6 */
    HDC hdc = CreateDC("DISPLAY", NULL, NULL, NULL);
    ASSERT_NE(hdc, (HDC)NULL);
    RECT rect = { 0, 1, 2, 3 };
    RECT bound;
    BOOL res = ScrollDC(hdc, 3, -4, NULL, &rect, NULL, &bound);
    ASSERT_EQ(res, TRUE);
    DeleteDC(hdc);
}

TEST(NtUserTests, BuildPropList) {
    /* i#1816: test NtUserBuildPropList */
    static const char *myclass = "BuildPropList";
    WNDCLASS wc = {0,};
    wc.lpfnWndProc = DefWindowProc;
    wc.lpszClassName = myclass;
    RegisterClass(&wc);
    HWND window = CreateWindow(myclass, "Test Window", WS_OVERLAPPEDWINDOW,
                               CW_USEDEFAULT, CW_USEDEFAULT, CW_USEDEFAULT, CW_USEDEFAULT,
                               (HWND)NULL, (HMENU)NULL, (HINSTANCE)NULL, NULL);
    HRESULT hr;
    IPropertyStore *pps;
    hr = SHGetPropertyStoreForWindow(window, IID_PPV_ARGS(&pps));
    EXPECT_TRUE(SUCCEEDED(hr));
    /* Add a 2nd property to better test the syscall: */
    PROPVARIANT prop;
    hr = InitPropVariantFromString(L"Example property", &prop);
    EXPECT_TRUE(SUCCEEDED(hr));
    hr = pps->SetValue(PKEY_Search_HitCount, prop);
    EXPECT_TRUE(SUCCEEDED(hr));
    pps->Commit();
    DWORD num;
    /* This is the call that ends up invoking NtUserBuildPropList: */
    hr = pps->GetCount(&num);
    EXPECT_TRUE(SUCCEEDED(hr));
    if (num > 0) {
        PROPERTYKEY pkey;
        pps->GetAt(0, &pkey);
    }
    PropVariantClear(&prop);
    pps->Release();
}

TEST(NtUserTests, GetKeyNameTextW) {
    /* i#1819: ensure null char is marked init */
    WCHAR buf[MAX_PATH];
    int ret = GetKeyNameTextW(35454976/*CTRL*/, buf, MAX_PATH);
    EXPECT_NE(ret, 0);
    EXPECT_EQ(buf[ret], '\0');
}
