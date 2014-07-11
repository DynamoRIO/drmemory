/* **********************************************************
 * Copyright (c) 2012-2014 Google, Inc.  All rights reserved.
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

/* Tests Windows Handle Leaks */

#ifndef WINDOWS
# error Windows-only
#endif

#include <windows.h>
#include <assert.h>
#include <stdio.h>
#include <process.h> /* for _beginthreadex */
#include <tchar.h>   /* for tchar */
#include <strsafe.h> /* for Str* */
#include <tlhelp32.h>

static void
test_gdi_handles(bool close)
{
    HDC mydc = GetDC(NULL);
    assert(mydc != NULL);
    HDC dupdc = CreateCompatibleDC(mydc);
    assert(dupdc != NULL);
    HPEN mypen = CreatePen(PS_SOLID,  0xab,RGB(0xab,0xcd,0xef));
    assert(mypen != NULL);
    HBITMAP mybmA = CreateBitmap(30, 30, 1, 16, NULL);
    assert(mybmA != NULL);
    HBITMAP mybmB = CreateCompatibleBitmap(dupdc, 30, 30);
    assert(mybmB != NULL);
    HDC emf_dc = CreateEnhMetaFile(mydc, NULL, NULL, NULL);
    assert(emf_dc != NULL);
    HENHMETAFILE hemf = CloseEnhMetaFile(emf_dc);
    assert(hemf != NULL);
    if (close) {
        DeleteObject(mybmB);
        DeleteObject(mybmA);
        DeleteObject(mypen);
        DeleteDC(dupdc);
        DeleteEnhMetaFile(hemf);
        ReleaseDC(NULL, mydc);
    }
}

static unsigned int WINAPI
thread_func(void *arg)
{
    int i;
    HANDLE hEvent;
    for (i = 0; i < 10; i++) {
        hEvent = CreateEvent(NULL, FALSE, FALSE, NULL);
        if (hEvent == NULL) {
            printf("fail to create event\n");
            return 0;
        }
        CloseHandle(hEvent);
    }
    return 0;
}

static void
test_thread_handles(bool close)
{
    unsigned int tid;
    HANDLE thread;
    thread = (HANDLE) _beginthreadex(NULL, 0, thread_func, NULL, 0, &tid);
    thread_func(NULL);
    WaitForSingleObject(thread, INFINITE);
    if (close)
        CloseHandle(thread);
}

static void
test_file_handles(bool close)
{
    // the files' handles
    HANDLE hFile, dupFile1, dupFile2;
    HANDLE hFind;
    // filenames, the file is not there...
    TCHAR buf[MAX_PATH];
    DWORD size;
    WIN32_FIND_DATA ffd;
    bool  create_file_tested = false;

    size = GetCurrentDirectory(MAX_PATH, buf);
    // check size
    if (size == 0) {
        printf("fail to get current directory\n");
        return;
    }
    // append
    StringCchCat(buf, MAX_PATH, TEXT("\\*"));
    // find the first file in the directory.
    hFind = FindFirstFile(buf, &ffd);
    if (hFind == INVALID_HANDLE_VALUE) {
        printf("fail to find the first file\n");
        return;
    }
    // find all the files in the directory
    do {
        bool test_done = false;
        if (!create_file_tested &&
            !(ffd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) {
            hFile = CreateFile(ffd.cFileName, 0, 0, NULL, OPEN_EXISTING,
                               FILE_ATTRIBUTE_NORMAL, NULL);
            create_file_tested = true;
            if (hFile == INVALID_HANDLE_VALUE) {
                printf("fail to open the file %s\n", ffd.cFileName);
                return;
            }
            // test DuplicateHandle
            DuplicateHandle(GetCurrentProcess(),
                            hFile,
                            GetCurrentProcess(),
                            &dupFile1,
                            0,
                            FALSE,
                            DUPLICATE_SAME_ACCESS);
            if (dupFile1 == INVALID_HANDLE_VALUE) {
                printf("fail to duplicate the file handle\n");
                return;
            }
            // close the handle using DuplicateHandle
            DuplicateHandle(GetCurrentProcess(),
                            dupFile1,
                            GetCurrentProcess(),
                            &dupFile2, // NULL would cause another leak
                            0,
                            FALSE,
                            DUPLICATE_CLOSE_SOURCE);
            if (dupFile2 == INVALID_HANDLE_VALUE) {
                printf("fail to duplicate the file handle\n");
                return;
            }
            CloseHandle(dupFile2);
            if (close) {
                // test handle leak on syscall
                DuplicateHandle(GetCurrentProcess(),
                                hFile,
                                GetCurrentProcess(),
                                NULL, // handle leak
                                0,
                                FALSE,
                                DUPLICATE_SAME_ACCESS);
                CloseHandle(hFile);
            }
            test_done = true;
        }
        if (test_done)
            break;
    } while (FindNextFile(hFind, &ffd) != 0);
    if (GetLastError() == ERROR_NO_MORE_FILES) {
        printf("failed to find the next file\n");
    }
    if (close)
        FindClose(hFind);
}

void
test_window_handles(bool close)
{
    HWND hWnd;
    hWnd = CreateWindowEx(0L,                           // ExStyle
                          "Button",                     // class name
                          "Main Window",                // window name
                          WS_OVERLAPPEDWINDOW,          // style
                          CW_USEDEFAULT, CW_USEDEFAULT, // pos
                          CW_USEDEFAULT, CW_USEDEFAULT, // size
                          (HWND) NULL,                  // no parent
                          (HMENU) NULL,                 // calls menu
                          (HINSTANCE) NULL,
                          NULL);
    if (!hWnd) {
        printf("fail to create window\n");
    }
    if (close) {
        DestroyWindow(hWnd);
    }
}

void
test_process_handles(bool close)
{
    HANDLE hSnapshot, hProcess;
    PROCESSENTRY32 pe;
    BOOL res;
    hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPALL, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) {
        printf("CreateToolhelp32Snapshot failed\n");
        return;
    }
    pe.dwSize = sizeof(pe);
    for (res = Process32First(hSnapshot, &pe);
         res;
         res = Process32Next(hSnapshot, &pe)) {
        hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pe.th32ProcessID);
        if (hProcess == INVALID_HANDLE_VALUE) {
            printf("OpenProcess failed\n");
            return;
        }
#ifdef VERBOSE
        printf("Process %6u: %s\n", pe.th32ProcessID, pe.szExeFile);
#endif
        if (hProcess != 0 && pe.th32ProcessID != 0) /* skip system process */
            break;
    }

    if (close) {
        CloseHandle(hProcess);
        CloseHandle(hSnapshot);
    }
}

void
test_desktop_handles(bool close)
{
    HWINSTA hWinSta1, hWinSta2, hWinSta3;
    HDESK hDesk1, hDesk2, hDesk3, hDesk4;
    SECURITY_ATTRIBUTES attr1 = {0}, attr2 = {0};
    TCHAR buf[MAX_PATH];

    hWinSta1 = CreateWindowStationW(NULL, 0, WINSTA_ALL_ACCESS, &attr1);
    if (hWinSta1 == NULL) {
        DWORD res = GetLastError();
        printf("CreateWindowStationW failed, %d\n", res);
        return;
    }
    hWinSta2 = OpenWindowStation(_T("winsta0"), FALSE, READ_CONTROL | WRITE_DAC);
    if (hWinSta2 == NULL) {
        DWORD res = GetLastError();
        printf("OpenWindowStation failed, %d\n", res);
        return;
    }
    hWinSta3 = GetProcessWindowStation();  /* return existing handle */
    if (hWinSta3 == NULL) {
        DWORD res = GetLastError();
        printf("GetProcessWindowStation failed, %d\n", res);
        return;
    }
    hDesk1 = CreateDesktop(_T("Desk1"), 0, 0, 0, GENERIC_ALL , &attr2);
    if (hDesk1 == NULL) {
        DWORD res = GetLastError();
        printf("CreateDesktop failed, %d\n", res);
        return;
    }
    hDesk2 = OpenInputDesktop(0, FALSE, READ_CONTROL);
    if (hDesk2 == NULL) {
        DWORD res = GetLastError();
        printf("OpenInputDesktop failed, %d\n", res);
        return;
    }
    hDesk3 = GetThreadDesktop(GetCurrentThreadId()); /* return existing handle */
    if (hDesk3 == NULL) {
        DWORD res = GetLastError();
        printf("GetThreadDesktop failed, %d\n", res);
        return;
    }
    if (!GetUserObjectInformation(hDesk3, 2, buf, MAX_PATH, NULL)) {
        DWORD res = GetLastError();
        printf("GetUserObjectInformation failed, %d\n", res);
    }
    hDesk4 = OpenDesktop(buf, 0, FALSE, READ_CONTROL | WRITE_DAC);
    if (hDesk4 == NULL) {
        DWORD res = GetLastError();
        printf("OpenDesktop failed, %d\n", res);
        return;
    }
    if (close) {
        CloseDesktop(hDesk1);
        CloseDesktop(hDesk2);
        CloseDesktop(hDesk4);
        CloseWindowStation(hWinSta1);
        CloseWindowStation(hWinSta2);
    }
}

int
main()
{
#   define ITERS 4
    int i;
    /* To test -filter_handle_leaks, we must call those test routines with
     * and without closing handles at the same place with the same callstack.
     */
    printf("test gdi handles\n");
    for (i = 0; i < ITERS/* make sure there is more than one leak */; i++)
        test_gdi_handles((i == 0)/* close handle? */);
    printf("test file handles\n");
    for (i = 0; i < ITERS; i++)
        test_file_handles((i == 0)/* close handle? */);
    printf("test thread handles\n");
    for (i = 0; i < ITERS; i++)
        test_thread_handles((i == 0)/* close handle? */);
    printf("test window handles\n");
    for (i = 0; i < ITERS; i++)
        test_window_handles((i == 0)/* close handle? */);
    printf("test process handles\n");
    for (i = 0; i < ITERS; i++)
        test_process_handles((i == 0)/* close handle? */);
    printf("test desktop handles\n");
    for (i = 0; i < ITERS; i++)
        test_desktop_handles((i == 0)/* close handle? */);
    return 0;
}
