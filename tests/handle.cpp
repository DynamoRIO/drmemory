/* **********************************************************
 * Copyright (c) 2012 Google, Inc.  All rights reserved.
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
    if (close) {
        DeleteObject(mybmB);
        DeleteObject(mybmA);
        DeleteObject(mypen);
        DeleteDC(dupdc);
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
    if (GetLastError() != ERROR_NO_MORE_FILES) {
        printf("fail to find the next file\n");
        return;
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
        return;
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

int
main()
{
    printf("test gdi handles\n");
    test_gdi_handles(true);   // create and close
    test_gdi_handles(false);  // create but not close, error raised
    printf("test file handles\n");
    test_file_handles(true);
    test_file_handles(false);
    printf("test thread handles\n");
    test_thread_handles(true);
    test_thread_handles(false);
    printf("test window handles\n");
    test_window_handles(true);
    test_window_handles(false);
    printf("test process handles\n");
    test_process_handles(true);
    test_process_handles(false);
    return 0;
}
