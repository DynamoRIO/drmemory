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

/* Tests GDI checks from i#752 */

#ifndef WINDOWS
# error Windows-only
#endif

#include <windows.h>
#include <process.h> /* for _beginthreadex */
#include <assert.h>

#pragma comment(lib, "gdi32.lib")
#pragma comment(lib, "user32.lib")

static void
test_DC_free(void)
{
    // Test DrMem check for: proper pairing GetDC|ReleaseDC and CreateDC|DeleteDC
    HDC mydc = GetDC(NULL);
    assert(mydc != NULL);
    // Not checking all the {Select,Delete,Release}* calls since some are
    // deliberately erroneous and meant to fail.  Note that on some platforms
    // at least the GDI impl is robust and handles some of these errors DrMem
    // is detecting.
    DeleteDC(mydc); // error raised

    mydc = GetDC(NULL);
    assert(mydc != NULL);
    HDC dupdc = CreateCompatibleDC(mydc);
    assert(dupdc != NULL);
    ReleaseDC(NULL, dupdc); // error raised
}

static unsigned int WINAPI
thread_dup_DC(void *arg)
{
    HDC *dc_out = (HDC *) arg;
    // ok for *dc_out to be NULL
    HDC dupdc = CreateCompatibleDC(*dc_out);
    assert(dupdc != NULL);
    *dc_out = dupdc;
    return 0;
}

static unsigned int WINAPI
thread_select(void *arg)
{
    HDC mydc = (HDC) arg;
    assert(mydc != NULL);
    HBITMAP mybm = CreateBitmap(30, 30, 1, 16, NULL);
    assert(mybm != NULL);
    HGDIOBJ orig = SelectObject(mydc, mybm); // error raised
    SelectObject(mydc, orig);
    DeleteObject(mybm);
    return 0;
}

static unsigned int WINAPI
thread_release(void *arg)
{
    HDC dc = (HDC) arg;
    assert(dc != NULL);
    ReleaseDC(NULL, dc); // error raised
    return 0;
}

static void
test_DC_threads(void)
{
    unsigned int tid;
    HANDLE thread;
    HDC mydc = GetDC(NULL);
    assert(mydc != NULL);

    // Test DrMem check for: CreateCompatibleDC is not used after creating thread exits
    HDC dupdc = NULL; // MSDN says this is bad only for dup of NULL
    thread = (HANDLE) _beginthreadex(NULL, 0, thread_dup_DC, (void*)&dupdc, 0, &tid);
    WaitForSingleObject(thread, INFINITE);
    HBITMAP mybm = CreateCompatibleBitmap(dupdc, 30, 30);
    assert(mybm != NULL);
    HGDIOBJ orig = SelectObject(dupdc, mybm); // error raised
    assert(orig != NULL);
    SelectObject(dupdc, orig); // error raised
    DeleteDC(dupdc);
    DeleteObject(mybm);
    // Ensure no error when duplicated from other than NULL
    dupdc = mydc;
    thread = (HANDLE) _beginthreadex(NULL, 0, thread_dup_DC, (void*)&dupdc, 0, &tid);
    WaitForSingleObject(thread, INFINITE);
    mybm = CreateCompatibleBitmap(dupdc, 30, 30);
    assert(mybm != NULL);
    orig = SelectObject(dupdc, mybm);
    assert(orig != NULL);
    SelectObject(dupdc, orig); // Should have no error raised!
    DeleteDC(dupdc);
    DeleteObject(mybm);

    // Test DrMem check for: do not operate on a single DC from two different threads
    // we need a memory DC to select a bitmap into
    dupdc = CreateCompatibleDC(mydc);
    assert(dupdc != NULL);
    mybm = CreateCompatibleBitmap(dupdc, 16, 16);
    assert(mybm != NULL);
    orig = SelectObject(dupdc, mybm);
    assert(orig != NULL);
    SelectObject(dupdc, orig);
    thread = (HANDLE) _beginthreadex(NULL, 0, thread_select, (void*)dupdc, 0, &tid);
    WaitForSingleObject(thread, INFINITE);
    CloseHandle(thread);
    DeleteObject(mybm);
    DeleteDC(dupdc);

    // Test DrMem check for: ReleaseDC called from the same thread that called GetDC
    thread = (HANDLE) _beginthreadex(NULL, 0, thread_release, (void*)mydc, 0, &tid);
    WaitForSingleObject(thread, INFINITE);
    CloseHandle(thread);
}

static void
test_DC_objdel(void)
{
    // Test DrMem check for: do not delete HGDIOBJ that is selected in any DC
    HPEN mypen = CreatePen(PS_SOLID,  0xab,RGB(0xab,0xcd,0xef));
    assert(mypen != NULL);
    HDC mydc = GetDC(NULL);
    assert(mydc != NULL);
    HGDIOBJ orig = SelectObject(mydc, mypen);
    DeleteObject(mypen); // error raised
    SelectObject(mydc, orig);

    // we need a memory DC to select a bitmap into
    HDC dupdc = CreateCompatibleDC(mydc);
    assert(dupdc != NULL);
    HBITMAP mybm = CreateCompatibleBitmap(dupdc, 30, 30);
    assert(mybm != NULL);
    orig = SelectObject(dupdc, mybm);
    assert(orig != NULL);
    DeleteObject(mybm); // no error raised since not a drawing object (i#899)
    SelectObject(dupdc, orig);
    DeleteDC(dupdc);
    ReleaseDC(NULL, mydc);
}

static void
test_DC_bitmap(void)
{
    // Test DrMem check for: do not select the same bitmap into two different DC's
    HDC mydc = GetDC(NULL);
    assert(mydc != NULL);
    // we need a memory DC to select a bitmap into
    HDC dupdcA = CreateCompatibleDC(mydc);
    assert(dupdcA != NULL);
    HDC dupdcB = CreateCompatibleDC(mydc);
    assert(dupdcB != NULL);
    HBITMAP mybm = CreateCompatibleBitmap(dupdcA, 30, 30);
    assert(mybm != NULL);
    HGDIOBJ orig = SelectObject(dupdcA, mybm);
    assert(orig != NULL);
    orig = SelectObject(dupdcB, mybm); // error raised
    // not asserting b/c orig is NULL on win7
    DeleteDC(dupdcA); // error raised
    DeleteDC(dupdcB);
    ReleaseDC(NULL, mydc);
}

static void
test_DC_select(void)
{
    // Test DrMem check for: non-default objects selected in a DC being deleted
    // (N.B. (i#764): need to intercept library routine to see pen selection)
    HPEN mypen = CreatePen(PS_SOLID,  0xab,RGB(0xab,0xcd,0xef));
    assert(mypen != NULL);
    HDC mydc = GetDC(NULL);
    assert(mydc != NULL);
    HDC dupdc = CreateCompatibleDC(mydc);
    assert(dupdc != NULL);
    SelectObject(dupdc, mypen);
    DeleteDC(dupdc); // error raised
    DeleteObject(mypen); // error raised
    ReleaseDC(NULL, mydc);
}

static void
test_suppress(void)
{
    // duplicate of test_objdel but suppressed
    HPEN mypen = CreatePen(PS_SOLID,  0xab,RGB(0xab,0xcd,0xef));
    assert(mypen != NULL);
    HDC mydc = GetDC(NULL);
    assert(mydc != NULL);
    HGDIOBJ orig = SelectObject(mydc, mypen);
    DeleteObject(mypen); // error raised
    SelectObject(mydc, orig);
}

int CALLBACK
EnumFontFamExProc(const LOGFONT *lpelfe,
                  const TEXTMETRIC *lpntme,
                  DWORD FontType,
                  LPARAM lParam)
{
    return 0; /* stop enumeration */
}

static void
test_EnumFont()
{
    HDC mydc = GetDC(NULL);
    LOGFONT logfont;
    /* test i#502 */
    logfont.lfCharSet = DEFAULT_CHARSET;
    logfont.lfFaceName[0] = '\0';
    logfont.lfPitchAndFamily = 0;
    EnumFontFamiliesEx(mydc, &logfont, EnumFontFamExProc, NULL, 0);
    ReleaseDC(NULL, mydc);
}

int
main()
{
    test_DC_free();

    test_DC_threads();

    test_DC_objdel();

    test_DC_bitmap();

    test_DC_select();

    test_suppress();

    test_EnumFont();

    return 0;
}
