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

int
main()
{
    test_gdi_handles(true);   // create and close
    test_gdi_handles(false);  // create but not close, error raised

    return 0;
}
