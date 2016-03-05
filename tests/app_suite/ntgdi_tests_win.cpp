/* **********************************************************
 * Copyright (c) 2011-2016 Google, Inc.  All rights reserved.
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

#define NOMINMAX
#include <windows.h>

#include <richedit.h>
#include <textserv.h>

#include "gtest/gtest.h"

#pragma comment(lib, "gdi32.lib")
#pragma comment(lib, "user32.lib")

TEST(NtGdiTests, GetTextMetricsW) {
    // Was: http://https://github.com/DynamoRIO/drmemory/issues/395
    HDC screen_dc = GetDC(NULL);
    TEXTMETRICW font_metrics;
    SetMapMode(screen_dc, MM_TEXT);
    GetTextMetricsW(screen_dc, &font_metrics);
    EXPECT_GT(font_metrics.tmHeight, 0);
    EXPECT_GT(font_metrics.tmAscent, 0);
}

TEST(NtGdiTests, CreateTextServices) {
    // Was: http://https://github.com/DynamoRIO/drmemory/issues/455
    /* i#1152: VS2012 doesn't have riched20.lib so we have to do this dynamically */
    HMODULE lib = LoadLibrary("riched20.dll");
    EXPECT_NE(lib, (HMODULE)NULL);
    typedef HRESULT (*create_text_services_t)(IUnknown *, ITextHost *, IUnknown **);
    create_text_services_t func = (create_text_services_t)
        GetProcAddress(lib, "CreateTextServices");
    EXPECT_NE(func, (create_text_services_t)NULL);
    (*func)(NULL, NULL, NULL);  // it fails but it's OK
}

TEST(NtGdiTests, DeviceContext) {
    HDC mydc = GetDC(NULL);
    HGDIOBJ prior = SelectObject(mydc, GetStockObject(WHITE_BRUSH));
    EXPECT_NE((HGDIOBJ)NULL, prior);
    prior = SelectObject(mydc, prior);
    EXPECT_NE((HGDIOBJ)NULL, prior);

    HDC dupdc = CreateCompatibleDC(mydc);
    HBRUSH brush = CreateSolidBrush(RGB(200,200,200));
    HPEN pen = CreatePen(PS_SOLID,  0xab,RGB(0xab,0xcd,0xef));
    prior = SelectObject(dupdc, brush);
    EXPECT_NE((HGDIOBJ)NULL, prior);
    prior = SelectObject(dupdc, prior);
    EXPECT_NE((HGDIOBJ)NULL, prior);
    prior = SelectObject(dupdc, pen);
    EXPECT_NE((HGDIOBJ)NULL, prior);
    prior = SelectObject(dupdc, prior);
    EXPECT_NE((HGDIOBJ)NULL, prior);

    BOOL ok = DeleteObject(brush);
    EXPECT_EQ(TRUE, ok);
    ok = DeleteObject(pen);
    EXPECT_EQ(TRUE, ok);
    ok = DeleteDC(dupdc);
    EXPECT_EQ(TRUE, ok);
    int res = ReleaseDC(NULL, mydc);
    EXPECT_EQ(1, res);
}

TEST(NtGdiTests, CreatePolygonRgn) {
    /* Test i#809 */

    /* Allocate a 0-sized array, which raised a false pos in i#809 */
    POINT *points = new POINT[0];
    HRGN hrgn = CreatePolygonRgn(points, 0, ALTERNATE);
    EXPECT_EQ((HRGN)NULL, hrgn);
    delete [] points;

    points = new POINT[3];
    memset(points, 0, 3*sizeof(POINT));
    hrgn = CreatePolygonRgn(points, 3, ALTERNATE);
    EXPECT_NE((HRGN)NULL, hrgn);
    DeleteObject(hrgn);
    delete [] points;
}

TEST(NtGdiTests, FontResource) {
    /* i#1825: test NtGdiAddFontResourceW */
    /* XXX: we assume arial.ttf exists */
    int ret = AddFontResourceExW(L"C:\\Windows\\Fonts\\arial.ttf", FR_PRIVATE, NULL);
    EXPECT_EQ(ret, 1);
}
