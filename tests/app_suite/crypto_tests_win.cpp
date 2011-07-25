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

#define NOMINMAX
#include <windows.h>

#include <richedit.h>
#include <textserv.h>

#include "gtest/gtest.h"

#pragma comment(lib, "gdi32.lib")
#pragma comment(lib, "riched20.lib")
#pragma comment(lib, "user32.lib")

TEST(NtGdiTests, GetTextMetricsW) {
    // Was: http://code.google.com/p/drmemory/issues/detail?id=395
    HDC screen_dc = GetDC(NULL);
    TEXTMETRICW font_metrics;
    SetMapMode(screen_dc, MM_TEXT);
    GetTextMetricsW(screen_dc, &font_metrics);
    EXPECT_GT(font_metrics.tmHeight, 0);
    EXPECT_GT(font_metrics.tmAscent, 0);
}

TEST(NtGdiTests, CreateTextServices) {
    // Was: http://code.google.com/p/drmemory/issues/detail?id=455
    CreateTextServices(NULL, NULL, NULL);  // it fails but it's OK
}
