/* **********************************************************
 * Copyright (c) 2011-2012 Google, Inc.  All rights reserved.
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

#include "gtest/gtest.h"

TEST(StringTests, Memmove) {
    const char input[128] = "0123456789abcdefg";  // strlen(input) = 17.
    char tmp[128];

    // Trivial: aligned copy, no overlapping.
    EXPECT_EQ(tmp, memmove(tmp, input, strlen(input) + 1));
    ASSERT_STREQ(input, tmp);

    strcpy(tmp, input);
    // Overlapping copy forwards, should skip 1 byte before going to fastpath.
    EXPECT_EQ(tmp+7, memmove(tmp+7, tmp+3, strlen(tmp) + 1 - 3));
    EXPECT_STREQ("01234563456789abcdefg", tmp);

    strcpy(tmp, input);
    // Overlapping copy forwards, different alignment.
    EXPECT_EQ(tmp+6, memmove(tmp+6, tmp+3, strlen(tmp) + 1 - 3));
    EXPECT_STREQ("0123453456789abcdefg", tmp);

    strcpy(tmp, input);
    // Overlapping copy backwards, should skip 3 bytes before going to fastpath.
    EXPECT_EQ(tmp+3, memmove(tmp+3, tmp+7, strlen(tmp) + 1 - 7));
    EXPECT_STREQ("012789abcdefg", tmp);

    strcpy(tmp, input);
    // Overlapping copy backwards, different alignment.
    EXPECT_EQ(tmp+3, memmove(tmp+3, tmp+6, strlen(tmp) + 1 - 6));
    EXPECT_STREQ("0126789abcdefg", tmp);
}

TEST(StringTests, wcschr) {
    // Try to stress sub-malloc-chunk alloc
    wchar_t *w = new wchar_t[3];
    w[0] = L'a';
    w[1] = L'b';
    w[2] = L'\0';
    wchar_t *found = wcschr(w, L'b');
    ASSERT_TRUE(found == w + 1);
    found = wcschr(w, L'\0');
    ASSERT_TRUE(found == w + 2);
    found = wcschr(w, L'x');
    ASSERT_TRUE(found == NULL);
    delete [] w;
}

TEST(StringTests, wcsrchr) {
    // Try to stress sub-malloc-chunk alloc
    wchar_t *w = new wchar_t[3];
    w[0] = L'a';
    w[1] = L'b';
    w[2] = L'\0';
    wchar_t *found = wcsrchr(w, L'b');
    ASSERT_TRUE(found == w + 1);
    found = wcsrchr(w, L'\0');
    ASSERT_TRUE(found == w + 2);
    found = wcsrchr(w, L'x');
    ASSERT_TRUE(found == NULL);
    delete [] w;
}
