/* **********************************************************
 * Copyright (c) 2011-2015 Google, Inc.  All rights reserved.
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
#include "app_suite_utils.h"
#include <locale.h>

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

TEST(StringTests, strncpy) {
    char buf[64];
    size_t i;
    const char *src = "source";
    char *dst = strncpy(buf, src, BUFFER_SIZE_ELEMENTS(buf));
    ASSERT_EQ(dst, buf);
    ASSERT_STREQ(dst, "source");
    for (i = strlen(buf); i < BUFFER_SIZE_ELEMENTS(buf); i++)
        ASSERT_EQ(buf[i], '\0');
}

TEST(StringTests, wcscpy) {
    wchar_t buf[64];
    const wchar_t *src = L"source";
    wchar_t *dst = wcscpy(buf, src);
    ASSERT_EQ(dst, buf);
    ASSERT_STREQ(dst, L"source");
}

TEST(StringTests, strstr) {
    ASSERT_STREQ(strstr("abcaddccdx", "cd"), "cdx");
    ASSERT_STREQ(strstr("xyzabcxyz", "xyz"), "xyzabcxyz");
    ASSERT_EQ(strstr("xy", "xyz"), (char *)NULL);
    ASSERT_STREQ(strstr("abcd", ""), "abcd");
    /* Test i#1718 */
    ASSERT_STREQ(strstr("xxxA", "xxA"), "xxA");
    ASSERT_STREQ(strstr("PREFIXxxxxxASUFFIX", "xxxxA"), "xxxxASUFFIX");
    ASSERT_EQ(strstr("xxxAxABxxxA", "xxAB"), (char *)NULL);
    ASSERT_EQ(strstr("xxx", "a"), (char *)NULL);

    /* Test i#1243 where msvcr100!strstr calls into the middle of strchr
     * and has an unaddr if the string doesn't fill out a malloc chunk
     */
    char *p = new char[3];
    strcpy(p, "xy");
    ASSERT_STREQ(strstr(p, "y"), "y");
    delete [] p;
}

TEST(StringTests, wcsstr) {
    ASSERT_STREQ(wcsstr(L"abcaddccdx", L"cd"), L"cdx");
    ASSERT_STREQ(wcsstr(L"xyzabcxyz", L"xyz"), L"xyzabcxyz");
    ASSERT_EQ(wcsstr(L"xy", L"xyz"), (wchar_t *)NULL);
    ASSERT_STREQ(wcsstr(L"abcd", L""), L"abcd");
    /* Test i#1718 */
    ASSERT_STREQ(wcsstr(L"xxxA", L"xxA"), L"xxA");
    ASSERT_STREQ(wcsstr(L"PREFIXxxxxxASUFFIX", L"xxxxA"), L"xxxxASUFFIX");
    ASSERT_EQ(wcsstr(L"xxxAxABxxxA", L"xxAB"), (wchar_t *)NULL);
    ASSERT_STREQ(wcsstr(L"xxx", L"a"), (wchar_t *)NULL);

    /* Test i#350 where VS2012 wcsstr is optimized */
    std::wstring s2(L"foo\r\nbar");
    ASSERT_STREQ(wcsstr(s2.c_str(), L"\r\n"), L"\r\nbar");
}

#ifdef UNIX
TEST(StringTests, strcasecmp) {
    char *s = new char[3];
    s[0] = 'a';
    s[1] = 'B';
    s[2] = '\0';
    int res = strcasecmp(s, "Ab");
    ASSERT_EQ(res, 0);
    res = strcasecmp(s, "ab");
    ASSERT_EQ(res, 0);
    res = strcasecmp(s, "abc");
    ASSERT_LT(res, 0);
    delete [] s;

    // Test locale-specific tolower()
    char *prior_locale = setlocale(LC_ALL, NULL);
    // Not all machines have targeted langs like "deutsch" so going for
    // iso88591* but even that is not always installed so perhaps we
    // should skip the test?  But we want to know if the test is working.
    char *locale = setlocale(LC_ALL, "en_US.iso88591");
    if (locale != NULL) {
        ASSERT_STREQ(locale, "en_US.iso88591");
    } else {
        locale = setlocale(LC_ALL, "en_US.iso885915");
        if (locale != NULL) {
            ASSERT_STREQ(locale, "en_US.iso885915");
        } else {
            printf("Expected locales not found...aborting.\n");
        }
    }

    if (locale != NULL) {
        ASSERT_EQ(tolower('\xd6'), tolower('\xf6'));

# ifdef TOOL_DR_MEMORY
        // XXX: this fails natively!  Presumably b/c the ifunc for the optimized
        // strcasecmp hardcodes the locale set at startup.
        res = strcasecmp("\xd6", "\xf6"); // 0xd6==0n214=Ö, 0xf6=0n246=ö
        ASSERT_EQ(res, 0);
# endif
    }
    locale = setlocale(LC_ALL, prior_locale);
    ASSERT_STREQ(locale, prior_locale);
}

TEST(StringTests, strncasecmp) {
    char *s = new char[3];
    s[0] = 'a';
    s[1] = 'B';
    s[2] = '\0';
    int res = strncasecmp(s, "Abcde", 1);
    ASSERT_EQ(res, 0);
    res = strncasecmp(s, "ab", 5);
    ASSERT_EQ(res, 0);
    res = strncasecmp(s, "abc", 3);
    ASSERT_LT(res, 0);
    delete [] s;
}

TEST(StringTests, stpcpy) {
    char buf[64];
    char *cur = buf;
    cur = stpcpy(cur, "first");
    cur = stpcpy(cur, "second");
    cur = stpcpy(cur, "third");
    ASSERT_STREQ(buf, "firstsecondthird");
}

TEST(StringTests, strspn) {
    ASSERT_EQ(1UL, strspn("abc", "a"));
    ASSERT_EQ(2UL, strspn("a;b;c", "a;"));
    ASSERT_EQ(5UL, strspn("a;b;c", "a; bcd:"));
    ASSERT_EQ(0UL, strspn("a; b;c", " "));
    ASSERT_EQ(7UL, strspn("a; b;cd:", "a; b;cd"));
    ASSERT_EQ(0UL, strspn("a; b;cd:", ""));
}

TEST(StringTests, strcspn) {
    ASSERT_EQ(0UL, strcspn("abc", "a"));
    ASSERT_EQ(1UL, strcspn("a;b;c", ";"));
    ASSERT_EQ(1UL, strcspn("a;b;c", "; bcd:"));
    ASSERT_EQ(2UL, strcspn("a; b;c", " "));
    ASSERT_EQ(7UL, strcspn("a; b;cd:", ":"));
    ASSERT_EQ(8UL, strcspn("a; b;cd:", ""));
}

TEST(StringTests, strnlen) {
    const char *str = "string";
    /* i#1368: type cast to avoid compilation error on some old gcc,
     * but somehow strcspn/strspn above do not need the cast.
     */
    ASSERT_EQ((unsigned long)strlen(str), (unsigned long)strnlen(str, 7));
    ASSERT_EQ((unsigned long)strlen(str), (unsigned long)strnlen(str, 6));
    ASSERT_EQ(5UL, (unsigned long)strnlen(str, 5));
    ASSERT_EQ(0UL, (unsigned long)strnlen(str, 0));
}

#endif /* UNIX */
