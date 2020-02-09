/* **********************************************************
 * Copyright (c) 2010-2020 Google, Inc.  All rights reserved.
 * Copyright (c) 2008-2010 VMware, Inc.  All rights reserved.
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

/***************************************************************************
 * replace.c: replacement routines for str* and mem* libc routines that
 * tend to cause false positives due to their optimizations.
 * Ours may be a little slower, but Dr. Memory's general slowdown
 * far outweighs that, and replacing avoids having to use fragile
 * pattern matches (though we still need those for inlined (or static,
 * until we have symbols) copies of these routines).
 * Xref PR 485412.
 */

#include "dr_api.h"
#include "drwrap.h"
#include "utils.h"
#include "heap.h"
#include "drmemory.h"
#include "shadow.h"
#ifdef USE_DRSYMS
# include "drsymcache.h"
#endif
#include <limits.h>  /* UCHAR_MAX */
#ifdef UNIX
# include <unistd.h> /* size_t */
#endif
#ifdef WINDOWS
# include <rpc.h> /* RPC_STATUS */
#endif
#ifdef USE_DRSYMS
# include "drsyms.h"
#endif

#undef strcasecmp /* undo def from utils.h */

/* On Windows, keep this updated with drmemory.pl which queries these pre-run.
 *
 * When adding, make sure the regexs passed to find_syms_regex() cover
 * the new name!
 *
 * Template: REPLACE_NAME_DEF(app-name, replace_ func name, corresponding-wide-char)
 *
 * The order does matter for routines that are sometimes aliases to one another:
 * the later one takes precedence (thus, memmove is later than memcpy: i#1868).
 */
#define REPLACE_DEF(name, wide) REPLACE_NAME_DEF(name, name, wide)
#define REPLACE_DEFS()             \
    REPLACE_DEF(memset, NULL)      \
    REPLACE_DEF(memcpy, NULL)      \
    REPLACE_DEF(memchr, NULL)      \
    IF_UNIX(REPLACE_DEF(memrchr, NULL)) \
    IF_UNIX(REPLACE_DEF(rawmemchr, NULL)) \
    REPLACE_DEF(strchr, "wcschr")  \
    REPLACE_DEF(strrchr, "wcsrchr")\
    IF_UNIX(REPLACE_DEF(strchrnul, NULL)) \
    REPLACE_DEF(strlen, "wcslen")  \
    REPLACE_DEF(strnlen, "wcsnlen")  \
    REPLACE_DEF(strcmp, "wcscmp")  \
    REPLACE_DEF(strncmp, "wcsncmp")\
    REPLACE_DEF(strcpy, "wcscpy")  \
    REPLACE_DEF(strncpy, NULL)     \
    REPLACE_DEF(strcat, NULL)      \
    REPLACE_DEF(strncat, NULL)     \
    REPLACE_DEF(memmove, NULL)     \
    /* DO NOT ADD ABOVE HERE w/o updating drmemory.pl -libc_addrs */ \
    REPLACE_DEF(memcmp, NULL)      \
    REPLACE_DEF(wmemset, NULL)     \
    REPLACE_DEF(wmemcpy, NULL)     \
    REPLACE_DEF(wmemchr, NULL)     \
    REPLACE_DEF(wcslen, NULL)      \
    REPLACE_DEF(wcsnlen, NULL)     \
    REPLACE_DEF(wcscmp, NULL)      \
    REPLACE_DEF(wcsncmp, NULL)     \
    REPLACE_DEF(wcscpy, NULL)      \
    REPLACE_DEF(wmemcmp, NULL)     \
    REPLACE_DEF(wcschr, NULL)      \
    REPLACE_DEF(wcsrchr, NULL)     \
    REPLACE_DEF(strcasecmp, NULL)  \
    REPLACE_DEF(strncasecmp, NULL) \
    REPLACE_DEF(strspn, NULL)      \
    REPLACE_DEF(strcspn, NULL)     \
    REPLACE_DEF(stpcpy, NULL)      \
    REPLACE_DEF(strstr, "wcsstr")  \
    REPLACE_DEF(wcsstr, NULL)      \
    IF_UNIX(REPLACE_DEF(bzero, NULL)) \
    IF_MACOS(REPLACE_NAME_DEF(_platform_memchr, memchr, NULL)) \
    IF_MACOS(REPLACE_NAME_DEF(_platform_memcmp, memcmp, NULL)) \
    IF_MACOS(REPLACE_NAME_DEF(_platform_memmove, memmove, NULL)) \
    IF_MACOS(REPLACE_NAME_DEF(_platform_memset, memset, NULL)) \
    IF_MACOS(REPLACE_NAME_DEF(_platform_strchr, strchr, NULL)) \
    IF_MACOS(REPLACE_NAME_DEF(_platform_strcmp, strcmp, NULL)) \
    IF_MACOS(REPLACE_NAME_DEF(_platform_strncmp, strncmp, NULL)) \
    IF_MACOS(REPLACE_NAME_DEF(_platform_strlen, strlen, NULL)) \
    IF_MACOS(REPLACE_NAME_DEF(_platform_bzero, bzero, NULL))

/* XXX i#350: add wrappers for wcsncpy, wcscat,
 * wcsncat, wmemmove.
 */

static const char *replace_routine_name[] = {
#define REPLACE_NAME_DEF(nm, func, wide) STRINGIFY(nm),
    REPLACE_DEFS()
#undef REPLACE_NAME_DEF
};
#define REPLACE_NUM (sizeof(replace_routine_name)/sizeof(replace_routine_name[0]))

#ifdef WINDOWS
static const char * const replace_routine_wide_alt[] = {
# define REPLACE_NAME_DEF(nm, func, wide) wide,
    REPLACE_DEFS()
# undef REPLACE_NAME_DEF
};
#endif


static app_pc replace_routine_start;
static size_t replace_routine_size;

static int index_memcpy;
static int index_memmove;

#ifdef USE_DRSYMS
/* for passing data to sym enum callback */
typedef struct _sym_enum_data_t {
    bool add;
    bool processed[REPLACE_NUM];
    app_pc indirect[REPLACE_NUM];
    const module_data_t *mod;
} sym_enum_data_t;

/* for considering wildcard symbols */
#define REPLACE_NAME_TABLE_HASH_BITS 6
static hashtable_t replace_name_table;
#endif

static int
replace_tolower_ascii(int c);

/* for locale-specific tolower() for str{,n}casecmp */
static int (*app_tolower)(int) = replace_tolower_ascii;

/***************************************************************************
 * The replacements themselves.
 * These routines are not static so that under gdb a fault will show
 * up as drmemory!replace_strlen and the user can see it's strlen.
 */

/* To distinguish these routines, we place into a separate page-aligned
 * section.
 * We really only use this separate section for debugging purposes, currently.
 * If we later hide client libraries, we should probably move these
 * to a visible library.
 */
#ifdef MACOS
asm(".section __TEXT,__replace");
asm(".align 12"); /* 2^12 */
# define IN_REPLACE_SECTION __attribute__ ((section ("__TEXT,__replace")))
#elif defined(LINUX)
asm(".section .replace, \"ax\", " IF_X86_ELSE("@progbits","%progbits"));
asm(".align " IF_X86_ELSE("0x1000","12"));
# define IN_REPLACE_SECTION __attribute__ ((section (".replace")))
#else /* WINDOWS */
ACTUAL_PRAGMA( code_seg(".replace") )
# define IN_REPLACE_SECTION /* nothing */
#endif

/* prevent cl from replacing our loop with a call to ntdll!memset,
 * which we replace with this routine, which results an infinite loop!
 */
DO_NOT_OPTIMIZE
IN_REPLACE_SECTION void *
replace_memset(void *dst, int val_in, size_t size)
{
    register unsigned char *ptr = (unsigned char *) dst;
    unsigned char val = (unsigned char) val_in;
    unsigned int val4 = (val << 24) | (val << 16) | (val << 8) | val;
    while (!ALIGNED(ptr, 4) && size > 0) {
        *ptr++ = val;
        size--;
    }
    while (size > 3) {
        *((unsigned int *)ptr) = val4;
        ptr += 4;
        size -= 4;
    }
    while (size > 0) {
        *ptr++ = val;
        size--;
    }
    return dst;
}

IN_REPLACE_SECTION wchar_t *
replace_wmemset(wchar_t *dst, wchar_t val_in, size_t size)
{
    wchar_t *ret = dst;
    while (size-- > 0)
        *dst++ = val_in;
    return ret;
}
END_DO_NOT_OPTIMIZE

DO_NOT_OPTIMIZE

IN_REPLACE_SECTION void
replace_bzero(void *dst, size_t size)
{
    replace_memset(dst, 0, size);
}

IN_REPLACE_SECTION void *
replace_memcpy(void *dst, const void *src, size_t size)
{
    register unsigned char *d = (unsigned char *) dst;
    register unsigned char *s = (unsigned char *) src;
    if (((ptr_uint_t)dst & 3) == ((ptr_uint_t)src & 3)) {
        /* same alignment, so we can do 4 aligned bytes at a time and stay
         * on fastpath.  when not same alignment, I'm assuming it's faster
         * to have all 1-byte moves on fastpath rather than half 4-byte
         * (aligned) on fastpath and half 4-byte (unaligned) on slowpath.
         */
        while (!ALIGNED(d, 4) && size > 0) {
            *d++ = *s++;
            size--;
        }
        while (size > 3) {
            *((unsigned int *)d) = *((unsigned int *)s);
            s += 4;
            d += 4;
            size -= 4;
        }
        while (size > 0) {
            *d++ = *s++;
            size--;
        }
    } else {
        while (size-- > 0) /* loop will terminate before underflow */
            *d++ = *s++;
    }
    return dst;
}

IN_REPLACE_SECTION void *
replace_memmove(void *dst, const void *src, size_t size);

IN_REPLACE_SECTION wchar_t *
replace_wmemcpy(wchar_t *dst, const wchar_t *src, size_t size)
{
#if defined(WINDOWS) && defined(X64)
    /* i#1868: 64-bit Visual Studio labels memmove as "memcpy" so we are
     * forced to handle overlap (though mingw doesn't need it).
     */
    return (wchar_t*)replace_memmove(dst, src, size * sizeof(wchar_t));
#else
    return (wchar_t*)replace_memcpy(dst, src, size * sizeof(wchar_t));
#endif
}

IN_REPLACE_SECTION void *
replace_memchr(const void *mem, int find, size_t size)
{
    register const unsigned char *s = (unsigned char *) mem;
    register unsigned char c = (unsigned char) find;
    while (size-- > 0) { /* loop will terminate before underflow */
        if (*s == c)
            return (void *) s;
        s++;
    }
    return NULL;
}

IN_REPLACE_SECTION wchar_t *
replace_wmemchr(wchar_t *s, wchar_t c, size_t size)
{
    while (size-- > 0) { /* loop will terminate before underflow */
        if (*s == c)
            return s;
        s++;
    }
    return NULL;
}

IN_REPLACE_SECTION void *
replace_memrchr(const void *mem, int find, size_t size)
{
    register const unsigned char *s = ((unsigned char *) mem) + size - 1;
    register unsigned char c = (unsigned char) find;
    while (size-- > 0) { /* loop will terminate before underflow */
        if (*s == c)
            return (void *) s;
        s--;
    }
    return NULL;
}

#ifdef UNIX
IN_REPLACE_SECTION void *
replace_rawmemchr(const void *mem, int find)
{
    register unsigned char *s = (unsigned char *) mem;
    register unsigned char c = (unsigned char) find;
    while (*s != c)
        s++;
    return s;
}
#endif

IN_REPLACE_SECTION char *
replace_strchr(const char *str, int find)
{
    register const char *s = str;
    register char c = (char) find;
    /* be sure to match the terminating 0 instead of failing (i#275) */
    while (true) {
        if (*s == c)
            return (char *) s;
        if (*s == '\0')
            return NULL;
        s++;
    }
    return NULL;
}

IN_REPLACE_SECTION wchar_t *
replace_wcschr(const wchar_t *str, int find)
{
    register const wchar_t *s = str;
    register wchar_t c = (wchar_t) find;
    /* be sure to match the terminating 0 instead of failing (i#275) */
    while (true) {
        if (*s == c)
            return (wchar_t *) s;
        if (*s == L'\0')
            return NULL;
        s++;
    }
    return NULL;
}

IN_REPLACE_SECTION char *
replace_strrchr(const char *str, int find)
{
    register const char *s = str;
    register char c = (char) find;
    const char *last = NULL;
    /* be sure to match the terminating 0 instead of failing (i#275) */
    while (true) {
        if (*s == c)
            last = s;
        if (*s == '\0')
            break;
        s++;
    }
    return (char *) last;
}

IN_REPLACE_SECTION wchar_t *
replace_wcsrchr(const wchar_t *str, int find)
{
    register const wchar_t *s = str;
    register wchar_t c = (wchar_t) find;
    const wchar_t *last = NULL;
    /* be sure to match the terminating 0 instead of failing (i#275) */
    while (true) {
        if (*s == c)
            last = s;
        if (*s == L'\0')
            break;
        s++;
    }
    return (wchar_t *) last;
}

#ifdef UNIX
IN_REPLACE_SECTION char *
replace_strchrnul(const char *str, int find)
{
    register const char *s = str;
    register char c = (char) find;
    while (*s != '\0') {
        if (*s == c)
            return (char *) s;
        s++;
    }
    return (char *) s;
}
#endif

IN_REPLACE_SECTION size_t
replace_strlen(const char *str)
{
    register const char *s = str;
    while (*s != '\0')
        s++;
    return (s - str);
}

IN_REPLACE_SECTION size_t
replace_wcslen(const wchar_t *str)
{
    register const wchar_t *s = str;
    while (*s != L'\0')
        s++;
    return (s - str);
}

IN_REPLACE_SECTION size_t
replace_strnlen(const char *str, size_t max)
{
    register const char *s = str;
    while ((s - str) < max && *s != '\0')
        s++;
    return (s - str);
}

IN_REPLACE_SECTION size_t
replace_wcsnlen(const wchar_t *str, size_t max)
{
    register const wchar_t *s = str;
    while ((s - str) < max && *s != L'\0')
        s++;
    return (s - str);
}

IN_REPLACE_SECTION int
replace_strncmp(const char *str1, const char *str2, size_t size)
{
    register const unsigned char *s1 = (const unsigned char *) str1;
    register const unsigned char *s2 = (const unsigned char *) str2;
    while (size-- > 0) { /* loop will terminate before underflow */
        if (*s1 == '\0') {
            if (*s2 == '\0')
                return 0;
            return -1;
        }
        if (*s2 == '\0')
            return 1;
        if (*s1 < *s2)
            return -1;
        if (*s1 > *s2)
            return 1;
        s1++;
        s2++;
    }
    return 0;
}

IN_REPLACE_SECTION int
replace_wcsncmp(const wchar_t *s1, const wchar_t *s2, size_t size)
{
    while (size-- > 0) { /* loop will terminate before underflow */
        if (*s1 == L'\0') {
            if (*s2 == L'\0')
                return 0;
            return -1;
        }
        if (*s2 == L'\0')
            return 1;
        if ((unsigned int)*s1 < (unsigned int)*s2)
            return -1;
        if ((unsigned int)*s1 > (unsigned int)*s2)
            return 1;
        s1++;
        s2++;
    }
    return 0;
}

IN_REPLACE_SECTION int
replace_strcmp(const char *str1, const char *str2)
{
    register const unsigned char *s1 = (const unsigned char *) str1;
    register const unsigned char *s2 = (const unsigned char *) str2;
    while (1) {
        if (*s1 == '\0') {
            if (*s2 == '\0')
                return 0;
            return -1;
        }
        if (*s2 == '\0')
            return 1;
        if (*s1 < *s2)
            return -1;
        if (*s1 > *s2)
            return 1;
        s1++;
        s2++;
    }
    return 0;
}

/* used by replace_str{,n}casecmp when we can't find a locale-aware version */
IN_REPLACE_SECTION static int
replace_tolower_ascii(int c)
{
    if (c >= 'A' && c <= 'Z')
        return (c - ('A' - 'a'));
    return c;
}

IN_REPLACE_SECTION int
replace_strcasecmp(const char *str1, const char *str2)
{
    register const unsigned char *s1 = (const unsigned char *) str1;
    register const unsigned char *s2 = (const unsigned char *) str2;
    while (1) {
        register unsigned char l1 = (unsigned char) app_tolower(*s1);
        register unsigned char l2 = (unsigned char) app_tolower(*s2);
        if (l1 == '\0') {
            if (l2 == '\0')
                return 0;
            return -1;
        }
        if (l2 == '\0')
            return 1;
        if (l1 < l2)
            return -1;
        if (l1 > l2)
            return 1;
        s1++;
        s2++;
    }
    return 0;
}

IN_REPLACE_SECTION int
replace_strncasecmp(const char *str1, const char *str2, size_t size)
{
    register const unsigned char *s1 = (const unsigned char *) str1;
    register const unsigned char *s2 = (const unsigned char *) str2;
    while (size-- > 0) { /* loop will terminate before underflow */
        register unsigned char l1 = (unsigned char) app_tolower(*s1);
        register unsigned char l2 = (unsigned char) app_tolower(*s2);
        if (l1 == '\0') {
            if (l2 == '\0')
                return 0;
            return -1;
        }
        if (l2 == '\0')
            return 1;
        if (l1 < l2)
            return -1;
        if (l1 > l2)
            return 1;
        s1++;
        s2++;
    }
    return 0;
}

IN_REPLACE_SECTION int
replace_wcscmp(const wchar_t *s1, const wchar_t *s2)
{
    while (1) {
        if (*s1 == L'\0') {
            if (*s2 == L'\0')
                return 0;
            return -1;
        }
        if (*s2 == L'\0')
            return 1;
        if ((unsigned int)*s1 < (unsigned int)*s2)
            return -1;
        if ((unsigned int)*s1 > (unsigned int)*s2)
            return 1;
        s1++;
        s2++;
    }
    return 0;
}

IN_REPLACE_SECTION char *
replace_strcpy(char *dst, const char *src)
{
    register const char *s = (char *) src;
    register char *d = (char *) dst;
    while (*s != '\0')
        *d++ = *s++;
    *d = '\0';
    return dst;
}

IN_REPLACE_SECTION wchar_t *
replace_wcscpy(wchar_t *dst, const wchar_t *src)
{
    register const wchar_t *s = (wchar_t *) src;
    register wchar_t *d = (wchar_t *) dst;
    while (*s != '\0')
        *d++ = *s++;
    *d = '\0';
    return dst;
}

IN_REPLACE_SECTION char *
replace_strncpy(char *dst, const char *src, size_t size)
{
    register const char *s = (char *) src;
    register char *d = (char *) dst;
    while (size > 0 && *s != '\0') {
        *d++ = *s++;
        size--;
    }
    /* if hit size, do not null terminate */
    while (size > 0) {
        *d++ = '\0';
        size--;
    }
    return dst;
}

IN_REPLACE_SECTION char *
replace_stpcpy(char *dst, const char *src)
{
    register const char *s = (char *) src;
    register char *d = (char *) dst;
    while (*s != '\0')
        *d++ = *s++;
    *d = '\0';
    return d;
}

IN_REPLACE_SECTION char *
replace_strcat(char *dst, const char *src)
{
    register char *d = (char *) dst;
    while (*d != '\0')
        d++;
    replace_strcpy(d, src);
    return dst;
}

IN_REPLACE_SECTION char *
replace_strncat(char *dst, const char *src, size_t size)
{
    /* we can't easily use replace_strncpy b/c we don't want
     * to fill to size, and we want to null-terminate
     */
    register const char *s = (char *) src;
    register char *d = (char *) dst;
    while (*d != '\0')
        d++;
    while (size > 0 && *s != '\0') {
        *d++ = *s++;
        size--;
    }
    *d = '\0';
    return dst;
}

IN_REPLACE_SECTION size_t
replace_strspn(const char *str, const char *accept)
{
    const char *cur = str;
    bool table[UCHAR_MAX];
    replace_memset(table, 0, sizeof(table));
    while (*accept != '\0') {
        table[(unsigned char)*accept] = true;
        accept++;
    }
    while (*cur != '\0' && table[(unsigned char)*cur])
        cur++;
    return cur - str;
}

IN_REPLACE_SECTION size_t
replace_strcspn(const char *str, const char *reject)
{
    const char *cur = str;
    bool table[UCHAR_MAX];
    replace_memset(table, 1, sizeof(table));
    while (*reject != '\0') {
        table[(unsigned char)*reject] = false;
        reject++;
    }
    while (*cur != '\0' && table[(unsigned char)*cur])
        cur++;
    return cur - str;
}

IN_REPLACE_SECTION char *
replace_strstr(const char *haystack, const char *needle)
{
    register const char *hs = haystack;
    register const char *n = needle;
    /* empty needle should return haystack */
    if (*n == '\0')
        return (char *) haystack;
    while (*hs != '\0') {
        if (*hs != *n && n > needle) {
            hs -= n - 1 - needle; /* backtrack */
            n = needle;
        }
        if (*hs == *n) {
            n++;
            if (*n == '\0')
                return (char *) (hs - (n - 1 - needle));
        }
        hs++;
    }
    return NULL;
}

IN_REPLACE_SECTION wchar_t *
replace_wcsstr(const wchar_t *haystack, const wchar_t *needle)
{
    register const wchar_t *hs = haystack;
    register const wchar_t *n = needle;
    /* empty needle should return haystack */
    if (*n == '\0')
        return (wchar_t *) haystack;
    while (*hs != '\0') {
        if (*hs != *n && n > needle) {
            hs -= n - 1 - needle; /* backtrack */
            n = needle;
        }
        if (*hs == *n) {
            n++;
            if (*n == '\0')
                return (wchar_t *) (hs - (n - 1 - needle));
        }
        hs++;
    }
    return NULL;
}

IN_REPLACE_SECTION void *
replace_memmove(void *dst, const void *src, size_t size)
{
    if (((ptr_uint_t)dst) - ((ptr_uint_t)src) >= size) {
        /* forward walk won't clobber: either no overlap or dst < src */
        register const char *s = (const char *) src;
        register char *d = (char *) dst;
        if (((ptr_uint_t)dst & 3) == ((ptr_uint_t)src & 3)) {
            /* same alignment, so we can do 4 aligned bytes at a time and stay
             * on fastpath.  when not same alignment, I'm assuming it's faster
             * to have all 1-byte moves on fastpath rather than half 4-byte
             * (aligned) on fastpath and half 4-byte (unaligned) on slowpath.
             */
            while (!ALIGNED(d, 4) && size > 0) {
                *d++ = *s++;
                size--;
            }
            while (size > 3) {
                *((unsigned int *)d) = *((unsigned int *)s);
                s += 4;
                d += 4;
                size -= 4;
            }
            while (size > 0) {
                *d++ = *s++;
                size--;
            }
        } else {
            while (size > 0) {
                *d++ = *s++;
                size--;
            }
        }
    } else {
        /* walk backward to avoid clobbering since overlaps and src < dst */
        register const char *s = ((const char *) src) + size;
        register char *d = ((char *) dst) + size;
        if (((ptr_uint_t)dst & 3) == ((ptr_uint_t)src & 3)) {
            /* same alignment, so we can do 4 aligned bytes at a time and stay
             * on fastpath.  we want to do 4 aligned on mod 3 since backward.
             */
            while (!ALIGNED(d, 4) && size > 0) {
                *(--d) = *(--s);
                size--;
            }
            while (size > 3) {
                *((unsigned int *)(d-4)) = *((unsigned int *)(s-4));
                s -= 4;
                d -= 4;
                size -= 4;
            }
            while (size > 0) {
                *(--d) = *(--s);
                size--;
            }
        } else {
            while (size > 0) {
                *(--d) = *(--s);
                size--;
            }
        }
    }
    return dst;
}

IN_REPLACE_SECTION int
replace_memcmp(const void *p1, const void *p2, size_t size)
{
    register const unsigned char *s1 = (unsigned char *) p1;
    register const unsigned char *s2 = (unsigned char *) p2;
    ssize_t diff;
    while (size-- > 0) { /* loop will terminate before underflow */
        diff = (*s1 - *s2);
        if (diff != 0)
            return diff;
        s1++;
        s2++;
    }
    return 0;
}

IN_REPLACE_SECTION int
replace_wmemcmp(const wchar_t *s1, const wchar_t *s2, size_t count)
{
    ssize_t diff;
    while (count-- > 0) { /* loop will terminate before underflow */
        diff = (*s1 - *s2);
        if (diff != 0)
            return diff;
        s1++;
        s2++;
    }
    return 0;
}

IN_REPLACE_SECTION void
replace_final_routine(void)
{
}
/* do not add .replace routines below here */

#ifdef MACOS
asm(".section __TEXT,.text");
asm(".align 12");
asm(".text");
#elif defined(LINUX)
asm(".section .text, \"ax\", " IF_X86_ELSE("@progbits","%progbits"));
asm(".align " IF_X86_ELSE("0x1000","12"));
#else
ACTUAL_PRAGMA( code_seg() )
#endif

/*
 ***************************************************************************/

static const void *replace_routine_addr[] = {
#define REPLACE_NAME_DEF(nm, func, wide) replace_##func,
    REPLACE_DEFS()
#undef REPLACE_NAME_DEF
};

static app_pc
get_function_entry(app_pc C_var)
{
    void *drcontext = dr_get_current_drcontext();
    byte *pc;
    instr_t inst;
    instr_init(drcontext, &inst);
    pc = decode(drcontext, C_var, &inst);
    ASSERT(pc != NULL, "invalid instr at function entry");
    if (instr_get_opcode(&inst) == OP_jmp) {
        /* skip jmp in ILT */
        ASSERT(opnd_is_pc(instr_get_target(&inst)), "decoded jmp should have pc tgt");
        pc = opnd_get_pc(instr_get_target(&inst));
    } else
        pc = C_var;
    instr_free(drcontext, &inst);
    return pc;
}

void
replace_init(void)
{
    if (options.replace_libc) {
        app_pc addr;
        int i;
        char *s;

        /* replace_module_load will be called for each module to populate the hashtable */

        ASSERT(sizeof(int) >= sizeof(wchar_t),
               "wchar_t replacement functions assume wchar_t is not larger than int");
        replace_routine_start = (app_pc)
            PAGE_START(get_function_entry((app_pc)replace_memset));
        /* For now we assume the routines are laid out in source file order.
         * It doesn't matter much because currently they all fit on on page.
         * XXX i#1069: we could implement a more complex scheme to get the
         * real bounds of .section.
         */
        replace_routine_size =
            ALIGN_FORWARD(get_function_entry((app_pc)replace_final_routine), PAGE_SIZE) -
            PAGE_START(get_function_entry((app_pc)replace_memset));

        /* PR 485412: we support passing in addresses of libc routines to
         * be replaced if statically included in the executable and if
         * we have no symbols available
         */
        s = options.libc_addrs;
        i = 0;
        while (s != NULL) {
            if (dr_sscanf(s, PIFX, (ptr_uint_t *)&addr) == 1 ||
                /* we save option space by having no 0x prefix but assuming hex */
                dr_sscanf(s, PIFMT, (ptr_uint_t *)&addr) == 1) {
                LOG(2, "replacing %s @"PFX" in executable from options\n",
                    replace_routine_name[i], addr);
                if (!drwrap_replace((app_pc)addr, (app_pc)replace_routine_addr[i], false))
                    ASSERT(false, "failed to replace");
            }
            s = strchr(s, ',');
            if (s != NULL)
                s++;
            i++;
        }

#ifdef USE_DRSYMS
        hashtable_init(&replace_name_table, REPLACE_NAME_TABLE_HASH_BITS, HASH_STRING,
                       false/*!strdup*/);
        for (i=0; i<REPLACE_NUM; i++) {
            if (strcmp(replace_routine_name[i], "memcpy") == 0)
                index_memcpy = i;
            if (strcmp(replace_routine_name[i], "memmove") == 0)
                index_memmove = i;
            hashtable_add(&replace_name_table, (void *) replace_routine_name[i],
                          (void *)(ptr_int_t)(i+1)/*since 0 is "not found"*/);
        }
#endif
    }
}

void
replace_exit(void)
{
#ifdef USE_DRSYMS
    if (options.replace_libc) {
        hashtable_delete(&replace_name_table);
    }
#endif
}

static void
replace_routine(bool add, const module_data_t *mod,
                app_pc addr, int index)
{
    IF_DEBUG(const char *modname = dr_module_preferred_name(mod);)
    /* look for partial map (i#730) */
    if (!dr_module_contains_addr(mod, addr)) {
        LOG(1, "NOT replacing %s @"PFX" beyond end of mapping for module %s\n",
            replace_routine_name[index], addr, modname == NULL ? "<noname>" : modname);
        return;
    }
    LOG(2, "%s %s @"PFX" in %s (base "PFX")\n",
        add ? "replacing" : "removing replacement",
        replace_routine_name[index], addr,
        modname == NULL ? "<noname>" : modname, mod->start);
    /* We can't store 0 in the table (==miss) so we store index + 1 */
    if (add) {
        const void *replace_addr = replace_routine_addr[index];
#if defined(WINDOWS) && defined(X64)
        /* i#1868: 64-bit Visual Studio labels memmove as "memcpy" so we are
         * forced to handle overlap (though mingw doesn't need it).  It's more
         * efficient to swap here than to have replace_memcpy call replace_memmove.
         */
        if (index == index_memcpy)
            replace_addr = replace_routine_addr[index_memmove];
#endif
#ifdef USE_DRSYMS
        if (options.use_symcache)
            drsymcache_add(mod, replace_routine_name[index], addr - mod->start);
#endif
        /* Replacement strategy: we assume these routines will always be entered in
         * a new bb (we're not going to request elision or indcall2direct from DR).
         * We want to interpret our own routines, so we replace the whole bb with
         * a jump to the replacement routine.  This avoids having faults in
         * our lib, for which DR will abort.
         */
        /* Pass true to override b/c we do end up w/ dups b/c we process exports
         * and then all symbols (see below).  This also lets us handle aliases
         * (e.g., memcpy aliased to memmove on MacOS: xref i#1868) by having
         * the later-listed routine take precedence (memmove over memcpy, e.g.).
         */
        if (!drwrap_replace((app_pc)addr, (app_pc)replace_addr, true))
            ASSERT(false, "failed to replace");
    } else {
        if (!drwrap_replace((app_pc)addr, NULL, true)) {
            /* We can't easily assert b/c we may have already removed an instance
             * of this symbol (i#1200) or even of a different symbol with the
             * same address (i#1818).
             */
        }
    }
}

/* Modern glibc uses an ELF indirect code object to enable strlen to
 * dynamically resolve to an arch-specific optimized version.
 * However, some internal glibc routines like fputs have
 * hardcoded calls to strlen that sometimes target the version
 * that is not the one resolved at runtime, and these versions
 * are not exported.  If we had full debug information we could
 * find them as they are named __strlen_ia32 and __strlen_sse2.
 * This routine tries to identify all such routines and replace
 * them all.  It assumes the strlen() resolution routine first
 * does the typical "call thunk to get retaddr in ebx, add immed to ebx"
 * to find the GOT, and then has "lea <offs of func>+GOT into eax"
 * for each return possibility.  Xref PR 623449.
 * 32-bit example:
 *    0x4efd50 <strlen>:      push   %ebx
 *    0x4efd51 <strlen+1>:    call   0x48f9ef <__i686.get_pc_thunk.bx>
 *    0x4efd56 <strlen+6>:    add    $0xfa29e,%ebx
 *    0x4efd5c <strlen+12>:   cmpl   $0x0,0x354c(%ebx)
 *    0x4efd63 <strlen+19>:   jne    0x4efd6a <strlen+26>
 *    0x4efd65 <strlen+21>:   call   0x48ffa0 <__init_cpu_features>
 *    0x4efd6a <strlen+26>:   lea    -0xfa1e4(%ebx),%eax
 *    0x4efd70 <strlen+32>:   testl  $0x4000000,0x3560(%ebx)
 *    0x4efd7a <strlen+42>:   je     0x4efd82 <strlen+50>
 *    0x4efd7c <strlen+44>:   lea    -0xfa264(%ebx),%eax
 *    0x4efd82 <strlen+50>:   pop    %ebx
 *    0x4efd83 <strlen+51>:   ret
 *
 * For 64-bit, we simply look for "lea <rip-rel+offs> into eax".
 * Example:
 *    0x37a4284b90 <strcmp>:    cmpl   $0x0,0x339029(%rip)       # <__cpu_features>
 *    0x37a4284b97 <strcmp+7>:  jne    0x37a4284b9e <strcmp+14>
 *    0x37a4284b99 <strcmp+9>:  callq  0x37a4221fa0 <__init_cpu_features>
 *    0x37a4284b9e <strcmp+14>: testl  $0x200,0x339020(%rip)     # <__cpu_features+8>
 *    0x37a4284ba8 <strcmp+24>: jne    0x37a4284bbd <strcmp+45>
 *    0x37a4284baa <strcmp+26>: lea    0xac32f(%rip),%rax        # <__strcmp_sse42>
 *    0x37a4284bb1 <strcmp+33>: testl  $0x100000,0x339015(%rip)  # <__cpu_features+16>
 *    0x37a4284bbb <strcmp+43>: jne    0x37a4284bd7 <strcmp+71>
 *    0x37a4284bbd <strcmp+45>: lea    0xb763c(%rip),%rax        # <__strcmp_ssse3>
 *    0x37a4284bc4 <strcmp+52>: testl  $0x200,0x339002(%rip)     # <__cpu_features+16>
 *    0x37a4284bce <strcmp+62>: jne    0x37a4284bd7 <strcmp+71>
 *    0x37a4284bd0 <strcmp+64>: lea    0x9(%rip),%rax            # <__strcmp_sse2>
 *    0x37a4284bd7 <strcmp+71>: retq
 */
static void
replace_all_indirect(bool add, const module_data_t *mod,
                     int index, app_pc indir, app_pc resolved)
{
#ifdef X86
    void *drcontext = dr_get_current_drcontext();
    instr_t inst;
    app_pc pc = indir;
# if !defined(X64) || defined(DEBUG)
    app_pc prev_pc;
# endif
# ifndef X64
    bool last_was_call = false, first_call = false;
    app_pc addr_got = NULL;
# endif
    instr_init(drcontext, &inst);
    do {
        instr_reset(drcontext, &inst);
# if !defined(X64) || defined(DEBUG)
        prev_pc = pc;
# endif
        /* look for partial map (i#730) */
        if (!dr_module_contains_addr(mod, pc + MAX_INSTR_SIZE)) {
            WARN("WARNING: decoding off end of module for %s\n",
                 replace_routine_name[index]);
            break;
        }
        /* use safe_decode() in case of addr in gap in ELF module */
        if (!safe_decode(drcontext, pc, &inst, &pc) ||
            pc == NULL || !instr_valid(&inst)) {
            LOG(1, "WARNING: invalid instr at indir func %s "PFX"\n",
                replace_routine_name[index], prev_pc);
            break;
        }
# ifndef X64
        if (last_was_call) {
            /* At instr after call to thunk: should be add of immed to ebx */
            first_call = true;
            if (instr_get_opcode(&inst) == OP_add &&
                opnd_is_immed_int(instr_get_src(&inst, 0)) &&
                opnd_is_reg(instr_get_dst(&inst, 0)) &&
                opnd_get_reg(instr_get_dst(&inst, 0)) == REG_XBX) {
                addr_got = opnd_get_immed_int(instr_get_src(&inst, 0)) + prev_pc;
                LOG(2, "\tfound GOT "PFX" for indir func %s\n",
                    addr_got, replace_routine_name[index]);
                if (addr_got < mod->start || !dr_module_contains_addr(mod, addr_got))
                    addr_got = NULL;
            }
            last_was_call = false;
        }
        if (addr_got != NULL &&
            instr_get_opcode(&inst) == OP_lea &&
            opnd_get_reg(instr_get_dst(&inst, 0)) == REG_XAX &&
            opnd_is_base_disp(instr_get_src(&inst, 0)) &&
            opnd_get_base(instr_get_src(&inst, 0)) == REG_XBX &&
            opnd_get_index(instr_get_src(&inst, 0)) == REG_NULL &&
            opnd_get_scale(instr_get_src(&inst, 0)) == 0) {
            app_pc addr = addr_got + opnd_get_disp(instr_get_src(&inst, 0));
            LOG(2, "\tfound return value "PFX" for indir func %s @"PFX"\n",
                addr, replace_routine_name[index], prev_pc);
            if (addr < mod->start || !dr_module_contains_addr(mod, addr)) {
                LOG(1, "WARNING: unknown code in indir func %s @"PFX"\n",
                    replace_routine_name[index], prev_pc);
                break;
            }
            if (addr != resolved)
                replace_routine(add, mod, addr, index);
        }
        if (!first_call && instr_is_call_direct(&inst))
            last_was_call = true;
# else
        if (instr_get_opcode(&inst) == OP_lea &&
            opnd_get_reg(instr_get_dst(&inst, 0)) == REG_XAX &&
            opnd_is_rel_addr(instr_get_src(&inst, 0))) {
            app_pc addr = opnd_get_addr(instr_get_src(&inst, 0));
            LOG(2, "\tfound return value "PFX" for indir func %s @"PFX"\n",
                addr, replace_routine_name[index], prev_pc);
            if (addr < mod->start || !dr_module_contains_addr(mod, addr)) {
                LOG(1, "WARNING: unknown code in indir func %s @"PFX"\n",
                    replace_routine_name[index], prev_pc);
                break;
            }
            if (addr != resolved)
                replace_routine(add, mod, addr, index);
        }
# endif
    } while (!instr_is_return(&inst));
    instr_reset(drcontext, &inst);
#elif defined(ARM)
    /* NYI: our current ARM targets do not have indirected routines in glibc. */
    ASSERT_NOT_IMPLEMENTED();
#endif
}

#ifdef USE_DRSYMS
/* It's faster to search for multiple symbols at once via regex
 * and strcmp to identify precise targets (i#315).
 */
static bool
enumerate_syms_cb(drsym_info_t *info, drsym_error_t status, void *data)
{
    uint i;
    sym_enum_data_t *edata = (sym_enum_data_t *) data;
    bool replace = true;
    const char *name = info->name;
    size_t modoffs = info->start_offs;

    ASSERT(edata != NULL && edata->processed != NULL, "invalid param");
    LOG(2, "%s: %s "PIFX"\n", __FUNCTION__, name, modoffs);

    /* Using hashtable lookup to avoid linear walk of strcmp.
     * Linear walk isn't much slower now, but will become worse
     * as we add more routines.
     */
    i = (uint)(ptr_uint_t) hashtable_lookup(&replace_name_table, (void *)name);
    if (i == 0)
        return true; /* keep iterating */

#ifdef WINDOWS /* drsym_get_func_type NYI on Linux, and wchar_t rarely used there */
    /* i#682: chrome has str* routines that take in wchar_t.  We ask for types
     * and treat wide as corresponding wcs*.  We only look at the str* routines
     * and we assume each has a char* (or const char*) pointer as its first arg.
     * Could have a bool in REPLACE_DEFS.
     */
    if (name[0] == 's' && name[1] == 't' && name[2] == 'r') {
        size_t bufsz = 256; /* good starting size: big enough for str* in practice */
        char *buf = (char *) global_alloc(bufsz, HEAPSTAT_MISC);
        drsym_func_type_t *func_type;
        drsym_error_t err;
        do {
            err = drsym_get_func_type(edata->mod->full_path, modoffs,
                                      buf, bufsz, &func_type);
            if (err != DRSYM_ERROR_NOMEM)
                break;
            global_free(buf, bufsz, HEAPSTAT_MISC);
            bufsz *= 2;
            buf = (char *) global_alloc(bufsz, HEAPSTAT_MISC);
        } while (true);
        if (err == DRSYM_SUCCESS &&
            func_type->num_args >= 1 &&
            func_type->arg_types[0]->kind == DRSYM_TYPE_PTR) {
            drsym_ptr_type_t *arg_type = (drsym_ptr_type_t*) func_type->arg_types[0];
            if (arg_type->elt_type->kind == DRSYM_TYPE_INT &&
                arg_type->elt_type->size == sizeof(wchar_t)) {
                WARN("WARNING: %s "PIFX" arg type is wchar_t*!\n", name, modoffs);
                if (i != 0 && replace_routine_wide_alt[i-1] != NULL) {
                    /* Replace as wide-char routine instead.  It will get
                     * put into symcache under the wide name, so we will
                     * avoid this type lookup next time.
                     */
                    name = replace_routine_wide_alt[i-1];
                    i = (uint)(ptr_uint_t)
                        hashtable_lookup(&replace_name_table, (void *)name);
                } else
                    replace = false;
            } else if (arg_type->elt_type->kind != DRSYM_TYPE_INT ||
                       arg_type->elt_type->size != sizeof(char)) {
                WARN("WARNING: %s "PIFX" has unknown arg types!\n", name, modoffs);
                replace = false;
            }
        }
        global_free(buf, bufsz, HEAPSTAT_MISC);
    }
#endif

    if (replace) {
        /* i#617: some modules have multiple addresses for one symbol:
         * e.g., unit_tests.exe strlen, strchr, and strrchr
         */
        if (i != 0 && !edata->processed[i-1] &&
            /* i#1710: do not replace indirected top-level object */
            edata->mod->start + modoffs != edata->indirect[i-1]) {
            i--;
            replace_routine(edata->add, edata->mod, edata->mod->start + modoffs, i);
        }
    }
    return true; /* keep iterating */
}

static void
find_syms_regex(sym_enum_data_t *edata, const char *regex)
{
    if (!lookup_all_symbols(edata->mod, regex, false/*!full*/,
                            enumerate_syms_cb, (void *)edata))
        LOG(2, "WARNING: failed to look up symbols: %s\n", regex);
}
#endif /* USE_DRSYMS */

#ifdef WINDOWS
/* i#511: Save UuidCreate's outparam so we can mark it as defined in the post
 * callback.
 *
 * RPC_STATUS UuidCreate(UUID __RPC_FAR *Uuid);
 */
static void
wrap_UuidCreate_pre(void *wrapcxt, OUT void **user_data)
{
    /* Save arg to mark as initialized afterwards. */
    *user_data = drwrap_get_arg(wrapcxt, 0);
}

static void
wrap_UuidCreate_post(void *wrapcxt, void *user_data)
{
    app_pc cur;
    app_pc start = user_data;
    RPC_STATUS status;

    ASSERT(options.check_uninitialized, "invalid shadow mode");
    if (wrapcxt == NULL)
        return;  /* Do nothing on unwind. */
    /* Check for success.  It's not clear if the output is written on other
     * status codes.
     */
    status = (RPC_STATUS)(ptr_uint_t) drwrap_get_retval(wrapcxt);
    if (status != RPC_S_OK && status != RPC_S_UUID_LOCAL_ONLY)
        return;
    /* Mark the outparam as defined. */
    shadow_set_non_matching_range(start, sizeof(GUID), SHADOW_DEFINED,
                                  SHADOW_UNADDRESSABLE);
}
#endif

/* XXX: better to walk hashtable on remove, like alloc.c does, instead of
 * re-doing all these symbol queries
 */
static void
replace_in_module(const module_data_t *mod, bool add)
{
    /* We want to replace str/mem in libc, and in the executable if
     * it has statically included libc, and in any library that has done
     * so: so we aggressively apply to all libraries.
     * FIXME: we need symbols to find statically-included libc.
     *
     * It's possible some library exports a routine that is slightly
     * different w/ the same name but that seems very unlikely since it
     * would conflict w/ the libc routine.  On Windows it's more likely
     * since there's no global namespace.
     */
    int i;
    app_pc libc = get_libc_base(NULL);
    void *drcontext = dr_get_current_drcontext();
#ifdef USE_DRSYMS
    sym_enum_data_t edata = {add, {0,}, {0}, mod};
    bool missing_entry = false;
#endif
#ifdef DEBUG
    const char *print_name = (dr_module_preferred_name(mod) == NULL) ?
        "<NULL>" : dr_module_preferred_name(mod);
#endif
#ifdef WINDOWS
    const char *modname = dr_module_preferred_name(mod);
    /* i#511: Wrap UuidCreate in rpcrt4.dll. */
    if (options.check_uninitialized &&
        text_matches_pattern("rpcrt4.dll", modname, true/*ignore case */)) {
        generic_func_t fn = dr_get_proc_address(mod->handle, "UuidCreate");
        if (fn != NULL) {
            if (add) {
                drwrap_wrap((app_pc)fn, wrap_UuidCreate_pre,
                            wrap_UuidCreate_post);
            } else {
                drwrap_unwrap((app_pc)fn, wrap_UuidCreate_pre,
                              wrap_UuidCreate_post);
            }
        }
    }

    if (options.skip_msvc_importers &&
        module_imports_from_msvc(mod) &&
        (modname == NULL ||
         (!text_matches_pattern(modname, "msvcp*.dll", true/*ignore case*/) &&
          !text_matches_pattern(modname, "msvcr*.dll", true/*ignore case*/)))) {
        /* i#963: assume there are no static libc routines if the module
         * imports from dynamic libc (unless it's dynamic C++ lib).
         * XXX: We'll miss some non-libc custom routine: but those may be
         * unlikely to have the optimizations that cause false positives.
         * XXX: Look through imported funcs?
         */
        LOG(2, "module %s imports from msvc* so not searching inside it\n",
            modname == NULL ? "" : modname);
        return;
    }
#else
    if (mod->start == libc) {
        /* prefer locale-aware tolower from libc to our English version (i#181) */
        generic_func_t func = dr_get_proc_address(mod->handle, "tolower");
        if (func != NULL) {
            if (add)
                app_tolower = (int (*)(int)) func;
            else
                app_tolower = replace_tolower_ascii;
        }
    }
#endif
    ASSERT(options.replace_libc, "should not be called if op not on");
    /* step 1: find and replace symbols in exports
     * if we find an export we can't mark as processed b/c
     * there can be other symbols of same name.
     */
    for (i=0; i<REPLACE_NUM; i++) {
        dr_export_info_t info;
        app_pc addr = NULL;
        if (dr_get_proc_address_ex(mod->handle, replace_routine_name[i],
                                   &info, sizeof(info))) {
            addr = (app_pc) info.address;
            ASSERT(addr != NULL, "can't succeed yet have NULL addr!");
            if (info.is_indirect_code) {
                /* i#248/PR 510905: new ELF indirect code object type.
                 * We have to call the export to get the real impl.
                 * This could be unsafe: but we're already trusting the app and
                 * assuming it's not trying to intentionally subvert us.
                 */
                app_pc (*indir)(void) = (app_pc (*)(void)) cast_to_func(addr);
                app_pc orig_addr = addr;
                DR_TRY_EXCEPT(drcontext, {
                    addr = (*indir)();
                }, { /* EXCEPT */
                    addr = NULL;
                });
                LOG(2, "export %s indirected from "PFX" to "PFX"\n",
                    replace_routine_name[i], info.address, addr);
                if (mod->start == libc)
                    replace_all_indirect(add, mod, i, orig_addr, addr);
                /* i#1710: while we do want to find other instances, we can't
                 * let the symbol enumerator replace the top-level indirected
                 * object, so we store its address.
                 */
                edata.indirect[i] = (app_pc) info.address;
            }
        }
        if (addr != NULL) {
            replace_routine(add, mod, addr, i);
        } else {
            /* We should find every single routine in libc on linux: on windows
             * the wide-char ones aren't always there
             */
            IF_UNIX(ASSERT(mod->start != libc ||
                           /* i#1747: bionic libc does not have all replace routines.
                            * We could add a generated array of whether the routine is
                            * expected to be there instead if more routines are missing.
                            */
                           (strcmp(replace_routine_name[i], "rawmemchr") == 0 ||
                            strcmp(replace_routine_name[i], "strchrnul") == 0),
                           "can't find libc routine to replace"));
        }
    }

#ifdef USE_DRSYMS
    /* step 2, find and replace symbols in symcache
     * i#617: some modules have multiple addresses for one symbol:
     * e.g., unit_tests.exe: strlen, strchr, and strrchr,
     * so we always need check if we can find it in the symcache.
     * We assume that we have all the entries of a symbol if we can find one
     * entry for that symbol in the symcache.
     */
    for (i = 0; i < REPLACE_NUM; i++) {
        size_t *modoffs, single;
        uint count;
        uint idx;
        bool res;
        LOG(3, "Search %s in %s symcache\n", replace_routine_name[i], print_name);
        if (options.use_symcache &&
            drsymcache_module_is_cached(mod, &res) == DRMF_SUCCESS && res &&
            drsymcache_lookup(mod, replace_routine_name[i],
                              &modoffs, &count, &single) == DRMF_SUCCESS) {
            STATS_INC(symbol_search_cache_hits);
            edata.processed[i] = true;
            for (idx = 0; idx < count; idx++) {
                if (modoffs[idx] != 0) {
                    replace_routine(add, mod, mod->start + modoffs[idx], i);
                }
            }
            drsymcache_free_lookup(modoffs, count);
        }
        if (!edata.processed[i]) {
            LOG(2, "%s: did not find %s in symcache\n", print_name,
                replace_routine_name[i]);
            missing_entry = true;
        }
    }

    /* step 3, some symbols are not found in symcache, lookup them in modules */
    if (missing_entry) {
        /* PR 486382: look up these symbols online for all modules.
         * We rely on drsym_init() having been called during init.
         * It's faster to look up multiple via regex (xref i#315)
         * when most modules don't have any of the replacement syms.
         */
        /* add 0, which will be replaced if we find it */
        if (options.use_symcache) {
            for (i = 0; i < REPLACE_NUM; i++) {
                if (!edata.processed[i])
                    drsymcache_add(mod, replace_routine_name[i], 0);
            }
        }
        /* These regex cover all function names we replace.  Both
         * number of syms and number of queries count.  This is a good
         * compromise.  "*mem*" has too many matches, while
         * "mem[scrm]*", "*wmem*", "str[crln]*", and "wcs*" is too
         * many queries.  Note that dbghelp does not support a regex
         * symbol for "0 or 1 chars".
         */
        if (lookup_has_fast_search(mod)) {
            /* N.B.: if you change these regexes, bump SYMCACHE_VERSION! */
            find_syms_regex(&edata, "[msw]?????");
            find_syms_regex(&edata, "[msw]??????");
# ifdef UNIX
            find_syms_regex(&edata, "strchrnul");
            find_syms_regex(&edata, "rawmemchr");
# endif
        } else {
            /* better to do just one walk */
            LOG(2, "looking up all symbols for %s\n", print_name);
            if (!lookup_all_symbols(edata.mod, "", false/*!full*/,
                                    enumerate_syms_cb, (void *)&edata))
                LOG(2, "WARNING: failed to look up symbols to replace\n");
        }
    }
#endif
}

void
replace_module_load(void *drcontext, const module_data_t *info, bool loaded)
{
    /* Skip DR (its forwarders raise a curiosity in module_shared.c, plus
     * we don't want to replace its or client uses)
     */
    if (options.replace_libc &&
        !dr_memory_is_dr_internal(info->start) &&
        !dr_memory_is_in_client(info->start))
        replace_in_module(info, true/*add*/);
}

void
replace_module_unload(void *drcontext, const module_data_t *info)
{
    /* Skip DR (its forwarders raise a curiosity in module_shared.c, plus
     * we don't want to replace its or client uses)
     */
    if (options.replace_libc &&
        !dr_memory_is_dr_internal(info->start) &&
        !dr_memory_is_in_client(info->start))
        replace_in_module(info, false/*remove*/);
}

bool
in_replace_routine(app_pc pc)
{
    return (options.replace_libc &&
            pc >= replace_routine_start &&
            pc < replace_routine_start + replace_routine_size);
}

bool
in_replace_memset(app_pc pc)
{
    /* we assume the layout for memset is all in one spot (optimizations
     * are disabled) and that memcpy follows it.  it wouldn't be
     * disastrous to include another routine since only used for
     * heap-unaddr checks.
     */
    static app_pc memset_entry, memcpy_entry;
    if (memset_entry == NULL) {
        memset_entry = get_function_entry((app_pc)replace_memset);
        memcpy_entry = get_function_entry((app_pc)replace_memcpy);
    }
    return (pc >= (app_pc)memset_entry && pc < (app_pc)memcpy_entry);
}
