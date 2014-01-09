/* **********************************************************
 * Copyright (c) 2013 Google, Inc.  All rights reserved.
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

/* Leak tests that need to report leaks (and thus can't be in app_suite)
 * and don't easily fit into malloc.c, cs2bug.cpp, or leakcycle.cpp.
 */

#include <windows.h>
#include <stdio.h>

static bool verbose;

/* We test i#625 -strings_vs_pointers.
 * We write a sequence of strings into here with a pointer embedded
 * at the start.
 */
static char buf[4096];
static wchar_t wbuf[4096];

#define IS_ASCII(c) ((c) < 0x80)
#define IS_ASCII_NONZERO(c) ((c) > 0 && (c) < 0x80)
#define MAX_TRY 4096 /* both Heaps and heap allocs */

static bool
is_ascii_top_nonzero_pointer(void *ptr)
{
    ULONG_PTR p = (ULONG_PTR) ptr;
    return (IS_ASCII(p & 0xff) &&
            IS_ASCII((p >> 8) & 0xff) &&
            IS_ASCII_NONZERO((p >> 16) & 0xff) &&
            IS_ASCII_NONZERO((p >> 24) & 0xff));
}

static bool
is_ascii_all_nonzero_pointer(void *ptr)
{
    ULONG_PTR p = (ULONG_PTR) ptr;
    return (IS_ASCII_NONZERO(p & 0xff) &&
            IS_ASCII_NONZERO((p >> 8) & 0xff) &&
            IS_ASCII_NONZERO((p >> 16) & 0xff) &&
            IS_ASCII_NONZERO((p >> 24) & 0xff));
}

static bool
is_wide_top_nonzero_pointer(void *ptr)
{
    ULONG_PTR p = (ULONG_PTR) ptr;
    return (IS_ASCII(p & 0xff) &&
            ((p >> 8) & 0xff) == 0 &&
            IS_ASCII_NONZERO((p >> 16) & 0xff) &&
            ((p >> 24) & 0xff) == 0);
}

static bool
is_wide_all_nonzero_pointer(void *ptr)
{
    ULONG_PTR p = (ULONG_PTR) ptr;
    return (IS_ASCII_NONZERO(p & 0xff) &&
            ((p >> 8) & 0xff) == 0 &&
            IS_ASCII_NONZERO((p >> 16) & 0xff) &&
            ((p >> 24) & 0xff) == 0);
}

int
main()
{
    /* Strategy: repeatedly create a Heap until we get one whose
     * leading address is composed of ascii chars.  Then we allocate
     * individual allocs until we get one whose entire address is
     * composed of ascii chars.  We free all the other allocs, leak
     * just the final one, and write its address into a string.
     *
     * This is a little flaky as
     * it relies on idiomatic properties of the heap implementation,
     * so we try to be robust to failure, in which case we simply
     * won't test -strings_vs_pointers but this test will pass.
     *
     * Note that I don't think I can easily fool drmem's heap
     * identification algorithm and cheat using VirtualAlloc.  If we
     * had annotations I could b/c I could mark my own routine as a
     * heap routine.
     */
    HANDLE heap;
    HANDLE todestroy[MAX_TRY];
    char *p;
    char *tofree[MAX_TRY];
    int i, heap_count = 0, count;
    do {
        heap = HeapCreate(0, 0, 0);
        todestroy[heap_count++] = heap;
        if (verbose)
            fprintf(stderr, "trying heap %p\n", heap);
        if (is_ascii_top_nonzero_pointer(heap)) {
            if (verbose)
                fprintf(stderr, "heap: %p\n", heap);
            count = 0;
            do {
                tofree[count++] = (char *) HeapAlloc(heap, 0, 24);
                if (verbose)
                    fprintf(stderr, "  trying %p\n", tofree[count-1]);
            } while (tofree[count-1] != NULL &&
                     !is_ascii_all_nonzero_pointer(tofree[count-1]) &&
                     count < MAX_TRY);
            if (tofree[count-1] != NULL) {
                p = tofree[count-1];
                if (verbose)
                    fprintf(stderr, "  got: %p, %p\n", heap, p);
                for (i = 0; i < count - 1; i++)
                    HeapFree(heap, 0, tofree[i]);
                break;
            }
        }
    } while (heap != NULL && heap_count < MAX_TRY);
    if (heap != NULL && heap_count < MAX_TRY) {
        for (i = 0; i < heap_count - 1; i++)
            HeapDestroy(todestroy[i]);
        if (verbose)
            fprintf(stderr, "found ascii pointer: %p\n", p);
        *((char **)buf) = p;
        if (verbose)
            fprintf(stderr, "wrote %p to string table @%p\n", p, buf);
        for (i = sizeof(p); i < 128; i++) {
            if (i % 15 == 0)
                buf[i] = '\0';
            else
                buf[i] = 'a';
        }
    } else {
        p = (char *) HeapAlloc(GetProcessHeap(), 0, 24);
    }

    /* Now repeat with wide chars. */
    heap_count = 0;
    do {
        heap = HeapCreate(0, 72*1024, 72*1024);
        todestroy[heap_count++] = heap;
        if (verbose)
            fprintf(stderr, "trying heap %p\n", heap);
        if (is_wide_top_nonzero_pointer(heap)) {
            if (verbose)
                fprintf(stderr, "heap: %p\n", heap);
            count = 0;
            tofree[count++] = (char *) HeapAlloc(heap, 0, 62*1024+512);
            do {
                tofree[count++] = (char *) HeapAlloc(heap, 0, 24);
                if (verbose)
                    fprintf(stderr, "  trying %p\n", tofree[count-1]);
            } while (tofree[count-1] != NULL &&
                     !is_wide_all_nonzero_pointer(tofree[count-1]) &&
                     count < MAX_TRY);
            if (tofree[count-1] != NULL) {
                p = tofree[count-1];
                if (verbose)
                    fprintf(stderr, "  got: %p, %p\n", heap, p);
                for (i = 0; i < count - 1; i++)
                    HeapFree(heap, 0, tofree[i]);
                break;
            }
        }
    } while (heap != NULL && heap_count < MAX_TRY);
    if (heap != NULL && heap_count < MAX_TRY) {
        for (i = 0; i < heap_count - 1; i++)
            HeapDestroy(todestroy[i]);
        if (verbose)
            fprintf(stderr, "found wide pointer: %p\n", p);
        *((char **)wbuf) = p;
        if (verbose)
            fprintf(stderr, "wrote %p to string table @%p\n", p, wbuf);
        for (i = sizeof(p)/sizeof(wchar_t); i < 128; i++) {
            if (i % 15 == 0)
                wbuf[i] = L'\0';
            else
                wbuf[i] = L'a';
        }
    } else {
        p = (char *) HeapAlloc(GetProcessHeap(), 0, 24);
    }

    fprintf(stderr, "done\n");
    return 0;
}
