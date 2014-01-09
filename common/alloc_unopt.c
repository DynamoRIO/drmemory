/* **********************************************************
 * Copyright (c) 2010-2011 Google, Inc.  All rights reserved.
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

#include "dr_api.h"
#include "utils.h"

void * marker_malloc(size_t size) { return NULL; }
size_t marker_size(void *ptr) { return 0; }
void marker_free(void *ptr) { }

/* Our fastpath can't handle OP_movs of uninit, which is common
 * w/ realloc, so we use a regular OP_mov loop.
 * XXX: share w/ drmem's replace_memcpy
 */
DO_NOT_OPTIMIZE
static void *
memcpy_no_movs(void *dst, const void *src, size_t size)
{
    register unsigned char *d = (unsigned char *) dst;
    register unsigned char *s = (unsigned char *) src;
    if (((ptr_uint_t)dst & 3) == ((ptr_uint_t)src & 3)) {
        /* same alignment, so we can do 4 aligned bytes at a time and stay
         * on fastpath
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
END_DO_NOT_OPTIMIZE

DO_NOT_OPTIMIZE
void *
replace_realloc_template(void *p, size_t newsz)
{
    volatile void *q = NULL;
    volatile size_t oldsz = 0;
    if (p != NULL) {
        oldsz = marker_size(p);
        if (oldsz == (size_t)-1 /* 0 is not failure: not calling usable_ */) {
            return NULL; /* on failure, do not free */
        }
    }
    if (newsz > 0 || p == NULL) {
        q = marker_malloc(newsz);
        if (q == NULL)
            return NULL; /* on failure, do not free */
        if (p != NULL) {
            size_t copysz = (newsz <= oldsz) ? newsz : oldsz;
            memcpy_no_movs((void *)q, p, copysz);
        }
    }
    marker_free(p);
    return (void *)q;
}
END_DO_NOT_OPTIMIZE

#ifdef WINDOWS
/* _dbg version */
void * marker_malloc_dbg(size_t size, int type, const char *file, int line)
    { return NULL; }
size_t marker_size_dbg(void *ptr, int type) { return 0; }
void marker_free_dbg(void *ptr, int type) { }

#ifndef _NORMAL_BLOCK
# define _NORMAL_BLOCK 1
#endif

DO_NOT_OPTIMIZE
void *
replace_realloc_template_dbg(void *p, size_t newsz, int type)
{
    volatile void *q = NULL;
    volatile size_t oldsz = 0;
    if (p != NULL) {
        oldsz = marker_size_dbg(p, type);
        if (oldsz == (size_t)-1 /* 0 is not failure: not calling usable_ */) {
            return NULL; /* on failure, do not free */
        }
    }
    if (newsz > 0 || p == NULL) {
        q = marker_malloc_dbg(newsz, type, "<drmem internal>", 42);
        if (q == NULL)
            return NULL; /* on failure, do not free */
        if (p != NULL) {
            size_t copysz = (newsz <= oldsz) ? newsz : oldsz;
            memcpy_no_movs((void *)q, p, copysz);
        }
    }
    marker_free_dbg(p, type);
    return (void *)q;
}
END_DO_NOT_OPTIMIZE

/* Rtl version */
PVOID NTAPI
marker_RtlAllocateHeap(HANDLE heap, DWORD flags, SIZE_T size) { return NULL; }
ULONG NTAPI
marker_RtlSizeHeap(HANDLE heap, ULONG flags, PVOID block) { return 0; }
bool NTAPI
marker_RtlFreeHeap(HANDLE heap, ULONG flags, PVOID block) { return false; }

DO_NOT_OPTIMIZE
void * NTAPI
replace_realloc_template_Rtl(HANDLE heap, ULONG flags, PVOID p, SIZE_T newsz)
{
    void *q = NULL;
    size_t oldsz = 0;
    if (TEST(HEAP_REALLOC_IN_PLACE_ONLY, flags)) {
        /* XXX i#71: want to call regular RtlReAllocateHeap and not
         * replace: need to set that up.  For now we fail and we'll
         * see if any apps don't handle such failure.
         * We should issue a warning but this is app code: should have
         * API routine to do so: XXX
         */
        return NULL;
    }
    /* Unlike libc realloc, NULL is not valid */
    if (p == NULL)
        return NULL;
    if (p != NULL) {
        oldsz = marker_RtlSizeHeap(heap, 0, p);
        if (oldsz == (size_t)-1 /* 0 is not failure */) {
            return NULL; /* on failure, do not free */
        }
    }
    /* HeapReAlloc has different behavior: (,0) does allocate a 0-sized chunk */
    q = marker_RtlAllocateHeap(heap, flags, newsz);
    if (q == NULL)
        return NULL; /* on failure, do not free */
    if (p != NULL) {
        size_t copysz = (newsz <= oldsz) ? newsz : oldsz;
        memcpy_no_movs(q, p, copysz);
    }
    marker_RtlFreeHeap(heap, 0, p);
    return q;
}
END_DO_NOT_OPTIMIZE
#endif

