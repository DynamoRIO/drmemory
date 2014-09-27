/* **********************************************************
 * Copyright (c) 2011-2014 Google, Inc.  All rights reserved.
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

#ifdef WINDOWS
#  define LIB_EXPORT __declspec(dllexport)
#else
#  ifdef USE_VISIBILITY_ATTRIBUTES
#    define LIB_EXPORT __attribute__ ((visibility ("default")))
#  endif
#endif

#if !defined(WINDOWS) || !defined(X64)
/* 64-bit Windows complains about redef */
typedef unsigned long size_t;
#endif

#ifdef USE_CUSTOM_MALLOC
LIB_EXPORT
void *
malloc(size_t size)
{
    return 0;
}

LIB_EXPORT
void
free(void *ptr)
{
    /* nothing */
}

LIB_EXPORT
void *
realloc(void *ptr, size_t size)
{
    return 0;
}
#endif /* USE_CUSTOM_MALLOC */

#ifdef WINDOWS

/* to avoid conflicts w/ libc we go /nodefaultlib /noentry */

#else /* UNIX */

void __attribute__ ((constructor))
my_init(void)
{
    /* nothing */
}

void __attribute__ ((destructor))
my_fini(void)
{
    /* nothing */
}

#endif
