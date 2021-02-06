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

#include <stdlib.h>

#ifdef WINDOWS
#  define LIB_EXPORT __declspec(dllexport)
#else
#  ifdef USE_VISIBILITY_ATTRIBUTES
#    define LIB_EXPORT __attribute__ ((visibility ("default")))
#  endif
#endif

#ifdef UNIX
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

LIB_EXPORT char
raise_error(char ignored)
{
    void *p = malloc(3);
    char c = *(((char *)p)+3); /* error: unaddressable */
    free(p);
    return c;
}
