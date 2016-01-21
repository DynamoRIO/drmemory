/* **********************************************************
 * Copyright (c) 2014-2016 Google, Inc.  All rights reserved.
 * Copyright (c) 2009 VMware, Inc.  All rights reserved.
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

/* Tests various read-dword optimizations in str* and mem* routines
 * that DrMem handles via pattern matching.
 */

#if defined(LINUX) && !defined(ANDROID)
# define _GNU_SOURCE /* strchrnul */
#endif
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

int
main()
{
    int num;
    char *dup, *c;
    char buf[8];
    dup = strdup("3"); /* not 4-byte-aligned in length */

    /* PR 406535: sscanf calls rawmemchr which reads a full dword => UNADDR */
    if (sscanf(dup, "%d", &num) > 0)
        printf("got %d\n", num);

    /* PR 406535: various other glibc routines all use the same dword load
     * and magic constant 0xfefefeff
     */

    c = strrchr(dup, 'x');

    c = strchr(dup, 'x');

#if defined(LINUX) && !defined(ANDROID)
    c = strchrnul(dup, 'x');
#endif

    c = (char *) memchr(dup, 'x', 2);

    buf[0] = '1';
    buf[1] = '\0';
    strcat(buf, dup);

    num = strlen(dup);

    free(dup);
    return 0;
}
