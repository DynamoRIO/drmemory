/* **********************************************************
 * Copyright (c) 2020 Google, Inc.  All rights reserved.
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

#include "drmemory_annotations.h"
#include <iostream>

void
foo(int x)
{
    int *y = new int[2];
    y[1] = x;
    DRMEMORY_ANNOTATE_DUMP_MEMORY_LAYOUT();
}

int
main()
{
    int i,**j,k,l,*m;
    i = 0;
    j = new int*[3];
    j[0] = new int;
    j[1] = &i;
    m = *(j+1);
    DRMEMORY_ANNOTATE_DUMP_MEMORY_LAYOUT();
    j[1] = &k;
    k=10;
    *(j[0]) = 5;
    j[2] = j[0];
    *(j[0]) = 18;
    *m = 4;
    l = 3;

    char *ch = new char[13];
    ch[4] = 'x';

    foo(l);

    std::cerr << "goodbye\n";

    return 0;
}
