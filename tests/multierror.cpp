/* **********************************************************
 * Copyright (c) 2014 Google, Inc.  All rights reserved.
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

#include <iostream>

int
main()
{
    int count = 30;
    int *fib = new int[count];
    fib[0] = 0;
    fib[1] = 1;
    for (int i = 0; i < count; i++) {
        /* Ensure both a read and a write are reported (i#1476) */
        fib[i+2] = fib[i] + fib[i+1];
    }
    std::cout << "half-way value: " << fib[count/2] << std::endl;
    delete [] fib;
    return 0;
}
