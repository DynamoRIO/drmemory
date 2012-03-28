/* **********************************************************
 * Copyright (c) 2012 Google, Inc.  All rights reserved.
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

#include <stdio.h>

typedef unsigned int uint;

struct bitfield {
    bitfield() : bits21_(0), bits1_(0) { }
    bitfield(uint bits21, bool bits1) : bits21_(bits21), bits1_(bits1) { }
    uint bits21_ : 21;
    bool bits1_ : 1;
};

int main(int argc, char *argv[])
{
    bitfield b1(argc, true);
    if (b1.bits21_ > 0)
        printf("correct\n");
    bitfield b2;
    if (b2.bits21_ == 0)
        printf("correct\n");
    return 0;
}
