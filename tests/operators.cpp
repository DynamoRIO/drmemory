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

/* Test nothrow and placement operators.  Mismatches are already tested
 * in cs2bug.cpp.
 */

#include <new> // For std::nothrow
#include <iostream>
#include "stdlib.h"
#include "limits.h"

// Windows compiler and gcc4.4.3 complain if the size is over 0x7fffffff
# define SIZE_OOM 0x7fffffff
#ifdef UNIX
# define IF_UNIX_ELSE(x,y) x
#else
# define IF_UNIX_ELSE(x,y) y
#endif

class hasdtr {
public:
    hasdtr() { x = new int[7]; }
    ~hasdtr() { delete[] x; }
    int *x;
    int y;
    char z;
};

class enormous {
public:
    // i#972: char[SIZE_OOM] is the static limit but won't run OOM in Linux
    char buf[SIZE_OOM];
    char buf2[SIZE_OOM];
};

static void
test_placement()
{
    int *p = (int *) calloc(1, sizeof(hasdtr));
    hasdtr *placed = new (p) hasdtr;
    placed->y = 4;
    if (((hasdtr *)p)->y != placed->y)
        std::cout << "placement new not honored" << std::endl;
    // Cannot call placement delete (only for language-internal use, e.g.,
    // if constructor fails) so we must invoke destructor directly.
    placed->~hasdtr();
    free(p);

    p = (int *) malloc(sizeof(hasdtr)*2);
    placed = new (p) hasdtr[2];
    // Cannot call placement delete (only for language-internal use, e.g.,
    // if constructor fails) so we must invoke destructor directly.
    placed[0].~hasdtr();
    placed[1].~hasdtr();
    free(p);
}

static void
test_nothrow()
{
    enormous *e = new (std::nothrow) enormous;
    if (e == NULL)
        std::cout << "new returned NULL" << std::endl;
    else
        delete e;

    IF_UNIX_ELSE(int, char) *p =
        new (std::nothrow) IF_UNIX_ELSE(int, char)[SIZE_OOM];
    if (p == NULL)
        std::cout << "new[] returned NULL" << std::endl;
    else
        delete[] p;
}

// Actually Dr. Memory is unable to throw an exception (i#957): it just aborts,
// so we must run this last, and we end up only testing new[] and not new.
static void
test_throw()
{
    std::cout << "about to die" << std::endl;
    try {
        // On Linux if the size is too small we don't run out of memory until
        // we've constructed most of the elements, which takes a long
        // time and causes issues under drmem w/ DR doing resets, etc.
        hasdtr *lots = new hasdtr[IF_UNIX_ELSE(SIZE_OOM,SIZE_OOM/sizeof(hasdtr))];
        lots[0].y = 4;
    } catch (std::bad_alloc&) {
        std::cout << "caught bad_alloc" << std::endl;
    }
}

int main()
{
    test_placement();

    test_nothrow();

    // This one won't return under Dr. Memory!
    test_throw();

    std::cout << "all done" << std::endl;
    return 0;
}
