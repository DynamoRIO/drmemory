/* **********************************************************
 * Copyright (c) 2012-2019 Google, Inc.  All rights reserved.
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

// Windows compiler and gcc4.4.3 complain if the size is over 0x7fffffff;
// Clang and gcc 7.3.2 complain if it's over 0xfffffff.
#ifdef UNIX
# define SIZE_OOM 0xfffffff
#else
# define SIZE_OOM 0x7fffffff
#endif
#define SIZE_OOM_ARR 1024
#ifdef UNIX
# define IF_UNIX_ELSE(x,y) x
#else
# define IF_UNIX_ELSE(x,y) y
#endif
#ifdef X64
# define IF_X64_ELSE(x,y) x
#else
# define IF_X64_ELSE(x,y) y
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
    /*
     * i#972: char[SIZE_OOM] is the static limit but won't run OOM in Linux,
     * so we alloc in a loop until OOM is triggered.
     */
    char buf[SIZE_OOM];
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
#ifdef X64
    // FIXME i#2029: taking too much time and resources to hit OOM w/ our allocator
    std::cout << "new returned NULL" << std::endl;
    std::cout << "new[] returned NULL" << std::endl;
    return;
#endif
    unsigned int i = 0;
    enormous **e = new (std::nothrow) enormous*[SIZE_OOM_ARR];
    for (i = 0; i < SIZE_OOM_ARR; i++) {
        e[i] = new (std::nothrow) enormous;
        std::cout << "i: " << i << std::endl;
        if (e[i] == NULL) {
            std::cout << "new returned NULL" << std::endl;
            break;
        }
    }
    for (unsigned int j = 0; j <= i && j < SIZE_OOM_ARR; j++)
        delete e[j];
    delete[] e;

    IF_UNIX_ELSE(int *, char *) *p =
        new (std::nothrow) IF_UNIX_ELSE(int *, char *)[SIZE_OOM_ARR];
    for (i = 0; i < SIZE_OOM_ARR; i++) {
        p[i] = new (std::nothrow) IF_UNIX_ELSE(int, char)[SIZE_OOM];
        if (p[i] == NULL) {
            std::cout << "new[] returned NULL" << std::endl;
            break;
        }
    }
    for (unsigned int j = 0; j <= i && j < SIZE_OOM_ARR; j++)
        delete[] p[j];
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
        // gcc 7.3+ forces us to use the new smaller SIZE_OOM/2 for 32-bit,
        // but that causes 64-bit to take forever here so we up it.
#ifdef X64
        // We indirect through a variable for a larger size to avoid taking forever.
        size_t count = 0x7ffffffffffff;
        hasdtr *lots = new hasdtr[count];
#else
        hasdtr *lots = new hasdtr[IF_UNIX_ELSE(SIZE_OOM/2,SIZE_OOM/sizeof(hasdtr))];
#endif
        lots[0].y = 4;
    } catch (std::bad_alloc&) {
        std::cout << "caught bad_alloc" << std::endl;
    }
}

int
main()
{
    test_placement();

    test_nothrow();

    // This one won't return under Dr. Memory!
    test_throw();

    std::cout << "all done" << std::endl;
    return 0;
}
