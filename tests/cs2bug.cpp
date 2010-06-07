/* **********************************************************
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

#include <iostream>

class hasdtr {
public:
    hasdtr() { x = new int[7]; }
    ~hasdtr() { delete[] x; }
    int *x;
    int y;
    char z;
};

class parA {
public:
    parA() { a = "parA"; };
    virtual ~parA() {}
    virtual const char *getval() const { return a; }
    const char *a;
};

class parB {
public:
    parB() { b = "parB"; }
    virtual ~parB() {}
    virtual const char *getval() const { return b; }
    virtual const char *myfunc() const { return b; }
    const char *b;
};

class childAB : public parA, public parB {
public:
    childAB() { ab = "childAB"; }
    virtual ~childAB() {}
    virtual const char *getval() const { return ab; }
    const char *ab;
};

int main() 
{
    /* test mid-chunk std::string leak (PR 535344) */
    static std::string *str = new std::string("leak");
    std::cout << "size=" << str->size() <<
        " capacity=" << str->capacity() << std::endl;

    /* test mid-chunk pointer in leak due to new[] header (PR 484544)
     * (header is only present if class has destructor)
     */
    static hasdtr *leak = new hasdtr[4];
    leak[0].y = 0;

    /* test mid-chunk pointer in leak due to multiple inheritance by
     * casting to the 2nd of the two parent classes (PR 484544)
     */
    static parB *multi = (parB *) new childAB();
    std::cout << "getval: " << multi->getval() << std::endl;
    std::cout << "myfunc: " << multi->myfunc() << std::endl;

    /* uninit error */
    int *p = new int;
    if (*p != 10)
        std::cout << "hi" << std::endl;

    /* unaddr error */
    int *a = new int[3];
    /* on xp64x2cpu vm, w/ VS2005 SP1, heap assert fires: detects
     * the overflow if do a[3], so doing a[4], which is not detected.
     */
    a[4] = 12;
    delete a;
    
    std::cout << "bye" << std::endl;
}
