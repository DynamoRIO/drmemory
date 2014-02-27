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

#include "gtest/gtest.h"
#include <map>
#ifdef WIN32
# include <hash_map>
# include <hash_set>
# define STD_HASH stdext
#endif

TEST(FloatTests, CopyConstructor) {
    /* Test i#471/i#931 where copy constructors use "fld;fstp" to copy
     * float fields.
     */
    struct hasfloat {
        int x;
        float f;
        /* We need something that forces a copy constructor to be created.
         * A std::string does the trick.
         */
        std::string s;
    };
    hasfloat src;
    src.x = 4;
    /* This copy will do "fld;fstp" */
    hasfloat tocopy = src;
    printf("value is %d\n", tocopy.x); /* avoid optimizing away the copy */

    /* Same thing but with a double.  This is the only one that shows up
     * on Linux for me.  We need the more advanced heuristic from i#1453
     * as gcc has a mov in between that writes to the store's address base.
     */
    struct hasdouble {
        int x;
        double f;
        std::string s;
    };
    hasdouble src2;
    src2.x = 4;
    hasdouble tocopy2 = src2;
    printf("value is %d\n", tocopy2.x);
}

/* XXX: I tried to get this to build on Linux but failed so disabling.
 * I tried including <ext/hash_map> and <ext/hash_set> and
 * defining STD_HASH as __gnu_cxx.
 */
#ifdef WIN32
TEST(FloatTests, StdSwap) {
    /* Test i#931: std::swap<float> VS2010 false pos */
    typedef STD_HASH::hash_set<std::string> myset_t;
    myset_t myset;
    std::map<std::string, myset_t> mymap;
    myset.insert("test");
    mymap["foo"] = myset;
}
#endif
