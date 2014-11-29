/* **********************************************************
 * Copyright (c) 2011 Google, Inc.  All rights reserved.
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

#include <sstream>

TEST(StlTests, ostringstreamTest) {
    // This is a known leak in xlocale internals, see
    // http://https://github.com/DynamoRIO/drmemory/issues/257
    std::ostringstream os;
    os << "BOO\n" << 1 << "\n";
}

TEST(StlTests, wostringstreamTest) {
    // This is a known leak in xlocale internals, see
    // http://https://github.com/DynamoRIO/drmemory/issues/257
    std::wostringstream wos;
    wos << L"BOO\n" << 1 << L"\n";
}

TEST(StlTests, istringstreamTest) {
    // There are two uninit errors from msvc:
    // - https://https://github.com/DynamoRIO/drmemory/issues/1155
    // - https://https://github.com/DynamoRIO/drmemory/issues/1474
    std::istringstream stream("0.25");
    float value;
    stream >> value;
    ASSERT_TRUE(!stream.fail());
    ASSERT_EQ(value, 0.25);
}
