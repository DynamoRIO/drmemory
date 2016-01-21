/* **********************************************************
 * Copyright (c) 2012-2016 Google, Inc.  All rights reserved.
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
#include <stdio.h>
#include <unistd.h>

#if defined(LINUX) && !defined(ANDROID)
TEST(FSTests, SyncFS){
    FILE *tempfile;
    tempfile = fopen("syncfs_test_file", "w");

    fprintf(tempfile, "this is a test for syncfs");

    int fd = fileno(tempfile);

    ASSERT_EQ(syncfs(fd), 0);

    fclose(tempfile);
    unlink("syncfs_test_file");
}
#endif
