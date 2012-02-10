/* **********************************************************
 * Copyright (c) 2012 Google, Inc.  All rights reserved.
 * **********************************************************/

/* Dr. Memory: the memory debugger
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation;
 * version 2.1 of the License, and no later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * Library General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#include <windows.h>
#include <userenv.h>

#include "gtest/gtest.h"

// userenv.dll is required for CreateEnvironmentBlock().
#pragma comment(lib, "userenv.lib")

TEST(UserEnvTests, CreateEnvironmentBlock) {
    HANDLE token;
    void* enviroment_block = NULL;
    BOOL success;
    success = OpenProcessToken(GetCurrentProcess(), TOKEN_ALL_ACCESS, &token);
    ASSERT_TRUE(success) << "OpenProcessToken failed: " << GetLastError();
    success = CreateEnvironmentBlock(&enviroment_block, token, FALSE);
    ASSERT_TRUE(success) << "CreateEnvironmentBlock failed: " << GetLastError();
    DestroyEnvironmentBlock(enviroment_block);
}
