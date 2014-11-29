/* **********************************************************
 * Copyright (c) 2011-2012 Google, Inc.  All rights reserved.
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
#include <iphlpapi.h>

#include "gtest/gtest.h"

#pragma comment(lib, "IPHLPAPI.lib")

TEST(IPHlpApiTests, GetAdaptersInfo) {
    // http://https://github.com/DynamoRIO/drmemory/issues/719
    IP_ADAPTER_INFO dummy;
    ULONG size = 0;  // force overflow
    ULONG res = GetAdaptersInfo(&dummy, &size);
    if (res != NO_ERROR) {
        ASSERT_EQ(ERROR_BUFFER_OVERFLOW, res)
            << "Failed to determine number of networks available.";

        char *buffer = new char[size];
        IP_ADAPTER_INFO *infos = (IP_ADAPTER_INFO*)buffer;
        res = GetAdaptersInfo(infos, &size);
        ASSERT_EQ(NO_ERROR, res);
        // Verify that we don't get uninits from using the outputs in
        // conditionals.
        if (size > 0) {
            MEMORY_BASIC_INFORMATION mbi;
            VirtualQuery(infos->Next, &mbi, sizeof(mbi));
        }
        delete [] buffer;
    } else {
        ASSERT_EQ(0, size)
            << "GetAdaptersInfo should only succeed when there are 0 adapters";
    }
}

