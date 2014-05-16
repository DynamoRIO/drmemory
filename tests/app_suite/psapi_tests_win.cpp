/* **********************************************************
 * Copyright (c) 2012-2014 Google, Inc.  All rights reserved.
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
#include <psapi.h>

#include "gtest/gtest.h"

/* FIXME: If we want this to work on Win2K, we'll have to use LoadLibrary and
 * GetProcAddress.
 */

#pragma comment(lib, "psapi.lib")

TEST(PsApiTest, GetPerformanceInfoTest) {
    PERFORMANCE_INFORMATION perf_info;
    GetPerformanceInfo(&perf_info, sizeof(perf_info));
}

TEST(PsApiTest, GetWorkingSetTest) {
    PSAPI_WORKING_SET_INFORMATION *buf = NULL;
    ULONG_PTR count = 0; /* first call will give us real count */
    DWORD rx_pages = 0;
    for (int iters = 0; iters < 5; iters++) {
        DWORD buf_sz = sizeof(PSAPI_WORKING_SET_INFORMATION) +
            (count * sizeof(PSAPI_WORKING_SET_BLOCK));
        buf = (PSAPI_WORKING_SET_INFORMATION *) realloc(buf, buf_sz);
        ASSERT_NE(buf, (PSAPI_WORKING_SET_INFORMATION *)NULL);

        if (QueryWorkingSet(GetCurrentProcess(), buf, buf_sz))
            break; /* we have the data */
        ASSERT_EQ(GetLastError(), ERROR_BAD_LENGTH);
        count = buf->NumberOfEntries * 2 /*handle new entries*/;
    }

    for (int i = 0; i < buf->NumberOfEntries; i++) {
        // There must be at least 1 rx page
        if (buf->WorkingSetInfo[i].Protection == 3/*rx*/)
            rx_pages++;
    }
    ASSERT_NE(rx_pages, 0);
    free(buf);
}
