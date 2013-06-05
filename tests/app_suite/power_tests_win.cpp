/* **********************************************************
 * Copyright (c) 2013 Google, Inc.  All rights reserved.
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

#include "gtest/gtest.h"

#if (_WIN32_WINNT >= _WIN32_WINNT_WIN7) && (_MSC_VER > 1500)
TEST(PowerTest, PowerCreateRequest) {
    REASON_CONTEXT cxt;
    cxt.Version = POWER_REQUEST_CONTEXT_VERSION;
    /* Use the undocumented value seen in i#1247 */
    cxt.Flags = 0x80000000;
    HANDLE h = PowerCreateRequest(&cxt);
    EXPECT_NE(h, (HANDLE) NULL);
    CloseHandle(h);

    cxt.Version = POWER_REQUEST_CONTEXT_VERSION;
    cxt.Flags = POWER_REQUEST_CONTEXT_SIMPLE_STRING;
    cxt.Reason.SimpleReasonString = L"Power outage";
    h = PowerCreateRequest(&cxt);
    EXPECT_NE(h, (HANDLE) NULL);

    PowerSetRequest(h, PowerRequestAwayModeRequired);
    PowerClearRequest(h, PowerRequestAwayModeRequired);
    CloseHandle(h);

    cxt.Version = POWER_REQUEST_CONTEXT_VERSION;
    cxt.Flags = POWER_REQUEST_CONTEXT_DETAILED_STRING;
    LPWSTR array[] = {L"Reason1", L"Reason2"};
    /* Kind of bogus since we don't have real resource strings */
    cxt.Reason.Detailed.LocalizedReasonModule = GetModuleHandle("ntdll.dll");
    cxt.Reason.Detailed.LocalizedReasonId = 0;
    cxt.Reason.Detailed.ReasonStringCount = sizeof(array)/sizeof(array[0]);
    cxt.Reason.Detailed.ReasonStrings = array;
    h = PowerCreateRequest(&cxt);
    EXPECT_NE(h, (HANDLE) NULL);

    CloseHandle(h);
}
#endif
