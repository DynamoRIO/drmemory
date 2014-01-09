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

#include "gtest/gtest.h"
#include <windows.h>
#include <iostream>

// We use a separate helper to avoid compiler error C2712 with EXPECT and __try
// (EXPECT creates objects with destructors).
static bool
seh_helper(void)
{
    // Bit 28 is reserved and gets cleared so we don't use it.
    static const DWORD MY_CODE = 0xaebadbad;
    ULONG_PTR args[] = {1, 2, 3};
    EXCEPTION_RECORD er;
    // If we use EXPECT macros we fail to compile with C2712 so we
    // go with function-wide success.
    bool ok = true;
    // test EXCEPTION_EXECUTE_HANDLER
    __try {
        RaiseException(MY_CODE, 0, 3, args);
        // should not reach statement after exception
        ok = false;
    }
    __except (er = *(GetExceptionInformation())->ExceptionRecord,
              (er.ExceptionCode == MY_CODE &&
               er.NumberParameters == 3 &&
               er.ExceptionInformation[0] == args[0] &&
               er.ExceptionInformation[1] == args[1] &&
               er.ExceptionInformation[2] == args[2]) ?
              EXCEPTION_EXECUTE_HANDLER : EXCEPTION_CONTINUE_EXECUTION) {
        // should execute handler
    }
    // test EXCEPTION_CONTINUE_EXECUTION
    __try {
        RaiseException(MY_CODE, 0, 3, args);
        // should reach statement after 2nd exception
    }
    __except (er = *(GetExceptionInformation())->ExceptionRecord,
              (er.ExceptionCode == MY_CODE &&
               er.NumberParameters == 3 &&
               er.ExceptionInformation[0] == args[0] &&
               er.ExceptionInformation[1] == args[1] &&
               er.ExceptionInformation[2] == args[2]) ?
              EXCEPTION_CONTINUE_EXECUTION : EXCEPTION_EXECUTE_HANDLER) {
        // should not execute handler
        ok = false;
    }
    return ok;
}

TEST(SEHTests, RaiseException) {
    bool ok = seh_helper();
    EXPECT_TRUE(ok);
}
