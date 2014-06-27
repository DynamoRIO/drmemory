/* **********************************************************
 * Copyright (c) 2014 Google, Inc.  All rights reserved.
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

HANDLE timer_routine_done_event;

VOID CALLBACK
timer_routine(PVOID param, BOOLEAN timer_or_wait_fired)
{
    ASSERT_NE((PVOID)NULL, param);
    ASSERT_EQ(0xC0DE, *(ULONG*)param);
    SetEvent(timer_routine_done_event);
}

TEST(NtExApiTest, NtSetTimer2) {
    HANDLE timer = NULL;
    ULONG arg = 0xC0DE;
    BOOL result = FALSE;
    DWORD wait_result;

    timer_routine_done_event = CreateEvent(NULL, TRUE, FALSE, NULL);
    ASSERT_NE((HANDLE)NULL, timer_routine_done_event);

    /* NtSetTimer2 is used by CreateTimerQueueTimer in Win 8.1 */
    result = CreateTimerQueueTimer(&timer,
                                    NULL,
                                    (WAITORTIMERCALLBACK)timer_routine,
                                    &arg, /* Parameter */
                                    10,   /* DueTime in millseconds */
                                    0,    /* Period in millseconds */
                                    0     /* Flags */);
    ASSERT_NE(FALSE, result);

    wait_result = WaitForSingleObject(timer_routine_done_event, 1000 /* ms */);
    ASSERT_EQ(WAIT_OBJECT_0, wait_result);

    CloseHandle(timer_routine_done_event);
    result = DeleteTimerQueueTimer(NULL, timer, INVALID_HANDLE_VALUE);
    ASSERT_NE(FALSE, result);
}

TEST(NtExApiTest, NtCancelTimer2) {
    HANDLE timer = NULL;
    ULONG arg = 0xC0DE;
    BOOL result = FALSE;
    DWORD wait_result;

    timer_routine_done_event = CreateEvent(NULL, TRUE, FALSE, NULL);
    ASSERT_NE((HANDLE)NULL, timer_routine_done_event);

    result = CreateTimerQueueTimer(&timer,
                                    NULL,
                                    (WAITORTIMERCALLBACK)timer_routine,
                                    &arg,  /* Parameter */
                                    10000, /* DueTime in millseconds */
                                    0,     /* Period in millseconds */
                                    0      /* Flags */);
    ASSERT_NE(FALSE, result);

    /* NtCancelTimer2 is used by CreateTimerQueueTimer in Win 8.1 */
    result = ChangeTimerQueueTimer(NULL, timer,
                                    100, /* DueTime in millseconds */
                                    0    /* Period in millseconds */);
    ASSERT_NE(FALSE, result);

    wait_result = WaitForSingleObject(timer_routine_done_event, 1000 /* ms */);
    ASSERT_EQ(WAIT_OBJECT_0, wait_result);

    CloseHandle(timer_routine_done_event);
    result = DeleteTimerQueueTimer(NULL, timer, INVALID_HANDLE_VALUE);
    ASSERT_NE(FALSE, result);
}
