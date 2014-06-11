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

HANDLE hTimerRoutineDoneEvent;

VOID CALLBACK
TimerRoutine(PVOID lpParam, BOOLEAN TimerOrWaitFired)
{
    ASSERT_NE((PVOID)NULL, lpParam);
    ASSERT_EQ(0xC0DE, *(ULONG*)lpParam);
    SetEvent(hTimerRoutineDoneEvent);
}

TEST(NtExApiTest, NtSetTimer2) {
    HANDLE hTimer = NULL;
    ULONG arg = 0xC0DE;
    BOOL bResult = FALSE;
    DWORD dwWaitResult;

    hTimerRoutineDoneEvent = CreateEvent(NULL, TRUE, FALSE, NULL);
    ASSERT_NE((HANDLE)NULL, hTimerRoutineDoneEvent);

    /* NtSetTimer2 is used by CreateTimerQueueTimer in Win 8.1 */
    bResult = CreateTimerQueueTimer(&hTimer,
                                    NULL,
                                    (WAITORTIMERCALLBACK)TimerRoutine,
                                    &arg, /* Parameter */
                                    10,   /* DueTime in millseconds */
                                    0,    /* Period in millseconds */
                                    0     /* Flags */);
    ASSERT_NE(FALSE, bResult);

    dwWaitResult = WaitForSingleObject(hTimerRoutineDoneEvent, 1000 /* ms */);
    ASSERT_EQ(WAIT_OBJECT_0, dwWaitResult);

    CloseHandle(hTimerRoutineDoneEvent);
    bResult = DeleteTimerQueueTimer(NULL, hTimer, NULL);
    ASSERT_NE(FALSE, bResult);
}

TEST(NtExApiTest, NtCancelTimer2) {
    HANDLE hTimer = NULL;
    ULONG arg = 0xC0DE;
    BOOL bResult = FALSE;
    DWORD dwWaitResult;

    hTimerRoutineDoneEvent = CreateEvent(NULL, TRUE, FALSE, NULL);
    ASSERT_NE((HANDLE)NULL, hTimerRoutineDoneEvent);

    bResult = CreateTimerQueueTimer(&hTimer,
                                    NULL,
                                    (WAITORTIMERCALLBACK)TimerRoutine,
                                    &arg,  /* Parameter */
                                    10000, /* DueTime in millseconds */
                                    0,     /* Period in millseconds */
                                    0      /* Flags */);
    ASSERT_NE(FALSE, bResult);

    /* NtCancelTimer2 is used by CreateTimerQueueTimer in Win 8.1 */
    bResult = ChangeTimerQueueTimer(NULL, hTimer,
                                    100, /* DueTime in millseconds */
                                    0    /* Period in millseconds */);
    ASSERT_NE(FALSE, bResult);

    dwWaitResult = WaitForSingleObject(hTimerRoutineDoneEvent, 1000/* ms */);
    ASSERT_EQ(WAIT_OBJECT_0, dwWaitResult);

    CloseHandle(hTimerRoutineDoneEvent);
    bResult = DeleteTimerQueueTimer(NULL, hTimer, NULL);
    ASSERT_NE(FALSE, bResult);
}
