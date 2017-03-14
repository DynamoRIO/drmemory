/* **********************************************************
 * Copyright (c) 2012-2017 Google, Inc.  All rights reserved.
 * Copyright (c) 2004 VMware, Inc.  All rights reserved.
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

/*
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * * Redistributions of source code must retain the above copyright notice,
 *   this list of conditions and the following disclaimer.
 *
 * * Redistributions in binary form must reproduce the above copyright notice,
 *   this list of conditions and the following disclaimer in the documentation
 *   and/or other materials provided with the distribution.
 *
 * * Neither the name of VMware, Inc. nor the names of its contributors may be
 *   used to endorse or promote products derived from this software without
 *   specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL VMWARE, INC. OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
 * CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH
 * DAMAGE.
 */

/* Based on DR's client.fibers.c */

#include "gtest/gtest.h"
#include <windows.h>
#include <ntverp.h>
#if VER_PRODUCTBUILD >= 9200 /* win8+ SDK */
# include "fibersapi.h"
#endif
#include "stdio.h"

static DWORD flsA_index;
static DWORD flsB_index;

static void WINAPI
fls_delete(void *fls_val)
{
    /* Called on DeleteFiber, thread exit, and FlsFree */
    EXPECT_TRUE(fls_val == (void *)(ULONG_PTR)0xdeadbeef ||
                fls_val == (void *)(ULONG_PTR)0x12345678);
}

static void WINAPI
run_fibers(void *arg)
{
    void *fiber_worker = GetCurrentFiber();
    void *fiber_main = arg;
    ASSERT_NE(FlsGetValue(flsA_index), arg);
    printf("in worker fiber\n");
    ASSERT_EQ(GetFiberData(), fiber_main);

    FlsSetValue(flsA_index, (void *)(ULONG_PTR)0xdeadbeef);
    FlsSetValue(flsB_index, (void *)(ULONG_PTR)0x12345678);
    ASSERT_EQ(FlsGetValue(flsA_index), (void *)(ULONG_PTR)0xdeadbeef);
    ASSERT_EQ(FlsGetValue(flsB_index), (void *)(ULONG_PTR)0x12345678);

    printf("back to main\n");
    SwitchToFiber(fiber_main);

    printf("in worker fiber again\n");
    ASSERT_EQ(FlsGetValue(flsA_index), (void *)(ULONG_PTR)0xdeadbeef);
    ASSERT_EQ(FlsGetValue(flsB_index), (void *)(ULONG_PTR)0x12345678);

    /* We have to switch back -- else the thread exits */
    printf("back to main\n");
    SwitchToFiber(fiber_main);
}

TEST(FiberTests, FlsAlloc) {
    int i;
    void *fiber_main, *fiber;

    fiber_main = ConvertThreadToFiber(NULL);
    printf("in main fiber\n");

    flsA_index = FlsAlloc(fls_delete);
    flsB_index = FlsAlloc(fls_delete);
    ASSERT_EQ(FlsGetValue(flsA_index), (void *)NULL);
    ASSERT_EQ(FlsGetValue(flsB_index), (void *)NULL);

    FlsSetValue(flsA_index, (void *)(ULONG_PTR)0x12345678);
    FlsSetValue(flsB_index, (void *)(ULONG_PTR)0xdeadbeef);
    ASSERT_EQ(FlsGetValue(flsA_index), (void *)(ULONG_PTR)0x12345678);
    ASSERT_EQ(FlsGetValue(flsB_index), (void *)(ULONG_PTR)0xdeadbeef);

    for (i = 0; i < 2; i++) {
        printf("creating worker fiber %d\n", i);
        fiber = CreateFiber(0, run_fibers, fiber_main);

        printf("switching to worker fiber first time\n");
        SwitchToFiber(fiber);
        ASSERT_EQ(FlsGetValue(flsA_index), (void *)(ULONG_PTR)0x12345678);
        ASSERT_EQ(FlsGetValue(flsB_index), (void *)(ULONG_PTR)0xdeadbeef);

        printf("switching to worker fiber second time\n");
        SwitchToFiber(fiber);
        ASSERT_EQ(FlsGetValue(flsA_index), (void *)(ULONG_PTR)0x12345678);
        ASSERT_EQ(FlsGetValue(flsB_index), (void *)(ULONG_PTR)0xdeadbeef);

        printf("deleting worker fiber %d\n", i);
        DeleteFiber(fiber);
    }

    printf("all done\n");
}

TEST(FiberTests, FlsCount) {
#   define FLS_COUNT 128
    DWORD idx[FLS_COUNT];
    int i;
    bool ran_out = false;
    for (i = 0; i < FLS_COUNT; i++) {
        idx[i] = FlsAlloc(fls_delete);
        /* We need to update FLS_MAX_COUNT in kernel32_proc.c if the max ever
         * goes up.  Several slots should already be taken by static libc.
         */
        if (!ran_out && idx[i] == FLS_OUT_OF_INDEXES)
            ran_out = true;
    }
    ASSERT_EQ(ran_out, true);
    for (i = 0; i < FLS_COUNT; i++) {
        if (idx[i] != FLS_OUT_OF_INDEXES)
            FlsFree(idx[i]);
    }
}
