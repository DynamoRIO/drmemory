/* **********************************************************
 * Copyright (c) 2011-2020 Google, Inc.  All rights reserved.
 * Copyright (c) 2009-2010 VMware, Inc.  All rights reserved.
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

#include <windows.h>
#include <process.h> /* for _beginthreadex */
#include <stdio.h>

#define NUM_THREADS 3

int WINAPI
run_and_exit_func(void *arg)
{
    MEMORY_BASIC_INFORMATION mbi;
    char *p = malloc(4);
    int i = (int)(intptr_t) arg;
    if (i == 0)
        *(p+5) = 3;
    else {
        if (*p == 'a')
            *p = 'b';
    }
    free(p);
    VirtualQuery(&mbi, &mbi, sizeof(mbi));
    Sleep(100);
    _endthreadex(0);  /* doesn't close thread handle */
    return 0;
}

int WINAPI
run_func(void *arg)
{
    MEMORY_BASIC_INFORMATION mbi;
    while (1) {
        /* make a syscall that DR intercepts to increase chance
         * of a racy crash
         */
        VirtualQuery(&mbi, &mbi, sizeof(mbi));
        Sleep(100);
    }
    _endthread(); /* closes the thread handle for us */
    return 0;
}

int
main()
{
    int i, tid;
    /* Keep these reachable so the handles don't count as leaks. */
    static HANDLE thread[NUM_THREADS];
    printf("Starting\n");
    /* make some threads that exit to test leaks, etc. */
    for (i = 0; i < NUM_THREADS; i++) {
        thread[i] = (HANDLE) _beginthreadex(NULL, 0, run_and_exit_func,
                                            (void*)(intptr_t)i, 0, &tid);
    }
    /* i#680: Wait for the first batch of threads to exit, or we may not catch
     * their errors before we exit.
     */
    for (i = 0; i < NUM_THREADS; i++) {
        WaitForSingleObject(thread[i], INFINITE);
        CloseHandle(thread[i]);
    }
    /* make some threads and then just exit the process while they're still
     * running to test exit races (PR 470957)
     */
    for (i = 0; i < NUM_THREADS; i++) {
        thread[i] = (HANDLE) _beginthreadex(NULL, 0, run_func, NULL, 0, &tid);
    }
    /* don't wait */
    printf("Exiting\n");
    return 0;
}
