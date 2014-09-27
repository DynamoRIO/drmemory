/* **********************************************************
 * Copyright (c) 2010-2014 Google, Inc.  All rights reserved.
 * Copyright (c) 2010 VMware, Inc.  All rights reserved.
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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#ifdef WINDOWS
# include <windows.h>
#else
# include <pthread.h>
#endif

#define NUM_THREADS 8

/* Test realloc races (i#69) */

#ifdef WINDOWS
DWORD WINAPI
#else
void *
#endif
thread_func(void *arg)
{
    void *ptr = NULL;
    int i;
    for (i = 8; i < 128; i++) {
        int size = (1 << (i / 8)) - 1;
        ptr = realloc(ptr, size);
        if (ptr == NULL) {
            fprintf(stderr, "realloc failed\n");
            exit(1);
        }
        memset(ptr, 42, size);
    }
    free(ptr);
    return 0;
}

int main()
{
    int i;
#ifdef WINDOWS
    HANDLE thread[NUM_THREADS];
    for (i = 0; i < NUM_THREADS; i++) {
        thread[i] = CreateThread(NULL, 0, thread_func, NULL, 0, 0);
        if (thread[i] == NULL) {
            fprintf(stderr, "CreateThread failed\n");
            exit(1);
        }
    }
    for (i = 0; i < NUM_THREADS; i++)
        WaitForSingleObject(thread[i], INFINITE);
#else
    pthread_t thread[NUM_THREADS];
    for (i = 0; i < NUM_THREADS; i++) {
        if (pthread_create(&thread[i], NULL, thread_func, (void *)(intptr_t)i) != 0) {
            fprintf(stderr, "pthread_create failed\n");
            exit(1);
        }
    }
    for (i = 0; i < NUM_THREADS; i++) {
        void *retval;
        if (pthread_join(thread[i], &retval) != 0) {
            fprintf(stderr, "pthread_join failed\n");
            exit(1);
        }
    }
#endif
    printf("success\n");
    return 0;
}
