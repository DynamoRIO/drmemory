/* **************************************************************
 * Copyright (c) 2015 Google, Inc.  All rights reserved.
 * **************************************************************/

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
 * * Neither the name of Google, Inc. nor the names of its contributors may be
 *   used to endorse or promote products derived from this software without
 *   specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL GOOGLE, INC. OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
 * CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH
 * DAMAGE.
 */

/* Test the Dr. Memory fuzzer on a multi-threaded app. */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <windows.h>
#include <process.h> /* for _beginthreadex */

#define NUM_THREADS 10
#define TEST_BUFFER "abcdefgh"
#define TEST_BUFFER_SIZE strlen(TEST_BUFFER)

typedef unsigned int uint;

void
print_buffer(byte *data, uint len, byte *counter)
{
    uint i;
    char *buf;

    /* call something heavy like malloc to encourage thread interleaving */
    buf = malloc((len * 2/*per byte*/) + 1/*null-term*/);

    for (i = 0; i < len; i++)
        sprintf(buf + (i*2), "%02x", data[i] + *counter);
    printf("%s\n", buf); /* print the whole line to avoid character interleaving */

    (*counter)++;
    free(buf);
}

int WINAPI
thread_main(void *arg)
{
    byte b = (byte) (intptr_t) arg;
    char *buffer = malloc(sizeof(TEST_BUFFER));

    strncpy(buffer, TEST_BUFFER, TEST_BUFFER_SIZE);
    print_buffer(buffer, TEST_BUFFER_SIZE, &b);

    free(buffer);
    return 0;
}

int
main(int argc, char **argv)
{
    int i, tid;
    HANDLE thread[NUM_THREADS];

    for (i = 0; i < NUM_THREADS; i++)
        thread[i] = (HANDLE) _beginthreadex(NULL, 0, thread_main, (void*)i, 0, &tid);

    for (i = 0; i < NUM_THREADS; i++) {
        WaitForSingleObject(thread[i], INFINITE);
        CloseHandle(thread[i]);
    }
    return 0;
}
