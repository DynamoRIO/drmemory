/* **************************************************************
 * Copyright (c) 2016 Google, Inc.  All rights reserved.
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

/* Test of the Dr. Memory Fuzz Corpus Feature */

#include <stdio.h>
#include <stdlib.h>

#ifdef WINDOWS
# define EXPORT __declspec(dllexport)
#else
# define EXPORT
#endif

#define NUM_ENTRIES 2
#define BUF_SIZE    (NUM_ENTRIES * sizeof(int))

static int found_1, found_2, found_3;

/* using default fuzz function name */
EXPORT int
DrMemFuzzFunc(int *buf, int size)
{
    if (buf[0] == 1)
        found_1 = 1;
    else if (buf[0] == 2)
        found_2 = 1;
    else if (buf[0] == 3)
        found_3 = 1;
    else {
        printf("buf[0] is %d\n", buf[0]);
        return 1;
    }
    return 0;
}

int
main(int argc, char **argv)
{
    int *buf = (int *)malloc(BUF_SIZE);
    /* use function pointer and conditional assignment to avoid inlining */
    int (*func_ptr)(int *, int) = argc > 2 ? NULL : &DrMemFuzzFunc;
    if (func_ptr(buf, BUF_SIZE) == 1)
        return 0;
    if (!found_1 || !found_2 || !found_3) {
        printf("Error: some value was not seen\n");
        return 0;
    }
    free(buf);
    printf("all done\n");
    return 0;
}
