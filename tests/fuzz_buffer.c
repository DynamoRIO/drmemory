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

/* Test of the Dr. Memory Fuzz Testing Feature */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef WINDOWS
# define EXPORT __declspec(dllexport)
#else
# define EXPORT
#endif

#define BUFFER_ELEMENTS 4
#define ELEMENT_SIZE (sizeof(unsigned int))

typedef unsigned int uint;

typedef enum _bool {
    false,
    true
} bool;

typedef struct _deliberate_errors_t {
    bool overread;
    bool underread;
    bool overwrite;
    bool underwrite;
    bool leak;
    uint fuzz_iteration;
} deliberate_errors_t;

static deliberate_errors_t deliberate_errors;

/* print the contents of the buffer as unsigned integers */
EXPORT void
repeatme(uint *buffer, size_t size)
{
    uint i, elements = (size / ELEMENT_SIZE);

    printf("Buffer:");
    for (i = 0; i < elements; i++)
        printf(" 0x%x", buffer[i]);
    printf("\n");

    if ((++deliberate_errors.fuzz_iteration % 2) == 0) {
        if (deliberate_errors.overread)
            printf("over-read: %d\n", buffer[elements + 1]);
        if (deliberate_errors.underread)
            printf("under-read: %d\n", *(buffer - 1));
        if (deliberate_errors.overwrite) {
            buffer[elements] = 7;
        }
        if (deliberate_errors.underwrite)
            *(buffer - 1) = 7;
    }
}

int
main(int argc, char **argv)
{
    uint i, size = BUFFER_ELEMENTS * ELEMENT_SIZE, *buffer = malloc(size);

    if (argc > 1 && strcmp(argv[1], "initialize") == 0) {
        for (i = 0; i < BUFFER_ELEMENTS; i++)
            buffer[i] = (i + 1);
    }

    if (argc > 2) {
        if (strcmp(argv[2], "overread") == 0)
            deliberate_errors.overread = true;
        else if (strcmp(argv[2], "underread") == 0)
            deliberate_errors.underread = true;
        else if (strcmp(argv[2], "overwrite") == 0)
            deliberate_errors.overwrite = true;
        else if (strcmp(argv[2], "underwrite") == 0)
            deliberate_errors.underwrite = true;
        else if (strcmp(argv[2], "leak") == 0)
            deliberate_errors.leak = true;
    }

    repeatme(buffer, size);

    if (!deliberate_errors.leak)
        free(buffer);

    printf("done\n");
    return 0;
}
