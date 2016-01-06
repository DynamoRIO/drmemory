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
#define ELEMENT_SIZE (sizeof(uint))

typedef unsigned int uint;

class BufferPrinter;

class DeliberateErrors {
    friend class BufferPrinter;

    public:
        DeliberateErrors(const char *deliberate_error);

    private:
        bool uninit;
        bool overread;
        bool underread;
        bool overwrite;
        bool underwrite;
        bool leak;
        uint fuzz_iteration;
};

class BufferPrinter {

    public:
        /* print the contents of the buffer as unsigned integers */
        EXPORT void
        repeatme(uint *buffer, size_t size);

        BufferPrinter(const char *deliberate_error);

        ~BufferPrinter();

    private:
        DeliberateErrors *deliberate_errors;
};

BufferPrinter::BufferPrinter(const char *deliberate_error)
{
    deliberate_errors = new DeliberateErrors(deliberate_error);
}

BufferPrinter::~BufferPrinter()
{
    if (!deliberate_errors->leak)
        delete deliberate_errors;
}

EXPORT void
BufferPrinter::repeatme(uint *buffer, size_t size)
{
    uint i = 0, elements = (size / ELEMENT_SIZE);

    if (deliberate_errors->uninit) {
        uint val;
        for (i = 0; i < elements; i++) {
            /* buffer value should have at most one bit set */
            val = buffer[i] & (buffer[i] - 1);
            if (val != 0)
                printf("Error: mutator flipped too many bits: %u!\n", val);
        }
    } else {
        printf("Buffer:");
        for (i = 0; i < elements; i++)
            printf(" 0x%08x", buffer[i]);
        printf("\n");
    }

    if ((++deliberate_errors->fuzz_iteration % 2) == 0) {
        if (deliberate_errors->overread)
            printf("over-read: %d\n", buffer[elements + 1]);
        if (deliberate_errors->underread)
            printf("under-read: %d\n", *(buffer - 1));
        if (deliberate_errors->overwrite)
            buffer[elements] = 7;
        if (deliberate_errors->underwrite)
            *(buffer - 1) = 7;
    }
}

DeliberateErrors::DeliberateErrors(const char *deliberate_error)
{
    this->uninit = (strcmp(deliberate_error, "uninit") == 0);
    this->overread = (strcmp(deliberate_error, "overread") == 0);
    this->underread = (strcmp(deliberate_error, "underread") == 0);
    this->overwrite = (strcmp(deliberate_error, "overwrite") == 0);
    this->underwrite = (strcmp(deliberate_error, "underwrite") == 0);
    this->leak = (strcmp(deliberate_error, "leak") == 0);
    this->fuzz_iteration = 0;
}

int
main(int argc, char **argv)
{
    uint i, size = BUFFER_ELEMENTS * ELEMENT_SIZE, *buffer = new uint[BUFFER_ELEMENTS];
    /* assuming argv[1] must be "initialize" if exists */
    const char *deliberate_error = (argc > 2 ? argv[2] : (argc > 1 ? "" : "uninit"));
    BufferPrinter bp(deliberate_error);

    if (argc > 1) {
        /* argv[1] must be "initialize" */
        if (strcmp(argv[1], "initialize") != 0)
            return 1;
        for (i = 0; i < BUFFER_ELEMENTS; i++)
            buffer[i] = (i + 1);
    }

    bp.repeatme(buffer, size);

    delete [] buffer;

    printf("done\n");
    return 0;
}
