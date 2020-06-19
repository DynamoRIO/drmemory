/* **************************************************************
 * Copyright (c) 2017-2020 Google, Inc.  All rights reserved.
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

#include <stdio.h>
#include <stdlib.h>

static void
print_64bit_range(unsigned long start, unsigned long end)
{
    printf("  [0x%08x'%08x, 0x%08x'%08x)\n",
           (int)(start>>32), (int)start, (int)(end>>32), (int)end);
}

static void
map(unsigned long start, unsigned long end,
    unsigned long mask, unsigned long offs,
    int scaleup, int scaledown,
    unsigned long *out_start, unsigned long *out_end)
{
    if (scaleup == 0) {
        *out_start =    ((start & mask) + (offs << scaledown)) >> scaledown;
        *out_end   = ((((end-1) & mask) + (offs << scaledown))+1) >> scaledown;
    } else {
        *out_start =    ((start & mask) + (offs >> scaleup)) << scaleup;
        *out_end   = ((((end-1) & mask) + (offs >> scaleup))+1) << scaleup;
    }
    if (*out_end < *out_start)
        printf("ERROR: end < start:\n");
}

static int
compare_ranges(unsigned long r1a, unsigned long r1b,
               unsigned long r2a, unsigned long r2b)
{
    if (r1a < r2b && r1b >= r2a) {
        printf("ERROR: overlap\n");
        return 0;
    }
    if (r1a > r1b || r2a > r2b)
        return 0;
    return 1;
}

static void
compute_scale(unsigned long app1a, unsigned long app1b,
              unsigned long app2a, unsigned long app2b,
              unsigned long mask, unsigned long offs,
              int scaleup, int scaledown)
{
    unsigned long sh1a, sh1b, sh2a, sh2b;
    map(app1a, app1b, mask, offs, scaleup, scaledown, &sh1a, &sh1b);
    map(app2a, app2b, mask, offs, scaleup, scaledown, &sh2a, &sh2b);
    printf(" shadow(app):\n");
    print_64bit_range(sh1a, sh1b);
    print_64bit_range(sh2a, sh2b);
    compare_ranges(sh1a, sh1b, app1a, app1b);
    compare_ranges(sh1a, sh1b, app2a, app2b);
    compare_ranges(sh2a, sh2b, app1a, app1b);
    compare_ranges(sh2a, sh2b, app2a, app2b);
    unsigned long ss1a, ss1b, ss2a, ss2b;
    map(sh1a, sh1b, mask, offs, scaleup, scaledown, &ss1a, &ss1b);
    map(sh2a, sh2b, mask, offs, scaleup, scaledown, &ss2a, &ss2b);
    printf(" shadow(shadow(app)):\n");
    print_64bit_range(ss1a, ss1b);
    print_64bit_range(ss2a, ss2b);
    if (compare_ranges(ss1a, ss1b, app1a, app1b) &&
        compare_ranges(ss1a, ss1b, app2a, app2b) &&
        compare_ranges(ss2a, ss2b, app1a, app1b) &&
        compare_ranges(ss2a, ss2b, app2a, app2b) &&
        compare_ranges(ss1a, ss1b, sh1a, sh1b) &&
        compare_ranges(ss1a, ss1b, sh2a, sh2b) &&
        compare_ranges(ss2a, ss2b, sh1a, sh1b) &&
        compare_ranges(ss2a, ss2b, sh2a, sh2b) &&
        compare_ranges(ss1a, ss1b, ss2a, ss2b))
        printf("SUCCESS\n");
}

int
main(int argc, const char *argv[])
{
    if (argc != 3) {
        fprintf(stderr, "Usage: %s <mask> <offs>\n", argv[0]);
        return 1;
    }
    unsigned long mask = strtol(argv[1], NULL, 16);
    unsigned long offs = strtol(argv[2], NULL, 16);
    unsigned long app1a =     0x00000000;
    unsigned long app1b = 0x030000000000;
    unsigned long app2a = 0x7c0000000000;
    unsigned long app2b = 0x800000000000;
    printf("&0x%08x'%08x +0x%08x'%08x)\n",
           (int)(mask>>32), (int)mask, (int)(offs>>32), (int)offs);
    printf("app:\n");
    print_64bit_range(app1a, app1b);
    print_64bit_range(app2a, app2b);
#if 0
    /* For i#2184: try to find an offs for up-2x. */
    printf("up 2x:\n");
    for (offs = 0x0000030000000000; offs < 0x0000700000000000; offs += 0x0000010000000000) {
        printf("\n---------------------\noffs = 0x%08x'%08x\n",
               (int)(offs>>32), (int)offs);
        compute_scale(app1a, app1b, app2a, app2b, mask, offs, 1, 0);
    }
#else
    printf("one-to-one:\n");
    compute_scale(app1a, app1b, app2a, app2b, mask, offs, 0, 0);
    printf("up 2x:\n");
    compute_scale(app1a, app1b, app2a, app2b, mask, offs, 1, 0);
    printf("down 2x:\n");
    compute_scale(app1a, app1b, app2a, app2b, mask, offs, 0, 1);
    printf("down 4x:\n");
    compute_scale(app1a, app1b, app2a, app2b, mask, offs, 0, 2);
    printf("down 8x:\n");
    compute_scale(app1a, app1b, app2a, app2b, mask, offs, 0, 3);
#endif
    return 0;
}
