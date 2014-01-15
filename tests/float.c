/* **********************************************************
 * Copyright (c) 2013-2014 Google, Inc.  All rights reserved.
 * Copyright (c) 2009 VMware, Inc.  All rights reserved.
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
#include <assert.h>

int
main()
{
    char *p1;
    float f;
    double d;
    double da[2];
    int i;

    printf("testing floats on heap\n");
    p1 = (char *) malloc(64);
    f = *((float *)p1); /* error: uninitialized, but won't report until used */
    if (f < 0.f) /* use -> reported */
        d = 4.;
    /* For doubles Dr. Memory will report right away since no shadowing
     * of floating-point registers: except w/ the new i#471 heuristic we need
     * to add a use.
     */
    d = *((double *)(p1+8)); /* error: uninitialized */
    if (d < 0.) /* use -> reported */
        d = 4.;
    *((float*)(p1+16)) = 0.f;
    d = *((double *)(p1+16)); /* error: half uninitialized */
    if (d < 0.) /* use -> reported */
        d = 4.;
    *((float*)(p1+28)) = 0.f;
    d = *((double *)(p1+24)); /* error: other half uninitialized */
    if (d < 0.) /* use -> reported */
        d = 4.;
    /* test unaligned */
    d = *((double *)(p1+34)); /* error: uninitialized */
    if (d < 0.) /* use -> reported */
        d = 4.;
    free((void *)p1);

    printf("testing floats on stack\n");
    da[0] = 0.;
    i = 1; /* if we use da[1] cl identifies the bad read */
    if (da[i] < 0.f) /* error: uninitialized */
        d = 4.;

    printf("all done\n");
    return 0;
}
