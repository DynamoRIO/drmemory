/* **********************************************************
 * Copyright (c) 2010-2017 Google, Inc.  All rights reserved.
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

#include <stdio.h>
#include <stdlib.h>

int
main()
{
    /* test PR 576032's identification of direct vs indirect leaks
     * = is head pointer, - is mid-chunk pointer:
     *
     *       X===========
     *                  ||
     *                   V
     * A ==> B ==> C --> D
     *       |      \\=> E
     *       |       \-> F
     *       ----------/
     *
     * We expect reported:
     * 1) Leak pA + pB + pC + pE
     * 2) Possible leak pF
     * 3) Leak pX + pD
     * Note: I used to have pX=>pB to further test dup dependents, but
     * it's too difficult to control the ordering on all platforms.
     */
    char *pA, *pB, *pC, *pD, *pE, *pF, *pX;
    pA = malloc(sizeof(pA)*4);
    pB = malloc(sizeof(pB)*4);
    pC = malloc(sizeof(pC)*4);
    pD = malloc(sizeof(pD)*4);
    pE = malloc(sizeof(pE)*4);
    pF = malloc(sizeof(pF)*4);
    pX = malloc(sizeof(pX)*4);
    *((char **)pA) = pB;
    *((char **)pB) = pC;
    *((char **)(pB + sizeof(pB))) = pF + sizeof(pF);
    *((char **)pC) = pD + sizeof(pD);
    *((char **)(pC + sizeof(pC))) = pE;
    *((char **)(pC + 2*sizeof(pC))) = pF + sizeof(pF);
    *((char **)(pX + sizeof(pX))) = pD;

    printf("all done\n");
    return 0;
}
