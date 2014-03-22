/* **********************************************************
 * Copyright (c) 2014 Google, Inc.  All rights reserved.
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

#ifndef ASM_CODE_ONLY /* C code ***********************************************/

/* registers.c is getting large and unwieldy, with every change requiring
 * line# changes in registers.res.  This is essentially an app_suite asm
 * test, with no errors expected, making it easier to expand.
 */

#include <stdio.h>
#include <stdlib.h>

void asm_test(char *undef, char *def);

void
asm_test_C(void)
{
    char undef[128];
    char def[128] = {0,};
    asm_test(undef, def);
}

int
main(int argc, char *argv[])
{
    asm_test_C();

    printf("all done\n");
    return 0;
}

#else /* asm code *************************************************************/
#include "cpp2asm_defines.h"
START_FILE

#define FUNCNAME asm_test
/* void asm_test(char *undef, char *def); */
        DECLARE_FUNC(FUNCNAME)
GLOBAL_LABEL(FUNCNAME:)
        mov      REG_XAX, ARG1
        mov      REG_XDX, ARG2
        push     REG_XBP
        mov      REG_XBP, REG_XSP
        END_PROLOG

        /* ensure top zeroed bits from shr are defined, and test bswap */
        mov      ecx, DWORD [REG_XAX] /* undef */
        shr      ecx, 16
        bswap    ecx
        movzx    ecx, cx
        cmp      ecx, HEX(1)

        movdqu   xmm0, [REG_XAX] /* undef */
        mov      ecx, DWORD [REG_XAX] /* undef */
        pxor     xmm1, xmm1
        punpcklwd xmm0, xmm1
        pextrw   ecx, xmm0, 7 /* top word came from xmm1 so defined */
        cmp      ecx, HEX(2)

        movdqu   xmm0, [REG_XAX] /* undef */
        pxor     xmm1, xmm1
        mov      ecx, DWORD [REG_XDX] /* def */
        pinsrd   xmm0, ecx, 0
        comiss   xmm0, xmm1 /* only looks at bottom 32 bits */

        movdqu   xmm0, [REG_XAX] /* undef */
        mov      ecx, DWORD [REG_XAX] /* undef */
        pxor     xmm1, xmm1
        movlhps  xmm0, xmm1
        pextrw   ecx, xmm0, 7 /* word came from xmm1 so defined */
        cmp      ecx, HEX(3)

        movdqu   xmm0, [REG_XAX] /* undef */
        mov      ecx, DWORD [REG_XAX] /* undef */
        pxor     xmm1, xmm1
        movhlps  xmm0, xmm1
        pextrw   ecx, xmm0, 1 /* word came from xmm1 so defined */
        cmp      ecx, HEX(3)

        /* XXX: add more tests here */

        add      REG_XSP, 0 /* make a legal SEH64 epilog */
        mov      REG_XSP, REG_XBP
        pop      REG_XBP
        ret
        END_FUNC(FUNCNAME)
#undef FUNCNAME

END_FILE
#endif
