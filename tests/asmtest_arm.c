/* **********************************************************
 * Copyright (c) 2014-2016 Google, Inc.  All rights reserved.
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

/* This is essentially an app_suite asm test, with no errors expected,
 * making it easier to expand.
 */

#include <stdio.h>
#include <stdlib.h>

void asm_test(char *undef, char *def);
void asm_test_thumb(char *undef, char *def);

static void
asm_test_C(void)
{
    char undef[256];
    char def[256] = {0,};
    asm_test(undef, def);
    asm_test_thumb(undef, def);
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

.code 32 /* ARM */
#define FUNCNAME asm_test
/* void asm_test(char *undef, char *def); */
        DECLARE_FUNC(FUNCNAME)
GLOBAL_LABEL(FUNCNAME:)
        push     {r4, lr}

        /* test SIMD */
        sub      r2, sp, #64
        vstm     r2, {d25}
        vldm     r2, {d25}

        /* test sub-word */
        mov      r2, #0
        mov      r4, sp
        strb     r1, [r4, r2, lsl #2]

        /***************************************************
         * XXX: add more tests here.  Avoid clobbering r0 (holds undef mem) or
         * r1 (holds def mem).
         */

        pop      {r4, pc}
        END_FUNC(FUNCNAME)
#undef FUNCNAME

.code 16 /* Thumb */
#define FUNCNAME asm_test_thumb
/* void asm_test_thumb(char *undef, char *def); */
        DECLARE_FUNC(FUNCNAME)
        .thumb_func
GLOBAL_LABEL(FUNCNAME:)
        push     {r4, lr}

        /* test sub-word */
        mov      r2, #0
        mov      r4, sp
        /* ldrsh.w r1, [r3, r2, lsl #2]  (can't get it to assemble) */
        .short 0xf933
        .short 0x1022

        /***************************************************
         * XXX: add more tests here.  Avoid clobbering r0 (holds undef mem) or
         * r1 (holds def mem).
         */

        pop      {r4, pc}
        END_FUNC(FUNCNAME)
#undef FUNCNAME

END_FILE
#endif
