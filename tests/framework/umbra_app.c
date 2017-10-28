/* **********************************************************
 * Copyright (c) 2017 Google, Inc.  All rights reserved.
 * **********************************************************/

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

#ifndef ASM_CODE_ONLY /* C code ***********************************************/

#include <stdio.h>
#include <stdlib.h>

void asm_test(void);
#ifdef ARM
void asm_test_thumb(void);
#endif

int
main(int argc, char *argv[])
{
    asm_test();
#ifdef ARM
    asm_test_thumb();
#endif
    printf("TEST PASSED\n");
    return 0;
}

#else /* asm code *************************************************************/
#include "cpp2asm_defines.h"
#include "umbra_test_shared.h"
START_FILE

#ifdef X64
# define FRAME_PADDING 8
#else
# define FRAME_PADDING 0
#endif

#ifdef ARM
.code 32 /* ARM */
#endif

#define FUNCNAME asm_test
        DECLARE_FUNC_SEH(FUNCNAME)
GLOBAL_LABEL(FUNCNAME:)
#ifdef X86
        /* push callee-saved registers */
        PUSH_SEH(REG_XBX)
        PUSH_SEH(REG_XBP)
        PUSH_SEH(REG_XSI)
        PUSH_SEH(REG_XDI)
        sub      REG_XSP, FRAME_PADDING /* align */
        mov      REG_XBP, REG_XSP
        sub      REG_XSP, 4
        END_PROLOG
        jmp      test1

        /* test 1 - write to memory */
     test1:
        mov      REG_XDI, UMBRA_TEST_1_ASM
        mov      REG_XDI, UMBRA_TEST_1_ASM
        mov      [REG_XBP], REG_XDI

        jmp      test2

        /* test 2 - read from memory */
     test2:
        mov      REG_XDI, UMBRA_TEST_2_ASM
        mov      REG_XDI, UMBRA_TEST_2_ASM
        mov      REG_XDI, [REG_XBP]

        jmp      epilog

    epilog:
        mov      REG_XSP, REG_XBP
        add      REG_XSP, FRAME_PADDING /* make a legal SEH64 epilog */
        pop      REG_XDI
        pop      REG_XSI
        pop      REG_XBP
        pop      REG_XBX
        ret
#elif defined(ARM)
        push     {r4, r7, lr}
        sub      sp, sp, #4
        add      r7, sp, #0
        b        test1

        /* test 1 - write to memory */
     test1:
        movw     r4, UMBRA_TEST_1_ASM
        movw     r4, UMBRA_TEST_1_ASM
        str      r4, [r7]
        b        test2

        /* test 2 - read from memory */
     test2:
        movw     r4, UMBRA_TEST_2_ASM
        movw     r4, UMBRA_TEST_2_ASM
        ldr      r4, [r7]
        b        epilog

    epilog:
        add      sp, sp, #4
        pop      {r4, r7, pc}
#endif /* ARM */
        END_FUNC(FUNCNAME)
#undef FUNCNAME

#ifdef ARM
.code 16 /* Thumb */
#define FUNCNAME asm_test_thumb
        DECLARE_FUNC(FUNCNAME)
GLOBAL_LABEL(FUNCNAME:)
        push     {r4, r7, lr}
        sub      sp, sp, #4
        add      r7, sp, #0
        b        test3

        /* test 1 - write to memory */
     test3:
        movw     r4, UMBRA_TEST_1_ASM
        movw     r4, UMBRA_TEST_1_ASM
        str      r4, [r7]
        b        test4

        /* test 2 - read from memory */
     test4:
        movw     r4, UMBRA_TEST_2_ASM
        movw     r4, UMBRA_TEST_2_ASM
        ldr      r4, [r7]
        b        epilog2

   epilog2:
        add      sp, sp, #4
        pop      {r4, r7, pc}
        END_FUNC(FUNCNAME)
#undef FUNCNAME
#endif /* ARM */

END_FILE
#endif
