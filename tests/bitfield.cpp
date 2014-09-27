/* **********************************************************
 * Copyright (c) 2012-2014 Google, Inc.  All rights reserved.
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

#include <stdio.h>

typedef unsigned int uint;

struct bitfield {
    bitfield() : bits21_(0), bits1_(0) { }
    bitfield(uint bits21, bool bits1) : bits21_(bits21), bits1_(bits1) { }
    uint bits21_ : 21;
    bool bits1_ : 1;
};

extern "C" {
void bitfield_asm_test(char *undef, char *def);
}

static void
bitfield_asm_test_C(void)
{
    char undef[128];
    char def[128] = {0,};
    bitfield_asm_test(undef, def);
}

int
main(int argc, char *argv[])
{
    bitfield b1(argc, true);
    if (b1.bits21_ > 0)
        printf("correct\n");
    bitfield b2;
    if (b2.bits21_ == 0)
        printf("correct\n");

#ifdef BITFIELD_ASM
    bitfield_asm_test_C();
#endif

    printf("all done\n");
    return 0;
}

#else /* asm code *************************************************************/
#include "cpp2asm_defines.h"
START_FILE

#define FUNCNAME bitfield_asm_test
/* void bitfield_asm_test(char *undef, char *def); */
        DECLARE_FUNC_SEH(FUNCNAME)
GLOBAL_LABEL(FUNCNAME:)
        mov      REG_XAX, ARG1
        mov      REG_XDX, ARG2
        push     REG_XBP
        mov      REG_XBP, REG_XSP
        END_PROLOG

        /* test i#849-ish bitfield sequence for i#1520 */
        mov      ecx, DWORD [REG_XAX] /* undef */
        shr      ecx, HEX(1b)
        and      ecx, HEX(0f)
        mov      ecx, 0
        sete     cl
        cmp      eax,ecx

        /* test i#878-ish bitfield sequence for i#1520 */
        push     REG_XBX /* save callee-saved reg */
        mov      ecx, 0
        mov      cl, BYTE [REG_XAX] /* undef */
        push     REG_XCX /* set up undef memory we can write to */
        xor      cl, cl
        mov      bl, BYTE [REG_XSP] /* undef */
        xor      bl, cl
        and      bl, 1
        xor      bl, BYTE [REG_XSP]
        mov      BYTE [REG_XSP], bl
        test     bl, 1
        pop      REG_XBX
        pop      REG_XBX /* restore */

        /* test i#1520 bitfield sequence A */
        mov      ecx, DWORD [REG_XAX] /* undef */
        and      ecx, HEX(80000000)
        shr      ecx, HEX(11)
        test     cl, 1

        /* test i#1520 bitfield sequence B */
        mov      ecx, DWORD [REG_XAX] /* undef */
        and      ecx, HEX(f3009000)
        cmp      eax,ecx

        /* test i#1520 byte-aligned masks: we later decided to not tighten
         * the bitfield heuristics for whole-byte constants, but I'm leaving
         * this test in case we enable later.
         */
        mov      ecx, DWORD [REG_XAX] /* undef */
        and      ecx, HEX(ff00ff00)
        cmp      al,cl /* ok */
        cmp      ah,ch /* uninit -- but we disabled byte masks, so no error */
        mov      ecx, DWORD [REG_XAX] /* undef */
        and      ecx, HEX(ffff00ff)
        cmp      al,cl /* uninit -- but we disabled byte masks, so no error */
        cmp      ah,ch /* ok */
        mov      ecx, DWORD [REG_XAX] /* undef */
        and      ecx, HEX(ffffff00)
        cmp      al,cl /* ok */
        cmp      ah,ch /* uninit -- but we disabled byte masks, so no error */
        mov      ecx, DWORD [REG_XAX] /* undef */
        and      ecx, HEX(00ff0000)
        cmp      eax,ecx /* uninit -- but we disabled byte masks, so no error */
        /* test i#1576 */
        and      ecx, HEX(2)
        call     next_instr
    next_instr:
        test     ecx, HEX(1) /* uninit -- but we disabled byte masks, so no error */
        pop      REG_XCX

        /* test i#1523 double-xor */
        push     REG_XBX /* save callee-saved reg */
        push     REG_XSI /* save callee-saved reg */
        push     REG_XDI /* save callee-saved reg */
        push     REG_XDX /* save def ptr */
        mov      ebx, 0 /* used as 1st xor src for both */
        mov      dl, BYTE [REG_XAX] /* undef */
        mov      esi, DWORD [REG_XAX] /* undef */
        mov      cl, dl
        mov      edi, esi
        xor      cl, bl
        xor      edi, ebx
        and      cl, 1
        and      edi, HEX(1fffff)
        xor      dl, cl
        xor      esi, edi
        test     dl, 1
        test     esi, 1
        pop      REG_XDX /* restore */
        pop      REG_XDI /* restore */
        pop      REG_XSI /* restore */
        pop      REG_XBX /* restore */

        /* test i#1530 interrupted xor sequence */
        push     REG_XBX /* save callee-saved reg */
        movzx    ecx, BYTE [REG_XAX] /* undef */
        push     REG_XCX /* set up undef memory we can write to */
        xor      cl, BYTE [REG_XSP]
        and      cl, 1
        mov      bl, BYTE [REG_XAX] /* unrelated interrupting instr */
        xor      BYTE [REG_XSP], cl
        test     BYTE [REG_XSP], 1
        pop      REG_XBX
        pop      REG_XBX /* restore */

        /* test i#1542 interrupted xor sequence */
        push     REG_XBX /* save callee-saved reg */
        mov      cl, BYTE [REG_XAX] /* undef */
        xor      cl, BYTE [REG_XSP] /* assuming ebx is defined */
        and      cl, 1
        mov      BYTE [REG_XAX+2], 1 /* unrelated interrupting instr */
        xor      BYTE [REG_XAX], cl
        test     BYTE [REG_XAX], 1
        pop      REG_XBX /* restore */

        /* XXX: add more tests here.  Avoid clobbering eax (holds undef mem) or
         * edx (holds def mem).
         */

        add      REG_XSP, 0 /* make a legal SEH64 epilog */
        mov      REG_XSP, REG_XBP
        pop      REG_XBP
        ret
        END_FUNC(FUNCNAME)
#undef FUNCNAME

END_FILE
#endif
