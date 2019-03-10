/* **********************************************************
 * Copyright (c) 2014-2019 Google, Inc.  All rights reserved.
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
void asm_test_avx(char *undef, char *def);
void asm_test_i1680(char *buf);
void asm_test_reach(void);

static void
asm_test_C(void)
{
    char undef[256];
    char def[256] = {0,};
    asm_test(undef, def);
    asm_test_avx(undef, def);
    asm_test_i1680(def);
    asm_test_reach();
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
        DECLARE_FUNC_SEH(FUNCNAME)
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
        pxor     xmm1, xmm1
        mov      ecx, DWORD [REG_XDX] /* def */
        pinsrd   xmm0, ecx, 0
        pinsrd   xmm0, ecx, 1
        comisd   xmm0, xmm1 /* only looks at bottom 64 bits */

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

        movdqu   xmm0, [REG_XAX] /* undef */
        mov      ecx, DWORD [REG_XDX] /* def */
        pinsrd   xmm0, ecx, 0
        shufps   xmm0, xmm0, 0 /* bottom 4 bytes fill the whole thing */
        pextrw   ecx, xmm0, 7
        cmp      ecx, HEX(4)

        /* test unusual stack adjustments such as i#1500 */
        mov      REG_XCX, REG_XSP
        sub      REG_XCX, 16
        push     REG_XCX
        pop      REG_XSP
        mov      REG_XCX, PTRSZ [REG_XCX] /* unaddr if doesn't track "pop xsp" */
        add      REG_XSP, 16

        /* test pop into (esp) for i#1502 */
        push     REG_XCX
        push     REG_XCX
        pop      PTRSZ [REG_XSP]
        pop      REG_XCX

        /* test pop into (esp) for i#1502 */
        push     REG_XDX
        push     REG_XBX
        mov      edx, DWORD [REG_XAX] /* undef */
        or       ecx, HEX(28)
        mov      ebx, DWORD [REG_XAX + 4] /* undef */
        and      ebx, HEX(FFFFFF00)
        and      edx, HEX(C0014000)
        shl      ecx, HEX(B)
        or       ecx, edx
        cmp      ecx, 0
        cmp      ebx, 0
        pop      REG_XBX
        pop      REG_XDX

        /* test 4-byte div: really we want to ensure on fastpath (i#1573), but
         * how???
         */
        push     REG_XDX
        push     REG_XAX
        mov      ecx, DWORD [REG_XDX] /* def */
        mov      edx, DWORD [REG_XDX] /* def */
        div      DWORD [REG_XSP] /* 3 srcs and 2 dsts */
        cmp      eax,0 /* NOT uninit */
        cmp      edx,0 /* NOT uninit */
        pop      REG_XAX
        pop      REG_XDX

        /* Test i#1590 where whole-bb scratch regs conflict with sharing on
         * sub-dword instrs.  We need a bb with scratch ecx and eax.
         */
        jmp force_bb_i1590
    force_bb_i1590:
        cmp      BYTE [2 + REG_XDX], 0
        cmp      BYTE [3 + REG_XDX], 0
        test     dl, dl
        test     bl, bl
        jmp force_bb_i1590_end
    force_bb_i1590_end:

        /* Test i#1595: arrange for xl8 sharing with a 3rd scratch reg
         * to ensure we restore it properly.
         */
        jmp force_bb_i1595
    force_bb_i1595:
        /* Get ebx and ecx as scratch to ensure we share (xref i#1590) and
         * get edx as 3rd scratch so we crash if we mess it up.
         */
        mov      REG_XCX, REG_XAX
        mov      REG_XAX, REG_XAX
        cmp      BYTE [4 + REG_XDX], 0
        cmp      BYTE [5 + REG_XDX], 0
        jmp force_bb_i1595_end
    force_bb_i1595_end:

        /***************************************************
         * Test i#1484: packed shifts
         */

        /* packed word shift right */
        movdqu   xmm0, [REG_XAX] /* undef */
        pxor     xmm1, xmm1
        mov      ecx, 8
        pinsrd   xmm1, ecx, 0 /* shift amount: 8 */
        psrlw    xmm0, xmm1
        pextrb   ecx, xmm0, 15 /* top byte was undef, now 0's shifted in */
        cmp      ecx, HEX(40)

        /* packed word shift left */
        movdqu   xmm0, [REG_XAX] /* undef */
        pxor     xmm1, xmm1
        mov      ecx, 8
        pinsrd   xmm1, ecx, 0 /* shift amount: 8 */
        psllw    xmm0, xmm1
        pextrb   ecx, xmm0, 14 /* bottom of top word was undef, now 0's */
        cmp      ecx, HEX(41)

        /* packed dword shift right */
        movdqu   xmm0, [REG_XAX] /* undef */
        pxor     xmm1, xmm1
        mov      ecx, 16
        pinsrd   xmm1, ecx, 0 /* shift amount: 16 */
        psrld    xmm0, xmm1
        pextrw   ecx, xmm0, 7 /* top word was undef, now 0's shifted in */
        cmp      ecx, HEX(42)

        /* packed dword shift left */
        movdqu   xmm0, [REG_XAX] /* undef */
        pxor     xmm1, xmm1
        mov      ecx, 16
        pinsrd   xmm1, ecx, 0 /* shift amount: 16 */
        pslld    xmm0, xmm1
        pextrw   ecx, xmm0, 6 /* bottom of top dword was undef, now 0's */
        cmp      ecx, HEX(43)

        /* packed qword shift right */
        movdqu   xmm0, [REG_XAX] /* undef */
        pxor     xmm1, xmm1
        mov      ecx, HEX(9)
        pinsrd   xmm1, ecx, 0 /* shift amount: 0x1001 */
        pinsrd   xmm1, ecx, 1 /* shift amount: 0x100100001001 */
        psrlq    xmm0, xmm1
        pextrb   ecx, xmm0, 15 /* top byte was undef, now 1 0 bit */
        cmp      ecx, HEX(44) /* XXX: if we had per-bit this would be undef */

        /* packed mmx dword shift right */
        movq     mm0, [REG_XAX] /* undef */
        pxor     mm1, mm1
        mov      ecx, 16
        movd     mm1, ecx /* shift amount: 16 */
        psrld    mm0, mm1
        pextrw   ecx, mm0, 3 /* top byte was undef, now 0's shifted in */
        cmp      ecx, HEX(45)

        /* packed dqword shift left */
        movdqu   xmm0, [REG_XAX] /* undef */
        mov      ecx, HEX(0) /* def */
        pinsrb   xmm0, ecx, 5
        pslldq   xmm0, 1
        pextrb   ecx, xmm0, 6
        cmp      ecx, HEX(46)
        pextrb   ecx, xmm0, 0 /* filled with zeroes */
        cmp      ecx, HEX(47)

        /***************************************************
         * Test i#1484: conversions
         */

        /* an expanding conversion */
        movdqu   xmm0, [REG_XAX] /* undef */
        cvtpi2pd xmm0, QWORD [REG_XDX]
        pextrw   ecx, xmm0, 7
        cmp      ecx, HEX(46)

        /* XXX: add more conversion tests */

        /***************************************************
         * Test xlat, w/ live flags
         */
        jmp      xlat_test
    xlat_test:
        push     REG_XBX
        mov      REG_XBX, REG_XAX /* preserve */
        xlat
        mov      REG_XAX, REG_XBX
        pop      REG_XBX
        jmp      post_xlat_test
    post_xlat_test:

        /***************************************************
         * Test i#1870: xl8 sharing with a modrm nop
         */
        jmp      al_test
    al_test:
        push     REG_XBX
        push     REG_XAX
        mov      REG_XBX, REG_XSP
        mov      eax, DWORD [REG_XBX]
        nop      DWORD [REG_XBX]
        mov      al, BYTE [REG_XSP]
        test     al, al
        movsx    eax, al
        jmp      post_al_test
    post_al_test:
        pop      REG_XAX
        pop      REG_XBX

#ifdef X64
        /***************************************************
         * Test the top 32 bits being auto-defined.
         */
        jmp      top32_test
    top32_test:
        mov      r11d, DWORD [REG_XAX] /* undef */
        shr      r11, 32
        cmp      r11, 0
        jne      top32_never_happens
        nop
    top32_never_happens:
        nop
#endif

        /***************************************************
         * XXX: add more tests here.  Avoid clobbering eax (holds undef mem) or
         * edx (holds def mem).  Do not place AVX instructions here: put them
         * into asm_test_avx().
         */

        add      REG_XSP, 0 /* make a legal SEH64 epilog */
        mov      REG_XSP, REG_XBP
        pop      REG_XBP
        ret
        END_FUNC(FUNCNAME)
#undef FUNCNAME


#define FUNCNAME asm_test_avx
/* void asm_test_avx(char *undef, char *def); */
        DECLARE_FUNC_SEH(FUNCNAME)
GLOBAL_LABEL(FUNCNAME:)
        mov      REG_XAX, ARG1
        mov      REG_XDX, ARG2
        push     REG_XBP
        mov      REG_XBP, REG_XSP
        END_PROLOG

        /* i#1577: only run AVX instructions on processors that support them */
        push     REG_XAX
        push     REG_XDX
        mov      eax, 1
        cpuid
#       define HAS_AVX 28
        mov      edx, 1
        shl      edx, HAS_AVX
        test     edx, ecx
        pop      REG_XDX
        pop      REG_XAX
        je       no_avx

        movdqu   xmm0, [REG_XAX] /* undef */
        pxor     xmm1, xmm1
        mov      ecx, DWORD [REG_XDX] /* def */
        vpinsrd  xmm0, xmm0, ecx, 0 /* test vpinsrd (i#1559) */
        comiss   xmm0, xmm1 /* only looks at bottom 32 bits */

        /***************************************************
         * Test i#1484: AVX packed shifts
         */

        /* packed word shift right */
        movdqu   xmm0, [REG_XAX] /* undef */
        pxor     xmm1, xmm1
        mov      ecx, 8
        pinsrd   xmm1, ecx, 0 /* shift amount: 8 */
        vpsrlw   xmm0, xmm0, xmm1
        pextrb   ecx, xmm0, 15 /* top byte was undef, now 0's shifted in */
        cmp      ecx, HEX(40)

        /* packed word shift left */
        movdqu   xmm0, [REG_XAX] /* undef */
        pxor     xmm1, xmm1
        mov      ecx, 8
        pinsrd   xmm1, ecx, 0 /* shift amount: 8 */
        vpsllw   xmm0, xmm0, xmm1
        pextrb   ecx, xmm0, 14 /* bottom of top word was undef, now 0's */
        cmp      ecx, HEX(41)

        /* VS2010 assembler has a bug where "vpsrld" is encoded as "vpslld" */
# if MSC_VER >= 1700
        /* packed dword shift right */
        movdqu   xmm0, [REG_XAX] /* undef */
        pxor     xmm1, xmm1
        mov      ecx, 16
        pinsrd   xmm1, ecx, 0 /* shift amount: 16 */
        vpsrld   xmm0, xmm0, xmm1
        pextrw   ecx, xmm0, 7 /* top word was undef, now 0's shifted in */
        cmp      ecx, HEX(42)
# endif

        /* packed dword shift left */
        movdqu   xmm0, [REG_XAX] /* undef */
        pxor     xmm1, xmm1
        mov      ecx, 16
        pinsrd   xmm1, ecx, 0 /* shift amount: 16 */
        vpslld   xmm0, xmm0, xmm1
        pextrw   ecx, xmm0, 6 /* bottom of top dword was undef, now 0's */
        cmp      ecx, HEX(43)

        /* XXX: once we propagate ymm regs, add tests here */

        /***************************************************
         * XXX: add more tests here.  Avoid clobbering eax (holds undef mem) or
         * edx (holds def mem).
         */

     no_avx:
        add      REG_XSP, 0 /* make a legal SEH64 epilog */
        mov      REG_XSP, REG_XBP
        pop      REG_XBP
        ret
        END_FUNC(FUNCNAME)
#undef FUNCNAME


#define FUNCNAME asm_test_i1680
/* XXX: we want to test i#1680 but it's not yet clear how to make this trigger
 * the in-heap checks.  Naming as LdrShutdownProcess does not do it: may need
 * to be in a dll?  I'm waiting for more info on exactly why i#1680 is in-heap.
 */
/* void asm_test_i1680(char *buf); */
        DECLARE_FUNC_SEH(FUNCNAME)
GLOBAL_LABEL(FUNCNAME:)
        mov      REG_XCX, ARG1
        push     REG_XBP
        mov      REG_XBP, REG_XSP
        END_PROLOG

        /* Ensure the processor supports AES */
        push     REG_XCX
        push     REG_XDX
#       define HAS_AES 25
        mov      eax, 1
        cpuid
        mov      edx, 1
        shl      edx, HAS_AES
        test     ecx, edx
        pop      REG_XDX
        pop      REG_XCX
        je       no_aes

        mov      eax, [REG_XCX]
        movd     xmm0, eax
        movsldup xmm0, xmm0
        aeskeygenassist xmm0, xmm0, 0
        movd     eax, xmm0
        mov      eax, [REG_XCX]

     no_aes:
        add      REG_XSP, 0 /* make a legal SEH64 epilog */
        mov      REG_XSP, REG_XBP
        pop      REG_XBP
        ret
        END_FUNC(FUNCNAME)
#undef FUNCNAME


#define FUNCNAME asm_test_reach
/* Tests i#2118 reachability. */
/* void asm_test_reach(); */
        DECLARE_FUNC_SEH(FUNCNAME)
GLOBAL_LABEL(FUNCNAME:)
        END_PROLOG
        mov      eax, 0
        movdqu   XMMWORD [8 + REG_XSP + REG_XAX], xmm0
        ret
        END_FUNC(FUNCNAME)
#undef FUNCNAME


END_FILE
#endif
