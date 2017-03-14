/* **********************************************************
 * Copyright (c) 2011-2017 Google, Inc.  All rights reserved.
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

#ifndef ASM_CODE_ONLY /* C code ***********************************************/

#include <stdio.h>
#include <stdlib.h>

typedef unsigned char byte;

#ifdef UNIX
# include <stdint.h>
typedef intptr_t reg_t;
#else
# include <windows.h>
typedef INT_PTR reg_t;
typedef unsigned short ushort;
#endif

typedef struct _gpr_t {
    reg_t xflags;
    reg_t xax;
    reg_t xcx;
    reg_t xdx;
    reg_t xbx;
    reg_t xsp;
    reg_t xbp;
    reg_t xsi;
    reg_t xdi;
} gpr_t;

static int array[128];

/* asm routines
 * FIXME i#934: convert the rest of the inlined asm to cross-platform asm
 */
void float_test_asm(double *zero);
void regtest_asm(int array[128], gpr_t *gpr_pre, gpr_t *gpr_post);
void subdword_test2_asm(char *undef, int *val1, int *val2);
void addronly_test_asm(char *undef);
void subdword_test_asm(char *undef, int *val);
void repstr_test_asm(char *a1, char *a2);
void eflags_test_asm(char *undef);
void mem2mem_test_asm(int *array_uninit);
void cmpxchg8b_test_asm(int *array_init, int *array_uninit);
void and_or_test_asm(int *array_uninit, int *zero);
void nop_test_asm(void);
void test_stack_asm(void);

static void check_reg(reg_t pre, reg_t post, const char *name)
{
    if (pre != post) {
        printf("mismatch %s: 0x%08lx vs 0x%08lx\n", name,
               (unsigned long)pre, (unsigned long)post);
    }
}

static void
regtest(void)
{
    static gpr_t gpr_pre, gpr_post;
    printf("before regtest!\n"); /* using ! as workaround for i#625 */
    regtest_asm(array, &gpr_pre, &gpr_post);
    check_reg(gpr_pre.xdi, gpr_post.xdi, "xdi");
    check_reg(gpr_pre.xsi, gpr_post.xsi, "xsi");
    check_reg(gpr_pre.xbp, gpr_post.xbp, "xbp");
    check_reg(gpr_pre.xsp, gpr_post.xsp, "xsp");
    check_reg(gpr_pre.xbx, gpr_post.xbx, "xbx");
    check_reg(gpr_pre.xdx, gpr_post.xdx, "xdx");
    check_reg(gpr_pre.xcx, gpr_post.xcx, "xcx");
    check_reg(gpr_pre.xax, gpr_post.xax, "xax");
    printf("after regtest!\n");
}

void
subdword_test(void)
{
    /* source of uninits: on Windows a stack buffer is filled w/ 0xcc
     * in debug build (PR 473614) so we use malloc
     */
    char *undef = (char *) malloc(128);
    int val;
    printf("before subdword test!\n");
    subdword_test_asm(undef, &val); /* val is set uninit in subdword_test_asm */
    if (val == 0) /* uninit */
        array[0] = val;
    printf("after subdword test!\n");
    free(undef);
}

/* Tests PR 580123: add fastpath for rep string instrs */
void
repstr_test(void)
{
    char *undef = (char *) malloc(128);
    char *a1 = (char *) malloc(15);
    char *a2 = (char *) malloc(15);
    int i;
    for (i = 0; i < 15; i++) {
        /* leave one in the middle undef */
        if (i != 7)
            a1[i] = 0;
    }
    printf("before repstr test!\n");
    repstr_test_asm(a1, a2);
    printf("after repstr test!\n");
    free(undef);
}

/* Tests PR 425622: eflags shadow propagation */
void
eflags_test(void)
{
    char *undef_array = (char *) malloc(16);
    printf("before eflags test!\n");
    eflags_test_asm(undef_array);
    printf("after eflags test!\n");
    free(undef_array);
}

static void
mem2mem_test(void)
{
    int *array_uninit = malloc(16);
    mem2mem_test_asm(array_uninit);
    free(array_uninit);
}

static void
cmpxchg8b_test(void)
{
    int *array_uninit = malloc(8);
    int *array_init = calloc(8, 1);
    cmpxchg8b_test_asm(array_init, array_uninit);
    free(array_uninit);
    free(array_init);
}

static void
and_or_test(void)
{
    int *array_uninit = malloc(8);
    static int zero;
    and_or_test_asm(array_uninit, &zero);
    free(array_uninit);
}

static void
float_test(void)
{
    double val = 0.;
    /* test cvttsd2si (i#258, i#259, DRi#371) */
    float_test_asm(&val);
}

static void
subdword_test2(void)
{
    /* source of uninits: on Windows a stack buffer is filled w/ 0xcc
     * in debug build (PR 473614) so we use malloc
     */
    char *undef = (char *) malloc(128);
    int val1, val2;
    printf("before subdword test2!\n");
    subdword_test2_asm(undef, &val1, &val2);
    if (val1 == 0) /* NOT uninit */
        array[0] = val1;
    if (val2 == 0) /* uninit */
        array[0] = val2;
    printf("after subdword test2!\n");
    free(undef);
}

static void
addronly_test(void)
{
    /* test state restoration on ud2a fault path (in particular, i#533)
     * when run w/ -no_check_uninitialized
     */
    char unused[128]; /* i#624: shift in stack to avoid stale ptr for addronly */
    char *undef = (char *) malloc(128);
    unused[0] = 1;
    printf("before addronly test!\n");
    addronly_test_asm(undef);
    free(undef);
    printf("after addronly test!\n");
}

/* Tests weird nops with memory operands. */
static void
nop_test(void)
{
    nop_test_asm();
}

static void
multi_dst_test(void)
{
    /* try to avoid divide-by-zero by initializing our uninit */
    int *x = (int *) calloc(1, sizeof(int));
    free(x);
    x = (int *) malloc(sizeof(int));
    /* we trust this will have an idiv (i#1010) w/o needing to go to asm */
    if (100 / (*x + 1) > 100)
        *x = 4;
    free(x);
}

/* i#1127 */
static void
data16_div_test(void)
{
    /* Declare here to avoid disturbing line numbers. */
    unsigned short data16_div_test_asm(unsigned short a, unsigned short b);
    unsigned short res = data16_div_test_asm(10, 5);
    if (res != 2)
        printf("10 / 5 != 2, res: %d\n", res);
    res = data16_div_test_asm(13, 5);
    if (res != 2)
        printf("13 / 5 != 2, res: %d\n", res);
    res = data16_div_test_asm(65000, 20);
    if (res != 3250)
        printf("65000 / 20 != 3250, res: %d\n", res);
}

/* i#1453: memory copy through xmm regs */
void copy_through_xmm_asm(char *dst, char *src);
void copy_through_xmm_asm_ebp(char *dst, char *src);
void xmm_operations(char *dst, char *src);

static void
copy_through_xmm_test(void)
{
    char dst1[16];
    char dst2[16];
    char dst3[16];
    char uninit[16];
    uninit[0] = 'x';
    copy_through_xmm_asm(dst1, uninit);
    if (dst1[0] != 'x')
        printf("copy failed\n");
    copy_through_xmm_asm_ebp(dst2, uninit);
    if (dst2[0] != 'x')
        printf("copy failed\n");
    xmm_operations(dst3, uninit);
    if (dst3[14] == 'x')
        printf("got x\n");
    if (dst3[0] == 'x') /* uninit, from the movss pextrw series */
        printf("got x\n");
}

/* i#1473: mmx shadowing */
void copy_through_mmx(char *dst, char *src);
void mmx_operations(char *dst, char *src);

static void
mmx_test(void)
{
    char dst1[8];
    char dst2[8];
    char uninit[8];
    uninit[0] = 'x';
    copy_through_mmx(dst1, uninit);
    if (dst1[0] != 'x')
        printf("copy failed\n");
    mmx_operations(dst2, uninit);
    if (dst2[6] == 'x') /* no error b/c punpcklbw cleared the 2nd-to-top */
        printf("got x\n");
    if (dst2[3] == 'x') /* uninit! */
        array[127] = 4;
}

/* i#1597: sub-dword xl8 sharing*/
void xl8_share_subdword(char *undef, char *def);
/* Test clearing sharing in slowpath */
void xl8_share_slowpath(char *undef, char *def);

static void
sharing_test(void)
{
    char undef[128];
    char def[128] = {0,};
    xl8_share_subdword(undef, def);
    xl8_share_slowpath(undef, def);
}

int
main(int argc, char *argv[])
{
    test_stack_asm();

    regtest();

    /* test sub-dword w/ part of dword undef */
    subdword_test();

    subdword_test2();

    repstr_test();

    eflags_test();

    mem2mem_test();

    cmpxchg8b_test();

    and_or_test();

    float_test();

    addronly_test();

    nop_test();

    multi_dst_test();

    data16_div_test();

    copy_through_xmm_test();

    mmx_test();

    sharing_test();

    return 0;
}

#else /* asm code *************************************************************/
#include "cpp2asm_defines.h"
START_FILE

#define FUNCNAME eflags_test_asm
/* void eflags_test_asm(char *undef_array); */
        DECLARE_FUNC_SEH(FUNCNAME)
GLOBAL_LABEL(FUNCNAME:)
        mov      REG_XCX, ARG1 /* undef_array, assuming 16 bytes */
        /* save callee-saved regs */
        PUSH_SEH(REG_XDI)
        END_PROLOG

        mov      REG_XDI, REG_XCX /* undef_array */
        mov      ecx, DWORD [REG_XDI + 4]
        add      ecx, eax
        adc      ecx, 0
        cmovb    ecx, ebx /* error: cmovcc is a cmp for -check_cmps */
        mov      ecx, DWORD [REG_XDI + 8]
        sub      ecx, 1
        sbb      ecx, ecx
        jb       eflags_test_label1 /* error: eflags prop through sbb (PR 425622) */
    eflags_test_label1:
        mov      ecx, DWORD [REG_XDI + 12]
        sub      ecx, 1
        setb     cl
        cmp      cl, 4 /* error: eflags prop through setcc (PR 408552) */

        /* restore callee-saved regs */
        add      REG_XSP, 0 /* make a legal SEH64 epilog */
        pop      REG_XDI
        ret
        END_FUNC(FUNCNAME)
#undef FUNCNAME

#define FUNCNAME mem2mem_test_asm
/* void mem2mem_test_asm(int *array_uninit); */
        DECLARE_FUNC_SEH(FUNCNAME)
GLOBAL_LABEL(FUNCNAME:)
        mov      REG_XCX, ARG1 /* array_uninit, assume 16 bytes */
        END_PROLOG

        push     PTRSZ [REG_XCX]
        push     PTRSZ [REG_XCX + 8]
        pop      PTRSZ [REG_XCX + 8]
        pop      REG_XCX
        cmp      REG_XCX, 0
        je       equals
    equals:
        nop

        add      REG_XSP, 0 /* make a legal SEH64 epilog */
        ret
        END_FUNC(FUNCNAME)
#undef FUNCNAME

#define FUNCNAME cmpxchg8b_test_asm
/* void cmpxchg8b_test_asm(int *array_init, int *array_uninit); */
        DECLARE_FUNC_SEH(FUNCNAME)
GLOBAL_LABEL(FUNCNAME:)
        mov     REG_XCX, ARG1 /* array_init */
        mov     REG_XAX, ARG2 /* array_uninit */
        /* save callee-saved regs */
        PUSH_SEH(REG_XSI)
        END_PROLOG

        mov     REG_XSI, REG_XAX  /* save array_uninit */
#ifdef ASSEMBLE_WITH_NASM
        cmpxchg8b [REG_XCX] /* cmpxchg8b with array_init */
#else
        cmpxchg8b QWORD [REG_XCX] /* cmpxchg8b with array_init */
#endif
        mov     REG_XCX, REG_XSI  /* use array_uninit */
#ifdef ASSEMBLE_WITH_NASM
        cmpxchg8b [REG_XCX] /* cmpxchg8b with array_uninit */
#else
        cmpxchg8b QWORD [REG_XCX] /* cmpxchg8b with array_uninit */
#endif

        /* restore callee-saved regs */
        add      REG_XSP, 0 /* make a legal SEH64 epilog */
        pop      REG_XSI
        ret
        END_FUNC(FUNCNAME)
#undef FUNCNAME

#define FUNCNAME and_or_test_asm
/* void and_or_test(int *array_uninit, int *zero); */
        DECLARE_FUNC_SEH(FUNCNAME)
GLOBAL_LABEL(FUNCNAME:)
        mov      REG_XCX, ARG1 /* array_uninit */
        mov      REG_XDX, ARG2 /* zero */
        END_PROLOG

        mov      ecx, DWORD [REG_XCX]
        test     DWORD [REG_XDX], ecx
        mov      eax, DWORD [REG_XDX]
        test     ecx, eax

        add      REG_XSP, 0 /* make a legal SEH64 epilog */
        ret
        END_FUNC(FUNCNAME)
#undef FUNCNAME

#define FUNCNAME nop_test_asm
/* void nop_test_asm(void); */
        DECLARE_FUNC_SEH(FUNCNAME)
GLOBAL_LABEL(FUNCNAME:)
        END_PROLOG

        xor      REG_XAX, REG_XAX
        /* Can't figure out how to convince cl.exe to encode the long nop with a
         * memory operand, so we just emit the raw bytes.
         *
         * 0f 1f 84 00 00 00 00 00  nop 0x00000000(%eax,%eax,1)
         */
        RAW(0f)
        RAW(1f)
        RAW(84)
        RAW(00)
        RAW(00)
        RAW(00)
        RAW(00)
        RAW(00)

        /* restore callee-saved regs */
        add      REG_XSP, 0 /* make a legal SEH64 epilog */
        ret
        END_FUNC(FUNCNAME)
#undef FUNCNAME

#define FUNCNAME test_stack_asm
/* test PR 408519: void test_stack_asm(void); */
        DECLARE_FUNC(FUNCNAME)
GLOBAL_LABEL(FUNCNAME:)
        sub      REG_XSP, 2
#ifdef ASSEMBLE_WITH_NASM
        /* XXX: I can't get "o16 push 0" to assemble */
        RAW(66) RAW(6a) RAW(00)
#else
        pushw    0
#endif
        add      REG_XSP, 4
        ret
        END_FUNC(FUNCNAME)
#undef FUNCNAME

#define FUNCNAME repstr_test_asm
/* void repstr_test_asm(char *a1, char *a2); */
        DECLARE_FUNC_SEH(FUNCNAME)

GLOBAL_LABEL(FUNCNAME:)

        mov      REG_XAX, ARG1 /* a1, 15 bytes init buffer except a1[7] */
        mov      REG_XDX, ARG2 /* a2, 15 bytes uninit buffer */
        /* save callee-saved regs */
        PUSH_SEH(REG_XDI)
        PUSH_SEH(REG_XSI)
        PUSH_SEH(REG_XBX)
        END_PROLOG

        mov      REG_XBX, REG_XAX
        mov      REG_XSI, REG_XBX /* a1 */
        mov      REG_XDI, REG_XDX /* a2 */
        mov      REG_XCX, 15
        rep      movsb
        mov      REG_XDI, REG_XDX /* a2 */
        mov      REG_XAX, 1
        mov      REG_XCX, 15
        rep      stosb
        mov      REG_XDI, REG_XDX /* a2 */
        cmp      BYTE [REG_XDI + 7], 1
        jne      stos_error
       stos_error:
        /* should be no error on the movs, and the stos should make a2[7] defined,
         * but the cmps should hit error on a1[7]
         */
        mov      REG_XDI, REG_XBX /* a1 */
        mov      REG_XSI, REG_XDX /* a2 */
        mov      REG_XCX, 15
        repne    cmpsb
        mov      REG_XDI, REG_XBX /* a1 */
        mov      REG_XAX, 1
        xadd     [REG_XDI], REG_XAX

        /* restore callee-saved regs */
        add      REG_XSP, 0 /* make a legal SEH64 epilog */
        pop      REG_XBX
        pop      REG_XSI
        pop      REG_XDI
        ret
        END_FUNC(FUNCNAME)
#undef FUNCNAME

#define FUNCNAME subdword_test_asm
/* void subword_test_asm(char *undef, int *val); */
        DECLARE_FUNC_SEH(FUNCNAME)
GLOBAL_LABEL(FUNCNAME:)
        mov      REG_XCX, ARG1 /* undef, assuming 128 bytes */
        mov      REG_XDX, ARG2 /* val */
        END_PROLOG

        mov      eax, 0
        add      al, BYTE [REG_XCX + 37] /* write to flags */
        js       uninit /* uninit eflags! */
    uninit:
        sub      ah, al
        mov      DWORD [REG_XDX], eax /* set val uninit */
        /* stores */
        mov      REG_XAX, 0
        sub      BYTE [REG_XCX + 1], ah /* write to flags */
        js       uninit2 /* uninit eflags! */
    uninit2:
        nop

        add      REG_XSP, 0 /* make a legal SEH64 epilog */
        ret
        END_FUNC(FUNCNAME)
#undef FUNCNAME

#define FUNCNAME addronly_test_asm
/* void addronly_test_asm(char *undef); */
        DECLARE_FUNC_SEH(FUNCNAME)
GLOBAL_LABEL(FUNCNAME:)
        mov      REG_XAX, ARG1 /* undef, assuming 128 bytes */
        /* save callee-saved regs */
        PUSH_SEH(REG_XBX)
        END_PROLOG

        /* i#533: eflags restore */
        inc      BYTE [REG_XAX + 128] /* partial aflags write so need aflags restore */
        inc      REG_XAX /* ensure ebx and edx are the drmem scratch regs to get xchg */
        inc      REG_XAX
        inc      REG_XAX
        inc      REG_XAX
        inc      REG_XCX
        inc      REG_XCX
        inc      REG_XCX
        inc      REG_XCX
        jmp      foo /* end bb */
    foo:

        inc      BYTE [REG_XAX + 128] /* partial aflags write so need aflags restore */
        inc      REG_XBX /* this time have eax and ecx as the drmem scratch regs */
        inc      REG_XBX
        inc      REG_XBX
        inc      REG_XBX
        mov      REG_XDX, 0
        inc      REG_XDX
        inc      REG_XDX
        inc      REG_XDX
        jmp      foo2 /* end bb */
    foo2:

        /* Undo modifications to avoid RtlHeap/free crash (i#924) */
        dec      BYTE [REG_XAX + 124]
        dec      BYTE [REG_XAX + 128]

        /* restore callee-saved regs */
        add      REG_XSP, 0 /* make a legal SEH64 epilog */
        pop      REG_XBX
        ret
        END_FUNC(FUNCNAME)
#undef FUNCNAME


#define FUNCNAME regtest_asm
/* void regtest_asm(int array[128], gpr_t *gpr_pre, gpr_t *gpr_post); */
        DECLARE_FUNC_SEH(FUNCNAME)
GLOBAL_LABEL(FUNCNAME:)
        mov      REG_XAX, ARG1
        mov      REG_XCX, ARG2
        mov      REG_XDX, ARG3
        /* save callee-saved regs */
        PUSH_SEH(REG_XDI)
        PUSH_SEH(REG_XSI)
        END_PROLOG
        mov      REG_XSI, REG_XCX /* gpr_pre */
        mov      REG_XDI, REG_XDX /* gpr_post */
        mov      REG_XCX, REG_XAX /* array */
        PUSHF
        pop      REG_XAX   /* note: reg_eax = 0 and eax gets zero from array[*] */
        /* values we can recognize, but stay under array[128] */
        mov      edx,     7
        mov      PTRSZ [REG_XSI + 0*ARG_SZ /*xflags*/], REG_XAX
        mov      PTRSZ [REG_XSI + 1*ARG_SZ /* xax  */], 0
        mov      PTRSZ [REG_XSI + 2*ARG_SZ /* xcx  */], REG_XCX
        mov      PTRSZ [REG_XSI + 3*ARG_SZ /* xdx  */], REG_XDX
        mov      PTRSZ [REG_XSI + 4*ARG_SZ /* xbx  */], REG_XBX
        mov      PTRSZ [REG_XSI + 5*ARG_SZ /* xsp  */], REG_XSP
        mov      PTRSZ [REG_XSI + 6*ARG_SZ /* xbp  */], REG_XBP
        mov      PTRSZ [REG_XSI + 7*ARG_SZ /* xsi  */], REG_XSI
        mov      PTRSZ [REG_XSI + 8*ARG_SZ /* xdi  */], REG_XDI
        /* loads */
        mov      eax, DWORD [REG_XCX]
        mov      eax, DWORD [REG_XCX + 37]
        mov      eax, DWORD [REG_XCX + 37 + REG_XDX*2]
        mov      ax,   WORD [REG_XCX]
        mov      ax,   WORD [REG_XCX + 37]
        mov      ax,   WORD [REG_XCX + 37 + REG_XDX*2]
        mov      ah,   BYTE [REG_XCX]
        mov      ah,   BYTE [REG_XCX + 37]
        mov      ah,   BYTE [REG_XCX + 37 + REG_XDX*2]
        /* stores */
        mov      DWORD [REG_XCX], eax
        mov      DWORD [REG_XCX + 37], eax
        mov      DWORD [REG_XCX + 37 + REG_XDX*2], eax
        mov       WORD [REG_XCX], ax
        mov       WORD [REG_XCX + 37], ax
        mov       WORD [REG_XCX + 37 + REG_XDX*2], ax
        mov       BYTE [REG_XCX], ah
        mov       BYTE [REG_XCX + 37], ah
        mov       BYTE [REG_XCX + 37 + REG_XDX*2], ah
        /* get flags on stack before ALU tests change them */
        PUSHF
        /* test i#877: ALU sub-dword shift */
        add      BYTE [REG_XCX], 8 /* fastpath ok */
        shr      BYTE [REG_XCX], 8 /* needs slowpath */
        add      WORD [REG_XCX], 8 /* fastpath ok */
        shl      WORD [REG_XCX], 8 /* needs slowpath */
        /* pushes and pops */
        push     PTRSZ [REG_XCX + 37 + REG_XDX*2]
        pop      PTRSZ [REG_XCX + 37 + REG_XDX*2]
        enter    0, 0
        leave
        /* ensure regs haven't changed by storing copy in post_reg
         * (since act of comparing + printing will touch regs)
         */
        mov      PTRSZ [REG_XDI + 1*ARG_SZ /* xax  */], REG_XAX
        pop      REG_XAX
        mov      PTRSZ [REG_XDI + 0*ARG_SZ /*xflags*/], REG_XAX
        mov      PTRSZ [REG_XDI + 2*ARG_SZ /* xcx  */], REG_XCX
        mov      PTRSZ [REG_XDI + 3*ARG_SZ /* xdx  */], REG_XDX
        mov      PTRSZ [REG_XDI + 4*ARG_SZ /* xbx  */], REG_XBX
        mov      PTRSZ [REG_XDI + 5*ARG_SZ /* xsp  */], REG_XSP
        mov      PTRSZ [REG_XDI + 6*ARG_SZ /* xbp  */], REG_XBP
        mov      PTRSZ [REG_XDI + 7*ARG_SZ /* xsi  */], REG_XSI
        mov      PTRSZ [REG_XDI + 8*ARG_SZ /* xdi  */], REG_XDI
        /* restore callee-saved regs */
        add      REG_XSP, 0 /* make a legal SEH64 epilog */
        pop      REG_XSI
        pop      REG_XDI
        ret
        END_FUNC(FUNCNAME)
#undef FUNCNAME


#define FUNCNAME float_test_asm
/* void float_test_asm(double *zero); */
        DECLARE_FUNC(FUNCNAME)
GLOBAL_LABEL(FUNCNAME:)
        /* leaf function so no SEH64 prologue/epilogue needed */
        mov      REG_XAX, ARG1
        cvttsd2si eax, QWORD [REG_XAX]
        ret
        END_FUNC(FUNCNAME)
#undef FUNCNAME


#define FUNCNAME data16_div_test_asm
/* ushort data16_div_test_asm(ushort a, ushort b); */
        DECLARE_FUNC_SEH(FUNCNAME)
GLOBAL_LABEL(FUNCNAME:)
        mov      REG_XAX, ARG1
        mov      REG_XCX, ARG2
        PUSH_SEH(REG_XDI)
        END_PROLOG
        mov      di, cx
        xor      edx, edx
        div      di
        add      REG_XSP, 0 /* make a legal SEH64 epilog */
        pop      REG_XDI
        ret
        END_FUNC(FUNCNAME)
#undef FUNCNAME


#define FUNCNAME subdword_test2_asm
/* void subdword_test2_asm(char *undef, int *val1, int *val2) */
        DECLARE_FUNC_SEH(FUNCNAME)
GLOBAL_LABEL(FUNCNAME:)
        mov      REG_XCX, ARG1
        mov      REG_XAX, ARG2
        mov      REG_XDX, ARG3
        /* save callee-saved regs */
        PUSH_SEH(REG_XDI)
        PUSH_SEH(REG_XSI)
        END_PROLOG
        /* now put args into registers unused in legacy code below */
        mov      REG_XDI, REG_XAX /* val1 */
        mov      REG_XSI, REG_XDX /* val2 */

        /* shift uninit bits away */
        mov   eax, 0
        add   ax, WORD [REG_XCX + 32]
        shl   eax, 8
        movzx edx, al
        mov   DWORD [REG_XDI], edx
        shr   eax, 8
        movzx edx, al
        mov   DWORD [REG_XSI], edx

        /* test sub-dword offs mismatch (i#396) */
        mov   eax, 0
        mov   al, BYTE [REG_XCX + 32] /* so al undef, ah def */
        mov   BYTE [REG_XCX + 0], ah
        cmp   BYTE [REG_XCX + 0], 0 /* NOT uninit */

        mov   dl,ah /* test reg-reg sub-dword mismatch-offs */
        cmp   dl,0 /* NOT uninit */

        xchg  al,ah /* now ah undef */
        mov   BYTE [REG_XCX + 66], HEX(64)
        imul  BYTE [REG_XCX + 66] /* reads al, writes ax */
        cmp   ax,0 /* NOT uninit */

        mov   edx,0
        mov   BYTE [REG_XCX + 67], HEX(64)
        div   BYTE [REG_XCX + 66] /* 3 srcs and 2 dsts */
        cmp   ax,0 /* NOT uninit */

        mov   al, BYTE [REG_XCX + 32] /* al undef */
        mov   ah,4 /* al still undef */
        mov   BYTE [REG_XCX + 66], HEX(64)
        idiv  BYTE [REG_XCX + 66] /* writes ah and al: test double dest */
        cmp   ax,0 /* uninit */

        mov   edx, DWORD [REG_XCX + 64]
        mov   dx,0 /* now edx bottom 16 defined, top 16 undef */
        mov   WORD [REG_XCX + 66],0
        add   dx,WORD [REG_XCX + 66] /* def, unless use wrong edx subdw offs */
        cmp   dx,0 /* NOT uninit */

        sub   WORD [REG_XCX + 66],dx /* def, unless use wrong edx subdw offs */
        cmp   dx,0 /* NOT uninit */

        /* test movzx offs mismatch (i#396) */
        mov   eax,0
        mov   al, BYTE [REG_XCX + 32] /* al undef */
        movzx dx,ah
        cmp   dx,0 /* NOT uninit */
        movzx dx,al
        cmp   dx,0 /* uninit */
        movzx edx,ah
        cmp   edx,0 /* NOT uninit */

        /* test movzx upper bits (i#1396) */
        mov   edx, DWORD [REG_XCX + 40] /* edx all undef */
        mov   eax,0
        movzx edx, ax
        cmp   edx,0 /* NOT uninit */
        mov   edx, DWORD [REG_XCX + 40] /* edx all undef */
        mov   eax, edx /* eax all undef */
        movzx ax, dl
        cmp   ah,0 /* NOT uninit */
        mov   edx, DWORD [REG_XCX + 40] /* edx all undef */
        mov   eax, edx /* eax all undef */
        movzx eax, dl
        cmp   ah,0 /* NOT uninit */
        mov   edx, DWORD [REG_XCX + 40] /* edx all undef */
        mov   WORD [REG_XCX + 66],0
        movzx edx, WORD [REG_XCX + 66]
        cmp   edx,0 /* NOT uninit */

        /* ALU */
        sub   DWORD [REG_XCX + 32],edx
        sub   edx, DWORD [REG_XCX + 32]

        /* test sar (i#1399) */
        mov   eax,0
        mov   ah, BYTE [REG_XCX + 44] /* ah undef */
        sar   ax,8
        cmp   ah,0 /* uninit */

        /* restore callee-saved regs */
        add      REG_XSP, 0 /* make a legal SEH64 epilog */
        pop      REG_XSI
        pop      REG_XDI
        ret
        END_FUNC(FUNCNAME)
#undef FUNCNAME


#define FUNCNAME copy_through_xmm_asm
/* void copy_through_xmm_asm(char *dst, char *src); */
        DECLARE_FUNC_SEH(FUNCNAME)
GLOBAL_LABEL(FUNCNAME:)
        mov      REG_XCX, ARG1
        mov      REG_XAX, ARG2
        END_PROLOG

        movdqu   xmm0, [REG_XAX] /* src */
        movdqu   [REG_XCX], xmm0 /* dst */

        add      REG_XSP, 0 /* make a legal SEH64 epilog */
        ret
        END_FUNC(FUNCNAME)
#undef FUNCNAME

#define FUNCNAME copy_through_xmm_asm_ebp
/* void copy_through_xmm_asm(char *dst, char *src); */
        DECLARE_FUNC_SEH(FUNCNAME)
GLOBAL_LABEL(FUNCNAME:)
        mov      REG_XCX, ARG1
        mov      REG_XAX, ARG2
        push     REG_XBP
        mov      REG_XBP, REG_XSP
        push     REG_XCX /* dst */
        END_PROLOG

        movdqu   xmm0, [REG_XAX] /* src */
        mov      REG_XCX, [REG_XBP - ARG_SZ]
        movdqu   [REG_XCX], xmm0 /* dst */

        add      REG_XSP, 0 /* make a legal SEH64 epilog */
        mov      REG_XSP, REG_XBP
        pop      REG_XBP
        ret
        END_FUNC(FUNCNAME)
#undef FUNCNAME

#define FUNCNAME xmm_operations
/* void xmm_operations(char *dst, char *src); */
        DECLARE_FUNC_SEH(FUNCNAME)
GLOBAL_LABEL(FUNCNAME:)
        mov      REG_XCX, ARG1
        mov      REG_XAX, ARG2
        push     REG_XBP
        mov      REG_XBP, REG_XSP
        push     REG_XCX /* dst */
        END_PROLOG

        movdqu   xmm4, [REG_XAX] /* src */
        xorps    xmm4, xmm4
        mov      REG_XCX, [REG_XBP - ARG_SZ]
        movdqu   [REG_XCX], xmm4 /* dst: just convenient mem loc */
        mov      edx, [REG_XCX + 4] /* uninit, but zeroed by xor */
        test     edx, edx /* should be no error */

        movq     xmm5, MMWORD [REG_XAX] /* src */
        mov      REG_XCX, [REG_XBP - ARG_SZ]
        movdqu   [REG_XCX], xmm5 /* dst: just convenient mem loc */
        mov      edx, [REG_XCX + 12] /* uninit, but top half zeroed by movq */
        test     edx, edx /* should be no error */
        movq     MMWORD [REG_XCX], xmm5 /* make sure movq to mem works */
        movd     DWORD [REG_XCX], xmm5 /* make sure movd to mem works */

        movdqu   xmm0, [REG_XAX] /* src */
        pxor     xmm1, xmm1
        punpcklbw xmm1, xmm0
        movdqa   xmm2, xmm1
        mov      REG_XCX, [REG_XBP - ARG_SZ]
        movdqu   [REG_XCX], xmm2 /* dst */

        movdqu   xmm0, [REG_XAX] /* undef */
        pxor     xmm1, xmm1
        movss    xmm0, xmm1 /* leaves top half of xmm0 alone */
        pextrw   edx, xmm0, 7 /* top word came from undef */
        mov      [REG_XCX], edx /* uninit */

        /* packed word shift right */
        movdqu   xmm0, [REG_XAX] /* undef */
        pxor     xmm1, xmm1
        mov      ecx, 7
        pinsrd   xmm1, ecx, 0 /* shift amount: 7 */
        psrlw    xmm0, xmm1
        pextrb   ecx, xmm0, 15 /* top byte still undef! */
        cmp      ecx, HEX(40) /* uninit */

        add      REG_XSP, 0 /* make a legal SEH64 epilog */
        mov      REG_XSP, REG_XBP
        pop      REG_XBP
        ret
        END_FUNC(FUNCNAME)
#undef FUNCNAME

#define FUNCNAME copy_through_mmx
/* void copy_through_mmx(char *dst, char *src); */
        DECLARE_FUNC_SEH(FUNCNAME)
GLOBAL_LABEL(FUNCNAME:)
        mov      REG_XCX, ARG1
        mov      REG_XAX, ARG2
        END_PROLOG

        movq     mm0, [REG_XAX] /* src */
        movq     [REG_XCX], mm0 /* dst */

        add      REG_XSP, 0 /* make a legal SEH64 epilog */
        ret
        END_FUNC(FUNCNAME)
#undef FUNCNAME

#define FUNCNAME mmx_operations
/* void mmx_operations(char *dst, char *src); */
        DECLARE_FUNC_SEH(FUNCNAME)
GLOBAL_LABEL(FUNCNAME:)
        mov      REG_XCX, ARG1
        mov      REG_XAX, ARG2
        push     REG_XBP
        mov      REG_XBP, REG_XSP
        push     REG_XCX /* dst */
        END_PROLOG

        movq     mm4, [REG_XAX] /* src */
        pxor     mm4, mm4
        mov      REG_XCX, [REG_XBP - ARG_SZ]
        movq     [REG_XCX], mm4 /* dst: just convenient mem loc */
        mov      edx, [REG_XCX + 4] /* uninit, but zeroed by xor */
        test     edx, edx /* should be no error */

        movd     mm5, DWORD [REG_XAX] /* src */
        mov      REG_XCX, [REG_XBP - ARG_SZ]
        movd     DWORD [REG_XCX], mm5 /* dst: just convenient mem loc */
        mov      edx, [REG_XCX + 4] /* uninit, but top half zeroed by movd */
        test     edx, edx /* should be no error */

        movq     mm0, [REG_XAX] /* src */
        pxor     mm1, mm1
        punpcklbw mm1, mm0
        movq     mm2, mm1
        mov      REG_XCX, [REG_XBP - ARG_SZ]
        movq     [REG_XCX], mm2 /* dst */

        add      REG_XSP, 0 /* make a legal SEH64 epilog */
        mov      REG_XSP, REG_XBP
        pop      REG_XBP
        ret
        END_FUNC(FUNCNAME)
#undef FUNCNAME

#define FUNCNAME xl8_share_subdword
/* void xl8_share_subdword(char *undef, char *def); */
        DECLARE_FUNC_SEH(FUNCNAME)
GLOBAL_LABEL(FUNCNAME:)
        mov      REG_XAX, ARG1
        mov      REG_XDX, ARG2
        push     REG_XBP
        mov      REG_XBP, REG_XSP
        END_PROLOG

        /* Test i#1597: ensure xl8 sharing of sub-dword cmp works across
         * dword boundaries.
         */

        /* Forward 1-byte */
        mov      cl, BYTE [REG_XAX] /* undef */
        mov      BYTE [8 + REG_XDX], cl
        jmp force_bb_i1597_forw_1
    force_bb_i1597_forw_1:
        mov      REG_XCX, REG_XAX
        mov      REG_XAX, REG_XAX
        cmp      BYTE [7 + REG_XDX], 0
        cmp      BYTE [8 + REG_XDX], 0
        jmp force_bb_i1597_forw_1_end
    force_bb_i1597_forw_1_end:
        mov      cl, BYTE [REG_XDX] /* restore to def */
        mov      BYTE [8 + REG_XDX], cl

        /* Backward 1-byte */
        mov      cl, BYTE [REG_XAX] /* undef */
        mov      BYTE [7 + REG_XDX], cl
        jmp force_bb_i1597_backw_1
    force_bb_i1597_backw_1:
        mov      REG_XCX, REG_XAX
        mov      REG_XAX, REG_XAX
        cmp      BYTE [8 + REG_XDX], 0
        cmp      BYTE [7 + REG_XDX], 0
        jmp force_bb_i1597_backw_1_end
    force_bb_i1597_backw_1_end:
        mov      cl, BYTE [REG_XDX] /* restore to def */
        mov      BYTE [7 + REG_XDX], cl

        /* Forward 2-byte */
        mov      cx, WORD [REG_XAX] /* undef */
        mov      WORD [8 + REG_XDX], cx
        jmp force_bb_i1597_forw_2
    force_bb_i1597_forw_2:
        mov      REG_XCX, REG_XAX
        mov      REG_XAX, REG_XAX
        cmp      WORD [6 + REG_XDX], 0
        cmp      WORD [8 + REG_XDX], 0
        jmp force_bb_i1597_forw_2_end
    force_bb_i1597_forw_2_end:
        mov      cx, WORD [REG_XDX] /* restore to def */
        mov      WORD [8 + REG_XDX], cx

        /* Backward 2-byte */
        mov      cx, WORD [REG_XAX] /* undef */
        mov      WORD [6 + REG_XDX], cx
        jmp force_bb_i1597_backw_2
    force_bb_i1597_backw_2:
        mov      REG_XCX, REG_XAX
        mov      REG_XAX, REG_XAX
        cmp      WORD [8 + REG_XDX], 0
        cmp      WORD [6 + REG_XDX], 0
        jmp force_bb_i1597_backw_2_end
    force_bb_i1597_backw_2_end:
        mov      cx, WORD [REG_XDX] /* restore to def */
        mov      WORD [6 + REG_XDX], cx

        add      REG_XSP, 0 /* make a legal SEH64 epilog */
        mov      REG_XSP, REG_XBP
        pop      REG_XBP
        ret
        END_FUNC(FUNCNAME)
#undef FUNCNAME

#define FUNCNAME xl8_share_slowpath
/* void xl8_share_slowpath(char *undef, char *def); */
        DECLARE_FUNC_SEH(FUNCNAME)
GLOBAL_LABEL(FUNCNAME:)
        mov      REG_XAX, ARG1
        mov      REG_XDX, ARG2
        push     REG_XBP
        mov      REG_XBP, REG_XSP
        END_PROLOG

        /* Test clearing sharing in slowpath.  This gets complex!  The only way to
         * test is to have a false negative if the xl8 is not cleared.  The reg
         * holding the xl8 addr will point to the app pc if not cleared, so we want
         * an app pc with 0 in its bottom 2 bits to fool the next instr into thinking
         * its memref is defined when it's not.  But, sharing doesn't happen for
         * sub-dword, so we have to read 4 bytes and then expand the bottom 2 bytes.
         */
        mov      ecx, DWORD [4 + REG_XAX]
        /* "lock" is automatic here, and adding it can cause ml to fail (i#1952) */
        xchg ecx, DWORD [0 + REG_XDX] /* undef => slowpath */
        mov      eax, DWORD [0 + REG_XDX] /* propagate lock==0xf0 unless xl8 cleared */
        movzx    eax, ax /* now 0x00==defined unless xl8 cleared */
        cmp      eax, edx /* undef w/ proper clearing */

        xor      ecx, ecx
        mov      DWORD [0 + REG_XDX], ecx /* restore def */

        add      REG_XSP, 0 /* make a legal SEH64 epilog */
        mov      REG_XSP, REG_XBP
        pop      REG_XBP
        ret
        END_FUNC(FUNCNAME)
#undef FUNCNAME


END_FILE
#endif
