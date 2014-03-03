/* **********************************************************
 * Copyright (c) 2011-2014 Google, Inc.  All rights reserved.
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
    /* FIXME i#934: convert to cross-platform asm routine */
#ifdef WINDOWS
    __asm {
        /* loads */
        mov   eax, 0
        mov   ecx, undef
        add   al, byte ptr [ecx + 37]
        js    uninit
      uninit:
        sub   ah, al
        mov   val, eax
        /* stores */
        mov   eax, 0
        sub   byte ptr [ecx + 1], ah
        js    uninit2
      uninit2:
        nop
    }
#else
    /* values we can recognize, but stay under undef[128] */
    asm("mov   %0, %%ecx" : : "g"(undef) : "ecx");
    /* loads */
    asm("mov   $0, %eax");
    asm("add   37(%ecx), %al"); /* write to flags */
    asm("js    uninit"); /* uninit eflags! */
    asm("uninit:");
    asm("sub   %al, %ah");
    asm("mov   %%eax, %0" : "=m"(val));
    /* stores */
    asm("mov   $0, %eax");
    asm("sub   %ah, 1(%ecx)"); /* write to flags */
    asm("js    uninit2"); /* uninit eflags! */
    asm("uninit2:");
#endif
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
    /* FIXME i#934: convert to cross-platform asm routine */
#ifdef WINDOWS
    __asm {
        mov   esi, a1
        mov   edi, a2
        mov   ecx, 15
        rep   movsb
        mov   edi, a2
        mov   eax, 1
        mov   ecx, 15
        rep   stosb
        mov   edi, a2
        cmp   byte ptr [7 + edi], 1
        jne   stos_error
      stos_error:
        mov   edi, a1
        mov   esi, a2
        mov   ecx, 15
        repne cmpsb
        mov   edi, a1
        mov   eax, 1
        xadd  dword ptr [edi], eax
    }
#else
    asm("mov   %0, %%esi" : : "g"(a1) : "esi");
    asm("mov   %0, %%edi" : : "g"(a2) : "edi");
    asm("mov   $15, %ecx");
    asm("rep movsb");
    asm("mov   %0, %%edi" : : "g"(a2) : "edi");
    asm("mov   $1, %eax");
    asm("mov   $15, %ecx");
    asm("rep stosb");
    asm("mov   %0, %%edi" : : "g"(a2) : "edi");
    asm("cmpb  $1, 7(%edi)");
    asm("jne   stos_error");
    asm("stos_error:");
    /* should be no error on the movs, and the stos should make a2[7] defined,
     * but the cmps should hit error on a1[7]
     */
    asm("mov   %0, %%edi" : : "g"(a1) : "edi");
    asm("mov   %0, %%esi" : : "g"(a2) : "esi");
    asm("mov   $15, %ecx");
    asm("repne cmpsb");
    asm("mov   %0, %%edi" : : "g"(a1) : "edi");
    asm("mov   $1, %eax");
    asm("xadd  %eax, (%edi)");
#endif
    printf("after repstr test!\n");
    free(undef);
}

/* Tests PR 425622: eflags shadow propagation */
void
eflags_test(void)
{
    char *undef = (char *) malloc(16);
    printf("before eflags test!\n");
    /* FIXME i#934: convert to cross-platform asm routine */
#ifdef WINDOWS
    __asm {
        mov   edi, undef
        mov   ecx, dword ptr [4 + edi]
        add   ecx, eax
        adc   ecx, 0
        cmovb ecx, ebx /* error: cmovcc is a cmp for -check_cmps */
        mov   ecx, dword ptr [8 + edi]
        sub   ecx, 1
        sbb   ecx, ecx
        jb    eflags_test_label1 /* error: eflags prop through sbb (PR 425622) */
      eflags_test_label1:
        mov   ecx, dword ptr [12 + edi]
        sub   ecx, 1
        setb  cl
        cmp   cl, 4 /* error: eflags prop through setcc (PR 408552) */
    }
#else
    asm("mov   %0, %%edi" : : "g"(undef) : "edi");
    asm("mov   4(%edi), %ecx");
    asm("add   %eax, %ecx");
    asm("adc   $0, %ecx");
    asm("cmovb %ebx, %ecx"); /* error: cmovcc is a cmp for -check_cmps */
    asm("mov   8(%edi), %ecx");
    asm("sub   $1, %ecx");
    asm("sbb   %ecx, %ecx");
    asm("jb    eflags_test_label1"); /* error: eflags prop through sbb (PR 425622) */
    asm("eflags_test_label1:");
    asm("mov   12(%edi), %ecx");
    asm("sub   $1, %ecx");
    asm("setb  %cl");
    asm("cmp   $4, %cl"); /* error: eflags prop through setcc (PR 408552) */
#endif
    printf("after eflags test!\n");
    free(undef);
}

static void
mem2mem_test(void)
{
    int *array_uninit = malloc(8);
    /* test push-mem propagation (i#236) */
#ifdef WINDOWS
    __asm {
        mov   ecx, dword ptr [array_uninit]
        push  dword ptr [ecx]
        push  dword ptr [ecx+4]
        pop   dword ptr [ecx+4]
        pop   ecx
        cmp   ecx,0
        je    equals
      equals:
        nop
    }
#else
    asm("mov   %0, %%ecx" : : "g"(array_uninit) : "ecx");
    asm("pushl  (%ecx)");
    asm("pushl  4(%ecx)");
    asm("popl   4(%ecx)");
    asm("popl   %ecx");
    asm("cmp    $0,%ecx");
    asm("je     equals");
    asm("equals: nop");
#endif
    free(array_uninit);
}


static void
cmpxchg8b_test(void)
{
    int *array_uninit = malloc(8);
    int *array_init = calloc(8, 1);
    /* test push-mem propagation (i#236) */
#ifdef WINDOWS
    __asm {
        mov   ecx, dword ptr [array_init]
        cmpxchg8b  qword ptr [ecx]
        mov   ecx, dword ptr [array_uninit]
        cmpxchg8b  qword ptr [ecx]
    }
#else
    asm("mov   %0, %%ecx" : : "g"(array_init) : "ecx");
    asm("cmpxchg8b  (%ecx)");
    asm("mov   %0, %%ecx" : : "g"(array_uninit) : "ecx");
    asm("cmpxchg8b  (%ecx)");
#endif
    free(array_uninit);
    free(array_init);
}

static void
and_or_test(void)
{
    int *array_uninit = malloc(8);
    static int zero;
    /* test push-mem propagation (i#236) */
#ifdef WINDOWS
    __asm {
        mov   ecx, dword ptr [array_uninit]
        mov   ecx, dword ptr [ecx]
        test  dword ptr [zero], ecx
        mov   eax, dword ptr [zero]
        test  ecx, eax
    }
#else
    asm("mov   %0, %%ecx" : : "g"(array_uninit) : "ecx");
    asm("mov   (%ecx), %ecx");
    asm("test  %0, %%ecx" : : "g"(zero) : "ecx");
    asm("mov   %0, %%ecx" : : "g"(zero) : "eax");
    asm("test  %ecx, %eax");
#endif
    free(array_uninit);
}

static void
float_test(void)
{
    double val = 0.;
    /* test cvttsd2si (i#258, i#259, DRi#371) */
    float_test_asm(&val);
}

void
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

void
addronly_test(void)
{
    /* test state restoration on ud2a fault path (in particular, i#533)
     * when run w/ -no_check_uninitialized
     */
    char unused[128]; /* i#624: shift in stack to avoid stale ptr for addronly */
    char *undef = (char *) malloc(128);
    unused[0] = 1;
    printf("before addronly test!\n");

#ifdef WINDOWS
    /* XXX i#403: add asm_defines.asm and write cross-os asm: this is getting
     * hard to maintain w/ two copies
     */
    __asm {
        pushad
        mov   eax, undef

        /* i#533: eflags restore */
        inc   byte ptr [eax+128] /* partial aflags write so need aflags restore */
        inc   eax /* ensure ebx and edx are the scratch regs to get xchg */
        inc   eax
        inc   eax
        inc   eax
        inc   ecx
        inc   ecx
        inc   ecx
        inc   ecx
        jmp   foo /* end bb */
      foo:

        inc   byte ptr [eax+128] /* partial aflags write so need aflags restore */
        inc   ebx /* this time have eax and ecx as the scratch regs */
        inc   ebx
        inc   ebx
        inc   ebx
        mov   edx, 0
        inc   edx
        inc   edx
        inc   edx
        jmp   foo2 /* end bb */
      foo2:

        /* Undo modifications to avoid RtlHeap crash (i#924) */
        dec   byte ptr [eax+124]
        dec   byte ptr [eax+128]

        popad
    }
#else
    asm("pusha");
    asm("mov   %0, %%eax" : : "g"(undef) : "eax");

    /* i#533: eflags restore */
    /* XXX: having separate asm lines means the compiler can insert spill code
     * in between (rnk: clang -O0 does), but it means the entire sequence
     * is one source line, messing up the line-based testing.  Going w/ separate
     * lines for now since it works out in gcc: in the future we'll probably
     * need separate, true asm anyway (for 64-bit) and we'll get the best of
     * both worlds then.
     */
    asm("incb  128(%eax)");
    asm("inc   %eax");
    asm("inc   %eax");
    asm("inc   %eax");
    asm("inc   %eax");
    asm("inc   %ecx");
    asm("inc   %ecx");
    asm("inc   %ecx");
    asm("inc   %ecx");
    asm("jmp foo");
    asm("foo:");
    asm("incb  128(%eax)");
    asm("inc   %ebx");
    asm("inc   %ebx");
    asm("inc   %ebx");
    asm("inc   %ebx");
    asm("mov   $0, %edx");
    asm("inc   %edx");
    asm("inc   %edx");
    asm("inc   %edx");
    asm("jmp foo2");
    asm("foo2:");

    /* Undo the modifications our unaddrs made to make glibc happy when running
     * natively.  After the first two writes, the memory is marked as defined,
     * so these don't get reported.
     */
    asm("decb  124(%eax)");
    asm("decb  128(%eax)");

    asm("popa");
#endif
    free(undef);
    printf("after addronly test!\n");
}

/* Tests weird nops with memory operands. */
void
nop_test(void)
{
#ifdef WINDOWS
    __asm {
        pushad;
        xor eax, eax;
        /* Can't figure out how to convince cl.exe to encode the long nop with a
         * memory operand, so we just emit the raw bytes.  Should be easier with
         * cross-os asm file support.
         *
         * 0f 1f 84 00 00 00 00 00  nop 0x00000000(%eax,%eax,1)
         */
        _emit 0x0f;
        _emit 0x1f;
        _emit 0x84;
        _emit 0x00;
        _emit 0x00;
        _emit 0x00;
        _emit 0x00;
        _emit 0x00;
        popad;
    }
#else
    /* FIXME i#934: Skipping Linux for now, we'll get the coverage when cross-os asm
     * support lands.
     */
#endif
}

void
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
void
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

void
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
    if (dst3[0] != 'x')
        printf("copy failed\n");
}

int
main()
{
#ifdef UNIX
    /* test PR 408519 */
    asm("sub $2, %esp");
    asm("pushw $0");
    asm("add $4, %esp");
#endif

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

    return 0;
}

#else /* asm code *************************************************************/
#include "cpp2asm_defines.h"
START_FILE

#define FUNCNAME regtest_asm
/* void regtest_asm(int array[128], gpr_t *gpr_pre, gpr_t *gpr_post); */
        DECLARE_FUNC(FUNCNAME)
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
        pushfd
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
        pushfd
        /* test i#877: ALU sub-dword shift */
        add      BYTE [REG_XCX], 8 /* fastpath ok */
        shr      BYTE [REG_XCX], 8 /* needs slowpath */
        add      WORD [REG_XCX], 8 /* fastpath ok */
        shl      WORD [REG_XCX], 8 /* needs slowpath */
        /* pushes and pops */
        push     DWORD [REG_XCX + 37 + REG_XDX*2]
        pop      DWORD [REG_XCX + 37 + REG_XDX*2]
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
        DECLARE_FUNC(FUNCNAME)
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
        DECLARE_FUNC(FUNCNAME)
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
        DECLARE_FUNC(FUNCNAME)
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
        DECLARE_FUNC(FUNCNAME)
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
        DECLARE_FUNC(FUNCNAME)
GLOBAL_LABEL(FUNCNAME:)
        mov      REG_XCX, ARG1
        mov      REG_XAX, ARG2
        push     REG_XBP
        mov      REG_XBP, REG_XSP
        push     REG_XCX /* dst */
        END_PROLOG

        movdqu   xmm0, [REG_XAX] /* src */
        pxor     xmm1, xmm2
        punpcklbw xmm1, xmm2
        movdqa   xmm1, xmm0
        mov      REG_XCX, [REG_XBP - ARG_SZ]
        movdqu   [REG_XCX], xmm1 /* dst */

        add      REG_XSP, 0 /* make a legal SEH64 epilog */
        mov      REG_XSP, REG_XBP
        pop      REG_XBP
        ret
        END_FUNC(FUNCNAME)
#undef FUNCNAME

END_FILE
#endif
