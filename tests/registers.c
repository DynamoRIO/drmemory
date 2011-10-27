/* **********************************************************
 * Copyright (c) 2011 Google, Inc.  All rights reserved.
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

typedef unsigned char byte;

static int reg_eflags;
static int reg_eax;
static int reg_ebx;
static int reg_ecx;
static int reg_edx;
static int reg_edi;
static int reg_esi;
static int reg_ebp;
static int reg_esp;
static byte *pusha_base;

static int array[128];

static void check_reg(byte *pusha_base, int pre_val, int offs)
{
    if (*(int *)(pusha_base+offs) != pre_val) {
        printf("mismatch %d: 0x%08x vs 0x%08x\n",
               offs, *(int *)(pusha_base+offs), pre_val);
    }
}

static void
regtest()
{
    printf("before regtest!\n"); /* using ! as workaround for i#625 */
#ifdef WINDOWS
    /* XXX i#403: add asm_defines.asm and write cross-os asm */
    __asm {
        pushfd
        pop   eax   /* note: reg_eax = 0 and eax gets zero from array[*] */
        /* values we can recognize, but stay under array[128] */
        mov   ecx, 37
        mov   edx, 7
        mov   reg_eflags, eax
        mov   reg_ecx, ecx
        mov   reg_edx, edx
        mov   reg_ebx, ebx
        mov   reg_esp, esp
        mov   reg_ebp, ebp
        mov   reg_esi, esi
        mov   reg_edi, edi
        /* loads */
        mov   eax, dword ptr [array]
        mov   eax, dword ptr [array + ecx]
        mov   eax, dword ptr [array + ecx + edx*2]
        mov   ax,   word ptr [array]
        mov   ax,   word ptr [array + ecx]
        mov   ax,   word ptr [array + ecx + edx*2]
        mov   ah,   byte ptr [array]
        mov   ah,   byte ptr [array + ecx]
        mov   ah,   byte ptr [array + ecx + edx*2]
        /* stores */
        mov   dword ptr [array],               eax
        mov   dword ptr [array + ecx],         eax
        mov   dword ptr [array + ecx + edx*2], eax
        mov    word ptr [array],               ax
        mov    word ptr [array + ecx],         ax
        mov    word ptr [array + ecx + edx*2], ax
        mov    byte ptr [array],               ah
        mov    byte ptr [array + ecx],         ah
        mov    byte ptr [array + ecx + edx*2], ah
        /* pushes and pops */
        push  dword ptr [array + ecx + edx*2]
        pop   dword ptr [array + ecx + edx*2]
        enter 0, 0
        leave
        /* ensure regs haven't changed by storing copy on stack
         * (since act of comparing + printing will touch regs)
         */
        pushfd
        pushad
        mov   pusha_base, esp
    }
#else
    asm("pushfl");
    asm("pop   %eax");
    /* values we can recognize, but stay under array[128] */
    /* FIXME: gave up trying to duplicate Windows side in gcc inline asm,
     * so putting array address into ecx and using 37 as offset.
     */
    asm("mov   %0, %%ecx" : : "g"(&array) : "ecx");
    asm("mov   $7, %edx");
    asm("mov   %%eax, %0" : "=m"(reg_eflags) :);
    asm("mov   %%ecx, %0" : "=m"(reg_ecx) :);
    asm("mov   %%edx, %0" : "=m"(reg_edx) :);
    asm("mov   %%ebx, %0" : "=m"(reg_ebx) :);
    asm("mov   %%esp, %0" : "=m"(reg_esp) :);
    asm("mov   %%ebp, %0" : "=m"(reg_ebp) :);
    asm("mov   %%esi, %0" : "=m"(reg_esi) :);
    asm("mov   %%edi, %0" : "=m"(reg_edi) :);
    /* loads */
    asm("mov   %0, %%eax" : : "m"(array[0]) : "eax");
    asm("mov   37(%ecx), %eax");
    asm("mov   37(%ecx,%edx,2), %eax");
    asm("mov   %0, %%ax" : : "m"(array[0]) : "ax");
    asm("mov   37(%ecx), %ax");
    asm("mov   37(%ecx,%edx,2), %ax");
    asm("mov   %0, %%ah" : : "m"(array[0]) : "ah");
    asm("mov   37(%ecx), %ah");
    asm("mov   37(%ecx,%edx,2), %ah");
    /* stores */
    asm("mov   %%eax, %0" : "=g"(array));
    asm("mov   %eax, 37(%ecx)");
    asm("mov   %eax, 37(%ecx,%edx,2)");
    asm("mov   %%ax, %0" : "=g"(array));
    asm("mov   %ax, 37(%ecx)");
    asm("mov   %ax, 37(%ecx,%edx,2)");
    asm("mov   %%ah, %0" : "=g"(array));
    asm("mov   %ah, 37(%ecx)");
    asm("mov   %ah, 37(%ecx,%edx,2)");
    /* PR 425240: cmp of sub-dword */
    asm("cmp   %ah, 37(%ecx)");
    /* pushes and pops */
    asm("pushl  37(%ecx,%edx,2)");
    asm("popl   37(%ecx,%edx,2)");
    asm("enter $0, $0");
    asm("leave");
    /* ensure regs haven't changed by storing copy on stack
     * (since act of comparing + printing will touch regs)
     */
    asm("pushfl");
    asm("pushal");
    asm("mov   %%esp, %0" : "=m"(pusha_base) :);
    /* gcc is reserving stack space up front and then clobbering the
     * pusha slots, so make sure to get new slots
     */
    asm("sub   $12, %esp");
#endif
    check_reg(pusha_base, reg_edi,  0);
    check_reg(pusha_base, reg_esi,  4);
    check_reg(pusha_base, reg_ebp,  8);
    /* pushf prior to pusha added 4 to esp */
    check_reg(pusha_base, reg_esp-4, 12);
    check_reg(pusha_base, reg_ebx, 16);
    check_reg(pusha_base, reg_edx, 20);
    check_reg(pusha_base, reg_ecx, 24);
    check_reg(pusha_base, reg_eax, 28);
    check_reg(pusha_base, reg_eflags, 32);
#ifdef WINDOWS
    __asm {
        popad
        pop   eax
    }
#else
    asm("add   $12, %esp");
    asm("popal");
    asm("pop %eax");
#endif
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
#ifdef WINDOWS
    /* if this gets any longer should use asm_defines.asm and write cross-os asm */
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
#ifdef WINDOWS
    /* if this gets any longer should use asm_defines.asm and write cross-os asm */
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
#ifdef WINDOWS
    /* if this gets any longer should use asm_defines.asm and write cross-os asm */
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
#ifdef WINDOWS
    __asm {
        cvttsd2si  eax, dword ptr [val]
    }
#else
    asm("mov   %0, %%ecx" : : "g"(&val) : "ecx");
    asm("cvttsd2si  (%ecx), %eax");
#endif
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
#ifdef WINDOWS
    /* XXX i#403: add asm_defines.asm and write cross-os asm: this is getting
     * hard to maintain w/ two copies
     */
    __asm {
        mov   ecx, undef

        /* shift uninit bits away */
        mov   eax, 0
        add   ax, word ptr [ecx + 32]
        shl   eax, 8
        movzx edx, al
        mov   val1, edx
        shr   eax, 8
        movzx edx, al
        mov   val2, edx

        /* test sub-dword offs mismatch (i#396) */
        mov   eax, 0
        mov   al, byte ptr [ecx + 32] /* so al undef, ah def */
        mov   byte ptr [ecx + 0], ah
        cmp   byte ptr [ecx + 0], 0 /* NOT uninit */

        mov   dl,ah /* test reg-reg sub-dword mismatch-offs */
        cmp   dl,0 /* NOT uninit */

        xchg  al,ah /* now ah undef */
        mov   byte ptr [ecx + 66],0x64
        imul  byte ptr [ecx + 66] /* reads al, writes ax */
        cmp   ax,0 /* NOT uninit */

        mov   edx,0
        mov   byte ptr [ecx + 67],0x64
        div   byte ptr [ecx + 66] /* 3 srcs and 2 dsts */
        cmp   ax,0 /* NOT uninit */

        mov   al, byte ptr [ecx + 32] /* al undef */
        mov   ah,4 /* al still undef */
        mov   byte ptr [ecx + 66],0x64
        idiv  byte ptr [ecx + 66] /* writes ah and al: test double dest */
        cmp   ax,0 /* uninit */

        mov   edx, dword ptr [ecx + 64]
        mov   dx,0 /* now edx bottom 16 defined, top 16 undef */
        mov   word ptr [ecx + 66],0
        add   dx,word ptr [ecx + 66] /* def, unless use wrong edx subdw offs */
        cmp   dx,0 /* NOT uninit */

        sub   word ptr [ecx + 66],dx /* def, unless use wrong edx subdw offs */
        cmp   dx,0 /* NOT uninit */

        /* test movzx offs mismatch (i#396) */
        mov   eax,0
        mov   al, byte ptr [ecx + 32] /* al undef */
        movzx dx,ah
        cmp   dx,0 /* NOT uninit */
        movzx dx,al
        cmp   dx,0 /* uninit */
        movzx edx,ah
        cmp   edx,0 /* NOT uninit */

        /* ALU */
        sub   dword ptr [ecx + 32],edx
        sub   edx, dword ptr [ecx + 32]
    }
#else
    asm("mov   %0, %%ecx" : : "g"(undef) : "ecx");

    /* shift uninit bits away */
    asm("mov   $0, %eax");
    asm("add   32(%ecx), %ax");
    asm("shl   $8,%eax");
    asm("movzx %al,%edx");
    asm("mov   %%edx, %0" : "=m"(val1));
    asm("shr   $8,%eax");
    asm("movzx %al,%edx");
    asm("mov   %%edx, %0" : "=m"(val2));

    /* test sub-dword offs mismatch (i#396) */
    asm("mov   $0,%eax");
    asm("mov   32(%ecx),%al"); /* so al undef, ah def */
    asm("mov   %ah,0(%ecx)");
    asm("cmpb  $0, 0(%ecx)"); /* NOT uninit */

    asm("mov   %ah,%dl"); /* test reg-reg sub-dword mismatch-offs */
    asm("cmpb  $0, %dl"); /* NOT uninit */

    asm("xchg  %ah,%al"); /* now ah undef */
    asm("movb  $0x64,66(%ecx)");
    asm("imulb 66(%ecx)"); /* reads al, writes ax */
    asm("cmp   $0, %ax"); /* NOT uninit */

    asm("mov   $0, %edx");
    asm("movb  $0x64,67(%ecx)");
    asm("divw  66(%ecx)"); /* 3 srcs and 2 dsts */
    asm("cmp   $0, %ax"); /* NOT uninit */

    asm("mov   32(%ecx),%al"); /* al undef */
    asm("mov   $4,%ah"); /* al still undef */
    asm("movb  $0x64,66(%ecx)");
    asm("idivb 66(%ecx)"); /* writes ah and al: test double dest */
    asm("cmp   $0, %ax"); /* uninit */

    asm("mov   64(%ecx),%edx");
    asm("mov   $0, %dx"); /* now edx bottom 16 defined, top 16 undef */
    asm("movw  $0, 66(%ecx)");
    asm("add   66(%ecx),%dx"); /* def, unless use wrong edx subdw offs */
    asm("cmp   $0, %dx"); /* NOT uninit */

    asm("sub   %dx,66(%ecx)"); /* def, unless use wrong edx subdw offs */
    asm("cmp   $0, %dx"); /* NOT uninit */

    /* test movzx offs mismatch (i#396) */
    asm("mov   $0,%eax");
    asm("mov   32(%ecx),%al"); /* al undef */
    asm("movzx %ah,%dx");
    asm("cmp   $0, %dx"); /* NOT uninit */
    asm("movzx %al,%dx");
    asm("cmp   $0, %dx"); /* uninit */
    asm("movzx %ah,%edx");
    asm("cmp   $0, %edx"); /* NOT uninit */

    /* ALU */
    asm("sub   %edx,32(%ecx)");
    asm("sub   32(%ecx),%edx");
#endif
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

int
main()
{
#ifdef LINUX
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

    return 0;
}
