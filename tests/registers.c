/* **********************************************************
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
    printf("before regtest\n");
#ifdef WINDOWS
    /* if this gets any longer should use asm_defines.asm and write cross-os asm */
    __asm {
        pushfd
        pop   eax
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
    printf("after regtest\n");
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
    return 0;
}
