/* **********************************************************
 * Copyright (c) 2012-2015 Google, Inc.  All rights reserved.
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

/* **********************************************************
 * Portions Copyright (c) 2014-2015 Google, Inc.  All rights reserved.
 * ***********************************************************/
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
 * ARE DISCLAIMED. IN NO EVENT SHALL VMWARE, INC. OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
 * CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH
 * DAMAGE.
 */


/***************************************************************************
 * assembly utilities
 */

#include "cpp2asm_defines.h"

START_FILE

/* void get_stack_registers(reg_t *sp OUT, reg_t *fp OUT) */
/*  Get this reviewed. Assuming x0 and x1 hold addresses
  * of the memory locations for the arguments which are
  * passed by reference.
*/
#define FUNCNAME get_stack_registers
        DECLARE_FUNC(FUNCNAME)
GLOBAL_LABEL(FUNCNAME:)
        mov      x2, SP
        str      x2, [x0]
        str      FP, [x1]
        ret
        END_FUNC(FUNCNAME)
#undef FUNCNAME


#ifdef LINUX
/* Straight from DynamoRIO.
 * Signature: raw_syscall(sysnum, num_args, arg1, arg2, ...)
 * x8 - syscall number
 * x0 to x6 - syscall arguments
 */
        DECLARE_FUNC(raw_syscall)
GLOBAL_LABEL(raw_syscall:)
        /*Set up first 6 args and read 7th arg from stack
        only if there are at least 7 args*/
        cmp      w1, #7
        mov      x8, x0
        mov      x0, x2
        mov      x1, x3
        mov      x2, x4
        mov      x3, x5
        mov      x4, x6
        mov      x5, x7
        b.cc     1f
1:
        svc      #0
        ret
        END_FUNC(raw_syscall)
#endif /* LINUX */


/* void zero_pointers_on_stack(size_t count);
 * assuming count must be multiple of ARG_SZ
 *
 * Scans the memory in [xsp - count - ARG_SZ, xsp - ARG_SZ) and set it to 0
 * if the content looks like a pointer (> 0x10000).
 * Meant to be used to zero the stack, which is dangerous to do
 * from C as we can easily clobber our own local variables.
 */
#define FUNCNAME zero_pointers_on_stack
        DECLARE_FUNC_SEH(FUNCNAME)
GLOBAL_LABEL(FUNCNAME:)
        neg      x0, x0
        sub      x0, x0, #ARG_SZ
        mov      x2, #0
1:
        /* we assume no pointer pointing to address below 0x10000 */
        ldr      x1, [SP, x0]
        cmp      x1, HEX(10000)
        b.le     2f /* skip store if not a pointer */
        str      x2, [SP, x0]
2:
        add      x0, x0, #ARG_SZ
        cmp      x0, #-ARG_SZ
        bne      1b
        ret
        END_FUNC(FUNCNAME)
#undef FUNCNAME


END_FILE
