/* **********************************************************
 * Copyright (c) 2012 Google, Inc.  All rights reserved.
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

/***************************************************************************
 * assembly utilities for which there are no intrinsics
 */

#include "cpp2asm_defines.h"

START_FILE


/* void get_stack_registers(reg_t *xsp OUT, reg_t *xbp OUT);
 *
 * Returns the current values of xsp and xbp.
 * There's no cl intrinsic to get xbp (gcc has one), and even
 * then would have to assume no FPO to get xsp.
 */
#define FUNCNAME get_stack_registers
        DECLARE_FUNC(FUNCNAME)
GLOBAL_LABEL(FUNCNAME:)
        mov      REG_XAX, ARG1
        mov      REG_XCX, ARG2
        mov      PTRSZ [REG_XCX], REG_XBP
        mov      REG_XCX, REG_XSP
#if defined(X64) && defined(WINDOWS)
        add      REG_XCX, 32 + ARG_SZ   /* remove frame space + retaddr */
#elif !defined(X64)
        add      REG_XCX, 3 * ARG_SZ    /* remove args + retaddr */

#endif
        mov      PTRSZ [REG_XAX], REG_XCX
        ret
        END_FUNC(FUNCNAME)
#undef FUNCNAME


END_FILE
