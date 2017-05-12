/* **********************************************************
 * Copyright (c) 2011-2016 Google, Inc.  All rights reserved.
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

#include "dr_api.h"
#include "drsyscall.h"
#include "drsyscall_os.h"
#include "drsyscall_windows.h"
#include "table_defines.h"

/* To be able to use the syscall_info_t description scheme for both library calls
 * and system calls, perform arguments printing without additional hashtable and
 * special routines for library calls handling, we decide to assign a "fake"
 * syscall number for each libcall entry and distingiush them using a special bit
 * defined below.
 */
#define DR_LIBCALL 0x70000000

/* NOTE: These entries are used in drsys_num_to_syscall() and allows to perform
 * library calls arguments printing using a name of library call.
 */

/* XXX: i#1948: We have to add more library calls. */
syscall_info_t libcall_kernel32_info[] = {
    {{DR_LIBCALL,0},"CreateFileA", OK, DRSYS_TYPE_HANDLE, 7,
     {
         {0, sizeof(CSTRING), R|CT, SYSARG_TYPE_CSTRING},
         {1, sizeof(DWORD), SYSARG_INLINED, DRSYS_TYPE_UNSIGNED_INT},
         {2, sizeof(DWORD), SYSARG_INLINED, DRSYS_TYPE_UNSIGNED_INT},
         {3, sizeof(PVOID), SYSARG_INLINED, DRSYS_TYPE_UNKNOWN},
         {4, sizeof(DWORD), SYSARG_INLINED, DRSYS_TYPE_UNSIGNED_INT},
         {5, sizeof(DWORD), SYSARG_INLINED, DRSYS_TYPE_UNSIGNED_INT},
         {6, sizeof(HANDLE), SYSARG_INLINED, DRSYS_TYPE_HANDLE},
     }
    },
    {{DR_LIBCALL,0},"CreateFileW", OK, DRSYS_TYPE_HANDLE, 7,
     {
         {0, sizeof(CWSTRING), R|CT, SYSARG_TYPE_CSTRING_WIDE},
         {1, sizeof(DWORD), SYSARG_INLINED, DRSYS_TYPE_UNSIGNED_INT},
         {2, sizeof(DWORD), SYSARG_INLINED, DRSYS_TYPE_UNSIGNED_INT},
         {3, sizeof(PVOID), SYSARG_INLINED, DRSYS_TYPE_UNKNOWN},
         {4, sizeof(DWORD), SYSARG_INLINED, DRSYS_TYPE_UNSIGNED_INT},
         {5, sizeof(DWORD), SYSARG_INLINED, DRSYS_TYPE_UNSIGNED_INT},
         {6, sizeof(HANDLE), SYSARG_INLINED, DRSYS_TYPE_HANDLE},
     }
    },
};

#define NUM_KERNEL32_LIBCALLS \
    (sizeof(libcall_kernel32_info)/sizeof(libcall_kernel32_info[0]))

size_t
num_libcall_kernel32_info(void)
{
    return NUM_KERNEL32_LIBCALLS;
}

