/* **********************************************************
 * Copyright (c) 2011-2014 Google, Inc.  All rights reserved.
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

#include "../wininc/wdm.h"

#include "table_defines.h"

/* i#1549 We use the following approach here:
 * 1) We use macros below to describe secondary syscall entries.
 * 2) We add all syscalls with secondary components in the separate
 *    hashtable using drsys_sysnum_t.
 */

#define ENTRY_QueryKey(classname, typename)\
     {\
         {0, sizeof(HANDLE), SYSARG_INLINED, DRSYS_TYPE_HANDLE},\
         {1, sizeof(KEY_INFORMATION_CLASS), SYSARG_INLINED, DRSYS_TYPE_SIGNED_INT, classname},\
         {2, -3, W, 0, typename},\
         {2, -4, WI},\
         {3, sizeof(ULONG), SYSARG_INLINED, DRSYS_TYPE_UNSIGNED_INT},\
         {4, sizeof(ULONG), W|HT, DRSYS_TYPE_UNSIGNED_INT},\
    }

/* Since _ version of structure names stored in PDBs, we use the same names here. */
syscall_info_t syscall_QueryKey_info[] = {
   {{0,0},"NtQueryKey.KeyBasicInformation", OK|SYSINFO_RET_SMALL_WRITE_LAST, RNTST, 5,
         ENTRY_QueryKey("KeyBasicInformation", "_KEY_BASIC_INFORMATION")
   },
   {{0,0},"NtQueryKey.KeyNodeInformation", OK|SYSINFO_RET_SMALL_WRITE_LAST, RNTST, 5,
         ENTRY_QueryKey("KeyNodeInformation", "_KEY_NODE_INFORMATION")
   },
   {{0,0},"NtQueryKey.KeyFullInformation", OK|SYSINFO_RET_SMALL_WRITE_LAST, RNTST, 5,
         ENTRY_QueryKey("KeyFullInformation", "_KEY_FULL_INFORMATION")
   },
   {{0,0},"NtQueryKey.KeyNameInformation", OK|SYSINFO_RET_SMALL_WRITE_LAST, RNTST, 5,
         ENTRY_QueryKey("KeyNameInformation", "_KEY_NAME_INFORMATION")
   },
   {{0,0},"NtQueryKey.KeyCachedInformation", OK|SYSINFO_RET_SMALL_WRITE_LAST, RNTST, 5,
         ENTRY_QueryKey("KeyCachedInformation", "_KEY_CACHED_INFORMATION")
   },
   {{0,0},"NtQueryKey.KeyFlagsInformation", OK|SYSINFO_RET_SMALL_WRITE_LAST, RNTST, 5,
         ENTRY_QueryKey("KeyFlagsInformation", "Reserved")
   },
   {{0,0},"NtQueryKey.KeyVirtualizationInformation", OK|SYSINFO_RET_SMALL_WRITE_LAST, RNTST, 5,
         ENTRY_QueryKey("KeyVirtualizationInformation",
                        "_KEY_VIRTUALIZATION_INFORMATION")
   },
   {{0,0},"NtQueryKey.KeyHandleTagsInformation", OK|SYSINFO_RET_SMALL_WRITE_LAST, RNTST, 5,
         ENTRY_QueryKey("KeyHandleTagsInformation", "Reserved")
   },
   {{0,0},"NtQueryKey.MaximumValue", OK|SYSINFO_RET_SMALL_WRITE_LAST, RNTST, 5,
         ENTRY_QueryKey("MaxKeyInfoClass", "MaximumValue")
   },
   {SECONDARY_TABLE_ENTRY_MAX_NUMBER},
};

