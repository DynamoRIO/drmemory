/* **********************************************************
 * Copyright (c) 2011 Google, Inc.  All rights reserved.
 * Copyright (c) 2007-2010 VMware, Inc.  All rights reserved.
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
#include "drmemory.h"
#include "syscall.h"
#include "syscall_os.h"
#include "readwrite.h"
#include <stddef.h> /* offsetof */

#include "../wininc/ndk_dbgktypes.h"
#include "../wininc/ndk_iotypes.h"
#include "../wininc/ndk_extypes.h"
#include "../wininc/afd_shared.h"
#include "../wininc/msafdlib.h"
#include "../wininc/winioctl.h"

extern bool
wingdi_process_syscall(bool pre, void *drcontext, int sysnum, per_thread_t *pt,
                       dr_mcontext_t *mc);

extern bool
wingdi_process_syscall_arg(bool pre, int sysnum, dr_mcontext_t *mc, uint arg_num,
                           const syscall_arg_t *arg_info, app_pc start, uint size);

/***************************************************************************
 * WIN32K.SYS SYSTEM CALL NUMBERS
 */

/* For non-exported syscall wrappers we have tables of numbers */

#define NONE -1

#define IMM32 USER32
#define GDI32 USER32
#define KERNEL32 USER32

const char * const sysnum_names[] = {
#define USER32(name, w7wow, w7x86, vistawow, vistax86, xpwow, w2003, xpx86, w2K)   #name,
#include "syscall_numx.h"
#undef USER32
};
#define NUM_SYSNUM_NAMES (sizeof(sysnum_names)/sizeof(sysnum_names[0]))

const int win7wow_sysnums[] = {
#define USER32(n, w7wow, w7x86, vistawow, vistax86, xpwow, w2003, xpx86, w2K)   w7wow,
#include "syscall_numx.h"
#undef USER32
};

const int win7x86_sysnums[] = {
#define USER32(n, w7wow, w7x86, vistawow, vistax86, xpwow, w2003, xpx86, w2K)   w7x86,
#include "syscall_numx.h"
#undef USER32
};

const int vistawow_sysnums[] = {
#define USER32(n, w7wow, w7x86, vistawow, vistax86, xpwow, w2003, xpx86, w2K)   vistawow,
#include "syscall_numx.h"
#undef USER32
};

const int vistax86_sysnums[] = {
#define USER32(n, w7wow, w7x86, vistawow, vistax86, xpwow, w2003, xpx86, w2K)   vistax86,
#include "syscall_numx.h"
#undef USER32
};

const int winXPwow_sysnums[] = {
#define USER32(n, w7wow, w7x86, vistawow, vistax86, xpwow, w2003, xpx86, w2K)   xpwow,
#include "syscall_numx.h"
#undef USER32
};

const int win2003_sysnums[] = {
#define USER32(n, w7wow, w7x86, vistawow, vistax86, xpwow, w2003, xpx86, w2K)   w2003,
#include "syscall_numx.h"
#undef USER32
};

const int winXP_sysnums[] = {
#define USER32(n, w7wow, w7x86, vistawow, vistax86, xpwow, w2003, xpx86, w2K)   xpx86,
#include "syscall_numx.h"
#undef USER32
};

const int win2K_sysnums[] = {
#define USER32(n, w7wow, w7x86, vistawow, vistax86, xpwow, w2003, xpx86, w2K)   w2K,
#include "syscall_numx.h"
#undef USER32
};

#undef IMM32
#undef GDI32
#undef KERNEL32

/* Table that maps win32k.sys names to numbers.  We store the unchanged number
 * under the assumption that it's never 0 (that would be an ntoskrnl syscall)
 */
#define SYSNUM_TABLE_HASH_BITS 12 /* nearly 1K of them, x2 for no-prefix entries */
static hashtable_t sysnum_table;

#ifdef STATISTICS
/* Until we have everything in the tables for syscall_lookup we use this
 * to provide names
 */
# define SYSNAME_TABLE_HASH_BITS 11 /* nearly 1K of them */
static hashtable_t sysname_table;
#endif

/***************************************************************************
 * SYSTEM CALLS FOR WINDOWS
 */

/* We need a hashtable to map system call # to index in table, since syscall #s
 * vary by Windows version.
 */
#define SYSTABLE_HASH_BITS 12 /* has ntoskrnl and win32k.sys */
static hashtable_t systable;

/* Syscalls that need special processing.  The address of each is kept
 * in the syscall_info_t entry so we don't need separate lookup.
 */
static int sysnum_CreateThread = -1;
static int sysnum_CreateThreadEx = -1;
static int sysnum_CreateUserProcess = -1;
static int sysnum_DeviceIoControlFile = -1;
static int sysnum_QuerySystemInformation = -1;
static int sysnum_SetSystemInformation = -1;

/* FIXME i#97: IIS syscalls!
 * FIXME i#98: add new XP, Vista, and Win7 syscalls!
 * FIXME i#99: my windows syscall data is missing 3 types of information:
 *   - some structs have variable-length data on the end
 *     e.g., PORT_MESSAGE which I do handle today w/ hardcoded support
 *   - some structs have optional fields that don't need to be defined
 *   - need to add post-syscall write size entries: I put in a handful.
 *     should look at all OUT params whose (requested) size comes from an IN param.
 *     e.g., NtQueryValueKey: should use IN param to check addressability, but
 *     OUT ResultLength for what was actually written to.
 *     The strategy for these is to use a double entry with the second typically
 *     using WI to indicate that the OUT size needs to be dereferenced (PR 408536).
 *     E.g.:
 *       {0,"NtQuerySecurityObject", 20, 2,-3,W, 2,-4,WI, 4,sizeof(ULONG),W, },
 */
/* Originally generated via:
 *  ./mksystable.pl < ../../win32lore/syscalls/nebbett/ntdll-fix.h | sort
 * (ntdll-fix.h has NTAPI, etc. added to NtNotifyChangeDirectoryFile)
 * Don't forget to re-add the #if 1 below after re-generating
 *
 * Updated version generated via:
 * ./mksystable.pl < ../../win32lore/syscalls/metasploit/metasploit-syscalls-fix.html | sort 
 * metasploit-syscalls-fix.html has these changes:
 * - added IN/OUT to NtTranslateFilePath
 * - removed dups (in some cases not clear which alternative was better):
 *   > grep '^Nt' ../../win32lore/syscalls/metasploit/metasploit-syscalls.html | uniq -d
 *   NtAllocateUuids(
 *   NtOpenChannel(
 *   NtPlugPlayControl(
 *   NtReplyWaitSendChannel(
 *   NtSendWaitReplyChannel(
 *   NtSetContextChannel(
 * Also made manual additions for post-syscall write sizes
 * and to set arg size for 0-args syscalls to 0 (xref PR 534421)
 */
#define OK (SYSINFO_ALL_PARAMS_KNOWN)
#define UNKNOWN 0
#define W (SYSARG_WRITE)
#define R (SYSARG_READ)
#define CT (SYSARG_COMPLEX_TYPE)
#define WI (SYSARG_WRITE | SYSARG_LENGTH_INOUT)
#define IB (SYSARG_INLINED_BOOLEAN)
#define IO (SYSARG_POST_SIZE_IO_STATUS)
#define RET (SYSARG_POST_SIZE_RETVAL)
static syscall_info_t syscall_ntdll_info[] = {
    /* Base set from Windows NT, Windows 2000, and Windows XP */
    {0,"NtAcceptConnectPort", OK, 24, {{0,sizeof(HANDLE),W}, {2,sizeof(PORT_MESSAGE),R|CT,SYSARG_TYPE_PORT_MESSAGE}, {3,0,IB}, {4,sizeof(PORT_VIEW),R|W}, {5,sizeof(REMOTE_PORT_VIEW),R|W}, }},
    {0,"NtAccessCheck", OK, 32, {{0,sizeof(SECURITY_DESCRIPTOR),R|CT,SYSARG_TYPE_SECURITY_DESCRIPTOR}, {3,sizeof(GENERIC_MAPPING),R}, {4,sizeof(PRIVILEGE_SET),W}, {5,sizeof(ULONG),R}, {6,sizeof(ACCESS_MASK),W}, {7,sizeof(BOOLEAN),W}, }},
    {0,"NtAccessCheckAndAuditAlarm", OK, 44, {{0,sizeof(UNICODE_STRING),R|CT,SYSARG_TYPE_UNICODE_STRING}, {2,sizeof(UNICODE_STRING),R|CT,SYSARG_TYPE_UNICODE_STRING}, {3,sizeof(UNICODE_STRING),R|CT,SYSARG_TYPE_UNICODE_STRING}, {4,sizeof(SECURITY_DESCRIPTOR),R|CT,SYSARG_TYPE_SECURITY_DESCRIPTOR}, {6,sizeof(GENERIC_MAPPING),R}, {7,0,IB}, {8,sizeof(ACCESS_MASK),W}, {9,sizeof(BOOLEAN),W}, {10,sizeof(BOOLEAN),W}, }},
    {0,"NtAccessCheckByType", OK, 44, {{0,sizeof(SECURITY_DESCRIPTOR),R|CT,SYSARG_TYPE_SECURITY_DESCRIPTOR}, {1,sizeof(SID),R}, {4,sizeof(OBJECT_TYPE_LIST),R}, {6,sizeof(GENERIC_MAPPING),R}, {7,sizeof(PRIVILEGE_SET),R}, {8,sizeof(ULONG),R}, {9,sizeof(ACCESS_MASK),W}, {10,sizeof(ULONG),W}, }},
    {0,"NtAccessCheckByTypeAndAuditAlarm", OK, 64, {{0,sizeof(UNICODE_STRING),R|CT,SYSARG_TYPE_UNICODE_STRING}, {2,sizeof(UNICODE_STRING),R|CT,SYSARG_TYPE_UNICODE_STRING}, {3,sizeof(UNICODE_STRING),R|CT,SYSARG_TYPE_UNICODE_STRING}, {4,sizeof(SECURITY_DESCRIPTOR),R|CT,SYSARG_TYPE_SECURITY_DESCRIPTOR}, {5,sizeof(SID),R}, {9,sizeof(OBJECT_TYPE_LIST),R}, {11,sizeof(GENERIC_MAPPING),R}, {12,0,IB}, {13,sizeof(ACCESS_MASK),W}, {14,sizeof(ULONG),W}, {15,sizeof(BOOLEAN),W}, }},
    {0,"NtAccessCheckByTypeResultList", OK, 44, {{0,sizeof(SECURITY_DESCRIPTOR),R|CT,SYSARG_TYPE_SECURITY_DESCRIPTOR}, {1,sizeof(SID),R}, {4,sizeof(OBJECT_TYPE_LIST),R}, {6,sizeof(GENERIC_MAPPING),R}, {7,sizeof(PRIVILEGE_SET),R}, {8,sizeof(ULONG),R}, {9,sizeof(ACCESS_MASK),W}, {10,sizeof(ULONG),W}, }},
    {0,"NtAccessCheckByTypeResultListAndAuditAlarm", OK, 64, {{0,sizeof(UNICODE_STRING),R|CT,SYSARG_TYPE_UNICODE_STRING}, {2,sizeof(UNICODE_STRING),R|CT,SYSARG_TYPE_UNICODE_STRING}, {3,sizeof(UNICODE_STRING),R|CT,SYSARG_TYPE_UNICODE_STRING}, {4,sizeof(SECURITY_DESCRIPTOR),R|CT,SYSARG_TYPE_SECURITY_DESCRIPTOR}, {5,sizeof(SID),R}, {9,sizeof(OBJECT_TYPE_LIST),R}, {11,sizeof(GENERIC_MAPPING),R}, {12,0,IB}, {13,sizeof(ACCESS_MASK),W}, {14,sizeof(ULONG),W}, {15,sizeof(ULONG),W}, }},
    {0,"NtAccessCheckByTypeResultListAndAuditAlarmByHandle", OK, 68, {{0,sizeof(UNICODE_STRING),R|CT,SYSARG_TYPE_UNICODE_STRING}, {3,sizeof(UNICODE_STRING),R|CT,SYSARG_TYPE_UNICODE_STRING}, {4,sizeof(UNICODE_STRING),R|CT,SYSARG_TYPE_UNICODE_STRING}, {5,sizeof(SECURITY_DESCRIPTOR),R|CT,SYSARG_TYPE_SECURITY_DESCRIPTOR}, {6,sizeof(SID),R}, {10,sizeof(OBJECT_TYPE_LIST),R}, {12,sizeof(GENERIC_MAPPING),R}, {13,0,IB}, {14,sizeof(ACCESS_MASK),W}, {15,sizeof(ULONG),W}, {16,sizeof(ULONG),W}, }},
    {0,"NtAddAtom", OK, 12, {{0,-1,R}, {2,sizeof(USHORT),W}, }},
    {0,"NtAddBootEntry", OK, 8, {{0,sizeof(UNICODE_STRING),R|CT,SYSARG_TYPE_UNICODE_STRING}, {1,sizeof(UNICODE_STRING),R|CT,SYSARG_TYPE_UNICODE_STRING}, }},
    {0,"NtAddDriverEntry", OK, 8, {{0,sizeof(UNICODE_STRING),R|CT,SYSARG_TYPE_UNICODE_STRING}, {1,sizeof(UNICODE_STRING),R|CT,SYSARG_TYPE_UNICODE_STRING}, }},
    {0,"NtAdjustGroupsToken", OK, 24, {{1,0,IB}, {2,sizeof(TOKEN_GROUPS),R}, {4,-3,W}, {4,-5,WI}, {5,sizeof(ULONG),W}, }},
    {0,"NtAdjustPrivilegesToken", OK, 24, {{1,0,IB}, {2,sizeof(TOKEN_PRIVILEGES),R}, {4,-3,W}, {4,-5,WI}, {5,sizeof(ULONG),W}, }},
    {0,"NtAlertResumeThread", OK, 8, {{1,sizeof(ULONG),W}, }},
    {0,"NtAlertThread", OK, 4, },
    {0,"NtAllocateLocallyUniqueId", OK, 4, {{0,sizeof(LUID),W}, }},
    {0,"NtAllocateUserPhysicalPages", OK, 12, {{1,sizeof(ULONG),R}, {2,sizeof(ULONG),W}, }},
    {0,"NtAllocateUuids", OK, 16, {{0,sizeof(LARGE_INTEGER),W}, {1,sizeof(ULONG),W}, {2,sizeof(ULONG),W}, {3,sizeof(UCHAR),W}, }},
    {0,"NtAllocateVirtualMemory", OK, 24, {{1,sizeof(PVOID),R|W}, {3,sizeof(ULONG),R|W}, }},
    {0,"NtApphelpCacheControl", OK, 8, {{1,sizeof(UNICODE_STRING),R|CT,SYSARG_TYPE_UNICODE_STRING}, }},
    {0,"NtAreMappedFilesTheSame", OK, 8, },
    {0,"NtAssignProcessToJobObject", OK, 8, },
    {0,"NtCallbackReturn", OK, 12, },
    {0,"NtCancelDeviceWakeupRequest", OK, 4, },
    {0,"NtCancelIoFile", OK, 8, {{1,sizeof(IO_STATUS_BLOCK),W}, }},
    {0,"NtCancelTimer", OK, 8, {{1,sizeof(BOOLEAN),W}, }},
    {0,"NtClearEvent", OK, 4, },
    {0,"NtClose", OK, 4, },
    {0,"NtCloseObjectAuditAlarm", OK, 12, {{0,sizeof(UNICODE_STRING),R|CT,SYSARG_TYPE_UNICODE_STRING}, {2,0,IB}, }},
    {0,"NtCompactKeys", OK, 8, },
    {0,"NtCompareTokens", OK, 12, {{2,sizeof(BOOLEAN),W}, }},
    {0,"NtCompleteConnectPort", OK, 4, },
    {0,"NtCompressKey", OK, 4, },
    /* Arg#4 is IN OUT for Nebbett, but not for Metasploit */
    {0,"NtConnectPort", OK, 32, {{0,sizeof(HANDLE),W}, {1,sizeof(UNICODE_STRING),R|CT,SYSARG_TYPE_UNICODE_STRING}, {2,sizeof(SECURITY_QUALITY_OF_SERVICE),R|CT,SYSARG_TYPE_SECURITY_QOS}, {3,sizeof(PORT_VIEW),R|W}, {4,sizeof(REMOTE_PORT_VIEW),W}, {5,sizeof(ULONG),W}, {6,-7,R|WI}, {7,sizeof(ULONG),R|W}, }},
    {0,"NtContinue", OK, 8, {{0,sizeof(CONTEXT),R|CT,SYSARG_TYPE_CONTEXT}, {1,0,IB}, }},
    {0,"NtCreateChannel", OK, 8, {{0,sizeof(HANDLE),W}, {1,sizeof(OBJECT_ATTRIBUTES),R|CT,SYSARG_TYPE_OBJECT_ATTRIBUTES}, }},
    {0,"NtCreateDebugObject", OK, 16, {{0,sizeof(HANDLE),W}, {2,sizeof(OBJECT_ATTRIBUTES),R|CT,SYSARG_TYPE_OBJECT_ATTRIBUTES}, {3,0,IB}, }},
    {0,"NtCreateDirectoryObject", OK, 12, {{0,sizeof(HANDLE),W}, {2,sizeof(OBJECT_ATTRIBUTES),R|CT,SYSARG_TYPE_OBJECT_ATTRIBUTES}, }},
    {0,"NtCreateEvent", OK, 20, {{0,sizeof(HANDLE),W}, {2,sizeof(OBJECT_ATTRIBUTES),R|CT,SYSARG_TYPE_OBJECT_ATTRIBUTES}, {4,0,IB}, }},
    {0,"NtCreateEventPair", OK, 12, {{0,sizeof(HANDLE),W}, {2,sizeof(OBJECT_ATTRIBUTES),R|CT,SYSARG_TYPE_OBJECT_ATTRIBUTES}, }},
    {0,"NtCreateFile", OK, 44, {{0,sizeof(HANDLE),W}, {2,sizeof(OBJECT_ATTRIBUTES),R|CT,SYSARG_TYPE_OBJECT_ATTRIBUTES}, {3,sizeof(IO_STATUS_BLOCK),W}, {4,sizeof(LARGE_INTEGER),R}, }},
    {0,"NtCreateIoCompletion", OK, 16, {{0,sizeof(HANDLE),W}, {2,sizeof(OBJECT_ATTRIBUTES),R|CT,SYSARG_TYPE_OBJECT_ATTRIBUTES}, }},
    {0,"NtCreateJobObject", OK, 12, {{0,sizeof(HANDLE),W}, {2,sizeof(OBJECT_ATTRIBUTES),R|CT,SYSARG_TYPE_OBJECT_ATTRIBUTES}, }},
    {0,"NtCreateJobSet", OK, 12, {{1,sizeof(JOB_SET_ARRAY),R}, }},
    {0,"NtCreateKey", OK, 28, {{0,sizeof(HANDLE),W}, {2,sizeof(OBJECT_ATTRIBUTES),R|CT,SYSARG_TYPE_OBJECT_ATTRIBUTES}, {4,sizeof(UNICODE_STRING),R|CT,SYSARG_TYPE_UNICODE_STRING}, {6,sizeof(ULONG),W}, }},
    {0,"NtCreateKeyedEvent", OK, 16, {{0,sizeof(HANDLE),W}, {2,sizeof(OBJECT_ATTRIBUTES),R|CT,SYSARG_TYPE_OBJECT_ATTRIBUTES}, }},
    {0,"NtCreateMailslotFile", OK, 32, {{0,sizeof(HANDLE),W}, {2,sizeof(OBJECT_ATTRIBUTES),R|CT,SYSARG_TYPE_OBJECT_ATTRIBUTES}, {3,sizeof(IO_STATUS_BLOCK),W}, {7,sizeof(LARGE_INTEGER),R}, }},
    {0,"NtCreateMutant", OK, 16, {{0,sizeof(HANDLE),W}, {2,sizeof(OBJECT_ATTRIBUTES),R|CT,SYSARG_TYPE_OBJECT_ATTRIBUTES}, {3,0,IB}, }},
    {0,"NtCreateNamedPipeFile", OK, 56, {{0,sizeof(HANDLE),W}, {2,sizeof(OBJECT_ATTRIBUTES),R|CT,SYSARG_TYPE_OBJECT_ATTRIBUTES}, {3,sizeof(IO_STATUS_BLOCK),W}, {7,0,IB}, {8,0,IB}, {9,0,IB}, {13,sizeof(LARGE_INTEGER),R}, }},
    {0,"NtCreatePagingFile", OK, 16, {{0,sizeof(UNICODE_STRING),R|CT,SYSARG_TYPE_UNICODE_STRING}, {1,sizeof(ULARGE_INTEGER),R}, {2,sizeof(ULARGE_INTEGER),R}, }},
    {0,"NtCreatePort", OK, 20, {{0,sizeof(HANDLE),W}, {1,sizeof(OBJECT_ATTRIBUTES),R|CT,SYSARG_TYPE_OBJECT_ATTRIBUTES}, }},
    {0,"NtCreateProcess", OK, 32, {{0,sizeof(HANDLE),W}, {2,sizeof(OBJECT_ATTRIBUTES),R|CT,SYSARG_TYPE_OBJECT_ATTRIBUTES}, {4,0,IB}, }},
    {0,"NtCreateProcessEx", OK, 36, {{0,sizeof(HANDLE),W}, {2,sizeof(OBJECT_ATTRIBUTES),R|CT,SYSARG_TYPE_OBJECT_ATTRIBUTES}, }},
    {0,"NtCreateProfile", OK, 36, {{0,sizeof(HANDLE),W}, {5,sizeof(ULONG),R}, }},
    {0,"NtCreateSection", OK, 28, {{0,sizeof(HANDLE),W}, {2,sizeof(OBJECT_ATTRIBUTES),R|CT,SYSARG_TYPE_OBJECT_ATTRIBUTES}, {3,sizeof(LARGE_INTEGER),R}, }},
    {0,"NtCreateSemaphore", OK, 20, {{0,sizeof(HANDLE),W}, {2,sizeof(OBJECT_ATTRIBUTES),R|CT,SYSARG_TYPE_OBJECT_ATTRIBUTES}, }},
    {0,"NtCreateSymbolicLinkObject", OK, 16, {{0,sizeof(HANDLE),W}, {2,sizeof(OBJECT_ATTRIBUTES),R|CT,SYSARG_TYPE_OBJECT_ATTRIBUTES}, {3,sizeof(UNICODE_STRING),R|CT,SYSARG_TYPE_UNICODE_STRING}, }},
    {0,"NtCreateThread", OK, 32, {{0,sizeof(HANDLE),W}, {2,sizeof(OBJECT_ATTRIBUTES),R|CT,SYSARG_TYPE_OBJECT_ATTRIBUTES}, {4,sizeof(CLIENT_ID),W}, {5,sizeof(CONTEXT),R|CT,SYSARG_TYPE_CONTEXT}, {6,sizeof(USER_STACK),R}, {7,0,IB}, }, &sysnum_CreateThread},
    {0,"NtCreateThreadEx", OK, 44, {{0,sizeof(HANDLE),W}, {2,sizeof(OBJECT_ATTRIBUTES),R|CT,SYSARG_TYPE_OBJECT_ATTRIBUTES}, 6,0,IB /*rest handled manually*/, }, &sysnum_CreateThreadEx},
    {0,"NtCreateTimer", OK, 16, {{0,sizeof(HANDLE),W}, {2,sizeof(OBJECT_ATTRIBUTES),R|CT,SYSARG_TYPE_OBJECT_ATTRIBUTES}, }},
    {0,"NtCreateToken", OK, 52, {{0,sizeof(HANDLE),W}, {2,sizeof(OBJECT_ATTRIBUTES),R|CT,SYSARG_TYPE_OBJECT_ATTRIBUTES}, {4,sizeof(LUID),R}, {5,sizeof(LARGE_INTEGER),R}, {6,sizeof(TOKEN_USER),R}, {7,sizeof(TOKEN_GROUPS),R}, {8,sizeof(TOKEN_PRIVILEGES),R}, {9,sizeof(TOKEN_OWNER),R}, {10,sizeof(TOKEN_PRIMARY_GROUP),R}, {11,sizeof(TOKEN_DEFAULT_DACL),R}, {12,sizeof(TOKEN_SOURCE),R}, }},
    {0,"NtCreateUserProcess", OK, 44, {{0,sizeof(HANDLE),W}, {1,sizeof(HANDLE),W}, {4,sizeof(OBJECT_ATTRIBUTES),R|CT,SYSARG_TYPE_OBJECT_ATTRIBUTES}, {5,sizeof(OBJECT_ATTRIBUTES),R|CT,SYSARG_TYPE_OBJECT_ATTRIBUTES}, {7,0,IB}, {8,sizeof(RTL_USER_PROCESS_PARAMETERS),R}, /*XXX i#98: arg 9 is in/out but not completely known*/ 10,sizeof(create_proc_thread_info_t),R/*rest handled manually*/, }, &sysnum_CreateUserProcess},
    {0,"NtCreateWaitablePort", OK, 20, {{0,sizeof(HANDLE),W}, {1,sizeof(OBJECT_ATTRIBUTES),R|CT,SYSARG_TYPE_OBJECT_ATTRIBUTES}, }},
    {0,"NtDebugActiveProcess", OK, 8, },
    {0,"NtDebugContinue", OK, 12, {{1,sizeof(CLIENT_ID),R}, }},
    {0,"NtDelayExecution", OK, 8, {{0,0,IB}, {1,sizeof(LARGE_INTEGER),R}, }},
    {0,"NtDeleteAtom", OK, 4, },
    {0,"NtDeleteBootEntry", OK, 8, {{0,sizeof(UNICODE_STRING),R|CT,SYSARG_TYPE_UNICODE_STRING}, {1,sizeof(UNICODE_STRING),R|CT,SYSARG_TYPE_UNICODE_STRING}, }},
    {0,"NtDeleteDriverEntry", OK, 8, {{0,sizeof(UNICODE_STRING),R|CT,SYSARG_TYPE_UNICODE_STRING}, {1,sizeof(UNICODE_STRING),R|CT,SYSARG_TYPE_UNICODE_STRING}, }},
    {0,"NtDeleteFile", OK, 4, {{0,sizeof(OBJECT_ATTRIBUTES),R|CT,SYSARG_TYPE_OBJECT_ATTRIBUTES}, }},
    {0,"NtDeleteKey", OK, 4, },
    {0,"NtDeleteObjectAuditAlarm", OK, 12, {{0,sizeof(UNICODE_STRING),R|CT,SYSARG_TYPE_UNICODE_STRING}, {2,0,IB}, }},
    {0,"NtDeleteValueKey", OK, 8, {{1,sizeof(UNICODE_STRING),R|CT,SYSARG_TYPE_UNICODE_STRING}, }},
    {0,"NtDeviceIoControlFile", UNKNOWN/*to do param cmp for unknown ioctl codes*/, 40, {{4,sizeof(IO_STATUS_BLOCK),W}, /*param6 handled manually*/ {8,-9,W}, }, &sysnum_DeviceIoControlFile},
    {0,"NtDisplayString", OK, 4, {{0,sizeof(UNICODE_STRING),R|CT,SYSARG_TYPE_UNICODE_STRING}, }},
    {0,"NtDuplicateObject", OK, 28, {{3,sizeof(HANDLE),W}, }},
    {0,"NtDuplicateToken", OK, 24, {{2,sizeof(OBJECT_ATTRIBUTES),R|CT,SYSARG_TYPE_OBJECT_ATTRIBUTES}, {3,0,IB}, {5,sizeof(HANDLE),W}, }},
    {0,"NtEnumerateBootEntries", OK, 8, },
    {0,"NtEnumerateDriverEntries", OK, 8, },
    {0,"NtEnumerateKey", OK, 24, {{3,-4,W}, {3,-5,WI}, {5,sizeof(ULONG),W}, }},
    {0,"NtEnumerateSystemEnvironmentValuesEx", OK, 12, },
    {0,"NtEnumerateValueKey", OK, 24, {{3,-4,W}, {3,-5,WI}, {5,sizeof(ULONG),W}, }},
    {0,"NtExtendSection", OK, 8, {{1,sizeof(LARGE_INTEGER),R}, }},
    {0,"NtFilterToken", OK, 24, {{2,sizeof(TOKEN_GROUPS),R}, {3,sizeof(TOKEN_PRIVILEGES),R}, {4,sizeof(TOKEN_GROUPS),R}, {5,sizeof(HANDLE),W}, }},
    {0,"NtFindAtom", OK, 12, {{0,-1,R}, {2,sizeof(USHORT),W}, }},
    {0,"NtFlushBuffersFile", OK, 8, {{1,sizeof(IO_STATUS_BLOCK),W}, }},
    {0,"NtFlushInstructionCache", OK, 12, },
    {0,"NtFlushKey", OK, 4, },
    {0,"NtFlushVirtualMemory", OK, 16, {{1,sizeof(PVOID),R|W}, {2,sizeof(ULONG),R|W}, {3,sizeof(IO_STATUS_BLOCK),W}, }},
    {0,"NtFlushWriteBuffer", OK, 0, },
    {0,"NtFreeUserPhysicalPages", OK, 12, {{1,sizeof(ULONG),R|W}, {2,sizeof(ULONG),R}, }},
    {0,"NtFreeVirtualMemory", OK, 16, {{1,sizeof(PVOID),R|W}, {2,sizeof(ULONG),R|W}, }},
    {0,"NtFsControlFile", OK, 40, {{4,sizeof(IO_STATUS_BLOCK),W}, {8,-9,W}, }},
    {0,"NtGetContextThread", OK, 8, {{1,sizeof(CONTEXT),W|CT,SYSARG_TYPE_CONTEXT}, }},
    {0,"NtGetCurrentProcessorNumber", OK, 4, },
    {0,"NtGetDevicePowerState", OK, 8, {{1,sizeof(DEVICE_POWER_STATE),W}, }},
    {0,"NtGetPlugPlayEvent", OK, 16, {{2,-3,W}, }},
    /* BufferEntries is #elements, not #bytes */
    {0,"NtGetWriteWatch", OK, 28, {{4,-5,WI|SYSARG_SIZE_IN_ELEMENTS,sizeof(void*)}, {4,-5,WI|SYSARG_SIZE_IN_ELEMENTS,sizeof(void*)}, {5,sizeof(ULONG),R|W}, {6,sizeof(ULONG),W}, }},
    {0,"NtImpersonateAnonymousToken", OK, 4, },
    {0,"NtImpersonateClientOfPort", OK, 8, {{1,sizeof(PORT_MESSAGE),R|CT,SYSARG_TYPE_PORT_MESSAGE}, }},
    {0,"NtImpersonateThread", OK, 12, {{2,sizeof(SECURITY_QUALITY_OF_SERVICE),R|CT,SYSARG_TYPE_SECURITY_QOS}, }},
    {0,"NtInitializeRegistry", OK, 4, {{0,0,IB}, }},
    {0,"NtInitiatePowerAction", OK, 16, {{3,0,IB}, }},
    {0,"NtIsProcessInJob", OK, 8, },
    {0,"NtIsSystemResumeAutomatic", OK, 0, },
    {0,"NtListenChannel", OK, 8, {{1,sizeof(CHANNEL_MESSAGE),W}, }},
    {0,"NtListenPort", OK, 8, {{1,sizeof(PORT_MESSAGE),W|CT,SYSARG_TYPE_PORT_MESSAGE}, }},
    {0,"NtLoadDriver", OK, 4, {{0,sizeof(UNICODE_STRING),R|CT,SYSARG_TYPE_UNICODE_STRING}, }},
    {0,"NtLoadKey2", OK, 12, {{0,sizeof(OBJECT_ATTRIBUTES),R|CT,SYSARG_TYPE_OBJECT_ATTRIBUTES}, {1,sizeof(OBJECT_ATTRIBUTES),R|CT,SYSARG_TYPE_OBJECT_ATTRIBUTES}, }},
    {0,"NtLoadKey", OK, 8, {{0,sizeof(OBJECT_ATTRIBUTES),R|CT,SYSARG_TYPE_OBJECT_ATTRIBUTES}, {1,sizeof(OBJECT_ATTRIBUTES),R|CT,SYSARG_TYPE_OBJECT_ATTRIBUTES}, }},
    {0,"NtLoadKeyEx", OK, 16, {{0,sizeof(OBJECT_ATTRIBUTES),R|CT,SYSARG_TYPE_OBJECT_ATTRIBUTES}, {1,sizeof(OBJECT_ATTRIBUTES),R|CT,SYSARG_TYPE_OBJECT_ATTRIBUTES}, }},
    {0,"NtLockFile", OK, 40, {{4,sizeof(IO_STATUS_BLOCK),W}, {5,sizeof(ULARGE_INTEGER),R}, {6,sizeof(ULARGE_INTEGER),R}, {8,0,IB}, {9,0,IB}, }},
    {0,"NtLockProductActivationKeys", OK, 8, {{0,sizeof(ULONG),W}, {1,sizeof(ULONG),W}, }},
    {0,"NtLockRegistryKey", OK, 4, },
    {0,"NtLockVirtualMemory", OK, 16, {{1,sizeof(PVOID),R|W}, {2,sizeof(ULONG),R|W}, }},
    {0,"NtMakePermanentObject", OK, 4, },
    {0,"NtMakeTemporaryObject", OK, 4, },
    {0,"NtMapCMFModule", OK, 24, {/* XXX DRi#415 not all known */ {4,sizeof(PVOID),W}, {5,sizeof(ULONG),W}, }},
    {0,"NtMapUserPhysicalPages", OK, 12, {{1,sizeof(ULONG),R}, {2,sizeof(ULONG),R}, }},
    {0,"NtMapUserPhysicalPagesScatter", OK, 12, {{0,sizeof(PVOID),R}, {1,sizeof(ULONG),R}, {2,sizeof(ULONG),R}, }},
    {0,"NtMapViewOfSection", OK, 40, {{2,sizeof(PVOID),R|W}, {5,sizeof(LARGE_INTEGER),R|W}, {6,sizeof(ULONG),R|W}, }},
    {0,"NtModifyBootEntry", OK, 8, {{0,sizeof(UNICODE_STRING),R|CT,SYSARG_TYPE_UNICODE_STRING}, {1,sizeof(UNICODE_STRING),R|CT,SYSARG_TYPE_UNICODE_STRING}, }},
    {0,"NtModifyDriverEntry", OK, 8, {{0,sizeof(UNICODE_STRING),R|CT,SYSARG_TYPE_UNICODE_STRING}, {1,sizeof(UNICODE_STRING),R|CT,SYSARG_TYPE_UNICODE_STRING}, }},
    {0,"NtNotifyChangeDirectoryFile", OK, 36, {{4,sizeof(IO_STATUS_BLOCK),W}, {5,sizeof(FILE_NOTIFY_INFORMATION),W}, {8,0,IB}, }},
    {0,"NtNotifyChangeKey", OK, 40, {{4,sizeof(IO_STATUS_BLOCK),W}, {6,0,IB}, {9,0,IB}, }},
    {0,"NtNotifyChangeMultipleKeys", OK, 48, {{2,sizeof(OBJECT_ATTRIBUTES),R|CT,SYSARG_TYPE_OBJECT_ATTRIBUTES}, {6,sizeof(IO_STATUS_BLOCK),W}, {8,0,IB}, {11,0,IB}, }},
    {0,"NtOpenChannel", OK, 8, {{0,sizeof(HANDLE),W}, {1,sizeof(OBJECT_ATTRIBUTES),R|CT,SYSARG_TYPE_OBJECT_ATTRIBUTES}, }},
    {0,"NtOpenDirectoryObject", OK, 12, {{0,sizeof(HANDLE),W}, {2,sizeof(OBJECT_ATTRIBUTES),R|CT,SYSARG_TYPE_OBJECT_ATTRIBUTES}, }},
    {0,"NtOpenEvent", OK, 12, {{0,sizeof(HANDLE),W}, {2,sizeof(OBJECT_ATTRIBUTES),R|CT,SYSARG_TYPE_OBJECT_ATTRIBUTES}, }},
    {0,"NtOpenEventPair", OK, 12, {{0,sizeof(HANDLE),W}, {2,sizeof(OBJECT_ATTRIBUTES),R|CT,SYSARG_TYPE_OBJECT_ATTRIBUTES}, }},
    {0,"NtOpenFile", OK, 24, {{0,sizeof(HANDLE),W}, {2,sizeof(OBJECT_ATTRIBUTES),R|CT,SYSARG_TYPE_OBJECT_ATTRIBUTES}, {3,sizeof(IO_STATUS_BLOCK),W}, }},
    {0,"NtOpenIoCompletion", OK, 12, {{0,sizeof(HANDLE),W}, {2,sizeof(OBJECT_ATTRIBUTES),R|CT,SYSARG_TYPE_OBJECT_ATTRIBUTES}, }},
    {0,"NtOpenJobObject", OK, 12, {{0,sizeof(HANDLE),W}, {2,sizeof(OBJECT_ATTRIBUTES),R|CT,SYSARG_TYPE_OBJECT_ATTRIBUTES}, }},
    {0,"NtOpenKey", OK, 12, {{0,sizeof(HANDLE),W}, {2,sizeof(OBJECT_ATTRIBUTES),R|CT,SYSARG_TYPE_OBJECT_ATTRIBUTES}, }},
    {0,"NtOpenKeyEx", OK, 16, {{0,sizeof(HANDLE),W}, {2,sizeof(OBJECT_ATTRIBUTES),R|CT,SYSARG_TYPE_OBJECT_ATTRIBUTES}, }},
    {0,"NtOpenKeyedEvent", OK, 12, {{0,sizeof(HANDLE),W}, {2,sizeof(OBJECT_ATTRIBUTES),R|CT,SYSARG_TYPE_OBJECT_ATTRIBUTES}, }},
    {0,"NtOpenMutant", OK, 12, {{0,sizeof(HANDLE),W}, {2,sizeof(OBJECT_ATTRIBUTES),R|CT,SYSARG_TYPE_OBJECT_ATTRIBUTES}, }},
    {0,"NtOpenObjectAuditAlarm", OK, 48, {{0,sizeof(UNICODE_STRING),R|CT,SYSARG_TYPE_UNICODE_STRING}, {1,sizeof(PVOID),R}, {2,sizeof(UNICODE_STRING),R|CT,SYSARG_TYPE_UNICODE_STRING}, {3,sizeof(UNICODE_STRING),R|CT,SYSARG_TYPE_UNICODE_STRING}, {4,sizeof(SECURITY_DESCRIPTOR),R|CT,SYSARG_TYPE_SECURITY_DESCRIPTOR}, {8,sizeof(PRIVILEGE_SET),R}, {9,0,IB}, {10,0,IB}, {11,sizeof(BOOLEAN),W}, }},
    {0,"NtOpenProcess", OK, 16, {{0,sizeof(HANDLE),W}, {2,sizeof(OBJECT_ATTRIBUTES),R|CT,SYSARG_TYPE_OBJECT_ATTRIBUTES}, {3,sizeof(CLIENT_ID),R}, }},
    {0,"NtOpenProcessToken", OK, 12, {{2,sizeof(HANDLE),W}, }},
    {0,"NtOpenProcessTokenEx", OK, 16, {{3,sizeof(HANDLE),W}, }},
    {0,"NtOpenSection", OK, 12, {{0,sizeof(HANDLE),W}, {2,sizeof(OBJECT_ATTRIBUTES),R|CT,SYSARG_TYPE_OBJECT_ATTRIBUTES}, }},
    {0,"NtOpenSemaphore", OK, 12, {{0,sizeof(HANDLE),W}, {2,sizeof(OBJECT_ATTRIBUTES),R|CT,SYSARG_TYPE_OBJECT_ATTRIBUTES}, }},
    {0,"NtOpenSymbolicLinkObject", OK, 12, {{0,sizeof(HANDLE),W}, {2,sizeof(OBJECT_ATTRIBUTES),R|CT,SYSARG_TYPE_OBJECT_ATTRIBUTES}, }},
    {0,"NtOpenThread", OK, 16, {{0,sizeof(HANDLE),W}, {2,sizeof(OBJECT_ATTRIBUTES),R|CT,SYSARG_TYPE_OBJECT_ATTRIBUTES}, {3,sizeof(CLIENT_ID),R}, }},
    {0,"NtOpenThreadToken", OK, 16, {{2,0,IB}, {3,sizeof(HANDLE),W}, }},
    {0,"NtOpenThreadTokenEx", OK, 20, {{2,0,IB}, {4,sizeof(HANDLE),W}, }},
    {0,"NtOpenTimer", OK, 12, {{0,sizeof(HANDLE),W}, {2,sizeof(OBJECT_ATTRIBUTES),R|CT,SYSARG_TYPE_OBJECT_ATTRIBUTES}, }},
    {0,"NtPlugPlayControl", OK, 16, {{1,-2,W}, }},
    {0,"NtPowerInformation", OK, 20, {{3,-4,W}, }},
    {0,"NtPrivilegeCheck", OK, 12, {{1,sizeof(PRIVILEGE_SET),R}, {2,sizeof(BOOLEAN),W}, }},
    {0,"NtPrivilegedServiceAuditAlarm", OK, 20, {{0,sizeof(UNICODE_STRING),R|CT,SYSARG_TYPE_UNICODE_STRING}, {1,sizeof(UNICODE_STRING),R|CT,SYSARG_TYPE_UNICODE_STRING}, {3,sizeof(PRIVILEGE_SET),R}, {4,0,IB}, }},
    {0,"NtPrivilegeObjectAuditAlarm", OK, 24, {{0,sizeof(UNICODE_STRING),R|CT,SYSARG_TYPE_UNICODE_STRING}, {4,sizeof(PRIVILEGE_SET),R}, {5,0,IB}, }},
    {0,"NtProtectVirtualMemory", OK, 20, {{1,sizeof(PVOID),R|W}, {2,sizeof(ULONG),R|W}, {4,sizeof(ULONG),W}, }},
    {0,"NtPulseEvent", OK, 8, {{1,sizeof(ULONG),W}, }},
    {0,"NtQueryAttributesFile", OK, 8, {{0,sizeof(OBJECT_ATTRIBUTES),R|CT,SYSARG_TYPE_OBJECT_ATTRIBUTES}, {1,sizeof(FILE_BASIC_INFORMATION),W}, }},
    {0,"NtQueryBootEntryOrder", OK, 8, },
    {0,"NtQueryBootOptions", OK, 8, },
    {0,"NtQueryDebugFilterState", OK, 8, },
    {0,"NtQueryDefaultLocale", OK, 8, {{0,0,IB}, {1,sizeof(LCID),W}, }},
    {0,"NtQueryDefaultUILanguage", OK, 4, {{0,sizeof(LANGID),W}, }},
    {0,"NtQueryDirectoryFile", OK, 44, {{4,sizeof(IO_STATUS_BLOCK),W}, {5,-6,W}, {8,0,IB}, {9,sizeof(UNICODE_STRING),R|CT,SYSARG_TYPE_UNICODE_STRING}, {10,0,IB}, }},
    {0,"NtQueryDirectoryObject", OK, 28, {{1,-2,W}, {1,-6,WI}, {3,0,IB}, {4,0,IB}, {5,sizeof(ULONG),R|W}, {6,sizeof(ULONG),W}, }},
    {0,"NtQueryDriverEntryOrder", OK, 8, },
    {0,"NtQueryEaFile", OK, 36, {{1,sizeof(IO_STATUS_BLOCK),W}, {2,sizeof(FILE_FULL_EA_INFORMATION),W}, {4,0,IB}, {5,sizeof(FILE_GET_EA_INFORMATION),R}, {7,sizeof(ULONG),R}, {8,0,IB}, }},
    {0,"NtQueryEvent", OK, 20, {{2,-3,W}, {2,-4,WI}, {4,sizeof(ULONG),W}, }},
    {0,"NtQueryFullAttributesFile", OK, 8, {{0,sizeof(OBJECT_ATTRIBUTES),R|CT,SYSARG_TYPE_OBJECT_ATTRIBUTES}, {1,sizeof(FILE_NETWORK_OPEN_INFORMATION),W}, }},
    {0,"NtQueryInformationAtom", OK, 20, {{2,-3,W}, {2,-4,WI}, {4,sizeof(ULONG),W}, }},
    {0,"NtQueryInformationFile", OK, 20, {{1,sizeof(IO_STATUS_BLOCK),W}, {2,-3,W}, }},
    {0,"NtQueryInformationJobObject", OK, 20, {{2,-3,W}, {2,-4,WI}, {4,sizeof(ULONG),W}, }},
    {0,"NtQueryInformationPort", OK, 20, {{2,-3,W}, {2,-4,WI}, {4,sizeof(ULONG),W}, }},
    {0,"NtQueryInformationProcess", OK, 20, {{2,-3,W}, {2,-4,WI}, {4,sizeof(ULONG),W}, }},
    {0,"NtQueryInformationThread", OK, 20, {{2,-3,W}, {2,-4,WI}, {4,sizeof(ULONG),W}, }},
    {0,"NtQueryInformationToken", OK, 20, {{2,-3,W}, {2,-4,WI}, {4,sizeof(ULONG),W}, }},
    {0,"NtQueryInstallUILanguage", OK, 4, {{0,sizeof(LANGID),W}, }},
    {0,"NtQueryIntervalProfile", OK, 8, {{1,sizeof(ULONG),W}, }},
    {0,"NtQueryIoCompletion", OK, 20, {{2,-3,W}, {2,-4,WI}, {4,sizeof(ULONG),W}, }},
    {0,"NtQueryKey", OK, 20, {{2,-3,W}, {2,-4,WI}, {4,sizeof(ULONG),W}, }},
    {0,"NtQueryMultipleValueKey", OK, 24, {{1,sizeof(KEY_VALUE_ENTRY),R|W}, {3,-4,WI}, {4,sizeof(ULONG),R|W}, {5,sizeof(ULONG),W}, }},
    {0,"NtQueryMutant", OK, 20, {{2,-3,W}, {2,-4,WI}, {4,sizeof(ULONG),W}, }},
    {0,"NtQueryObject", OK, 20, {{2,-3,W}, {2,-4,WI}, {4,sizeof(ULONG),W}, }},
    {0,"NtQueryOleDirectoryFile", OK, 44, {{4,sizeof(IO_STATUS_BLOCK),W}, {5,-6,W}, {8,0,IB}, {9,sizeof(UNICODE_STRING),R|CT,SYSARG_TYPE_UNICODE_STRING}, {10,0,IB}, }},
    {0,"NtQueryOpenSubKeys", OK, 8, {{0,sizeof(OBJECT_ATTRIBUTES),R|CT,SYSARG_TYPE_OBJECT_ATTRIBUTES}, {1,sizeof(ULONG),W}, }},
    {0,"NtQueryOpenSubKeysEx", OK, 16, {{0,sizeof(OBJECT_ATTRIBUTES),R|CT,SYSARG_TYPE_OBJECT_ATTRIBUTES}, {2,sizeof(ULONG),W}, {3,sizeof(ULONG),W}, }},
    {0,"NtQueryPerformanceCounter", OK, 8, {{0,sizeof(LARGE_INTEGER),W}, {1,sizeof(LARGE_INTEGER),W}, }},
    {0,"NtQueryPortInformationProcess", OK, 4, },
    {0,"NtQueryQuotaInformationFile", OK, 36, {{1,sizeof(IO_STATUS_BLOCK),W}, {2,sizeof(FILE_USER_QUOTA_INFORMATION),W}, {4,0,IB}, {5,sizeof(FILE_QUOTA_LIST_INFORMATION),R}, {7,sizeof(SID),R}, {8,0,IB}, }},
    {0,"NtQuerySection", OK, 20, {{2,-3,W}, {2,-4,WI}, {4,sizeof(ULONG),W}, }},
    {0,"NtQuerySecurityObject", OK, 20, {{2,-3,W}, {2,-4,WI}, {4,sizeof(ULONG),W}, }},
    {0,"NtQuerySemaphore", OK, 20, {{2,-3,W}, {2,-4,WI}, {4,sizeof(ULONG),W}, }},
    /* No double entry for 3rd param needed b/c the written size is in
     * .Length of the UNICODE_STRING as well as returned in the param:
     */
    {0,"NtQuerySymbolicLinkObject", OK, 12, {{1,sizeof(UNICODE_STRING),W|CT,SYSARG_TYPE_UNICODE_STRING}, {2,sizeof(ULONG),W}, }},
    {0,"NtQuerySystemEnvironmentValue", OK, 16, {{0,sizeof(UNICODE_STRING),R|CT,SYSARG_TYPE_UNICODE_STRING}, {1,-2,W}, {1,-3,WI}, {3,sizeof(ULONG),W}, }},
    {0,"NtQuerySystemEnvironmentValueEx", OK, 20, },
    /* One info class reads data, which is special-cased */
    {0,"NtQuerySystemInformation", OK, 16, {{1,-2,W}, {1,-3,WI}, {3,sizeof(ULONG),W}, }, &sysnum_QuerySystemInformation},
    {0,"NtQuerySystemTime", OK, 4, {{0,sizeof(LARGE_INTEGER),W}, }},
    {0,"NtQueryTimer", OK, 20, {{2,-3,W}, {2,-4,WI}, {4,sizeof(ULONG),W}, }},
    {0,"NtQueryTimerResolution", OK, 12, {{0,sizeof(ULONG),W}, {1,sizeof(ULONG),W}, {2,sizeof(ULONG),W}, }},
    {0,"NtQueryValueKey", OK, 24, {{1,sizeof(UNICODE_STRING),R|CT,SYSARG_TYPE_UNICODE_STRING}, {3,-4,W}, {3,-5,WI}, {5,sizeof(ULONG),W}, }},
    {0,"NtQueryVirtualMemory", OK, 24, {{3,-4,W}, {3,-5,WI}, {5,sizeof(ULONG),W}, }},
    {0,"NtQueryVolumeInformationFile", OK, 20, {{1,sizeof(IO_STATUS_BLOCK),W}, {2,-3,W}, }},
    {0,"NtQueueApcThread", OK, 20, },
    {0,"NtRaiseException", OK, 12, {{0,sizeof(EXCEPTION_RECORD),R|CT,SYSARG_TYPE_EXCEPTION_RECORD}, {1,sizeof(CONTEXT),R|CT,SYSARG_TYPE_CONTEXT}, {2,0,IB}, }},
    {0,"NtRaiseHardError", OK, 24, {{3,sizeof(ULONG_PTR),R}, {5,sizeof(ULONG),W}, }},
    {0,"NtReadFile", OK, 36, {{4,sizeof(IO_STATUS_BLOCK),W}, {5,-6,W}, {5,-4,(W|IO)}, {7,sizeof(LARGE_INTEGER),R}, {8,sizeof(ULONG),R}, }},
    {0,"NtReadFileScatter", OK, 36, {{4,sizeof(IO_STATUS_BLOCK),W}, {5,sizeof(FILE_SEGMENT_ELEMENT),R}, {7,sizeof(LARGE_INTEGER),R}, {8,sizeof(ULONG),R}, }},
    {0,"NtReadRequestData", OK, 24, {{1,sizeof(PORT_MESSAGE),R|CT,SYSARG_TYPE_PORT_MESSAGE}, {3,-4,W}, {3,-5,WI}, {5,sizeof(ULONG),W}, }},
    {0,"NtReadVirtualMemory", OK, 20, {{2,-3,W}, {2,-4,WI}, {4,sizeof(ULONG),W}, }},
    {0,"NtRegisterThreadTerminatePort", OK, 4, },
    {0,"NtReleaseKeyedEvent", OK, 16, {{2,0,IB}, {3,sizeof(LARGE_INTEGER),R}, }},
    {0,"NtReleaseMutant", OK, 8, {{1,sizeof(ULONG),W}, }},
    {0,"NtReleaseSemaphore", OK, 12, {{2,sizeof(LONG),W}, }},
    {0,"NtRemoveIoCompletion", OK, 20, {{1,sizeof(ULONG),W}, {2,sizeof(ULONG),W}, {3,sizeof(IO_STATUS_BLOCK),W}, {4,sizeof(LARGE_INTEGER),R}, }},
    {0,"NtRemoveProcessDebug", OK, 8, },
    {0,"NtRenameKey", OK, 8, {{1,sizeof(UNICODE_STRING),R|CT,SYSARG_TYPE_UNICODE_STRING}, }},
    {0,"NtReplaceKey", OK, 12, {{0,sizeof(OBJECT_ATTRIBUTES),R|CT,SYSARG_TYPE_OBJECT_ATTRIBUTES}, {2,sizeof(OBJECT_ATTRIBUTES),R|CT,SYSARG_TYPE_OBJECT_ATTRIBUTES}, }},
    {0,"NtReplyPort", OK, 8, {{1,sizeof(PORT_MESSAGE),R|CT,SYSARG_TYPE_PORT_MESSAGE}, }},
    {0,"NtReplyWaitReceivePort", OK, 16, {{1,sizeof(ULONG),W}, {2,sizeof(PORT_MESSAGE),R|CT,SYSARG_TYPE_PORT_MESSAGE}, {3,sizeof(PORT_MESSAGE),W|CT,SYSARG_TYPE_PORT_MESSAGE}, }},
    {0,"NtReplyWaitReceivePortEx", OK, 20, {{1,sizeof(PVOID),W}, {2,sizeof(PORT_MESSAGE),R|CT,SYSARG_TYPE_PORT_MESSAGE}, {3,sizeof(PORT_MESSAGE),W|CT,SYSARG_TYPE_PORT_MESSAGE}, {4,sizeof(LARGE_INTEGER),R}, }},
    {0,"NtReplyWaitReplyPort", OK, 8, {{1,sizeof(PORT_MESSAGE),R|W|CT,SYSARG_TYPE_PORT_MESSAGE}, }},
    {0,"NtReplyWaitSendChannel", OK, 12, {{2,sizeof(CHANNEL_MESSAGE),W}, }},
    {0,"NtRequestDeviceWakeup", OK, 4, },
    {0,"NtRequestPort", OK, 8, {{1,sizeof(PORT_MESSAGE),R|CT,SYSARG_TYPE_PORT_MESSAGE}, }},
#if 1
    /* FIXME PR 406356: suppressing undefined read I see on every app at process
     * termination on w2k3 vm (though not on wow64 laptop) where the last 16
     * bytes are not filled in (so only length and type are).  Length indicates
     * there is data afterward which we try to handle specially.
     */
    {0,"NtRequestWaitReplyPort", OK, 12, {{1,8,R}, {2,sizeof(PORT_MESSAGE),W|CT,SYSARG_TYPE_PORT_MESSAGE}, }},
#else
    {0,"NtRequestWaitReplyPort", OK, 12, {{1,sizeof(PORT_MESSAGE),R|CT,SYSARG_TYPE_PORT_MESSAGE}, {2,sizeof(PORT_MESSAGE),W|CT,SYSARG_TYPE_PORT_MESSAGE}, }},
#endif
    {0,"NtRequestWakeupLatency", OK, 4, },
    {0,"NtResetEvent", OK, 8, {{1,sizeof(ULONG),W}, }},
    {0,"NtResetWriteWatch", OK, 12, },
    {0,"NtRestoreKey", OK, 12, },
    {0,"NtResumeProcess", OK, 4, },
    {0,"NtResumeThread", OK, 8, {{1,sizeof(ULONG),W}, }},
    {0,"NtSaveKey", OK, 8, },
    {0,"NtSaveKeyEx", OK, 12, },
    {0,"NtSaveMergedKeys", OK, 12, },
    {0,"NtSecureConnectPort", OK, 36, {{0,sizeof(HANDLE),W}, {1,sizeof(UNICODE_STRING),R|CT,SYSARG_TYPE_UNICODE_STRING}, {2,sizeof(SECURITY_QUALITY_OF_SERVICE),R|CT,SYSARG_TYPE_SECURITY_QOS}, {3,sizeof(PORT_VIEW),R|W}, {4,sizeof(SID),R}, {5,sizeof(REMOTE_PORT_VIEW),R|W}, {6,sizeof(ULONG),W}, {7,-8,R|WI}, {8,sizeof(ULONG),R|W}, }},
    {0,"NtSendWaitReplyChannel", OK, 16, {{3,sizeof(CHANNEL_MESSAGE),W}, }},
    {0,"NtSetBootEntryOrder", OK, 8, },
    {0,"NtSetBootOptions", OK, 8, {{0,sizeof(BOOT_OPTIONS),R}, }},
    {0,"NtSetContextChannel", OK, 4, },
    {0,"NtSetContextThread", OK, 8, {{1,sizeof(CONTEXT),R|CT,SYSARG_TYPE_CONTEXT}, }},
    {0,"NtSetDebugFilterState", OK, 12, {{2,0,IB}, }},
    {0,"NtSetDefaultHardErrorPort", OK, 4, },
    {0,"NtSetDefaultLocale", OK, 8, {{0,0,IB}, }},
    {0,"NtSetDefaultUILanguage", OK, 4, },
    {0,"NtSetEaFile", OK, 16, {{1,sizeof(IO_STATUS_BLOCK),W}, {2,sizeof(FILE_FULL_EA_INFORMATION),R}, }},
    {0,"NtSetEvent", OK, 8, {{1,sizeof(ULONG),W}, }},
    {0,"NtSetEventBoostPriority", OK, 4, },
    {0,"NtSetHighEventPair", OK, 4, },
    {0,"NtSetHighWaitLowEventPair", OK, 4, },
    {0,"NtSetHighWaitLowThread", OK, 0, },
    {0,"NtSetInformationDebugObject", OK, 20, {{4,sizeof(ULONG),W}, }},
    {0,"NtSetInformationFile", OK, 20, {{1,sizeof(IO_STATUS_BLOCK),W}, }},
    {0,"NtSetInformationJobObject", OK, 16, },
    {0,"NtSetInformationKey", OK, 16, },
    {0,"NtSetInformationObject", OK, 16, },
    {0,"NtSetInformationProcess", OK, 16, },
    {0,"NtSetInformationThread", OK, 16, },
    {0,"NtSetInformationToken", OK, 16, },
    {0,"NtSetIntervalProfile", OK, 8, },
    {0,"NtSetIoCompletion", OK, 20, },
    {0,"NtSetLdtEntries", OK, 16, },
    {0,"NtSetLowEventPair", OK, 4, },
    {0,"NtSetLowWaitHighEventPair", OK, 4, },
    {0,"NtSetLowWaitHighThread", OK, 0, },
    {0,"NtSetQuotaInformationFile", OK, 16, {{1,sizeof(IO_STATUS_BLOCK),W}, {2,sizeof(FILE_USER_QUOTA_INFORMATION),R}, }},
    {0,"NtSetSecurityObject", OK, 12, {{2,sizeof(SECURITY_DESCRIPTOR),R|CT,SYSARG_TYPE_SECURITY_DESCRIPTOR}, }},
    {0,"NtSetSystemEnvironmentValue", OK, 8, {{0,sizeof(UNICODE_STRING),R|CT,SYSARG_TYPE_UNICODE_STRING}, {1,sizeof(UNICODE_STRING),R|CT,SYSARG_TYPE_UNICODE_STRING}, }},
    {0,"NtSetSystemEnvironmentValueEx", OK, 8, {{0,sizeof(UNICODE_STRING),R|CT,SYSARG_TYPE_UNICODE_STRING}, {1,sizeof(GUID),R}, }},
    /* Some info classes write data as well, which is special-cased */
    {0,"NtSetSystemInformation", OK, 12, {{1,-2,R}, }, &sysnum_SetSystemInformation},
    {0,"NtSetSystemPowerState", OK, 12, },
    {0,"NtSetSystemTime", OK, 8, {{0,sizeof(LARGE_INTEGER),R}, {1,sizeof(LARGE_INTEGER),W}, }},
    {0,"NtSetThreadExecutionState", OK, 8, {{1,sizeof(EXECUTION_STATE),W}, }},
    {0,"NtSetTimer", OK, 28, {{1,sizeof(LARGE_INTEGER),R}, {4,0,IB}, {6,sizeof(BOOLEAN),W}, }},
    {0,"NtSetTimerResolution", OK, 12, {{1,0,IB}, {2,sizeof(ULONG),W}, }},
    {0,"NtSetUuidSeed", OK, 4, {{0,sizeof(UCHAR),R}, }},
    {0,"NtSetValueKey", OK, 24, {{1,sizeof(UNICODE_STRING),R|CT,SYSARG_TYPE_UNICODE_STRING}, }},
    {0,"NtSetVolumeInformationFile", OK, 20, {{1,sizeof(IO_STATUS_BLOCK),W}, }},
    {0,"NtShutdownSystem", OK, 4, },
    {0,"NtSignalAndWaitForSingleObject", OK, 16, {{2,0,IB}, {3,sizeof(LARGE_INTEGER),R}, }},
    {0,"NtStartProfile", OK, 4, },
    {0,"NtStopProfile", OK, 4, },
    {0,"NtSuspendProcess", OK, 4, },
    {0,"NtSuspendThread", OK, 8, {{1,sizeof(ULONG),W}, }},
    {0,"NtSystemDebugControl", OK, 24, {{3,-4,W}, {3,-5,WI}, {5,sizeof(ULONG),W}, }},
    {0,"NtTerminateJobObject", OK, 8, },
    {0,"NtTerminateProcess", OK, 8, },
    {0,"NtTerminateThread", OK, 8, },
    {0,"NtTestAlert", OK, 0, },
    /* unlike TraceEvent API routine, syscall takes size+flags as
     * separate params, and struct observed to be all uninit, so we
     * assume struct is all OUT
     */
    {0,"NtTraceEvent", OK, 16, {{3,sizeof(EVENT_TRACE_HEADER),W}, }},
    {0,"NtTranslateFilePath", OK, 16, {{0,sizeof(FILE_PATH),R}, {2,sizeof(FILE_PATH),W}, }},
    {0,"NtUnloadDriver", OK, 4, {{0,sizeof(UNICODE_STRING),R|CT,SYSARG_TYPE_UNICODE_STRING}, }},
    {0,"NtUnloadKey2", OK, 8, {{0,sizeof(OBJECT_ATTRIBUTES),R|CT,SYSARG_TYPE_OBJECT_ATTRIBUTES}, {1,0,IB}, }},
    {0,"NtUnloadKey", OK, 4, {{0,sizeof(OBJECT_ATTRIBUTES),R|CT,SYSARG_TYPE_OBJECT_ATTRIBUTES}, }},
    {0,"NtUnloadKeyEx", OK, 8, {{0,sizeof(OBJECT_ATTRIBUTES),R|CT,SYSARG_TYPE_OBJECT_ATTRIBUTES}, }},
    {0,"NtUnlockFile", OK, 20, {{1,sizeof(IO_STATUS_BLOCK),W}, {2,sizeof(ULARGE_INTEGER),R}, {3,sizeof(ULARGE_INTEGER),R}, }},
    {0,"NtUnlockVirtualMemory", OK, 16, {{1,sizeof(PVOID),R|W}, {2,sizeof(ULONG),R|W}, }},
    {0,"NtUnmapViewOfSection", OK, 8, },
    {0,"NtVdmControl", OK, 8, },
    {0,"NtW32Call", OK, 20, {{3,-4,WI/*FIXME: de-ref w/o corresponding R to check definedness: but not enough info to understand exactly what's going on here*/}, {4,sizeof(ULONG),W}, }},
    {0,"NtWaitForDebugEvent", OK, 16, {{1,0,IB}, {2,sizeof(LARGE_INTEGER),R}, {3,sizeof(DBGUI_WAIT_STATE_CHANGE),W}, }},
    {0,"NtWaitForKeyedEvent", OK, 16, {{2,0,IB}, {3,sizeof(LARGE_INTEGER),R}, }},
    {0,"NtWaitForMultipleObjects", OK, 20, {{1,sizeof(HANDLE),R}, {3,0,IB}, {4,sizeof(LARGE_INTEGER),R}, }},
    {0,"NtWaitForMultipleObjects32", OK, 20, {{1,sizeof(HANDLE),R}, {3,0,IB}, {4,sizeof(LARGE_INTEGER),R}, }},
    {0,"NtWaitForSingleObject", OK, 12, {{1,0,IB}, {2,sizeof(LARGE_INTEGER),R}, }},
    {0,"NtWaitHighEventPair", OK, 4, },
    {0,"NtWaitLowEventPair", OK, 4, },
    {0,"NtWriteFile", OK, 36, {{4,sizeof(IO_STATUS_BLOCK),W}, {7,sizeof(LARGE_INTEGER),R}, {8,sizeof(ULONG),R}, }},
    {0,"NtWriteFileGather", OK, 36, {{4,sizeof(IO_STATUS_BLOCK),W}, {5,sizeof(FILE_SEGMENT_ELEMENT),R}, {7,sizeof(LARGE_INTEGER),R}, {8,sizeof(ULONG),R}, }},
    {0,"NtWriteRequestData", OK, 24, {{1,sizeof(PORT_MESSAGE),R|CT,SYSARG_TYPE_PORT_MESSAGE}, {5,sizeof(ULONG),W}, }},
    {0,"NtWriteVirtualMemory", OK, 20, {{4,sizeof(ULONG),W}, }},
    {0,"NtYieldExecution", OK, 0, },

    /* added in Windows 2003 */
    /* FIXME i#98: has two PULONG params.  Is 2nd an INOUT count of 1st array or what? */
    {0,"NtSetDriverEntryOrder", UNKNOWN, 8, },

    /* added in Windows XP64 WOW64 */
    {0,"NtWow64CsrClientConnectToServer", UNKNOWN, 20, },
    {0,"NtWow64CsrNewThread", UNKNOWN, 0, },
    {0,"NtWow64CsrIdentifyAlertableThread", UNKNOWN, 0, },
    {0,"NtWow64CsrClientCallServer", UNKNOWN, 16, },
    {0,"NtWow64CsrAllocateCaptureBuffer", UNKNOWN, 8, },
    {0,"NtWow64CsrFreeCaptureBuffer", UNKNOWN, 4, },
    {0,"NtWow64CsrAllocateMessagePointer", UNKNOWN, 12, },
    {0,"NtWow64CsrCaptureMessageBuffer", UNKNOWN, 16, },
    {0,"NtWow64CsrCaptureMessageString", UNKNOWN, 20, },
    {0,"NtWow64CsrSetPriorityClass", UNKNOWN, 8, },
    {0,"NtWow64CsrGetProcessId", UNKNOWN, 0, },
    {0,"NtWow64DebuggerCall", UNKNOWN, 20, },
    /* args seem to be identical to NtQuerySystemInformation */
    {0,"NtWow64GetNativeSystemInformation", OK, 16, {{1,-2,W}, {1,-3,WI}, {3,sizeof(ULONG),W}, }},
    {0,"NtWow64QueryInformationProcess64", UNKNOWN, 20, },
    {0,"NtWow64ReadVirtualMemory64", UNKNOWN, 28, },
    {0,"NtWow64QueryVirtualMemory64", UNKNOWN, 32, },

    /* added in Windows Vista SP0 */
    {0,"NtAcquireCMFViewOwnership", UNKNOWN, 12, },
    {0,"NtAlpcAcceptConnectPort", UNKNOWN, 36, },
    {0,"NtAlpcCancelMessage", UNKNOWN, 12, },
    {0,"NtAlpcConnectPort", UNKNOWN, 44, },
    {0,"NtAlpcCreatePort", UNKNOWN, 12, },
    {0,"NtAlpcCreatePortSection", UNKNOWN, 24, },
    {0,"NtAlpcCreatePortSection", UNKNOWN, 24, },
    {0,"NtAlpcCreateResourceReserve", UNKNOWN, 16, },
    {0,"NtAlpcCreateSectionView", UNKNOWN, 12, },
    {0,"NtAlpcCreateSecurityContext", UNKNOWN, 12, },
    {0,"NtAlpcDeletePortSection", UNKNOWN, 12, },
    {0,"NtAlpcDeleteResourceReserve", UNKNOWN, 12, },
    {0,"NtAlpcDeleteSectionView", UNKNOWN, 12, },
    {0,"NtAlpcDeleteSecurityContext", UNKNOWN, 12, },
    {0,"NtAlpcDisconnectPort", UNKNOWN, 8, },
    {0,"NtAlpcImpersonateClientOfPort", UNKNOWN, 12, },
    {0,"NtAlpcOpenSenderProcess", UNKNOWN, 24, },
    {0,"NtAlpcOpenSenderThread", UNKNOWN, 24, },
    {0,"NtAlpcQueryInformation", UNKNOWN, 20, },
    {0,"NtAlpcQueryInformationMessage", UNKNOWN, 24, },
    {0,"NtAlpcQueryInformationMessage", UNKNOWN, 24, },
    {0,"NtAlpcRevokeSecurityContext", UNKNOWN, 12, },
    {0,"NtAlpcSendWaitReceivePort", UNKNOWN, 32, },
    {0,"NtAlpcSetInformation", UNKNOWN, 16, },
    {0,"NtCancelIoFileEx", UNKNOWN, 12, },
    {0,"NtCancelSynchronousIoFile", UNKNOWN, 12, },
    {0,"NtClearAllSavepointsTransaction", UNKNOWN, 4, },
    {0,"NtClearSavepointTransaction", UNKNOWN, 8, },
    {0,"NtCommitComplete", UNKNOWN, 8, },
    {0,"NtCommitEnlistment", UNKNOWN, 8, },
    {0,"NtCommitTransaction", UNKNOWN, 8, },
    {0,"NtCreateEnlistment", UNKNOWN, 32, },
    {0,"NtCreateKeyTransacted", UNKNOWN, 32, },
    {0,"NtCreatePrivateNamespace", UNKNOWN, 16, },
    {0,"NtCreateResourceManager", UNKNOWN, 28, },
    {0,"NtCreateTransaction", UNKNOWN, 40, },
    {0,"NtCreateTransactionManager", UNKNOWN, 24, },
    {0,"NtCreateTransactionManager", UNKNOWN, 24, },
    {0,"NtCreateWorkerFactory", UNKNOWN, 40, },
    {0,"NtDeletePrivateNamespace", UNKNOWN, 4, },
    {0,"NtEnumerateTransactionObject", UNKNOWN, 20, },
    {0,"NtFlushInstallUILanguage", UNKNOWN, 8, },
    {0,"NtFlushProcessWriteBuffers", UNKNOWN, 0, },
    {0,"NtFreezeRegistry", UNKNOWN, 4, },
    {0,"NtFreezeTransactions", UNKNOWN, 8, },
    {0,"NtGetMUIRegistryInfo", UNKNOWN, 12, },
    {0,"NtGetNextProcess", UNKNOWN, 20, },
    {0,"NtGetNextThread", UNKNOWN, 24, },
    {0,"NtGetNlsSectionPtr", UNKNOWN, 20, },
    {0,"NtGetNotificationResourceManager", UNKNOWN, 28, },
    {0,"NtInitializeNlsFiles", UNKNOWN, 12, },
    {0,"NtIsUILanguageComitted", UNKNOWN, 0, },
    {0,"NtListTransactions", UNKNOWN, 12, },
    {0,"NtMarshallTransaction", UNKNOWN, 24, },
    {0,"NtOpenEnlistment", UNKNOWN, 20, },
    {0,"NtOpenKeyTransacted", UNKNOWN, 16, },
    {0,"NtOpenPrivateNamespace", UNKNOWN, 16, },
    {0,"NtOpenResourceManager", UNKNOWN, 20, },
    {0,"NtOpenSession", UNKNOWN, 12, },
    {0,"NtOpenTransaction", UNKNOWN, 20, },
    {0,"NtOpenTransactionManager", UNKNOWN, 24, },
    {0,"NtOpenTransactionManager", UNKNOWN, 24, },
    {0,"NtPrepareComplete", UNKNOWN, 8, },
    {0,"NtPrepareEnlistment", UNKNOWN, 8, },
    {0,"NtPrePrepareComplete", UNKNOWN, 8, },
    {0,"NtPrePrepareEnlistment", UNKNOWN, 8, },
    {0,"NtPropagationComplete", UNKNOWN, 16, },
    {0,"NtPropagationFailed", UNKNOWN, 12, },
    {0,"NtPullTransaction", UNKNOWN, 28, },
    {0,"NtQueryInformationEnlistment", UNKNOWN, 20, },
    {0,"NtQueryInformationResourceManager", UNKNOWN, 20, },
    {0,"NtQueryInformationTransaction", UNKNOWN, 20, },
    {0,"NtQueryInformationTransactionManager", UNKNOWN, 20, },
    {0,"NtQueryInformationTransactionManager", UNKNOWN, 20, },
    {0,"NtQueryInformationWorkerFactory", UNKNOWN, 20, },
    {0,"NtQueryLicenseValue", UNKNOWN, 20, },
    {0,"NtReadOnlyEnlistment", UNKNOWN, 8, },
    {0,"NtRecoverEnlistment", UNKNOWN, 8, },
    {0,"NtRecoverResourceManager", UNKNOWN, 4, },
    {0,"NtRecoverTransactionManager", UNKNOWN, 4, },
    {0,"NtRegisterProtocolAddressInformation", UNKNOWN, 20, },
    {0,"NtReleaseCMFViewOwnership", UNKNOWN, 0, },
    {0,"NtReleaseWorkerFactoryWorker", UNKNOWN, 4, },
    {0,"NtRemoveIoCompletionEx", UNKNOWN, 24, },
    {0,"NtRollbackComplete", UNKNOWN, 8, },
    {0,"NtRollbackEnlistment", UNKNOWN, 8, },
    {0,"NtRollbackSavepointTransaction", UNKNOWN, 8, },
    {0,"NtRollbackTransaction", UNKNOWN, 8, },
    {0,"NtRollforwardTransactionManager", UNKNOWN, 8, },
    {0,"NtSavepointComplete", UNKNOWN, 8, },
    {0,"NtSavepointTransaction", UNKNOWN, 12, },
    {0,"NtSetDriverEntryOrder", UNKNOWN, 8, },
    {0,"NtSetInformationEnlistment", UNKNOWN, 16, },
    {0,"NtSetInformationResourceManager", UNKNOWN, 16, },
    {0,"NtSetInformationTransaction", UNKNOWN, 16, },
    {0,"NtSetInformationTransactionManager", UNKNOWN, 16, },
    {0,"NtSetInformationTransactionManager", UNKNOWN, 16, },
    {0,"NtSetInformationWorkerFactory", UNKNOWN, 16, },
    {0,"NtSetSystemEnvironmentValueEx", UNKNOWN, 20, },
    {0,"NtShutdownWorkerFactory", UNKNOWN, 8, },
    {0,"NtSinglePhaseReject", UNKNOWN, 8, },
    {0,"NtStartTm", UNKNOWN, 0, },
    {0,"NtThawRegistry", UNKNOWN, 0, },
    {0,"NtThawTransactions", UNKNOWN, 0, },
    {0,"NtTraceControl", UNKNOWN, 24, },
    {0,"NtWaitForWorkViaWorkerFactory", UNKNOWN, 8, },
    {0,"NtWorkerFactoryWorkerReady", UNKNOWN, 4, },

    /* added in Windows Vista SP1 */
    {0,"NtRenameTransactionManager", UNKNOWN, 8, },
    {0,"NtReplacePartitionUnit", UNKNOWN, 12, },
    {0,"NtWow64CsrVerifyRegion", UNKNOWN, 8, },
    {0,"NtWow64WriteVirtualMemory64", UNKNOWN, 28, },
    {0,"NtWow64CallFunction64", UNKNOWN, 28, },

    /* added in Windows 7 */
    {0,"NtAllocateReserveObject", UNKNOWN, 12, },
    {0,"NtCreateProfileEx", UNKNOWN, 40, },
    {0,"NtDisableLastKnownGood", UNKNOWN, 0, },
    {0,"NtDrawText", UNKNOWN, 4, },
    {0,"NtEnableLastKnownGood", UNKNOWN, 0, },
    {0,"NtNotifyChangeSession", UNKNOWN, 32, },
    {0,"NtOpenKeyTransactedEx", UNKNOWN, 20, },
    {0,"NtQuerySecurityAttributesToken", UNKNOWN, 24, },
    {0,"NtQuerySystemInformationEx", UNKNOWN, 24, },
    {0,"NtQueueApcThreadEx", UNKNOWN, 24, },
    {0,"NtSerializeBoot", UNKNOWN, 0, },
    {0,"NtSetIoCompletionEx", UNKNOWN, 24, },
    {0,"NtSetTimerEx", UNKNOWN, 16, },
    {0,"NtUmsThreadYield", UNKNOWN, 4, },
    {0,"NtWow64GetCurrentProcessorNumberEx", UNKNOWN, 4, },
    {0,"NtWow64InterlockedPopEntrySList", UNKNOWN, 4, },
};
#define NUM_NTDLL_SYSCALLS (sizeof(syscall_ntdll_info)/sizeof(syscall_ntdll_info[0]))

/* win32k.sys and other non-ntoskrnl syscalls are in syscall_wingdi.c */
extern syscall_info_t syscall_kernel32_info[];
extern size_t num_kernel32_syscalls(void);
extern syscall_info_t syscall_user32_info[];
extern size_t num_user32_syscalls(void);
extern syscall_info_t syscall_gdi32_info[];
extern size_t num_gdi32_syscalls(void);

#undef OK
#undef UNKNOWN
#undef W
#undef R
#undef CT
#undef WI
#undef IB
#undef IO
#undef RET

/* takes in any Nt syscall wrapper entry point */
byte *
vsyscall_pc(void *drcontext, byte *entry)
{
    byte *vpc = NULL;
    byte *pc = entry;
    uint opc;
    instr_t instr;
    ASSERT(entry != NULL, "invalid entry");
    instr_init(drcontext, &instr);
    do {
        instr_reset(drcontext, &instr);
        pc = decode(drcontext, pc, &instr);
        ASSERT(instr_valid(&instr), "unknown system call sequence");
        opc = instr_get_opcode(&instr);
        ASSERT(opc_is_in_syscall_wrapper(opc), "unknown system call sequence");
        /* safety check: should only get 11 or 12 bytes in */
        if (pc - entry > 20) {
            ASSERT(false, "unknown system call sequence");
            instr_free(drcontext, &instr);
            return NULL;
        }
        if (opc == OP_mov_imm && opnd_is_reg(instr_get_dst(&instr, 0)) &&
            opnd_get_reg(instr_get_dst(&instr, 0)) == REG_EDX) {
            ASSERT(opnd_is_immed_int(instr_get_src(&instr, 0)), "internal error");
            vpc = (byte *) opnd_get_immed_int(instr_get_src(&instr, 0));
        }
        /* stop at call to vsyscall or at int itself */
    } while (opc != OP_call_ind && opc != OP_int);
    /* vpc should only exist if have call* */
    ASSERT(vpc == NULL || opc == OP_call_ind, "internal error");
    instr_free(drcontext, &instr);
    return vpc;
}

static int
syscall_num_from_name(void *drcontext, const module_data_t *info, const char *name,
                      const char *optional_prefix, bool sym_lookup)
{
    app_pc entry = (app_pc)
        dr_get_proc_address(info->start, name);
    int num = -1;
    if (entry != NULL)
        num = syscall_num(drcontext, entry);
#ifdef USE_DRSYMS
    if (entry == NULL && sym_lookup) {
        /* i#388: for those that aren't exported, if we have symbols, find the
         * sysnum that way.
         */
        /* drsym_init() was called already in utils_init() */
        entry = lookup_internal_symbol(info, name);
        if (entry != NULL)
            num = syscall_num(drcontext, entry);
        if (num == -1 && optional_prefix != NULL) {
            const char *skip_prefix = name + strlen(optional_prefix);
            ASSERT(strstr(name, optional_prefix) == name,
                   "missing syscall prefix");
            entry = lookup_internal_symbol(info, skip_prefix);
            if (entry != NULL)
                num = syscall_num(drcontext, entry);
        }
    }
#endif
    if (num == -1) {
        /* i#388: use sysnum table if the wrapper is not exported and we don't have
         * symbol info.  Currently the table only has win32k.sys entries since
         * all the ntdll wrappers are exported.
         */
        int sysnum = (int) hashtable_lookup(&sysnum_table, (void *)name);
        if (sysnum != 0) {
            LOG(SYSCALL_VERBOSE, "using sysnum_table since no wrapper found for %s\n",
                name);
            num = sysnum;
        }
    } else {
        DOLOG(1, {
            int sysnum = (int) hashtable_lookup(&sysnum_table, (void *)name);
            if (sysnum != 0 && sysnum != num) {
                WARN("WARNING: sysnum table "PIFX" != wrapper "PIFX" for %s\n",
                     sysnum, num, name);
                ASSERT(false, "syscall number table error detected");
            }
        });
    }
    return num;
}

static void
add_syscall_entry(void *drcontext, const module_data_t *info, syscall_info_t *syslist,
                  const char *optional_prefix)
{
    if (TEST(SYSINFO_REQUIRES_PREFIX, syslist->flags))
        optional_prefix = NULL;
    syslist->num = syscall_num_from_name(drcontext, info, syslist->name,
                                         optional_prefix, 
                                         /* it's a perf hit to do one-at-a-time symbol
                                          * lookup for hundreds of syscalls, so we rely
                                          * on our tables unless asked
                                          */
                                         options.verify_sysnums);
    if (syslist->num > -1) {
        hashtable_add(&systable, (void *) syslist->num, (void *) syslist);
        LOG(info->start == ntdll_base ? 2 : SYSCALL_VERBOSE,
            "system call %-35s = %3d (0x%04x)\n", syslist->name, syslist->num, syslist->num);
        if (syslist->num_out != NULL)
            *syslist->num_out = syslist->num;
    } else {
        LOG(SYSCALL_VERBOSE, "WARNING: could not find system call %s\n", syslist->name);
    }
}

/* uses tables and other sources not available to sysnum_from_name() */
int
os_syscall_get_num(void *drcontext, const module_data_t *info, const char *name)
{
    return syscall_num_from_name(drcontext, info, name, NULL, true/*sym lookup*/);
}

void
syscall_os_init(void *drcontext, app_pc ntdll_base)
{
    uint i;
    const int *sysnums;
    bool wow64 = is_wow64_process();
    dr_os_version_info_t info = {sizeof(info),};
    if (!dr_get_os_version(&info)) {
        ASSERT(false, "unable to get version");
        sysnums = win7wow_sysnums;
    }
    switch (info.version) {
    case DR_WINDOWS_VERSION_7:
        sysnums = wow64 ? win7wow_sysnums : win7x86_sysnums;
        break;
    case DR_WINDOWS_VERSION_VISTA:
        sysnums = wow64 ? vistawow_sysnums : vistax86_sysnums;
        break;
    case DR_WINDOWS_VERSION_2003:
        sysnums = wow64 ? winXPwow_sysnums : win2003_sysnums;
        break;
    case DR_WINDOWS_VERSION_XP:
        sysnums = wow64 ? winXPwow_sysnums : winXP_sysnums;
        break;
    case DR_WINDOWS_VERSION_2000:
        sysnums = win2K_sysnums;
        break;
    case DR_WINDOWS_VERSION_NT:
    default:
        usage_error("This version of Windows is not supported", "");
    }

    /* Set up hashtable of win32k.sys syscall numbers */
    hashtable_init(&sysnum_table, SYSNUM_TABLE_HASH_BITS, HASH_STRING, false/*!strdup*/);
#ifdef STATISTICS
    hashtable_init(&sysname_table, SYSNAME_TABLE_HASH_BITS, HASH_INTPTR, false/*!strdup*/);
#endif
    for (i = 0; i < NUM_SYSNUM_NAMES; i++) {
        if (sysnums[i] != NONE) {
            const char *skip_prefix = NULL;
            IF_DEBUG(bool ok =)
                hashtable_add(&sysnum_table, (void *)sysnum_names[i], (void *)sysnums[i]);
            ASSERT(ok, "no dup entries in sysnum_table");
            ASSERT(sysnums[i] != 0, "no 0 sysnum: then can't tell from empty");

            /* we also add the version without the prefix, so e.g. alloc.c
             * can pass in "UserConnectToServer" without having the
             * optional_prefix param in sysnum_from_name()
             */
            if (strstr(sysnum_names[i], "NtUser") == sysnum_names[i])
                skip_prefix = sysnum_names[i] + strlen("NtUser");
            else if (strstr(sysnum_names[i], "NtGdi") == sysnum_names[i])
                skip_prefix = sysnum_names[i] + strlen("NtGdi");
            if (skip_prefix != NULL) {
                IF_DEBUG(ok =)
                    hashtable_add(&sysnum_table, (void *)skip_prefix, (void *)sysnums[i]);
#ifdef DEBUG
                if (!ok) {
                    /* If we have any more of these, add a flag to syscall_numx.h */
                    ASSERT(strcmp(sysnum_names[i], "NtUserGetThreadDesktop") ==
                           0/*i#487*/, "no dup entries in sysnum_table");
                }
#endif
            }

#ifdef STATISTICS
            hashtable_add(&sysname_table, (void *)sysnums[i], (void *)sysnum_names[i]);
            LOG(2, "adding win32k.sys syscall #%d \"%s\" to table under #0x%04x\n",
                i, sysnum_names[i], sysnums[i]);
#endif
        }
    }

    hashtable_init(&systable, SYSTABLE_HASH_BITS, HASH_INTPTR, false/*!strdup*/);
}

void
syscall_os_exit(void)
{
    hashtable_delete(&systable);
    hashtable_delete(&sysnum_table);
#ifdef STATISTICS
    hashtable_delete(&sysname_table);
#endif
}

void
syscall_os_module_load(void *drcontext, const module_data_t *info, bool loaded)
{
    uint i;
    const char *modname = dr_module_preferred_name(info);
    if (modname == NULL)
        return;

    /* systable synch: if really get two threads adding at same time 2nd should
     * just fail in the hashtable_add so no harm done
     */
    if (stri_eq(modname, "ntdll.dll")) {
        ASSERT(info->start == ntdll_base, "duplicate ntdll?");
        for (i = 0; i < NUM_NTDLL_SYSCALLS; i++)
            add_syscall_entry(drcontext, info, &syscall_ntdll_info[i], NULL);
    } else if (stri_eq(modname, "kernel32.dll")) {
        for (i = 0; i < num_kernel32_syscalls(); i++)
            add_syscall_entry(drcontext, info, &syscall_kernel32_info[i], NULL);
    } else if (stri_eq(modname, "user32.dll")) {
        for (i = 0; i < num_user32_syscalls(); i++) {
            if (!TEST(SYSINFO_IMM32_DLL, syscall_user32_info[i].flags))
                add_syscall_entry(drcontext, info, &syscall_user32_info[i], "NtUser");
        }
    } else if (stri_eq(modname, "imm32.dll")) {
        for (i = 0; i < num_user32_syscalls(); i++) {
            if (TEST(SYSINFO_IMM32_DLL, syscall_user32_info[i].flags))
                add_syscall_entry(drcontext, info, &syscall_user32_info[i], "NtUser");
        }
    } else if (stri_eq(modname, "gdi32.dll")) {
        for (i = 0; i < num_gdi32_syscalls(); i++)
            add_syscall_entry(drcontext, info, &syscall_gdi32_info[i], "NtGdi");
    }
}

syscall_info_t *
syscall_lookup(int num)
{
    return (syscall_info_t *) hashtable_lookup(&systable, (void *) num);
}

/* Though DR's new syscall events provide parameter value access,
 * we need the address of all parameters passed on the stack
 */
static reg_t *
get_sysparam_base(dr_mcontext_t *mc)
{
    reg_t *base = (reg_t *) mc->edx;
    if (is_using_sysenter())
        base += 2;
    return base;
}

static app_pc
get_sysparam_addr(uint ord, dr_mcontext_t *mc)
{
    return (app_pc)(((reg_t *)get_sysparam_base(mc)) + ord);
}

uint
get_sysparam_shadow_val(uint sysnum, uint argnum, dr_mcontext_t *mc)
{
    return shadow_get_byte(get_sysparam_addr(argnum, mc));
}

void
check_sysparam_defined(uint sysnum, uint argnum, dr_mcontext_t *mc, size_t argsz)
{
    check_sysmem(MEMREF_CHECK_DEFINEDNESS, sysnum,
                 get_sysparam_addr(argnum, mc), argsz, mc, NULL);
}

bool
os_shared_pre_syscall(void *drcontext, int sysnum)
{
    return true; /* execute syscall */
}

void
os_shared_post_syscall(void *drcontext, int sysnum)
{
    /* FIXME PR 456501: watch CreateProcess, CreateProcessEx, and
     * CreateUserProcess.  Convert process handle to pid and section
     * handle to file path, and write both as a FORKEXEC line in
     * f_fork.
     */
}

bool
os_syscall_succeeded(int sysnum, syscall_info_t *info, ptr_int_t res)
{
    if (res == STATUS_BUFFER_OVERFLOW) {
        /* Data is filled in so consider success */
        return true;
    }
    /* if info==NULL we assume special call and we don't need to look it up */
    if (info != NULL && TEST(SYSINFO_RET_ZERO_FAIL, info->flags)) {
        return (res != 0);
    }
    /* FIXME i#486: syscalls that return the capacity needed in an OUT param
     * will still write to it when returning STATUS_BUFFER_TOO_SMALL
     */
    return (res >= 0);
}

/* provides name if known when not in syscall_lookup(num) */
const char *
os_syscall_get_name(uint num)
{
#ifdef STATISTICS
    return (const char *) hashtable_lookup(&sysname_table, (void *)num);
#else
    /* not bothering to keep data outside of table */
    return NULL;
#endif
}

/***************************************************************************
 * SHADOW PER-ARG-TYPE HANDLING
 */

static bool
handle_port_message_access(bool pre, int sysnum, dr_mcontext_t *mc,
                           uint arg_num,
                           const syscall_arg_t *arg_info,
                           app_pc start, uint size)
{
    uint check_type = SYSARG_CHECK_TYPE(arg_info->flags, pre);
    /* variable-length */
    PORT_MESSAGE pm;
    if (TEST(SYSARG_WRITE, arg_info->flags) && pre &&
        !TEST(SYSARG_READ, arg_info->flags)) {
        /* Struct is passed in uninit w/ max-len buffer after it.
         * FIXME i#415: There is some ambiguity over the max, hence we choose
         * the lower estimation to avoid false positives.
         * (We'll still use sizeof(PORT_MESSAGE) + PORT_MAXIMUM_MESSAGE_LENGTH
         *  in the ASSERTs below)
         * We'll re-do the addressability check at the post- hook.
         */
        size = PORT_MAXIMUM_MESSAGE_LENGTH;
    } else if (safe_read(start, sizeof(pm), &pm)) {
        if (pm.u1.s1.DataLength > 0)
            size = pm.u1.s1.TotalLength;
        else
            size = pm.u1.Length;
        if (size > sizeof(PORT_MESSAGE) + PORT_MAXIMUM_MESSAGE_LENGTH) {
            DO_ONCE({ WARN("WARNING: PORT_MESSAGE size larger than known max\n"); });
        }
        /* See above: I've seen 0x15c and 0x130.  Anything too large, though,
         * may indicate an error in our syscall param types, so we want a
         * full stop assert.
         */
        ASSERT(size <= 2*(sizeof(PORT_MESSAGE) + PORT_MAXIMUM_MESSAGE_LENGTH),
               "PORT_MESSAGE size much larger than expected");
        /* For optional PORT_MESSAGE args I've seen valid pointers to structs
         * filled with 0's
         */
        ASSERT(size == 0 || (ssize_t)size >= sizeof(pm), "PORT_MESSAGE size too small");
        LOG(2, "total size of PORT_MESSAGE arg %d is %d\n", arg_num, size);
    } else {
        /* can't read real size, so report presumed-unaddr w/ struct size */
        ASSERT(size == sizeof(PORT_MESSAGE), "invalid PORT_MESSAGE sysarg size");
    }

    /* FIXME i#415: As a temp workaround, check for addressability
     * once again in the post- hook but knowing the size precisely.
     * This won't catch a bug where a too-small capacity is passed yet in all
     * the actual syscalls during execution all the written data is small.
     */
    if (TEST(SYSARG_WRITE, arg_info->flags) && !pre) {
        check_sysmem(MEMREF_CHECK_ADDRESSABLE, sysnum, start, size, mc, NULL);
    }

    check_sysmem(check_type, sysnum, start, size, mc, NULL);
    return true;
}

static bool
handle_context_access(bool pre, int sysnum, dr_mcontext_t *mc, uint arg_num,
                      const syscall_arg_t *arg_info,
                      app_pc start, uint size)
{
#if !defined(_X86_) || defined(X64)
# error CONTEXT read handler is not yet implemented on non-x86
#else /* defined(_X86_) */
    uint check_type = SYSARG_CHECK_TYPE(arg_info->flags, pre);
    /* The 'cxt' pointer will only be used for retrieving pointers
     * for the CONTEXT fields, hence we can do without safe_read.
     */
    const CONTEXT *cxt = (CONTEXT *)start;
    DWORD context_flags;
    check_sysmem(check_type, sysnum, start, sizeof(context_flags),
                 mc, NULL);
    if (!safe_read((void*)&cxt->ContextFlags, sizeof(context_flags),
                   &context_flags)) {
        /* if safe_read fails due to CONTEXT being unaddr, the preceding
         * check_sysmem should have raised the error, and there's
         * no point in trying to further check the CONTEXT
         */
        return true;
    }

    ASSERT(TEST(CONTEXT_i486, context_flags),
           "ContextFlags doesn't have CONTEXT_i486 bit set");

    /* CONTEXT structure on x86 consists of the following sections:
     * a) DWORD ContextFlags
     *
     * The following fields should be defined if the corresponding
     * flags are set:
     * b) DWORD Dr{0...3, 6, 7}        - CONTEXT_DEBUG_REGISTERS,
     * c) FLOATING_SAVE_AREA FloatSave - CONTEXT_FLOATING_POINT,
     * d) DWORD Seg{G,F,E,D}s          - CONTEXT_SEGMENTS,
     * e) DWORD E{di,si,bx,dx,cx,ax}   - CONTEXT_INTEGER,
     * f) DWORD Ebp, Eip, SegCs, EFlags, Esp, SegSs - CONTEXT_CONTROL,
     * g) BYTE ExtendedRegisters[...]  - CONTEXT_EXTENDED_REGISTERS.
     */

    if (TESTALL(CONTEXT_DEBUG_REGISTERS, context_flags)) {
#define CONTEXT_NUM_DEBUG_REGS 6
        check_sysmem(check_type, sysnum,
                     (app_pc)&cxt->Dr0, CONTEXT_NUM_DEBUG_REGS*sizeof(DWORD),
                     mc, NULL);
    }
    if (TESTALL(CONTEXT_FLOATING_POINT, context_flags)) {
        check_sysmem(check_type, sysnum,
                     (app_pc)&cxt->FloatSave, sizeof(cxt->FloatSave),
                     mc, NULL);
    }
    /* Segment registers are 16-bits each but stored with 16-bit gaps
     * so we can't use sizeof(cxt->Seg*s);
     */
#define SIZE_SEGMENT_REG 2
    if (TESTALL(CONTEXT_SEGMENTS, context_flags)) {
        check_sysmem(check_type, sysnum,
                     (app_pc)&cxt->SegGs, SIZE_SEGMENT_REG, mc, NULL);
        check_sysmem(check_type, sysnum,
                     (app_pc)&cxt->SegFs, SIZE_SEGMENT_REG, mc, NULL);
        check_sysmem(check_type, sysnum,
                     (app_pc)&cxt->SegEs, SIZE_SEGMENT_REG, mc, NULL);
        check_sysmem(check_type, sysnum,
                     (app_pc)&cxt->SegDs, SIZE_SEGMENT_REG, mc, NULL);
    }
    if (TESTALL(CONTEXT_INTEGER, context_flags) &&
        sysnum != sysnum_CreateThread) {
        /* For some reason, cxt->Edi...Eax are not initialized when calling
         * NtCreateThread though CONTEXT_INTEGER flag is set
         */
#define CONTEXT_NUM_INT_REGS 6
        check_sysmem(check_type, sysnum,
                     (app_pc)&cxt->Edi, CONTEXT_NUM_INT_REGS*sizeof(DWORD),
                     mc, NULL);
    }
    if (TESTALL(CONTEXT_CONTROL, context_flags)) {
        if (sysnum != sysnum_CreateThread) {
            /* Ebp is not initialized when calling NtCreateThread,
             * so we skip it
             */
            check_sysmem(check_type, sysnum,
                         (app_pc)&cxt->Ebp, sizeof(DWORD),
                         mc, NULL);
        }
        check_sysmem(check_type, sysnum,
                     (app_pc)&cxt->Eip, sizeof(cxt->Eip), mc, NULL);
        check_sysmem(check_type, sysnum,
                     (app_pc)&cxt->Esp, sizeof(cxt->Esp), mc, NULL);
        check_sysmem(check_type, sysnum,
                     (app_pc)&cxt->EFlags, sizeof(cxt->EFlags), mc, NULL);
        check_sysmem(check_type, sysnum,
                     (app_pc)&cxt->SegCs, SIZE_SEGMENT_REG, mc, NULL);
        check_sysmem(check_type, sysnum,
                     (app_pc)&cxt->SegSs, SIZE_SEGMENT_REG, mc, NULL);
    }
    if (TESTALL(CONTEXT_EXTENDED_REGISTERS, context_flags)) {
        check_sysmem(check_type, sysnum,
                     (app_pc)&cxt->ExtendedRegisters,
                     sizeof(cxt->ExtendedRegisters), mc, NULL);
    }
    return true;
#endif
}

static bool
handle_exception_record_access(bool pre, int sysnum, dr_mcontext_t *mc,
                               uint arg_num,
                               const syscall_arg_t *arg_info,
                               app_pc start, uint size)
{
    uint check_type = SYSARG_CHECK_TYPE(arg_info->flags, pre);
    const EXCEPTION_RECORD *er = (EXCEPTION_RECORD *)start;
    DWORD num_params;
    /* According to MSDN, NumberParameters stores the number of defined
     * elements of the ExceptionInformation array
     * at the end of the EXCEPTION_RECORD structure.
     * http://msdn.microsoft.com/en-us/library/aa363082(VS.85).aspx
     */
    check_sysmem(check_type, sysnum,
                 start, sizeof(*er) - sizeof(er->ExceptionInformation),
                 mc, NULL);
    ASSERT(sizeof(num_params) == sizeof(er->NumberParameters), "");
    if (safe_read((void*)&er->NumberParameters, sizeof(num_params),
                  &num_params)) {
        check_sysmem(check_type, sysnum,
                     (app_pc)er->ExceptionInformation,
                     num_params * sizeof(er->ExceptionInformation[0]),
                     mc, NULL);
    }
    return true;
}

static bool
handle_security_qos_access(bool pre, int sysnum, dr_mcontext_t *mc,
                           uint arg_num,
                           const syscall_arg_t *arg_info,
                           app_pc start, uint size)
{
    uint check_type = SYSARG_CHECK_TYPE(arg_info->flags, pre);
    const SECURITY_QUALITY_OF_SERVICE *s = (SECURITY_QUALITY_OF_SERVICE *)start;
    /* The SECURITY_QUALITY_OF_SERVICE structure is
     * DWORD + DWORD + unsigned char + BOOLEAN
     * so it takes 12 bytes (and its Length field value is 12)
     * but only 10 must be initialized.
     */
    check_sysmem(check_type, sysnum, start,
                 sizeof(s->Length) + sizeof(s->ImpersonationLevel) +
                 sizeof(s->ContextTrackingMode) + sizeof(s->EffectiveOnly),
                 mc, NULL);
    return true;
}

static bool
handle_security_descriptor_access(bool pre, int sysnum, dr_mcontext_t *mc,
                                  uint arg_num,
                                  const syscall_arg_t *arg_info,
                                  app_pc start, uint size)
{
    uint check_type = SYSARG_CHECK_TYPE(arg_info->flags, pre);
    const SECURITY_DESCRIPTOR *s = (SECURITY_DESCRIPTOR *)start;
    SECURITY_DESCRIPTOR_CONTROL flags;
    ASSERT(check_type == MEMREF_CHECK_DEFINEDNESS,
           "Should only be called for reads");
    if (!pre) {
        /* Handling pre- is enough for reads */
        return true;
    }
    /* The SECURITY_DESCRIPTOR structure has two fields at the end (Sacl, Dacl)
     * which must be init only when the corresponding bits of Control are set.
     */
    ASSERT(start + sizeof(*s) == (app_pc)&s->Dacl + sizeof(s->Dacl), "");
    check_sysmem(check_type, sysnum, start, (app_pc)&s->Sacl - start, mc, NULL);

    ASSERT(sizeof(flags) == sizeof(s->Control), "");
    if (safe_read((void*)&s->Control, sizeof(flags), &flags)) {
        if (TEST(SE_SACL_PRESENT, flags)) {
            check_sysmem(check_type, sysnum,
                         (app_pc)&s->Sacl, sizeof(s->Sacl), mc, NULL);
        }
        if (TEST(SE_DACL_PRESENT, flags)) {
            check_sysmem(check_type, sysnum,
                         (app_pc)&s->Dacl, sizeof(s->Dacl), mc, NULL);
        }
    }
    return true;
}

bool
handle_unicode_string_access(bool pre, int sysnum, dr_mcontext_t *mc,
                             uint arg_num, const syscall_arg_t *arg_info,
                             app_pc start, uint size, bool ignore_len)
{
    uint check_type = SYSARG_CHECK_TYPE(arg_info->flags, pre);
    UNICODE_STRING us;
    UNICODE_STRING *arg = (UNICODE_STRING *) start;
    ASSERT(size == sizeof(UNICODE_STRING), "invalid size");
    /* we assume OUT fields just have their Buffer as OUT */
    if (pre) {
        if (TEST(SYSARG_READ, arg_info->flags)) {
            check_sysmem(MEMREF_CHECK_DEFINEDNESS, sysnum, start, size, mc,
                         "UNICODE_STRING fields");
        } else {
            check_sysmem(MEMREF_CHECK_DEFINEDNESS, sysnum, (byte *)&arg->MaximumLength,
                         sizeof(arg->MaximumLength), mc, "UNICODE_STRING.MaximumLength");
            check_sysmem(MEMREF_CHECK_DEFINEDNESS, sysnum, (byte *)&arg->Buffer,
                         sizeof(arg->Buffer), mc, "UNICODE_STRING.Buffer");
        }
    }
    if (safe_read((void*)start, sizeof(us), &us)) {
        LOG(SYSCALL_VERBOSE,
            "UNICODE_STRING Buffer="PFX" Length=%d MaximumLength=%d\n",
            (byte *)us.Buffer, us.Length, us.MaximumLength);
        if (pre) {
            check_sysmem(MEMREF_CHECK_ADDRESSABLE, sysnum,
                         (byte *)us.Buffer, us.MaximumLength, mc,
                         "UNICODE_STRING capacity");
        }
        if (us.MaximumLength > 0) {
            if (ignore_len) {
                /* i#490: wrong Length stored so as workaround we walk the string */
                handle_cwstring(pre, sysnum, mc, "UNICODE_STRING content",
                                (byte *)us.Buffer, us.MaximumLength,
                                arg_info->flags, NULL, false);
            } else {
                check_sysmem(check_type, sysnum, (byte *)us.Buffer,
                             /* Length field does not include final NULL */
                             us.Length+sizeof(wchar_t),
                             mc, "UNICODE_STRING content");
            }
        }
    } else
        WARN("WARNING: unable to read syscall param\n");
    return true;
}

bool
handle_object_attributes_access(bool pre, int sysnum, dr_mcontext_t *mc,
                                uint arg_num,
                                const syscall_arg_t *arg_info,
                                app_pc start, uint size)
{
    uint check_type = SYSARG_CHECK_TYPE(arg_info->flags, pre);
    OBJECT_ATTRIBUTES oa;
    ASSERT(size == sizeof(OBJECT_ATTRIBUTES), "invalid size");
    check_sysmem(check_type, sysnum, start, size, mc, "OBJECT_ATTRIBUTES fields");
    if (safe_read((void*)start, sizeof(oa), &oa)) {
        handle_unicode_string_access(pre, sysnum, mc, arg_num, arg_info,
                                     (byte *) oa.ObjectName,
                                     sizeof(*oa.ObjectName), false);
        handle_security_descriptor_access(pre, sysnum, mc, arg_num, arg_info,
                                          (byte *) oa.SecurityDescriptor,
                                          sizeof(SECURITY_DESCRIPTOR));
        handle_security_qos_access(pre, sysnum, mc, arg_num, arg_info,
                                   (byte *) oa.SecurityQualityOfService,
                                   sizeof(SECURITY_QUALITY_OF_SERVICE));
    } else
        WARN("WARNING: unable to read syscall param\n");
    return true;
}

/* pass 0 for size if there is no max size */
bool
handle_cwstring(bool pre, int sysnum, dr_mcontext_t *mc, const char *id,
                byte *start, size_t size/*in bytes*/, uint arg_flags, wchar_t *safe,
                bool check_addr)
{
    uint check_type = SYSARG_CHECK_TYPE(arg_flags, pre);
    /* the kernel wrote a wide string to the buffer: only up to the terminating
     * null should be marked as defined
     */
    uint i;
    wchar_t c;
    /* input params have size 0: for safety stopping at MAX_PATH */
    size_t maxsz = (size == 0) ? (MAX_PATH*sizeof(wchar_t)) : size;
    if (start == NULL)
        return false; /* nothing to do */
    if (pre && !TEST(SYSARG_READ, arg_flags)) {
        if (!check_addr)
            return false;
        if (size > 0) {
            /* if max size specified, on pre-write check whole thing for addr */
            check_sysmem(check_type, sysnum, start, size, mc, id);
            return true;
        }
    }
    if (!pre && !TEST(SYSARG_WRITE, arg_flags))
        return false; /*nothing to do */
    for (i = 0; i < maxsz; i += sizeof(wchar_t)) {
        if (safe != NULL)
            c = safe[i/sizeof(wchar_t)];
        else if (!safe_read(start + i, sizeof(c), &c)) {
            WARN("WARNING: unable to read syscall param string\n");
            break;
        }
        if (c == L'\0')
            break;
    }
    check_sysmem(check_type, sysnum, start, i + sizeof(wchar_t), mc, id);
    return true;
}

static bool
handle_cstring_wide_access(bool pre, int sysnum, dr_mcontext_t *mc,
                           uint arg_num,
                           const syscall_arg_t *arg_info,
                           app_pc start, uint size/*in bytes*/)
{
    return handle_cwstring(pre, sysnum, mc, NULL, start, size, arg_info->flags, NULL,
                           /* let normal check ensure full size is addressable */
                           false);
}

static bool
os_handle_syscall_arg_access(bool pre,
                             int sysnum, dr_mcontext_t *mc, uint arg_num,
                             const syscall_arg_t *arg_info,
                             app_pc start, uint size)
{
    if (!TEST(SYSARG_COMPLEX_TYPE, arg_info->flags))
        return false;

    switch (arg_info->misc) {
    case SYSARG_TYPE_PORT_MESSAGE:
        return handle_port_message_access(pre, sysnum, mc, arg_num,
                                          arg_info, start, size);
    case SYSARG_TYPE_CONTEXT:
        return handle_context_access(pre, sysnum, mc, arg_num,
                                     arg_info, start, size);
    case SYSARG_TYPE_EXCEPTION_RECORD:
        return handle_exception_record_access(pre, sysnum, mc, arg_num,
                                              arg_info, start, size);
    case SYSARG_TYPE_SECURITY_QOS:
        return handle_security_qos_access(pre, sysnum, mc, arg_num,
                                          arg_info, start, size);
    case SYSARG_TYPE_SECURITY_DESCRIPTOR:
        return handle_security_descriptor_access(pre, sysnum, mc, arg_num,
                                                 arg_info, start, size);
    case SYSARG_TYPE_UNICODE_STRING:
        return handle_unicode_string_access(pre, sysnum, mc, arg_num,
                                            arg_info, start, size, false);
    case SYSARG_TYPE_UNICODE_STRING_NOLEN:
        return handle_unicode_string_access(pre, sysnum, mc, arg_num,
                                            arg_info, start, size, true);
    case SYSARG_TYPE_OBJECT_ATTRIBUTES:
        return handle_object_attributes_access(pre, sysnum, mc, arg_num,
                                               arg_info, start, size);
    case SYSARG_TYPE_CSTRING_WIDE:
        return handle_cstring_wide_access(pre, sysnum, mc, arg_num,
                                          arg_info, start, size);
    }
    return wingdi_process_syscall_arg(pre, sysnum, mc, arg_num,
                                      arg_info, start, size);
}

bool
os_handle_pre_syscall_arg_access(int sysnum, dr_mcontext_t *mc, uint arg_num,
                                 const syscall_arg_t *arg_info,
                                 app_pc start, uint size)
{
    return os_handle_syscall_arg_access(true/*pre*/, sysnum, mc, arg_num,
                                        arg_info, start, size);
}

bool
os_handle_post_syscall_arg_access(int sysnum, dr_mcontext_t *mc, uint arg_num,
                                  const syscall_arg_t *arg_info,
                                  app_pc start, uint size)
{
    return os_handle_syscall_arg_access(false/*!pre*/, sysnum, mc, arg_num,
                                        arg_info, start, size);
}

/***************************************************************************
 * SHADOW PER-SYSCALL HANDLING
 */

static void
handle_post_CreateThread(void *drcontext, int sysnum, per_thread_t *pt,
                         dr_mcontext_t *mc)
{
    if (NT_SUCCESS(dr_syscall_get_result(drcontext))) {
        /* Even on XP+ where csrss frees the stack, the stack alloc happens
         * in-process and we see it.  The TEB alloc, however, is done by
         * the kernel, and kernel32!CreateRemoteThread writes to the TEB
         * prior to the thread resuming, so we handle it here.
         * We also process the TEB in set_thread_initial_structures() in
         * case someone creates a thread remotely, or in-process but custom
         * so it's not suspended at this point.
         */
        HANDLE thread_handle;
        /* If not suspended, let set_thread_initial_structures() handle it to
         * avoid races: though since setting as defined the only race would be
         * the thread exiting
         */
        if (pt->sysarg[7]/*bool suspended*/ &&
            is_current_process((HANDLE)pt->sysarg[3]) &&
            safe_read((byte *)pt->sysarg[0], sizeof(thread_handle), &thread_handle)) {
            TEB *teb = get_TEB_from_handle(thread_handle);
            LOG(1, "TEB for new thread: "PFX"\n", teb);
            set_teb_initial_shadow(teb);
        }
    }
}

static bool
handle_pre_CreateThreadEx(void *drcontext, int sysnum, per_thread_t *pt,
                          dr_mcontext_t *mc)
{
    if (is_current_process((HANDLE)pt->sysarg[3])) {
        create_thread_info_t info;
        if (safe_read(&((create_thread_info_t *)pt->sysarg[10])->struct_size,
                      sizeof(info.struct_size), &info.struct_size)) {
            if (info.struct_size > sizeof(info)) {
                DO_ONCE({ WARN("WARNING: create_thread_info_t size too large\n"); });
                info.struct_size = sizeof(info);  /* avoid overflowing the struct */
            }
            if (safe_read((byte *)pt->sysarg[10], info.struct_size, &info)) {
                check_sysmem(MEMREF_CHECK_DEFINEDNESS, sysnum, (byte *)pt->sysarg[10],
                             info.struct_size, mc, "create_thread_info_t");
                if (info.struct_size > offsetof(create_thread_info_t, client_id)) {
                    check_sysmem(MEMREF_CHECK_ADDRESSABLE, sysnum, info.client_id.buffer,
                                 info.client_id.buffer_size, mc, "PCLIENT_ID");
                }
                if (info.struct_size > offsetof(create_thread_info_t, teb)) {
                    /* This is optional, and omitted in i#342 */
                    check_sysmem(MEMREF_CHECK_ADDRESSABLE, sysnum, info.teb.buffer,
                                 info.teb.buffer_size, mc, "PTEB");
                }
            }
        }
    }
    return true;
}

static void
handle_post_CreateThreadEx(void *drcontext, int sysnum, per_thread_t *pt,
                           dr_mcontext_t *mc)
{
    if (is_current_process((HANDLE)pt->sysarg[3]) &&
        NT_SUCCESS(dr_syscall_get_result(drcontext))) {
        HANDLE thread_handle;
        create_thread_info_t info;
        /* See notes in handle_post_CreateThread() */
        if (pt->sysarg[6]/*bool suspended*/ &&
            safe_read((byte *)pt->sysarg[0], sizeof(thread_handle), &thread_handle)) {
            TEB *teb = get_TEB_from_handle(thread_handle);
            LOG(1, "TEB for new thread: "PFX"\n", teb);
            set_teb_initial_shadow(teb);
        }
        if (safe_read(&((create_thread_info_t *)pt->sysarg[10])->struct_size,
                      sizeof(info.struct_size), &info.struct_size)) {
            if (info.struct_size > sizeof(info)) {
                info.struct_size = sizeof(info);  /* avoid overflowing the struct */
            }
            if (safe_read((byte *)pt->sysarg[10], info.struct_size, &info)) {
                if (info.struct_size > offsetof(create_thread_info_t, client_id)) {
                    check_sysmem(MEMREF_WRITE, sysnum, info.client_id.buffer,
                                 info.client_id.buffer_size, mc, "PCLIENT_ID");
                }
                if (info.struct_size > offsetof(create_thread_info_t, teb)) {
                    check_sysmem(MEMREF_WRITE, sysnum, info.teb.buffer,
                                 info.teb.buffer_size, mc, "PTEB");
                }
            }
        }
    }
}

static bool
handle_pre_CreateUserProcess(void *drcontext, int sysnum, per_thread_t *pt,
                             dr_mcontext_t *mc)
{
    create_proc_thread_info_t info;
    if (safe_read((byte *)pt->sysarg[10], sizeof(info), &info)) {
        check_sysmem(MEMREF_CHECK_DEFINEDNESS, sysnum, info.nt_path_to_exe.buffer,
                     info.nt_path_to_exe.buffer_size, mc, "path to exe");
        check_sysmem(MEMREF_CHECK_ADDRESSABLE, sysnum, info.client_id.buffer,
                     info.client_id.buffer_size, mc, "PCLIENT_ID");
        check_sysmem(MEMREF_CHECK_ADDRESSABLE, sysnum, info.exe_stuff.buffer,
                     info.exe_stuff.buffer_size, mc, "path to exe");
        /* XXX i#98: there are other IN/OUT params but exact form not clear */
    }
    return true;
}

static void
handle_post_CreateUserProcess(void *drcontext, int sysnum, per_thread_t *pt,
                              dr_mcontext_t *mc)
{
    if (NT_SUCCESS(dr_syscall_get_result(drcontext))) {
        create_proc_thread_info_t info;
        if (safe_read((byte *)pt->sysarg[10], sizeof(info), &info)) {
            check_sysmem(MEMREF_WRITE, sysnum, info.client_id.buffer,
                         info.client_id.buffer_size, mc, "PCLIENT_ID");
            check_sysmem(MEMREF_WRITE, sysnum, info.exe_stuff.buffer,
                         info.exe_stuff.buffer_size, mc, "exe_stuff");
            /* XXX i#98: there are other IN/OUT params but exact form not clear */
        }
    }
}

static bool
handle_QuerySystemInformation(bool pre, void *drcontext, int sysnum, per_thread_t *pt,
                            dr_mcontext_t *mc)
{
    /* Normally the buffer is just output.  For the input case here we
     * will mark the buffer as defined b/c of the regular table processing:
     * not a big deal as we'll report any uninit prior to that.
     */
    SYSTEM_INFORMATION_CLASS cls = (SYSTEM_INFORMATION_CLASS) pt->sysarg[0];
    if (cls == SystemSessionProcessesInformation) {
        SYSTEM_SESSION_PROCESS_INFORMATION buf;
        if (pre) {
            check_sysmem(MEMREF_CHECK_DEFINEDNESS, sysnum, (byte *)pt->sysarg[1],
                         sizeof(buf), mc, "SYSTEM_SESSION_PROCESS_INFORMATION");
        }
        if (safe_read((byte *) pt->sysarg[1], sizeof(buf), &buf)) {
            check_sysmem(pre ? MEMREF_CHECK_ADDRESSABLE : MEMREF_WRITE,
                         sysnum, buf.Buffer, buf.SizeOfBuf, mc, "Buffer");
        }
    }
    return true;
}

static bool
handle_SetSystemInformation(bool pre, void *drcontext, int sysnum, per_thread_t *pt,
                            dr_mcontext_t *mc)
{
    /* Normally the buffer is just input, but some info classes write data */
    SYSTEM_INFORMATION_CLASS cls = (SYSTEM_INFORMATION_CLASS) pt->sysarg[0];
    if (pre)
        return true;
    /* Nebbett had this as SystemLoadImage and SYSTEM_LOAD_IMAGE */
    if (cls == SystemLoadGdiDriverInformation) {
        SYSTEM_GDI_DRIVER_INFORMATION *buf =
            (SYSTEM_GDI_DRIVER_INFORMATION *) pt->sysarg[1];
        check_sysmem(MEMREF_WRITE, sysnum, (byte *) &buf->ImageAddress,
                     sizeof(*buf) - offsetof(SYSTEM_GDI_DRIVER_INFORMATION, ImageAddress),
                     mc, "loaded image info");
        /* Nebbett had this as SystemCreateSession and SYSTEM_CREATE_SESSION */
    } else if (cls == SystemSessionCreate) {
        /* Just a ULONG, no struct */
        check_sysmem(MEMREF_WRITE, sysnum, (byte *) pt->sysarg[1],
                     sizeof(ULONG), mc, "session id");
    }
    return true;
}

/***************************************************************************
 * IOCTLS
 */

/*
NTSYSAPI NTSTATUS NTAPI
ZwDeviceIoControlFile(
    IN HANDLE FileHandle,
    IN HANDLE Event OPTIONAL,
    IN PIO_APC_ROUTINE ApcRoutine OPTIONAL,
    IN PVOID ApcContext OPTIONAL,
    OUT PIO_STATUS_BLOCK IoStatusBlock,
    IN ULONG IoControlCode,
    IN PVOID InputBuffer OPTIONAL,
    IN ULONG InputBufferLength,
    OUT PVOID OutputBuffer OPTIONAL,
    IN ULONG OutputBufferLength
    );
*/

/* Note that the AFD (Ancillary Function Driver, afd.sys, for winsock)
 * ioctls don't follow the regular CTL_CODE where the device is <<16.
 * Instead they have the device (FILE_DEVICE_NETWORK == 0x12) << 12,
 * and the function << 2, with access bits always set to 0.
 * NtDeviceIoControlFile only looks at the access and method bits
 * though.
 */

/* XXX: very similar to Linux layouts, though exact constants are different.
 * Still, should be able to share some code.
 */
static void
check_sockaddr(byte *ptr, size_t len, uint memcheck_flags, dr_mcontext_t *mc,
               int sysnum, const char *id)
{
    struct sockaddr *sa = (struct sockaddr *) ptr;
    ADDRESS_FAMILY family;
    if (TESTANY(MEMREF_CHECK_DEFINEDNESS | MEMREF_CHECK_ADDRESSABLE, memcheck_flags)) {
        check_sysmem(memcheck_flags, sysnum,
                     (app_pc) &sa->sa_family, sizeof(sa->sa_family), mc, id);
    }
    if (!safe_read(&sa->sa_family, sizeof(family), &family))
        return;
    /* FIXME: do not check beyond len */
    switch (family) {
    case AF_UNSPEC: {
        /* FIXME i#386: I'm seeing 0 (AF_UNSPEC) a lot, e.g., with
         * IOCTL_AFD_SET_CONTEXT where the entire sockaddrs are just zero.  Not sure
         * whether to require that anything beyond sa_family be defined.  Sometimes
         * there is further data and the family is set later.  For now ignoring
         * beyond sa_family.
         */
        break;
    }
    case AF_INET: {
        struct sockaddr_in *sin = (struct sockaddr_in *) sa;
        check_sysmem(memcheck_flags, sysnum,
                     (app_pc) &sin->sin_port, sizeof(sin->sin_port), mc, id);
        check_sysmem(memcheck_flags, sysnum,
                     (app_pc) &sin->sin_addr, sizeof(sin->sin_addr), mc, id);
        break;
    }
    case AF_INET6: {
        struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *) sa;
        check_sysmem(memcheck_flags, sysnum,
                     (app_pc) &sin6->sin6_port, sizeof(sin6->sin6_port), mc, id);
        check_sysmem(memcheck_flags, sysnum,
                     (app_pc) &sin6->sin6_flowinfo, sizeof(sin6->sin6_flowinfo), mc, id);
        check_sysmem(memcheck_flags, sysnum,
                     (app_pc) &sin6->sin6_addr, sizeof(sin6->sin6_addr), mc, id);
        /* FIXME: when is sin6_scope_struct used? */
        check_sysmem(memcheck_flags, sysnum,
                     (app_pc) &sin6->sin6_scope_id, sizeof(sin6->sin6_scope_id), mc, id);
        break;
    }
    default:
        WARN("WARNING: unknown sockaddr type %d\n", family); 
        IF_DEBUG(report_callstack(dr_get_current_drcontext(), mc);)
        break;
    }
}

/* Macros for shorter, easier-to-read code */
#define CHECK_DEF(ptr, sz, id) \
    check_sysmem(MEMREF_CHECK_DEFINEDNESS, sysnum, (byte*)ptr, sz, mc, id)
#define CHECK_ADDR(ptr, sz, id) \
    check_sysmem(MEMREF_CHECK_ADDRESSABLE, sysnum, (byte*)ptr, sz, mc, id)
#define MARK_WRITE(ptr, sz, id) \
    check_sysmem(MEMREF_WRITE, sysnum, ptr, sz, mc, id)

static void handle_AFD_ioctl(bool pre, int sysnum, per_thread_t *pt,
                             dr_mcontext_t *mc)
{
    uint full_code = (uint) pt->sysarg[5];
    byte *inbuf = (byte *) pt->sysarg[6];
    uint insz = (uint) pt->sysarg[7];
    /* FIXME: put max of insz on all the sizes below */

    /* Extract operation from 0x12xxx and bottom 2 method bits */
    uint opcode = (full_code & 0xfff) >> 2;

    /* We have "8,-9,W" in the table so we only need to handle additional pointers
     * here or cases where subsets of the full output buffer are written.
     *
     * XXX i#410: We treat asynch i/o as happening now rather than trying to
     * watch NtWait* and tracking event objects, though we'll
     * over-estimate the amount written in some cases.
     */

    bool pre_post_ioctl = true;
    /* First check if the given opcode is one of those needing both pre- and
     * post- handling in the first switch. We'll set the pre_post_ioctl to
     * "false" in the default block to continue to the second switch.
     */
    switch (opcode) {
    case AFD_RECV: { /* 5 == 0x12017 */
        /* InputBuffer == AFD_RECV_INFO */
        AFD_RECV_INFO info;
        uint i;
        if (pre)
            CHECK_DEF(inbuf, insz, "AFD_RECV_INFO");

        if (inbuf == NULL || !safe_read(inbuf, sizeof(info), &info)) {
            WARN("WARNING: AFD_RECV: can't read param\n");
            break;
        }

        if (pre) {
            CHECK_DEF(info.BufferArray, info.BufferCount * sizeof(*info.BufferArray),
                      "AFD_RECV_INFO.BufferArray");
        }

        for (i = 0; i < info.BufferCount; i++) {
            AFD_WSABUF buf;
            if (safe_read((char *)&info.BufferArray[i], sizeof(buf), &buf)) {
                if (pre)
                    CHECK_ADDR(buf.buf, buf.len, "AFD_RECV_INFO.BufferArray[i].buf");
                else {
                    LOG(SYSCALL_VERBOSE, "\tAFD_RECV_INFO buf %d: "PFX"-"PFX"\n",
                        i, buf.buf, buf.len);
                    MARK_WRITE(buf.buf, buf.len, "AFD_RECV_INFO.BufferArray[i].buf");
                }
            } else
                WARN("WARNING: AFD_RECV: can't read param\n");
        }
        break;
    }
    case AFD_RECV_DATAGRAM: { /* 6 ==  0x1201b */
        /* InputBuffer == AFD_RECV_INFO_UDP */
        AFD_RECV_INFO_UDP info;
        uint i;
        if (pre)
            CHECK_DEF(inbuf, insz, "AFD_RECV_INFO_UDP");

        if (inbuf == NULL || !safe_read(inbuf, sizeof(info), &info)) {
            WARN("WARNING: AFD_RECV_DATAGRAM: can't read param\n");
            break;
        }

        if (safe_read(info.AddressLength, sizeof(i), &i)) {
            if (pre)
                CHECK_ADDR((byte*)info.Address, i, "AFD_RECV_INFO_UDP.Address");
            else {
                check_sockaddr((byte*)info.Address, i, MEMREF_WRITE, mc, sysnum,
                               "AFD_RECV_INFO_UDP.Address");
            }
        } else
            WARN("WARNING: AFD_RECV_DATAGRAM: can't read AddressLength\n");

        if (pre) {
            CHECK_DEF(info.BufferArray, info.BufferCount * sizeof(*info.BufferArray),
                      "AFD_RECV_INFO_UDP.BufferArray");
        }
        for (i = 0; i < info.BufferCount; i++) {
            AFD_WSABUF buf;
            if (safe_read((char *)&info.BufferArray[i], sizeof(buf), &buf)) {
                if (pre)
                    CHECK_ADDR(buf.buf, buf.len, "AFD_RECV_INFO_UDP.BufferArray[i].buf");
                else {
                    LOG(SYSCALL_VERBOSE, "\tAFD_RECV_INFO_UDP buf %d: "PFX"-"PFX"\n",
                        i, buf.buf, buf.len);
                    MARK_WRITE(buf.buf, buf.len, "AFD_RECV_INFO_UDP.BufferArray[i].buf");
                }
            } else
                WARN("WARNING: AFD_RECV_DATAGRAM: can't read BufferArray\n");
        }
        break;
    }
    case AFD_SELECT: { /* 9 == 0x12024 */
        AFD_POLL_INFO info;
        uint i;
        AFD_POLL_INFO *ptr = NULL;
        if (pre) {
            CHECK_DEF(inbuf, offsetof(AFD_POLL_INFO, Handles),
                      "AFD_POLL_INFO pre-Handles");
        }

        if (inbuf == NULL || !safe_read(inbuf, sizeof(info), &info) ||
            insz != offsetof(AFD_POLL_INFO, Handles) +
            info.HandleCount * sizeof(AFD_HANDLE)) {
            WARN("WARNING: unreadable or invalid AFD_POLL_INFO\n");
            break;
        }

        ptr = (AFD_POLL_INFO *) inbuf;
        for (i = 0; i < info.HandleCount; i++) {
            /* I'm assuming Status is an output field */
            if (pre ) {
                CHECK_DEF(&ptr->Handles[i], offsetof(AFD_HANDLE, Status),
                          "AFD_POLL_INFO.Handles[i]");
            } else {
              MARK_WRITE((byte*)&ptr->Handles[i].Status, sizeof(ptr->Handles[i].Status),
                          "AFD_POLL_INFO.Handles[i].Status");
            }
        }
        break;
    }
    case AFD_GET_TDI_HANDLES: { /* 13 == 0x12037 */
        if (pre) {
            /* I believe input is a uint of AFD_*_HANDLE flags */
            CHECK_DEF(inbuf, insz, "AFD_GET_TDI_HANDLES flags");
            /* as usual the write param will be auto-checked for addressabilty */
        } else {
            uint outsz = (uint) pt->sysarg[9];
            AFD_TDI_HANDLE_DATA *info = (AFD_TDI_HANDLE_DATA *) pt->sysarg[8];
            uint flags;
            if (safe_read(inbuf, sizeof(flags), &flags) &&
                outsz == sizeof(*info)) {
                if (TEST(AFD_ADDRESS_HANDLE, flags)) {
                    MARK_WRITE((byte*)&info->TdiAddressHandle,
                               sizeof(info->TdiAddressHandle),
                               "AFD_TDI_HANDLE_DATA.TdiAddressHandle");
                }
                if (TEST(AFD_CONNECTION_HANDLE, flags)) {
                    MARK_WRITE((byte*)&info->TdiConnectionHandle,
                               sizeof(info->TdiConnectionHandle),
                               "AFD_TDI_HANDLE_DATA.TdiConnectionHandle");
                }
            } else
                WARN("WARNING: unreadable AFD_GET_TDI_HANDLES flags or invalid outsz\n");
        }
        break;
    }
    case AFD_GET_INFO: { /* 30 == 0x1207b */
        if (pre) {
            /* InputBuffer == AFD_INFO.  Only InformationClass need be defined. */
            CHECK_DEF(inbuf, sizeof(((AFD_INFO*)0)->InformationClass),
                      "AFD_INFO.InformationClass");
        } else {
            /* XXX i#378: post-syscall we should only define the particular info
             * fields written.  e.g., only AFD_INFO_GROUP_ID_TYPE uses the
             * LargeInteger field and the rest will leave the extra dword there
             * undefined.  Punting on that for now.
             */
        }

        break;
    }
    default: {
        pre_post_ioctl = false;
    }
    }

    if (pre_post_ioctl || !pre) {
        return;
    }

    /* All the ioctls below need only pre- handling */
    switch (opcode) {
    case AFD_SET_INFO: { /* 14 == 0x1203b */
        /* InputBuffer == AFD_INFO.  If not LARGE_INTEGER, 2nd word can be undef.
         * Padding also need not be defined.
         */
        AFD_INFO info;
        CHECK_DEF(inbuf, sizeof(info.InformationClass), "AFD_INFO.InformationClass");
        if (safe_read(inbuf, sizeof(info), &info)) {
            switch (info.InformationClass) {
            case AFD_INFO_BLOCKING_MODE:
                /* uses BOOLEAN in union */
                CHECK_DEF(inbuf + offsetof(AFD_INFO, Information.Boolean),
                          sizeof(info.Information.Boolean), "AFD_INFO.Information");
                break;
            default:
                /* the other codes are only valid with AFD_GET_INFO */
                WARN("WARNING: AFD_SET_INFO: unknown info opcode\n");
                break;
            }
        } else
            WARN("WARNING: AFD_SET_INFO: cannot read info opcode\n");
        break;
    }
    case AFD_SET_CONTEXT: { /* 17 == 0x12047 */
        /* InputBuffer == SOCKET_CONTEXT.  SOCKET_CONTEXT.Padding need not be defined,
         * and the helper data is var-len.
         *
         * Depending on the Windows version, the SOCKET_CONTEXT struct layout
         * can be different (see i#375). We start with reading the first SOCK_SHARED_INFO
         * field cause it contains the flags needed to identify the layout.
         */
        SOCK_SHARED_INFO sd;
        size_t helper_size, helper_offs;
        byte *l_addr_ptr = NULL, *r_addr_ptr = NULL;

        ASSERT(offsetof(SOCKET_CONTEXT, SharedData) == 0,
               "SOCKET_CONTEXT layout changed?");
        ASSERT(offsetof(SOCKET_CONTEXT_NOGUID, SharedData) == 0,
               "SOCKET_CONTEXT_NOGUID layout changed?");

        CHECK_DEF(inbuf, sizeof(sd), "SOCKET_CONTEXT SharedData");
        if (!safe_read(inbuf, sizeof(sd), &sd)) {
            WARN("WARNING: AFD_SET_CONTEXT: can't read param\n");
            break;
        }

        /* Now that we know the exact layout we can re-read the SOCKET_CONTEXT */
        if (sd.HasGUID) {
            SOCKET_CONTEXT sc;
            CHECK_DEF(inbuf, offsetof(SOCKET_CONTEXT, Padding),
                      "SOCKET_CONTEXT pre-Padding");
            if (!safe_read(inbuf, sizeof(sc), &sc)) {
                WARN("WARNING: AFD_SET_CONTEXT: can't read param\n");
                break;
            }

            /* I'm treating these SOCKADDRS as var-len */
            l_addr_ptr = inbuf + sizeof(SOCKET_CONTEXT);
            r_addr_ptr = inbuf + sizeof(SOCKET_CONTEXT) + sd.SizeOfLocalAddress;
            helper_size = sc.SizeOfHelperData;
            helper_offs = sizeof(SOCKET_CONTEXT) +
                sd.SizeOfLocalAddress + sd.SizeOfRemoteAddress;
        } else {
            SOCKET_CONTEXT_NOGUID sc;
            CHECK_DEF(inbuf, offsetof(SOCKET_CONTEXT_NOGUID, Padding),
                      "SOCKET_CONTEXT pre-Padding");
            if (!safe_read(inbuf, sizeof(sc), &sc)) {
                WARN("WARNING: AFD_SET_CONTEXT: can't read param\n");
                break;
            }

            /* I'm treating these SOCKADDRS as var-len */
            l_addr_ptr = inbuf + sizeof(SOCKET_CONTEXT_NOGUID);
            r_addr_ptr = inbuf + sizeof(SOCKET_CONTEXT_NOGUID) + sd.SizeOfLocalAddress;
            helper_size = sc.SizeOfHelperData;
            helper_offs = sizeof(SOCKET_CONTEXT_NOGUID) +
                sd.SizeOfLocalAddress + sd.SizeOfRemoteAddress;
        }

        if (helper_offs + helper_size != insz) {
            WARN("WARNING AFD_SET_CONTEXT param fields messed up\n");
            break;
        }

        check_sockaddr(l_addr_ptr, sd.SizeOfLocalAddress, MEMREF_CHECK_DEFINEDNESS,
                       mc, sysnum, "SOCKET_CONTEXT.LocalAddress");
        /* I'm treating these SOCKADDRS as var-len */
        check_sockaddr(r_addr_ptr, sd.SizeOfRemoteAddress, MEMREF_CHECK_DEFINEDNESS,
                       mc, sysnum, "SOCKET_CONTEXT.RemoteAddress");

        /* FIXME i#424: helper data could be a struct w/ padding. I have seen pieces of
         * it be uninit on XP. Just ignore the definedness check if helper data
         * is not trivial
         */
        if (helper_size <= 4)
            CHECK_DEF(inbuf + helper_offs, helper_size, "SOCKET_CONTEXT.HelperData");
        break;
    }
    case AFD_BIND: { /* 0 == 0x12003 */
        /* InputBuffer == AFD_BIND_DATA.  Address.Address is var-len and mswsock.dll
         * seems to pass an over-estimate of the real size.
         */
        CHECK_DEF(inbuf, offsetof(AFD_BIND_DATA, Address), "AFD_BIND_DATA pre-Address");
        check_sockaddr(inbuf + offsetof(AFD_BIND_DATA, Address),
                       insz - offsetof(AFD_BIND_DATA, Address), MEMREF_CHECK_DEFINEDNESS,
                       mc, sysnum, "AFD_BIND_DATA.Address");
        break;
    }
    case AFD_CONNECT: { /* 1 == 0x12007 */
        /* InputBuffer == AFD_CONNECT_INFO.  RemoteAddress.Address is var-len. */
        AFD_CONNECT_INFO *info = (AFD_CONNECT_INFO *) inbuf;
        /* Have to separate the Boolean since padding after it */
        CHECK_DEF(inbuf, sizeof(info->UseSAN), "AFD_CONNECT_INFO.UseSAN");
        CHECK_DEF(&info->Root, (byte*)&info->RemoteAddress - (byte*)&info->Root,
                  "AFD_CONNECT_INFO pre-RemoteAddress");
        check_sockaddr((byte*)&info->RemoteAddress,
                       insz - offsetof(AFD_CONNECT_INFO, RemoteAddress),
                       MEMREF_CHECK_DEFINEDNESS, mc, sysnum,
                       "AFD_CONNECT_INFO.RemoteAddress");
        break;
    }
    case AFD_DISCONNECT: { /* 10 == 0x1202b */
        /* InputBuffer == AFD_DISCONNECT_INFO.  Padding between fields need not be def. */
        AFD_DISCONNECT_INFO *info = (AFD_DISCONNECT_INFO *) inbuf;
        CHECK_DEF(inbuf, sizeof(info->DisconnectType),
                  "AFD_DISCONNECT_INFO.DisconnectType");
        CHECK_DEF(inbuf + offsetof(AFD_DISCONNECT_INFO, Timeout),
                  sizeof(info->Timeout), "AFD_DISCONNECT_INFO.Timeout");
        break;
    }
    case AFD_DEFER_ACCEPT: { /* 35 == 0x120bf */
        /* InputBuffer == AFD_DEFER_ACCEPT_DATA */
        AFD_DEFER_ACCEPT_DATA *info = (AFD_DEFER_ACCEPT_DATA *) inbuf;
        CHECK_DEF(inbuf, sizeof(info->SequenceNumber),
                  "AFD_DEFER_ACCEPT_DATA.SequenceNumber");
        CHECK_DEF(inbuf + offsetof(AFD_DEFER_ACCEPT_DATA, RejectConnection),
                  sizeof(info->RejectConnection),
                  "AFD_DEFER_ACCEPT_DATA.RejectConnection");
        break;
    }
    case AFD_SEND: { /* 7 == 0x1201f */
        /* InputBuffer == AFD_SEND_INFO */
        AFD_SEND_INFO info;
        CHECK_DEF(inbuf, insz, "AFD_SEND_INFO"); /* no padding */
        if (safe_read(inbuf, sizeof(info), &info)) {
            uint i;
            CHECK_DEF(info.BufferArray, info.BufferCount * sizeof(*info.BufferArray),
                      "AFD_SEND_INFO.BufferArray");
            for (i = 0; i < info.BufferCount; i++) {
                AFD_WSABUF buf;
                if (safe_read((char *)&info.BufferArray[i], sizeof(buf), &buf))
                    CHECK_DEF(buf.buf, buf.len, "AFD_SEND_INFO.BufferArray[i].buf");
                else
                    WARN("WARNING: AFD_SEND: can't read param\n");
            }
        } else
            WARN("WARNING: AFD_SEND: can't read param\n");
        break;
    }
    case AFD_SEND_DATAGRAM: { /* 8 == 0x12023 */
        /* InputBuffer == AFD_SEND_INFO_UDP */
        AFD_SEND_INFO_UDP info;
        ULONG size_of_remote_address;
        void *remote_address;
        ASSERT(sizeof(size_of_remote_address) == sizeof(info.SizeOfRemoteAddress) &&
               sizeof(remote_address) == sizeof(info.RemoteAddress), "sizes don't match");
        /* Looks like AFD_SEND_INFO_UDP has 36 bytes of uninit gap in the middle: i#418 */
        CHECK_DEF(inbuf, offsetof(AFD_SEND_INFO_UDP, UnknownGap),
                  "AFD_SEND_INFO_UDP before gap");
        if (safe_read(inbuf, offsetof(AFD_SEND_INFO_UDP, UnknownGap), &info)) {
            uint i;
            CHECK_DEF(info.BufferArray, info.BufferCount * sizeof(*info.BufferArray),
                      "AFD_SEND_INFO_UDP.BufferArray");
            for (i = 0; i < info.BufferCount; i++) {
                AFD_WSABUF buf;
                if (safe_read((char *)&info.BufferArray[i], sizeof(buf), &buf))
                    CHECK_DEF(buf.buf, buf.len, "AFD_SEND_INFO_UDP.BufferArray[i].buf");
                else
                    WARN("WARNING: AFD_SEND_DATAGRAM: can't read param\n");
            }
        } else
            WARN("WARNING: AFD_SEND_DATAGRAM: can't read param\n");
        CHECK_DEF(inbuf + offsetof(AFD_SEND_INFO_UDP, SizeOfRemoteAddress),
                  sizeof(info.SizeOfRemoteAddress),
                  "AFD_SEND_INFO_UDP.SizeOfRemoteAddress");
        CHECK_DEF(inbuf + offsetof(AFD_SEND_INFO_UDP, RemoteAddress),
                  sizeof(info.RemoteAddress),
                  "AFD_SEND_INFO_UDP.RemoteAddress");
        if (safe_read(inbuf + offsetof(AFD_SEND_INFO_UDP, SizeOfRemoteAddress),
                      sizeof(size_of_remote_address), &size_of_remote_address) &&
            safe_read(inbuf + offsetof(AFD_SEND_INFO_UDP, RemoteAddress),
                      sizeof(remote_address), &remote_address)) {
            CHECK_DEF(remote_address, size_of_remote_address,
                      "AFD_SEND_INFO_UDP.RemoteAddress buffer");
        }

        break;
    }
    case AFD_EVENT_SELECT: { /* 33 == 0x12087 */
        CHECK_DEF(inbuf, insz, "AFD_EVENT_SELECT_INFO");
        break;
    }
    case AFD_ENUM_NETWORK_EVENTS: { /* 34 == 0x1208b */
        CHECK_DEF(inbuf, insz, "AFD_ENUM_NETWORK_EVENTS_INFO"); /*  */
        break;
    }
    case AFD_START_LISTEN: { /* 2 == 0x1200b */
        AFD_LISTEN_DATA *info = (AFD_LISTEN_DATA *) inbuf;
        if (insz != sizeof(AFD_LISTEN_DATA))
            WARN("WARNING: invalid size for AFD_LISTEN_DATA\n");
        /* Have to separate the Booleans since padding after */
        CHECK_DEF(inbuf, sizeof(info->UseSAN), "AFD_LISTEN_DATA.UseSAN");
        CHECK_DEF(&info->Backlog, sizeof(info->Backlog), "AFD_LISTEN_DATA.Backlog");
        CHECK_DEF(&info->UseDelayedAcceptance, sizeof(info->UseDelayedAcceptance),
                  "AFD_LISTEN_DATA.UseDelayedAcceptance");
        break;
    }
    case AFD_ACCEPT: { /* 4 == 0x12010 */
        CHECK_DEF(inbuf, insz, "AFD_ACCEPT_DATA");
        break;
    }
    default: {
        /* FIXME i#377: add more ioctl codes.
         * I've seen 0x120bf == operation # 47 called by
         * WS2_32.dll!setsockopt.  no uninits.  not sure what it is.
         */
        WARN("WARNING: unknown AFD ioctl "PIFX" => op %d\n", full_code, opcode);
        /* XXX: should perhaps dump a callstack too at higher verbosity */
        /* assume full thing must be defined */ 
        CHECK_DEF(inbuf, insz, "AFD InputBuffer");
        break;
    }
    }

    ASSERT(pre, "Sanity check - we should only process pre- ioctls at this point");
}

static bool
handle_DeviceIoControlFile(bool pre, void *drcontext, int sysnum, per_thread_t *pt,
                           dr_mcontext_t *mc)
{
    uint code = (uint) pt->sysarg[5];
    /* FIXME this is not foolproof: could be FILE_DEVICE_BEEP */
    bool is_afd_ioctl = ((code >> 12) == 0x12);

    if (pre) {
        byte *inbuf = (byte *) pt->sysarg[6];
        uint insz = (uint) pt->sysarg[7];
        if (inbuf == NULL)
            return true;
        /* We don't put "6,-7,R" into the table b/c for some ioctls only part of
         * the input buffer needs to be defined.
         */
        /* XXX i#378: should break down the output buffer as well since it
         * may not all be written to.
         */

        if (is_afd_ioctl) {
            /* This is redundant for those where entire buffer must be defined but
             * most need subset defined.
             */
            CHECK_ADDR(inbuf, insz, "InputBuffer");
        } else {
            /* FIXME i#377: add more ioctl codes. */
            WARN("WARNING: unknown ioctl "PIFX" => op %d\n",
                 pt->sysarg[5], (code >> 2) & 0xfff);
            /* XXX: should perhaps dump a callstack too at higher verbosity */
            /* assume full thing must be defined */
            CHECK_DEF(inbuf, insz, "InputBuffer");
        }
    } else {
        /* We have "8,-9,W" in the table so we only need to handle additional pointers
         * here or cases where subsets of the full output buffer are written.
         *
         * XXX i#410: We treat asynch i/o as happening now rather than trying to
         * watch NtWait* and tracking event objects, though we'll
         * over-estimate the amount written in some cases.
         */
        if (!os_syscall_succeeded(sysnum, NULL, dr_syscall_get_result(drcontext)))
            return true;
    }

    /* FIXME i#377: add more ioctl codes. */
    if (is_afd_ioctl) {
        handle_AFD_ioctl(pre, sysnum, pt, mc);
    }
    return true;
}

#undef CHECK_DEF
#undef CHECK_ADDR
#undef MARK_WRITE

/***************************************************************************
 * SHADOW TOP-LEVEL ROUTINES
 */


bool
os_shadow_pre_syscall(void *drcontext, int sysnum)
{
    per_thread_t *pt = (per_thread_t *) dr_get_tls_field(drcontext);
    dr_mcontext_t mc; /* do not init whole thing: memset is expensive */
    mc.size = sizeof(mc);
    dr_get_mcontext(drcontext, &mc); /* move up once have more cases */
    if (sysnum == sysnum_CreateThreadEx)
        return handle_pre_CreateThreadEx(drcontext, sysnum, pt, &mc);
    else if (sysnum == sysnum_CreateUserProcess)
        return handle_pre_CreateUserProcess(drcontext, sysnum, pt, &mc);
    else if (sysnum == sysnum_DeviceIoControlFile)
        return handle_DeviceIoControlFile(true/*pre*/, drcontext, sysnum, pt, &mc);
    else if (sysnum == sysnum_SetSystemInformation)
        return handle_SetSystemInformation(true/*pre*/, drcontext, sysnum, pt, &mc);
    else if (sysnum == sysnum_QuerySystemInformation)
        return handle_QuerySystemInformation(true/*pre*/, drcontext, sysnum, pt, &mc);
    else
        return wingdi_process_syscall(true/*pre*/, drcontext, sysnum, pt, &mc);
}

#ifdef DEBUG
/* info to help analyze syscall false positives.
 * maybe could eventually spin some of this off as an strace tool.
 */
void
syscall_diagnostics(void *drcontext, int sysnum)
{
    /* XXX: even though only at -verbose 2, should use safe_read for all derefs */
    per_thread_t *pt = (per_thread_t *) dr_get_tls_field(drcontext);
    syscall_info_t *sysinfo = syscall_lookup(sysnum);
    if (sysinfo == NULL)
        return;
    if (!NT_SUCCESS(dr_syscall_get_result(drcontext)))
        return;
    if (strcmp(sysinfo->name, "NtQueryValueKey") == 0) {
        UNICODE_STRING *us = (UNICODE_STRING *) pt->sysarg[1];
        LOG(2, "NtQueryValueKey %S => ", us->Buffer);
        if (pt->sysarg[2] == KeyValuePartialInformation) {
            KEY_VALUE_PARTIAL_INFORMATION *info = (KEY_VALUE_PARTIAL_INFORMATION *)
                pt->sysarg[3];
            if (info->Type == REG_SZ || info->Type == REG_EXPAND_SZ ||
                info->Type == REG_MULTI_SZ/*just showing first*/)
                LOG(2, "%.*S", info->DataLength, (wchar_t *)info->Data);
            else
                LOG(2, PFX, *(ptr_int_t *)info->Data);
        } else if (pt->sysarg[2] == KeyValueFullInformation) {
            KEY_VALUE_FULL_INFORMATION *info = (KEY_VALUE_FULL_INFORMATION *)
                pt->sysarg[3];
            LOG(2, "%.*S = ", info->NameLength, info->Name);
            if (info->Type == REG_SZ || info->Type == REG_EXPAND_SZ ||
                info->Type == REG_MULTI_SZ/*just showing first*/) {
                LOG(2, "%.*S",
                    info->DataLength, (wchar_t *)(((byte*)info)+info->DataOffset));
            } else
                LOG(2, PFX, *(ptr_int_t *)(((byte*)info)+info->DataOffset));
        }
        LOG(2, "\n");
    } else if (strcmp(sysinfo->name, "NtOpenFile") == 0 ||
               strcmp(sysinfo->name, "NtCreateFile") == 0) {
        OBJECT_ATTRIBUTES *obj = (OBJECT_ATTRIBUTES *) pt->sysarg[2];
        if (obj != NULL && obj->ObjectName != NULL)
            LOG(2, "%s %S\n", sysinfo->name, obj->ObjectName->Buffer);
    }
}
#endif

void
os_shadow_post_syscall(void *drcontext, int sysnum)
{
    per_thread_t *pt = (per_thread_t *) dr_get_tls_field(drcontext);
    dr_mcontext_t mc; /* do not init whole thing: memset is expensive */
    mc.size = sizeof(mc);
    dr_get_mcontext(drcontext, &mc); /* move up once have more cases */
    /* FIXME code org: there's some processing of syscalls in alloc_drmem.c's
     * client_post_syscall() where common/alloc.c identifies the sysnum: but
     * for things that don't have anything to do w/ mem alloc I think it's
     * cleaner to have it all in here rather than having to edit both files.
     * Perhaps NtContinue and NtSetContextThread should also be here?  OTOH,
     * the teb is an alloc.
     */
    if (sysnum == sysnum_CreateThread)
        handle_post_CreateThread(drcontext, sysnum, pt, &mc);
    else if (sysnum == sysnum_CreateThreadEx)
        handle_post_CreateThreadEx(drcontext, sysnum, pt, &mc);
    else if (sysnum == sysnum_CreateUserProcess)
        handle_post_CreateUserProcess(drcontext, sysnum, pt, &mc);
    else if (sysnum == sysnum_DeviceIoControlFile)
        handle_DeviceIoControlFile(false/*!pre*/, drcontext, sysnum, pt, &mc);
    else if (sysnum == sysnum_SetSystemInformation)
        handle_SetSystemInformation(false/*!pre*/, drcontext, sysnum, pt, &mc);
    else if (sysnum == sysnum_QuerySystemInformation)
        handle_QuerySystemInformation(false/*!pre*/, drcontext, sysnum, pt, &mc);
    else
        wingdi_process_syscall(false/*!pre*/, drcontext, sysnum, pt, &mc);
    DOLOG(2, { syscall_diagnostics(drcontext, sysnum); });
}

