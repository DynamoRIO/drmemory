/* **********************************************************
 * Copyright (c) 2007-2009 VMware, Inc.  All rights reserved.
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

/***************************************************************************
 * SYSTEM CALLS FOR WINDOWS
 */

/* We need a hashtable to map system call # to index in table, since syscall #s
 * vary by Windows version.
 */
#define SYSTABLE_HASH_BITS 8
static hashtable_t systable;

/* Syscalls that need special processing */
int sysnum_CreateThread;

/* FIXME PR 406349: win32k.sys syscalls!  currently doing memcmp to see what was written
 * FIXME PR 406350: IIS syscalls!
 * FIXME PR 406351: add XP and Vista syscalls!
 * FIXME PR 406355: my windows syscall data is missing 3 types of information:
 *   - some structs have variable-length data on the end
 *     e.g., PORT_MESSAGE which I do handle today w/ hardcoded support
 *   - some structs have optional fields that don't need to be defined
 *   - need to add post-syscall write size entries: I put in a handful.
 *     should look at all OUT params whose (requested) size comes from an IN param
 */
/* Sources:
 *   /work/dr/tot/internal/win32lore/syscalls/nebbett/ntdll.h
 *   /extsw/pkgs/ReactOS-0.3.1/include/ddk/winddk.h
 *   /extsw/pkgs/ReactOS-0.3.1/include/psdk/winternl.h
 *   Metasploit syscall table
 * Originally generated via:
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
#define W (SYSARG_WRITE)
#define R (0)
#define RP (SYSARG_PORT_MESSAGE)
#define WP (SYSARG_WRITE | SYSARG_PORT_MESSAGE)
#define WI (SYSARG_WRITE | SYSARG_LENGTH_INOUT)
#define IB (SYSARG_INLINED_BOOLEAN)
#define IO (SYSARG_POST_SIZE_IO_STATUS)
syscall_info_t syscall_info[] = {
    {0,"NtAcceptConnectPort", 24, 0,sizeof(HANDLE),W, 2,sizeof(PORT_MESSAGE),RP, 3,0,IB, 4,sizeof(PORT_VIEW),W, 5,sizeof(REMOTE_PORT_VIEW),W, },
    {0,"NtAccessCheck", 32, 0,sizeof(SECURITY_DESCRIPTOR),R|SYSARG_SECURITY_DESCRIPTOR, 3,sizeof(GENERIC_MAPPING),R, 4,sizeof(PRIVILEGE_SET),W, 5,sizeof(ULONG),R, 6,sizeof(ACCESS_MASK),W, 7,sizeof(BOOLEAN),W, },
    {0,"NtAccessCheckAndAuditAlarm", 44, 0,sizeof(UNICODE_STRING),R, 2,sizeof(UNICODE_STRING),R, 3,sizeof(UNICODE_STRING),R, 4,sizeof(SECURITY_DESCRIPTOR),R|SYSARG_SECURITY_DESCRIPTOR, 6,sizeof(GENERIC_MAPPING),R, 7,0,IB, 8,sizeof(ACCESS_MASK),W, 9,sizeof(BOOLEAN),W, 10,sizeof(BOOLEAN),W, },
    {0,"NtAccessCheckByType", 44, 0,sizeof(SECURITY_DESCRIPTOR),R|SYSARG_SECURITY_DESCRIPTOR, 1,sizeof(SID),R, 4,sizeof(OBJECT_TYPE_LIST),R, 6,sizeof(GENERIC_MAPPING),R, 7,sizeof(PRIVILEGE_SET),R, 8,sizeof(ULONG),R, 9,sizeof(ACCESS_MASK),W, 10,sizeof(ULONG),W, },
    {0,"NtAccessCheckByTypeAndAuditAlarm", 64, 0,sizeof(UNICODE_STRING),R, 2,sizeof(UNICODE_STRING),R, 3,sizeof(UNICODE_STRING),R, 4,sizeof(SECURITY_DESCRIPTOR),R|SYSARG_SECURITY_DESCRIPTOR, 5,sizeof(SID),R, 9,sizeof(OBJECT_TYPE_LIST),R, 11,sizeof(GENERIC_MAPPING),R, 12,0,IB, 13,sizeof(ACCESS_MASK),W, 14,sizeof(ULONG),W, 15,sizeof(BOOLEAN),W, },
    {0,"NtAccessCheckByTypeResultList", 44, 0,sizeof(SECURITY_DESCRIPTOR),R|SYSARG_SECURITY_DESCRIPTOR, 1,sizeof(SID),R, 4,sizeof(OBJECT_TYPE_LIST),R, 6,sizeof(GENERIC_MAPPING),R, 7,sizeof(PRIVILEGE_SET),R, 8,sizeof(ULONG),R, 9,sizeof(ACCESS_MASK),W, 10,sizeof(ULONG),W, },
    {0,"NtAccessCheckByTypeResultListAndAuditAlarm", 64, 0,sizeof(UNICODE_STRING),R, 2,sizeof(UNICODE_STRING),R, 3,sizeof(UNICODE_STRING),R, 4,sizeof(SECURITY_DESCRIPTOR),R|SYSARG_SECURITY_DESCRIPTOR, 5,sizeof(SID),R, 9,sizeof(OBJECT_TYPE_LIST),R, 11,sizeof(GENERIC_MAPPING),R, 12,0,IB, 13,sizeof(ACCESS_MASK),W, 14,sizeof(ULONG),W, 15,sizeof(ULONG),W, },
    {0,"NtAccessCheckByTypeResultListAndAuditAlarmByHandle", 68, 0,sizeof(UNICODE_STRING),R, 3,sizeof(UNICODE_STRING),R, 4,sizeof(UNICODE_STRING),R, 5,sizeof(SECURITY_DESCRIPTOR),R|SYSARG_SECURITY_DESCRIPTOR, 6,sizeof(SID),R, 10,sizeof(OBJECT_TYPE_LIST),R, 12,sizeof(GENERIC_MAPPING),R, 13,0,IB, 14,sizeof(ACCESS_MASK),W, 15,sizeof(ULONG),W, 16,sizeof(ULONG),W, },
    {0,"NtAddAtom", 12, 0,-1,R, 2,sizeof(USHORT),W, },
    {0,"NtAddBootEntry", 8, 0,sizeof(UNICODE_STRING),R, 1,sizeof(UNICODE_STRING),R, },
    {0,"NtAddDriverEntry", 8, 0,sizeof(UNICODE_STRING),R, 1,sizeof(UNICODE_STRING),R, },
    {0,"NtAdjustGroupsToken", 24, 1,0,IB, 2,sizeof(TOKEN_GROUPS),R, 4,sizeof(TOKEN_GROUPS),W, 5,sizeof(ULONG),W, },
    {0,"NtAdjustPrivilegesToken", 24, 1,0,IB, 2,sizeof(TOKEN_PRIVILEGES),R, 4,sizeof(TOKEN_PRIVILEGES),W, 5,sizeof(ULONG),W, },
    {0,"NtAlertResumeThread", 8, 1,sizeof(ULONG),W, },
    {0,"NtAlertThread", 4, },
    {0,"NtAllocateLocallyUniqueId", 4, 0,sizeof(LUID),W, },
    {0,"NtAllocateUserPhysicalPages", 12, 1,sizeof(ULONG),R, 2,sizeof(ULONG),W, },
    {0,"NtAllocateUuids", 16, 0,sizeof(LARGE_INTEGER),W, 1,sizeof(ULONG),W, 2,sizeof(ULONG),W, 3,sizeof(UCHAR),W, },
    {0,"NtAllocateVirtualMemory", 24, 1,sizeof(PVOID),W, 3,sizeof(ULONG),W, },
    {0,"NtApphelpCacheControl", 8, 1,sizeof(UNICODE_STRING),R, },
    {0,"NtAreMappedFilesTheSame", 8, },
    {0,"NtAssignProcessToJobObject", 8, },
    {0,"NtCallbackReturn", 12, },
    {0,"NtCancelDeviceWakeupRequest", 4, },
    {0,"NtCancelIoFile", 8, 1,sizeof(IO_STATUS_BLOCK),W, },
    {0,"NtCancelTimer", 8, 1,sizeof(BOOLEAN),W, },
    {0,"NtClearEvent", 4, },
    {0,"NtClose", 4, },
    {0,"NtCloseObjectAuditAlarm", 12, 0,sizeof(UNICODE_STRING),R, 2,0,IB, },
    {0,"NtCompactKeys", 8, },
    {0,"NtCompareTokens", 12, 2,sizeof(BOOLEAN),W, },
    {0,"NtCompleteConnectPort", 4, },
    {0,"NtCompressKey", 4, },
    {0,"NtConnectPort", 32, 0,sizeof(HANDLE),W, 1,sizeof(UNICODE_STRING),R, 2,sizeof(SECURITY_QUALITY_OF_SERVICE),R|SYSARG_SECURITY_QOS, 3,sizeof(PORT_VIEW),W, 4,sizeof(REMOTE_PORT_VIEW),W, 5,sizeof(ULONG),W, 6,-7,WI, 7,sizeof(ULONG),W, },
    {0,"NtContinue", 8, 0,sizeof(CONTEXT),R|SYSARG_CONTEXT, 1,0,IB, },
    {0,"NtCreateChannel", 8, 0,sizeof(HANDLE),W, 1,sizeof(OBJECT_ATTRIBUTES),R, },
    {0,"NtCreateDebugObject", 16, 0,sizeof(HANDLE),W, 2,sizeof(OBJECT_ATTRIBUTES),R, 3,0,IB, },
    {0,"NtCreateDirectoryObject", 12, 0,sizeof(HANDLE),W, 2,sizeof(OBJECT_ATTRIBUTES),R, },
    {0,"NtCreateEvent", 20, 0,sizeof(HANDLE),W, 2,sizeof(OBJECT_ATTRIBUTES),R, 4,0,IB, },
    {0,"NtCreateEventPair", 12, 0,sizeof(HANDLE),W, 2,sizeof(OBJECT_ATTRIBUTES),R, },
    {0,"NtCreateFile", 44, 0,sizeof(HANDLE),W, 2,sizeof(OBJECT_ATTRIBUTES),R, 3,sizeof(IO_STATUS_BLOCK),W, 4,sizeof(LARGE_INTEGER),R, },
    {0,"NtCreateIoCompletion", 16, 0,sizeof(HANDLE),W, 2,sizeof(OBJECT_ATTRIBUTES),R, },
    {0,"NtCreateJobObject", 12, 0,sizeof(HANDLE),W, 2,sizeof(OBJECT_ATTRIBUTES),R, },
    {0,"NtCreateJobSet", 12, 1,sizeof(JOB_SET_ARRAY),R, },
    {0,"NtCreateKey", 28, 0,sizeof(HANDLE),W, 2,sizeof(OBJECT_ATTRIBUTES),R, 4,sizeof(UNICODE_STRING),R, 6,sizeof(ULONG),W, },
    {0,"NtCreateKeyedEvent", 16, 0,sizeof(HANDLE),W, 2,sizeof(OBJECT_ATTRIBUTES),R, },
    {0,"NtCreateMailslotFile", 32, 0,sizeof(HANDLE),W, 2,sizeof(OBJECT_ATTRIBUTES),R, 3,sizeof(IO_STATUS_BLOCK),W, 7,sizeof(LARGE_INTEGER),R, },
    {0,"NtCreateMutant", 16, 0,sizeof(HANDLE),W, 2,sizeof(OBJECT_ATTRIBUTES),R, 3,0,IB, },
    {0,"NtCreateNamedPipeFile", 56, 0,sizeof(HANDLE),W, 2,sizeof(OBJECT_ATTRIBUTES),R, 3,sizeof(IO_STATUS_BLOCK),W, 7,0,IB, 8,0,IB, 9,0,IB, 13,sizeof(LARGE_INTEGER),R, },
    {0,"NtCreatePagingFile", 16, 0,sizeof(UNICODE_STRING),R, 1,sizeof(ULARGE_INTEGER),R, 2,sizeof(ULARGE_INTEGER),R, },
    {0,"NtCreatePort", 20, 0,sizeof(HANDLE),W, 1,sizeof(OBJECT_ATTRIBUTES),R, },
    {0,"NtCreateProcess", 32, 0,sizeof(HANDLE),W, 2,sizeof(OBJECT_ATTRIBUTES),R, 4,0,IB, },
    {0,"NtCreateProcessEx", 36, 0,sizeof(HANDLE),W, 2,sizeof(OBJECT_ATTRIBUTES),R, },
    {0,"NtCreateProfile", 36, 0,sizeof(HANDLE),W, 5,sizeof(ULONG),R, },
    {0,"NtCreateSection", 28, 0,sizeof(HANDLE),W, 2,sizeof(OBJECT_ATTRIBUTES),R, 3,sizeof(LARGE_INTEGER),R, },
    {0,"NtCreateSemaphore", 20, 0,sizeof(HANDLE),W, 2,sizeof(OBJECT_ATTRIBUTES),R, },
    {0,"NtCreateSymbolicLinkObject", 16, 0,sizeof(HANDLE),W, 2,sizeof(OBJECT_ATTRIBUTES),R, 3,sizeof(UNICODE_STRING),R, },
    {0,"NtCreateThread", 32, 0,sizeof(HANDLE),W, 2,sizeof(OBJECT_ATTRIBUTES),R, 4,sizeof(CLIENT_ID),W, 5,sizeof(CONTEXT),R|SYSARG_CONTEXT, 6,sizeof(USER_STACK),R, 7,0,IB, },
    {0,"NtCreateTimer", 16, 0,sizeof(HANDLE),W, 2,sizeof(OBJECT_ATTRIBUTES),R, },
    {0,"NtCreateToken", 52, 0,sizeof(HANDLE),W, 2,sizeof(OBJECT_ATTRIBUTES),R, 4,sizeof(LUID),R, 5,sizeof(LARGE_INTEGER),R, 6,sizeof(TOKEN_USER),R, 7,sizeof(TOKEN_GROUPS),R, 8,sizeof(TOKEN_PRIVILEGES),R, 9,sizeof(TOKEN_OWNER),R, 10,sizeof(TOKEN_PRIMARY_GROUP),R, 11,sizeof(TOKEN_DEFAULT_DACL),R, 12,sizeof(TOKEN_SOURCE),R, },
    {0,"NtCreateWaitablePort", 20, 0,sizeof(HANDLE),W, 1,sizeof(OBJECT_ATTRIBUTES),R, },
    {0,"NtDebugActiveProcess", 8, },
    {0,"NtDebugContinue", 12, 1,sizeof(CLIENT_ID),R, },
    {0,"NtDelayExecution", 8, 0,0,IB, 1,sizeof(LARGE_INTEGER),R, },
    {0,"NtDeleteAtom", 4, },
    {0,"NtDeleteBootEntry", 8, 0,sizeof(UNICODE_STRING),R, 1,sizeof(UNICODE_STRING),R, },
    {0,"NtDeleteDriverEntry", 8, 0,sizeof(UNICODE_STRING),R, 1,sizeof(UNICODE_STRING),R, },
    {0,"NtDeleteFile", 4, 0,sizeof(OBJECT_ATTRIBUTES),R, },
    {0,"NtDeleteKey", 4, },
    {0,"NtDeleteObjectAuditAlarm", 12, 0,sizeof(UNICODE_STRING),R, 2,0,IB, },
    {0,"NtDeleteValueKey", 8, 1,sizeof(UNICODE_STRING),R, },
    {0,"NtDeviceIoControlFile", 40, 4,sizeof(IO_STATUS_BLOCK),W, 8,-9,W, },
    {0,"NtDisplayString", 4, 0,sizeof(UNICODE_STRING),R, },
    {0,"NtDuplicateObject", 28, 3,sizeof(HANDLE),W, },
    {0,"NtDuplicateToken", 24, 2,sizeof(OBJECT_ATTRIBUTES),R, 3,0,IB, 5,sizeof(HANDLE),W, },
    {0,"NtEnumerateBootEntries", 8, },
    {0,"NtEnumerateDriverEntries", 8, },
    {0,"NtEnumerateKey", 24, 3,-4,W, 3,-5,WI, 5,sizeof(ULONG),W, },
    {0,"NtEnumerateSystemEnvironmentValuesEx", 12, },
    {0,"NtEnumerateValueKey", 24, 3,-4,W, 3,-5,WI, 5,sizeof(ULONG),W, },
    {0,"NtExtendSection", 8, 1,sizeof(LARGE_INTEGER),R, },
    {0,"NtFilterToken", 24, 2,sizeof(TOKEN_GROUPS),R, 3,sizeof(TOKEN_PRIVILEGES),R, 4,sizeof(TOKEN_GROUPS),R, 5,sizeof(HANDLE),W, },
    {0,"NtFindAtom", 12, 0,-1,R, 2,sizeof(USHORT),W, },
    {0,"NtFlushBuffersFile", 8, 1,sizeof(IO_STATUS_BLOCK),W, },
    {0,"NtFlushInstructionCache", 12, },
    {0,"NtFlushKey", 4, },
    {0,"NtFlushVirtualMemory", 16, 1,sizeof(PVOID),W, 2,sizeof(ULONG),W, 3,sizeof(IO_STATUS_BLOCK),W, },
    {0,"NtFlushWriteBuffer", 0, },
    {0,"NtFreeUserPhysicalPages", 12, 1,sizeof(ULONG),W, 2,sizeof(ULONG),R, },
    {0,"NtFreeVirtualMemory", 16, 1,sizeof(PVOID),W, 2,sizeof(ULONG),W, },
    {0,"NtFsControlFile", 40, 4,sizeof(IO_STATUS_BLOCK),W, 8,-9,W, },
    {0,"NtGetContextThread", 8, 1,sizeof(CONTEXT),W|SYSARG_CONTEXT, },
    {0,"NtGetCurrentProcessorNumber", 4, },
    {0,"NtGetDevicePowerState", 8, 1,sizeof(DEVICE_POWER_STATE),W, },
    {0,"NtGetPlugPlayEvent", 16, 2,-3,W, },
    /* FIXME: Buffer and BufferEntries: */
    {0,"NtGetWriteWatch", 28, 4,sizeof(ULONG),W, 5,sizeof(ULONG),W, 6,sizeof(ULONG),W, },
    {0,"NtImpersonateAnonymousToken", 4, },
    {0,"NtImpersonateClientOfPort", 8, 1,sizeof(PORT_MESSAGE),RP, },
    {0,"NtImpersonateThread", 12, 2,sizeof(SECURITY_QUALITY_OF_SERVICE),R|SYSARG_SECURITY_QOS, },
    {0,"NtInitializeRegistry", 4, 0,0,IB, },
    {0,"NtInitiatePowerAction", 16, 3,0,IB, },
    {0,"NtIsProcessInJob", 8, },
    {0,"NtIsSystemResumeAutomatic", 0, },
    {0,"NtListenChannel", 8, 1,sizeof(CHANNEL_MESSAGE),W, },
    {0,"NtListenPort", 8, 1,sizeof(PORT_MESSAGE),WP, },
    {0,"NtLoadDriver", 4, 0,sizeof(UNICODE_STRING),R, },
    {0,"NtLoadKey2", 12, 0,sizeof(OBJECT_ATTRIBUTES),R, 1,sizeof(OBJECT_ATTRIBUTES),R, },
    {0,"NtLoadKey", 8, 0,sizeof(OBJECT_ATTRIBUTES),R, 1,sizeof(OBJECT_ATTRIBUTES),R, },
    {0,"NtLoadKeyEx", 16, 0,sizeof(OBJECT_ATTRIBUTES),R, 1,sizeof(OBJECT_ATTRIBUTES),R, },
    {0,"NtLockFile", 40, 4,sizeof(IO_STATUS_BLOCK),W, 5,sizeof(ULARGE_INTEGER),R, 6,sizeof(ULARGE_INTEGER),R, 8,0,IB, 9,0,IB, },
    {0,"NtLockProductActivationKeys", 8, 0,sizeof(ULONG),W, 1,sizeof(ULONG),W, },
    {0,"NtLockRegistryKey", 4, },
    {0,"NtLockVirtualMemory", 16, 1,sizeof(PVOID),W, 2,sizeof(ULONG),W, },
    {0,"NtMakePermanentObject", 4, },
    {0,"NtMakeTemporaryObject", 4, },
    {0,"NtMapUserPhysicalPages", 12, 1,sizeof(ULONG),R, 2,sizeof(ULONG),R, },
    {0,"NtMapUserPhysicalPagesScatter", 12, 0,sizeof(PVOID),R, 1,sizeof(ULONG),R, 2,sizeof(ULONG),R, },
    {0,"NtMapViewOfSection", 40, 2,sizeof(PVOID),W, 5,sizeof(LARGE_INTEGER),W, 6,sizeof(ULONG),W, },
    {0,"NtModifyBootEntry", 8, 0,sizeof(UNICODE_STRING),R, 1,sizeof(UNICODE_STRING),R, },
    {0,"NtModifyDriverEntry", 8, 0,sizeof(UNICODE_STRING),R, 1,sizeof(UNICODE_STRING),R, },
    {0,"NtNotifyChangeDirectoryFile", 36, 4,sizeof(IO_STATUS_BLOCK),W, 5,sizeof(FILE_NOTIFY_INFORMATION),W, 8,0,IB, },
    {0,"NtNotifyChangeKey", 40, 4,sizeof(IO_STATUS_BLOCK),W, 6,0,IB, 9,0,IB, },
    {0,"NtNotifyChangeMultipleKeys", 48, 2,sizeof(OBJECT_ATTRIBUTES),R, 6,sizeof(IO_STATUS_BLOCK),W, 8,0,IB, 11,0,IB, },
    {0,"NtOpenChannel", 8, 0,sizeof(HANDLE),W, 1,sizeof(OBJECT_ATTRIBUTES),R, },
    {0,"NtOpenDirectoryObject", 12, 0,sizeof(HANDLE),W, 2,sizeof(OBJECT_ATTRIBUTES),R, },
    {0,"NtOpenEvent", 12, 0,sizeof(HANDLE),W, 2,sizeof(OBJECT_ATTRIBUTES),R, },
    {0,"NtOpenEventPair", 12, 0,sizeof(HANDLE),W, 2,sizeof(OBJECT_ATTRIBUTES),R, },
    {0,"NtOpenFile", 24, 0,sizeof(HANDLE),W, 2,sizeof(OBJECT_ATTRIBUTES),R, 3,sizeof(IO_STATUS_BLOCK),W, },
    {0,"NtOpenIoCompletion", 12, 0,sizeof(HANDLE),W, 2,sizeof(OBJECT_ATTRIBUTES),R, },
    {0,"NtOpenJobObject", 12, 0,sizeof(HANDLE),W, 2,sizeof(OBJECT_ATTRIBUTES),R, },
    {0,"NtOpenKey", 12, 0,sizeof(HANDLE),W, 2,sizeof(OBJECT_ATTRIBUTES),R, },
    {0,"NtOpenKeyedEvent", 12, 0,sizeof(HANDLE),W, 2,sizeof(OBJECT_ATTRIBUTES),R, },
    {0,"NtOpenMutant", 12, 0,sizeof(HANDLE),W, 2,sizeof(OBJECT_ATTRIBUTES),R, },
    {0,"NtOpenObjectAuditAlarm", 48, 0,sizeof(UNICODE_STRING),R, 1,sizeof(PVOID),R, 2,sizeof(UNICODE_STRING),R, 3,sizeof(UNICODE_STRING),R, 4,sizeof(SECURITY_DESCRIPTOR),R|SYSARG_SECURITY_DESCRIPTOR, 8,sizeof(PRIVILEGE_SET),R, 9,0,IB, 10,0,IB, 11,sizeof(BOOLEAN),W, },
    {0,"NtOpenProcess", 16, 0,sizeof(HANDLE),W, 2,sizeof(OBJECT_ATTRIBUTES),R, 3,sizeof(CLIENT_ID),R, },
    {0,"NtOpenProcessToken", 12, 2,sizeof(HANDLE),W, },
    {0,"NtOpenProcessTokenEx", 16, 3,sizeof(HANDLE),W, },
    {0,"NtOpenSection", 12, 0,sizeof(HANDLE),W, 2,sizeof(OBJECT_ATTRIBUTES),R, },
    {0,"NtOpenSemaphore", 12, 0,sizeof(HANDLE),W, 2,sizeof(OBJECT_ATTRIBUTES),R, },
    {0,"NtOpenSymbolicLinkObject", 12, 0,sizeof(HANDLE),W, 2,sizeof(OBJECT_ATTRIBUTES),R, },
    {0,"NtOpenThread", 16, 0,sizeof(HANDLE),W, 2,sizeof(OBJECT_ATTRIBUTES),R, 3,sizeof(CLIENT_ID),R, },
    {0,"NtOpenThreadToken", 16, 2,0,IB, 3,sizeof(HANDLE),W, },
    {0,"NtOpenThreadTokenEx", 20, 2,0,IB, 4,sizeof(HANDLE),W, },
    {0,"NtOpenTimer", 12, 0,sizeof(HANDLE),W, 2,sizeof(OBJECT_ATTRIBUTES),R, },
    {0,"NtPlugPlayControl", 16, 1,-2,W, },
    {0,"NtPowerInformation", 20, 3,-4,W, },
    {0,"NtPrivilegeCheck", 12, 1,sizeof(PRIVILEGE_SET),R, 2,sizeof(BOOLEAN),W, },
    {0,"NtPrivilegedServiceAuditAlarm", 20, 0,sizeof(UNICODE_STRING),R, 1,sizeof(UNICODE_STRING),R, 3,sizeof(PRIVILEGE_SET),R, 4,0,IB, },
    {0,"NtPrivilegeObjectAuditAlarm", 24, 0,sizeof(UNICODE_STRING),R, 4,sizeof(PRIVILEGE_SET),R, 5,0,IB, },
    {0,"NtProtectVirtualMemory", 20, 1,sizeof(PVOID),W, 2,sizeof(ULONG),W, 4,sizeof(ULONG),W, },
    {0,"NtPulseEvent", 8, 1,sizeof(ULONG),W, },
    {0,"NtQueryAttributesFile", 8, 0,sizeof(OBJECT_ATTRIBUTES),R, 1,sizeof(FILE_BASIC_INFORMATION),W, },
    {0,"NtQueryBootEntryOrder", 8, },
    {0,"NtQueryBootOptions", 8, },
    {0,"NtQueryDebugFilterState", 8, },
    {0,"NtQueryDefaultLocale", 8, 0,0,IB, 1,sizeof(LCID),W, },
    {0,"NtQueryDefaultUILanguage", 4, 0,sizeof(LANGID),W, },
    {0,"NtQueryDirectoryFile", 44, 4,sizeof(IO_STATUS_BLOCK),W, 5,-6,W, 8,0,IB, 9,sizeof(UNICODE_STRING),R, 10,0,IB, },
    {0,"NtQueryDirectoryObject", 28, 1,-2,W, 3,0,IB, 4,0,IB, 5,sizeof(ULONG),W, 6,sizeof(ULONG),W, },
    {0,"NtQueryDriverEntryOrder", 8, },
    {0,"NtQueryEaFile", 36, 1,sizeof(IO_STATUS_BLOCK),W, 2,sizeof(FILE_FULL_EA_INFORMATION),W, 4,0,IB, 5,sizeof(FILE_GET_EA_INFORMATION),R, 7,sizeof(ULONG),R, 8,0,IB, },
    {0,"NtQueryEvent", 20, 2,-3,W, 4,sizeof(ULONG),W, },
    {0,"NtQueryFullAttributesFile", 8, 0,sizeof(OBJECT_ATTRIBUTES),R, 1,sizeof(FILE_NETWORK_OPEN_INFORMATION),W, },
    {0,"NtQueryInformationAtom", 20, 2,-3,W, 4,sizeof(ULONG),W, },
    {0,"NtQueryInformationFile", 20, 1,sizeof(IO_STATUS_BLOCK),W, 2,-3,W, },
    {0,"NtQueryInformationJobObject", 20, 2,-3,W, 4,sizeof(ULONG),W, },
    {0,"NtQueryInformationPort", 20, 2,-3,W, 4,sizeof(ULONG),W, },
    {0,"NtQueryInformationProcess", 20, 2,-3,W, 4,sizeof(ULONG),W, },
    {0,"NtQueryInformationThread", 20, 2,-3,W, 4,sizeof(ULONG),W, },
    {0,"NtQueryInformationToken", 20, 2,-3,W, 4,sizeof(ULONG),W, },
    {0,"NtQueryInstallUILanguage", 4, 0,sizeof(LANGID),W, },
    {0,"NtQueryIntervalProfile", 8, 1,sizeof(ULONG),W, },
    {0,"NtQueryIoCompletion", 20, 2,-3,W, 4,sizeof(ULONG),W, },
    {0,"NtQueryKey", 20, 2,-3,W, 4,sizeof(ULONG),W, },
    {0,"NtQueryMultipleValueKey", 24, 1,sizeof(KEY_VALUE_ENTRY),W, 3,-4,WI, 4,sizeof(ULONG),W, 5,sizeof(ULONG),W, },
    {0,"NtQueryMutant", 20, 2,-3,W, 4,sizeof(ULONG),W, },
    {0,"NtQueryObject", 20, 2,-3,W, 4,sizeof(ULONG),W, },
    {0,"NtQueryOleDirectoryFile", 44, 4,sizeof(IO_STATUS_BLOCK),W, 5,-6,W, 8,0,IB, 9,sizeof(UNICODE_STRING),R, 10,0,IB, },
    {0,"NtQueryOpenSubKeys", 8, 0,sizeof(OBJECT_ATTRIBUTES),R, 1,sizeof(ULONG),W, },
    {0,"NtQueryOpenSubKeysEx", 16, 0,sizeof(OBJECT_ATTRIBUTES),R, 2,sizeof(ULONG),W, 3,sizeof(ULONG),W, },
    {0,"NtQueryPerformanceCounter", 8, 0,sizeof(LARGE_INTEGER),W, 1,sizeof(LARGE_INTEGER),W, },
    {0,"NtQueryPortInformationProcess", 4, },
    {0,"NtQueryQuotaInformationFile", 36, 1,sizeof(IO_STATUS_BLOCK),W, 2,sizeof(FILE_USER_QUOTA_INFORMATION),W, 4,0,IB, 5,sizeof(FILE_QUOTA_LIST_INFORMATION),R, 7,sizeof(SID),R, 8,0,IB, },
    {0,"NtQuerySection", 20, 2,-3,W, 4,sizeof(ULONG),W, },
    /* FIXME NtQuerySecurityObject may not initialize some fields
     * of SECURITY_DESCRIPTOR, depends on the 2nd argument.
     */
    {0,"NtQuerySecurityObject", 20, 2,sizeof(SECURITY_DESCRIPTOR),W, 4,sizeof(ULONG),W, },
    {0,"NtQuerySemaphore", 20, 2,-3,W, 4,sizeof(ULONG),W, },
    {0,"NtQuerySymbolicLinkObject", 12, 1,sizeof(UNICODE_STRING),W, 2,sizeof(ULONG),W, },
    {0,"NtQuerySystemEnvironmentValue", 16, 0,sizeof(UNICODE_STRING),R, 1,-2,W, 3,sizeof(ULONG),W, },
    {0,"NtQuerySystemEnvironmentValueEx", 20, },
    {0,"NtQuerySystemInformation", 16, 1,-2,W, 3,sizeof(ULONG),W, },
    {0,"NtQuerySystemTime", 4, 0,sizeof(LARGE_INTEGER),W, },
    {0,"NtQueryTimer", 20, 2,-3,W, 4,sizeof(ULONG),W, },
    {0,"NtQueryTimerResolution", 12, 0,sizeof(ULONG),W, 1,sizeof(ULONG),W, 2,sizeof(ULONG),W, },
    {0,"NtQueryValueKey", 24, 1,sizeof(UNICODE_STRING),R, 3,-4,W, 5,sizeof(ULONG),W, },
    {0,"NtQueryVirtualMemory", 24, 3,-4,W, 5,sizeof(ULONG),W, },
    {0,"NtQueryVolumeInformationFile", 20, 1,sizeof(IO_STATUS_BLOCK),W, 2,-3,W, },
    {0,"NtQueueApcThread", 20, },
    {0,"NtRaiseException", 12, 0,sizeof(EXCEPTION_RECORD),R|SYSARG_EXCEPTION_RECORD, 1,sizeof(CONTEXT),R|SYSARG_CONTEXT, 2,0,IB, },
    {0,"NtRaiseHardError", 24, 3,sizeof(ULONG_PTR),R, 5,sizeof(ULONG),W, },
    {0,"NtReadFile", 36, 4,sizeof(IO_STATUS_BLOCK),W, 5,-6,W, 5,-4,(W|IO), 7,sizeof(LARGE_INTEGER),R, 8,sizeof(ULONG),R, },
    {0,"NtReadFileScatter", 36, 4,sizeof(IO_STATUS_BLOCK),W, 5,sizeof(FILE_SEGMENT_ELEMENT),R, 7,sizeof(LARGE_INTEGER),R, 8,sizeof(ULONG),R, },
    {0,"NtReadRequestData", 24, 1,sizeof(PORT_MESSAGE),RP, 3,-4,W, 5,sizeof(ULONG),W, },
    {0,"NtReadVirtualMemory", 20, 2,-3,W, 4,sizeof(ULONG),W, },
    {0,"NtRegisterThreadTerminatePort", 4, },
    {0,"NtReleaseKeyedEvent", 16, 2,0,IB, 3,sizeof(LARGE_INTEGER),R, },
    {0,"NtReleaseMutant", 8, 1,sizeof(ULONG),W, },
    {0,"NtReleaseSemaphore", 12, 2,sizeof(LONG),W, },
    {0,"NtRemoveIoCompletion", 20, 1,sizeof(ULONG),W, 2,sizeof(ULONG),W, 3,sizeof(IO_STATUS_BLOCK),W, 4,sizeof(LARGE_INTEGER),R, },
    {0,"NtRemoveProcessDebug", 8, },
    {0,"NtRenameKey", 8, 1,sizeof(UNICODE_STRING),R, },
    {0,"NtReplaceKey", 12, 0,sizeof(OBJECT_ATTRIBUTES),R, 2,sizeof(OBJECT_ATTRIBUTES),R, },
    {0,"NtReplyPort", 8, 1,sizeof(PORT_MESSAGE),RP, },
    {0,"NtReplyWaitReceivePort", 16, 1,sizeof(ULONG),W, 2,sizeof(PORT_MESSAGE),RP, 3,sizeof(PORT_MESSAGE),WP, },
    {0,"NtReplyWaitReceivePortEx", 20, 1,sizeof(PVOID),W, 2,sizeof(PORT_MESSAGE),RP, 3,sizeof(PORT_MESSAGE),WP, 4,sizeof(LARGE_INTEGER),R, },
    {0,"NtReplyWaitReplyPort", 8, 1,sizeof(PORT_MESSAGE),WP, },
    {0,"NtReplyWaitSendChannel", 12, 2,sizeof(CHANNEL_MESSAGE),W, },
    {0,"NtRequestDeviceWakeup", 4, },
    {0,"NtRequestPort", 8, 1,sizeof(PORT_MESSAGE),RP, },
#if 1
    /* FIXME PR 406356: suppressing undefined read I see on every app at process
     * termination on w2k3 vm (though not on wow64 laptop) where the last 16
     * bytes are not filled in (so only length and type are).  Length indicates
     * there is data afterward which we try to handle specially.
     */
    {0,"NtRequestWaitReplyPort", 12, 1,8,R, 2,sizeof(PORT_MESSAGE),WP, },
#else
    {0,"NtRequestWaitReplyPort", 12, 1,sizeof(PORT_MESSAGE),RP, 2,sizeof(PORT_MESSAGE),WP, },
#endif
    {0,"NtRequestWakeupLatency", 4, },
    {0,"NtResetEvent", 8, 1,sizeof(ULONG),W, },
    {0,"NtResetWriteWatch", 12, },
    {0,"NtRestoreKey", 12, },
    {0,"NtResumeProcess", 4, },
    {0,"NtResumeThread", 8, 1,sizeof(ULONG),W, },
    {0,"NtSaveKey", 8, },
    {0,"NtSaveKeyEx", 12, },
    {0,"NtSaveMergedKeys", 12, },
    {0,"NtSecureConnectPort", 36, 0,sizeof(HANDLE),W, 1,sizeof(UNICODE_STRING),R, 2,sizeof(SECURITY_QUALITY_OF_SERVICE),R|SYSARG_SECURITY_QOS, 3,sizeof(PORT_VIEW),W, 4,sizeof(SID),R, 5,sizeof(REMOTE_PORT_VIEW),W, 6,sizeof(ULONG),W, 7,-8,WI, 8,sizeof(ULONG),W, },
    {0,"NtSendWaitReplyChannel", 16, 3,sizeof(CHANNEL_MESSAGE),W, },
    {0,"NtSetBootEntryOrder", 8, },
    {0,"NtSetBootOptions", 8, 0,sizeof(BOOT_OPTIONS),R, },
    {0,"NtSetContextChannel", 4, },
    {0,"NtSetContextThread", 8, 1,sizeof(CONTEXT),R|SYSARG_CONTEXT, },
    {0,"NtSetDebugFilterState", 12, 2,0,IB, },
    {0,"NtSetDefaultHardErrorPort", 4, },
    {0,"NtSetDefaultLocale", 8, 0,0,IB, },
    {0,"NtSetDefaultUILanguage", 4, },
    {0,"NtSetEaFile", 16, 1,sizeof(IO_STATUS_BLOCK),W, 2,sizeof(FILE_FULL_EA_INFORMATION),R, },
    {0,"NtSetEvent", 8, 1,sizeof(ULONG),W, },
    {0,"NtSetEventBoostPriority", 4, },
    {0,"NtSetHighEventPair", 4, },
    {0,"NtSetHighWaitLowEventPair", 4, },
    {0,"NtSetHighWaitLowThread", 0, },
    {0,"NtSetInformationDebugObject", 20, 4,sizeof(ULONG),W, },
    {0,"NtSetInformationFile", 20, 1,sizeof(IO_STATUS_BLOCK),W, },
    {0,"NtSetInformationJobObject", 16, },
    {0,"NtSetInformationKey", 16, },
    {0,"NtSetInformationObject", 16, },
    {0,"NtSetInformationProcess", 16, },
    {0,"NtSetInformationThread", 16, },
    {0,"NtSetInformationToken", 16, },
    {0,"NtSetIntervalProfile", 8, },
    {0,"NtSetIoCompletion", 20, },
    {0,"NtSetLdtEntries", 16, },
    {0,"NtSetLowEventPair", 4, },
    {0,"NtSetLowWaitHighEventPair", 4, },
    {0,"NtSetLowWaitHighThread", 0, },
    {0,"NtSetQuotaInformationFile", 16, 1,sizeof(IO_STATUS_BLOCK),W, 2,sizeof(FILE_USER_QUOTA_INFORMATION),R, },
    {0,"NtSetSecurityObject", 12, 2,sizeof(SECURITY_DESCRIPTOR),R|SYSARG_SECURITY_DESCRIPTOR, },
    {0,"NtSetSystemEnvironmentValue", 8, 0,sizeof(UNICODE_STRING),R, 1,sizeof(UNICODE_STRING),R, },
    {0,"NtSetSystemInformation", 12, 1,-2,W, },
    {0,"NtSetSystemPowerState", 12, },
    {0,"NtSetSystemTime", 8, 0,sizeof(LARGE_INTEGER),R, 1,sizeof(LARGE_INTEGER),W, },
    {0,"NtSetThreadExecutionState", 8, 1,sizeof(EXECUTION_STATE),W, },
    {0,"NtSetTimer", 28, 1,sizeof(LARGE_INTEGER),R, 4,0,IB, 6,sizeof(BOOLEAN),W, },
    {0,"NtSetTimerResolution", 12, 1,0,IB, 2,sizeof(ULONG),W, },
    {0,"NtSetUuidSeed", 4, 0,sizeof(UCHAR),R, },
    {0,"NtSetValueKey", 24, 1,sizeof(UNICODE_STRING),R, },
    {0,"NtSetVolumeInformationFile", 20, 1,sizeof(IO_STATUS_BLOCK),W, },
    {0,"NtShutdownSystem", 4, },
    {0,"NtSignalAndWaitForSingleObject", 16, 2,0,IB, 3,sizeof(LARGE_INTEGER),R, },
    {0,"NtStartProfile", 4, },
    {0,"NtStopProfile", 4, },
    {0,"NtSuspendProcess", 4, },
    {0,"NtSuspendThread", 8, 1,sizeof(ULONG),W, },
    {0,"NtSystemDebugControl", 24, 3,-4,W, 5,sizeof(ULONG),W, },
    {0,"NtTerminateJobObject", 8, },
    {0,"NtTerminateProcess", 8, },
    {0,"NtTerminateThread", 8, },
    {0,"NtTestAlert", 0, },
    {0,"NtTraceEvent", 16, 3,sizeof(EVENT_TRACE_HEADER),R, },
    {0,"NtTranslateFilePath", 16, 0,sizeof(FILE_PATH),R, 2,sizeof(FILE_PATH),W, },
    {0,"NtUnloadDriver", 4, 0,sizeof(UNICODE_STRING),R, },
    {0,"NtUnloadKey2", 8, 0,sizeof(OBJECT_ATTRIBUTES),R, 1,0,IB, },
    {0,"NtUnloadKey", 4, 0,sizeof(OBJECT_ATTRIBUTES),R, },
    {0,"NtUnloadKeyEx", 8, 0,sizeof(OBJECT_ATTRIBUTES),R, },
    {0,"NtUnlockFile", 20, 1,sizeof(IO_STATUS_BLOCK),W, 2,sizeof(ULARGE_INTEGER),R, 3,sizeof(ULARGE_INTEGER),R, },
    {0,"NtUnlockVirtualMemory", 16, 1,sizeof(PVOID),W, 2,sizeof(ULONG),W, },
    {0,"NtUnmapViewOfSection", 8, },
    {0,"NtVdmControl", 8, },
    {0,"NtW32Call", 20, 3,sizeof(PVOID),W, 4,sizeof(ULONG),W, },
    {0,"NtWaitForDebugEvent", 16, 1,0,IB, 2,sizeof(LARGE_INTEGER),R, 3,sizeof(DBGUI_WAIT_STATE_CHANGE),W, },
    {0,"NtWaitForKeyedEvent", 16, 2,0,IB, 3,sizeof(LARGE_INTEGER),R, },
    {0,"NtWaitForMultipleObjects", 20, 1,sizeof(HANDLE),R, 3,0,IB, 4,sizeof(LARGE_INTEGER),R, },
    {0,"NtWaitForMultipleObjects32", 20, 1,sizeof(HANDLE),R, 3,0,IB, 4,sizeof(LARGE_INTEGER),R, },
    {0,"NtWaitForSingleObject", 12, 1,0,IB, 2,sizeof(LARGE_INTEGER),R, },
    {0,"NtWaitHighEventPair", 4, },
    {0,"NtWaitLowEventPair", 4, },
    {0,"NtWriteFile", 36, 4,sizeof(IO_STATUS_BLOCK),W, 7,sizeof(LARGE_INTEGER),R, 8,sizeof(ULONG),R, },
    {0,"NtWriteFileGather", 36, 4,sizeof(IO_STATUS_BLOCK),W, 5,sizeof(FILE_SEGMENT_ELEMENT),R, 7,sizeof(LARGE_INTEGER),R, 8,sizeof(ULONG),R, },
    {0,"NtWriteRequestData", 24, 1,sizeof(PORT_MESSAGE),RP, 5,sizeof(ULONG),W, },
    {0,"NtWriteVirtualMemory", 20, 4,sizeof(ULONG),W, },
    {0,"NtYieldExecution", 0, },

};
#undef W
#undef R
#undef WP
#undef RP
#undef WI
#undef IB
#undef IO

#define NUM_SYSCALLS (sizeof(syscall_info)/sizeof(syscall_info[0]))


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

void
syscall_os_init(void *drcontext, app_pc ntdll_base)
{
    uint i;
    hashtable_init(&systable, SYSTABLE_HASH_BITS, HASH_INTPTR, false/*!strdup*/);
    for (i = 0; i < NUM_SYSCALLS; i++) {
        app_pc entry = (app_pc) dr_get_proc_address(ntdll_base, syscall_info[i].name);
        if (entry != NULL) {
            syscall_info[i].num = syscall_num(drcontext, entry);
            hashtable_add(&systable, (void *) syscall_info[i].num,
                          (void *) &syscall_info[i]);
            LOG(2, "system call %s = %d\n", syscall_info[i].name, syscall_info[i].num);
        } else {
            LOG(2, "WARNING: could not find system call %s\n", syscall_info[i].name);
        }
    }
    sysnum_CreateThread = sysnum_from_name(drcontext, ntdll_base, "NtCreateThread");
    ASSERT(sysnum_CreateThread >= 0, "cannot find NtCreateThread sysnum");
}

void
syscall_os_exit(void)
{
    hashtable_delete(&systable);
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
os_shadow_pre_syscall(void *drcontext, int sysnum)
{
    return true; /* execute syscall */
}

void
os_shadow_post_syscall(void *drcontext, int sysnum)
{
    per_thread_t *pt = (per_thread_t *) dr_get_tls_field(drcontext);
    /* FIXME code org: there's some processing of syscalls in alloc_drmem.c's
     * client_post_syscall() where common/alloc.c identifies the sysnum: but
     * for things that don't have anything to do w/ mem alloc I think it's
     * cleaner to have it all in here rather than having to edit both files.
     * Perhaps NtContinue and NtSetContextThread should also be here?  OTOH,
     * the teb is an alloc.
     */
    if (sysnum == sysnum_CreateThread && NT_SUCCESS(dr_syscall_get_result(drcontext))) {
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

static bool handle_port_message_access(bool pre, int sysnum, dr_mcontext_t *mc,
                                       uint arg_num,
                                       const syscall_arg_t *arg_info,
                                       app_pc start, uint size)
{
    uint check_type = SYSARG_CHECK_TYPE(arg_info->flags, pre);
    /* variable-length */
    PORT_MESSAGE pm;
    if (TEST(SYSARG_WRITE, arg_info->flags) && pre) {
        /* Struct is passed in uninit w/ max-len buffer after it.
         * There is some ambiguity over the max:
         * - NtCreatePort's MaxMessageSize: can that be any size?
         *   do we need to query the port?
         * - rpcrt4!LRPC_ADDRESS::ReceiveLotsaCalls seems to allocate 0x100
         * - some sources claim the max is 0x130, instead of the 0x118 I have here.
         * - I have seem 0x15c in rpcrt4!I_RpcSendReceive: leaving my smaller
         *   max for the writes though
         */
        size = sizeof(PORT_MESSAGE) + PORT_MAXIMUM_MESSAGE_LENGTH;
    } else if (safe_read(start, sizeof(pm), &pm)) {
        if (pm.u1.s1.DataLength > 0)
            size = pm.u1.s1.TotalLength;
        else
            size = pm.u1.Length;
        if (size > sizeof(PORT_MESSAGE) + PORT_MAXIMUM_MESSAGE_LENGTH) {
            DO_ONCE({ LOG(1, "WARNING: PORT_MESSAGE size larger than known max"); });
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
    check_sysmem(check_type, sysnum, start, size, mc, NULL);
    return true;
}

static bool handle_context_access(bool pre, int sysnum, dr_mcontext_t *mc, uint arg_num,
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

static bool handle_exception_record_access(bool pre, int sysnum, dr_mcontext_t *mc,
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

static bool handle_security_qos_access(bool pre, int sysnum, dr_mcontext_t *mc,
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

static bool handle_security_descriptor_access(bool pre, int sysnum, dr_mcontext_t *mc,
                                              uint arg_num,
                                              const syscall_arg_t *arg_info,
                                              app_pc start, uint size)
{
    uint check_type = SYSARG_CHECK_TYPE(arg_info->flags, pre);
    const SECURITY_DESCRIPTOR *s = (SECURITY_DESCRIPTOR *)start;
    SECURITY_DESCRIPTOR_CONTROL flags;
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
os_handle_pre_syscall_arg_access(int sysnum, dr_mcontext_t *mc, uint arg_num,
                                 const syscall_arg_t *arg_info,
                                 app_pc start, uint size)
{
    if (TEST(SYSARG_PORT_MESSAGE, arg_info->flags)) {
        return handle_port_message_access(true/*pre*/, sysnum, mc, arg_num,
                                          arg_info, start, size);
    }
    if (TEST(SYSARG_CONTEXT, arg_info->flags)) {
        return handle_context_access(true/*pre*/, sysnum, mc, arg_num,
                                     arg_info, start, size);
    }
    if (TEST(SYSARG_EXCEPTION_RECORD, arg_info->flags)) {
        return handle_exception_record_access(true/*pre*/, sysnum, mc, arg_num,
                                              arg_info, start, size);
    }
    if (TEST(SYSARG_SECURITY_QOS, arg_info->flags)) {
        return handle_security_qos_access(true/*pre*/, sysnum, mc, arg_num,
                                          arg_info, start, size);
    }
    if (TEST(SYSARG_SECURITY_DESCRIPTOR, arg_info->flags)) {
        return handle_security_descriptor_access(true/*pre*/, sysnum, mc, arg_num,
                                                 arg_info, start, size);
    }
    return false;
}

bool
os_handle_post_syscall_arg_access(int sysnum, dr_mcontext_t *mc, uint arg_num,
                                  const syscall_arg_t *arg_info,
                                  app_pc start, uint size)
{
    if (TEST(SYSARG_PORT_MESSAGE, arg_info->flags)) {
        return handle_port_message_access(false/*!pre*/, sysnum, mc, arg_num,
                                          arg_info, start, size);
    }
    if (TEST(SYSARG_CONTEXT, arg_info->flags)) {
        return handle_context_access(false/*!pre*/, sysnum, mc, arg_num,
                                     arg_info, start, size);
    }
    if (TEST(SYSARG_EXCEPTION_RECORD, arg_info->flags)) {
        return handle_exception_record_access(false/*!pre*/, sysnum, mc, arg_num,
                                              arg_info, start, size);
    }
    if (TEST(SYSARG_SECURITY_QOS, arg_info->flags)) {
        return handle_security_qos_access(false/*!pre*/, sysnum, mc, arg_num,
                                          arg_info, start, size);
    }
    if (TEST(SYSARG_SECURITY_DESCRIPTOR, arg_info->flags)) {
        return handle_security_descriptor_access(false/*!pre*/, sysnum, mc, arg_num,
                                                 arg_info, start, size);
    }
    return false;
}

