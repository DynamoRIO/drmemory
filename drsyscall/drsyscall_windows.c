/* **********************************************************
 * Copyright (c) 2011-2013 Google, Inc.  All rights reserved.
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
#include "drsyscall.h"
#include "drsyscall_os.h"
#include "drsyscall_windows.h"
#include <string.h> /* for strcmp */
#include <stddef.h> /* offsetof */

#include "../wininc/ndk_dbgktypes.h"
#include "../wininc/ndk_iotypes.h"
#include "../wininc/ndk_extypes.h"
#include "../wininc/ndk_psfuncs.h"
#include "../wininc/ndk_ketypes.h"
#include "../wininc/ndk_lpctypes.h"
#include "../wininc/ndk_mmtypes.h"
#include "../wininc/afd_shared.h"
#include "../wininc/msafdlib.h"
#include "../wininc/winioctl.h"
#include "../wininc/tcpioctl.h"
#include "../wininc/iptypes_undocumented.h"
#include "../wininc/ntalpctyp.h"
#include "../wininc/wdm.h"
#include "../wininc/ntifs.h"

static app_pc ntdll_base;
dr_os_version_info_t win_ver = {sizeof(win_ver),};

/***************************************************************************
 * WIN32K.SYS SYSTEM CALL NUMBERS
 */

/* For non-exported syscall wrappers we have tables of numbers */

#define NONE -1

#define IMM32 USER32
#define GDI32 USER32
#define KERNEL32 USER32

static const char * const sysnum_names[] = {
#define USER32(name, w7wow, w7x86, vistawow, vistax86, xpwow, w2003, xpx86, w2K)   #name,
#include "drsyscall_numx.h"
#undef USER32
};
#define NUM_SYSNUM_NAMES (sizeof(sysnum_names)/sizeof(sysnum_names[0]))

static const int win7wow_sysnums[] = {
#define USER32(n, w7wow, w7x86, vistawow, vistax86, xpwow, w2003, xpx86, w2K)   w7wow,
#include "drsyscall_numx.h"
#undef USER32
};

static const int win7x86_sysnums[] = {
#define USER32(n, w7wow, w7x86, vistawow, vistax86, xpwow, w2003, xpx86, w2K)   w7x86,
#include "drsyscall_numx.h"
#undef USER32
};

static const int vistawow_sysnums[] = {
#define USER32(n, w7wow, w7x86, vistawow, vistax86, xpwow, w2003, xpx86, w2K)   vistawow,
#include "drsyscall_numx.h"
#undef USER32
};

static const int vistax86_sysnums[] = {
#define USER32(n, w7wow, w7x86, vistawow, vistax86, xpwow, w2003, xpx86, w2K)   vistax86,
#include "drsyscall_numx.h"
#undef USER32
};

static const int winXPwow_sysnums[] = {
#define USER32(n, w7wow, w7x86, vistawow, vistax86, xpwow, w2003, xpx86, w2K)   xpwow,
#include "drsyscall_numx.h"
#undef USER32
};

static const int win2003_sysnums[] = {
#define USER32(n, w7wow, w7x86, vistawow, vistax86, xpwow, w2003, xpx86, w2K)   w2003,
#include "drsyscall_numx.h"
#undef USER32
};

static const int winXP_sysnums[] = {
#define USER32(n, w7wow, w7x86, vistawow, vistax86, xpwow, w2003, xpx86, w2K)   xpx86,
#include "drsyscall_numx.h"
#undef USER32
};

static const int win2K_sysnums[] = {
#define USER32(n, w7wow, w7x86, vistawow, vistax86, xpwow, w2003, xpx86, w2K)   w2K,
#include "drsyscall_numx.h"
#undef USER32
};

#undef IMM32
#undef GDI32
#undef KERNEL32

/***************************************************************************
 * NAME TO NUMBER
 */

/* Table that maps syscall names to numbers.  We need to store primary + secondary,
 * and we need to allocate the Zw forms, so we can't avoid a heap-allocated payload.
 */
#define NAME2NUM_TABLE_HASH_BITS 13 /* 1.5K of them, x2 for no-prefix entries + Zw */
static hashtable_t name2num_table;

typedef struct _name2num_entry_t {
    char *name;
    bool name_allocated;
    drsys_sysnum_t num;
} name2num_entry_t;

static void
name2num_entry_free(void *p)
{
    name2num_entry_t *e = (name2num_entry_t *) p;
    if (e->name_allocated)
        global_free(e->name, strlen(e->name) + 1/*null*/, HEAPSTAT_MISC);
    global_free(e, sizeof(*e), HEAPSTAT_MISC);
}

void
name2num_entry_add(const char *name, drsys_sysnum_t num, bool dup_Zw)
{
    name2num_entry_t *e = global_alloc(sizeof(*e), HEAPSTAT_MISC);
    bool ok;
    if (dup_Zw && name[0] == 'N' && name[1] == 't') {
        size_t len = strlen(name) + 1/*null*/;
        e->name = global_alloc(len, HEAPSTAT_MISC);
        dr_snprintf(e->name, len, "Zw%s", name + 2/*skip "Nt"*/);
        e->name[len - 1] = '\0';
        e->name_allocated = true;
    } else {
        e->name = (char *) name;
        e->name_allocated = false;
    }
    e->num = num;
    LOG(SYSCALL_VERBOSE + 1, "name2num: adding %s => "SYSNUM_FMT"."SYSNUM_FMT"\n",
        e->name, num.number, num.secondary);
    ok = hashtable_add(&name2num_table, (void *)e->name, (void *)e);
    if (!ok) {
        /* If we have any more of these, add a flag to drsyscall_numx.h */
        ASSERT(strcmp(e->name, "GetThreadDesktop") == 0/*i#487*/ ||
               strstr(e->name, "PREPAREFORLOGOFF") != NULL, /* NoParam vs OneParam */
               "no dup entries in name2num_table");
        name2num_entry_free((void *)e);
    }
}

/***************************************************************************
 * SYSTEM CALLS FOR WINDOWS
 */

/* We need a hashtable to map system call # to index in table, since syscall #s
 * vary by Windows version.
 */
#define SYSTABLE_HASH_BITS 12 /* has ntoskrnl and win32k.sys */
hashtable_t systable;

/* Syscalls that need special processing.  The address of each is kept
 * in the syscall_info_t entry so we don't need separate lookup.
 */
static drsys_sysnum_t sysnum_CreateThread = {-1,0};
static drsys_sysnum_t sysnum_CreateThreadEx = {-1,0};
static drsys_sysnum_t sysnum_CreateUserProcess = {-1,0};
static drsys_sysnum_t sysnum_DeviceIoControlFile = {-1,0};
static drsys_sysnum_t sysnum_QuerySystemInformation = {-1,0};
static drsys_sysnum_t sysnum_SetSystemInformation = {-1,0};

/* FIXME i#97: IIS syscalls!
 * FIXME i#98: fill in data on rest of Vista and Win7 syscalls!
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
 *       {0,"NtQuerySecurityObject", 5, 2,-3,W, 2,-4,WI, 4,sizeof(ULONG),W, },
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
#define HT (SYSARG_HAS_TYPE)
#define WI (SYSARG_WRITE | SYSARG_LENGTH_INOUT)
#define IO (SYSARG_POST_SIZE_IO_STATUS)
#define RET (SYSARG_POST_SIZE_RETVAL)
#define RNTST (DRSYS_TYPE_NTSTATUS) /* they all return NTSTATUS */

/* A non-SYSARG_INLINED type is by default DRSYS_TYPE_STRUCT, unless
 * a different type is specified with |HT.
 * So a truly unknown memory type must be explicitly marked DRSYS_TYPE_UNKNOWN.
 */
static syscall_info_t syscall_ntdll_info[] = {
    /***************************************************/
    /* Base set from Windows NT, Windows 2000, and Windows XP */
    {{0,0},"NtAcceptConnectPort", OK, RNTST, 6,
     {
         {0, sizeof(HANDLE), W|HT, DRSYS_TYPE_HANDLE},
         {1, sizeof(ULONG), SYSARG_INLINED, DRSYS_TYPE_UNSIGNED_INT},
         {2, sizeof(PORT_MESSAGE), R|CT, SYSARG_TYPE_PORT_MESSAGE},
         {3, sizeof(BOOLEAN), SYSARG_INLINED, DRSYS_TYPE_BOOL},
         {4, sizeof(PORT_VIEW), R|W},
         {5, sizeof(REMOTE_PORT_VIEW), R|W},
     }
    },
    {{0,0},"NtAccessCheck", OK, RNTST, 8,
     {
         {0, sizeof(SECURITY_DESCRIPTOR), R|CT, SYSARG_TYPE_SECURITY_DESCRIPTOR},
         {1, sizeof(HANDLE), SYSARG_INLINED, DRSYS_TYPE_HANDLE},
         {2, sizeof(ACCESS_MASK), SYSARG_INLINED, DRSYS_TYPE_UNSIGNED_INT},
         {3, sizeof(GENERIC_MAPPING), R},
         {4, sizeof(PRIVILEGE_SET), R},
         {5, sizeof(ULONG), R|HT, DRSYS_TYPE_UNSIGNED_INT},
         {6, sizeof(ACCESS_MASK), W|HT, DRSYS_TYPE_UNSIGNED_INT},
         {7, sizeof(BOOLEAN), W|HT, DRSYS_TYPE_BOOL},
     }
    },
    {{0,0},"NtAccessCheckAndAuditAlarm", OK, RNTST, 11,
     {
         {0, sizeof(UNICODE_STRING), R|CT, SYSARG_TYPE_UNICODE_STRING},
         {1, sizeof(PVOID), SYSARG_INLINED, DRSYS_TYPE_UNKNOWN},
         {2, sizeof(UNICODE_STRING), R|CT, SYSARG_TYPE_UNICODE_STRING},
         {3, sizeof(UNICODE_STRING), R|CT, SYSARG_TYPE_UNICODE_STRING},
         {4, sizeof(SECURITY_DESCRIPTOR), R|CT, SYSARG_TYPE_SECURITY_DESCRIPTOR},
         {5, sizeof(ACCESS_MASK), SYSARG_INLINED, DRSYS_TYPE_UNSIGNED_INT},
         {6, sizeof(GENERIC_MAPPING), R},
         {7, sizeof(BOOLEAN), SYSARG_INLINED, DRSYS_TYPE_BOOL},
         {8, sizeof(ACCESS_MASK), W|HT, DRSYS_TYPE_UNSIGNED_INT},
         {9, sizeof(BOOLEAN), W|HT, DRSYS_TYPE_BOOL},
         {10, sizeof(BOOLEAN), W|HT, DRSYS_TYPE_BOOL},
     }
    },
    {{0,0},"NtAccessCheckByType", OK, RNTST, 11,
     {
         {0, sizeof(SECURITY_DESCRIPTOR), R|CT, SYSARG_TYPE_SECURITY_DESCRIPTOR},
         {1, sizeof(SID), R},
         {2, sizeof(HANDLE), SYSARG_INLINED, DRSYS_TYPE_HANDLE},
         {3, sizeof(ULONG), SYSARG_INLINED, DRSYS_TYPE_UNSIGNED_INT},
         {4, sizeof(OBJECT_TYPE_LIST), R},
         {5, sizeof(ULONG), SYSARG_INLINED, DRSYS_TYPE_UNSIGNED_INT},
         {6, sizeof(GENERIC_MAPPING), R},
         {7, sizeof(PRIVILEGE_SET), R},
         {8, sizeof(ULONG), R|HT, DRSYS_TYPE_UNSIGNED_INT},
         {9, sizeof(ACCESS_MASK), W|HT, DRSYS_TYPE_UNSIGNED_INT},
         {10, sizeof(ULONG), W|HT, DRSYS_TYPE_UNSIGNED_INT},
     }
    },
    {{0,0},"NtAccessCheckByTypeAndAuditAlarm", OK, RNTST, 16,
     {
         {0, sizeof(UNICODE_STRING), R|CT, SYSARG_TYPE_UNICODE_STRING},
         {1, sizeof(PVOID), SYSARG_INLINED, DRSYS_TYPE_UNKNOWN},
         {2, sizeof(UNICODE_STRING), R|CT, SYSARG_TYPE_UNICODE_STRING},
         {3, sizeof(UNICODE_STRING), R|CT, SYSARG_TYPE_UNICODE_STRING},
         {4, sizeof(SECURITY_DESCRIPTOR), R|CT, SYSARG_TYPE_SECURITY_DESCRIPTOR},
         {5, sizeof(SID), R},
         {6, sizeof(ACCESS_MASK), SYSARG_INLINED, DRSYS_TYPE_UNSIGNED_INT},
         {7, sizeof(AUDIT_EVENT_TYPE), SYSARG_INLINED, DRSYS_TYPE_SIGNED_INT},
         {8, sizeof(ULONG), SYSARG_INLINED, DRSYS_TYPE_UNSIGNED_INT},
         {9, sizeof(OBJECT_TYPE_LIST), R},
         {10, sizeof(ULONG), SYSARG_INLINED, DRSYS_TYPE_UNSIGNED_INT},
         {11, sizeof(GENERIC_MAPPING), R},
         {12, sizeof(BOOLEAN), SYSARG_INLINED, DRSYS_TYPE_BOOL},
         {13, sizeof(ACCESS_MASK), W|HT, DRSYS_TYPE_UNSIGNED_INT},
         {14, sizeof(ULONG), W|HT, DRSYS_TYPE_UNSIGNED_INT},
         {15, sizeof(BOOLEAN), W|HT, DRSYS_TYPE_BOOL},
     }
    },
    {{0,0},"NtAccessCheckByTypeResultList", OK, RNTST, 11,
     {
         {0, sizeof(SECURITY_DESCRIPTOR), R|CT, SYSARG_TYPE_SECURITY_DESCRIPTOR},
         {1, sizeof(SID), R},
         {2, sizeof(HANDLE), SYSARG_INLINED, DRSYS_TYPE_HANDLE},
         {3, sizeof(ACCESS_MASK), SYSARG_INLINED, DRSYS_TYPE_UNSIGNED_INT},
         {4, sizeof(OBJECT_TYPE_LIST), R},
         {5, sizeof(ULONG), SYSARG_INLINED, DRSYS_TYPE_UNSIGNED_INT},
         {6, sizeof(GENERIC_MAPPING), R},
         {7, sizeof(PRIVILEGE_SET), R},
         {8, sizeof(ULONG), R|HT, DRSYS_TYPE_UNSIGNED_INT},
         {9, sizeof(ACCESS_MASK), W|HT, DRSYS_TYPE_UNSIGNED_INT},
         {10, sizeof(ULONG), W|HT, DRSYS_TYPE_UNSIGNED_INT},
     }
    },
    {{0,0},"NtAccessCheckByTypeResultListAndAuditAlarm", OK, RNTST, 16,
     {
         {0, sizeof(UNICODE_STRING), R|CT, SYSARG_TYPE_UNICODE_STRING},
         {1, sizeof(PVOID), SYSARG_INLINED, DRSYS_TYPE_UNKNOWN},
         {2, sizeof(UNICODE_STRING), R|CT, SYSARG_TYPE_UNICODE_STRING},
         {3, sizeof(UNICODE_STRING), R|CT, SYSARG_TYPE_UNICODE_STRING},
         {4, sizeof(SECURITY_DESCRIPTOR), R|CT, SYSARG_TYPE_SECURITY_DESCRIPTOR},
         {5, sizeof(SID), R},
         {6, sizeof(ACCESS_MASK), SYSARG_INLINED, DRSYS_TYPE_UNSIGNED_INT},
         {7, sizeof(AUDIT_EVENT_TYPE), SYSARG_INLINED, DRSYS_TYPE_SIGNED_INT},
         {8, sizeof(ULONG), SYSARG_INLINED, DRSYS_TYPE_UNSIGNED_INT},
         {9, sizeof(OBJECT_TYPE_LIST), R},
         {10, sizeof(ULONG), SYSARG_INLINED, DRSYS_TYPE_UNSIGNED_INT},
         {11, sizeof(GENERIC_MAPPING), R},
         {12, sizeof(BOOLEAN), SYSARG_INLINED, DRSYS_TYPE_BOOL},
         {13, sizeof(ACCESS_MASK), W|HT, DRSYS_TYPE_UNSIGNED_INT},
         {14, sizeof(ULONG), W|HT, DRSYS_TYPE_UNSIGNED_INT},
         {15, sizeof(ULONG), W|HT, DRSYS_TYPE_UNSIGNED_INT},
     }
    },
    {{0,0},"NtAccessCheckByTypeResultListAndAuditAlarmByHandle", OK, RNTST, 17,
     {
         {0, sizeof(UNICODE_STRING), R|CT, SYSARG_TYPE_UNICODE_STRING},
         {1, sizeof(PVOID), SYSARG_INLINED, DRSYS_TYPE_UNKNOWN},
         {2, sizeof(HANDLE), SYSARG_INLINED, DRSYS_TYPE_HANDLE},
         {3, sizeof(UNICODE_STRING), R|CT, SYSARG_TYPE_UNICODE_STRING},
         {4, sizeof(UNICODE_STRING), R|CT, SYSARG_TYPE_UNICODE_STRING},
         {5, sizeof(SECURITY_DESCRIPTOR), R|CT, SYSARG_TYPE_SECURITY_DESCRIPTOR},
         {6, sizeof(SID), R},
         {7, sizeof(ACCESS_MASK), SYSARG_INLINED, DRSYS_TYPE_UNSIGNED_INT},
         {8, sizeof(AUDIT_EVENT_TYPE), SYSARG_INLINED, DRSYS_TYPE_SIGNED_INT},
         {9, sizeof(ULONG), SYSARG_INLINED, DRSYS_TYPE_UNSIGNED_INT},
         {10, sizeof(OBJECT_TYPE_LIST), R},
         {11, sizeof(ULONG), SYSARG_INLINED, DRSYS_TYPE_UNSIGNED_INT},
         {12, sizeof(GENERIC_MAPPING), R},
         {13, sizeof(BOOLEAN), SYSARG_INLINED, DRSYS_TYPE_BOOL},
         {14, sizeof(ACCESS_MASK), W|HT, DRSYS_TYPE_UNSIGNED_INT},
         {15, sizeof(ULONG), W|HT, DRSYS_TYPE_UNSIGNED_INT},
         {16, sizeof(ULONG), W|HT, DRSYS_TYPE_UNSIGNED_INT},
     }
    },
    {{0,0},"NtAddAtom", OK, RNTST, 3,
     {
         {0, -1, R|HT, DRSYS_TYPE_CWSTRING},
         {1, sizeof(ULONG), SYSARG_INLINED, DRSYS_TYPE_UNSIGNED_INT},
         {2, sizeof(ATOM), W|HT, DRSYS_TYPE_ATOM},
     }
    },
    {{0,0},"NtAddBootEntry", OK, RNTST, 2,
     {
         {0, sizeof(UNICODE_STRING), R|CT, SYSARG_TYPE_UNICODE_STRING},
         {1, sizeof(UNICODE_STRING), R|CT, SYSARG_TYPE_UNICODE_STRING},
     }
    },
    {{0,0},"NtAddDriverEntry", OK, RNTST, 2,
     {
         {0, sizeof(UNICODE_STRING), R|CT, SYSARG_TYPE_UNICODE_STRING},
         {1, sizeof(UNICODE_STRING), R|CT, SYSARG_TYPE_UNICODE_STRING},
     }
    },
    {{0,0},"NtAdjustGroupsToken", OK, RNTST, 6,
     {
         {0, sizeof(HANDLE), SYSARG_INLINED, DRSYS_TYPE_HANDLE},
         {1, sizeof(BOOLEAN), SYSARG_INLINED, DRSYS_TYPE_BOOL},
         {2, sizeof(TOKEN_GROUPS), R},
         {3, sizeof(ULONG), SYSARG_INLINED, DRSYS_TYPE_UNSIGNED_INT},
         {4, -3, W},
         {4, -5, WI},
         {5, sizeof(ULONG), W|HT, DRSYS_TYPE_UNSIGNED_INT},
     }
    },
    {{0,0},"NtAdjustPrivilegesToken", OK, RNTST, 6,
     {
         {0, sizeof(HANDLE), SYSARG_INLINED, DRSYS_TYPE_HANDLE},
         {1, sizeof(BOOLEAN), SYSARG_INLINED, DRSYS_TYPE_BOOL},
         {2, sizeof(TOKEN_PRIVILEGES), R},
         {3, sizeof(ULONG), SYSARG_INLINED, DRSYS_TYPE_UNSIGNED_INT},
         {4, -3, W},
         {4, -5, WI},
         {5, sizeof(ULONG), W|HT, DRSYS_TYPE_UNSIGNED_INT},
     }
    },
    {{0,0},"NtAlertResumeThread", OK, RNTST, 2,
     {
         {0, sizeof(HANDLE), SYSARG_INLINED, DRSYS_TYPE_HANDLE},
         {1, sizeof(ULONG), W|HT, DRSYS_TYPE_UNSIGNED_INT},
     }
    },
    {{0,0},"NtAlertThread", OK, RNTST, 1,
     {
         {0, sizeof(HANDLE), SYSARG_INLINED, DRSYS_TYPE_HANDLE},
     }
    },
    {{0,0},"NtAllocateLocallyUniqueId", OK, RNTST, 1,
     {
         {0, sizeof(LUID), W},
     }
    },
    {{0,0},"NtAllocateUserPhysicalPages", OK, RNTST, 3,
     {
         {0, sizeof(HANDLE), SYSARG_INLINED, DRSYS_TYPE_HANDLE},
         {1, sizeof(ULONG), R|HT, DRSYS_TYPE_UNSIGNED_INT},
         {2, sizeof(ULONG), W|HT, DRSYS_TYPE_UNSIGNED_INT},
     }
    },
    {{0,0},"NtAllocateUuids", OK, RNTST, 4,
     {
         {0, sizeof(LARGE_INTEGER), W|HT, DRSYS_TYPE_LARGE_INTEGER},
         {1, sizeof(ULONG), W|HT, DRSYS_TYPE_UNSIGNED_INT},
         {2, sizeof(ULONG), W|HT, DRSYS_TYPE_UNSIGNED_INT},
         {3, sizeof(UCHAR), W|HT, DRSYS_TYPE_UNSIGNED_INT},
     }
    },
    {{0,0},"NtAllocateVirtualMemory", OK, RNTST, 6,
     {
         {0, sizeof(HANDLE), SYSARG_INLINED, DRSYS_TYPE_HANDLE},
         {1, sizeof(PVOID), R|W|HT, DRSYS_TYPE_POINTER},
         {2, sizeof(ULONG), SYSARG_INLINED, DRSYS_TYPE_UNSIGNED_INT},
         {3, sizeof(ULONG), R|W|HT, DRSYS_TYPE_UNSIGNED_INT},
         {4, sizeof(ULONG), SYSARG_INLINED, DRSYS_TYPE_UNSIGNED_INT},
         {5, sizeof(ULONG), SYSARG_INLINED, DRSYS_TYPE_UNSIGNED_INT},
     }
    },
    {{0,0},"NtApphelpCacheControl", OK, RNTST, 2,
     {
         {0, sizeof(APPHELPCACHESERVICECLASS), SYSARG_INLINED, DRSYS_TYPE_UNSIGNED_INT},
         {1, sizeof(UNICODE_STRING), R|CT, SYSARG_TYPE_UNICODE_STRING},
     }
    },
    {{0,0},"NtAreMappedFilesTheSame", OK, RNTST, 2,
     {
         {0, sizeof(PVOID), SYSARG_INLINED, DRSYS_TYPE_UNKNOWN},
         {1, sizeof(PVOID), SYSARG_INLINED, DRSYS_TYPE_UNKNOWN},
     }
    },
    {{0,0},"NtAssignProcessToJobObject", OK, RNTST, 2,
     {
         {0, sizeof(HANDLE), SYSARG_INLINED, DRSYS_TYPE_HANDLE},
         {1, sizeof(HANDLE), SYSARG_INLINED, DRSYS_TYPE_HANDLE},
     }
    },
    {{0,0},"NtCallbackReturn", OK, RNTST, 3,
     {
         {0, sizeof(PVOID), SYSARG_INLINED, DRSYS_TYPE_UNKNOWN},
         {1, sizeof(ULONG), SYSARG_INLINED, DRSYS_TYPE_UNSIGNED_INT},
         {2, sizeof(NTSTATUS), SYSARG_INLINED, DRSYS_TYPE_NTSTATUS},
     }
    },
    {{0,0},"NtCancelDeviceWakeupRequest", OK, RNTST, 1,
     {
         {0, sizeof(HANDLE), SYSARG_INLINED, DRSYS_TYPE_HANDLE},
     }
    },
    {{0,0},"NtCancelIoFile", OK, RNTST, 2,
     {
         {0, sizeof(HANDLE), SYSARG_INLINED, DRSYS_TYPE_HANDLE},
         {1, sizeof(IO_STATUS_BLOCK), W|HT, DRSYS_TYPE_IO_STATUS_BLOCK},
     }
    },
    {{0,0},"NtCancelTimer", OK, RNTST, 2,
     {
         {0, sizeof(HANDLE), SYSARG_INLINED, DRSYS_TYPE_HANDLE},
         {1, sizeof(BOOLEAN), W|HT, DRSYS_TYPE_BOOL},
     }
    },
    {{0,0},"NtClearEvent", OK, RNTST, 1,
     {
         {0, sizeof(HANDLE), SYSARG_INLINED, DRSYS_TYPE_HANDLE},
     }
    },
    {{0,0},"NtClose", OK, RNTST, 1,
     {
         {0, sizeof(HANDLE), SYSARG_INLINED, DRSYS_TYPE_HANDLE},
     }
    },
    {{0,0},"NtCloseObjectAuditAlarm", OK, RNTST, 3,
     {
         {0, sizeof(UNICODE_STRING), R|CT, SYSARG_TYPE_UNICODE_STRING},
         {1, sizeof(PVOID), SYSARG_INLINED, DRSYS_TYPE_UNKNOWN},
         {2, sizeof(BOOLEAN), SYSARG_INLINED, DRSYS_TYPE_BOOL},
     }
    },
    {{0,0},"NtCompactKeys", OK, RNTST, 2,
     {
         {0, sizeof(ULONG), SYSARG_INLINED, DRSYS_TYPE_UNSIGNED_INT},
         {1, sizeof(HANDLE), SYSARG_INLINED, DRSYS_TYPE_HANDLE},
     }
    },
    {{0,0},"NtCompareTokens", OK, RNTST, 3,
     {
         {0, sizeof(HANDLE), SYSARG_INLINED, DRSYS_TYPE_HANDLE},
         {1, sizeof(HANDLE), SYSARG_INLINED, DRSYS_TYPE_HANDLE},
         {2, sizeof(BOOLEAN), W|HT, DRSYS_TYPE_BOOL},
     }
    },
    {{0,0},"NtCompleteConnectPort", OK, RNTST, 1,
     {
         {0, sizeof(HANDLE), SYSARG_INLINED, DRSYS_TYPE_HANDLE},
     }
    },
    {{0,0},"NtCompressKey", OK, RNTST, 1,
     {
         {0, sizeof(HANDLE), SYSARG_INLINED, DRSYS_TYPE_HANDLE},
     }
    },
    /* Arg#4 is IN OUT for Nebbett, but not for Metasploit.
     * Arg#6 is of a user-defined format and since IN/OUT but w/ only one
     * capacity/size on IN can easily have capacity be larger than IN size:
     * xref i#494.  Be on the lookout for other false positives.
     */
    {{0,0},"NtConnectPort", OK, RNTST, 8,
     {
         {0, sizeof(HANDLE), W|HT, DRSYS_TYPE_HANDLE},
         {1, sizeof(UNICODE_STRING), R|CT, SYSARG_TYPE_UNICODE_STRING},
         {2, sizeof(SECURITY_QUALITY_OF_SERVICE), R|CT, SYSARG_TYPE_SECURITY_QOS},
         {3, sizeof(PORT_VIEW), R|W},
         {4, sizeof(REMOTE_PORT_VIEW), W},
         {5, sizeof(ULONG), W|HT, DRSYS_TYPE_UNSIGNED_INT},
         {6, -7, R|WI},
         {7, sizeof(ULONG), R|W|HT, DRSYS_TYPE_UNSIGNED_INT},
     }
    },
    {{0,0},"NtContinue", OK, RNTST, 2,
     {
         {0, sizeof(CONTEXT), R|CT, SYSARG_TYPE_CONTEXT},
         {1, sizeof(BOOLEAN), SYSARG_INLINED, DRSYS_TYPE_BOOL},
     }
    },
    {{0,0},"NtCreateChannel", OK, RNTST, 2,
     {
         {0, sizeof(HANDLE), W|HT, DRSYS_TYPE_HANDLE},
         {1, sizeof(OBJECT_ATTRIBUTES), R|CT, SYSARG_TYPE_OBJECT_ATTRIBUTES},
     }
    },
    {{0,0},"NtCreateDebugObject", OK, RNTST, 4,
     {
         {0, sizeof(HANDLE), W|HT, DRSYS_TYPE_HANDLE},
         {1, sizeof(ULONG), SYSARG_INLINED, DRSYS_TYPE_UNSIGNED_INT},
         {2, sizeof(OBJECT_ATTRIBUTES), R|CT, SYSARG_TYPE_OBJECT_ATTRIBUTES},
         {3, sizeof(BOOLEAN), SYSARG_INLINED, DRSYS_TYPE_BOOL},
     }
    },
    {{0,0},"NtCreateDirectoryObject", OK, RNTST, 3,
     {
         {0, sizeof(HANDLE), W|HT, DRSYS_TYPE_HANDLE},
         {1, sizeof(ACCESS_MASK), SYSARG_INLINED, DRSYS_TYPE_UNSIGNED_INT},
         {2, sizeof(OBJECT_ATTRIBUTES), R|CT, SYSARG_TYPE_OBJECT_ATTRIBUTES},
     }
    },
    {{0,0},"NtCreateEvent", OK, RNTST, 5,
     {
         {0, sizeof(HANDLE), W|HT, DRSYS_TYPE_HANDLE},
         {1, sizeof(ACCESS_MASK), SYSARG_INLINED, DRSYS_TYPE_UNSIGNED_INT},
         {2, sizeof(OBJECT_ATTRIBUTES), R|CT, SYSARG_TYPE_OBJECT_ATTRIBUTES},
         {3, sizeof(EVENT_TYPE), SYSARG_INLINED, DRSYS_TYPE_SIGNED_INT},
         {4, sizeof(BOOLEAN), SYSARG_INLINED, DRSYS_TYPE_BOOL},
     }
    },
    {{0,0},"NtCreateEventPair", OK, RNTST, 3,
     {
         {0, sizeof(HANDLE), W|HT, DRSYS_TYPE_HANDLE},
         {1, sizeof(ACCESS_MASK), SYSARG_INLINED, DRSYS_TYPE_UNSIGNED_INT},
         {2, sizeof(OBJECT_ATTRIBUTES), R|CT, SYSARG_TYPE_OBJECT_ATTRIBUTES},
     }
    },
    {{0,0},"NtCreateFile", OK, RNTST, 11,
     {
         {0, sizeof(HANDLE), W|HT, DRSYS_TYPE_HANDLE},
         {1, sizeof(ACCESS_MASK), SYSARG_INLINED, DRSYS_TYPE_UNSIGNED_INT},
         {2, sizeof(OBJECT_ATTRIBUTES), R|CT, SYSARG_TYPE_OBJECT_ATTRIBUTES},
         {3, sizeof(IO_STATUS_BLOCK), W|HT, DRSYS_TYPE_IO_STATUS_BLOCK},
         {4, sizeof(LARGE_INTEGER), R|HT, DRSYS_TYPE_LARGE_INTEGER},
         {5, sizeof(ULONG), SYSARG_INLINED, DRSYS_TYPE_UNSIGNED_INT},
         {6, sizeof(ULONG), SYSARG_INLINED, DRSYS_TYPE_UNSIGNED_INT},
         {7, sizeof(ULONG), SYSARG_INLINED, DRSYS_TYPE_UNSIGNED_INT},
         {8, sizeof(ULONG), SYSARG_INLINED, DRSYS_TYPE_UNSIGNED_INT},
         {9, -10, R},
         {10, sizeof(ULONG), SYSARG_INLINED, DRSYS_TYPE_UNSIGNED_INT},
     }
    },
    {{0,0},"NtCreateIoCompletion", OK, RNTST, 4,
     {
         {0, sizeof(HANDLE), W|HT, DRSYS_TYPE_HANDLE},
         {1, sizeof(ACCESS_MASK), SYSARG_INLINED, DRSYS_TYPE_UNSIGNED_INT},
         {2, sizeof(OBJECT_ATTRIBUTES), R|CT, SYSARG_TYPE_OBJECT_ATTRIBUTES},
         {3, sizeof(ULONG), SYSARG_INLINED, DRSYS_TYPE_UNSIGNED_INT},
     }
    },
    {{0,0},"NtCreateJobObject", OK, RNTST, 3,
     {
         {0, sizeof(HANDLE), W|HT, DRSYS_TYPE_HANDLE},
         {1, sizeof(ACCESS_MASK), SYSARG_INLINED, DRSYS_TYPE_UNSIGNED_INT},
         {2, sizeof(OBJECT_ATTRIBUTES), R|CT, SYSARG_TYPE_OBJECT_ATTRIBUTES},
     }
    },
    {{0,0},"NtCreateJobSet", OK, RNTST, 3,
     {
         {0, sizeof(ULONG), SYSARG_INLINED, DRSYS_TYPE_UNSIGNED_INT},
         {1, sizeof(JOB_SET_ARRAY), R},
         {2, sizeof(ULONG), SYSARG_INLINED, DRSYS_TYPE_UNSIGNED_INT},
     }
    },
    {{0,0},"NtCreateKey", OK, RNTST, 7,
     {
         {0, sizeof(HANDLE), W|HT, DRSYS_TYPE_HANDLE},
         {1, sizeof(ACCESS_MASK), SYSARG_INLINED, DRSYS_TYPE_UNSIGNED_INT},
         {2, sizeof(OBJECT_ATTRIBUTES), R|CT, SYSARG_TYPE_OBJECT_ATTRIBUTES},
         {3, sizeof(ULONG), SYSARG_INLINED, DRSYS_TYPE_UNSIGNED_INT},
         {4, sizeof(UNICODE_STRING), R|CT, SYSARG_TYPE_UNICODE_STRING},
         {5, sizeof(ULONG), SYSARG_INLINED, DRSYS_TYPE_UNSIGNED_INT},
         {6, sizeof(ULONG), W|HT, DRSYS_TYPE_UNSIGNED_INT},
     }
    },
    {{0,0},"NtCreateKeyedEvent", OK, RNTST, 4,
     {
         {0, sizeof(HANDLE), W|HT, DRSYS_TYPE_HANDLE},
         {1, sizeof(ACCESS_MASK), SYSARG_INLINED, DRSYS_TYPE_UNSIGNED_INT},
         {2, sizeof(OBJECT_ATTRIBUTES), R|CT, SYSARG_TYPE_OBJECT_ATTRIBUTES},
         {3, sizeof(ULONG), SYSARG_INLINED, DRSYS_TYPE_UNSIGNED_INT},
     }
    },
    {{0,0},"NtCreateMailslotFile", OK, RNTST, 8,
     {
         {0, sizeof(HANDLE), W|HT, DRSYS_TYPE_HANDLE},
         {1, sizeof(ACCESS_MASK), SYSARG_INLINED, DRSYS_TYPE_UNSIGNED_INT},
         {2, sizeof(OBJECT_ATTRIBUTES), R|CT, SYSARG_TYPE_OBJECT_ATTRIBUTES},
         {3, sizeof(IO_STATUS_BLOCK), W|HT, DRSYS_TYPE_IO_STATUS_BLOCK},
         {4, sizeof(ULONG), SYSARG_INLINED, DRSYS_TYPE_UNSIGNED_INT},
         {5, sizeof(ULONG), SYSARG_INLINED, DRSYS_TYPE_UNSIGNED_INT},
         {6, sizeof(ULONG), SYSARG_INLINED, DRSYS_TYPE_UNSIGNED_INT},
         {7, sizeof(LARGE_INTEGER), R|HT, DRSYS_TYPE_LARGE_INTEGER},
     }
    },
    {{0,0},"NtCreateMutant", OK, RNTST, 4,
     {
         {0, sizeof(HANDLE), W|HT, DRSYS_TYPE_HANDLE},
         {1, sizeof(ACCESS_MASK), SYSARG_INLINED, DRSYS_TYPE_UNSIGNED_INT},
         {2, sizeof(OBJECT_ATTRIBUTES), R|CT, SYSARG_TYPE_OBJECT_ATTRIBUTES},
         {3, sizeof(BOOLEAN), SYSARG_INLINED, DRSYS_TYPE_BOOL},
     }
    },
    {{0,0},"NtCreateNamedPipeFile", OK, RNTST, 14,
     {
         {0, sizeof(HANDLE), W|HT, DRSYS_TYPE_HANDLE},
         {1, sizeof(ACCESS_MASK), SYSARG_INLINED, DRSYS_TYPE_UNSIGNED_INT},
         {2, sizeof(OBJECT_ATTRIBUTES), R|CT, SYSARG_TYPE_OBJECT_ATTRIBUTES},
         {3, sizeof(IO_STATUS_BLOCK), W|HT, DRSYS_TYPE_IO_STATUS_BLOCK},
         {4, sizeof(ULONG), SYSARG_INLINED, DRSYS_TYPE_UNSIGNED_INT},
         {5, sizeof(ULONG), SYSARG_INLINED, DRSYS_TYPE_UNSIGNED_INT},
         {6, sizeof(ULONG), SYSARG_INLINED, DRSYS_TYPE_UNSIGNED_INT},
         {7, sizeof(BOOLEAN), SYSARG_INLINED, DRSYS_TYPE_BOOL},
         {8, sizeof(BOOLEAN), SYSARG_INLINED, DRSYS_TYPE_BOOL},
         {9, sizeof(BOOLEAN), SYSARG_INLINED, DRSYS_TYPE_BOOL},
         {10, sizeof(ULONG), SYSARG_INLINED, DRSYS_TYPE_UNSIGNED_INT},
         {11, sizeof(ULONG), SYSARG_INLINED, DRSYS_TYPE_UNSIGNED_INT},
         {12, sizeof(ULONG), SYSARG_INLINED, DRSYS_TYPE_UNSIGNED_INT},
         {13, sizeof(LARGE_INTEGER), R|HT, DRSYS_TYPE_LARGE_INTEGER},
     }
    },
    {{0,0},"NtCreatePagingFile", OK, RNTST, 4,
     {
         {0, sizeof(UNICODE_STRING), R|CT, SYSARG_TYPE_UNICODE_STRING},
         {1, sizeof(ULARGE_INTEGER), R|HT, DRSYS_TYPE_ULARGE_INTEGER},
         {2, sizeof(ULARGE_INTEGER), R|HT, DRSYS_TYPE_ULARGE_INTEGER},
         {3, sizeof(ULONG), SYSARG_INLINED, DRSYS_TYPE_UNSIGNED_INT},
     }
    },
    {{0,0},"NtCreatePort", OK, RNTST, 5,
     {
         {0, sizeof(HANDLE), W|HT, DRSYS_TYPE_HANDLE},
         {1, sizeof(OBJECT_ATTRIBUTES), R|CT, SYSARG_TYPE_OBJECT_ATTRIBUTES},
         {2, sizeof(ULONG), SYSARG_INLINED, DRSYS_TYPE_UNSIGNED_INT},
         {3, sizeof(ULONG), SYSARG_INLINED, DRSYS_TYPE_UNSIGNED_INT},
         {4, sizeof(ULONG), SYSARG_INLINED, DRSYS_TYPE_UNSIGNED_INT},
     }
    },
    {{0,0},"NtCreateProcess", OK, RNTST, 8,
     {
         {0, sizeof(HANDLE), W|HT, DRSYS_TYPE_HANDLE},
         {1, sizeof(ACCESS_MASK), SYSARG_INLINED, DRSYS_TYPE_UNSIGNED_INT},
         {2, sizeof(OBJECT_ATTRIBUTES), R|CT, SYSARG_TYPE_OBJECT_ATTRIBUTES},
         {3, sizeof(HANDLE), SYSARG_INLINED, DRSYS_TYPE_HANDLE},
         {4, sizeof(BOOLEAN), SYSARG_INLINED, DRSYS_TYPE_BOOL},
         {5, sizeof(HANDLE), SYSARG_INLINED, DRSYS_TYPE_HANDLE},
         {6, sizeof(HANDLE), SYSARG_INLINED, DRSYS_TYPE_HANDLE},
         {7, sizeof(HANDLE), SYSARG_INLINED, DRSYS_TYPE_HANDLE},
     }
    },
    {{0,0},"NtCreateProcessEx", OK, RNTST, 9,
     {
         {0, sizeof(HANDLE), W|HT, DRSYS_TYPE_HANDLE},
         {1, sizeof(ACCESS_MASK), SYSARG_INLINED, DRSYS_TYPE_UNSIGNED_INT},
         {2, sizeof(OBJECT_ATTRIBUTES), R|CT, SYSARG_TYPE_OBJECT_ATTRIBUTES},
         {3, sizeof(HANDLE), SYSARG_INLINED, DRSYS_TYPE_HANDLE},
         {4, sizeof(ULONG), SYSARG_INLINED, DRSYS_TYPE_UNSIGNED_INT},
         {5, sizeof(HANDLE), SYSARG_INLINED, DRSYS_TYPE_HANDLE},
         {6, sizeof(HANDLE), SYSARG_INLINED, DRSYS_TYPE_HANDLE},
         {7, sizeof(HANDLE), SYSARG_INLINED, DRSYS_TYPE_HANDLE},
         {8, sizeof(ULONG), SYSARG_INLINED, DRSYS_TYPE_UNSIGNED_INT},
     }
    },
    {{0,0},"NtCreateProfile", OK, RNTST, 9,
     {
         {0, sizeof(HANDLE), W|HT, DRSYS_TYPE_HANDLE},
         {1, sizeof(HANDLE), SYSARG_INLINED, DRSYS_TYPE_HANDLE},
         {2, sizeof(PVOID), SYSARG_INLINED, DRSYS_TYPE_UNKNOWN},
         {3, sizeof(ULONG), SYSARG_INLINED, DRSYS_TYPE_UNSIGNED_INT},
         {4, sizeof(ULONG), SYSARG_INLINED, DRSYS_TYPE_UNSIGNED_INT},
         {5, sizeof(ULONG), R|HT, DRSYS_TYPE_UNSIGNED_INT},
         {6, sizeof(ULONG), SYSARG_INLINED, DRSYS_TYPE_UNSIGNED_INT},
         {7, sizeof(KPROFILE_SOURCE), SYSARG_INLINED, DRSYS_TYPE_SIGNED_INT},
         {8, sizeof(ULONG), SYSARG_INLINED, DRSYS_TYPE_UNSIGNED_INT},
     }
    },
    {{0,0},"NtCreateSection", OK, RNTST, 7,
     {
         {0, sizeof(HANDLE), W|HT, DRSYS_TYPE_HANDLE},
         {1, sizeof(ACCESS_MASK), SYSARG_INLINED, DRSYS_TYPE_UNSIGNED_INT},
         {2, sizeof(OBJECT_ATTRIBUTES), R|CT, SYSARG_TYPE_OBJECT_ATTRIBUTES},
         {3, sizeof(LARGE_INTEGER), R|HT, DRSYS_TYPE_LARGE_INTEGER},
         {4, sizeof(ULONG), SYSARG_INLINED, DRSYS_TYPE_UNSIGNED_INT},
         {5, sizeof(ULONG), SYSARG_INLINED, DRSYS_TYPE_UNSIGNED_INT},
         {6, sizeof(HANDLE), SYSARG_INLINED, DRSYS_TYPE_HANDLE},
     }
    },
    {{0,0},"NtCreateSemaphore", OK, RNTST, 5,
     {
         {0, sizeof(HANDLE), W|HT, DRSYS_TYPE_HANDLE},
         {1, sizeof(ACCESS_MASK), SYSARG_INLINED, DRSYS_TYPE_UNSIGNED_INT},
         {2, sizeof(OBJECT_ATTRIBUTES), R|CT, SYSARG_TYPE_OBJECT_ATTRIBUTES},
         {3, sizeof(LONG), SYSARG_INLINED, DRSYS_TYPE_SIGNED_INT},
         {4, sizeof(LONG), SYSARG_INLINED, DRSYS_TYPE_SIGNED_INT},
     }
    },
    {{0,0},"NtCreateSymbolicLinkObject", OK, RNTST, 4,
     {
         {0, sizeof(HANDLE), W|HT, DRSYS_TYPE_HANDLE},
         {1, sizeof(ACCESS_MASK), SYSARG_INLINED, DRSYS_TYPE_UNSIGNED_INT},
         {2, sizeof(OBJECT_ATTRIBUTES), R|CT, SYSARG_TYPE_OBJECT_ATTRIBUTES},
         {3, sizeof(UNICODE_STRING), R|CT, SYSARG_TYPE_UNICODE_STRING},
     }
    },
    {{0,0},"NtCreateThread", OK, RNTST, 8,
     {
         {0, sizeof(HANDLE), W|HT, DRSYS_TYPE_HANDLE},
         {1, sizeof(ACCESS_MASK), SYSARG_INLINED, DRSYS_TYPE_UNSIGNED_INT},
         {2, sizeof(OBJECT_ATTRIBUTES), R|CT, SYSARG_TYPE_OBJECT_ATTRIBUTES},
         {3, sizeof(HANDLE), SYSARG_INLINED, DRSYS_TYPE_HANDLE},
         {4, sizeof(CLIENT_ID), W},
         {5, sizeof(CONTEXT), R|CT, SYSARG_TYPE_CONTEXT},
         {6, sizeof(USER_STACK), R},
         {7, sizeof(BOOLEAN), SYSARG_INLINED, DRSYS_TYPE_BOOL},
     }, &sysnum_CreateThread
    },
    {{0,0},"NtCreateThreadEx", OK, RNTST, 11,
     {
         {0, sizeof(HANDLE), W|HT, DRSYS_TYPE_HANDLE},
         {1, sizeof(ACCESS_MASK), SYSARG_INLINED, DRSYS_TYPE_UNSIGNED_INT},
         {2, sizeof(OBJECT_ATTRIBUTES), R|CT, SYSARG_TYPE_OBJECT_ATTRIBUTES},
         {3, sizeof(HANDLE), SYSARG_INLINED, DRSYS_TYPE_HANDLE},
         {4, sizeof(PTHREAD_START_ROUTINE), SYSARG_INLINED, DRSYS_TYPE_FUNCTION},
         {5, sizeof(PVOID), SYSARG_INLINED, DRSYS_TYPE_UNKNOWN},
         {6, sizeof(BOOLEAN), SYSARG_INLINED, DRSYS_TYPE_BOOL},
         {7, sizeof(ULONG), SYSARG_INLINED, DRSYS_TYPE_UNSIGNED_INT},
         {8, sizeof(ULONG), SYSARG_INLINED, DRSYS_TYPE_UNSIGNED_INT},
         {9, sizeof(ULONG), SYSARG_INLINED, DRSYS_TYPE_UNSIGNED_INT},
         /* 10 is handled manually */
     }, &sysnum_CreateThreadEx
    },
    {{0,0},"NtCreateTimer", OK, RNTST, 4,
     {
         {0, sizeof(HANDLE), W|HT, DRSYS_TYPE_HANDLE},
         {1, sizeof(ACCESS_MASK), SYSARG_INLINED, DRSYS_TYPE_UNSIGNED_INT},
         {2, sizeof(OBJECT_ATTRIBUTES), R|CT, SYSARG_TYPE_OBJECT_ATTRIBUTES},
         {3, sizeof(TIMER_TYPE), SYSARG_INLINED, DRSYS_TYPE_SIGNED_INT},
     }
    },
    {{0,0},"NtCreateToken", OK, RNTST, 13,
     {
         {0, sizeof(HANDLE), W|HT, DRSYS_TYPE_HANDLE},
         {1, sizeof(ACCESS_MASK), SYSARG_INLINED, DRSYS_TYPE_UNSIGNED_INT},
         {2, sizeof(OBJECT_ATTRIBUTES), R|CT, SYSARG_TYPE_OBJECT_ATTRIBUTES},
         {3, sizeof(TOKEN_TYPE), SYSARG_INLINED, DRSYS_TYPE_SIGNED_INT},
         {4, sizeof(LUID), R},
         {5, sizeof(LARGE_INTEGER), R|HT, DRSYS_TYPE_LARGE_INTEGER},
         {6, sizeof(TOKEN_USER), R},
         {7, sizeof(TOKEN_GROUPS), R},
         {8, sizeof(TOKEN_PRIVILEGES), R},
         {9, sizeof(TOKEN_OWNER), R},
         {10, sizeof(TOKEN_PRIMARY_GROUP), R},
         {11, sizeof(TOKEN_DEFAULT_DACL), R},
         {12, sizeof(TOKEN_SOURCE), R},
     }
    },
    {{0,0},"NtCreateUserProcess", OK, RNTST, 11,
     {
         {0, sizeof(HANDLE), W|HT, DRSYS_TYPE_HANDLE},
         {1, sizeof(HANDLE), W|HT, DRSYS_TYPE_HANDLE},
         {2, sizeof(ACCESS_MASK), SYSARG_INLINED, DRSYS_TYPE_UNSIGNED_INT},
         {3, sizeof(ACCESS_MASK), SYSARG_INLINED, DRSYS_TYPE_UNSIGNED_INT},
         {4, sizeof(OBJECT_ATTRIBUTES), R|CT, SYSARG_TYPE_OBJECT_ATTRIBUTES},
         {5, sizeof(OBJECT_ATTRIBUTES), R|CT, SYSARG_TYPE_OBJECT_ATTRIBUTES},
         {6, sizeof(ULONG), SYSARG_INLINED, DRSYS_TYPE_UNSIGNED_INT},
         {7, sizeof(BOOLEAN), SYSARG_INLINED, DRSYS_TYPE_BOOL},
         {8, sizeof(RTL_USER_PROCESS_PARAMETERS), R},
         /*XXX i#98: arg 9 is in/out but not completely known*/ 
         {10, sizeof(create_proc_thread_info_t), R/*rest handled manually*/, },
     }, &sysnum_CreateUserProcess
    },
    {{0,0},"NtCreateWaitablePort", OK, RNTST, 5,
     {
         {0, sizeof(HANDLE), W|HT, DRSYS_TYPE_HANDLE},
         {1, sizeof(OBJECT_ATTRIBUTES), R|CT, SYSARG_TYPE_OBJECT_ATTRIBUTES},
         {2, sizeof(ULONG), SYSARG_INLINED, DRSYS_TYPE_UNSIGNED_INT},
         {3, sizeof(ULONG), SYSARG_INLINED, DRSYS_TYPE_UNSIGNED_INT},
         {4, sizeof(ULONG), SYSARG_INLINED, DRSYS_TYPE_UNSIGNED_INT},
     }
    },
    {{0,0},"NtDebugActiveProcess", OK, RNTST, 2,
     {
         {0, sizeof(HANDLE), SYSARG_INLINED, DRSYS_TYPE_HANDLE},
         {1, sizeof(HANDLE), SYSARG_INLINED, DRSYS_TYPE_HANDLE},
     }
    },
    {{0,0},"NtDebugContinue", OK, RNTST, 3,
     {
         {0, sizeof(HANDLE), SYSARG_INLINED, DRSYS_TYPE_HANDLE},
         {1, sizeof(CLIENT_ID), R},
         {2, sizeof(NTSTATUS), SYSARG_INLINED, DRSYS_TYPE_NTSTATUS},
     }
    },
    {{0,0},"NtDelayExecution", OK, RNTST, 2,
     {
         {0, sizeof(BOOLEAN), SYSARG_INLINED, DRSYS_TYPE_BOOL},
         {1, sizeof(LARGE_INTEGER), R|HT, DRSYS_TYPE_LARGE_INTEGER},
     }
    },
    {{0,0},"NtDeleteAtom", OK, RNTST, 1,
     {
         {0, sizeof(ATOM), SYSARG_INLINED, DRSYS_TYPE_ATOM},
     }
    },
    {{0,0},"NtDeleteBootEntry", OK, RNTST, 2,
     {
         {0, sizeof(UNICODE_STRING), R|CT, SYSARG_TYPE_UNICODE_STRING},
         {1, sizeof(UNICODE_STRING), R|CT, SYSARG_TYPE_UNICODE_STRING},
     }
    },
    {{0,0},"NtDeleteDriverEntry", OK, RNTST, 2,
     {
         {0, sizeof(UNICODE_STRING), R|CT, SYSARG_TYPE_UNICODE_STRING},
         {1, sizeof(UNICODE_STRING), R|CT, SYSARG_TYPE_UNICODE_STRING},
     }
    },
    {{0,0},"NtDeleteFile", OK, RNTST, 1,
     {
         {0, sizeof(OBJECT_ATTRIBUTES), R|CT, SYSARG_TYPE_OBJECT_ATTRIBUTES},
     }
    },
    {{0,0},"NtDeleteKey", OK, RNTST, 1,
     {
         {0, sizeof(HANDLE), SYSARG_INLINED, DRSYS_TYPE_HANDLE},
     }
    },
    {{0,0},"NtDeleteObjectAuditAlarm", OK, RNTST, 3,
     {
         {0, sizeof(UNICODE_STRING), R|CT, SYSARG_TYPE_UNICODE_STRING},
         {1, sizeof(PVOID), SYSARG_INLINED, DRSYS_TYPE_UNKNOWN},
         {2, sizeof(BOOLEAN), SYSARG_INLINED, DRSYS_TYPE_BOOL},
     }
    },
    {{0,0},"NtDeleteValueKey", OK, RNTST, 2,
     {
         {0, sizeof(HANDLE), SYSARG_INLINED, DRSYS_TYPE_HANDLE},
         {1, sizeof(UNICODE_STRING), R|CT, SYSARG_TYPE_UNICODE_STRING},
     }
    },
    {{0,0},"NtDeviceIoControlFile", UNKNOWN/*to do param cmp for unknown ioctl codes*/, RNTST, 10,
     {
         {0, sizeof(HANDLE), SYSARG_INLINED, DRSYS_TYPE_HANDLE},
         {1, sizeof(HANDLE), SYSARG_INLINED, DRSYS_TYPE_HANDLE},
         {2, sizeof(PIO_APC_ROUTINE), SYSARG_INLINED, DRSYS_TYPE_FUNCTION},
         {3, sizeof(PVOID), SYSARG_INLINED, DRSYS_TYPE_UNKNOWN},
         {4, sizeof(IO_STATUS_BLOCK), W|HT, DRSYS_TYPE_IO_STATUS_BLOCK},
         {5, sizeof(ULONG), SYSARG_INLINED, DRSYS_TYPE_UNSIGNED_INT},
         /*param6 handled manually*/
         {7, sizeof(ULONG), SYSARG_INLINED, DRSYS_TYPE_UNSIGNED_INT},
         {8, -9, W},
         {9, sizeof(ULONG), SYSARG_INLINED, DRSYS_TYPE_UNSIGNED_INT},
     }, &sysnum_DeviceIoControlFile
    },
    {{0,0},"NtDisplayString", OK, RNTST, 1,
     {
         {0, sizeof(UNICODE_STRING), R|CT, SYSARG_TYPE_UNICODE_STRING},
     }
    },
    {{0,0},"NtDuplicateObject", OK, RNTST, 7,
     {
         {0, sizeof(HANDLE), SYSARG_INLINED, DRSYS_TYPE_HANDLE},
         {1, sizeof(HANDLE), SYSARG_INLINED, DRSYS_TYPE_HANDLE},
         {2, sizeof(HANDLE), SYSARG_INLINED, DRSYS_TYPE_HANDLE},
         {3, sizeof(HANDLE), W|HT, DRSYS_TYPE_HANDLE},
         {4, sizeof(ACCESS_MASK), SYSARG_INLINED, DRSYS_TYPE_UNSIGNED_INT},
         {5, sizeof(ULONG), SYSARG_INLINED, DRSYS_TYPE_UNSIGNED_INT},
         {6, sizeof(ULONG), SYSARG_INLINED, DRSYS_TYPE_UNSIGNED_INT},
     }
    },
    {{0,0},"NtDuplicateToken", OK, RNTST, 6,
     {
         {0, sizeof(HANDLE), SYSARG_INLINED, DRSYS_TYPE_HANDLE},
         {1, sizeof(ACCESS_MASK), SYSARG_INLINED, DRSYS_TYPE_UNSIGNED_INT},
         {2, sizeof(OBJECT_ATTRIBUTES), R|CT, SYSARG_TYPE_OBJECT_ATTRIBUTES},
         {3, sizeof(BOOLEAN), SYSARG_INLINED, DRSYS_TYPE_BOOL},
         {4, sizeof(TOKEN_TYPE), SYSARG_INLINED, DRSYS_TYPE_SIGNED_INT},
         {5, sizeof(HANDLE), W|HT, DRSYS_TYPE_HANDLE},
     }
    },
    {{0,0},"NtEnumerateBootEntries", OK, RNTST, 2,
     {
         {0, -1, WI},
         {1, sizeof(ULONG), R|W|HT, DRSYS_TYPE_UNSIGNED_INT},
     }
    },
    {{0,0},"NtEnumerateDriverEntries", OK, RNTST, 2,
     {
         {0, -1, WI},
         {1, sizeof(ULONG), R|W|HT, DRSYS_TYPE_UNSIGNED_INT},
     }
    },
    {{0,0},"NtEnumerateKey", OK, RNTST, 6,
     {
         {0, sizeof(HANDLE), SYSARG_INLINED, DRSYS_TYPE_HANDLE},
         {1, sizeof(ULONG), SYSARG_INLINED, DRSYS_TYPE_UNSIGNED_INT},
         {2, sizeof(KEY_INFORMATION_CLASS), SYSARG_INLINED, DRSYS_TYPE_SIGNED_INT},
         {3, -4, W},
         {3, -5, WI},
         {4, sizeof(ULONG), SYSARG_INLINED, DRSYS_TYPE_UNSIGNED_INT},
         {5, sizeof(ULONG), W|HT, DRSYS_TYPE_UNSIGNED_INT},
     }
    },
    {{0,0},"NtEnumerateSystemEnvironmentValuesEx", OK, RNTST, 3,
     {
         {0, sizeof(ULONG), SYSARG_INLINED, DRSYS_TYPE_UNSIGNED_INT},
         {1, -2, WI},
         {2, sizeof(ULONG), R|W|HT, DRSYS_TYPE_UNSIGNED_INT},
     }
    },
    {{0,0},"NtEnumerateValueKey", OK, RNTST, 6,
     {
         {0, sizeof(HANDLE), SYSARG_INLINED, DRSYS_TYPE_HANDLE},
         {1, sizeof(ULONG), SYSARG_INLINED, DRSYS_TYPE_UNSIGNED_INT},
         {2, sizeof(KEY_VALUE_INFORMATION_CLASS), SYSARG_INLINED, DRSYS_TYPE_SIGNED_INT},
         {3, -4, W},
         {3, -5, WI},
         {4, sizeof(ULONG), SYSARG_INLINED, DRSYS_TYPE_UNSIGNED_INT},
         {5, sizeof(ULONG), W|HT, DRSYS_TYPE_UNSIGNED_INT},
     }
    },
    {{0,0},"NtExtendSection", OK, RNTST, 2,
     {
         {0, sizeof(HANDLE), SYSARG_INLINED, DRSYS_TYPE_HANDLE},
         {1, sizeof(LARGE_INTEGER), R|HT, DRSYS_TYPE_LARGE_INTEGER},
     }
    },
    {{0,0},"NtFilterToken", OK, RNTST, 6,
     {
         {0, sizeof(HANDLE), SYSARG_INLINED, DRSYS_TYPE_HANDLE},
         {1, sizeof(ULONG), SYSARG_INLINED, DRSYS_TYPE_UNSIGNED_INT},
         {2, sizeof(TOKEN_GROUPS), R},
         {3, sizeof(TOKEN_PRIVILEGES), R},
         {4, sizeof(TOKEN_GROUPS), R},
         {5, sizeof(HANDLE), W|HT, DRSYS_TYPE_HANDLE},
     }
    },
    {{0,0},"NtFindAtom", OK, RNTST, 3,
     {
         {0, -1, R|HT, DRSYS_TYPE_CWSTRING},
         {1, sizeof(ULONG), SYSARG_INLINED, DRSYS_TYPE_UNSIGNED_INT},
         {2, sizeof(ATOM), W|HT, DRSYS_TYPE_ATOM},
     }
    },
    {{0,0},"NtFlushBuffersFile", OK, RNTST, 2,
     {
         {0, sizeof(HANDLE), SYSARG_INLINED, DRSYS_TYPE_HANDLE},
         {1, sizeof(IO_STATUS_BLOCK), W|HT, DRSYS_TYPE_IO_STATUS_BLOCK},
     }
    },
    {{0,0},"NtFlushInstructionCache", OK, RNTST, 3,
     {
         {0, sizeof(HANDLE), SYSARG_INLINED, DRSYS_TYPE_HANDLE},
         {1, sizeof(PVOID), SYSARG_INLINED, DRSYS_TYPE_UNKNOWN},
         {2, sizeof(ULONG), SYSARG_INLINED, DRSYS_TYPE_UNSIGNED_INT},
     }
    },
    {{0,0},"NtFlushKey", OK, RNTST, 1,
     {
         {0, sizeof(HANDLE), SYSARG_INLINED, DRSYS_TYPE_HANDLE},
     }
    },
    {{0,0},"NtFlushVirtualMemory", OK, RNTST, 4,
     {
         {0, sizeof(HANDLE), SYSARG_INLINED, DRSYS_TYPE_HANDLE},
         {1, sizeof(PVOID), R|W|HT, DRSYS_TYPE_POINTER},
         {2, sizeof(ULONG), R|W|HT, DRSYS_TYPE_UNSIGNED_INT},
         {3, sizeof(IO_STATUS_BLOCK), W|HT, DRSYS_TYPE_IO_STATUS_BLOCK},
     }
    },
    {{0,0},"NtFlushWriteBuffer", OK, RNTST, 0, },
    {{0,0},"NtFreeUserPhysicalPages", OK, RNTST, 3,
     {
         {0, sizeof(HANDLE), SYSARG_INLINED, DRSYS_TYPE_HANDLE},
         {1, sizeof(ULONG), R|W|HT, DRSYS_TYPE_UNSIGNED_INT},
         {2, sizeof(ULONG), R|HT, DRSYS_TYPE_UNSIGNED_INT},
     }
    },
    {{0,0},"NtFreeVirtualMemory", OK, RNTST, 4,
     {
         {0, sizeof(HANDLE), SYSARG_INLINED, DRSYS_TYPE_HANDLE},
         {1, sizeof(PVOID), R|W|HT, DRSYS_TYPE_POINTER},
         {2, sizeof(ULONG), R|W|HT, DRSYS_TYPE_UNSIGNED_INT},
         {3, sizeof(ULONG), SYSARG_INLINED, DRSYS_TYPE_UNSIGNED_INT},
     }
    },
    {{0,0},"NtFsControlFile", OK, RNTST, 10,
     {
         {0, sizeof(HANDLE), SYSARG_INLINED, DRSYS_TYPE_HANDLE},
         {1, sizeof(HANDLE), SYSARG_INLINED, DRSYS_TYPE_HANDLE},
         {2, sizeof(PIO_APC_ROUTINE), SYSARG_INLINED, DRSYS_TYPE_FUNCTION},
         {3, sizeof(PVOID), SYSARG_INLINED, DRSYS_TYPE_UNKNOWN},
         {4, sizeof(IO_STATUS_BLOCK), W|HT, DRSYS_TYPE_IO_STATUS_BLOCK},
         {5, sizeof(ULONG), SYSARG_INLINED, DRSYS_TYPE_UNSIGNED_INT},
         {6, -7, R},
         {7, sizeof(ULONG), SYSARG_INLINED, DRSYS_TYPE_UNSIGNED_INT},
         {8, -9, W},
         {9, sizeof(ULONG), SYSARG_INLINED, DRSYS_TYPE_UNSIGNED_INT},
     }
    },
    {{0,0},"NtGetContextThread", OK, RNTST, 2,
     {
         {0, sizeof(HANDLE), SYSARG_INLINED, DRSYS_TYPE_HANDLE},
         {1, sizeof(CONTEXT), W|CT, SYSARG_TYPE_CONTEXT},
     }
    },
    {{0,0},"NtGetCurrentProcessorNumber", OK, RNTST, 0, },
    {{0,0},"NtGetDevicePowerState", OK, RNTST, 2,
     {
         {0, sizeof(HANDLE), SYSARG_INLINED, DRSYS_TYPE_HANDLE},
         {1, sizeof(DEVICE_POWER_STATE), W|HT, DRSYS_TYPE_SIGNED_INT},
     }
    },
    {{0,0},"NtGetPlugPlayEvent", OK, RNTST, 4,
     {
         {0, sizeof(ULONG), SYSARG_INLINED, DRSYS_TYPE_UNSIGNED_INT},
         {1, sizeof(ULONG), SYSARG_INLINED, DRSYS_TYPE_UNSIGNED_INT},
         {2, -3, W},
         {3, sizeof(ULONG), SYSARG_INLINED, DRSYS_TYPE_UNSIGNED_INT},
     }
    },
    /* BufferEntries is #elements, not #bytes */
    {{0,0},"NtGetWriteWatch", OK, RNTST, 7,
     {
         {0, sizeof(HANDLE), SYSARG_INLINED, DRSYS_TYPE_HANDLE},
         {1, sizeof(ULONG), SYSARG_INLINED, DRSYS_TYPE_UNSIGNED_INT},
         {2, sizeof(PVOID), SYSARG_INLINED, DRSYS_TYPE_UNKNOWN},
         {3, sizeof(ULONG), SYSARG_INLINED, DRSYS_TYPE_UNSIGNED_INT},
         {4, -5, WI|SYSARG_SIZE_IN_ELEMENTS, sizeof(void*)},
         {5, sizeof(ULONG), R|W|HT, DRSYS_TYPE_UNSIGNED_INT},
         {6, sizeof(ULONG), W|HT, DRSYS_TYPE_UNSIGNED_INT},
     }
    },
    {{0,0},"NtImpersonateAnonymousToken", OK, RNTST, 1,
     {
         {0, sizeof(HANDLE), SYSARG_INLINED, DRSYS_TYPE_HANDLE},
     }
    },
    {{0,0},"NtImpersonateClientOfPort", OK, RNTST, 2,
     {
         {0, sizeof(HANDLE), SYSARG_INLINED, DRSYS_TYPE_HANDLE},
         {1, sizeof(PORT_MESSAGE), R|CT, SYSARG_TYPE_PORT_MESSAGE},
     }
    },
    {{0,0},"NtImpersonateThread", OK, RNTST, 3,
     {
         {0, sizeof(HANDLE), SYSARG_INLINED, DRSYS_TYPE_HANDLE},
         {1, sizeof(HANDLE), SYSARG_INLINED, DRSYS_TYPE_HANDLE},
         {2, sizeof(SECURITY_QUALITY_OF_SERVICE), R|CT, SYSARG_TYPE_SECURITY_QOS},
     }
    },
    {{0,0},"NtInitializeRegistry", OK, RNTST, 1,
     {
         {0, sizeof(BOOLEAN), SYSARG_INLINED, DRSYS_TYPE_BOOL},
     }
    },
    {{0,0},"NtInitiatePowerAction", OK, RNTST, 4,
     {
         {0, sizeof(POWER_ACTION), SYSARG_INLINED, DRSYS_TYPE_SIGNED_INT},
         {1, sizeof(SYSTEM_POWER_STATE), SYSARG_INLINED, DRSYS_TYPE_SIGNED_INT},
         {2, sizeof(ULONG), SYSARG_INLINED, DRSYS_TYPE_UNSIGNED_INT},
         {3, sizeof(BOOLEAN), SYSARG_INLINED, DRSYS_TYPE_BOOL},
     }
    },
    {{0,0},"NtIsProcessInJob", OK, RNTST, 2,
     {
         {0, sizeof(HANDLE), SYSARG_INLINED, DRSYS_TYPE_HANDLE},
         {1, sizeof(HANDLE), SYSARG_INLINED, DRSYS_TYPE_HANDLE},
     }
    },
    {{0,0},"NtIsSystemResumeAutomatic", OK, RNTST, 0, },
    {{0,0},"NtListenChannel", OK, RNTST, 2,
     {
         {0, sizeof(HANDLE), SYSARG_INLINED, DRSYS_TYPE_HANDLE},
         {1, sizeof(CHANNEL_MESSAGE), W},
     }
    },
    {{0,0},"NtListenPort", OK, RNTST, 2,
     {
         {0, sizeof(HANDLE), SYSARG_INLINED, DRSYS_TYPE_HANDLE},
         {1, sizeof(PORT_MESSAGE), W|CT, SYSARG_TYPE_PORT_MESSAGE},
     }
    },
    {{0,0},"NtLoadDriver", OK, RNTST, 1,
     {
         {0, sizeof(UNICODE_STRING), R|CT, SYSARG_TYPE_UNICODE_STRING},
     }
    },
    {{0,0},"NtLoadKey", OK, RNTST, 2,
     {
         {0, sizeof(OBJECT_ATTRIBUTES), R|CT, SYSARG_TYPE_OBJECT_ATTRIBUTES},
         {1, sizeof(OBJECT_ATTRIBUTES), R|CT, SYSARG_TYPE_OBJECT_ATTRIBUTES},
     }
    },
    {{0,0},"NtLoadKey2", OK, RNTST, 3,
     {
         {0, sizeof(OBJECT_ATTRIBUTES), R|CT, SYSARG_TYPE_OBJECT_ATTRIBUTES},
         {1, sizeof(OBJECT_ATTRIBUTES), R|CT, SYSARG_TYPE_OBJECT_ATTRIBUTES},
         {2, sizeof(ULONG), SYSARG_INLINED, DRSYS_TYPE_UNSIGNED_INT},
     }
    },
    {{0,0},"NtLoadKeyEx", OK, RNTST, 4,
     {
         {0, sizeof(OBJECT_ATTRIBUTES), R|CT, SYSARG_TYPE_OBJECT_ATTRIBUTES},
         {1, sizeof(OBJECT_ATTRIBUTES), R|CT, SYSARG_TYPE_OBJECT_ATTRIBUTES},
         {2, sizeof(ULONG), SYSARG_INLINED, DRSYS_TYPE_UNSIGNED_INT},
         {3, sizeof(HANDLE), SYSARG_INLINED, DRSYS_TYPE_HANDLE},
     }
    },
    {{0,0},"NtLockFile", OK, RNTST, 10,
     {
         {0, sizeof(HANDLE), SYSARG_INLINED, DRSYS_TYPE_HANDLE},
         {1, sizeof(HANDLE), SYSARG_INLINED, DRSYS_TYPE_HANDLE},
         {2, sizeof(PIO_APC_ROUTINE), SYSARG_INLINED, DRSYS_TYPE_FUNCTION},
         {3, sizeof(PVOID), SYSARG_INLINED, DRSYS_TYPE_UNKNOWN},
         {4, sizeof(IO_STATUS_BLOCK), W|HT, DRSYS_TYPE_IO_STATUS_BLOCK},
         {5, sizeof(ULARGE_INTEGER), R|HT, DRSYS_TYPE_ULARGE_INTEGER},
         {6, sizeof(ULARGE_INTEGER), R|HT, DRSYS_TYPE_ULARGE_INTEGER},
         {7, sizeof(ULONG), SYSARG_INLINED, DRSYS_TYPE_UNSIGNED_INT},
         {8, sizeof(BOOLEAN), SYSARG_INLINED, DRSYS_TYPE_BOOL},
         {9, sizeof(BOOLEAN), SYSARG_INLINED, DRSYS_TYPE_BOOL},
     }
    },
    {{0,0},"NtLockProductActivationKeys", OK, RNTST, 2,
     {
         {0, sizeof(ULONG), R|W|HT, DRSYS_TYPE_UNSIGNED_INT},
         {1, sizeof(ULONG), W|HT, DRSYS_TYPE_UNSIGNED_INT},
     }
    },
    {{0,0},"NtLockRegistryKey", OK, RNTST, 1,
     {
         {0, sizeof(HANDLE), SYSARG_INLINED, DRSYS_TYPE_HANDLE},
     }
    },
    {{0,0},"NtLockVirtualMemory", OK, RNTST, 4,
     {
         {0, sizeof(HANDLE), SYSARG_INLINED, DRSYS_TYPE_HANDLE},
         {1, sizeof(PVOID), R|W|HT, DRSYS_TYPE_POINTER},
         {2, sizeof(ULONG), R|W|HT, DRSYS_TYPE_UNSIGNED_INT},
         {3, sizeof(ULONG), SYSARG_INLINED, DRSYS_TYPE_UNSIGNED_INT},
     }
    },
    {{0,0},"NtMakePermanentObject", OK, RNTST, 1,
     {
         {0, sizeof(HANDLE), SYSARG_INLINED, DRSYS_TYPE_HANDLE},
     }
    },
    {{0,0},"NtMakeTemporaryObject", OK, RNTST, 1,
     {
         {0, sizeof(HANDLE), SYSARG_INLINED, DRSYS_TYPE_HANDLE},
     }
    },
    {{0,0},"NtMapCMFModule", OK, RNTST, 6,
     {
         /* XXX DRi#415 not all known */
         {4, sizeof(PVOID), W|HT, DRSYS_TYPE_POINTER},
         {5, sizeof(ULONG), W|HT, DRSYS_TYPE_UNSIGNED_INT},
     }
    },
    {{0,0},"NtMapUserPhysicalPages", OK, RNTST, 3,
     {
         {0, sizeof(PVOID), SYSARG_INLINED, DRSYS_TYPE_UNKNOWN},
         {1, sizeof(ULONG), R|HT, DRSYS_TYPE_UNSIGNED_INT},
         {2, sizeof(ULONG), R|HT, DRSYS_TYPE_UNSIGNED_INT},
     }
    },
    {{0,0},"NtMapUserPhysicalPagesScatter", OK, RNTST, 3,
     {
         {0, sizeof(PVOID), R|HT, DRSYS_TYPE_POINTER},
         {1, sizeof(ULONG), R|HT, DRSYS_TYPE_UNSIGNED_INT},
         {2, sizeof(ULONG), R|HT, DRSYS_TYPE_UNSIGNED_INT},
     }
    },
    {{0,0},"NtMapViewOfSection", OK, RNTST, 10,
     {
         {0, sizeof(HANDLE), SYSARG_INLINED, DRSYS_TYPE_HANDLE},
         {1, sizeof(HANDLE), SYSARG_INLINED, DRSYS_TYPE_HANDLE},
         {2, sizeof(PVOID), R|W|HT, DRSYS_TYPE_POINTER},
         {3, sizeof(ULONG), SYSARG_INLINED, DRSYS_TYPE_UNSIGNED_INT},
         {4, sizeof(ULONG), SYSARG_INLINED, DRSYS_TYPE_UNSIGNED_INT},
         {5, sizeof(LARGE_INTEGER), R|W|HT, DRSYS_TYPE_LARGE_INTEGER},
         {6, sizeof(ULONG), R|W|HT, DRSYS_TYPE_UNSIGNED_INT},
         {7, sizeof(SECTION_INHERIT), SYSARG_INLINED, DRSYS_TYPE_SIGNED_INT},
         {8, sizeof(ULONG), SYSARG_INLINED, DRSYS_TYPE_UNSIGNED_INT},
         {9, sizeof(ULONG), SYSARG_INLINED, DRSYS_TYPE_UNSIGNED_INT},
     }
    },
    {{0,0},"NtModifyBootEntry", OK, RNTST, 2,
     {
         {0, sizeof(UNICODE_STRING), R|CT, SYSARG_TYPE_UNICODE_STRING},
         {1, sizeof(UNICODE_STRING), R|CT, SYSARG_TYPE_UNICODE_STRING},
     }
    },
    {{0,0},"NtModifyDriverEntry", OK, RNTST, 2,
     {
         {0, sizeof(UNICODE_STRING), R|CT, SYSARG_TYPE_UNICODE_STRING},
         {1, sizeof(UNICODE_STRING), R|CT, SYSARG_TYPE_UNICODE_STRING},
     }
    },
    {{0,0},"NtNotifyChangeDirectoryFile", OK, RNTST, 9,
     {
         {0, sizeof(HANDLE), SYSARG_INLINED, DRSYS_TYPE_HANDLE},
         {1, sizeof(HANDLE), SYSARG_INLINED, DRSYS_TYPE_HANDLE},
         {2, sizeof(PIO_APC_ROUTINE), SYSARG_INLINED, DRSYS_TYPE_FUNCTION},
         {3, sizeof(PVOID), SYSARG_INLINED, DRSYS_TYPE_UNKNOWN},
         {4, sizeof(IO_STATUS_BLOCK), W|HT, DRSYS_TYPE_IO_STATUS_BLOCK},
         {5, sizeof(FILE_NOTIFY_INFORMATION), W},
         {6, sizeof(ULONG), SYSARG_INLINED, DRSYS_TYPE_UNSIGNED_INT},
         {7, sizeof(ULONG), SYSARG_INLINED, DRSYS_TYPE_UNSIGNED_INT},
         {8, sizeof(BOOLEAN), SYSARG_INLINED, DRSYS_TYPE_BOOL},
     }
    },
    {{0,0},"NtNotifyChangeKey", OK, RNTST, 10,
     {
         {0, sizeof(HANDLE), SYSARG_INLINED, DRSYS_TYPE_HANDLE},
         {1, sizeof(HANDLE), SYSARG_INLINED, DRSYS_TYPE_HANDLE},
         {2, sizeof(PIO_APC_ROUTINE), SYSARG_INLINED, DRSYS_TYPE_FUNCTION},
         {3, sizeof(PVOID), SYSARG_INLINED, DRSYS_TYPE_UNKNOWN},
         {4, sizeof(IO_STATUS_BLOCK), W|HT, DRSYS_TYPE_IO_STATUS_BLOCK},
         {5, sizeof(ULONG), SYSARG_INLINED, DRSYS_TYPE_UNSIGNED_INT},
         {6, sizeof(BOOLEAN), SYSARG_INLINED, DRSYS_TYPE_BOOL},
         {7, -8, R},
         {8, sizeof(ULONG), SYSARG_INLINED, DRSYS_TYPE_UNSIGNED_INT},
         {9, sizeof(BOOLEAN), SYSARG_INLINED, DRSYS_TYPE_BOOL},
     }
    },
    {{0,0},"NtNotifyChangeMultipleKeys", OK, RNTST, 12,
     {
         {0, sizeof(HANDLE), SYSARG_INLINED, DRSYS_TYPE_HANDLE},
         {1, sizeof(ULONG), SYSARG_INLINED, DRSYS_TYPE_UNSIGNED_INT},
         {2, sizeof(OBJECT_ATTRIBUTES), R|CT, SYSARG_TYPE_OBJECT_ATTRIBUTES},
         {3, sizeof(HANDLE), SYSARG_INLINED, DRSYS_TYPE_HANDLE},
         {4, sizeof(PIO_APC_ROUTINE), SYSARG_INLINED, DRSYS_TYPE_FUNCTION},
         {5, sizeof(PVOID), SYSARG_INLINED, DRSYS_TYPE_UNKNOWN},
         {6, sizeof(IO_STATUS_BLOCK), W|HT, DRSYS_TYPE_IO_STATUS_BLOCK},
         {7, sizeof(ULONG), SYSARG_INLINED, DRSYS_TYPE_UNSIGNED_INT},
         {8, sizeof(BOOLEAN), SYSARG_INLINED, DRSYS_TYPE_BOOL},
         {9, -10, R},
         {10, sizeof(ULONG), SYSARG_INLINED, DRSYS_TYPE_UNSIGNED_INT},
         {11, sizeof(BOOLEAN), SYSARG_INLINED, DRSYS_TYPE_BOOL},
     }
    },
    {{0,0},"NtOpenChannel", OK, RNTST, 2,
     {
         {0, sizeof(HANDLE), W|HT, DRSYS_TYPE_HANDLE},
         {1, sizeof(OBJECT_ATTRIBUTES), R|CT, SYSARG_TYPE_OBJECT_ATTRIBUTES},
     }
    },
    {{0,0},"NtOpenDirectoryObject", OK, RNTST, 3,
     {
         {0, sizeof(HANDLE), W|HT, DRSYS_TYPE_HANDLE},
         {1, sizeof(ACCESS_MASK), SYSARG_INLINED, DRSYS_TYPE_UNSIGNED_INT},
         {2, sizeof(OBJECT_ATTRIBUTES), R|CT, SYSARG_TYPE_OBJECT_ATTRIBUTES},
     }
    },
    {{0,0},"NtOpenEvent", OK, RNTST, 3,
     {
         {0, sizeof(HANDLE), W|HT, DRSYS_TYPE_HANDLE},
         {1, sizeof(ACCESS_MASK), SYSARG_INLINED, DRSYS_TYPE_UNSIGNED_INT},
         {2, sizeof(OBJECT_ATTRIBUTES), R|CT, SYSARG_TYPE_OBJECT_ATTRIBUTES},
     }
    },
    {{0,0},"NtOpenEventPair", OK, RNTST, 3,
     {
         {0, sizeof(HANDLE), W|HT, DRSYS_TYPE_HANDLE},
         {1, sizeof(ACCESS_MASK), SYSARG_INLINED, DRSYS_TYPE_UNSIGNED_INT},
         {2, sizeof(OBJECT_ATTRIBUTES), R|CT, SYSARG_TYPE_OBJECT_ATTRIBUTES},
     }
    },
    {{0,0},"NtOpenFile", OK, RNTST, 6,
     {
         {0, sizeof(HANDLE), W|HT, DRSYS_TYPE_HANDLE},
         {1, sizeof(ACCESS_MASK), SYSARG_INLINED, DRSYS_TYPE_UNSIGNED_INT},
         {2, sizeof(OBJECT_ATTRIBUTES), R|CT, SYSARG_TYPE_OBJECT_ATTRIBUTES},
         {3, sizeof(IO_STATUS_BLOCK), W|HT, DRSYS_TYPE_IO_STATUS_BLOCK},
         {4, sizeof(ULONG), SYSARG_INLINED, DRSYS_TYPE_UNSIGNED_INT},
         {5, sizeof(ULONG), SYSARG_INLINED, DRSYS_TYPE_UNSIGNED_INT},
     }
    },
    {{0,0},"NtOpenIoCompletion", OK, RNTST, 3,
     {
         {0, sizeof(HANDLE), W|HT, DRSYS_TYPE_HANDLE},
         {1, sizeof(ACCESS_MASK), SYSARG_INLINED, DRSYS_TYPE_UNSIGNED_INT},
         {2, sizeof(OBJECT_ATTRIBUTES), R|CT, SYSARG_TYPE_OBJECT_ATTRIBUTES},
     }
    },
    {{0,0},"NtOpenJobObject", OK, RNTST, 3,
     {
         {0, sizeof(HANDLE), W|HT, DRSYS_TYPE_HANDLE},
         {1, sizeof(ACCESS_MASK), SYSARG_INLINED, DRSYS_TYPE_UNSIGNED_INT},
         {2, sizeof(OBJECT_ATTRIBUTES), R|CT, SYSARG_TYPE_OBJECT_ATTRIBUTES},
     }
    },
    {{0,0},"NtOpenKey", OK, RNTST, 3,
     {
         {0, sizeof(HANDLE), W|HT, DRSYS_TYPE_HANDLE},
         {1, sizeof(ACCESS_MASK), SYSARG_INLINED, DRSYS_TYPE_UNSIGNED_INT},
         {2, sizeof(OBJECT_ATTRIBUTES), R|CT, SYSARG_TYPE_OBJECT_ATTRIBUTES},
     }
    },
    {{0,0},"NtOpenKeyEx", OK, RNTST, 4,
     {
         {0, sizeof(HANDLE), W|HT, DRSYS_TYPE_HANDLE},
         {1, sizeof(ACCESS_MASK), SYSARG_INLINED, DRSYS_TYPE_UNSIGNED_INT},
         {2, sizeof(OBJECT_ATTRIBUTES), R|CT, SYSARG_TYPE_OBJECT_ATTRIBUTES},
         {3, sizeof(ULONG), SYSARG_INLINED, DRSYS_TYPE_UNSIGNED_INT},
     }
    },
    {{0,0},"NtOpenKeyedEvent", OK, RNTST, 3,
     {
         {0, sizeof(HANDLE), W|HT, DRSYS_TYPE_HANDLE},
         {1, sizeof(ACCESS_MASK), SYSARG_INLINED, DRSYS_TYPE_UNSIGNED_INT},
         {2, sizeof(OBJECT_ATTRIBUTES), R|CT, SYSARG_TYPE_OBJECT_ATTRIBUTES},
     }
    },
    {{0,0},"NtOpenMutant", OK, RNTST, 3,
     {
         {0, sizeof(HANDLE), W|HT, DRSYS_TYPE_HANDLE},
         {1, sizeof(ACCESS_MASK), SYSARG_INLINED, DRSYS_TYPE_UNSIGNED_INT},
         {2, sizeof(OBJECT_ATTRIBUTES), R|CT, SYSARG_TYPE_OBJECT_ATTRIBUTES},
     }
    },
    {{0,0},"NtOpenObjectAuditAlarm", OK, RNTST, 12,
     {
         {0, sizeof(UNICODE_STRING), R|CT, SYSARG_TYPE_UNICODE_STRING},
         /* XXX: not a regular HANDLE?  ditto NtAccessCheck* */
         {1, sizeof(PVOID), R|HT, DRSYS_TYPE_UNKNOWN},
         {2, sizeof(UNICODE_STRING), R|CT, SYSARG_TYPE_UNICODE_STRING},
         {3, sizeof(UNICODE_STRING), R|CT, SYSARG_TYPE_UNICODE_STRING},
         {4, sizeof(SECURITY_DESCRIPTOR), R|CT, SYSARG_TYPE_SECURITY_DESCRIPTOR},
         {5, sizeof(HANDLE), SYSARG_INLINED, DRSYS_TYPE_HANDLE},
         {6, sizeof(ACCESS_MASK), SYSARG_INLINED, DRSYS_TYPE_UNSIGNED_INT},
         {7, sizeof(ACCESS_MASK), SYSARG_INLINED, DRSYS_TYPE_UNSIGNED_INT},
         {8, sizeof(PRIVILEGE_SET), R},
         {9, sizeof(BOOLEAN), SYSARG_INLINED, DRSYS_TYPE_BOOL},
         {10, sizeof(BOOLEAN), SYSARG_INLINED, DRSYS_TYPE_BOOL},
         {11, sizeof(BOOLEAN), W|HT, DRSYS_TYPE_BOOL},
     }
    },
    {{0,0},"NtOpenProcess", OK, RNTST, 4,
     {
         {0, sizeof(HANDLE), W|HT, DRSYS_TYPE_HANDLE},
         {1, sizeof(ACCESS_MASK), SYSARG_INLINED, DRSYS_TYPE_UNSIGNED_INT},
         {2, sizeof(OBJECT_ATTRIBUTES), R|CT, SYSARG_TYPE_OBJECT_ATTRIBUTES},
         {3, sizeof(CLIENT_ID), R},
     }
    },
    {{0,0},"NtOpenProcessToken", OK, RNTST, 3,
     {
         {0, sizeof(HANDLE), SYSARG_INLINED, DRSYS_TYPE_HANDLE},
         {1, sizeof(ACCESS_MASK), SYSARG_INLINED, DRSYS_TYPE_UNSIGNED_INT},
         {2, sizeof(HANDLE), W|HT, DRSYS_TYPE_HANDLE},
     }
    },
    {{0,0},"NtOpenProcessTokenEx", OK, RNTST, 4,
     {
         {0, sizeof(HANDLE), SYSARG_INLINED, DRSYS_TYPE_HANDLE},
         {1, sizeof(ACCESS_MASK), SYSARG_INLINED, DRSYS_TYPE_UNSIGNED_INT},
         {2, sizeof(ULONG), SYSARG_INLINED, DRSYS_TYPE_UNSIGNED_INT},
         {3, sizeof(HANDLE), W|HT, DRSYS_TYPE_HANDLE},
     }
    },
    {{0,0},"NtOpenSection", OK, RNTST, 3,
     {
         {0, sizeof(HANDLE), W|HT, DRSYS_TYPE_HANDLE},
         {1, sizeof(ACCESS_MASK), SYSARG_INLINED, DRSYS_TYPE_UNSIGNED_INT},
         {2, sizeof(OBJECT_ATTRIBUTES), R|CT, SYSARG_TYPE_OBJECT_ATTRIBUTES},
     }
    },
    {{0,0},"NtOpenSemaphore", OK, RNTST, 3,
     {
         {0, sizeof(HANDLE), W|HT, DRSYS_TYPE_HANDLE},
         {1, sizeof(ACCESS_MASK), SYSARG_INLINED, DRSYS_TYPE_UNSIGNED_INT},
         {2, sizeof(OBJECT_ATTRIBUTES), R|CT, SYSARG_TYPE_OBJECT_ATTRIBUTES},
     }
    },
    {{0,0},"NtOpenSymbolicLinkObject", OK, RNTST, 3,
     {
         {0, sizeof(HANDLE), W|HT, DRSYS_TYPE_HANDLE},
         {1, sizeof(ACCESS_MASK), SYSARG_INLINED, DRSYS_TYPE_UNSIGNED_INT},
         {2, sizeof(OBJECT_ATTRIBUTES), R|CT, SYSARG_TYPE_OBJECT_ATTRIBUTES},
     }
    },
    {{0,0},"NtOpenThread", OK, RNTST, 4,
     {
         {0, sizeof(HANDLE), W|HT, DRSYS_TYPE_HANDLE},
         {1, sizeof(ACCESS_MASK), SYSARG_INLINED, DRSYS_TYPE_UNSIGNED_INT},
         {2, sizeof(OBJECT_ATTRIBUTES), R|CT, SYSARG_TYPE_OBJECT_ATTRIBUTES},
         {3, sizeof(CLIENT_ID), R},
     }
    },
    {{0,0},"NtOpenThreadToken", OK, RNTST, 4,
     {
         {0, sizeof(HANDLE), SYSARG_INLINED, DRSYS_TYPE_HANDLE},
         {1, sizeof(ACCESS_MASK), SYSARG_INLINED, DRSYS_TYPE_UNSIGNED_INT},
         {2, sizeof(BOOLEAN), SYSARG_INLINED, DRSYS_TYPE_BOOL},
         {3, sizeof(HANDLE), W|HT, DRSYS_TYPE_HANDLE},
     }
    },
    {{0,0},"NtOpenThreadTokenEx", OK, RNTST, 5,
     {
         {0, sizeof(HANDLE), SYSARG_INLINED, DRSYS_TYPE_HANDLE},
         {1, sizeof(ACCESS_MASK), SYSARG_INLINED, DRSYS_TYPE_UNSIGNED_INT},
         {2, sizeof(BOOLEAN), SYSARG_INLINED, DRSYS_TYPE_BOOL},
         {3, sizeof(ULONG), SYSARG_INLINED, DRSYS_TYPE_UNSIGNED_INT},
         {4, sizeof(HANDLE), W|HT, DRSYS_TYPE_HANDLE},
     }
    },
    {{0,0},"NtOpenTimer", OK, RNTST, 3,
     {
         {0, sizeof(HANDLE), W|HT, DRSYS_TYPE_HANDLE},
         {1, sizeof(ACCESS_MASK), SYSARG_INLINED, DRSYS_TYPE_UNSIGNED_INT},
         {2, sizeof(OBJECT_ATTRIBUTES), R|CT, SYSARG_TYPE_OBJECT_ATTRIBUTES},
     }
    },
    {{0,0},"NtPlugPlayControl", OK, RNTST, 4,
     {
         {0, sizeof(ULONG), SYSARG_INLINED, DRSYS_TYPE_UNSIGNED_INT},
         {1, -2, W},
         {2, sizeof(ULONG), SYSARG_INLINED, DRSYS_TYPE_UNSIGNED_INT},
         {3, sizeof(PVOID), SYSARG_INLINED, DRSYS_TYPE_UNKNOWN},
     }
    },
    {{0,0},"NtPowerInformation", OK, RNTST, 5,
     {
         {0, sizeof(POWER_INFORMATION_LEVEL), SYSARG_INLINED, DRSYS_TYPE_SIGNED_INT},
         {1, -2, R},
         {2, sizeof(ULONG), SYSARG_INLINED, DRSYS_TYPE_UNSIGNED_INT},
         {3, -4, W},
         {4, sizeof(ULONG), SYSARG_INLINED, DRSYS_TYPE_UNSIGNED_INT},
     }
    },
    {{0,0},"NtPrivilegeCheck", OK, RNTST, 3,
     {
         {0, sizeof(HANDLE), SYSARG_INLINED, DRSYS_TYPE_HANDLE},
         {1, sizeof(PRIVILEGE_SET), R},
         {2, sizeof(BOOLEAN), W|HT, DRSYS_TYPE_BOOL},
     }
    },
    {{0,0},"NtPrivilegedServiceAuditAlarm", OK, RNTST, 5,
     {
         {0, sizeof(UNICODE_STRING), R|CT, SYSARG_TYPE_UNICODE_STRING},
         {1, sizeof(UNICODE_STRING), R|CT, SYSARG_TYPE_UNICODE_STRING},
         {2, sizeof(HANDLE), SYSARG_INLINED, DRSYS_TYPE_HANDLE},
         {3, sizeof(PRIVILEGE_SET), R},
         {4, sizeof(BOOLEAN), SYSARG_INLINED, DRSYS_TYPE_BOOL},
     }
    },
    {{0,0},"NtPrivilegeObjectAuditAlarm", OK, RNTST, 6,
     {
         {0, sizeof(UNICODE_STRING), R|CT, SYSARG_TYPE_UNICODE_STRING},
         {1, sizeof(PVOID), SYSARG_INLINED, DRSYS_TYPE_UNKNOWN},
         {2, sizeof(HANDLE), SYSARG_INLINED, DRSYS_TYPE_HANDLE},
         {3, sizeof(ACCESS_MASK), SYSARG_INLINED, DRSYS_TYPE_UNSIGNED_INT},
         {4, sizeof(PRIVILEGE_SET), R},
         {5, sizeof(BOOLEAN), SYSARG_INLINED, DRSYS_TYPE_BOOL},
     }
    },
    {{0,0},"NtProtectVirtualMemory", OK, RNTST, 5,
     {
         {0, sizeof(HANDLE), SYSARG_INLINED, DRSYS_TYPE_HANDLE},
         {1, sizeof(PVOID), R|W|HT, DRSYS_TYPE_POINTER},
         {2, sizeof(ULONG), R|W|HT, DRSYS_TYPE_UNSIGNED_INT},
         {3, sizeof(ULONG), SYSARG_INLINED, DRSYS_TYPE_UNSIGNED_INT},
         {4, sizeof(ULONG), W|HT, DRSYS_TYPE_UNSIGNED_INT},
     }
    },
    {{0,0},"NtPulseEvent", OK, RNTST, 2,
     {
         {0, sizeof(HANDLE), SYSARG_INLINED, DRSYS_TYPE_HANDLE},
         {1, sizeof(ULONG), W|HT, DRSYS_TYPE_UNSIGNED_INT},
     }
    },
    {{0,0},"NtQueryAttributesFile", OK, RNTST, 2,
     {
         {0, sizeof(OBJECT_ATTRIBUTES), R|CT, SYSARG_TYPE_OBJECT_ATTRIBUTES},
         {1, sizeof(FILE_BASIC_INFORMATION), W},
     }
    },
    {{0,0},"NtQueryBootEntryOrder", OK, RNTST, 2,
     {
         {0, -1, WI|SYSARG_SIZE_IN_ELEMENTS, sizeof(ULONG)},
         {1, sizeof(ULONG), R|W|HT, DRSYS_TYPE_UNSIGNED_INT},
     }
    },
    {{0,0},"NtQueryBootOptions", OK, RNTST, 2,
     {
         {0, -1, WI},
         {1, sizeof(ULONG), R|W|HT, DRSYS_TYPE_UNSIGNED_INT}
     }
    },
    {{0,0},"NtQueryDebugFilterState", OK, RNTST, 2,
     {
         {0, sizeof(ULONG), SYSARG_INLINED, DRSYS_TYPE_UNSIGNED_INT},
         {1, sizeof(ULONG), SYSARG_INLINED, DRSYS_TYPE_UNSIGNED_INT},
     }
    },
    {{0,0},"NtQueryDefaultLocale", OK, RNTST, 2,
     {
         {0, sizeof(BOOLEAN), SYSARG_INLINED, DRSYS_TYPE_BOOL},
         {1, sizeof(LCID), W|HT, DRSYS_TYPE_UNSIGNED_INT},
     }
    },
    {{0,0},"NtQueryDefaultUILanguage", OK, RNTST, 1,
     {
         {0, sizeof(LANGID), W|HT, DRSYS_TYPE_UNSIGNED_INT},
     }
    },
    {{0,0},"NtQueryDirectoryFile", OK, RNTST, 11,
     {
         {0, sizeof(HANDLE), SYSARG_INLINED, DRSYS_TYPE_HANDLE},
         {1, sizeof(HANDLE), SYSARG_INLINED, DRSYS_TYPE_HANDLE},
         {2, sizeof(PIO_APC_ROUTINE), SYSARG_INLINED, DRSYS_TYPE_FUNCTION},
         {3, sizeof(PVOID), SYSARG_INLINED, DRSYS_TYPE_UNKNOWN},
         {4, sizeof(IO_STATUS_BLOCK), W|HT, DRSYS_TYPE_IO_STATUS_BLOCK},
         {5, -6, W},
         {6, sizeof(ULONG), SYSARG_INLINED, DRSYS_TYPE_UNSIGNED_INT},
         {7, sizeof(FILE_INFORMATION_CLASS), SYSARG_INLINED, DRSYS_TYPE_SIGNED_INT},
         {8, sizeof(BOOLEAN), SYSARG_INLINED, DRSYS_TYPE_BOOL},
         {9, sizeof(UNICODE_STRING), R|CT, SYSARG_TYPE_UNICODE_STRING},
         {10, sizeof(BOOLEAN), SYSARG_INLINED, DRSYS_TYPE_BOOL},
     }
    },
    {{0,0},"NtQueryDirectoryObject", OK, RNTST, 7,
     {
         {0, sizeof(HANDLE), SYSARG_INLINED, DRSYS_TYPE_HANDLE},
         {1, -2, W},
         {1, -6, WI},
         {2, sizeof(ULONG), SYSARG_INLINED, DRSYS_TYPE_UNSIGNED_INT},
         {3, sizeof(BOOLEAN), SYSARG_INLINED, DRSYS_TYPE_BOOL},
         {4, sizeof(BOOLEAN), SYSARG_INLINED, DRSYS_TYPE_BOOL},
         {5, sizeof(ULONG), R|W|HT, DRSYS_TYPE_UNSIGNED_INT},
         {6, sizeof(ULONG), W|HT, DRSYS_TYPE_UNSIGNED_INT},
     }
    },
    {{0,0},"NtQueryDriverEntryOrder", OK, RNTST, 2,
     {
         {0, -1, WI|SYSARG_SIZE_IN_ELEMENTS, sizeof(ULONG)},
         {1, sizeof(ULONG), R|W|HT, DRSYS_TYPE_UNSIGNED_INT},
     }
    },
    {{0,0},"NtQueryEaFile", OK, RNTST, 9,
     {
         {0, sizeof(HANDLE), SYSARG_INLINED, DRSYS_TYPE_HANDLE},
         {1, sizeof(IO_STATUS_BLOCK), W|HT, DRSYS_TYPE_IO_STATUS_BLOCK},
         {2, sizeof(FILE_FULL_EA_INFORMATION), W},
         {3, sizeof(ULONG), SYSARG_INLINED, DRSYS_TYPE_UNSIGNED_INT},
         {4, sizeof(BOOLEAN), SYSARG_INLINED, DRSYS_TYPE_BOOL},
         {5, sizeof(FILE_GET_EA_INFORMATION), R},
         {6, sizeof(ULONG), SYSARG_INLINED, DRSYS_TYPE_UNSIGNED_INT},
         {7, sizeof(ULONG), R|HT, DRSYS_TYPE_UNSIGNED_INT},
         {8, sizeof(BOOLEAN), SYSARG_INLINED, DRSYS_TYPE_BOOL},
     }
    },
    {{0,0},"NtQueryEvent", OK|SYSINFO_RET_SMALL_WRITE_LAST, RNTST, 5,
     {
         {0, sizeof(HANDLE), SYSARG_INLINED, DRSYS_TYPE_HANDLE},
         {1, sizeof(EVENT_INFORMATION_CLASS), SYSARG_INLINED, DRSYS_TYPE_SIGNED_INT},
         {2, -3, W},
         {2, -4, WI},
         {3, sizeof(ULONG), SYSARG_INLINED, DRSYS_TYPE_UNSIGNED_INT},
         {4, sizeof(ULONG), W|HT, DRSYS_TYPE_UNSIGNED_INT},
     }
    },
    {{0,0},"NtQueryFullAttributesFile", OK, RNTST, 2,
     {
         {0, sizeof(OBJECT_ATTRIBUTES), R|CT, SYSARG_TYPE_OBJECT_ATTRIBUTES},
         {1, sizeof(FILE_NETWORK_OPEN_INFORMATION), W},
     }
    },
    {{0,0},"NtQueryInformationAtom", OK|SYSINFO_RET_SMALL_WRITE_LAST, RNTST, 5,
     {
         {0, sizeof(ATOM), SYSARG_INLINED, DRSYS_TYPE_ATOM},
         {1, sizeof(ATOM_INFORMATION_CLASS), SYSARG_INLINED, DRSYS_TYPE_SIGNED_INT},
         {2, -3, W},
         {2, -4, WI},
         {3, sizeof(ULONG), SYSARG_INLINED, DRSYS_TYPE_UNSIGNED_INT},
         {4, sizeof(ULONG), W|HT, DRSYS_TYPE_UNSIGNED_INT},
     }
    },
    {{0,0},"NtQueryInformationFile", OK, RNTST, 5,
     {
         {0, sizeof(HANDLE), SYSARG_INLINED, DRSYS_TYPE_HANDLE},
         {1, sizeof(IO_STATUS_BLOCK), W|HT, DRSYS_TYPE_IO_STATUS_BLOCK},
         {2, -3, W},
         {3, sizeof(ULONG), SYSARG_INLINED, DRSYS_TYPE_UNSIGNED_INT},
         {4, sizeof(FILE_INFORMATION_CLASS), SYSARG_INLINED, DRSYS_TYPE_SIGNED_INT},
     }
    },
    {{0,0},"NtQueryInformationJobObject", OK|SYSINFO_RET_SMALL_WRITE_LAST, RNTST, 5,
     {
         {0, sizeof(HANDLE), SYSARG_INLINED, DRSYS_TYPE_HANDLE},
         {1, sizeof(JOBOBJECTINFOCLASS), SYSARG_INLINED, DRSYS_TYPE_SIGNED_INT},
         {2, -3, W},
         {2, -4, WI},
         {3, sizeof(ULONG), SYSARG_INLINED, DRSYS_TYPE_UNSIGNED_INT},
         {4, sizeof(ULONG), W|HT, DRSYS_TYPE_UNSIGNED_INT},
     }
    },
    {{0,0},"NtQueryInformationPort", OK|SYSINFO_RET_SMALL_WRITE_LAST, RNTST, 5,
     {
         {0, sizeof(HANDLE), SYSARG_INLINED, DRSYS_TYPE_HANDLE},
         {1, sizeof(PORT_INFORMATION_CLASS), SYSARG_INLINED, DRSYS_TYPE_SIGNED_INT},
         {2, -3, W},
         {2, -4, WI},
         {3, sizeof(ULONG), SYSARG_INLINED, DRSYS_TYPE_UNSIGNED_INT},
         {4, sizeof(ULONG), W|HT, DRSYS_TYPE_UNSIGNED_INT},
     }
    },
    {{0,0},"NtQueryInformationProcess", OK|SYSINFO_RET_SMALL_WRITE_LAST, RNTST, 5,
     {
         {0, sizeof(HANDLE), SYSARG_INLINED, DRSYS_TYPE_HANDLE},
         {1, sizeof(PROCESSINFOCLASS), SYSARG_INLINED, DRSYS_TYPE_SIGNED_INT},
         {2, -3, W},
         {2, -4, WI},
         {3, sizeof(ULONG), SYSARG_INLINED, DRSYS_TYPE_UNSIGNED_INT},
         {4, sizeof(ULONG), W|HT, DRSYS_TYPE_UNSIGNED_INT},
     }
    },
    {{0,0},"NtQueryInformationThread", OK|SYSINFO_RET_SMALL_WRITE_LAST, RNTST, 5,
     {
         {0, sizeof(HANDLE), SYSARG_INLINED, DRSYS_TYPE_HANDLE},
         {1, sizeof(THREADINFOCLASS), SYSARG_INLINED, DRSYS_TYPE_SIGNED_INT},
         {2, -3, W},
         {2, -4, WI},
         {3, sizeof(ULONG), SYSARG_INLINED, DRSYS_TYPE_UNSIGNED_INT},
         {4, sizeof(ULONG), W|HT, DRSYS_TYPE_UNSIGNED_INT},
     }
    },
    {{0,0},"NtQueryInformationToken", OK|SYSINFO_RET_SMALL_WRITE_LAST, RNTST, 5,
     {
         {0, sizeof(HANDLE), SYSARG_INLINED, DRSYS_TYPE_HANDLE},
         {1, sizeof(TOKEN_INFORMATION_CLASS), SYSARG_INLINED, DRSYS_TYPE_SIGNED_INT},
         {2, -3, W},
         {2, -4, WI},
         {3, sizeof(ULONG), SYSARG_INLINED, DRSYS_TYPE_UNSIGNED_INT},
         {4, sizeof(ULONG), W|HT, DRSYS_TYPE_UNSIGNED_INT},
     }
    },
    {{0,0},"NtQueryInstallUILanguage", OK, RNTST, 1,
     {
         {0, sizeof(LANGID), W|HT, DRSYS_TYPE_UNSIGNED_INT},
     }
    },
    {{0,0},"NtQueryIntervalProfile", OK, RNTST, 2,
     {
         {0, sizeof(KPROFILE_SOURCE), SYSARG_INLINED, DRSYS_TYPE_SIGNED_INT},
         {1, sizeof(ULONG), W|HT, DRSYS_TYPE_UNSIGNED_INT},
     }
    },
    {{0,0},"NtQueryIoCompletion", OK|SYSINFO_RET_SMALL_WRITE_LAST, RNTST, 5,
     {
         {0, sizeof(HANDLE), SYSARG_INLINED, DRSYS_TYPE_HANDLE},
         {1, sizeof(IO_COMPLETION_INFORMATION_CLASS), SYSARG_INLINED, DRSYS_TYPE_SIGNED_INT},
         {2, -3, W},
         {2, -4, WI},
         {3, sizeof(ULONG), SYSARG_INLINED, DRSYS_TYPE_UNSIGNED_INT},
         {4, sizeof(ULONG), W|HT, DRSYS_TYPE_UNSIGNED_INT},
     }
    },
    {{0,0},"NtQueryKey", OK|SYSINFO_RET_SMALL_WRITE_LAST, RNTST, 5,
     {
         {0, sizeof(HANDLE), SYSARG_INLINED, DRSYS_TYPE_HANDLE},
         {1, sizeof(KEY_INFORMATION_CLASS), SYSARG_INLINED, DRSYS_TYPE_SIGNED_INT},
         {2, -3, W},
         {2, -4, WI},
         {3, sizeof(ULONG), SYSARG_INLINED, DRSYS_TYPE_UNSIGNED_INT},
         {4, sizeof(ULONG), W|HT, DRSYS_TYPE_UNSIGNED_INT},
     }
    },
    {{0,0},"NtQueryMultipleValueKey", OK, RNTST, 6,
     {
         {0, sizeof(HANDLE), SYSARG_INLINED, DRSYS_TYPE_HANDLE},
         {1, sizeof(KEY_VALUE_ENTRY), R|W},
         {2, sizeof(ULONG), SYSARG_INLINED, DRSYS_TYPE_UNSIGNED_INT},
         {3, -4, WI},
         {4, sizeof(ULONG), R|W|HT, DRSYS_TYPE_UNSIGNED_INT},
         {5, sizeof(ULONG), W|HT, DRSYS_TYPE_UNSIGNED_INT},
     }
    },
    {{0,0},"NtQueryMutant", OK|SYSINFO_RET_SMALL_WRITE_LAST, RNTST, 5,
     {
         {0, sizeof(HANDLE), SYSARG_INLINED, DRSYS_TYPE_HANDLE},
         {1, sizeof(MUTANT_INFORMATION_CLASS), SYSARG_INLINED, DRSYS_TYPE_SIGNED_INT},
         {2, -3, W},
         {2, -4, WI},
         {3, sizeof(ULONG), SYSARG_INLINED, DRSYS_TYPE_UNSIGNED_INT},
         {4, sizeof(ULONG), W|HT, DRSYS_TYPE_UNSIGNED_INT},
     }
    },
    {{0,0},"NtQueryObject", OK|SYSINFO_RET_SMALL_WRITE_LAST, RNTST, 5,
     {
         {0, sizeof(HANDLE), SYSARG_INLINED, DRSYS_TYPE_HANDLE},
         {1, sizeof(OBJECT_INFORMATION_CLASS), SYSARG_INLINED, DRSYS_TYPE_SIGNED_INT},
         {2, -3, W},
         {2, -4, WI},
         {3, sizeof(ULONG), SYSARG_INLINED, DRSYS_TYPE_UNSIGNED_INT},
         {4, sizeof(ULONG), W|HT, DRSYS_TYPE_UNSIGNED_INT},
     }
    },
    {{0,0},"NtQueryOleDirectoryFile", OK, RNTST, 11,
     {
         {0, sizeof(HANDLE), SYSARG_INLINED, DRSYS_TYPE_HANDLE},
         {1, sizeof(HANDLE), SYSARG_INLINED, DRSYS_TYPE_HANDLE},
         {2, sizeof(PIO_APC_ROUTINE), SYSARG_INLINED, DRSYS_TYPE_FUNCTION},
         {3, sizeof(PVOID), SYSARG_INLINED, DRSYS_TYPE_UNKNOWN},
         {4, sizeof(IO_STATUS_BLOCK), W|HT, DRSYS_TYPE_IO_STATUS_BLOCK},
         {5, -6, W},
         {6, sizeof(ULONG), SYSARG_INLINED, DRSYS_TYPE_UNSIGNED_INT},
         {7, sizeof(FILE_INFORMATION_CLASS), SYSARG_INLINED, DRSYS_TYPE_SIGNED_INT},
         {8, sizeof(BOOLEAN), SYSARG_INLINED, DRSYS_TYPE_BOOL},
         {9, sizeof(UNICODE_STRING), R|CT, SYSARG_TYPE_UNICODE_STRING},
         {10, sizeof(BOOLEAN), SYSARG_INLINED, DRSYS_TYPE_BOOL},
     }
    },
    {{0,0},"NtQueryOpenSubKeys", OK, RNTST, 2,
     {
         {0, sizeof(OBJECT_ATTRIBUTES), R|CT, SYSARG_TYPE_OBJECT_ATTRIBUTES},
         {1, sizeof(ULONG), W|HT, DRSYS_TYPE_UNSIGNED_INT},
     }
    },
    {{0,0},"NtQueryOpenSubKeysEx", OK, RNTST, 4,
     {
         {0, sizeof(OBJECT_ATTRIBUTES), R|CT, SYSARG_TYPE_OBJECT_ATTRIBUTES},
         {1, sizeof(ULONG), SYSARG_INLINED, DRSYS_TYPE_UNSIGNED_INT},
         {2, sizeof(ULONG), W|HT, DRSYS_TYPE_UNSIGNED_INT},
         {3, sizeof(ULONG), W|HT, DRSYS_TYPE_UNSIGNED_INT},
     }
    },
    {{0,0},"NtQueryPerformanceCounter", OK, RNTST, 2,
     {
         {0, sizeof(LARGE_INTEGER), W|HT, DRSYS_TYPE_LARGE_INTEGER},
         {1, sizeof(LARGE_INTEGER), W|HT, DRSYS_TYPE_LARGE_INTEGER},
     }
    },
    {{0,0},"NtQueryPortInformationProcess", OK, RNTST, 0, },
    {{0,0},"NtQueryQuotaInformationFile", OK, RNTST, 9,
     {
         {0, sizeof(HANDLE), SYSARG_INLINED, DRSYS_TYPE_HANDLE},
         {1, sizeof(IO_STATUS_BLOCK), W|HT, DRSYS_TYPE_IO_STATUS_BLOCK},
         {2, sizeof(FILE_USER_QUOTA_INFORMATION), W},
         {3, sizeof(ULONG), SYSARG_INLINED, DRSYS_TYPE_UNSIGNED_INT},
         {4, sizeof(BOOLEAN), SYSARG_INLINED, DRSYS_TYPE_BOOL},
         {5, sizeof(FILE_QUOTA_LIST_INFORMATION), R},
         {6, sizeof(ULONG), SYSARG_INLINED, DRSYS_TYPE_UNSIGNED_INT},
         {7, sizeof(SID), R},
         {8, sizeof(BOOLEAN), SYSARG_INLINED, DRSYS_TYPE_BOOL},
     }
    },
    {{0,0},"NtQuerySection", OK|SYSINFO_RET_SMALL_WRITE_LAST, RNTST, 5,
     {
         {0, sizeof(HANDLE), SYSARG_INLINED, DRSYS_TYPE_HANDLE},
         {1, sizeof(SECTION_INFORMATION_CLASS), SYSARG_INLINED, DRSYS_TYPE_SIGNED_INT},
         {2, -3, W},
         {2, -4, WI},
         {3, sizeof(ULONG), SYSARG_INLINED, DRSYS_TYPE_UNSIGNED_INT},
         {4, sizeof(ULONG), W|HT, DRSYS_TYPE_UNSIGNED_INT},
     }
    },
    {{0,0},"NtQuerySecurityObject", OK|SYSINFO_RET_SMALL_WRITE_LAST, RNTST, 5,
     {
         {0, sizeof(HANDLE), SYSARG_INLINED, DRSYS_TYPE_HANDLE},
         {1, sizeof(SECURITY_INFORMATION), SYSARG_INLINED, DRSYS_TYPE_UNSIGNED_INT},
         {2, -3, W},
         {2, -4, WI},
         {3, sizeof(ULONG), SYSARG_INLINED, DRSYS_TYPE_UNSIGNED_INT},
         {4, sizeof(ULONG), W|HT, DRSYS_TYPE_UNSIGNED_INT},
     }
    },
    {{0,0},"NtQuerySemaphore", OK|SYSINFO_RET_SMALL_WRITE_LAST, RNTST, 5,
     {
         {0, sizeof(HANDLE), SYSARG_INLINED, DRSYS_TYPE_HANDLE},
         {1, sizeof(SEMAPHORE_INFORMATION_CLASS), SYSARG_INLINED, DRSYS_TYPE_SIGNED_INT},
         {2, -3, W},
         {2, -4, WI},
         {3, sizeof(ULONG), SYSARG_INLINED, DRSYS_TYPE_UNSIGNED_INT},
         {4, sizeof(ULONG), W|HT, DRSYS_TYPE_UNSIGNED_INT},
     }
    },
    /* No double entry for 3rd param needed b/c the written size is in
     * .Length of the UNICODE_STRING as well as returned in the param:
     */
    {{0,0},"NtQuerySymbolicLinkObject", OK, RNTST, 3,
     {
         {0, sizeof(HANDLE), SYSARG_INLINED, DRSYS_TYPE_HANDLE},
         {1, sizeof(UNICODE_STRING), W|CT, SYSARG_TYPE_UNICODE_STRING},
         {2, sizeof(ULONG), W|HT, DRSYS_TYPE_UNSIGNED_INT},
     }
    },
    {{0,0},"NtQuerySystemEnvironmentValue", OK|SYSINFO_RET_SMALL_WRITE_LAST, RNTST, 4,
     {
         {0, sizeof(UNICODE_STRING), R|CT, SYSARG_TYPE_UNICODE_STRING},
         {1, -2, W},
         {1, -3, WI},
         {2, sizeof(ULONG), SYSARG_INLINED, DRSYS_TYPE_UNSIGNED_INT},
         {3, sizeof(ULONG), W|HT, DRSYS_TYPE_UNSIGNED_INT},
     }
    },
    {{0,0},"NtQuerySystemEnvironmentValueEx", OK, RNTST, 5,
     {
         {0, sizeof(UNICODE_STRING), R|CT, SYSARG_TYPE_UNICODE_STRING},
         {1, sizeof(GUID), R},
         {2, -3, WI},
         {3, sizeof(ULONG), R|W|HT, DRSYS_TYPE_UNSIGNED_INT},
         {4, sizeof(ULONG), W|HT, DRSYS_TYPE_UNSIGNED_INT},
     }
    },
    /* One info class reads data, which is special-cased */
    {{0,0},"NtQuerySystemInformation", OK|SYSINFO_RET_SMALL_WRITE_LAST, RNTST, 4,
     {
         {0, sizeof(SYSTEM_INFORMATION_CLASS), SYSARG_INLINED, DRSYS_TYPE_SIGNED_INT},
         {1, -2, W},
         {1, -3, WI},
         {2, sizeof(ULONG), SYSARG_INLINED, DRSYS_TYPE_UNSIGNED_INT},
         {3, sizeof(ULONG), W|HT, DRSYS_TYPE_UNSIGNED_INT},
     }, &sysnum_QuerySystemInformation
    },
    {{0,0},"NtQuerySystemTime", OK, RNTST, 1,
     {
         {0, sizeof(LARGE_INTEGER), W|HT, DRSYS_TYPE_LARGE_INTEGER},
     }
    },
    {{0,0},"NtQueryTimer", OK|SYSINFO_RET_SMALL_WRITE_LAST, RNTST, 5,
     {
         {0, sizeof(HANDLE), SYSARG_INLINED, DRSYS_TYPE_HANDLE},
         {1, sizeof(TIMER_INFORMATION_CLASS), SYSARG_INLINED, DRSYS_TYPE_SIGNED_INT},
         {2, -3, W},
         {2, -4, WI},
         {3, sizeof(ULONG), SYSARG_INLINED, DRSYS_TYPE_UNSIGNED_INT},
         {4, sizeof(ULONG), W|HT, DRSYS_TYPE_UNSIGNED_INT},
     }
    },
    {{0,0},"NtQueryTimerResolution", OK, RNTST, 3,
     {
         {0, sizeof(ULONG), W|HT, DRSYS_TYPE_UNSIGNED_INT},
         {1, sizeof(ULONG), W|HT, DRSYS_TYPE_UNSIGNED_INT},
         {2, sizeof(ULONG), W|HT, DRSYS_TYPE_UNSIGNED_INT},
     }
    },
    {{0,0},"NtQueryValueKey", OK, RNTST, 6,
     {
         {0, sizeof(HANDLE), SYSARG_INLINED, DRSYS_TYPE_HANDLE},
         {1, sizeof(UNICODE_STRING), R|CT, SYSARG_TYPE_UNICODE_STRING},
         {2, sizeof(KEY_VALUE_INFORMATION_CLASS), SYSARG_INLINED, DRSYS_TYPE_SIGNED_INT},
         {3, -4, W},
         {3, -5, WI},
         {4, sizeof(ULONG), SYSARG_INLINED, DRSYS_TYPE_UNSIGNED_INT},
         {5, sizeof(ULONG), W|HT, DRSYS_TYPE_UNSIGNED_INT},
     }
    },
    {{0,0},"NtQueryVirtualMemory", OK, RNTST, 6,
     {
         {0, sizeof(HANDLE), SYSARG_INLINED, DRSYS_TYPE_HANDLE},
         {1, sizeof(PVOID), SYSARG_INLINED, DRSYS_TYPE_UNKNOWN},
         {2, sizeof(MEMORY_INFORMATION_CLASS), SYSARG_INLINED, DRSYS_TYPE_SIGNED_INT},
         {3, -4, W},
         {3, -5, WI},
         {4, sizeof(ULONG), SYSARG_INLINED, DRSYS_TYPE_UNSIGNED_INT},
         {5, sizeof(ULONG), W|HT, DRSYS_TYPE_UNSIGNED_INT},
     }
    },
    {{0,0},"NtQueryVolumeInformationFile", OK, RNTST, 5,
     {
         {0, sizeof(HANDLE), SYSARG_INLINED, DRSYS_TYPE_HANDLE},
         {1, sizeof(IO_STATUS_BLOCK), W|HT, DRSYS_TYPE_IO_STATUS_BLOCK},
         {2, -3, W},
         {3, sizeof(ULONG), SYSARG_INLINED, DRSYS_TYPE_UNSIGNED_INT},
         {4, sizeof(FS_INFORMATION_CLASS), SYSARG_INLINED, DRSYS_TYPE_SIGNED_INT},
     }
    },
    {{0,0},"NtQueueApcThread", OK, RNTST, 5,
     {
         {0, sizeof(HANDLE), SYSARG_INLINED, DRSYS_TYPE_HANDLE},
         {1, sizeof(PKNORMAL_ROUTINE), SYSARG_INLINED, DRSYS_TYPE_FUNCTION},
         {2, sizeof(PVOID), SYSARG_INLINED, DRSYS_TYPE_UNKNOWN},
         {3, sizeof(PVOID), SYSARG_INLINED, DRSYS_TYPE_UNKNOWN},
         {4, sizeof(PVOID), SYSARG_INLINED, DRSYS_TYPE_UNKNOWN},
     }
    },
    {{0,0},"NtRaiseException", OK, RNTST, 3,
     {
         {0, sizeof(EXCEPTION_RECORD), R|CT, SYSARG_TYPE_EXCEPTION_RECORD},
         {1, sizeof(CONTEXT), R|CT, SYSARG_TYPE_CONTEXT},
         {2, sizeof(BOOLEAN), SYSARG_INLINED, DRSYS_TYPE_BOOL},
     }
    },
    {{0,0},"NtRaiseHardError", OK, RNTST, 6,
     {
         {0, sizeof(NTSTATUS), SYSARG_INLINED, DRSYS_TYPE_NTSTATUS},
         {1, sizeof(ULONG), SYSARG_INLINED, DRSYS_TYPE_UNSIGNED_INT},
         {2, sizeof(ULONG), SYSARG_INLINED, DRSYS_TYPE_UNSIGNED_INT},
         {3, sizeof(ULONG_PTR), R|HT, DRSYS_TYPE_UNSIGNED_INT},
         {4, sizeof(ULONG), SYSARG_INLINED, DRSYS_TYPE_UNSIGNED_INT},
         {5, sizeof(ULONG), W|HT, DRSYS_TYPE_UNSIGNED_INT},
     }
    },
    {{0,0},"NtReadFile", OK, RNTST, 9,
     {
         {0, sizeof(HANDLE), SYSARG_INLINED, DRSYS_TYPE_HANDLE},
         {1, sizeof(HANDLE), SYSARG_INLINED, DRSYS_TYPE_HANDLE},
         {2, sizeof(PIO_APC_ROUTINE), SYSARG_INLINED, DRSYS_TYPE_FUNCTION},
         {3, sizeof(PVOID), SYSARG_INLINED, DRSYS_TYPE_UNKNOWN},
         {4, sizeof(IO_STATUS_BLOCK), W|HT, DRSYS_TYPE_IO_STATUS_BLOCK},
         {5, -6, W|HT, DRSYS_TYPE_VOID},
         {5, -4,(W|IO)|HT, DRSYS_TYPE_VOID},
         {6, sizeof(ULONG), SYSARG_INLINED, DRSYS_TYPE_UNSIGNED_INT},
         {7, sizeof(LARGE_INTEGER), R|HT, DRSYS_TYPE_LARGE_INTEGER},
         {8, sizeof(ULONG), R|HT, DRSYS_TYPE_UNSIGNED_INT},
     }
    },
    {{0,0},"NtReadFileScatter", OK, RNTST, 9,
     {
         {0, sizeof(HANDLE), SYSARG_INLINED, DRSYS_TYPE_HANDLE},
         {1, sizeof(HANDLE), SYSARG_INLINED, DRSYS_TYPE_HANDLE},
         {2, sizeof(PIO_APC_ROUTINE), SYSARG_INLINED, DRSYS_TYPE_FUNCTION},
         {3, sizeof(PVOID), SYSARG_INLINED, DRSYS_TYPE_UNKNOWN},
         {4, sizeof(IO_STATUS_BLOCK), W|HT, DRSYS_TYPE_IO_STATUS_BLOCK},
         {5, sizeof(FILE_SEGMENT_ELEMENT), R},
         {6, sizeof(ULONG), SYSARG_INLINED, DRSYS_TYPE_UNSIGNED_INT},
         {7, sizeof(LARGE_INTEGER), R|HT, DRSYS_TYPE_LARGE_INTEGER},
         {8, sizeof(ULONG), R|HT, DRSYS_TYPE_UNSIGNED_INT},
     }
    },
    {{0,0},"NtReadRequestData", OK, RNTST, 6,
     {
         {0, sizeof(HANDLE), SYSARG_INLINED, DRSYS_TYPE_HANDLE},
         {1, sizeof(PORT_MESSAGE), R|CT, SYSARG_TYPE_PORT_MESSAGE},
         {2, sizeof(ULONG), SYSARG_INLINED, DRSYS_TYPE_UNSIGNED_INT},
         {3, -4, W},
         {3, -5, WI},
         {4, sizeof(ULONG), SYSARG_INLINED, DRSYS_TYPE_UNSIGNED_INT},
         {5, sizeof(ULONG), W|HT, DRSYS_TYPE_UNSIGNED_INT},
     }
    },
    {{0,0},"NtReadVirtualMemory", OK, RNTST, 5,
     {
         {0, sizeof(HANDLE), SYSARG_INLINED, DRSYS_TYPE_HANDLE},
         {1, sizeof(PVOID), SYSARG_INLINED, DRSYS_TYPE_UNKNOWN},
         {2, -3, W|HT, DRSYS_TYPE_VOID},
         {2, -4, WI|HT, DRSYS_TYPE_VOID},
         {3, sizeof(ULONG), SYSARG_INLINED, DRSYS_TYPE_UNSIGNED_INT},
         {4, sizeof(ULONG), W|HT, DRSYS_TYPE_UNSIGNED_INT},
     }
    },
    {{0,0},"NtRegisterThreadTerminatePort", OK, RNTST, 1,
     {
         {0, sizeof(HANDLE), SYSARG_INLINED, DRSYS_TYPE_HANDLE},
     }
    },
    {{0,0},"NtReleaseKeyedEvent", OK, RNTST, 4,
     {
         {0, sizeof(HANDLE), SYSARG_INLINED, DRSYS_TYPE_HANDLE},
         {1, sizeof(PVOID), SYSARG_INLINED, DRSYS_TYPE_UNKNOWN},
         {2, sizeof(BOOLEAN), SYSARG_INLINED, DRSYS_TYPE_BOOL},
         {3, sizeof(LARGE_INTEGER), R|HT, DRSYS_TYPE_LARGE_INTEGER},
     }
    },
    {{0,0},"NtReleaseMutant", OK, RNTST, 2,
     {
         {0, sizeof(HANDLE), SYSARG_INLINED, DRSYS_TYPE_HANDLE},
         {1, sizeof(ULONG), W|HT, DRSYS_TYPE_UNSIGNED_INT},
     }
    },
    {{0,0},"NtReleaseSemaphore", OK, RNTST, 3,
     {
         {0, sizeof(HANDLE), SYSARG_INLINED, DRSYS_TYPE_HANDLE},
         {1, sizeof(LONG), SYSARG_INLINED, DRSYS_TYPE_SIGNED_INT},
         {2, sizeof(LONG), W|HT, DRSYS_TYPE_SIGNED_INT},
     }
    },
    {{0,0},"NtRemoveIoCompletion", OK, RNTST, 5,
     {
         {0, sizeof(HANDLE), SYSARG_INLINED, DRSYS_TYPE_HANDLE},
         {1, sizeof(ULONG), W|HT, DRSYS_TYPE_UNSIGNED_INT},
         {2, sizeof(ULONG), W|HT, DRSYS_TYPE_UNSIGNED_INT},
         {3, sizeof(IO_STATUS_BLOCK), W|HT, DRSYS_TYPE_IO_STATUS_BLOCK},
         {4, sizeof(LARGE_INTEGER), R|HT, DRSYS_TYPE_LARGE_INTEGER},
     }
    },
    {{0,0},"NtRemoveProcessDebug", OK, RNTST, 2,
     {
         {0, sizeof(HANDLE), SYSARG_INLINED, DRSYS_TYPE_HANDLE},
         {1, sizeof(HANDLE), SYSARG_INLINED, DRSYS_TYPE_HANDLE},
     }
    },
    {{0,0},"NtRenameKey", OK, RNTST, 2,
     {
         {0, sizeof(HANDLE), SYSARG_INLINED, DRSYS_TYPE_HANDLE},
         {1, sizeof(UNICODE_STRING), R|CT, SYSARG_TYPE_UNICODE_STRING},
     }
    },
    {{0,0},"NtReplaceKey", OK, RNTST, 3,
     {
         {0, sizeof(OBJECT_ATTRIBUTES), R|CT, SYSARG_TYPE_OBJECT_ATTRIBUTES},
         {1, sizeof(HANDLE), SYSARG_INLINED, DRSYS_TYPE_HANDLE},
         {2, sizeof(OBJECT_ATTRIBUTES), R|CT, SYSARG_TYPE_OBJECT_ATTRIBUTES},
     }
    },
    {{0,0},"NtReplyPort", OK, RNTST, 2,
     {
         {0, sizeof(HANDLE), SYSARG_INLINED, DRSYS_TYPE_HANDLE},
         {1, sizeof(PORT_MESSAGE), R|CT, SYSARG_TYPE_PORT_MESSAGE},
     }
    },
    {{0,0},"NtReplyWaitReceivePort", OK, RNTST, 4,
     {
         {0, sizeof(HANDLE), SYSARG_INLINED, DRSYS_TYPE_HANDLE},
         {1, sizeof(PVOID), W|HT, DRSYS_TYPE_UNKNOWN /* XXX: what type is this? */},
         {2, sizeof(PORT_MESSAGE), R|CT, SYSARG_TYPE_PORT_MESSAGE},
         {3, sizeof(PORT_MESSAGE), W|CT, SYSARG_TYPE_PORT_MESSAGE},
     }
    },
    {{0,0},"NtReplyWaitReceivePortEx", OK, RNTST, 5,
     {
         {0, sizeof(HANDLE), SYSARG_INLINED, DRSYS_TYPE_HANDLE},
         {1, sizeof(PVOID), W|HT, DRSYS_TYPE_UNKNOWN /* XXX: what type is this? */},
         {2, sizeof(PORT_MESSAGE), R|CT, SYSARG_TYPE_PORT_MESSAGE},
         {3, sizeof(PORT_MESSAGE), W|CT, SYSARG_TYPE_PORT_MESSAGE},
         {4, sizeof(LARGE_INTEGER), R|HT, DRSYS_TYPE_LARGE_INTEGER},
     }
    },
    {{0,0},"NtReplyWaitReplyPort", OK, RNTST, 2,
     {
         {0, sizeof(HANDLE), SYSARG_INLINED, DRSYS_TYPE_HANDLE},
         {1, sizeof(PORT_MESSAGE), R|W|CT, SYSARG_TYPE_PORT_MESSAGE},
     }
    },
    {{0,0},"NtReplyWaitSendChannel", OK, RNTST, 3,
     {
         {0, sizeof(PVOID), SYSARG_INLINED, DRSYS_TYPE_UNKNOWN},
         {1, sizeof(ULONG), SYSARG_INLINED, DRSYS_TYPE_UNSIGNED_INT},
         {2, sizeof(CHANNEL_MESSAGE), W},
     }
    },
    {{0,0},"NtRequestDeviceWakeup", OK, RNTST, 1,
     {
         {0, sizeof(HANDLE), SYSARG_INLINED, DRSYS_TYPE_HANDLE},
     }
    },
    {{0,0},"NtRequestPort", OK, RNTST, 2,
     {
         {0, sizeof(HANDLE), SYSARG_INLINED, DRSYS_TYPE_HANDLE},
         {1, sizeof(PORT_MESSAGE), R|CT, SYSARG_TYPE_PORT_MESSAGE},
     }
    },
    {{0,0},"NtRequestWaitReplyPort", OK, RNTST, 3,
     {
         {0, sizeof(HANDLE), SYSARG_INLINED, DRSYS_TYPE_HANDLE},
#if 1
         /* FIXME PR 406356: suppressing undefined read I see on every app at process
          * termination on w2k3 vm (though not on wow64 laptop) where the last 16
          * bytes are not filled in (so only length and type are).  Length indicates
          * there is data afterward which we try to handle specially.
          */
         {1, 8, R},
#else
         {1, sizeof(PORT_MESSAGE), R|CT, SYSARG_TYPE_PORT_MESSAGE},
#endif
         {2, sizeof(PORT_MESSAGE), W|CT, SYSARG_TYPE_PORT_MESSAGE},
     }
    },
    {{0,0},"NtRequestWakeupLatency", OK, RNTST, 1,
     {
         {0, sizeof(LATENCY_TIME), SYSARG_INLINED, DRSYS_TYPE_SIGNED_INT},
     }
    },
    {{0,0},"NtResetEvent", OK, RNTST, 2,
     {
         {0, sizeof(HANDLE), SYSARG_INLINED, DRSYS_TYPE_HANDLE},
         {1, sizeof(ULONG), W|HT, DRSYS_TYPE_UNSIGNED_INT},
     }
    },
    {{0,0},"NtResetWriteWatch", OK, RNTST, 3,
     {
         {0, sizeof(HANDLE), SYSARG_INLINED, DRSYS_TYPE_HANDLE},
         {1, sizeof(PVOID), SYSARG_INLINED, DRSYS_TYPE_UNKNOWN},
         {2, sizeof(ULONG), SYSARG_INLINED, DRSYS_TYPE_UNSIGNED_INT},
     }
    },
    {{0,0},"NtRestoreKey", OK, RNTST, 3,
     {
         {0, sizeof(HANDLE), SYSARG_INLINED, DRSYS_TYPE_HANDLE},
         {1, sizeof(HANDLE), SYSARG_INLINED, DRSYS_TYPE_HANDLE},
         {2, sizeof(ULONG), SYSARG_INLINED, DRSYS_TYPE_UNSIGNED_INT},
     }
    },
    {{0,0},"NtResumeProcess", OK, RNTST, 1,
     {
         {0, sizeof(HANDLE), SYSARG_INLINED, DRSYS_TYPE_HANDLE},
     }
    },
    {{0,0},"NtResumeThread", OK, RNTST, 2,
     {
         {0, sizeof(HANDLE), SYSARG_INLINED, DRSYS_TYPE_HANDLE},
         {1, sizeof(ULONG), W|HT, DRSYS_TYPE_UNSIGNED_INT},
     }
    },
    {{0,0},"NtSaveKey", OK, RNTST, 2,
     {
         {0, sizeof(HANDLE), SYSARG_INLINED, DRSYS_TYPE_HANDLE},
         {1, sizeof(HANDLE), SYSARG_INLINED, DRSYS_TYPE_HANDLE},
     }
    },
    {{0,0},"NtSaveKeyEx", OK, RNTST, 3,
     {
         {0, sizeof(HANDLE), SYSARG_INLINED, DRSYS_TYPE_HANDLE},
         {1, sizeof(HANDLE), SYSARG_INLINED, DRSYS_TYPE_HANDLE},
         {2, sizeof(ULONG), SYSARG_INLINED, DRSYS_TYPE_UNSIGNED_INT},
     }
    },
    {{0,0},"NtSaveMergedKeys", OK, RNTST, 3,
     {
         {0, sizeof(HANDLE), SYSARG_INLINED, DRSYS_TYPE_HANDLE},
         {1, sizeof(HANDLE), SYSARG_INLINED, DRSYS_TYPE_HANDLE},
         {2, sizeof(HANDLE), SYSARG_INLINED, DRSYS_TYPE_HANDLE},
     }
    },
    {{0,0},"NtSecureConnectPort", OK, RNTST, 9,
     {
         {0, sizeof(HANDLE), W|HT, DRSYS_TYPE_HANDLE},
         {1, sizeof(UNICODE_STRING), R|CT, SYSARG_TYPE_UNICODE_STRING},
         {2, sizeof(SECURITY_QUALITY_OF_SERVICE), R|CT, SYSARG_TYPE_SECURITY_QOS},
         {3, sizeof(PORT_VIEW), R|W},
         {4, sizeof(SID), R},
         {5, sizeof(REMOTE_PORT_VIEW), R|W},
         {6, sizeof(ULONG), W|HT, DRSYS_TYPE_UNSIGNED_INT},
         {7, -8, R|WI},
         {8, sizeof(ULONG), R|W|HT, DRSYS_TYPE_UNSIGNED_INT},
     }
    },
    {{0,0},"NtSendWaitReplyChannel", OK, RNTST, 4,
     {
         {0, sizeof(HANDLE), SYSARG_INLINED, DRSYS_TYPE_HANDLE},
         {1, sizeof(PVOID), SYSARG_INLINED, DRSYS_TYPE_UNKNOWN},
         {2, sizeof(ULONG), SYSARG_INLINED, DRSYS_TYPE_UNSIGNED_INT},
         {3, sizeof(CHANNEL_MESSAGE), W},
     }
    },
    {{0,0},"NtSetBootEntryOrder", OK, RNTST, 2,
     {
         {0, -1, R|SYSARG_SIZE_IN_ELEMENTS, sizeof(ULONG)},
         {1, sizeof(ULONG), SYSARG_INLINED, DRSYS_TYPE_UNSIGNED_INT},
     }
    },
    {{0,0},"NtSetBootOptions", OK, RNTST, 2,
     {
         {0, sizeof(BOOT_OPTIONS), R},
     }
    },
    {{0,0},"NtSetContextChannel", OK, RNTST, 1,
     {
         {0, sizeof(HANDLE), SYSARG_INLINED, DRSYS_TYPE_HANDLE},
     }
    },
    {{0,0},"NtSetContextThread", OK, RNTST, 2,
     {
         {0, sizeof(HANDLE), SYSARG_INLINED, DRSYS_TYPE_HANDLE},
         {1, sizeof(CONTEXT), R|CT, SYSARG_TYPE_CONTEXT},
     }
    },
    {{0,0},"NtSetDebugFilterState", OK, RNTST, 3,
     {
         {0, sizeof(ULONG), SYSARG_INLINED, DRSYS_TYPE_UNSIGNED_INT},
         {1, sizeof(ULONG), SYSARG_INLINED, DRSYS_TYPE_UNSIGNED_INT},
         {2, sizeof(BOOLEAN), SYSARG_INLINED, DRSYS_TYPE_BOOL},
     }
    },
    {{0,0},"NtSetDefaultHardErrorPort", OK, RNTST, 1,
     {
         {0, sizeof(HANDLE), SYSARG_INLINED, DRSYS_TYPE_HANDLE},
     }
    },
    {{0,0},"NtSetDefaultLocale", OK, RNTST, 2,
     {
         {0, sizeof(BOOLEAN), SYSARG_INLINED, DRSYS_TYPE_BOOL},
         {1, sizeof(LCID), SYSARG_INLINED, DRSYS_TYPE_UNSIGNED_INT},
     }
    },
    {{0,0},"NtSetDefaultUILanguage", OK, RNTST, 1,
     {
         {0, sizeof(LANGID), SYSARG_INLINED, DRSYS_TYPE_UNSIGNED_INT},
     }
    },
    {{0,0},"NtSetEaFile", OK, RNTST, 4,
     {
         {0, sizeof(HANDLE), SYSARG_INLINED, DRSYS_TYPE_HANDLE},
         {1, sizeof(IO_STATUS_BLOCK), W|HT, DRSYS_TYPE_IO_STATUS_BLOCK},
         {2, sizeof(FILE_FULL_EA_INFORMATION), R},
         {3, sizeof(ULONG), SYSARG_INLINED, DRSYS_TYPE_UNSIGNED_INT},
     }
    },
    {{0,0},"NtSetEvent", OK, RNTST, 2,
     {
         {0, sizeof(HANDLE), SYSARG_INLINED, DRSYS_TYPE_HANDLE},
         {1, sizeof(ULONG), W|HT, DRSYS_TYPE_UNSIGNED_INT},
     }
    },
    {{0,0},"NtSetEventBoostPriority", OK, RNTST, 1,
     {
         {0, sizeof(HANDLE), SYSARG_INLINED, DRSYS_TYPE_HANDLE},
     }
    },
    {{0,0},"NtSetHighEventPair", OK, RNTST, 1,
     {
         {0, sizeof(HANDLE), SYSARG_INLINED, DRSYS_TYPE_HANDLE},
     }
    },
    {{0,0},"NtSetHighWaitLowEventPair", OK, RNTST, 1,
     {
         {0, sizeof(HANDLE), SYSARG_INLINED, DRSYS_TYPE_HANDLE},
     }
    },
    {{0,0},"NtSetHighWaitLowThread", OK, RNTST, 0},
    {{0,0},"NtSetInformationDebugObject", OK, RNTST, 5,
     {
         {0, sizeof(HANDLE), SYSARG_INLINED, DRSYS_TYPE_HANDLE},
         {1, sizeof(DEBUGOBJECTINFOCLASS), SYSARG_INLINED, DRSYS_TYPE_SIGNED_INT},
         {2, -3, R},
         {3, sizeof(ULONG), SYSARG_INLINED, DRSYS_TYPE_UNSIGNED_INT},
         {4, sizeof(ULONG), W|HT, DRSYS_TYPE_UNSIGNED_INT},
     }
    },
    {{0,0},"NtSetInformationFile", OK, RNTST, 5,
     {
         {0, sizeof(HANDLE), SYSARG_INLINED, DRSYS_TYPE_HANDLE},
         {1, sizeof(IO_STATUS_BLOCK), W|HT, DRSYS_TYPE_IO_STATUS_BLOCK},
         {2, -3, R},
         {3, sizeof(ULONG), SYSARG_INLINED, DRSYS_TYPE_UNSIGNED_INT},
         {4, sizeof(FILE_INFORMATION_CLASS), SYSARG_INLINED, DRSYS_TYPE_SIGNED_INT},
     }
    },
    {{0,0},"NtSetInformationJobObject", OK, RNTST, 4,
     {
         {0, sizeof(HANDLE), SYSARG_INLINED, DRSYS_TYPE_HANDLE},
         {1, sizeof(JOBOBJECTINFOCLASS), SYSARG_INLINED, DRSYS_TYPE_SIGNED_INT},
         {2, -3, R},
         {3, sizeof(ULONG), SYSARG_INLINED, DRSYS_TYPE_UNSIGNED_INT},
     }
    },
    {{0,0},"NtSetInformationKey", OK, RNTST, 4,
     {
         {0, sizeof(HANDLE), SYSARG_INLINED, DRSYS_TYPE_HANDLE},
         {1, sizeof(KEY_SET_INFORMATION_CLASS), SYSARG_INLINED, DRSYS_TYPE_SIGNED_INT},
         {2, -3, R},
         {3, sizeof(ULONG), SYSARG_INLINED, DRSYS_TYPE_UNSIGNED_INT},
     }
    },
    {{0,0},"NtSetInformationObject", OK, RNTST, 4,
     {
         {0, sizeof(HANDLE), SYSARG_INLINED, DRSYS_TYPE_HANDLE},
         {1, sizeof(OBJECT_INFORMATION_CLASS), SYSARG_INLINED, DRSYS_TYPE_SIGNED_INT},
         {2, -3, R},
         {3, sizeof(ULONG), SYSARG_INLINED, DRSYS_TYPE_UNSIGNED_INT},
     }
    },
    {{0,0},"NtSetInformationProcess", OK, RNTST, 4,
     {
         {0, sizeof(HANDLE), SYSARG_INLINED, DRSYS_TYPE_HANDLE},
         {1, sizeof(PROCESSINFOCLASS), SYSARG_INLINED, DRSYS_TYPE_SIGNED_INT},
         {2, -3, R},
         {3, sizeof(ULONG), SYSARG_INLINED, DRSYS_TYPE_UNSIGNED_INT},
     }
    },
    {{0,0},"NtSetInformationThread", OK, RNTST, 4,
     {
         {0, sizeof(HANDLE), SYSARG_INLINED, DRSYS_TYPE_HANDLE},
         {1, sizeof(THREADINFOCLASS), SYSARG_INLINED, DRSYS_TYPE_SIGNED_INT},
         {2, -3, R},
         {3, sizeof(ULONG), SYSARG_INLINED, DRSYS_TYPE_UNSIGNED_INT},
     }
    },
    {{0,0},"NtSetInformationToken", OK, RNTST, 4,
     {
         {0, sizeof(HANDLE), SYSARG_INLINED, DRSYS_TYPE_HANDLE},
         {1, sizeof(TOKEN_INFORMATION_CLASS), SYSARG_INLINED, DRSYS_TYPE_SIGNED_INT},
         {2, -3, R},
         {3, sizeof(ULONG), SYSARG_INLINED, DRSYS_TYPE_UNSIGNED_INT},
     }
    },
    {{0,0},"NtSetIntervalProfile", OK, RNTST, 2,
     {
         {0, sizeof(ULONG), SYSARG_INLINED, DRSYS_TYPE_UNSIGNED_INT},
         {1, sizeof(KPROFILE_SOURCE), SYSARG_INLINED, DRSYS_TYPE_SIGNED_INT},
     }
    },
    {{0,0},"NtSetIoCompletion", OK, RNTST, 5,
     {
         {0, sizeof(HANDLE), SYSARG_INLINED, DRSYS_TYPE_HANDLE},
         {1, sizeof(ULONG), SYSARG_INLINED, DRSYS_TYPE_UNSIGNED_INT},
         {2, sizeof(ULONG), SYSARG_INLINED, DRSYS_TYPE_UNSIGNED_INT},
         {3, sizeof(NTSTATUS), SYSARG_INLINED, DRSYS_TYPE_NTSTATUS},
         {4, sizeof(ULONG), SYSARG_INLINED, DRSYS_TYPE_UNSIGNED_INT},
     }
    },
    {{0,0},"NtSetLdtEntries", OK, RNTST, 4,
     {
         {0, sizeof(ULONG), SYSARG_INLINED, DRSYS_TYPE_UNSIGNED_INT},
         {1, sizeof(LDT_ENTRY), SYSARG_INLINED, DRSYS_TYPE_STRUCT},
         {2, sizeof(ULONG), SYSARG_INLINED, DRSYS_TYPE_UNSIGNED_INT},
         {3, sizeof(LDT_ENTRY), SYSARG_INLINED, DRSYS_TYPE_STRUCT},
     }
    },
    {{0,0},"NtSetLowEventPair", OK, RNTST, 1,
     {
         {0, sizeof(HANDLE), SYSARG_INLINED, DRSYS_TYPE_HANDLE},
     }
    },
    {{0,0},"NtSetLowWaitHighEventPair", OK, RNTST, 1,
     {
         {0, sizeof(HANDLE), SYSARG_INLINED, DRSYS_TYPE_HANDLE},
     }
    },
    {{0,0},"NtSetLowWaitHighThread", OK, RNTST, 0, },
    {{0,0},"NtSetQuotaInformationFile", OK, RNTST, 4,
     {
         {0, sizeof(HANDLE), SYSARG_INLINED, DRSYS_TYPE_HANDLE},
         {1, sizeof(IO_STATUS_BLOCK), W|HT, DRSYS_TYPE_IO_STATUS_BLOCK},
         {2, sizeof(FILE_USER_QUOTA_INFORMATION), R},
         {3, sizeof(ULONG), SYSARG_INLINED, DRSYS_TYPE_UNSIGNED_INT},
     }
    },
    {{0,0},"NtSetSecurityObject", OK, RNTST, 3,
     {
         {0, sizeof(HANDLE), SYSARG_INLINED, DRSYS_TYPE_HANDLE},
         {1, sizeof(SECURITY_INFORMATION), SYSARG_INLINED, DRSYS_TYPE_UNSIGNED_INT},
         {2, sizeof(SECURITY_DESCRIPTOR), R|CT, SYSARG_TYPE_SECURITY_DESCRIPTOR},
     }
    },
    {{0,0},"NtSetSystemEnvironmentValue", OK, RNTST, 2,
     {
         {0, sizeof(UNICODE_STRING), R|CT, SYSARG_TYPE_UNICODE_STRING},
         {1, sizeof(UNICODE_STRING), R|CT, SYSARG_TYPE_UNICODE_STRING},
     }
    },
    {{0,0},"NtSetSystemEnvironmentValueEx", OK, RNTST, 2,
     {
         {0, sizeof(UNICODE_STRING), R|CT, SYSARG_TYPE_UNICODE_STRING},
         {1, sizeof(GUID), R},
     }
    },
    /* Some info classes write data as well, which is special-cased */
    {{0,0},"NtSetSystemInformation", OK, RNTST, 3,
     {
         {0, sizeof(SYSTEM_INFORMATION_CLASS), SYSARG_INLINED, DRSYS_TYPE_SIGNED_INT},
         {1, -2, R},
         {2, sizeof(ULONG), SYSARG_INLINED, DRSYS_TYPE_UNSIGNED_INT},
     }, &sysnum_SetSystemInformation
    },
    {{0,0},"NtSetSystemPowerState", OK, RNTST, 3,
     {
         {0, sizeof(POWER_ACTION), SYSARG_INLINED, DRSYS_TYPE_SIGNED_INT},
         {1, sizeof(SYSTEM_POWER_STATE), SYSARG_INLINED, DRSYS_TYPE_SIGNED_INT},
         {2, sizeof(ULONG), SYSARG_INLINED, DRSYS_TYPE_UNSIGNED_INT},
     }
    },
    {{0,0},"NtSetSystemTime", OK, RNTST, 2,
     {
         {0, sizeof(LARGE_INTEGER), R|HT, DRSYS_TYPE_LARGE_INTEGER},
         {1, sizeof(LARGE_INTEGER), W|HT, DRSYS_TYPE_LARGE_INTEGER},
     }
    },
    {{0,0},"NtSetThreadExecutionState", OK, RNTST, 2,
     {
         {0, sizeof(EXECUTION_STATE), SYSARG_INLINED, DRSYS_TYPE_UNSIGNED_INT},
         {1, sizeof(EXECUTION_STATE), W|HT, DRSYS_TYPE_UNSIGNED_INT},
     }
    },
    {{0,0},"NtSetTimer", OK, RNTST, 7,
     {
         {0, sizeof(HANDLE), SYSARG_INLINED, DRSYS_TYPE_HANDLE},
         {1, sizeof(LARGE_INTEGER), R|HT, DRSYS_TYPE_LARGE_INTEGER},
         {2, sizeof(PTIMER_APC_ROUTINE), SYSARG_INLINED, DRSYS_TYPE_FUNCTION},
         {3, sizeof(PVOID), SYSARG_INLINED, DRSYS_TYPE_UNKNOWN},
         {4, sizeof(BOOLEAN), SYSARG_INLINED, DRSYS_TYPE_BOOL},
         {5, sizeof(LONG), SYSARG_INLINED, DRSYS_TYPE_SIGNED_INT},
         {6, sizeof(BOOLEAN), W|HT, DRSYS_TYPE_BOOL},
     }
    },
    {{0,0},"NtSetTimerResolution", OK, RNTST, 3,
     {
         {0, sizeof(ULONG), SYSARG_INLINED, DRSYS_TYPE_UNSIGNED_INT},
         {1, sizeof(BOOLEAN), SYSARG_INLINED, DRSYS_TYPE_BOOL},
         {2, sizeof(ULONG), W|HT, DRSYS_TYPE_UNSIGNED_INT},
     }
    },
    {{0,0},"NtSetUuidSeed", OK, RNTST, 1,
     {
         {0, sizeof(UCHAR), R|HT, DRSYS_TYPE_UNSIGNED_INT},
     }
    },
    {{0,0},"NtSetValueKey", OK, RNTST, 6,
     {
         {0, sizeof(HANDLE), SYSARG_INLINED, DRSYS_TYPE_HANDLE},
         {1, sizeof(UNICODE_STRING), R|CT, SYSARG_TYPE_UNICODE_STRING},
         {2, sizeof(ULONG), SYSARG_INLINED, DRSYS_TYPE_UNSIGNED_INT},
         {3, sizeof(ULONG), SYSARG_INLINED, DRSYS_TYPE_UNSIGNED_INT},
         {4, sizeof(PVOID), SYSARG_INLINED, DRSYS_TYPE_UNKNOWN},
         {5, sizeof(ULONG), SYSARG_INLINED, DRSYS_TYPE_UNSIGNED_INT},
     }
    },
    {{0,0},"NtSetVolumeInformationFile", OK, RNTST, 5,
     {
         {0, sizeof(HANDLE), SYSARG_INLINED, DRSYS_TYPE_HANDLE},
         {1, sizeof(IO_STATUS_BLOCK), W|HT, DRSYS_TYPE_IO_STATUS_BLOCK},
         {2, -3, R},
         {3, sizeof(ULONG), SYSARG_INLINED, DRSYS_TYPE_UNSIGNED_INT},
         {4, sizeof(FS_INFORMATION_CLASS), SYSARG_INLINED, DRSYS_TYPE_SIGNED_INT},
     }
    },
    {{0,0},"NtShutdownSystem", OK, RNTST, 1,
     {
         {0, sizeof(SHUTDOWN_ACTION), SYSARG_INLINED, DRSYS_TYPE_SIGNED_INT},
     }
    },
    {{0,0},"NtSignalAndWaitForSingleObject", OK, RNTST, 4,
     {
         {0, sizeof(HANDLE), SYSARG_INLINED, DRSYS_TYPE_HANDLE},
         {1, sizeof(HANDLE), SYSARG_INLINED, DRSYS_TYPE_HANDLE},
         {2, sizeof(BOOLEAN), SYSARG_INLINED, DRSYS_TYPE_BOOL},
         {3, sizeof(LARGE_INTEGER), R|HT, DRSYS_TYPE_LARGE_INTEGER},
     }
    },
    {{0,0},"NtStartProfile", OK, RNTST, 1,
     {
         {0, sizeof(HANDLE), SYSARG_INLINED, DRSYS_TYPE_HANDLE},
     }
    },
    {{0,0},"NtStopProfile", OK, RNTST, 1,
     {
         {0, sizeof(HANDLE), SYSARG_INLINED, DRSYS_TYPE_HANDLE},
     }
    },
    {{0,0},"NtSuspendProcess", OK, RNTST, 1,
     {
         {0, sizeof(HANDLE), SYSARG_INLINED, DRSYS_TYPE_HANDLE},
     }
    },
    {{0,0},"NtSuspendThread", OK, RNTST, 2,
     {
         {0, sizeof(HANDLE), SYSARG_INLINED, DRSYS_TYPE_HANDLE},
         {1, sizeof(ULONG), W|HT, DRSYS_TYPE_UNSIGNED_INT},
     }
    },
    {{0,0},"NtSystemDebugControl", OK, RNTST, 6,
     {
         {0, sizeof(SYSDBG_COMMAND), SYSARG_INLINED, DRSYS_TYPE_UNSIGNED_INT},
         {1, -2, R},
         {2, sizeof(ULONG), SYSARG_INLINED, DRSYS_TYPE_UNSIGNED_INT},
         {3, -4, W},
         {3, -5, WI},
         {4, sizeof(ULONG), SYSARG_INLINED, DRSYS_TYPE_UNSIGNED_INT},
         {5, sizeof(ULONG), W|HT, DRSYS_TYPE_UNSIGNED_INT},
     }
    },
    {{0,0},"NtTerminateJobObject", OK, RNTST, 2,
     {
         {0, sizeof(HANDLE), SYSARG_INLINED, DRSYS_TYPE_HANDLE},
         {1, sizeof(NTSTATUS), SYSARG_INLINED, DRSYS_TYPE_NTSTATUS},
     }
    },
    {{0,0},"NtTerminateProcess", OK, RNTST, 2,
     {
         {0, sizeof(HANDLE), SYSARG_INLINED, DRSYS_TYPE_HANDLE},
         {1, sizeof(NTSTATUS), SYSARG_INLINED, DRSYS_TYPE_NTSTATUS},
     }
    },
    {{0,0},"NtTerminateThread", OK, RNTST, 2,
     {
         {0, sizeof(HANDLE), SYSARG_INLINED, DRSYS_TYPE_HANDLE},
         {1, sizeof(NTSTATUS), SYSARG_INLINED, DRSYS_TYPE_NTSTATUS},
     }
    },
    {{0,0},"NtTestAlert", OK, RNTST, 0},
    /* unlike TraceEvent API routine, syscall takes size+flags as
     * separate params, and struct observed to be all uninit, so we
     * assume struct is all OUT
     */
    {{0,0},"NtTraceEvent", OK, RNTST, 4,
     {
         {0, sizeof(ULONG), SYSARG_INLINED, DRSYS_TYPE_UNSIGNED_INT},
         {1, sizeof(ULONG), SYSARG_INLINED, DRSYS_TYPE_UNSIGNED_INT},
         {2, sizeof(ULONG), SYSARG_INLINED, DRSYS_TYPE_UNSIGNED_INT},
         {3, sizeof(EVENT_TRACE_HEADER), W},
     }
    },
    {{0,0},"NtTranslateFilePath", OK, RNTST, 4,
     {
         {0, sizeof(FILE_PATH), R},
         {1, sizeof(ULONG), SYSARG_INLINED, DRSYS_TYPE_UNSIGNED_INT},
         {2, sizeof(FILE_PATH), W},
         {3, sizeof(ULONG), SYSARG_INLINED, DRSYS_TYPE_UNSIGNED_INT},
     }
    },
    {{0,0},"NtUnloadDriver", OK, RNTST, 1,
     {
         {0, sizeof(UNICODE_STRING), R|CT, SYSARG_TYPE_UNICODE_STRING},
     }
    },
    {{0,0},"NtUnloadKey", OK, RNTST, 1,
     {
         {0, sizeof(OBJECT_ATTRIBUTES), R|CT, SYSARG_TYPE_OBJECT_ATTRIBUTES},
     }
    },
    {{0,0},"NtUnloadKey2", OK, RNTST, 2,
     {
         {0, sizeof(OBJECT_ATTRIBUTES), R|CT, SYSARG_TYPE_OBJECT_ATTRIBUTES},
         {1, sizeof(BOOLEAN), SYSARG_INLINED, DRSYS_TYPE_BOOL},
     }
    },
    {{0,0},"NtUnloadKeyEx", OK, RNTST, 2,
     {
         {0, sizeof(OBJECT_ATTRIBUTES), R|CT, SYSARG_TYPE_OBJECT_ATTRIBUTES},
         {1, sizeof(HANDLE), SYSARG_INLINED, DRSYS_TYPE_HANDLE},
     }
    },
    {{0,0},"NtUnlockFile", OK, RNTST, 5,
     {
         {0, sizeof(HANDLE), SYSARG_INLINED, DRSYS_TYPE_HANDLE},
         {1, sizeof(IO_STATUS_BLOCK), W|HT, DRSYS_TYPE_IO_STATUS_BLOCK},
         {2, sizeof(ULARGE_INTEGER), R|HT, DRSYS_TYPE_ULARGE_INTEGER},
         {3, sizeof(ULARGE_INTEGER), R|HT, DRSYS_TYPE_ULARGE_INTEGER},
         {4, sizeof(ULONG), SYSARG_INLINED, DRSYS_TYPE_UNSIGNED_INT},
     }
    },
    {{0,0},"NtUnlockVirtualMemory", OK, RNTST, 4,
     {
         {0, sizeof(HANDLE), SYSARG_INLINED, DRSYS_TYPE_HANDLE},
         {1, sizeof(PVOID), R|W|HT, DRSYS_TYPE_POINTER},
         {2, sizeof(ULONG), R|W|HT, DRSYS_TYPE_UNSIGNED_INT},
         {3, sizeof(ULONG), SYSARG_INLINED, DRSYS_TYPE_UNSIGNED_INT},
     }
    },
    {{0,0},"NtUnmapViewOfSection", OK, RNTST, 2,
     {
         {0, sizeof(HANDLE), SYSARG_INLINED, DRSYS_TYPE_HANDLE},
         {1, sizeof(PVOID), SYSARG_INLINED, DRSYS_TYPE_UNKNOWN},
     }
    },
    {{0,0},"NtVdmControl", OK, RNTST, 2,
     {
         {0, sizeof(ULONG), SYSARG_INLINED, DRSYS_TYPE_UNSIGNED_INT},
         {1, sizeof(PVOID), SYSARG_INLINED, DRSYS_TYPE_UNKNOWN},
     }
    },
    {{0,0},"NtW32Call", OK, RNTST, 5,
     {
         {0, sizeof(ULONG), SYSARG_INLINED, DRSYS_TYPE_UNSIGNED_INT},
         {1, sizeof(PVOID), SYSARG_INLINED, DRSYS_TYPE_UNKNOWN},
         {2, sizeof(ULONG), SYSARG_INLINED, DRSYS_TYPE_UNSIGNED_INT},
         /* FIXME: de-ref w/o corresponding R to check definedness: but not enough
          * info to understand exactly what's going on here
          */
         {3, -4, WI|HT, DRSYS_TYPE_VOID},
         {4, sizeof(ULONG), W|HT, DRSYS_TYPE_UNSIGNED_INT},
     }
    },
    {{0,0},"NtWaitForDebugEvent", OK, RNTST, 4,
     {
         {0, sizeof(HANDLE), SYSARG_INLINED, DRSYS_TYPE_HANDLE},
         {1, sizeof(BOOLEAN), SYSARG_INLINED, DRSYS_TYPE_BOOL},
         {2, sizeof(LARGE_INTEGER), R|HT, DRSYS_TYPE_LARGE_INTEGER},
         {3, sizeof(DBGUI_WAIT_STATE_CHANGE), W},
     }
    },
    {{0,0},"NtWaitForKeyedEvent", OK, RNTST, 4,
     {
         {0, sizeof(HANDLE), SYSARG_INLINED, DRSYS_TYPE_HANDLE},
         {1, sizeof(PVOID), SYSARG_INLINED, DRSYS_TYPE_UNKNOWN},
         {2, sizeof(BOOLEAN), SYSARG_INLINED, DRSYS_TYPE_BOOL},
         {3, sizeof(LARGE_INTEGER), R|HT, DRSYS_TYPE_LARGE_INTEGER},
     }
    },
    {{0,0},"NtWaitForMultipleObjects", OK, RNTST, 5,
     {
         {0, sizeof(ULONG), SYSARG_INLINED, DRSYS_TYPE_UNSIGNED_INT},
         {1, sizeof(HANDLE), R|HT, DRSYS_TYPE_HANDLE},
         {2, sizeof(WAIT_TYPE), SYSARG_INLINED, DRSYS_TYPE_SIGNED_INT},
         {3, sizeof(BOOLEAN), SYSARG_INLINED, DRSYS_TYPE_BOOL},
         {4, sizeof(LARGE_INTEGER), R|HT, DRSYS_TYPE_LARGE_INTEGER},
     }
    },
    {{0,0},"NtWaitForMultipleObjects32", OK, RNTST, 5,
     {
         {0, sizeof(ULONG), SYSARG_INLINED, DRSYS_TYPE_UNSIGNED_INT},
         {1, sizeof(HANDLE), R|HT, DRSYS_TYPE_HANDLE},
         {2, sizeof(WAIT_TYPE), SYSARG_INLINED, DRSYS_TYPE_SIGNED_INT},
         {3, sizeof(BOOLEAN), SYSARG_INLINED, DRSYS_TYPE_BOOL},
         {4, sizeof(LARGE_INTEGER), R|HT, DRSYS_TYPE_LARGE_INTEGER},
     }
    },
    {{0,0},"NtWaitForSingleObject", OK, RNTST, 3,
     {
         {0, sizeof(HANDLE), SYSARG_INLINED, DRSYS_TYPE_HANDLE},
         {1, sizeof(BOOLEAN), SYSARG_INLINED, DRSYS_TYPE_BOOL},
         {2, sizeof(LARGE_INTEGER), R|HT, DRSYS_TYPE_LARGE_INTEGER},
     }
    },
    {{0,0},"NtWaitHighEventPair", OK, RNTST, 1,
     {
         {0, sizeof(HANDLE), SYSARG_INLINED, DRSYS_TYPE_HANDLE},
     }
    },
    {{0,0},"NtWaitLowEventPair", OK, RNTST, 1,
     {
         {0, sizeof(HANDLE), SYSARG_INLINED, DRSYS_TYPE_HANDLE},
     }
    },
    {{0,0},"NtWriteFile", OK, RNTST, 9,
     {
         {0, sizeof(HANDLE), SYSARG_INLINED, DRSYS_TYPE_HANDLE},
         {1, sizeof(HANDLE), SYSARG_INLINED, DRSYS_TYPE_HANDLE},
         {2, sizeof(PIO_APC_ROUTINE), SYSARG_INLINED, DRSYS_TYPE_FUNCTION},
         {3, sizeof(PVOID), SYSARG_INLINED, DRSYS_TYPE_UNKNOWN},
         {4, sizeof(IO_STATUS_BLOCK), W|HT, DRSYS_TYPE_IO_STATUS_BLOCK},
         {5, -6, R|HT, DRSYS_TYPE_VOID},
         {6, sizeof(ULONG), SYSARG_INLINED, DRSYS_TYPE_UNSIGNED_INT},
         {7, sizeof(LARGE_INTEGER), R|HT, DRSYS_TYPE_LARGE_INTEGER},
         {8, sizeof(ULONG), R|HT, DRSYS_TYPE_UNSIGNED_INT},
     }
    },
    {{0,0},"NtWriteFileGather", OK, RNTST, 9,
     {
         {0, sizeof(HANDLE), SYSARG_INLINED, DRSYS_TYPE_HANDLE},
         {1, sizeof(HANDLE), SYSARG_INLINED, DRSYS_TYPE_HANDLE},
         {2, sizeof(PIO_APC_ROUTINE), SYSARG_INLINED, DRSYS_TYPE_FUNCTION},
         {3, sizeof(PVOID), SYSARG_INLINED, DRSYS_TYPE_UNKNOWN},
         {4, sizeof(IO_STATUS_BLOCK), W|HT, DRSYS_TYPE_IO_STATUS_BLOCK},
         {5, sizeof(FILE_SEGMENT_ELEMENT), R},
         {6, sizeof(ULONG), SYSARG_INLINED, DRSYS_TYPE_UNSIGNED_INT},
         {7, sizeof(LARGE_INTEGER), R|HT, DRSYS_TYPE_LARGE_INTEGER},
         {8, sizeof(ULONG), R|HT, DRSYS_TYPE_UNSIGNED_INT},
     }
    },
    {{0,0},"NtWriteRequestData", OK, RNTST, 6,
     {
         {0, sizeof(HANDLE), SYSARG_INLINED, DRSYS_TYPE_HANDLE},
         {1, sizeof(PORT_MESSAGE), R|CT, SYSARG_TYPE_PORT_MESSAGE},
         {2, sizeof(ULONG), SYSARG_INLINED, DRSYS_TYPE_UNSIGNED_INT},
         {3, -4, R},
         {4, sizeof(ULONG), SYSARG_INLINED, DRSYS_TYPE_UNSIGNED_INT},
         {5, sizeof(ULONG), W|HT, DRSYS_TYPE_UNSIGNED_INT},
     }
    },
    {{0,0},"NtWriteVirtualMemory", OK, RNTST, 5,
     {
         {0, sizeof(HANDLE), SYSARG_INLINED, DRSYS_TYPE_HANDLE},
         {1, sizeof(PVOID), SYSARG_INLINED, DRSYS_TYPE_UNKNOWN},
         {2, -3, R|HT, DRSYS_TYPE_VOID},
         {3, sizeof(ULONG), SYSARG_INLINED, DRSYS_TYPE_UNSIGNED_INT},
         {4, sizeof(ULONG), W|HT, DRSYS_TYPE_UNSIGNED_INT},
     }
    },
    {{0,0},"NtYieldExecution", OK, RNTST, 0, },

    /***************************************************/
    /* added in Windows 2003 */
    {{0,0},"NtSetDriverEntryOrder", OK, RNTST, 2,
     {
        {0, -1, R|SYSARG_SIZE_IN_ELEMENTS, sizeof(ULONG)},
        {1, sizeof(ULONG), SYSARG_INLINED, DRSYS_TYPE_UNSIGNED_INT},
     }
    },

    /* FIXME i#1089: fill in info on all the inlined args for the
     * syscalls below here.
     */

    /***************************************************/
    /* added in Windows XP64 WOW64 */
    {{0,0},"NtWow64CsrClientConnectToServer", UNKNOWN, RNTST, 5, },
    {{0,0},"NtWow64CsrNewThread", OK, RNTST, 0, },
    {{0,0},"NtWow64CsrIdentifyAlertableThread", OK, RNTST, 0, },
    {{0,0},"NtWow64CsrClientCallServer", UNKNOWN, RNTST, 4, },
    {{0,0},"NtWow64CsrAllocateCaptureBuffer", OK, RNTST, 2, },
    {{0,0},"NtWow64CsrFreeCaptureBuffer", OK, RNTST, 1, },
    {{0,0},"NtWow64CsrAllocateMessagePointer", UNKNOWN, RNTST, 3, },
    {{0,0},"NtWow64CsrCaptureMessageBuffer", UNKNOWN, RNTST, 4, },
    {{0,0},"NtWow64CsrCaptureMessageString", UNKNOWN, RNTST, 5, },
    {{0,0},"NtWow64CsrSetPriorityClass", OK, RNTST, 2,
     {
        {1, sizeof(ULONG), R|W|HT, DRSYS_TYPE_UNSIGNED_INT},
     }
    },
    {{0,0},"NtWow64CsrGetProcessId", OK, RNTST, 0, },
    {{0,0},"NtWow64DebuggerCall", OK, RNTST, 5, },
    /* args seem to be identical to NtQuerySystemInformation */
    {{0,0},"NtWow64GetNativeSystemInformation", OK|SYSINFO_RET_SMALL_WRITE_LAST, RNTST, 4,
     {
        {1, -2, W},
        {1, -3, WI},
        {3, sizeof(ULONG), W|HT, DRSYS_TYPE_UNSIGNED_INT},
     }
    },
    {{0,0},"NtWow64QueryInformationProcess64", OK|SYSINFO_RET_SMALL_WRITE_LAST, RNTST, 5,
     {
        {2, -3, W},
        {2, -4, WI},
        {4, sizeof(ULONG), W|HT, DRSYS_TYPE_UNSIGNED_INT},
     }
    },
    {{0,0},"NtWow64ReadVirtualMemory64", UNKNOWN, RNTST, 7, },
    {{0,0},"NtWow64QueryVirtualMemory64", UNKNOWN, RNTST, 8, },

    /***************************************************/
    /* added in Windows Vista SP0 */
    {{0,0},"NtAcquireCMFViewOwnership", UNKNOWN, RNTST, 3, },
    {{0,0},"NtAlpcAcceptConnectPort", OK, RNTST, 9,
     {
        {0, sizeof(HANDLE), W|HT, DRSYS_TYPE_HANDLE},
        {3, sizeof(OBJECT_ATTRIBUTES), R|CT, SYSARG_TYPE_OBJECT_ATTRIBUTES},
        {4, sizeof(ALPC_PORT_ATTRIBUTES), R|CT, SYSARG_TYPE_ALPC_PORT_ATTRIBUTES},
        {6, sizeof(PORT_MESSAGE), R|CT, SYSARG_TYPE_PORT_MESSAGE},
        {7, sizeof(ALPC_MESSAGE_ATTRIBUTES), R|W},
        {8, sizeof(BOOLEAN), SYSARG_INLINED, DRSYS_TYPE_BOOL},
     }
    },
    {{0,0},"NtAlpcCancelMessage", OK, RNTST, 3,
     {
        {2, sizeof(ALPC_CONTEXT_ATTRIBUTES), R},
     }
    },
    {{0,0},"NtAlpcConnectPort", OK, RNTST, 11,
     {
        {0, sizeof(HANDLE), W|HT, DRSYS_TYPE_HANDLE},
        {1, sizeof(UNICODE_STRING), R|CT, SYSARG_TYPE_UNICODE_STRING},
        {2, sizeof(OBJECT_ATTRIBUTES), R|CT, SYSARG_TYPE_OBJECT_ATTRIBUTES},
        {3, sizeof(ALPC_PORT_ATTRIBUTES), R|CT, SYSARG_TYPE_ALPC_PORT_ATTRIBUTES},
        {5, sizeof(SID), R},
        {6, -7, WI},
        {7, sizeof(ULONG), R|W|HT, DRSYS_TYPE_UNSIGNED_INT},
        {8, sizeof(ALPC_MESSAGE_ATTRIBUTES), R|W},
        {9, sizeof(ALPC_MESSAGE_ATTRIBUTES), R|W},
        {10, sizeof(LARGE_INTEGER), R|HT, DRSYS_TYPE_LARGE_INTEGER},
     }
    },
    {{0,0},"NtAlpcCreatePort", OK, RNTST, 3,
     {
        {0, sizeof(HANDLE), W|HT, DRSYS_TYPE_HANDLE},
        {1, sizeof(OBJECT_ATTRIBUTES), R|CT, SYSARG_TYPE_OBJECT_ATTRIBUTES},
        {2, sizeof(ALPC_PORT_ATTRIBUTES), R|CT, SYSARG_TYPE_ALPC_PORT_ATTRIBUTES},
     }
    },
    {{0,0},"NtAlpcCreatePortSection", OK, RNTST, 6,
     {
        {4, sizeof(HANDLE), W|HT, DRSYS_TYPE_HANDLE},
        {5, sizeof(ULONG), W|HT, DRSYS_TYPE_UNSIGNED_INT},
     }
    },
    {{0,0},"NtAlpcCreateResourceReserve", OK, RNTST, 4,
     {
        {3, sizeof(HANDLE), W|HT, DRSYS_TYPE_HANDLE},
     }
    },
    {{0,0},"NtAlpcCreateSectionView", OK, RNTST, 3,
     {
        {2, sizeof(ALPC_DATA_VIEW), R|W},
     }
    },
    {{0,0},"NtAlpcCreateSecurityContext", OK, RNTST, 3,
     {
        {2, sizeof(ALPC_SECURITY_ATTRIBUTES), R|W|CT, SYSARG_TYPE_ALPC_SECURITY_ATTRIBUTES},
     }
    },
    {{0,0},"NtAlpcDeletePortSection", OK, RNTST, 3, },
    {{0,0},"NtAlpcDeleteResourceReserve", OK, RNTST, 3, },
    /* XXX: ok for shadowing purposes, but we should look at tracking
     * the allocation once we understand NtAlpcCreateSectionView
     */
    {{0,0},"NtAlpcDeleteSectionView", OK, RNTST, 3, },
    {{0,0},"NtAlpcDeleteSecurityContext", OK, RNTST, 3, },
    {{0,0},"NtAlpcDisconnectPort", OK, RNTST, 2, },
    {{0,0},"NtAlpcImpersonateClientOfPort", OK, RNTST, 3,
     {
        {1, sizeof(PORT_MESSAGE), R|CT, SYSARG_TYPE_PORT_MESSAGE},
     }
    },
    {{0,0},"NtAlpcOpenSenderProcess", OK, RNTST, 6,
     {
        {0, sizeof(HANDLE), W|HT, DRSYS_TYPE_HANDLE},
        {2, sizeof(PORT_MESSAGE), R|CT, SYSARG_TYPE_PORT_MESSAGE},
        {5, sizeof(OBJECT_ATTRIBUTES), R|CT, SYSARG_TYPE_OBJECT_ATTRIBUTES},
     }
    },
    {{0,0},"NtAlpcOpenSenderThread", OK, RNTST, 6,
     {
        {0, sizeof(HANDLE), W|HT, DRSYS_TYPE_HANDLE},
        {2, sizeof(PORT_MESSAGE), R|CT, SYSARG_TYPE_PORT_MESSAGE},
        {5, sizeof(OBJECT_ATTRIBUTES), R|CT, SYSARG_TYPE_OBJECT_ATTRIBUTES},
     }
    },
    {{0,0},"NtAlpcQueryInformation", OK, RNTST, 5,
     {
        {2, -3, W},
        {4, sizeof(ULONG), W|HT, DRSYS_TYPE_UNSIGNED_INT},
     }
    },
    {{0,0},"NtAlpcQueryInformationMessage", OK, RNTST, 6,
     {
        {1, sizeof(PORT_MESSAGE), R|CT, SYSARG_TYPE_PORT_MESSAGE},
        {3, -4, W},
        {5, sizeof(ULONG), W|HT, DRSYS_TYPE_UNSIGNED_INT},
     }
    },
    {{0,0},"NtAlpcRevokeSecurityContext", OK, RNTST, 3, },
    /* FIXME i#98:
     * + #2 should be {2, sizeof(PORT_MESSAGE), R|CT, SYSARG_TYPE_PORT_MESSAGE}
     *   but it seems to have custom data that is not all IN
     * + #3 and #6 are void* buffers but where is their size stored?
     * + #4 could be {4, sizeof(PORT_MESSAGE), W|CT, SYSARG_TYPE_PORT_MESSAGE}
     *   but I'm assuming #5 points at size of OUT PORT_MESSAGE
     */
    {{0,0},"NtAlpcSendWaitReceivePort", UNKNOWN, RNTST, 8,
     {
        {4, -5, WI},
        {5, sizeof(ULONG), W|HT, DRSYS_TYPE_UNSIGNED_INT},
        {7, sizeof(LARGE_INTEGER), R|HT, DRSYS_TYPE_LARGE_INTEGER},
     }
    },
    {{0,0},"NtAlpcSetInformation", OK, RNTST, 4,
     {
        {2, -3, R},
     }
    },
    {{0,0},"NtCancelIoFileEx", UNKNOWN, RNTST, 3, },
    {{0,0},"NtCancelSynchronousIoFile", UNKNOWN, RNTST, 3, },
    {{0,0},"NtClearAllSavepointsTransaction", UNKNOWN, RNTST, 1, },
    {{0,0},"NtClearSavepointTransaction", UNKNOWN, RNTST, 2, },
    {{0,0},"NtCommitComplete", UNKNOWN, RNTST, 2, },
    {{0,0},"NtCommitEnlistment", UNKNOWN, RNTST, 2, },
    {{0,0},"NtCommitTransaction", UNKNOWN, RNTST, 2, },
    {{0,0},"NtCreateEnlistment", UNKNOWN, RNTST, 8, },
    {{0,0},"NtCreateKeyTransacted", UNKNOWN, RNTST, 8, },
    {{0,0},"NtCreatePrivateNamespace", UNKNOWN, RNTST, 4, },
    {{0,0},"NtCreateResourceManager", UNKNOWN, RNTST, 7, },
    {{0,0},"NtCreateTransaction", UNKNOWN, RNTST, 10, },
    {{0,0},"NtCreateTransactionManager", UNKNOWN, RNTST, 6, },
    {{0,0},"NtCreateWorkerFactory", UNKNOWN, RNTST, 10, },
    {{0,0},"NtDeletePrivateNamespace", UNKNOWN, RNTST, 1, },
    {{0,0},"NtEnumerateTransactionObject", UNKNOWN, RNTST, 5, },
    {{0,0},"NtFlushInstallUILanguage", UNKNOWN, RNTST, 2, },
    {{0,0},"NtFlushProcessWriteBuffers", OK, RNTST, 0, },
    {{0,0},"NtFreezeRegistry", UNKNOWN, RNTST, 1, },
    {{0,0},"NtFreezeTransactions", UNKNOWN, RNTST, 2, },
    {{0,0},"NtGetMUIRegistryInfo", UNKNOWN, RNTST, 3, },
    {{0,0},"NtGetNextProcess", UNKNOWN, RNTST, 5, },
    {{0,0},"NtGetNextThread", UNKNOWN, RNTST, 6, },
    {{0,0},"NtGetNlsSectionPtr", UNKNOWN, RNTST, 5, },
    {{0,0},"NtGetNotificationResourceManager", UNKNOWN, RNTST, 7, },
    {{0,0},"NtInitializeNlsFiles", UNKNOWN, RNTST, 3, },
    {{0,0},"NtIsUILanguageComitted", UNKNOWN, RNTST, 0, },
    {{0,0},"NtListTransactions", UNKNOWN, RNTST, 3, },
    {{0,0},"NtMarshallTransaction", UNKNOWN, RNTST, 6, },
    {{0,0},"NtOpenEnlistment", UNKNOWN, RNTST, 5, },
    {{0,0},"NtOpenKeyTransacted", UNKNOWN, RNTST, 4, },
    {{0,0},"NtOpenPrivateNamespace", UNKNOWN, RNTST, 4, },
    {{0,0},"NtOpenResourceManager", UNKNOWN, RNTST, 5, },
    {{0,0},"NtOpenSession", UNKNOWN, RNTST, 3, },
    {{0,0},"NtOpenTransaction", UNKNOWN, RNTST, 5, },
    {{0,0},"NtOpenTransactionManager", UNKNOWN, RNTST, 6, },
    {{0,0},"NtPrepareComplete", UNKNOWN, RNTST, 2, },
    {{0,0},"NtPrepareEnlistment", UNKNOWN, RNTST, 2, },
    {{0,0},"NtPrePrepareComplete", UNKNOWN, RNTST, 2, },
    {{0,0},"NtPrePrepareEnlistment", UNKNOWN, RNTST, 2, },
    {{0,0},"NtPropagationComplete", UNKNOWN, RNTST, 4, },
    {{0,0},"NtPropagationFailed", UNKNOWN, RNTST, 3, },
    {{0,0},"NtPullTransaction", UNKNOWN, RNTST, 7, },
    {{0,0},"NtQueryInformationEnlistment", UNKNOWN, RNTST, 5, },
    {{0,0},"NtQueryInformationResourceManager", UNKNOWN, RNTST, 5, },
    {{0,0},"NtQueryInformationTransaction", UNKNOWN, RNTST, 5, },
    {{0,0},"NtQueryInformationTransactionManager", UNKNOWN, RNTST, 5, },
    {{0,0},"NtQueryInformationWorkerFactory", UNKNOWN, RNTST, 5, },
    {{0,0},"NtQueryLicenseValue", UNKNOWN, RNTST, 5, },
    {{0,0},"NtReadOnlyEnlistment", UNKNOWN, RNTST, 2, },
    {{0,0},"NtRecoverEnlistment", UNKNOWN, RNTST, 2, },
    {{0,0},"NtRecoverResourceManager", UNKNOWN, RNTST, 1, },
    {{0,0},"NtRecoverTransactionManager", UNKNOWN, RNTST, 1, },
    {{0,0},"NtRegisterProtocolAddressInformation", UNKNOWN, RNTST, 5, },
    {{0,0},"NtReleaseCMFViewOwnership", UNKNOWN, RNTST, 0, },
    {{0,0},"NtReleaseWorkerFactoryWorker", UNKNOWN, RNTST, 1, },
    {{0,0},"NtRemoveIoCompletionEx", UNKNOWN, RNTST, 6, },
    {{0,0},"NtRollbackComplete", UNKNOWN, RNTST, 2, },
    {{0,0},"NtRollbackEnlistment", UNKNOWN, RNTST, 2, },
    {{0,0},"NtRollbackSavepointTransaction", UNKNOWN, RNTST, 2, },
    {{0,0},"NtRollbackTransaction", UNKNOWN, RNTST, 2, },
    {{0,0},"NtRollforwardTransactionManager", UNKNOWN, RNTST, 2, },
    {{0,0},"NtSavepointComplete", UNKNOWN, RNTST, 2, },
    {{0,0},"NtSavepointTransaction", UNKNOWN, RNTST, 3, },
    {{0,0},"NtSetInformationEnlistment", UNKNOWN, RNTST, 4, },
    {{0,0},"NtSetInformationResourceManager", UNKNOWN, RNTST, 4, },
    {{0,0},"NtSetInformationTransaction", UNKNOWN, RNTST, 4, },
    {{0,0},"NtSetInformationTransactionManager", UNKNOWN, RNTST, 4, },
    {{0,0},"NtSetInformationWorkerFactory", UNKNOWN, RNTST, 4, },
    {{0,0},"NtShutdownWorkerFactory", UNKNOWN, RNTST, 2, },
    {{0,0},"NtSinglePhaseReject", UNKNOWN, RNTST, 2, },
    {{0,0},"NtStartTm", UNKNOWN, RNTST, 0, },
    {{0,0},"NtThawRegistry", UNKNOWN, RNTST, 0, },
    {{0,0},"NtThawTransactions", UNKNOWN, RNTST, 0, },
    {{0,0},"NtTraceControl", UNKNOWN, RNTST, 6, },
    {{0,0},"NtWaitForWorkViaWorkerFactory", UNKNOWN, RNTST, 2, },
    {{0,0},"NtWorkerFactoryWorkerReady", UNKNOWN, RNTST, 1, },

    /***************************************************/
    /* added in Windows Vista SP1 */
    {{0,0},"NtRenameTransactionManager", UNKNOWN, RNTST, 2, },
    {{0,0},"NtReplacePartitionUnit", UNKNOWN, RNTST, 3, },
    {{0,0},"NtWow64CsrVerifyRegion", OK, RNTST, 2, },
    {{0,0},"NtWow64WriteVirtualMemory64", OK, RNTST, 7,
     {
        {6, sizeof(ULONGLONG), W|HT, DRSYS_TYPE_UNSIGNED_INT},
     }
    },
    {{0,0},"NtWow64CallFunction64", OK, RNTST, 7,
     {
        {3, -2, R},
        {5, -4, W},
        {6, sizeof(ULONG), W|HT, DRSYS_TYPE_UNSIGNED_INT},
     }
    },

    /***************************************************/
    /* added in Windows 7 */
    {{0,0},"NtAllocateReserveObject", OK, RNTST, 3,
     {
        {0, sizeof(HANDLE), W|HT, DRSYS_TYPE_HANDLE},
        {1, sizeof(OBJECT_ATTRIBUTES), R|CT, SYSARG_TYPE_OBJECT_ATTRIBUTES},
     }
    },
    {{0,0},"NtCreateProfileEx", UNKNOWN, RNTST, 10, },
    {{0,0},"NtDisableLastKnownGood", UNKNOWN, RNTST, 0, },
    {{0,0},"NtDrawText", UNKNOWN, RNTST, 1, },
    {{0,0},"NtEnableLastKnownGood", UNKNOWN, RNTST, 0, },
    {{0,0},"NtNotifyChangeSession", UNKNOWN, RNTST, 8, },
    {{0,0},"NtOpenKeyTransactedEx", UNKNOWN, RNTST, 5, },
    {{0,0},"NtQuerySecurityAttributesToken", UNKNOWN, RNTST, 6, },
    {{0,0},"NtQuerySystemInformationEx", UNKNOWN, RNTST, 6, },
    {{0,0},"NtQueueApcThreadEx", UNKNOWN, RNTST, 6, },
    {{0,0},"NtSerializeBoot", UNKNOWN, RNTST, 0, },
    {{0,0},"NtSetIoCompletionEx", UNKNOWN, RNTST, 6, },
    {{0,0},"NtSetTimerEx", UNKNOWN, RNTST, 4, },
    {{0,0},"NtUmsThreadYield", UNKNOWN, RNTST, 1, },
    {{0,0},"NtWow64GetCurrentProcessorNumberEx", OK, RNTST, 1,
     {
        {0, sizeof(PROCESSOR_NUMBER), W},
     }
    },
    {{0,0},"NtWow64InterlockedPopEntrySList", OK, RNTST, 1,
     {
        {0, sizeof(SLIST_HEADER), R|W},
     }
    },
};
#define NUM_NTDLL_SYSCALLS (sizeof(syscall_ntdll_info)/sizeof(syscall_ntdll_info[0]))

/* win32k.sys and other non-ntoskrnl syscalls are in syscall_wingdi.c */
extern syscall_info_t syscall_kernel32_info[];
extern size_t num_kernel32_syscalls(void);
extern syscall_info_t syscall_user32_info[];
extern size_t num_user32_syscalls(void);
extern syscall_info_t syscall_gdi32_info[];
extern size_t num_gdi32_syscalls(void);
extern syscall_info_t syscall_usercall_info[];
extern size_t num_usercall_syscalls(void);

#undef OK
#undef UNKNOWN
#undef W
#undef R
#undef HT
#undef CT
#undef WI
#undef IO
#undef RET

/* Takes in any Nt syscall wrapper entry point.
 * Will accept other entry points (e.g., we call it for gdi32!GetFontData)
 * and return -1 for them: up to caller to assert if that shouldn't happen.
 */
static int
syscall_num_from_wrapper(void *drcontext, byte *entry)
{
    /* Presumably the cross-module cost here doesn't matter vs all the
     * calls into DR: if so we should inline the DR calls and maybe
     * have our own copy here (like we used to).
     */
    return drmgr_decode_sysnum_from_wrapper(entry);
}

static bool
syscall_num_from_name(void *drcontext, const module_data_t *info,
                      const char *name, const char *optional_prefix,
                      bool sym_lookup, drsys_sysnum_t *num_out OUT)
{
    app_pc entry = (app_pc) dr_get_proc_address(info->handle, name);
    int num = -1;
    ASSERT(num_out != NULL, "invalid param");
    if (entry != NULL) {
        /* look for partial map (i#730) */
        if (entry >= info->end) /* XXX: syscall_num will decode a few instrs in */
            return -1;
        num = syscall_num_from_wrapper(drcontext, entry);
    }
    if (entry == NULL && sym_lookup && drsys_ops.lookup_internal_symbol != NULL) {
        /* i#388: for those that aren't exported, if we have symbols, find the
         * sysnum that way.
         */
        /* drsym_init() was called already in utils_init() */
        entry = (*drsys_ops.lookup_internal_symbol)(info, name);
        if (entry != NULL)
            num = syscall_num_from_wrapper(drcontext, entry);
        if (num == -1 && optional_prefix != NULL) {
            const char *skip_prefix = name + strlen(optional_prefix);
            ASSERT(strstr(name, optional_prefix) == name,
                   "missing syscall prefix");
            entry = (*drsys_ops.lookup_internal_symbol)(info, skip_prefix);
            if (entry != NULL)
                num = syscall_num_from_wrapper(drcontext, entry);
        }
    }
    DOLOG(1, {
        if (num != -1) {
            name2num_entry_t *e = (name2num_entry_t *)
                hashtable_lookup(&name2num_table, (void *)name);
            if (e != NULL && e->num.number != num) {
                WARN("WARNING: sysnum table "PIFX" != wrapper "PIFX" for %s\n",
                     e->num.number, num, name);
                ASSERT(false, "syscall number table error detected");
            }
        }
    });
    if (num == -1)
        return false;
    num_out->number = num;
    num_out->secondary = 0;
    return true;
}

bool
os_syscall_get_num(const char *name, drsys_sysnum_t *num OUT)
{
    name2num_entry_t *e = (name2num_entry_t *)
        hashtable_lookup(&name2num_table, (void *)name);
    ASSERT(num != NULL, "invalid param");
    if (e != NULL) {
        *num = e->num;
        return true;
    }
    return false;
}

static void
check_syscall_entry(void *drcontext, const module_data_t *info, syscall_info_t *syslist,
                  const char *optional_prefix)
{
    if (TEST(SYSINFO_REQUIRES_PREFIX, syslist->flags))
        optional_prefix = NULL;
    if (info != NULL) {
        drsys_sysnum_t num_from_wrapper;
        bool ok = syscall_num_from_name(drcontext, info, syslist->name,
                                        optional_prefix, 
                                        drsys_ops.verify_sysnums,
                                        &num_from_wrapper);
        ASSERT(!ok/*no syms*/ || drsys_sysnums_equal(&syslist->num, &num_from_wrapper),
               "sysnum table does not match wrapper");
    }
}

static void
add_syscall_entry(void *drcontext, const module_data_t *info, syscall_info_t *syslist,
                  const char *optional_prefix, bool add_name2num)
{
    bool ok = false;
    if (TEST(SYSINFO_REQUIRES_PREFIX, syslist->flags))
        optional_prefix = NULL;
    if (info != NULL) {
        ok = syscall_num_from_name(drcontext, info, syslist->name,
                                   optional_prefix, 
                                   /* it's a perf hit to do one-at-a-time symbol
                                    * lookup for hundreds of syscalls, so we rely
                                    * on our tables unless asked.
                                    * XXX: a single Nt* regex would probably
                                    * be performant enough
                                    */
                                   drsys_ops.verify_sysnums,
                                   &syslist->num);
    }
    if (!ok) {
        /* i#388: use sysnum table if the wrapper is not exported and we don't have
         * symbol info.  Currently the table only has win32k.sys entries since
         * all the ntdll wrappers are exported.
         */
        LOG(SYSCALL_VERBOSE, "using name2num_table since no wrapper found for %s\n",
            syslist->name);
        ok = os_syscall_get_num(syslist->name, &syslist->num);
    }
    if (ok) {
        dr_recurlock_lock(systable_lock);
        hashtable_add(&systable, (void *) &syslist->num, (void *) syslist);
        dr_recurlock_unlock(systable_lock);

        LOG((info != NULL && info->start == ntdll_base) ? 2 : SYSCALL_VERBOSE,
            "system call %-35s = %3d.%d (0x%04x.%x)\n", syslist->name, syslist->num.number,
            syslist->num.secondary, syslist->num.number, syslist->num.secondary);
        if (syslist->num_out != NULL)
            *syslist->num_out = syslist->num;
        if (add_name2num) {
            name2num_entry_add(syslist->name, syslist->num, false/*no dup*/);
            /* Add the Zw variant */
            name2num_entry_add(syslist->name, syslist->num, true/*dup Zw*/);
        }
    } else {
        LOG(SYSCALL_VERBOSE, "WARNING: could not find system call %s\n", syslist->name);
    }
}

drmf_status_t
drsyscall_os_init(void *drcontext)
{
    uint i;
#ifdef WINDOWS
    module_data_t *data;
#endif
    const int *sysnums; /* array of primary syscall numbers */
    /* FIXME i#945: we expect the #s and args of 64-bit windows syscall match
     * wow64, but we have not verified there's no number shifting or arg shifting
     * in the wow64 marshaling layer.
     * FIXME i#772: on win8, wow64 does add some upper bits, which we
     * want to honor so that our stateless number-to-name and
     * name-to-number match real numbers.
     */
    bool wow64 = IF_X64_ELSE(true, dr_is_wow64());
    if (!dr_get_os_version(&win_ver)) {
        ASSERT(false, "unable to get version");
        /* guess at win7 */
        win_ver.version = DR_WINDOWS_VERSION_7;
        win_ver.service_pack_major = 1;
        win_ver.service_pack_minor = 0;
        sysnums = win7wow_sysnums;
    }
    switch (win_ver.version) {
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
        return DRMF_ERROR_INCOMPATIBLE_VERSION;
    }

    /* Set up hashtable for name2num translation at init time.
     * Case-insensitive primarily for NtUserCallOneParam.*.
     */
    hashtable_init_ex(&name2num_table, NAME2NUM_TABLE_HASH_BITS, HASH_STRING_NOCASE,
                      false/*!strdup*/, true/*synch*/, name2num_entry_free,
                      NULL, NULL);
    for (i = 0; i < NUM_SYSNUM_NAMES; i++) {
        if (sysnums[i] != NONE) {
            const char *skip_prefix = NULL;
            drsys_sysnum_t sysnum = {sysnums[i], 0};
            name2num_entry_add(sysnum_names[i], sysnum, false/*no dup*/);

            /* we also add the version without the prefix, so e.g. alloc.c
             * can pass in "UserConnectToServer" without having the
             * optional_prefix param in sysnum_from_name()
             */
            if (strstr(sysnum_names[i], "NtUser") == sysnum_names[i])
                skip_prefix = sysnum_names[i] + strlen("NtUser");
            else if (strstr(sysnum_names[i], "NtGdi") == sysnum_names[i])
                skip_prefix = sysnum_names[i] + strlen("NtGdi");
            if (skip_prefix != NULL) {
                name2num_entry_add(skip_prefix, sysnum, false/*no dup*/);
            }
        }
    }

    hashtable_init_ex(&systable, SYSTABLE_HASH_BITS, HASH_INTPTR, false/*!strdup*/,
                      false/*!synch*/, NULL, sysnum_hash, sysnum_cmp);

    data = dr_lookup_module_by_name("ntdll.dll");
    ASSERT(data != NULL, "cannot find ntdll.dll");
    if (data == NULL)
        return DRMF_ERROR;
    ntdll_base = data->start;

    /* Add all entries at process init time, to support drsys_name_to_number()
     * for secondary win32k.sys and drsys_number_to_name() in dr_init.
     */
    for (i = 0; i < NUM_NTDLL_SYSCALLS; i++)
        add_syscall_entry(drcontext, data, &syscall_ntdll_info[i], NULL, true);
    for (i = 0; i < num_kernel32_syscalls(); i++) {
        add_syscall_entry(drcontext, NULL, &syscall_kernel32_info[i], NULL,
                          false/*already added*/);
    }
    for (i = 0; i < num_user32_syscalls(); i++) {
        if (!TEST(SYSINFO_IMM32_DLL, syscall_user32_info[i].flags)) {
            add_syscall_entry(drcontext, NULL, &syscall_user32_info[i], "NtUser",
                              false/*already added*/);
        }
    }
    for (i = 0; i < num_user32_syscalls(); i++) {
        if (TEST(SYSINFO_IMM32_DLL, syscall_user32_info[i].flags)) {
            add_syscall_entry(drcontext, NULL, &syscall_user32_info[i], "NtUser",
                              false/*already added*/);
        }
    }
    for (i = 0; i < num_gdi32_syscalls(); i++) {
        add_syscall_entry(drcontext, NULL, &syscall_gdi32_info[i], "NtGdi",
                          false/*already added*/);
    }

    dr_free_module_data(data);

    return drsyscall_wingdi_init(drcontext, ntdll_base, &win_ver);
}

void
drsyscall_os_exit(void)
{
    hashtable_delete(&systable);
    hashtable_delete(&name2num_table);
    drsyscall_wingdi_exit();
}

void
drsyscall_os_thread_init(void *drcontext)
{
    drsyscall_wingdi_thread_init(drcontext);
}

void
drsyscall_os_thread_exit(void *drcontext)
{
    drsyscall_wingdi_thread_exit(drcontext);
}

void
drsyscall_os_module_load(void *drcontext, const module_data_t *info, bool loaded)
{
    uint i;
    const char *modname = dr_module_preferred_name(info);
    if (modname == NULL)
        return;

    /* We've already added to the tables at process init time.
     * Here we just check vs the wrapper numbers for other than ntdll
     * (ntdll module was available at process init).
     */
    if (stri_eq(modname, "kernel32.dll")) {
        for (i = 0; i < num_kernel32_syscalls(); i++)
            check_syscall_entry(drcontext, info, &syscall_kernel32_info[i], NULL);
    } else if (stri_eq(modname, "user32.dll")) {
        for (i = 0; i < num_user32_syscalls(); i++) {
            if (!TEST(SYSINFO_IMM32_DLL, syscall_user32_info[i].flags))
                check_syscall_entry(drcontext, info, &syscall_user32_info[i], "NtUser");
        }
    } else if (stri_eq(modname, "imm32.dll")) {
        for (i = 0; i < num_user32_syscalls(); i++) {
            if (TEST(SYSINFO_IMM32_DLL, syscall_user32_info[i].flags))
                check_syscall_entry(drcontext, info, &syscall_user32_info[i], "NtUser");
        }
    } else if (stri_eq(modname, "gdi32.dll")) {
        for (i = 0; i < num_gdi32_syscalls(); i++)
            check_syscall_entry(drcontext, info, &syscall_gdi32_info[i], "NtGdi");
    }
}

/* Though DR's new syscall events provide parameter value access,
 * we need the address of all parameters passed on the stack
 */
static reg_t *
get_sysparam_base(cls_syscall_t *pt)
{
    reg_t *base = (reg_t *) pt->param_base;
    if (is_using_sysenter())
        base += 2;
    return base;
}

static app_pc
get_sysparam_addr(cls_syscall_t *pt, uint ord)
{
    return (app_pc)(((reg_t *)get_sysparam_base(pt)) + ord);
}

/* Either sets arg->reg to DR_REG_NULL and sets arg->start_addr, or sets arg->reg
 * to non-DR_REG_NULL
 */
void
drsyscall_os_get_sysparam_location(cls_syscall_t *pt, uint argnum, drsys_arg_t *arg)
{
    /* We store the sysparam base so we can answer queries about
     * syscall parameter addresses in post-syscall, where xdx (base
     * for 32-bit) is often clobbered.
     */
#ifdef X64
    arg->reg = DR_REG_NULL;
    switch (argnum) {
    case 0:
        arg->reg = DR_REG_RCX;
        break;
    case 1:
        arg->reg = DR_REG_RDX;
        break;
    case 2:
        arg->reg = DR_REG_R8;
        break;
    case 3:
        arg->reg = DR_REG_R9;
        break;
    }
    if (pt->pre)
        pt->param_base = arg->mc->xsp; /* x64 never uses xdx */
    if (arg->reg == DR_REG_NULL) {
        arg->start_addr = get_sysparam_addr(pt, argnum);
    } else {
        arg->start_addr = NULL;
    }
#else
    if (pt->pre)
        pt->param_base = arg->mc->xdx; /* xdx points at args on stack */
    arg->reg = DR_REG_NULL;
    arg->start_addr = get_sysparam_addr(pt, argnum);
#endif
}

bool
os_syscall_succeeded(drsys_sysnum_t sysnum, syscall_info_t *info, ptr_int_t res)
{
    bool success;
    if (wingdi_syscall_succeeded(sysnum, info, res, &success))
        return success;
    /* if info==NULL we assume specially handled and we don't need to look it up */
    if (info != NULL) {
        if (TEST(SYSINFO_RET_ZERO_FAIL, info->flags) ||
            info->return_type == SYSARG_TYPE_BOOL32 ||
            info->return_type == SYSARG_TYPE_BOOL8 ||
            info->return_type == DRSYS_TYPE_HANDLE ||
            info->return_type == DRSYS_TYPE_POINTER)
            return (res != 0);
        if (TEST(SYSINFO_RET_MINUS1_FAIL, info->flags))
            return (res != -1);
        /* i#486, i#932: syscalls that return the capacity needed in an OUT
         * param will still write to it when returning STATUS_BUFFER_TOO_SMALL
         */
        if (TEST(SYSINFO_RET_SMALL_WRITE_LAST, info->flags) &&
            (res == STATUS_BUFFER_TOO_SMALL ||
             res == STATUS_INFO_LENGTH_MISMATCH))
            return true;
    }
    if (res == STATUS_BUFFER_OVERFLOW) {
        /* Data is filled in so consider success (i#358) */
        return true;
    }
    return NT_SUCCESS(res);
}

/***************************************************************************
 * SYSTEM CALL TYPE
 */

DR_EXPORT
drmf_status_t
drsys_syscall_type(drsys_syscall_t *syscall, drsys_syscall_type_t *type OUT)
{
    syscall_info_t *sysinfo = (syscall_info_t *) syscall;
    if (syscall == NULL || type == NULL)
        return DRMF_ERROR_INVALID_PARAMETER;
    if ((sysinfo >= &syscall_user32_info[0] &&
         sysinfo <= &syscall_user32_info[num_user32_syscalls()-1]) ||
        (sysinfo >= &syscall_usercall_info[0] &&
         sysinfo <= &syscall_usercall_info[num_usercall_syscalls()-1]))
        *type = DRSYS_SYSCALL_TYPE_USER;
    else if (sysinfo >= &syscall_gdi32_info[0] &&
             sysinfo <= &syscall_gdi32_info[num_gdi32_syscalls()-1])
        *type = DRSYS_SYSCALL_TYPE_GRAPHICS;
    else
        *type = DRSYS_SYSCALL_TYPE_KERNEL;
    return DRMF_SUCCESS;
}


/***************************************************************************
 * SHADOW PER-ARG-TYPE HANDLING
 */

static bool
handle_port_message_access(sysarg_iter_info_t *ii,
                           const syscall_arg_t *arg_info,
                           app_pc start, uint size)
{
    /* variable-length */
    PORT_MESSAGE pm;
    if (TEST(SYSARG_WRITE, arg_info->flags) && ii->arg->pre &&
        !TEST(SYSARG_READ, arg_info->flags)) {
        /* Struct is passed in uninit w/ max-len buffer after it.
         * FIXME i#415: There is some ambiguity over the max, hence we choose
         * the lower estimation to avoid false positives.
         * (We'll still use sizeof(PORT_MESSAGE) + PORT_MAXIMUM_MESSAGE_LENGTH
         *  in the ASSERTs below)
         * We'll re-do the addressability check at the post- hook as part
         * of handling SYSARG_WRITE in any case.
         */
        size = PORT_MAXIMUM_MESSAGE_LENGTH;
    } else if (safe_read(start, sizeof(pm), &pm)) {
        if (pm.u1.s1.DataLength > 0 ||
            /* i#865: sometimes data has 0 length */
            (pm.u1.s1.DataLength == 0 && pm.u1.s1.TotalLength > 0))
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
        LOG(2, "total size of PORT_MESSAGE arg %d is %d\n", arg_info->param, size);
    } else {
        /* can't read real size, so report presumed-unaddr w/ struct size */
        ASSERT(size == sizeof(PORT_MESSAGE), "invalid PORT_MESSAGE sysarg size");
        /* XXX: should we mark arg->valid as false?  though start addr
         * is known: it's just size.  Could change meaning of valid as it's
         * not really used for memargs right now.
         */
    }

    if (!report_memarg(ii, arg_info, start, size, NULL))
        return true;
    return true;
}

static bool
handle_context_access(sysarg_iter_info_t *ii,
                      const syscall_arg_t *arg_info,
                      app_pc start, uint size)
{
#if !defined(_X86_) || defined(X64)
    ASSERT_NOT_IMPLEMENTED();
    return true;
#else /* defined(_X86_) */
    /* The 'cxt' pointer will only be used for retrieving pointers
     * for the CONTEXT fields, hence we can do without safe_read.
     */
    const CONTEXT *cxt = (CONTEXT *)start;
    DWORD context_flags;
    if (!report_memarg(ii, arg_info, start, sizeof(context_flags),
                       "CONTEXT.ContextFlags"))
        return true;
    if (!safe_read((void*)&cxt->ContextFlags, sizeof(context_flags),
                   &context_flags)) {
        /* if safe_read fails due to CONTEXT being unaddr, the preceding
         * report_memarg should have raised the error, and there's
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
        if (!report_memarg(ii, arg_info,
                           (app_pc)&cxt->Dr0, CONTEXT_NUM_DEBUG_REGS*sizeof(DWORD),
                           "CONTEXT.DrX"))
            return true;
    }
    if (TESTALL(CONTEXT_FLOATING_POINT, context_flags)) {
        if (!report_memarg(ii, arg_info,
                           (app_pc)&cxt->FloatSave, sizeof(cxt->FloatSave),
                           "CONTEXT.FloatSave"))
            return true;
    }
    /* Segment registers are 16-bits each but stored with 16-bit gaps
     * so we can't use sizeof(cxt->Seg*s);
     */
#define SIZE_SEGMENT_REG 2
    if (TESTALL(CONTEXT_SEGMENTS, context_flags)) {
        if (!report_memarg(ii, arg_info,
                           (app_pc)&cxt->SegGs, SIZE_SEGMENT_REG, "CONTEXT.SegGs"))
            return true;
        if (!report_memarg(ii, arg_info,
                           (app_pc)&cxt->SegFs, SIZE_SEGMENT_REG, "CONTEXT.SegFs"))
            return true;
        if (!report_memarg(ii, arg_info,
                           (app_pc)&cxt->SegEs, SIZE_SEGMENT_REG, "CONTEXT.SegEs"))
            return true;
        if (!report_memarg(ii, arg_info,
                           (app_pc)&cxt->SegDs, SIZE_SEGMENT_REG, "CONTEXT.SegDs"))
            return true;
    }
    if (TESTALL(CONTEXT_INTEGER, context_flags) &&
        ii->arg->sysnum.number != sysnum_CreateThread.number) {
        /* For some reason, cxt->Edi...Eax are not initialized when calling
         * NtCreateThread though CONTEXT_INTEGER flag is set
         */
#define CONTEXT_NUM_INT_REGS 6
        if (!report_memarg(ii, arg_info,
                           (app_pc)&cxt->Edi, CONTEXT_NUM_INT_REGS*sizeof(DWORD),
                           "CONTEXT.Exx"))
            return true;
    }
    if (TESTALL(CONTEXT_CONTROL, context_flags)) {
        if (ii->arg->sysnum.number != sysnum_CreateThread.number) {
            /* Ebp is not initialized when calling NtCreateThread,
             * so we skip it
             */
            if (!report_memarg(ii, arg_info,
                               (app_pc)&cxt->Ebp, sizeof(DWORD), "CONTEXT.Ebp"))
                return true;
        }
        if (!report_memarg(ii, arg_info,
                           (app_pc)&cxt->Eip, sizeof(cxt->Eip), "CONTEXT.Eip"))
            return true;
        if (!report_memarg(ii, arg_info,
                           (app_pc)&cxt->Esp, sizeof(cxt->Esp), "CONTEXT.Esp"))
            return true;
        if (!report_memarg(ii, arg_info,
                           (app_pc)&cxt->EFlags, sizeof(cxt->EFlags), "CONTEXT.Eflags"))
            return true;
        if (!report_memarg(ii, arg_info,
                           (app_pc)&cxt->SegCs, SIZE_SEGMENT_REG, "CONTEXT.SegCs"))
            return true;
        if (!report_memarg(ii, arg_info,
                           (app_pc)&cxt->SegSs, SIZE_SEGMENT_REG, "CONTEXT.SegSs"))
            return true;
    }
    if (TESTALL(CONTEXT_EXTENDED_REGISTERS, context_flags)) {
        if (!report_memarg(ii, arg_info, (app_pc)&cxt->ExtendedRegisters,
                           sizeof(cxt->ExtendedRegisters), "CONTEXT.ExtendedRegisters"))
            return true;
    }
    return true;
#endif
}

static bool
handle_exception_record_access(sysarg_iter_info_t *ii,
                               const syscall_arg_t *arg_info,
                               app_pc start, uint size)
{
    const EXCEPTION_RECORD *er = (EXCEPTION_RECORD *)start;
    DWORD num_params;
    /* According to MSDN, NumberParameters stores the number of defined
     * elements of the ExceptionInformation array
     * at the end of the EXCEPTION_RECORD structure.
     * http://msdn.microsoft.com/en-us/library/aa363082(VS.85).aspx
     */
    if (!report_memarg(ii, arg_info, start, sizeof(*er) - sizeof(er->ExceptionInformation),
                       "EXCEPTION_RECORD"))
        return true;
    ASSERT(sizeof(num_params) == sizeof(er->NumberParameters), "");
    if (safe_read((void*)&er->NumberParameters, sizeof(num_params),
                  &num_params)) {
        if (!report_memarg(ii, arg_info, (app_pc)er->ExceptionInformation,
                           num_params * sizeof(er->ExceptionInformation[0]),
                           "EXCEPTION_RECORD.ExceptionInformation"))
            return true;
    }
    return true;
}

static bool
handle_security_qos_access(sysarg_iter_info_t *ii,
                           const syscall_arg_t *arg_info,
                           app_pc start, uint size)
{
    const SECURITY_QUALITY_OF_SERVICE *s = (SECURITY_QUALITY_OF_SERVICE *)start;
    /* The SECURITY_QUALITY_OF_SERVICE structure is
     * DWORD + DWORD + unsigned char + BOOLEAN
     * so it takes 12 bytes (and its Length field value is 12)
     * but only 10 must be initialized.
     */
    if (!report_memarg(ii, arg_info, start,
                       sizeof(s->Length) + sizeof(s->ImpersonationLevel) +
                       sizeof(s->ContextTrackingMode) + sizeof(s->EffectiveOnly),
                       NULL))
        return true;
    return true;
}

static bool
handle_security_descriptor_access(sysarg_iter_info_t *ii,
                                  const syscall_arg_t *arg_info,
                                  app_pc start, uint size)
{
    const SECURITY_DESCRIPTOR *s = (SECURITY_DESCRIPTOR *)start;
    SECURITY_DESCRIPTOR_CONTROL flags;
    ASSERT(s != NULL, "descriptor must not be NULL"); /* caller should check */
    ASSERT(!TEST(SYSARG_WRITE, arg_info->flags), "Should only be called for reads");
    if (!ii->arg->pre) {
        /* Handling pre- is enough for reads */
        return true;
    }
    /* The SECURITY_DESCRIPTOR structure has two fields at the end (Sacl, Dacl)
     * which must be init only when the corresponding bits of Control are set.
     */
    ASSERT(start + sizeof(*s) == (app_pc)&s->Dacl + sizeof(s->Dacl), "");
    if (!report_memarg(ii, arg_info, start, (app_pc)&s->Sacl - start, NULL))
        return true;

    ASSERT(sizeof(flags) == sizeof(s->Control), "");
    if (safe_read((void*)&s->Control, sizeof(flags), &flags)) {
        if (TEST(SE_SACL_PRESENT, flags)) {
            if (!report_memarg(ii, arg_info, (app_pc)&s->Sacl, sizeof(s->Sacl), NULL))
                return true;
        }
        if (TEST(SE_DACL_PRESENT, flags)) {
            if (!report_memarg(ii, arg_info, (app_pc)&s->Dacl, sizeof(s->Dacl), NULL))
                return true;
        }
    }
    return true;
}

bool
handle_unicode_string_access(sysarg_iter_info_t *ii, const syscall_arg_t *arg_info,
                             app_pc start, uint size, bool ignore_len)
{
    UNICODE_STRING us;
    UNICODE_STRING *arg = (UNICODE_STRING *) start;
    ASSERT(size == sizeof(UNICODE_STRING), "invalid size");

    /* i#99: for optional params, we ignore if NULL. This may lead to false negatives */
    if (arg == NULL)
        return true;

    /* we assume OUT fields just have their Buffer as OUT */
    if (ii->arg->pre) {
        if (TEST(SYSARG_READ, arg_info->flags)) {
            if (!report_memarg(ii, arg_info, (byte *)&arg->Length,
                               sizeof(arg->Length), "UNICODE_STRING.Length"))
                return true;
            /* i#519: MaximumLength may not be initialized in case of IN params. */
        } else {
            if (!report_memarg_type(ii, arg_info->param, SYSARG_READ,
                                    (byte *)&arg->MaximumLength,
                                    sizeof(arg->MaximumLength),
                                    "UNICODE_STRING.MaximumLength",
                                    DRSYS_TYPE_UNICODE_STRING, NULL))
                return true;
            /* i#519: Length may not be initialized in case of OUT params. */
        }
        if (!report_memarg(ii, arg_info, (byte *)&arg->Buffer,
                           sizeof(arg->Buffer), "UNICODE_STRING.Buffer"))
            return true;
    }
    if (safe_read((void*)start, sizeof(us), &us)) {
        LOG(SYSCALL_VERBOSE,
            "UNICODE_STRING Buffer="PFX" Length=%d MaximumLength=%d\n",
            (byte *)us.Buffer, us.Length, us.MaximumLength);
        if (ii->arg->pre) {
            if (TEST(SYSARG_READ, arg_info->flags)) {
                /* For IN params, the buffer size is passed as us.Length */
                ASSERT(!ignore_len, "Length must be defined for IN params");
                /* XXX i#519: Length doesn't include NULL, but NULL seems
                 * to be optional, though there is inconsistency.  While it
                 * would be nice to clean up code by complaining if it's
                 * not there, we'd hit false positives in
                 * non-user-controlled code.
                 */
                if (!report_memarg(ii, arg_info, (byte *)us.Buffer, us.Length,
                                   "UNICODE_STRING content"))
                    return true;
            } else {
                /* For OUT params, MaximumLength-sized buffer should be addressable. */
                if (!report_memarg(ii, arg_info, (byte *)us.Buffer, us.MaximumLength,
                                   "UNICODE_STRING capacity"))
                    return true;
            }
        } else if (us.MaximumLength > 0) {
            /* Reminder: we don't do post-processing of IN params. */
            if (ignore_len) {
                /* i#490: wrong Length stored so as workaround we walk the string */
                handle_cwstring(ii, "UNICODE_STRING content",
                                (byte *)us.Buffer, us.MaximumLength,
                                arg_info->param, arg_info->flags, NULL, false);
                if (ii->abort)
                    return true;
            } else {
                if (!report_memarg(ii, arg_info, (byte *)us.Buffer,
                                   /* Length field does not include final NULL.
                                    * We mark it defined even though it may be optional
                                    * in some situations: i#519.
                                    */
                                   us.Length+sizeof(wchar_t),
                                   "UNICODE_STRING content"))
                    return true;
            }
        }
    } else
        WARN("WARNING: unable to read syscall param\n");
    return true;
}

bool
handle_object_attributes_access(sysarg_iter_info_t *ii,
                                const syscall_arg_t *arg_info,
                                app_pc start, uint size)
{
    OBJECT_ATTRIBUTES oa;
    ASSERT(size == sizeof(OBJECT_ATTRIBUTES), "invalid size");
    if (!report_memarg(ii, arg_info, start, size, "OBJECT_ATTRIBUTES fields"))
        return true;
    if (safe_read((void*)start, sizeof(oa), &oa)) {
        if ((byte *) oa.ObjectName != NULL) {
            handle_unicode_string_access(ii, arg_info, (byte *) oa.ObjectName,
                                         sizeof(*oa.ObjectName), false);
        }
        if (ii->abort)
            return true;
        if ((byte *) oa.SecurityDescriptor != NULL) {
            handle_security_descriptor_access(ii, arg_info,
                                              (byte *) oa.SecurityDescriptor,
                                              sizeof(SECURITY_DESCRIPTOR));
        }
        if (ii->abort)
            return true;
        if ((byte *) oa.SecurityQualityOfService != NULL) {
            handle_security_qos_access(ii, arg_info,
                                       (byte *) oa.SecurityQualityOfService,
                                       sizeof(SECURITY_QUALITY_OF_SERVICE));
        }
        if (ii->abort)
            return true;
    } else
        WARN("WARNING: unable to read syscall param\n");
    return true;
}

/* pass 0 for size if there is no max size */
bool
handle_cwstring(sysarg_iter_info_t *ii, const char *id,
                byte *start, size_t size/*in bytes*/, int ordinal, uint arg_flags,
                wchar_t *safe, bool check_addr)
{
    /* the kernel wrote a wide string to the buffer: only up to the terminating
     * null should be marked as defined
     */
    uint i;
    wchar_t c;
    /* input params have size 0: for safety stopping at MAX_PATH */
    size_t maxsz = (size == 0) ? (MAX_PATH*sizeof(wchar_t)) : size;
    if (start == NULL)
        return false; /* nothing to do */
    if (ii->arg->pre && !TEST(SYSARG_READ, arg_flags)) {
        if (!check_addr)
            return false;
        if (size > 0) {
            /* if max size specified, on pre-write check whole thing for addr */
            if (!report_memarg_type(ii, ordinal, arg_flags, start, size, id,
                                    DRSYS_TYPE_CSTRING, NULL))
                return true;
            return true;
        }
    }
    if (!ii->arg->pre && !TEST(SYSARG_WRITE, arg_flags))
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
    if (!report_memarg_type(ii, ordinal, arg_flags, start, i + sizeof(wchar_t), id,
                            DRSYS_TYPE_CSTRING, NULL))
        return true;
    return true;
}

static bool
handle_cstring_wide_access(sysarg_iter_info_t *ii,
                           const syscall_arg_t *arg_info,
                           app_pc start, uint size/*in bytes*/)
{
    return handle_cwstring(ii, NULL, start, size, arg_info->param, arg_info->flags, NULL,
                           /* let normal check ensure full size is addressable (since
                            * OUT user must pass in max size) 
                            */
                           false);
}

static bool
handle_alpc_port_attributes_access(sysarg_iter_info_t *ii,
                                   const syscall_arg_t *arg_info,
                                   app_pc start, uint size)
{
    ALPC_PORT_ATTRIBUTES *apa = (ALPC_PORT_ATTRIBUTES *) start;
    ASSERT(size == sizeof(ALPC_PORT_ATTRIBUTES), "invalid size");
    
    if (ii->arg->pre) {
        if (!report_memarg_ex(ii, arg_info->param, DRSYS_PARAM_BOUNDS,
                              start, size, "ALPC_PORT_ATTRIBUTES",
                              DRSYS_TYPE_ALPC_PORT_ATTRIBUTES, NULL, DRSYS_TYPE_INVALID))
            return true;
    }
    if (!report_memarg(ii, arg_info, (byte *) &apa->Flags, sizeof(apa->Flags),
                       "ALPC_PORT_ATTRIBUTES.Flags"))
        return true;
    handle_security_qos_access(ii, arg_info, (byte *) &apa->SecurityQos,
                               sizeof(SECURITY_QUALITY_OF_SERVICE));
    if (ii->abort)
        return true;
    if (!report_memarg(ii, arg_info, (byte *) &apa->MaxMessageLength,
                       ((byte *) &apa->MaxTotalSectionSize) +
                       sizeof(apa->MaxTotalSectionSize) -
                       (byte *) &apa->MaxMessageLength,
                       "ALPC_PORT_ATTRIBUTES MaxMessageLength..MaxTotalSectionSize"))
        return true;
    return true;
}

static bool
handle_alpc_security_attributes_access(sysarg_iter_info_t *ii,
                                       const syscall_arg_t *arg_info,
                                       app_pc start, uint size)
{
    ALPC_SECURITY_ATTRIBUTES asa;
    ALPC_SECURITY_ATTRIBUTES *arg = (ALPC_SECURITY_ATTRIBUTES *) start;
    ASSERT(size == sizeof(ALPC_SECURITY_ATTRIBUTES), "invalid size");

    if (!report_memarg(ii, arg_info, start, sizeof(arg->Flags) +
                       sizeof(arg->SecurityQos) + sizeof(arg->ContextHandle),
                       "ALPC_SECURITY_ATTRIBUTES fields"))
        return true;
    if (safe_read((void*)start, sizeof(asa), &asa)) {
        handle_security_qos_access(ii, arg_info,
                                   (byte *) asa.SecurityQos,
                                   sizeof(SECURITY_QUALITY_OF_SERVICE));
        if (ii->abort)
            return true;
    } else
        WARN("WARNING: unable to read syscall param\n");
    return true;
}

static bool
os_handle_syscall_arg_access(sysarg_iter_info_t *ii,
                             const syscall_arg_t *arg_info,
                             app_pc start, uint size)
{
    if (!TEST(SYSARG_COMPLEX_TYPE, arg_info->flags))
        return false;

    switch (arg_info->misc) {
    case SYSARG_TYPE_PORT_MESSAGE:
        return handle_port_message_access(ii, arg_info, start, size);
    case SYSARG_TYPE_CONTEXT:
        return handle_context_access(ii, arg_info, start, size);
    case SYSARG_TYPE_EXCEPTION_RECORD:
        return handle_exception_record_access(ii, arg_info, start, size);
    case SYSARG_TYPE_SECURITY_QOS:
        return handle_security_qos_access(ii, arg_info, start, size);
    case SYSARG_TYPE_SECURITY_DESCRIPTOR:
        return handle_security_descriptor_access(ii, arg_info, start, size);
    case SYSARG_TYPE_UNICODE_STRING:
        return handle_unicode_string_access(ii, arg_info, start, size, false);
    case SYSARG_TYPE_UNICODE_STRING_NOLEN:
        return handle_unicode_string_access(ii, arg_info, start, size, true);
    case SYSARG_TYPE_OBJECT_ATTRIBUTES:
        return handle_object_attributes_access(ii, arg_info, start, size);
    case SYSARG_TYPE_CSTRING_WIDE:
        return handle_cstring_wide_access(ii, arg_info, start, size);
    case SYSARG_TYPE_ALPC_PORT_ATTRIBUTES:
        return handle_alpc_port_attributes_access(ii, arg_info, start, size);
    case SYSARG_TYPE_ALPC_SECURITY_ATTRIBUTES:
        return handle_alpc_security_attributes_access(ii, arg_info, start, size);
    }
    return wingdi_process_arg(ii, arg_info, start, size);
}

bool
os_handle_pre_syscall_arg_access(sysarg_iter_info_t *ii,
                                 const syscall_arg_t *arg_info,
                                 app_pc start, uint size)
{
    return os_handle_syscall_arg_access(ii, arg_info, start, size);
}

bool
os_handle_post_syscall_arg_access(sysarg_iter_info_t *ii,
                                  const syscall_arg_t *arg_info,
                                  app_pc start, uint size)
{
    return os_handle_syscall_arg_access(ii, arg_info, start, size);
}

/***************************************************************************
 * SHADOW PER-SYSCALL HANDLING
 */

typedef LONG KPRIORITY;
typedef struct _PROCESS_BASIC_INFORMATION {
    NTSTATUS ExitStatus;
    PPEB PebBaseAddress;
    ULONG_PTR AffinityMask;
    KPRIORITY BasePriority;
    ULONG_PTR UniqueProcessId;
    ULONG_PTR InheritedFromUniqueProcessId;
} PROCESS_BASIC_INFORMATION;
typedef PROCESS_BASIC_INFORMATION *PPROCESS_BASIC_INFORMATION;

GET_NTDLL(NtQueryInformationProcess, (IN HANDLE ProcessHandle,
                                      IN PROCESSINFOCLASS ProcessInformationClass,
                                      OUT PVOID ProcessInformation,
                                      IN ULONG ProcessInformationLength,
                                      OUT PULONG ReturnLength OPTIONAL));

static TEB *
get_TEB(void)
{
#ifdef X64
    return (TEB *) __readgsqword(offsetof(TEB, Self));
#else
    return (TEB *) __readfsdword(offsetof(TEB, Self));
#endif
}

static uint
getpid(void)
{
    return (uint) get_TEB()->ClientId.UniqueProcess;
}

DR_EXPORT
drmf_status_t
drsys_handle_is_current_process(HANDLE h, bool *current)
{
    uint pid, got;
    PROCESS_BASIC_INFORMATION info;
    NTSTATUS res;
    if (current == NULL)
        return DRMF_ERROR_INVALID_PARAMETER;
    if (h == NT_CURRENT_PROCESS) {
        *current = true;
        return DRMF_SUCCESS;
    }
    if (h == NULL) {
        *current = false;
        return DRMF_SUCCESS;
    }
    memset(&info, 0, sizeof(PROCESS_BASIC_INFORMATION));
    res = NtQueryInformationProcess(h, ProcessBasicInformation,
                                    &info, sizeof(PROCESS_BASIC_INFORMATION), &got);
    if (!NT_SUCCESS(res) || got != sizeof(PROCESS_BASIC_INFORMATION)) {
        ASSERT(false, "internal error");
        return DRMF_ERROR; /* better to have false positives than negatives? */
    }
    *current = (info.UniqueProcessId == getpid());
    return DRMF_SUCCESS;
}

static void
handle_post_CreateThread(void *drcontext, cls_syscall_t *pt, sysarg_iter_info_t *ii)
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
        bool cur_proc;
        /* If not suspended, let set_thread_initial_structures() handle it to
         * avoid races: though since setting as defined the only race would be
         * the thread exiting
         */
        if (pt->sysarg[7]/*bool suspended*/ &&
            drsys_handle_is_current_process((HANDLE)pt->sysarg[3], &cur_proc) ==
            DRMF_SUCCESS && cur_proc &&
            safe_read((byte *)pt->sysarg[0], sizeof(thread_handle), &thread_handle)) {
            /* XXX: this is a new thread.  Should we tell the user to treat
             * its TEB as newly defined memory?
             */
        }
    }
}

static void
handle_pre_CreateThreadEx(void *drcontext, cls_syscall_t *pt, sysarg_iter_info_t *ii)
{
    bool cur_proc;
    if (drsys_handle_is_current_process((HANDLE)pt->sysarg[3], &cur_proc) ==
        DRMF_SUCCESS && cur_proc) {
        create_thread_info_t info;
        if (safe_read(&((create_thread_info_t *)pt->sysarg[10])->struct_size,
                      sizeof(info.struct_size), &info.struct_size)) {
            if (info.struct_size > sizeof(info)) {
                DO_ONCE({ WARN("WARNING: create_thread_info_t size too large\n"); });
                info.struct_size = sizeof(info);  /* avoid overflowing the struct */
            }
            if (safe_read((byte *)pt->sysarg[10], info.struct_size, &info)) {
                if (!report_memarg_type(ii, 10, SYSARG_READ, (byte *)pt->sysarg[10],
                                        info.struct_size, "create_thread_info_t",
                                        DRSYS_TYPE_STRUCT, NULL))
                    return;
                if (info.struct_size > offsetof(create_thread_info_t, client_id)) {
                    if (!report_memarg_type(ii, 10, SYSARG_WRITE, info.client_id.buffer,
                                            info.client_id.buffer_size, "PCLIENT_ID",
                                            DRSYS_TYPE_STRUCT, NULL))
                        return;
                }
                if (info.struct_size > offsetof(create_thread_info_t, teb)) {
                    /* This is optional, and omitted in i#342 */
                    if (!report_memarg_type(ii, 10, SYSARG_WRITE, info.teb.buffer,
                                            info.teb.buffer_size, "PTEB",
                                            DRSYS_TYPE_STRUCT, NULL))
                        return;
                }
            }
        }
    }
}

static void
handle_post_CreateThreadEx(void *drcontext, cls_syscall_t *pt, sysarg_iter_info_t *ii)
{
    bool cur_proc;
    if (drsys_handle_is_current_process((HANDLE)pt->sysarg[3], &cur_proc) ==
        DRMF_SUCCESS && cur_proc &&
        NT_SUCCESS(dr_syscall_get_result(drcontext))) {
        HANDLE thread_handle;
        create_thread_info_t info;
        /* See notes in handle_post_CreateThread() */
        if (pt->sysarg[6]/*bool suspended*/ &&
            safe_read((byte *)pt->sysarg[0], sizeof(thread_handle), &thread_handle)) {
            /* XXX: this is a new thread.  Should we tell the user to treat
             * its TEB as newly defined memory?
             */
        }
        if (safe_read(&((create_thread_info_t *)pt->sysarg[10])->struct_size,
                      sizeof(info.struct_size), &info.struct_size)) {
            if (info.struct_size > sizeof(info)) {
                info.struct_size = sizeof(info);  /* avoid overflowing the struct */
            }
            if (safe_read((byte *)pt->sysarg[10], info.struct_size, &info)) {
                if (info.struct_size > offsetof(create_thread_info_t, client_id)) {
                    if (!report_memarg_type(ii, 10, SYSARG_WRITE, info.client_id.buffer,
                                            info.client_id.buffer_size, "PCLIENT_ID",
                                            DRSYS_TYPE_STRUCT, NULL))
                        return;
                }
                if (info.struct_size > offsetof(create_thread_info_t, teb)) {
                    if (!report_memarg_type(ii, 10, SYSARG_WRITE, info.teb.buffer,
                                            info.teb.buffer_size, "PTEB",
                                            DRSYS_TYPE_STRUCT, NULL))
                        return;
                }
            }
        }
    }
}

static void
handle_pre_CreateUserProcess(void *drcontext, cls_syscall_t *pt, sysarg_iter_info_t *ii)
{
    create_proc_thread_info_t info;
    if (safe_read((byte *)pt->sysarg[10], sizeof(info), &info)) {
        if (!report_memarg_type(ii, 10, SYSARG_READ, info.nt_path_to_exe.buffer,
                                info.nt_path_to_exe.buffer_size, "path to exe",
                                DRSYS_TYPE_CWARRAY, param_type_names[DRSYS_TYPE_CWARRAY]))
            return;
        if (!report_memarg_type(ii, 10, SYSARG_WRITE, info.client_id.buffer,
                                info.client_id.buffer_size, "PCLIENT_ID",
                                DRSYS_TYPE_STRUCT, NULL))
            return;
        if (!report_memarg_type(ii, 10, SYSARG_WRITE, info.exe_stuff.buffer,
                                info.exe_stuff.buffer_size, "exe stuff",
                                DRSYS_TYPE_STRUCT, NULL))
            return;
        /* XXX i#98: there are other IN/OUT params but exact form not clear */
    }
}

static void
handle_post_CreateUserProcess(void *drcontext, cls_syscall_t *pt, sysarg_iter_info_t *ii)
{
    if (NT_SUCCESS(dr_syscall_get_result(drcontext))) {
        create_proc_thread_info_t info;
        if (safe_read((byte *)pt->sysarg[10], sizeof(info), &info)) {
            if (!report_memarg_type(ii, 10, SYSARG_WRITE, info.client_id.buffer,
                                    info.client_id.buffer_size, "PCLIENT_ID",
                                    DRSYS_TYPE_STRUCT, NULL))
                return;
            if (!report_memarg_type(ii, 10, SYSARG_WRITE, info.exe_stuff.buffer,
                                    info.exe_stuff.buffer_size, "exe_stuff",
                                    DRSYS_TYPE_STRUCT, NULL))
                return;
            /* XXX i#98: there are other IN/OUT params but exact form not clear */
        }
    }
}

static void
handle_QuerySystemInformation(void *drcontext, cls_syscall_t *pt, sysarg_iter_info_t *ii)
{
    /* Normally the buffer is just output.  For the input case here we
     * will mark the buffer as defined b/c of the regular table processing:
     * not a big deal as we'll report any uninit prior to that.
     */
    SYSTEM_INFORMATION_CLASS cls = (SYSTEM_INFORMATION_CLASS) pt->sysarg[0];
    if (cls == SystemSessionProcessesInformation) {
        SYSTEM_SESSION_PROCESS_INFORMATION buf;
        if (ii->arg->pre) {
            if (!report_memarg_type(ii, 1, SYSARG_READ, (byte *)pt->sysarg[1],
                                    sizeof(buf), "SYSTEM_SESSION_PROCESS_INFORMATION",
                                    DRSYS_TYPE_STRUCT, NULL))
                return;
        }
        if (safe_read((byte *) pt->sysarg[1], sizeof(buf), &buf)) {
            if (!report_memarg_type(ii, 1, SYSARG_WRITE,
                                    buf.Buffer, buf.SizeOfBuf, "Buffer",
                                    DRSYS_TYPE_STRUCT, NULL))
                return;
        }
    }
    /* i#932: The kernel always writes the size needed info ReturnLength, even
     * on error.  However, for some classes of info, Nebbet claims this value
     * may be zero.  For DrMemory, we can handle this with
     * SYSINFO_RET_SMALL_WRITE_LAST.
     */
}

static void
handle_SetSystemInformation(void *drcontext, cls_syscall_t *pt, sysarg_iter_info_t *ii)
{
    /* Normally the buffer is just input, but some info classes write data */
    SYSTEM_INFORMATION_CLASS cls = (SYSTEM_INFORMATION_CLASS) pt->sysarg[0];
    if (ii->arg->pre)
        return;
    /* Nebbett had this as SystemLoadImage and SYSTEM_LOAD_IMAGE */
    if (cls == SystemLoadGdiDriverInformation) {
        SYSTEM_GDI_DRIVER_INFORMATION *buf =
            (SYSTEM_GDI_DRIVER_INFORMATION *) pt->sysarg[1];
        if (!report_memarg_type(ii, 1, SYSARG_WRITE, (byte *) &buf->ImageAddress,
                                sizeof(*buf) -
                                offsetof(SYSTEM_GDI_DRIVER_INFORMATION, ImageAddress),
                                "loaded image info", DRSYS_TYPE_STRUCT, NULL))
            return;
        /* Nebbett had this as SystemCreateSession and SYSTEM_CREATE_SESSION */
    } else if (cls == SystemSessionCreate) {
        /* Just a ULONG, no struct */
        if (!report_memarg_type(ii, 1, SYSARG_WRITE, (byte *) pt->sysarg[1],
                                sizeof(ULONG), "session id", DRSYS_TYPE_INT, NULL))
            return;
    }
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

/* winioctl.h provides:
 * CTL_CODE: Forms code from dev_type, function, access, method.
 * DEVICE_TYPE_FROM_CTL_CODE: Extracts device bits.
 * METHOD_FROM_CTL_CODE: Extracts method bits.
 *
 * Below we provide macros to get the other bits.
 */
#define FUNCTION_FROM_CTL_CODE(code) (((code) >> 2) & 0xfff)
#define ACCESS_FROM_CTL_CODE(code) (((code) >> 14) & 0x3)

/* The AFD (Ancillary Function Driver, afd.sys, for winsock)
 * ioctls don't follow the regular CTL_CODE where the device is << 16.
 * Instead they have the device (FILE_DEVICE_NETWORK == 0x12) << 12,
 * and the function << 2, with access bits always set to 0.
 * NtDeviceIoControlFile only looks at the access and method bits
 * though.
 *
 * FIXME this is not foolproof: could be FILE_DEVICE_BEEP with other bits.
 */
#define IS_AFD_IOCTL(code) ((code >> 12) == FILE_DEVICE_NETWORK)
/* Since the AFD "device" overlaps with the function, we have to mask out those
 * overlapping high bits to get the right code.
 */
#define AFD_FUNCTION_FROM_CTL_CODE(code) \
        (FUNCTION_FROM_CTL_CODE(code) & 0x3ff)

#define IOCTL_INBUF_ARGNUM 6
#define IOCTL_OUTBUF_ARGNUM 8

/* XXX: very similar to Linux layouts, though exact constants are different.
 * Still, should be able to share some code.
 */
static void
check_sockaddr(cls_syscall_t *pt, sysarg_iter_info_t *ii, byte *ptr,
               size_t len, bool inbuf, const char *id)
{
    int ordinal = inbuf ? IOCTL_INBUF_ARGNUM : IOCTL_OUTBUF_ARGNUM;
    uint arg_flags = inbuf ? SYSARG_READ : SYSARG_WRITE;
    handle_sockaddr(pt, ii, ptr, len, ordinal, arg_flags, id);
}

/* Macros for shorter, easier-to-read code */
/* N.B.: these return directly, so do not use in functions that need cleanup! */
#define CHECK_DEF(ii, ptr, sz, id) do {                                        \
    if (!report_memarg_type(ii, IOCTL_INBUF_ARGNUM, SYSARG_READ, (byte *)(ptr),\
                            sz, id, DRSYS_TYPE_STRUCT, NULL))                  \
        return;                                                                \
} while (0)
#define CHECK_ADDR(ii, ptr, sz, id) do {                                         \
    if (!report_memarg_type(ii, IOCTL_OUTBUF_ARGNUM, SYSARG_WRITE, (byte *)(ptr),\
                            sz, id, DRSYS_TYPE_STRUCT, NULL))                    \
        return;                                                                  \
} while (0)
#define MARK_WRITE(ii, ptr, sz, id) do {                                       \
    if (!report_memarg_type(ii, IOCTL_OUTBUF_ARGNUM, SYSARG_WRITE, ptr, sz, id,\
                            DRSYS_TYPE_STRUCT, NULL))                          \
        return;                                                                \
} while (0)
#define CHECK_OUT_PARAM(ii, ptr, sz, id) do {                                  \
    if (!report_memarg_type(ii, IOCTL_OUTBUF_ARGNUM, SYSARG_WRITE, ptr, sz, id,\
                            DRSYS_TYPE_STRUCT, NULL))                          \
        return;                                                                \
} while (0)

static void
handle_AFD_ioctl(void *drcontext, cls_syscall_t *pt, sysarg_iter_info_t *ii)
{
    uint full_code = (uint) pt->sysarg[5];
    byte *inbuf = (byte *) pt->sysarg[IOCTL_INBUF_ARGNUM];
    uint insz = (uint) pt->sysarg[7];
    /* FIXME: put max of insz on all the sizes below */

    /* Extract operation. */
    uint opcode = AFD_FUNCTION_FROM_CTL_CODE(full_code);

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
        if (ii->arg->pre)
            CHECK_DEF(ii, inbuf, insz, "AFD_RECV_INFO");

        if (inbuf == NULL || !safe_read(inbuf, sizeof(info), &info)) {
            WARN("WARNING: AFD_RECV: can't read param\n");
            break;
        }

        if (ii->arg->pre) {
            CHECK_DEF(ii, (byte *)info.BufferArray,
                      info.BufferCount * sizeof(*info.BufferArray),
                      "AFD_RECV_INFO.BufferArray");
        }

        for (i = 0; i < info.BufferCount; i++) {
            AFD_WSABUF buf;
            if (safe_read((char *)&info.BufferArray[i], sizeof(buf), &buf)) {
                if (ii->arg->pre)
                    CHECK_ADDR(ii, buf.buf, buf.len, "AFD_RECV_INFO.BufferArray[i].buf");
                else {
                    LOG(SYSCALL_VERBOSE, "\tAFD_RECV_INFO buf %d: "PFX"-"PFX"\n",
                        i, buf.buf, buf.len);
                    MARK_WRITE(ii, buf.buf, buf.len, "AFD_RECV_INFO.BufferArray[i].buf");
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
        if (ii->arg->pre)
            CHECK_DEF(ii, inbuf, insz, "AFD_RECV_INFO_UDP");

        if (inbuf == NULL || !safe_read(inbuf, sizeof(info), &info)) {
            WARN("WARNING: AFD_RECV_DATAGRAM: can't read param\n");
            break;
        }

        if (safe_read(info.AddressLength, sizeof(i), &i)) {
            if (ii->arg->pre)
                CHECK_ADDR(ii, (byte*)info.Address, i, "AFD_RECV_INFO_UDP.Address");
            else {
                /* XXX i#410: This API is asynch and info.Address is an
                 * outparam, so its possible that none of this data is written
                 * yet.  We conservatively assume the whole thing is written,
                 * rather than using check_sockaddr(), which will try to look at
                 * the unwritten sa_family field.
                 */
                MARK_WRITE(ii, (byte*)info.Address, i, "AFD_RECV_INFO_UDP.Address");
            }
        } else
            WARN("WARNING: AFD_RECV_DATAGRAM: can't read AddressLength\n");

        if (ii->arg->pre) {
            CHECK_DEF(ii, info.BufferArray, info.BufferCount * sizeof(*info.BufferArray),
                      "AFD_RECV_INFO_UDP.BufferArray");
        }
        for (i = 0; i < info.BufferCount; i++) {
            AFD_WSABUF buf;
            if (safe_read((char *)&info.BufferArray[i], sizeof(buf), &buf)) {
                if (ii->arg->pre)
                    CHECK_ADDR(ii, buf.buf, buf.len, "AFD_RECV_INFO_UDP.BufferArray[i].buf");
                else {
                    LOG(SYSCALL_VERBOSE, "\tAFD_RECV_INFO_UDP buf %d: "PFX"-"PFX"\n",
                        i, buf.buf, buf.len);
                    MARK_WRITE(ii, buf.buf, buf.len, "AFD_RECV_INFO_UDP.BufferArray[i].buf");
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
        if (ii->arg->pre) {
            CHECK_DEF(ii, inbuf, offsetof(AFD_POLL_INFO, Handles),
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
            if (ii->arg->pre ) {
                CHECK_DEF(ii, &ptr->Handles[i], offsetof(AFD_HANDLE, Status),
                          "AFD_POLL_INFO.Handles[i]");
            } else {
              MARK_WRITE(ii, (byte*)&ptr->Handles[i].Status, sizeof(ptr->Handles[i].Status),
                          "AFD_POLL_INFO.Handles[i].Status");
            }
        }
        break;
    }
    case AFD_GET_TDI_HANDLES: { /* 13 == 0x12037 */
        if (ii->arg->pre) {
            /* I believe input is a uint of AFD_*_HANDLE flags */
            CHECK_DEF(ii, inbuf, insz, "AFD_GET_TDI_HANDLES flags");
            /* as usual the write param will be auto-checked for addressabilty */
        } else {
            uint outsz = (uint) pt->sysarg[9];
            AFD_TDI_HANDLE_DATA *info = (AFD_TDI_HANDLE_DATA *) pt->sysarg[8];
            uint flags;
            if (safe_read(inbuf, sizeof(flags), &flags) &&
                outsz == sizeof(*info)) {
                if (TEST(AFD_ADDRESS_HANDLE, flags)) {
                    MARK_WRITE(ii, (byte*)&info->TdiAddressHandle,
                               sizeof(info->TdiAddressHandle),
                               "AFD_TDI_HANDLE_DATA.TdiAddressHandle");
                }
                if (TEST(AFD_CONNECTION_HANDLE, flags)) {
                    MARK_WRITE(ii, (byte*)&info->TdiConnectionHandle,
                               sizeof(info->TdiConnectionHandle),
                               "AFD_TDI_HANDLE_DATA.TdiConnectionHandle");
                }
            } else
                WARN("WARNING: unreadable AFD_GET_TDI_HANDLES flags or invalid outsz\n");
        }
        break;
    }
    case AFD_GET_INFO: { /* 30 == 0x1207b */
        if (ii->arg->pre) {
            /* InputBuffer == AFD_INFO.  Only InformationClass need be defined. */
            CHECK_DEF(ii, inbuf, sizeof(((AFD_INFO*)0)->InformationClass),
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

    if (pre_post_ioctl || !ii->arg->pre) {
        return;
    }

    /* All the ioctls below need only pre- handling */
    switch (opcode) {
    case AFD_SET_INFO: { /* 14 == 0x1203b */
        /* InputBuffer == AFD_INFO.  If not LARGE_INTEGER, 2nd word can be undef.
         * Padding also need not be defined.
         */
        AFD_INFO info;
        CHECK_DEF(ii, inbuf, sizeof(info.InformationClass), "AFD_INFO.InformationClass");
        if (safe_read(inbuf, sizeof(info), &info)) {
            switch (info.InformationClass) {
            case AFD_INFO_BLOCKING_MODE:
                /* uses BOOLEAN in union */
                CHECK_DEF(ii, inbuf + offsetof(AFD_INFO, Information.Boolean),
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

        CHECK_DEF(ii, inbuf, sizeof(sd), "SOCKET_CONTEXT SharedData");
        if (!safe_read(inbuf, sizeof(sd), &sd)) {
            WARN("WARNING: AFD_SET_CONTEXT: can't read param\n");
            break;
        }

        /* Now that we know the exact layout we can re-read the SOCKET_CONTEXT */
        if (sd.HasGUID) {
            SOCKET_CONTEXT sc;
            CHECK_DEF(ii, inbuf, offsetof(SOCKET_CONTEXT, Padding),
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
            CHECK_DEF(ii, inbuf, offsetof(SOCKET_CONTEXT_NOGUID, Padding),
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

        check_sockaddr(pt, ii, l_addr_ptr, sd.SizeOfLocalAddress, true/*in*/,
                       "SOCKET_CONTEXT.LocalAddress");
        /* I'm treating these SOCKADDRS as var-len */
        check_sockaddr(pt, ii, r_addr_ptr, sd.SizeOfRemoteAddress, true/*in*/,
                       "SOCKET_CONTEXT.RemoteAddress");

        /* FIXME i#424: helper data could be a struct w/ padding. I have seen pieces of
         * it be uninit on XP. Just ignore the definedness check if helper data
         * is not trivial
         */
        if (helper_size <= 4)
            CHECK_DEF(ii, inbuf + helper_offs, helper_size, "SOCKET_CONTEXT.HelperData");
        break;
    }
    case AFD_BIND: { /* 0 == 0x12003 */
        /* InputBuffer == AFD_BIND_DATA.  Address.Address is var-len and mswsock.dll
         * seems to pass an over-estimate of the real size.
         */
        CHECK_DEF(ii, inbuf, offsetof(AFD_BIND_DATA, Address), "AFD_BIND_DATA pre-Address");
        check_sockaddr(pt, ii, inbuf + offsetof(AFD_BIND_DATA, Address),
                       insz - offsetof(AFD_BIND_DATA, Address), true/*in*/,
                       "AFD_BIND_DATA.Address");
        break;
    }
    case AFD_CONNECT: { /* 1 == 0x12007 */
        /* InputBuffer == AFD_CONNECT_INFO.  RemoteAddress.Address is var-len. */
        AFD_CONNECT_INFO *info = (AFD_CONNECT_INFO *) inbuf;
        /* Have to separate the Boolean since padding after it */
        CHECK_DEF(ii, inbuf, sizeof(info->UseSAN), "AFD_CONNECT_INFO.UseSAN");
        CHECK_DEF(ii, &info->Root, (byte*)&info->RemoteAddress - (byte*)&info->Root,
                  "AFD_CONNECT_INFO pre-RemoteAddress");
        check_sockaddr(pt, ii, (byte*)&info->RemoteAddress,
                       insz - offsetof(AFD_CONNECT_INFO, RemoteAddress),
                       true/*in*/, "AFD_CONNECT_INFO.RemoteAddress");
        break;
    }
    case AFD_DISCONNECT: { /* 10 == 0x1202b */
        /* InputBuffer == AFD_DISCONNECT_INFO.  Padding between fields need not be def. */
        AFD_DISCONNECT_INFO *info = (AFD_DISCONNECT_INFO *) inbuf;
        CHECK_DEF(ii, inbuf, sizeof(info->DisconnectType),
                  "AFD_DISCONNECT_INFO.DisconnectType");
        CHECK_DEF(ii, inbuf + offsetof(AFD_DISCONNECT_INFO, Timeout),
                  sizeof(info->Timeout), "AFD_DISCONNECT_INFO.Timeout");
        break;
    }
    case AFD_DEFER_ACCEPT: { /* 35 == 0x120bf */
        /* InputBuffer == AFD_DEFER_ACCEPT_DATA */
        AFD_DEFER_ACCEPT_DATA *info = (AFD_DEFER_ACCEPT_DATA *) inbuf;
        CHECK_DEF(ii, inbuf, sizeof(info->SequenceNumber),
                  "AFD_DEFER_ACCEPT_DATA.SequenceNumber");
        CHECK_DEF(ii, inbuf + offsetof(AFD_DEFER_ACCEPT_DATA, RejectConnection),
                  sizeof(info->RejectConnection),
                  "AFD_DEFER_ACCEPT_DATA.RejectConnection");
        break;
    }
    case AFD_SEND: { /* 7 == 0x1201f */
        /* InputBuffer == AFD_SEND_INFO */
        AFD_SEND_INFO info;
        CHECK_DEF(ii, inbuf, insz, "AFD_SEND_INFO"); /* no padding */
        if (safe_read(inbuf, sizeof(info), &info)) {
            uint i;
            CHECK_DEF(ii, info.BufferArray, info.BufferCount * sizeof(*info.BufferArray),
                      "AFD_SEND_INFO.BufferArray");
            for (i = 0; i < info.BufferCount; i++) {
                AFD_WSABUF buf;
                if (safe_read((char *)&info.BufferArray[i], sizeof(buf), &buf))
                    CHECK_DEF(ii, buf.buf, buf.len, "AFD_SEND_INFO.BufferArray[i].buf");
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
        CHECK_DEF(ii, inbuf, offsetof(AFD_SEND_INFO_UDP, UnknownGap),
                  "AFD_SEND_INFO_UDP before gap");
        if (safe_read(inbuf, offsetof(AFD_SEND_INFO_UDP, UnknownGap), &info)) {
            uint i;
            CHECK_DEF(ii, info.BufferArray, info.BufferCount * sizeof(*info.BufferArray),
                      "AFD_SEND_INFO_UDP.BufferArray");
            for (i = 0; i < info.BufferCount; i++) {
                AFD_WSABUF buf;
                if (safe_read((char *)&info.BufferArray[i], sizeof(buf), &buf))
                    CHECK_DEF(ii, buf.buf, buf.len, "AFD_SEND_INFO_UDP.BufferArray[i].buf");
                else
                    WARN("WARNING: AFD_SEND_DATAGRAM: can't read param\n");
            }
        } else
            WARN("WARNING: AFD_SEND_DATAGRAM: can't read param\n");
        CHECK_DEF(ii, inbuf + offsetof(AFD_SEND_INFO_UDP, SizeOfRemoteAddress),
                  sizeof(info.SizeOfRemoteAddress),
                  "AFD_SEND_INFO_UDP.SizeOfRemoteAddress");
        CHECK_DEF(ii, inbuf + offsetof(AFD_SEND_INFO_UDP, RemoteAddress),
                  sizeof(info.RemoteAddress),
                  "AFD_SEND_INFO_UDP.RemoteAddress");
        if (safe_read(inbuf + offsetof(AFD_SEND_INFO_UDP, SizeOfRemoteAddress),
                      sizeof(size_of_remote_address), &size_of_remote_address) &&
            safe_read(inbuf + offsetof(AFD_SEND_INFO_UDP, RemoteAddress),
                      sizeof(remote_address), &remote_address)) {
            CHECK_DEF(ii, remote_address, size_of_remote_address,
                      "AFD_SEND_INFO_UDP.RemoteAddress buffer");
        }

        break;
    }
    case AFD_EVENT_SELECT: { /* 33 == 0x12087 */
        CHECK_DEF(ii, inbuf, insz, "AFD_EVENT_SELECT_INFO");
        break;
    }
    case AFD_ENUM_NETWORK_EVENTS: { /* 34 == 0x1208b */
        CHECK_DEF(ii, inbuf, insz, "AFD_ENUM_NETWORK_EVENTS_INFO"); /*  */
        break;
    }
    case AFD_START_LISTEN: { /* 2 == 0x1200b */
        AFD_LISTEN_DATA *info = (AFD_LISTEN_DATA *) inbuf;
        if (insz != sizeof(AFD_LISTEN_DATA))
            WARN("WARNING: invalid size for AFD_LISTEN_DATA\n");
        /* Have to separate the Booleans since padding after */
        CHECK_DEF(ii, inbuf, sizeof(info->UseSAN), "AFD_LISTEN_DATA.UseSAN");
        CHECK_DEF(ii, &info->Backlog, sizeof(info->Backlog), "AFD_LISTEN_DATA.Backlog");
        CHECK_DEF(ii, &info->UseDelayedAcceptance, sizeof(info->UseDelayedAcceptance),
                  "AFD_LISTEN_DATA.UseDelayedAcceptance");
        break;
    }
    case AFD_ACCEPT: { /* 4 == 0x12010 */
        CHECK_DEF(ii, inbuf, insz, "AFD_ACCEPT_DATA");
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
        CHECK_DEF(ii, inbuf, insz, "AFD InputBuffer");
        break;
    }
    }

    ASSERT(ii->arg->pre, "Sanity check - we should only process pre- ioctls at this point");
}

/* Handles ioctls of type FILE_DEVICE_NETWORK.  Some codes are documented in
 * wininc/tcpioctl.h.
 */
static void
handle_NET_ioctl(void *drcontext, cls_syscall_t *pt, sysarg_iter_info_t *ii)
{
    uint full_code = (uint) pt->sysarg[5];
    byte *inbuf = (byte *) pt->sysarg[IOCTL_INBUF_ARGNUM];
    uint insz = (uint) pt->sysarg[7];
    byte *outbuf = (byte *) pt->sysarg[IOCTL_OUTBUF_ARGNUM];
    uint outsz = (uint) pt->sysarg[9];
    bool handled;

    /* Extract operation. */
    uint function = FUNCTION_FROM_CTL_CODE(full_code);

    ASSERT((uint)FILE_DEVICE_NETWORK == DEVICE_TYPE_FROM_CTL_CODE(full_code),
           "Unknown device type for handle_NET_ioctl!");

    /* Set handled to false in the default path. */
    handled = true;
    switch (full_code) {

    case _TCP_CTL_CODE(0x003, METHOD_NEITHER, FILE_ANY_ACCESS): /* 0x12000f */ {
        /* New in Vista+: called from NSI.dll through
         * IPHPAPI.dll!GetAdaptersInfo.  Found these similar ioctl values, but
         * none of these match the observed behavior:
         * - IOCTL_IPV6_QUERY_NEIGHBOR_CACHE from nddip6.h in WinCE DDK
         * - IOCTL_IP_NAT_DELETE_INTERFACE from ipnat.h in WinCE DDK
         * These checks are based on reverse engineering the interface.
         */
        net_ioctl_003_inout_t data;
        ip_adapter_info_t *adapter_info;
        LOG(SYSCALL_VERBOSE, "IOCTL_NET_0x003\n");
        if (inbuf == NULL || inbuf != outbuf ||
            insz != sizeof(data) || insz != outsz) {
            WARN("WARNING: expected same in/out param of size %d for ioctl "
                 PFX"\n", sizeof(data), full_code);
            break;
        }
        if (!safe_read(inbuf, sizeof(data), &data)) {
            WARN("WARNING: unable to read param for ioctl "PFX"\n", full_code);
            break;
        }
        adapter_info = data.adapter_info;
        if (ii->arg->pre && data.buf1) {
            CHECK_DEF(ii, data.buf1, data.buf1_sz, "net ioctl 0x003 buf1");
        }
        CHECK_OUT_PARAM(ii, data.buf2, data.buf2_sz, "net ioctl 0x003 buf2");

        /* Check whole buffer for addressability, but the kernel only writes
         * part of the output, so mark each struct member individually.
         */
        if (ii->arg->pre) {
            if (data.adapter_info_sz != sizeof(ip_adapter_info_t)) {
                WARN("WARNING: adapter info struct size does not match "
                     "expectation: found %d expected %d\n",
                     data.adapter_info_sz, sizeof(ip_adapter_info_t));
            }
            CHECK_ADDR(ii, adapter_info, data.adapter_info_sz,
                       "net ioctl 0x003 adapter_info");
        } else if (adapter_info != NULL) {
            /* XXX: Can we refactor these struct field checks here and above so
             * we only have to write the pointer, type, and field once?
             */
            MARK_WRITE(ii, (byte*)&adapter_info->adapter_name_len,
                       sizeof(adapter_info->adapter_name_len),
                       "net ioctl 0x003 adapter_info->adapter_name_len");
            MARK_WRITE(ii, (byte*)&adapter_info->adapter_name,
                       sizeof(adapter_info->adapter_name),
                       "net ioctl 0x003 adapter_info->adapter_name");
            MARK_WRITE(ii, (byte*)&adapter_info->unknown_a,
                       sizeof(adapter_info->unknown_a),
                       "net ioctl 0x003 adapter_info->unknown_a");
            MARK_WRITE(ii, (byte*)&adapter_info->unknown_b,
                       sizeof(adapter_info->unknown_b),
                       "net ioctl 0x003 adapter_info->unknown_b");
            MARK_WRITE(ii, (byte*)&adapter_info->unknown_c,
                       sizeof(adapter_info->unknown_c),
                       "net ioctl 0x003 adapter_info->unknown_c");
            MARK_WRITE(ii, (byte*)&adapter_info->unknown_d,
                       sizeof(adapter_info->unknown_d),
                       "net ioctl 0x003 adapter_info->unknown_d");
        }
        break;
    }

    case _TCP_CTL_CODE(0x006, METHOD_NEITHER, FILE_ANY_ACCESS): /* 0x12001b */ {
        /* New in Vista+: called from NSI.dll through
         * IPHPAPI.dll!GetAdaptersInfo.
         */
        net_ioctl_006_inout_t data;
        uint buf1sz, buf2sz, buf3sz, buf4sz;
        LOG(SYSCALL_VERBOSE, "IOCTL_NET_0x006\n");
        if (inbuf == NULL || inbuf != outbuf ||
            sizeof(data) != insz || insz != outsz) {
            WARN("WARNING: expected same in/out param of size %d for ioctl "
                 PFX"\n", sizeof(data), full_code);
            break;
        }
        if (!safe_read(inbuf, sizeof(data), &data)) {
            WARN("WARNING: unable to read param for ioctl "PFX"\n", full_code);
            break;
        }
        buf1sz = data.buf1_elt_sz * data.num_elts;
        buf2sz = data.buf2_elt_sz * data.num_elts;
        buf3sz = data.buf3_elt_sz * data.num_elts;
        buf4sz = data.buf4_elt_sz * data.num_elts;
        CHECK_OUT_PARAM(ii, data.buf1, buf1sz, "net ioctl 0x006 buf1");
        CHECK_OUT_PARAM(ii, data.buf2, buf2sz, "net ioctl 0x006 buf2");
        CHECK_OUT_PARAM(ii, data.buf3, buf3sz, "net ioctl 0x006 buf3");
        CHECK_OUT_PARAM(ii, data.buf4, buf4sz, "net ioctl 0x006 buf4");
        break;
    }

    /* These are known ioctl values used prior to Vista.  They seem to read and
     * write flat structures and we believe they are handled well by our default
     * behavior.
     */
    case IOCTL_TCP_QUERY_INFORMATION_EX:
    case IOCTL_TCP_SET_INFORMATION_EX:
        if (ii->arg->pre) {
            CHECK_DEF(ii, inbuf, insz, "NET InputBuffer");
        }
        break;

    default:
        handled = false;
        break;
    }

    if (!handled) {
        /* Unknown ioctl.  Check inbuf for full def and let table mark outbuf as
         * written.
         */
        if (ii->arg->pre) {
            WARN("WARNING: unhandled NET ioctl "PIFX" => op %d\n",
                 full_code, function);
            CHECK_DEF(ii, inbuf, insz, "NET InputBuffer");
        }
    }
}

static void
handle_DeviceIoControlFile_helper(void *drcontext, cls_syscall_t *pt,
                                  sysarg_iter_info_t *ii)
{
    uint code = (uint) pt->sysarg[5];
    uint device = (uint) DEVICE_TYPE_FROM_CTL_CODE(code);
    byte *inbuf = (byte *) pt->sysarg[IOCTL_INBUF_ARGNUM];
    uint insz = (uint) pt->sysarg[7];

    /* We don't put "6,-7,R" into the table b/c for some ioctls only part of
     * the input buffer needs to be defined.
     */

    /* Common ioctl handling before calling more specific handler. */
    if (ii->arg->pre) {
        if (inbuf == NULL)
            return;
    } else {
        /* We have "8,-9,W" in the table so we only need to handle additional pointers
         * here or cases where subsets of the full output buffer are written.
         *
         * XXX i#410: We treat asynch i/o as happening now rather than trying to
         * watch NtWait* and tracking event objects, though we'll
         * over-estimate the amount written in some cases.
         */
        if (!os_syscall_succeeded(ii->arg->sysnum, NULL,
                                  dr_syscall_get_result(drcontext)))
            return;
    }

    /* XXX: could use SYSINFO_SECONDARY_TABLE instead */
    if (IS_AFD_IOCTL(code)) {
        /* This is redundant for those where entire buffer must be defined but
         * most need subset defined.
         */
        if (ii->arg->pre)
            CHECK_ADDR(ii, inbuf, insz, "InputBuffer");
        handle_AFD_ioctl(drcontext, pt, ii);
    } else if (device == FILE_DEVICE_NETWORK) {
        handle_NET_ioctl(drcontext, pt, ii);
    } else {
        /* FIXME i#377: add more ioctl codes. */
        WARN("WARNING: unknown ioctl "PIFX" => op %d\n",
                code, FUNCTION_FROM_CTL_CODE(code));
        /* XXX: should perhaps dump a callstack too at higher verbosity */
        /* assume full thing must be defined */
        if (ii->arg->pre)
            CHECK_DEF(ii, inbuf, insz, "InputBuffer");

        /* Table always marks outbuf as written during post callback.
         * XXX i#378: should break down the output buffer as well since it
         * may not all be written to.
         */
    }

    return;
}

static bool
handle_DeviceIoControlFile(void *drcontext, cls_syscall_t *pt, sysarg_iter_info_t *ii)
{
    /* we use a helper w/ void return value so we can use CHECK_DEF, etc. macros */
    handle_DeviceIoControlFile_helper(drcontext, pt, ii);
    return true; /* handled */
}
#undef CHECK_DEF
#undef CHECK_ADDR
#undef MARK_WRITE

/***************************************************************************
 * SHADOW TOP-LEVEL ROUTINES
 */


void
os_handle_pre_syscall(void *drcontext, cls_syscall_t *pt, sysarg_iter_info_t *ii)
{
    if (drsys_sysnums_equal(&ii->arg->sysnum, &sysnum_CreateThreadEx))
        handle_pre_CreateThreadEx(drcontext, pt, ii);
    else if (drsys_sysnums_equal(&ii->arg->sysnum, &sysnum_CreateUserProcess))
        handle_pre_CreateUserProcess(drcontext, pt, ii);
    else if (drsys_sysnums_equal(&ii->arg->sysnum, &sysnum_DeviceIoControlFile))
        handle_DeviceIoControlFile(drcontext, pt, ii);
    else if (drsys_sysnums_equal(&ii->arg->sysnum, &sysnum_SetSystemInformation))
        handle_SetSystemInformation(drcontext, pt, ii);
    else if (drsys_sysnums_equal(&ii->arg->sysnum, &sysnum_QuerySystemInformation))
        handle_QuerySystemInformation(drcontext, pt, ii);
    else
        wingdi_shadow_process_syscall(drcontext, pt, ii);
}

#ifdef DEBUG
/* info to help analyze syscall false positives.
 * maybe could eventually spin some of this off as an strace tool.
 */
void
syscall_diagnostics(void *drcontext, cls_syscall_t *pt)
{
    /* XXX: even though only at -verbose 2, should use safe_read for all derefs */
    syscall_info_t *sysinfo = pt->sysinfo;
    if (sysinfo == NULL)
        return;
    if (!NT_SUCCESS(dr_syscall_get_result(drcontext)))
        return;
    if (strcmp(sysinfo->name, "NtQueryValueKey") == 0) {
        UNICODE_STRING *us = (UNICODE_STRING *) pt->sysarg[1];
        DR_TRY_EXCEPT(drcontext, {
            LOG(2, "NtQueryValueKey %S => ", (us == NULL || us->Buffer == NULL) ?
                L"" : us->Buffer);
        }, { /* EXCEPT */
        });
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
        DR_TRY_EXCEPT(drcontext, {
            if (obj != NULL && obj->ObjectName != NULL)
                LOG(2, "%s %S\n", sysinfo->name, obj->ObjectName->Buffer);
        }, { /* EXCEPT */
        });
    }
}
#endif

void
os_handle_post_syscall(void *drcontext, cls_syscall_t *pt, sysarg_iter_info_t *ii)
{
    /* FIXME code org: there's some processing of syscalls in alloc_drmem.c's
     * client_post_syscall() where common/alloc.c identifies the sysnum: but
     * for things that don't have anything to do w/ mem alloc I think it's
     * cleaner to have it all in here rather than having to edit both files.
     * Perhaps NtContinue and NtSetContextThread should also be here?  OTOH,
     * the teb is an alloc.
     */
    /* each handler checks result for success */
    if (drsys_sysnums_equal(&ii->arg->sysnum, &sysnum_CreateThread))
        handle_post_CreateThread(drcontext, pt, ii);
    else if (drsys_sysnums_equal(&ii->arg->sysnum, &sysnum_CreateThreadEx))
        handle_post_CreateThreadEx(drcontext, pt, ii);
    else if (drsys_sysnums_equal(&ii->arg->sysnum, &sysnum_CreateUserProcess))
        handle_post_CreateUserProcess(drcontext, pt, ii);
    else if (drsys_sysnums_equal(&ii->arg->sysnum, &sysnum_DeviceIoControlFile))
        handle_DeviceIoControlFile(drcontext, pt, ii);
    else if (drsys_sysnums_equal(&ii->arg->sysnum, &sysnum_SetSystemInformation))
        handle_SetSystemInformation(drcontext, pt, ii);
    else if (drsys_sysnums_equal(&ii->arg->sysnum, &sysnum_QuerySystemInformation))
        handle_QuerySystemInformation(drcontext, pt, ii);
    else
        wingdi_shadow_process_syscall(drcontext, pt, ii);
    DOLOG(2, { syscall_diagnostics(drcontext, pt); });
}

