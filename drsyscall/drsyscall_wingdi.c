/* **********************************************************
 * Copyright (c) 2011-2013 Google, Inc.  All rights reserved.
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

/* Need this defined and to the latest to get the latest defines and types */
#define _WIN32_WINNT 0x0601 /* == _WIN32_WINNT_WIN7 */
#define WINVER _WIN32_WINNT

#include "dr_api.h"
#include "drsyscall.h"
#include "drsyscall_os.h"
#include "drsyscall_windows.h"
#include <stddef.h> /* offsetof */

/* for NtGdi* syscalls */
#include <wingdi.h> /* usually from windows.h; required by winddi.h + ENUMLOGFONTEXDVW */
#define NT_BUILD_ENVIRONMENT 1 /* for d3dnthal.h */
#include <d3dnthal.h>
#include <winddi.h> /* required by ntgdityp.h and prntfont.h */
#include <prntfont.h>
#include "../wininc/ntgdityp.h"
#include <ntgdi.h>
#include <winspool.h> /* for DRIVER_INFO_2W */
#include <dxgiformat.h> /* for DXGI_FORMAT */

/* for NtUser* syscalls */
#include "../wininc/ndk_extypes.h" /* required by ntuser.h */
#include "../wininc/ntuser.h"
#include "../wininc/ntuser_win8.h"

#define OK (SYSINFO_ALL_PARAMS_KNOWN)
#define UNKNOWN 0
#define W (SYSARG_WRITE)
#define R (SYSARG_READ)
#define CT (SYSARG_COMPLEX_TYPE)
#define HT (SYSARG_HAS_TYPE)
#define WI (SYSARG_WRITE | SYSARG_LENGTH_INOUT)
#define RET (SYSARG_POST_SIZE_RETVAL)
#define RNTST (DRSYS_TYPE_NTSTATUS)

/* FIXME i#1089: fill in info on all the inlined args for all of
 * syscalls in this file.
 */

/***************************************************************************/
/* System calls with wrappers in kernel32.dll (on win7 these are duplicated
 * in kernelbase.dll as well but w/ the same syscall number)
 * Not all wrappers are exported: xref i#388.
 */
syscall_info_t syscall_kernel32_info[] = {
    /* wchar_t *locale OUT, size_t locale_sz (assuming size in bytes) */
    {{0,0},"NtWow64CsrBasepNlsGetUserInfo", OK, RNTST, 2,
     {
         {0, -1, W|CT, SYSARG_TYPE_CSTRING_WIDE},
     }
    },

    /* Takes a single param that's a pointer to a struct that has a PHANDLE at offset
     * 0x7c where the base of a new mmap is stored by the kernel.  We handle that by
     * waiting for RtlCreateActivationContext (i#352).  We don't know of any written
     * values in the rest of the struct or its total size so we ignore it for now and
     * use this entry to avoid "unknown syscall" warnings.
     *
     * XXX: there are 4+ wchar_t* input strings in the struct: should check them.
     */
    {{0,0},"NtWow64CsrBasepCreateActCtx", OK, RNTST, 1, },

    /* FIXME i#1091: add further kernel32 syscall info */
    {{0,0},"AddConsoleAliasInternal", UNKNOWN, DRSYS_TYPE_UNKNOWN, },
    {{0,0},"AllocConsoleInternal", UNKNOWN, DRSYS_TYPE_UNKNOWN, },
    {{0,0},"AttachConsoleInternal", UNKNOWN, DRSYS_TYPE_UNKNOWN, },
    {{0,0},"CloseConsoleHandle", UNKNOWN, DRSYS_TYPE_UNKNOWN, },
    {{0,0},"ConnectConsoleInternal", UNKNOWN, DRSYS_TYPE_UNKNOWN, },
    {{0,0},"ConsoleMenuControl", UNKNOWN, DRSYS_TYPE_UNKNOWN, },
    {{0,0},"CreateConsoleScreenBuffer", UNKNOWN, DRSYS_TYPE_UNKNOWN, },
    {{0,0},"DuplicateConsoleHandle", UNKNOWN, DRSYS_TYPE_UNKNOWN, },
    {{0,0},"ExpungeConsoleCommandHistoryInternal", UNKNOWN, DRSYS_TYPE_UNKNOWN, },
    {{0,0},"FillConsoleOutput", UNKNOWN, DRSYS_TYPE_UNKNOWN, },
    {{0,0},"FlushConsoleInputBuffer", UNKNOWN, DRSYS_TYPE_UNKNOWN, },
    {{0,0},"FreeConsoleInternal", UNKNOWN, DRSYS_TYPE_UNKNOWN, },
    {{0,0},"GenerateConsoleCtrlEvent", UNKNOWN, DRSYS_TYPE_UNKNOWN, },
    {{0,0},"GetConsoleAliasExesInternal", UNKNOWN, DRSYS_TYPE_UNKNOWN, },
    {{0,0},"GetConsoleAliasExesLengthInternal", UNKNOWN, DRSYS_TYPE_UNKNOWN, },
    {{0,0},"GetConsoleAliasInternal", UNKNOWN, DRSYS_TYPE_UNKNOWN, },
    {{0,0},"GetConsoleAliasesInternal", UNKNOWN, DRSYS_TYPE_UNKNOWN, },
    {{0,0},"GetConsoleAliasesLengthInternal", UNKNOWN, DRSYS_TYPE_UNKNOWN, },
    {{0,0},"GetConsoleCP", UNKNOWN, DRSYS_TYPE_UNKNOWN, },
    {{0,0},"GetConsoleCharType", UNKNOWN, DRSYS_TYPE_UNKNOWN, },
    {{0,0},"GetConsoleCommandHistoryInternal", UNKNOWN, DRSYS_TYPE_UNKNOWN, },
    {{0,0},"GetConsoleCommandHistoryLengthInternal", UNKNOWN, DRSYS_TYPE_UNKNOWN, },
    {{0,0},"GetConsoleCursorInfo", UNKNOWN, DRSYS_TYPE_UNKNOWN, },
    {{0,0},"GetConsoleCursorMode", UNKNOWN, DRSYS_TYPE_UNKNOWN, },
    {{0,0},"GetConsoleDisplayMode", UNKNOWN, DRSYS_TYPE_UNKNOWN, },
    {{0,0},"GetConsoleFontInfo", UNKNOWN, DRSYS_TYPE_UNKNOWN, },
    {{0,0},"GetConsoleFontSize", UNKNOWN, DRSYS_TYPE_UNKNOWN, },
    {{0,0},"GetConsoleHandleInformation", UNKNOWN, DRSYS_TYPE_UNKNOWN, },
    {{0,0},"GetConsoleHardwareState", UNKNOWN, DRSYS_TYPE_UNKNOWN, },
    {{0,0},"GetConsoleInput", UNKNOWN, DRSYS_TYPE_UNKNOWN, },
    {{0,0},"GetConsoleKeyboardLayoutNameWorker", UNKNOWN, DRSYS_TYPE_UNKNOWN, },
    {{0,0},"GetConsoleLangId", UNKNOWN, DRSYS_TYPE_UNKNOWN, },
    {{0,0},"GetConsoleMode", UNKNOWN, DRSYS_TYPE_UNKNOWN, },
    {{0,0},"GetConsoleNlsMode", UNKNOWN, DRSYS_TYPE_UNKNOWN, },
    {{0,0},"GetConsoleOutputCP", UNKNOWN, DRSYS_TYPE_UNKNOWN, },
    {{0,0},"GetConsoleProcessList", UNKNOWN, DRSYS_TYPE_UNKNOWN, },
    {{0,0},"GetConsoleScreenBufferInfo", UNKNOWN, DRSYS_TYPE_UNKNOWN, },
    {{0,0},"GetConsoleSelectionInfo", UNKNOWN, DRSYS_TYPE_UNKNOWN, },
    {{0,0},"GetConsoleTitleInternal", UNKNOWN, DRSYS_TYPE_UNKNOWN, },
    {{0,0},"GetConsoleWindow", UNKNOWN, DRSYS_TYPE_UNKNOWN, },
    {{0,0},"GetCurrentConsoleFont", UNKNOWN, DRSYS_TYPE_UNKNOWN, },
    {{0,0},"GetLargestConsoleWindowSize", UNKNOWN, DRSYS_TYPE_UNKNOWN, },
    {{0,0},"GetNumberOfConsoleFonts", UNKNOWN, DRSYS_TYPE_UNKNOWN, },
    {{0,0},"GetNumberOfConsoleInputEvents", UNKNOWN, DRSYS_TYPE_UNKNOWN, },
    {{0,0},"GetNumberOfConsoleMouseButtons", UNKNOWN, DRSYS_TYPE_UNKNOWN, },
    {{0,0},"InvalidateConsoleDIBits", UNKNOWN, DRSYS_TYPE_UNKNOWN, },
    {{0,0},"NtWow64CsrBaseCheckRunApp", UNKNOWN, DRSYS_TYPE_UNKNOWN, },
    {{0,0},"NtWow64CsrBaseClientConnectToServer", UNKNOWN, DRSYS_TYPE_UNKNOWN, },
    {{0,0},"NtWow64CsrBaseQueryModuleData", UNKNOWN, DRSYS_TYPE_UNKNOWN, },
    {{0,0},"NtWow64CsrBasepCreateProcess", UNKNOWN, DRSYS_TYPE_UNKNOWN, },
    {{0,0},"NtWow64CsrBasepCreateThread", UNKNOWN, DRSYS_TYPE_UNKNOWN, },
    {{0,0},"NtWow64CsrBasepDefineDosDevice", UNKNOWN, DRSYS_TYPE_UNKNOWN, },
    {{0,0},"NtWow64CsrBasepExitProcess", UNKNOWN, DRSYS_TYPE_UNKNOWN, },
    {{0,0},"NtWow64CsrBasepGetProcessShutdownParam", UNKNOWN, DRSYS_TYPE_UNKNOWN, },
    {{0,0},"NtWow64CsrBasepGetTempFile", UNKNOWN, DRSYS_TYPE_UNKNOWN, },
    {{0,0},"NtWow64CsrBasepNlsCreateSection", UNKNOWN, DRSYS_TYPE_UNKNOWN, },
    {{0,0},"NtWow64CsrBasepNlsSetMultipleUserInfo", UNKNOWN, DRSYS_TYPE_UNKNOWN, },
    {{0,0},"NtWow64CsrBasepNlsSetUserInfo", UNKNOWN, DRSYS_TYPE_UNKNOWN, },
    {{0,0},"NtWow64CsrBasepNlsUpdateCacheCount", UNKNOWN, DRSYS_TYPE_UNKNOWN, },
    {{0,0},"NtWow64CsrBasepRefreshIniFileMapping", UNKNOWN, DRSYS_TYPE_UNKNOWN, },
    {{0,0},"NtWow64CsrBasepSetClientTimeZoneInformation", UNKNOWN, DRSYS_TYPE_UNKNOWN, },
    {{0,0},"NtWow64CsrBasepSetProcessShutdownParam", UNKNOWN, DRSYS_TYPE_UNKNOWN, },
    {{0,0},"NtWow64CsrBasepSetTermsrvAppInstallMode", UNKNOWN, DRSYS_TYPE_UNKNOWN, },
    {{0,0},"NtWow64CsrBasepSoundSentryNotification", UNKNOWN, DRSYS_TYPE_UNKNOWN, },
    {{0,0},"OpenConsoleWInternal", UNKNOWN, DRSYS_TYPE_UNKNOWN, },
    {{0,0},"ReadConsoleInternal", UNKNOWN, DRSYS_TYPE_UNKNOWN, },
    {{0,0},"ReadConsoleOutputInternal", UNKNOWN, DRSYS_TYPE_UNKNOWN, },
    {{0,0},"ReadConsoleOutputString", UNKNOWN, DRSYS_TYPE_UNKNOWN, },
    {{0,0},"RegisterConsoleIMEInternal", UNKNOWN, DRSYS_TYPE_UNKNOWN, },
    {{0,0},"RegisterConsoleOS2", UNKNOWN, DRSYS_TYPE_UNKNOWN, },
    {{0,0},"RegisterConsoleVDM", UNKNOWN, DRSYS_TYPE_UNKNOWN, },
    {{0,0},"ScrollConsoleScreenBufferInternal", UNKNOWN, DRSYS_TYPE_UNKNOWN, },
    {{0,0},"SetConsoleActiveScreenBuffer", UNKNOWN, DRSYS_TYPE_UNKNOWN, },
    {{0,0},"SetConsoleCP", UNKNOWN, DRSYS_TYPE_UNKNOWN, },
    {{0,0},"SetConsoleCommandHistoryMode", UNKNOWN, DRSYS_TYPE_UNKNOWN, },
    {{0,0},"SetConsoleCursor", UNKNOWN, DRSYS_TYPE_UNKNOWN, },
    {{0,0},"SetConsoleCursorInfo", UNKNOWN, DRSYS_TYPE_UNKNOWN, },
    {{0,0},"SetConsoleCursorMode", UNKNOWN, DRSYS_TYPE_UNKNOWN, },
    {{0,0},"SetConsoleCursorPosition", UNKNOWN, DRSYS_TYPE_UNKNOWN, },
    {{0,0},"SetConsoleDisplayMode", UNKNOWN, DRSYS_TYPE_UNKNOWN, },
    {{0,0},"SetConsoleFont", UNKNOWN, DRSYS_TYPE_UNKNOWN, },
    {{0,0},"SetConsoleHandleInformation", UNKNOWN, DRSYS_TYPE_UNKNOWN, },
    {{0,0},"SetConsoleHardwareState", UNKNOWN, DRSYS_TYPE_UNKNOWN, },
    {{0,0},"SetConsoleIcon", UNKNOWN, DRSYS_TYPE_UNKNOWN, },
    {{0,0},"SetConsoleKeyShortcuts", UNKNOWN, DRSYS_TYPE_UNKNOWN, },
    {{0,0},"SetConsoleLocalEUDC", UNKNOWN, DRSYS_TYPE_UNKNOWN, },
    {{0,0},"SetConsoleMenuClose", UNKNOWN, DRSYS_TYPE_UNKNOWN, },
    {{0,0},"SetConsoleMode", UNKNOWN, DRSYS_TYPE_UNKNOWN, },
    {{0,0},"SetConsoleNlsMode", UNKNOWN, DRSYS_TYPE_UNKNOWN, },
    {{0,0},"SetConsoleNumberOfCommandsInternal", UNKNOWN, DRSYS_TYPE_UNKNOWN, },
    {{0,0},"SetConsoleOS2OemFormat", UNKNOWN, DRSYS_TYPE_UNKNOWN, },
    {{0,0},"SetConsoleOutputCPInternal", UNKNOWN, DRSYS_TYPE_UNKNOWN, },
    {{0,0},"SetConsolePaletteInternal", UNKNOWN, DRSYS_TYPE_UNKNOWN, },
    {{0,0},"SetConsoleScreenBufferSize", UNKNOWN, DRSYS_TYPE_UNKNOWN, },
    {{0,0},"SetConsoleTextAttribute", UNKNOWN, DRSYS_TYPE_UNKNOWN, },
    {{0,0},"SetConsoleTitleInternal", UNKNOWN, DRSYS_TYPE_UNKNOWN, },
    {{0,0},"SetConsoleWindowInfo", UNKNOWN, DRSYS_TYPE_UNKNOWN, },
    {{0,0},"SetLastConsoleEventActiveInternal", UNKNOWN, DRSYS_TYPE_UNKNOWN, },
    {{0,0},"ShowConsoleCursor", UNKNOWN, DRSYS_TYPE_UNKNOWN, },
    {{0,0},"UnregisterConsoleIMEInternal", UNKNOWN, DRSYS_TYPE_UNKNOWN, },
    {{0,0},"VerifyConsoleIoHandle", UNKNOWN, DRSYS_TYPE_UNKNOWN, },
    {{0,0},"WriteConsoleInputInternal", UNKNOWN, DRSYS_TYPE_UNKNOWN, },
    {{0,0},"WriteConsoleInternal", UNKNOWN, DRSYS_TYPE_UNKNOWN, },
    {{0,0},"WriteConsoleOutputInternal", UNKNOWN, DRSYS_TYPE_UNKNOWN, },
    {{0,0},"WriteConsoleOutputString", UNKNOWN, DRSYS_TYPE_UNKNOWN, },

    /***************************************************/
    /* Added in Vista */
    {{0,0},"GetConsoleHistoryInfo", UNKNOWN, DRSYS_TYPE_UNKNOWN, },
    {{0,0},"GetConsoleScreenBufferInfoEx", UNKNOWN, DRSYS_TYPE_UNKNOWN, },
    {{0,0},"GetCurrentConsoleFontEx", UNKNOWN, DRSYS_TYPE_UNKNOWN, },
    {{0,0},"QueryConsoleIMEInternal", UNKNOWN, DRSYS_TYPE_UNKNOWN, },
    {{0,0},"SetConsoleHistoryInfo", UNKNOWN, DRSYS_TYPE_UNKNOWN, },
    {{0,0},"SetConsoleScreenBufferInfoEx", UNKNOWN, DRSYS_TYPE_UNKNOWN, },
    {{0,0},"SetCurrentConsoleFontEx", UNKNOWN, DRSYS_TYPE_UNKNOWN, },

    /***************************************************/
    /* Added in Windows 8 */
    {{0,0},"NtWow64ConsoleLaunchServerProcess", UNKNOWN, DRSYS_TYPE_UNKNOWN, 4, },
};
#define NUM_KERNEL32_SYSCALLS \
    (sizeof(syscall_kernel32_info)/sizeof(syscall_kernel32_info[0]))

size_t
num_kernel32_syscalls(void)
{
    return NUM_KERNEL32_SYSCALLS;
}

/***************************************************************************/
/* System calls with wrappers in user32.dll.
 * Not all wrappers are exported: xref i#388.
 *
 * Initially obtained via mksystable.pl on ntuser.h.
 * That version was checked in separately to track manual changes.
 *
 * When adding new entries, use the NtUser prefix.
 * When we try to find the wrapper via symbol lookup we try with
 * and without the prefix.
 *
 * Unresolved issues are marked w/ FIXME in the table.
 */

static drsys_sysnum_t sysnum_UserSystemParametersInfo = {-1,0};
static drsys_sysnum_t sysnum_UserMenuInfo = {-1,0};
static drsys_sysnum_t sysnum_UserMenuItemInfo = {-1,0};
static drsys_sysnum_t sysnum_UserGetAltTabInfo = {-1,0};
static drsys_sysnum_t sysnum_UserGetRawInputBuffer = {-1,0};
static drsys_sysnum_t sysnum_UserGetRawInputData = {-1,0};
static drsys_sysnum_t sysnum_UserGetRawInputDeviceInfo = {-1,0};
static drsys_sysnum_t sysnum_UserTrackMouseEvent = {-1,0};
static drsys_sysnum_t sysnum_UserLoadKeyboardLayoutEx = {-1,0};
static drsys_sysnum_t sysnum_UserCreateWindowStation = {-1,0};
static drsys_sysnum_t sysnum_UserMessageCall = {-1,0};
static drsys_sysnum_t sysnum_UserCreateAcceleratorTable = {-1,0};
static drsys_sysnum_t sysnum_UserCopyAcceleratorTable = {-1,0};
static drsys_sysnum_t sysnum_UserSetScrollInfo = {-1,0};

/* forward decl so "extern" */
extern syscall_info_t syscall_usercall_info[];

/* Table that maps usercall names to secondary syscall numbers.
 * Number can be 0 so we store +1.
 */
#define USERCALL_TABLE_HASH_BITS 8
static hashtable_t usercall_table;

/* FIXME i#1093: figure out the failure codes for all the int and uint return values */

syscall_info_t syscall_user32_info[] = {
    {{0,0},"NtUserActivateKeyboardLayout", OK, DRSYS_TYPE_HANDLE, 2, },
    {{0,0},"NtUserAlterWindowStyle", OK, SYSARG_TYPE_UINT32, 3, },
    {{0,0},"NtUserAssociateInputContext", OK|SYSINFO_IMM32_DLL, SYSARG_TYPE_UINT32, 3, },
    {{0,0},"NtUserAttachThreadInput", OK, SYSARG_TYPE_BOOL32, 3, },
    {{0,0},"NtUserBeginPaint", OK, DRSYS_TYPE_HANDLE, 2,
     {
         {1, sizeof(PAINTSTRUCT), W,},
     }
    },
    {{0,0},"NtUserBitBltSysBmp", OK, SYSARG_TYPE_BOOL32, 8, },
    {{0,0},"NtUserBlockInput", OK, SYSARG_TYPE_BOOL32, 1, },
    {{0,0},"NtUserBuildHimcList", OK|SYSINFO_IMM32_DLL, SYSARG_TYPE_UINT32, 4,
     {
         {2, -1, W|SYSARG_SIZE_IN_ELEMENTS, sizeof(HIMC)},
         {3, sizeof(UINT), W},
     }
    },
    {{0,DR_WINDOWS_VERSION_7},"NtUserBuildHwndList", OK, RNTST, 7,
     {
         {2, sizeof(BOOLEAN), SYSARG_INLINED, DRSYS_TYPE_BOOL,},
         {5, -6, WI|SYSARG_SIZE_IN_ELEMENTS, sizeof(HWND)},
         {6, sizeof(ULONG), R|W,},
     }
    },
    {{DR_WINDOWS_VERSION_8,0},"NtUserBuildHwndList", OK, RNTST, 8,
     {
         {2, sizeof(BOOLEAN), SYSARG_INLINED, DRSYS_TYPE_BOOL,},
         /* i#1153: size of buffer seems to be a separate inline param inserted
          * at 5th position.
          */
         {6, -5, W|SYSARG_SIZE_IN_ELEMENTS, sizeof(HWND)},
         {7, sizeof(ULONG), W,},
     }
    },
    {{0,0},"NtUserBuildMenuItemList", OK, SYSARG_TYPE_UINT32, 4,
     {
         {1, -2, W,},
     }
    },
    {{0,0},"NtUserBuildNameList", OK, RNTST, 4,
     {
         {2, -1, W,},
         {2, -3, WI,},
         {3, sizeof(ULONG), W,},
     }
    },
    {{0,0},"NtUserBuildPropList", OK, RNTST, 4,
     {
         {1, -2, W,},
         {1, -3, WI,},
         {3, sizeof(DWORD), W,},
     }
    },
    {{0,0},"NtUserCalcMenuBar", OK, SYSARG_TYPE_UINT32, 5, },
    /* i#389: NtUserCall* take in a code and perform a variety of tasks */
    {{0,0},"NtUserCallHwnd", OK|SYSINFO_SECONDARY_TABLE, SYSARG_TYPE_UINT32, 2,
     {
         {1,}
     }, (drsys_sysnum_t*)syscall_usercall_info
    },
    {{0,0},"NtUserCallHwndLock", OK|SYSINFO_SECONDARY_TABLE, SYSARG_TYPE_UINT32, 2,
     {
         {1,}
     }, (drsys_sysnum_t*)syscall_usercall_info
    },
    {{0,0},"NtUserCallHwndOpt", OK|SYSINFO_SECONDARY_TABLE, DRSYS_TYPE_HANDLE, 2,
     {
         {1,}
     }, (drsys_sysnum_t*)syscall_usercall_info
    },
    {{0,0},"NtUserCallHwndParam", OK|SYSINFO_SECONDARY_TABLE, SYSARG_TYPE_UINT32, 3,
     {
         {2,}
     }, (drsys_sysnum_t*)syscall_usercall_info
    },
    {{0,0},"NtUserCallHwndParamLock", OK|SYSINFO_SECONDARY_TABLE, SYSARG_TYPE_UINT32, 3,
     {
         {2,}
     }, (drsys_sysnum_t*)syscall_usercall_info
    },
    {{0,0},"NtUserCallMsgFilter", UNKNOWN, SYSARG_TYPE_BOOL32, 2,
     {
         {0, sizeof(MSG), R|W,},
     }
    },
    {{0,0},"NtUserCallNextHookEx", UNKNOWN, DRSYS_TYPE_SIGNED_INT, 4, },
    {{0,0},"NtUserCallNoParam", OK|SYSINFO_SECONDARY_TABLE, DRSYS_TYPE_UNSIGNED_INT, 1,
     {
         {0,}
     }, (drsys_sysnum_t*)syscall_usercall_info
    },
    {{0,0},"NtUserCallOneParam", OK|SYSINFO_SECONDARY_TABLE, DRSYS_TYPE_UNSIGNED_INT, 2,
     {
         {1,}
     }, (drsys_sysnum_t*)syscall_usercall_info},
    {{0,0},"NtUserCallTwoParam", OK|SYSINFO_SECONDARY_TABLE, DRSYS_TYPE_UNSIGNED_INT, 3,
     {
         {2,}
     }, (drsys_sysnum_t*)syscall_usercall_info
    },
    {{0,0},"NtUserChangeClipboardChain", OK, SYSARG_TYPE_BOOL32, 2, },
    {{0,0},"NtUserChangeDisplaySettings", OK, SYSARG_TYPE_SINT32, 5,
     {
         {0, sizeof(UNICODE_STRING), R|CT, SYSARG_TYPE_UNICODE_STRING},
         {1, sizeof(DEVMODEW)/*really var-len*/, R|CT, SYSARG_TYPE_DEVMODEW},
         {4, -5, W,},
     }
    },
    {{0,0},"NtUserCheckDesktopByThreadId", OK, SYSARG_TYPE_BOOL32, 1, },
    {{0,0},"NtUserCheckImeHotKey", OK, SYSARG_TYPE_UINT32, 2, },
    {{0,0},"NtUserCheckMenuItem", OK|SYSINFO_RET_MINUS1_FAIL, SYSARG_TYPE_UINT32, 3, },
    {{0,0},"NtUserCheckWindowThreadDesktop", OK, SYSARG_TYPE_BOOL32, 3, },
    {{0,0},"NtUserChildWindowFromPointEx", OK, DRSYS_TYPE_HANDLE, 4, },
    {{0,0},"NtUserClipCursor", OK, SYSARG_TYPE_BOOL32, 1,
     {
         {0, sizeof(RECT), R,},
     }
    },
    {{0,0},"NtUserCloseClipboard", OK, SYSARG_TYPE_BOOL32, 0, },
    {{0,0},"NtUserCloseDesktop", OK, SYSARG_TYPE_BOOL32, 1, },
    {{0,0},"NtUserCloseWindowStation", OK, SYSARG_TYPE_BOOL32, 1, },
    {{0,0},"NtUserConsoleControl", OK, SYSARG_TYPE_UINT32, 3, },
    {{0,0},"NtUserConvertMemHandle", OK, DRSYS_TYPE_HANDLE, 2,
     {
         {0, -1, R},
     }
    },
    {{0,0},"NtUserCopyAcceleratorTable", OK|SYSINFO_RET_ZERO_FAIL, SYSARG_TYPE_UINT32, 3,
     {
         /* special-cased b/c ACCEL has padding */
         {1, -2, SYSARG_NON_MEMARG|SYSARG_SIZE_IN_ELEMENTS, sizeof(ACCEL)},
     }, &sysnum_UserCopyAcceleratorTable,
    },
    {{0,0},"NtUserCountClipboardFormats", OK, SYSARG_TYPE_UINT32, 0, },
    {{0,0},"NtUserCreateAcceleratorTable", OK, DRSYS_TYPE_HANDLE, 2,
     {
         /* special-cased b/c ACCEL has padding */
         {0, -1, SYSARG_NON_MEMARG|SYSARG_SIZE_IN_ELEMENTS, sizeof(ACCEL)},
     }, &sysnum_UserCreateAcceleratorTable,
    },
    {{0,0},"NtUserCreateCaret", OK, SYSARG_TYPE_BOOL32, 4, },
    {{0,0},"NtUserCreateDesktop", OK, DRSYS_TYPE_HANDLE, 5,
     {
         {0, sizeof(OBJECT_ATTRIBUTES), R|CT, SYSARG_TYPE_OBJECT_ATTRIBUTES},
         {1, sizeof(UNICODE_STRING), R|CT, SYSARG_TYPE_UNICODE_STRING},
         {2, sizeof(DEVMODEW)/*really var-len*/, R|CT, SYSARG_TYPE_DEVMODEW},
     }
    },
    {{0,0},"NtUserCreateInputContext", OK|SYSINFO_IMM32_DLL, SYSARG_TYPE_UINT32, 1, },
    {{0,0},"NtUserCreateLocalMemHandle", OK, RNTST, 4,
     {
         {1, -2, W},
         {3, sizeof(UINT), W},
     }
    },
    {{0,0},"NtUserCreateWindowEx", OK, DRSYS_TYPE_HANDLE, 15,
     {
         {1, sizeof(LARGE_STRING), R|CT, SYSARG_TYPE_LARGE_STRING},
         {2, sizeof(LARGE_STRING), R|CT, SYSARG_TYPE_LARGE_STRING},
         {3, sizeof(LARGE_STRING), R|CT, SYSARG_TYPE_LARGE_STRING},
     }
    },
    {{0,0},"NtUserCreateWindowStation", OK, DRSYS_TYPE_HANDLE, 7,
     {
         {0, sizeof(OBJECT_ATTRIBUTES), R|CT, SYSARG_TYPE_OBJECT_ATTRIBUTES},
     }, &sysnum_UserCreateWindowStation
    },
    {{0,0},"NtUserCtxDisplayIOCtl", OK, SYSARG_TYPE_UINT32, 3, },
    {{0,0},"NtUserDdeGetQualityOfService", OK, SYSARG_TYPE_BOOL32, 3,
     {
         {2, sizeof(SECURITY_QUALITY_OF_SERVICE), W,},
     }
    },
    {{0,0},"NtUserDdeInitialize", OK, SYSARG_TYPE_UINT32, 5, },
    {{0,0},"NtUserDdeSetQualityOfService", OK, SYSARG_TYPE_BOOL32, 3,
     {
         {1, sizeof(SECURITY_QUALITY_OF_SERVICE), R,},
         {2, sizeof(SECURITY_QUALITY_OF_SERVICE), W,},
     }
    },
    {{0,0},"NtUserDefSetText", OK, SYSARG_TYPE_BOOL32, 2,
     {
         {1, sizeof(LARGE_STRING), R|CT, SYSARG_TYPE_LARGE_STRING},
     }
    },
    {{0,0},"NtUserDeferWindowPos", OK, DRSYS_TYPE_HANDLE, 8, },
    {{0,0},"NtUserDeleteMenu", OK, SYSARG_TYPE_BOOL32, 3, },
    {{0,0},"NtUserDestroyAcceleratorTable", OK, SYSARG_TYPE_BOOL8, 1, },
    {{0,0},"NtUserDestroyCursor", OK, SYSARG_TYPE_BOOL32, 2, },
    {{0,0},"NtUserDestroyInputContext", OK|SYSINFO_IMM32_DLL, SYSARG_TYPE_UINT32, 1, },
    {{0,0},"NtUserDestroyMenu", OK, SYSARG_TYPE_BOOL32, 1, },
    {{0,0},"NtUserDestroyWindow", OK, SYSARG_TYPE_BOOL8, 1, },
    {{0,0},"NtUserDisableThreadIme", OK|SYSINFO_IMM32_DLL, SYSARG_TYPE_UINT32, 1, },
    {{0,0},"NtUserDispatchMessage", OK, DRSYS_TYPE_SIGNED_INT, 1,
     {
         {0, sizeof(MSG), R,},
     }
    },
    {{0,0},"NtUserDragDetect", OK, SYSARG_TYPE_BOOL32, 2, },
    {{0,0},"NtUserDragObject", OK, SYSARG_TYPE_UINT32, 5, },
    {{0,0},"NtUserDrawAnimatedRects", OK, SYSARG_TYPE_BOOL32, 4,
     {
         {2, sizeof(RECT), R,},
         {3, sizeof(RECT), R,},
     }
    },
    {{0,0},"NtUserDrawCaption", OK, SYSARG_TYPE_BOOL32, 4,
     {
         {2, sizeof(RECT), R,},
     }
    },
    {{0,0},"NtUserDrawCaptionTemp", OK, SYSARG_TYPE_BOOL32, 7,
     {
         {2, sizeof(RECT), R,},
         {5, sizeof(UNICODE_STRING), R|CT, SYSARG_TYPE_UNICODE_STRING},
     }
    },
    {{0,0},"NtUserDrawIconEx", OK, SYSARG_TYPE_BOOL32, 11, /*XXX: 10th arg is pointer?*/ },
    {{0,0},"NtUserDrawMenuBarTemp", OK, SYSARG_TYPE_UINT32, 5,
     {
         {2, sizeof(RECT), R,},
     }
    },
    {{0,0},"NtUserEmptyClipboard", OK, SYSARG_TYPE_BOOL32, 0, },
    {{0,0},"NtUserEnableMenuItem", OK, SYSARG_TYPE_UINT32, 3, },
    {{0,0},"NtUserEnableScrollBar", OK, SYSARG_TYPE_BOOL32, 3, },
    {{0,0},"NtUserEndDeferWindowPosEx", OK, SYSARG_TYPE_BOOL32, 2, },
    {{0,0},"NtUserEndMenu", OK, SYSARG_TYPE_BOOL32, 0, },
    {{0,0},"NtUserEndPaint", OK, SYSARG_TYPE_BOOL32, 2,
     {
         {1, sizeof(PAINTSTRUCT), R,},
     }
    },
    {{0,0},"NtUserEnumDisplayDevices", OK, RNTST, 4,
     {
         {0, sizeof(UNICODE_STRING), R|CT, SYSARG_TYPE_UNICODE_STRING},
         {2, SYSARG_SIZE_IN_FIELD, W, offsetof(DISPLAY_DEVICEW, cb)},
     }
    },
    {{0,0},"NtUserEnumDisplayMonitors", OK, SYSARG_TYPE_BOOL32, 5,
     {
         {1, sizeof(RECT), R,},/*experimentally this matches win32 API version so no more mem args*/
     }
    },
    {{0,0},"NtUserEnumDisplaySettings", OK, RNTST, 4,
     {
         {0, sizeof(UNICODE_STRING), R|CT, SYSARG_TYPE_UNICODE_STRING},
         {2, sizeof(DEVMODEW)/*really var-len*/, W|CT, SYSARG_TYPE_DEVMODEW},
     }
    },
    {{0,0},"NtUserEvent", OK, SYSARG_TYPE_UINT32, 1, },
    {{0,0},"NtUserExcludeUpdateRgn", OK, SYSARG_TYPE_UINT32, 2, },
    {{0,0},"NtUserFillWindow", OK, SYSARG_TYPE_BOOL32, 4, },
    {{0,0},"NtUserFindExistingCursorIcon", OK, DRSYS_TYPE_HANDLE, 4, },
    {{0,0},"NtUserFindWindowEx", OK, DRSYS_TYPE_HANDLE, 5,
     {
         {2, sizeof(UNICODE_STRING), R|CT, SYSARG_TYPE_UNICODE_STRING},
         {3, sizeof(UNICODE_STRING), R|CT, SYSARG_TYPE_UNICODE_STRING},
     }
    },
    {{0,0},"NtUserFlashWindowEx", OK, SYSARG_TYPE_BOOL32, 1,
     {
         {0, SYSARG_SIZE_IN_FIELD, R, offsetof(FLASHWINFO, cbSize)},
     }
    },
    {{0,0},"NtUserGetAltTabInfo", OK, SYSARG_TYPE_BOOL32, 6,
     {
         {2, SYSARG_SIZE_IN_FIELD, W, offsetof(ALTTABINFO, cbSize)},
         /*buffer is ansi or unicode so special-cased*/
     }, &sysnum_UserGetAltTabInfo
    },
    {{0,0},"NtUserGetAncestor", OK, DRSYS_TYPE_HANDLE, 2, },
    {{0,0},"NtUserGetAppImeLevel", OK|SYSINFO_IMM32_DLL, SYSARG_TYPE_UINT32, 1, },
    {{0,0},"NtUserGetAsyncKeyState", OK, SYSARG_TYPE_SINT16, 1, },
    {{0,0},"NtUserGetAtomName", OK, SYSARG_TYPE_UINT32, 2,
     {
         {1, sizeof(UNICODE_STRING), W|CT, SYSARG_TYPE_UNICODE_STRING_NOLEN/*i#490*/},
     }
    },
    {{0,0},"NtUserGetCPD", OK, DRSYS_TYPE_UNSIGNED_INT, 3, },
    {{0,0},"NtUserGetCaretBlinkTime", OK, SYSARG_TYPE_UINT32, 0, },
    {{0,0},"NtUserGetCaretPos", OK, SYSARG_TYPE_BOOL32, 1,
     {
         {0, sizeof(POINT), W,},
     }
    },
    {{0,0},"NtUserGetClassInfo", OK, SYSARG_TYPE_BOOL32, 5,
     {
         {1, sizeof(UNICODE_STRING), R|CT, SYSARG_TYPE_UNICODE_STRING},
         {2, sizeof(WNDCLASSEXW), W|CT, SYSARG_TYPE_WNDCLASSEXW},
         {3, sizeof(PWSTR)/*pointer to existing string (ansi or unicode) is copied*/, W,},
     }
    },
    {{0,0},"NtUserGetClassInfoEx", OK, SYSARG_TYPE_BOOL32, 5,
     {
         {1, sizeof(UNICODE_STRING), R|CT, SYSARG_TYPE_UNICODE_STRING},
         {2, sizeof(WNDCLASSEXW), W|CT, SYSARG_TYPE_WNDCLASSEXW},
         {3, sizeof(PWSTR)/*pointer to existing string (ansi or unicode) is copied*/, W,},
     }
    },
    {{0,0},"NtUserGetClassLong", OK, DRSYS_TYPE_UNSIGNED_INT, 3, },
    {{0,0},"NtUserGetClassName", OK, SYSARG_TYPE_SINT32, 3,
     {
         {2, sizeof(UNICODE_STRING), W|CT, SYSARG_TYPE_UNICODE_STRING_NOLEN/*i#490*/},
     }
    },
    {{0,0},"NtUserGetClipCursor", OK, SYSARG_TYPE_BOOL32, 1,
     {
         {0, sizeof(RECT), W,},
     }
    },
    {{0,0},"NtUserGetClipboardData", OK, DRSYS_TYPE_HANDLE, 2,
     {
         {1, sizeof(GETCLIPBDATA), W,},
     }
    },
    /* XXX: reactos now has this as LPWSTR instead of PUNICODE_STRING */
    {{0,0},"NtUserGetClipboardFormatName", OK, SYSARG_TYPE_SINT32, 3,
     {
         {1, sizeof(UNICODE_STRING), W|CT, SYSARG_TYPE_UNICODE_STRING},
         /*3rd param is max count but should be able to ignore*/
     }
    },
    {{0,0},"NtUserGetClipboardOwner", OK, DRSYS_TYPE_HANDLE, 0, },
    {{0,0},"NtUserGetClipboardSequenceNumber", OK, SYSARG_TYPE_UINT32, 0, },
    {{0,0},"NtUserGetClipboardViewer", OK, DRSYS_TYPE_HANDLE, 0, },
    {{0,0},"NtUserGetComboBoxInfo", OK, SYSARG_TYPE_BOOL32, 2,
     {
         {1, SYSARG_SIZE_IN_FIELD, W, offsetof(COMBOBOXINFO, cbSize)},
     }
    },
    {{0,0},"NtUserGetControlBrush", OK, DRSYS_TYPE_HANDLE, 3, },
    {{0,0},"NtUserGetControlColor", OK, DRSYS_TYPE_HANDLE, 4, },
    {{0,0},"NtUserGetCursorFrameInfo", OK, DRSYS_TYPE_HANDLE, 4, },
    {{0,0},"NtUserGetCursorInfo", OK, SYSARG_TYPE_BOOL32, 1,
     {
         {0, SYSARG_SIZE_IN_FIELD, W, offsetof(CURSORINFO, cbSize)},
     }
    },
    {{0,0},"NtUserGetDC", OK, DRSYS_TYPE_HANDLE, 1,
     {
         {0,}
     }
    },
    {{0,0},"NtUserGetDCEx", OK, DRSYS_TYPE_HANDLE, 3,
     {
         {0,}
     }
    },
    {{0,0},"NtUserGetDoubleClickTime", OK, SYSARG_TYPE_UINT32, 0, },
    {{0,0},"NtUserGetForegroundWindow", OK, DRSYS_TYPE_HANDLE, 0, },
    {{0,0},"NtUserGetGUIThreadInfo", OK, SYSARG_TYPE_BOOL32, 2,
     {
         {1, SYSARG_SIZE_IN_FIELD, W, offsetof(GUITHREADINFO, cbSize)},
     }
    },
    {{0,0},"NtUserGetGuiResources", OK, SYSARG_TYPE_UINT32, 2, },
    {{0,0},"NtUserGetIconInfo", OK, SYSARG_TYPE_BOOL32, 6,
     {
         {1, sizeof(ICONINFO), W,},
         {2, sizeof(UNICODE_STRING), W|CT, SYSARG_TYPE_UNICODE_STRING_NOLEN/*i#490*/},
         {3, sizeof(UNICODE_STRING), W|CT, SYSARG_TYPE_UNICODE_STRING},
         {4, sizeof(DWORD), W,},
     }
    },
    {{0,0},"NtUserGetIconSize", OK, SYSARG_TYPE_BOOL32, 4,
     {
         {2, sizeof(LONG), W,},
         {3, sizeof(LONG), W,},
     }
    },
    {{0,0},"NtUserGetImeHotKey", OK, SYSARG_TYPE_UINT32, 4, },
    /* FIXME i#487: 1st param is OUT but shape is unknown */
    {{0,0},"NtUserGetImeInfoEx", UNKNOWN|SYSINFO_IMM32_DLL, SYSARG_TYPE_UINT32, 2, },
    {{0,0},"NtUserGetInternalWindowPos", OK, SYSARG_TYPE_UINT32, 3,
     {
         {1, sizeof(RECT), W,},
         {2, sizeof(POINT), W,},
     }
    },
    {{0,0},"NtUserGetKeyNameText", OK, SYSARG_TYPE_UINT32, 3,
     {
         {1, -2, W|SYSARG_SIZE_IN_ELEMENTS, sizeof(wchar_t)},
         {1, RET, W|SYSARG_SIZE_IN_ELEMENTS, sizeof(wchar_t)},
     }
    },
    {{0,0},"NtUserGetKeyState", OK, SYSARG_TYPE_SINT16, 1, },
    {{0,0},"NtUserGetKeyboardLayout", OK, DRSYS_TYPE_HANDLE, 1, },
    {{0,0},"NtUserGetKeyboardLayoutList", OK, DRSYS_TYPE_HANDLE, 2,
     {
         {1, -0, W|SYSARG_SIZE_IN_ELEMENTS, sizeof(HKL)},
         {1, RET, W|SYSARG_NO_WRITE_IF_COUNT_0|SYSARG_SIZE_IN_ELEMENTS, sizeof(HKL)},
     }
    },
    {{0,0},"NtUserGetKeyboardLayoutName", OK, DRSYS_TYPE_HANDLE, 1,
     {
         {0, KL_NAMELENGTH*sizeof(wchar_t), W|CT, SYSARG_TYPE_CSTRING_WIDE},
     }
    },
    {{0,0},"NtUserGetKeyboardState", OK, SYSARG_TYPE_UINT32, 1,
     {
         {0, sizeof(BYTE), W,},
     }
    },
    {{0,0},"NtUserGetKeyboardType", OK, SYSARG_TYPE_UINT32, 1, },
    {{0,0},"NtUserGetLastInputInfo", OK, SYSARG_TYPE_BOOL32, 1,
     {
         {0, SYSARG_SIZE_IN_FIELD, W, offsetof(LASTINPUTINFO, cbSize)},
     }
    },
    {{0,0},"NtUserGetLayeredWindowAttributes", OK, SYSARG_TYPE_BOOL32, 4,
     {
         {1, sizeof(COLORREF), W,},
         {2, sizeof(BYTE), W,},
         {3, sizeof(DWORD), W,},
     }
    },
    {{0,0},"NtUserGetListBoxInfo", OK, SYSARG_TYPE_UINT32, 1, },
    {{0,0},"NtUserGetMenuBarInfo", OK, SYSARG_TYPE_BOOL32, 4,
     {
         {3, SYSARG_SIZE_IN_FIELD, W, offsetof(MENUBARINFO, cbSize)},
     }
    },
    {{0,0},"NtUserGetMenuDefaultItem", OK, SYSARG_TYPE_UINT32, 3, },
    {{0,0},"NtUserGetMenuIndex", OK, SYSARG_TYPE_UINT32, 2, },
    {{0,0},"NtUserGetMenuItemRect", OK, SYSARG_TYPE_BOOL32, 4,
     {
         {3, sizeof(RECT), W,},
     }
    },
    {{0,0},"NtUserGetMessage", OK, RNTST, 4,
     {
         {0, sizeof(MSG), W,},
     }
    },
    {{0,0},"NtUserGetMinMaxInfo", OK, SYSARG_TYPE_BOOL32, 3,
     {
         {1, sizeof(MINMAXINFO), W,},
     }
    },
    {{0,0},"NtUserGetMonitorInfo", OK, SYSARG_TYPE_BOOL32, 2,
     {
         {1, SYSARG_SIZE_IN_FIELD, W, offsetof(MONITORINFO, cbSize)},
     }
    },
    {{0,0},"NtUserGetMouseMovePointsEx", OK, SYSARG_TYPE_UINT32, 5,
     {
         {1, -0, R,},
         {2, -3, W|SYSARG_SIZE_IN_ELEMENTS, -0},
     }
    },
    {{0,0},"NtUserGetObjectInformation", OK|SYSINFO_RET_SMALL_WRITE_LAST, SYSARG_TYPE_BOOL32, 5,
     {
         {2, -3, W},
         {2, -4, WI},
         {4, sizeof(DWORD), W},
     }
    },
    {{0,0},"NtUserGetOpenClipboardWindow", OK, DRSYS_TYPE_HANDLE, 0, },
    {{0,0},"NtUserGetPriorityClipboardFormat", OK, SYSARG_TYPE_SINT32, 2,
     {
         {0, -1, R|SYSARG_SIZE_IN_ELEMENTS, sizeof(UINT)},
     }
    },
    {{0,0},"NtUserGetProcessWindowStation", OK, DRSYS_TYPE_HANDLE, 0, },
    {{0,0},"NtUserGetRawInputBuffer", OK, SYSARG_TYPE_UINT32, 3,
     {
         {0,}
     }, /*special-cased; FIXME: i#485: see handler*/ &sysnum_UserGetRawInputBuffer
    },
    {{0,0},"NtUserGetRawInputData", OK, SYSARG_TYPE_UINT32, 5,
     {
         {2, -3, WI,},
         {2, RET, W},
         /*arg 3 is R or W => special-cased*/
     }, &sysnum_UserGetRawInputData
    },
    {{0,0},"NtUserGetRawInputDeviceInfo", OK, SYSARG_TYPE_UINT32, 4,
     {
         {0,}
     }, &sysnum_UserGetRawInputDeviceInfo
    },
    {{0,0},"NtUserGetRawInputDeviceList", OK, SYSARG_TYPE_UINT32, 3,
     {
         {0, -1, WI|SYSARG_SIZE_IN_ELEMENTS, -2},
         {1, sizeof(UINT), R|W,/*really not written when #0!=NULL but harmless; ditto below and probably elsewhere in table*/},
     }
    },
    {{0,0},"NtUserGetRegisteredRawInputDevices", OK, SYSARG_TYPE_UINT32, 3,
     {
         {0, -1, WI|SYSARG_SIZE_IN_ELEMENTS, -2},
         {1, sizeof(UINT), R|W,},
     }
    },
    {{0,0},"NtUserGetScrollBarInfo", OK, SYSARG_TYPE_BOOL32, 3,
     {
         {2, SYSARG_SIZE_IN_FIELD, W, offsetof(SCROLLBARINFO, cbSize)},
     }
    },
    {{0,0},"NtUserGetSystemMenu", OK, DRSYS_TYPE_HANDLE, 2, },
    /* FIXME i#487: on WOW64 XP and Vista (but not win7) this makes a 0x2xxx syscall
     * instead of invoking NtUserGetThreadDesktop: is it really different?
     */
    {{0,0},"NtUserGetThreadDesktop", OK|SYSINFO_REQUIRES_PREFIX, DRSYS_TYPE_HANDLE, 2, },
    {{0,0},"GetThreadDesktop", OK, RNTST, 2, },
    {{0,0},"NtUserGetThreadState", OK, DRSYS_TYPE_UNSIGNED_INT, 1, },
    {{0,0},"NtUserGetTitleBarInfo", OK, SYSARG_TYPE_BOOL8, 2,
     {
         {1, SYSARG_SIZE_IN_FIELD, W, offsetof(TITLEBARINFO, cbSize)},
     }
    },
    {{0,0},"NtUserGetUpdateRect", OK, SYSARG_TYPE_BOOL32, 3,
     {
         {1, sizeof(RECT), W,},
     }
    },
    {{0,0},"NtUserGetUpdateRgn", OK, SYSARG_TYPE_SINT32, 3, },
    {{0,0},"NtUserGetWOWClass", OK, DRSYS_TYPE_POINTER, 2,
     {
         {1, sizeof(UNICODE_STRING), R|CT, SYSARG_TYPE_UNICODE_STRING},
     }
    },
    {{0,0},"NtUserGetWindowDC", OK, DRSYS_TYPE_HANDLE, 1,
     {
         {0,}
     }, 
    },
    {{0,0},"NtUserGetWindowPlacement", OK, SYSARG_TYPE_BOOL32, 2,
     {
         {1, SYSARG_SIZE_IN_FIELD, W, offsetof(WINDOWPLACEMENT, length)},
     }
    },
    {{0,0},"NtUserHardErrorControl", OK, SYSARG_TYPE_UINT32, 3, },
    {{0,0},"NtUserHideCaret", OK, SYSARG_TYPE_BOOL32, 1, },
    {{0,0},"NtUserHiliteMenuItem", OK, SYSARG_TYPE_BOOL32, 4, },
    {{0,0},"NtUserImpersonateDdeClientWindow", OK, SYSARG_TYPE_BOOL32, 2, },
    {{0,0},"NtUserInitTask", OK, SYSARG_TYPE_UINT32, 12, },
    {{0,0},"NtUserInitialize", OK, RNTST, 3, },
    /* FIXME i#487: not sure whether these are arrays and if so how long they are */
    {{0,0},"NtUserInitializeClientPfnArrays", UNKNOWN, RNTST, 4,
     {
         {0, sizeof(PFNCLIENT), R,},
         {1, sizeof(PFNCLIENT), R,},
         {2, sizeof(PFNCLIENTWORKER), R,},
     }
    },
    {{0,0},"NtUserInternalGetWindowText", OK, SYSARG_TYPE_SINT32, 3,
     {
         {1, -2, W|SYSARG_SIZE_IN_ELEMENTS, sizeof(wchar_t)},{1,0, W|CT, SYSARG_TYPE_CSTRING_WIDE},
     }
    },
    {{0,0},"NtUserInvalidateRect", OK, SYSARG_TYPE_BOOL32, 3,
     {
         {1, sizeof(RECT), R,},
     }
    },
    {{0,0},"NtUserInvalidateRgn", OK, SYSARG_TYPE_BOOL32, 3, },
    {{0,0},"NtUserIsClipboardFormatAvailable", OK, SYSARG_TYPE_BOOL32, 1, },
    {{0,0},"NtUserKillTimer", OK, SYSARG_TYPE_BOOL32, 2, },
    {{0,0},"NtUserLoadKeyboardLayoutEx", OK, DRSYS_TYPE_HANDLE, 7,
     {
         {2, sizeof(UNICODE_STRING), R|CT, SYSARG_TYPE_UNICODE_STRING},
         {4, sizeof(UNICODE_STRING), R|CT, SYSARG_TYPE_UNICODE_STRING},
     }, &sysnum_UserLoadKeyboardLayoutEx
    },
    {{0,0},"NtUserLockWindowStation", OK, SYSARG_TYPE_BOOL32, 1, },
    {{0,0},"NtUserLockWindowUpdate", OK, SYSARG_TYPE_BOOL32, 1, },
    {{0,0},"NtUserLockWorkStation", OK, SYSARG_TYPE_BOOL32, 0, },
    {{0,0},"NtUserMNDragLeave", OK, SYSARG_TYPE_UINT32, 0, },
    {{0,0},"NtUserMNDragOver", OK, SYSARG_TYPE_UINT32, 2, },
    {{0,0},"NtUserMapVirtualKeyEx", OK, SYSARG_TYPE_UINT32, 4, },
    {{0,0},"NtUserMenuInfo", OK, SYSARG_TYPE_BOOL32, 3,
     {
         {0,}/*can be R or W*/
     }, &sysnum_UserMenuInfo
    },
    {{0,0},"NtUserMenuItemFromPoint", OK, SYSARG_TYPE_SINT32, 4, },
    {{0,0},"NtUserMenuItemInfo", OK, SYSARG_TYPE_BOOL32, 5,
     {
         {0,}/*can be R or W*/
     }, &sysnum_UserMenuItemInfo
    },
    /* i#1249: NtUserMessageCall has a lot of sub-actions based on both 2nd
     * param and 6th param.  However, enough are identical for our purposes that
     * we handle in code.  That's based on an early examination: if more and
     * more need special handling we may want to switch to a secondary table(s).
     */
    {{0,0},"NtUserMessageCall", OK, SYSARG_TYPE_BOOL32, 7,
     {
         {0, sizeof(HANDLE),  SYSARG_INLINED,    DRSYS_TYPE_HANDLE},
         {1, sizeof(UINT),    SYSARG_INLINED,    DRSYS_TYPE_UNSIGNED_INT},
         {2, sizeof(WPARAM),  SYSARG_INLINED,    DRSYS_TYPE_UNSIGNED_INT},
         /* For some WM_ codes this is a pointer: special-cased.
          * XXX: non-memarg client would want secondary table(s)!
          */
         {3, sizeof(LPARAM),  SYSARG_INLINED,    DRSYS_TYPE_SIGNED_INT},
         /* 4th param is sometimes IN and sometimes OUT so we special-case it */
         {4, sizeof(LRESULT), SYSARG_NON_MEMARG, DRSYS_TYPE_UNSIGNED_INT},
         {5, sizeof(DWORD),   SYSARG_INLINED,    DRSYS_TYPE_UNSIGNED_INT},
         {6, sizeof(BOOL),    SYSARG_INLINED,    DRSYS_TYPE_BOOL},
     }, &sysnum_UserMessageCall
    },
    {{0,0},"NtUserMinMaximize", OK, SYSARG_TYPE_UINT32, 3, },
    {{0,0},"NtUserModifyUserStartupInfoFlags", OK, SYSARG_TYPE_UINT32, 2, },
    {{0,0},"NtUserMonitorFromPoint", OK, DRSYS_TYPE_HANDLE, 2, },
    {{0,0},"NtUserMonitorFromRect", OK, DRSYS_TYPE_HANDLE, 2,
     {
         {0, sizeof(RECT), R,},
     }
    },
    {{0,0},"NtUserMonitorFromWindow", OK, DRSYS_TYPE_HANDLE, 2, },
    {{0,0},"NtUserMoveWindow", OK, SYSARG_TYPE_BOOL32, 6, },
    {{0,0},"NtUserNotifyIMEStatus", OK, SYSARG_TYPE_UINT32, 3, },
    {{0,0},"NtUserNotifyProcessCreate", OK, SYSARG_TYPE_UINT32, 4, },
    {{0,0},"NtUserNotifyWinEvent", OK, DRSYS_TYPE_VOID, 4, },
    {{0,0},"NtUserOpenClipboard", OK, SYSARG_TYPE_BOOL32, 2, },
    {{0,0},"NtUserOpenDesktop", OK, DRSYS_TYPE_HANDLE, 3,
     {
         {0, sizeof(OBJECT_ATTRIBUTES), R|CT, SYSARG_TYPE_OBJECT_ATTRIBUTES},
     }
    },
    {{0,0},"NtUserOpenInputDesktop", OK, DRSYS_TYPE_HANDLE, 3, },
    {{0,0},"NtUserOpenWindowStation", OK, DRSYS_TYPE_HANDLE, 2,
     {
         {0, sizeof(OBJECT_ATTRIBUTES), R|CT, SYSARG_TYPE_OBJECT_ATTRIBUTES},
     }
    },
    {{0,0},"NtUserPaintDesktop", OK, SYSARG_TYPE_BOOL32, 1, },
    {{0,0},"NtUserPaintMenuBar", OK, SYSARG_TYPE_UINT32, 6, },
    {{0,0},"NtUserPeekMessage", OK, RNTST, 5,
     {
         {0, sizeof(MSG), W,},
     }
    },
    {{0,0},"NtUserPostMessage", OK, SYSARG_TYPE_BOOL32, 4, },
    {{0,0},"NtUserPostThreadMessage", OK, SYSARG_TYPE_BOOL32, 4, },
    {{0,0},"NtUserPrintWindow", OK, SYSARG_TYPE_BOOL32, 3, },
    /* FIXME i#487: lots of pointers inside USERCONNECT */
    {{0,0},"NtUserProcessConnect", UNKNOWN, RNTST, 3,
     {
         {1, sizeof(USERCONNECT), W,},
     }
    },
    {{0,0},"NtUserQueryInformationThread", OK, SYSARG_TYPE_UINT32, 5, },
    {{0,0},"NtUserQueryInputContext", OK|SYSINFO_IMM32_DLL, SYSARG_TYPE_UINT32, 2, },
    {{0,0},"NtUserQuerySendMessage", OK, SYSARG_TYPE_UINT32, 1, },
    {{0,0},"NtUserQueryUserCounters", OK, SYSARG_TYPE_UINT32, 5, },
    {{0,0},"NtUserQueryWindow", OK, SYSARG_TYPE_UINT32, 2, },
    {{0,0},"NtUserRealChildWindowFromPoint", OK, DRSYS_TYPE_HANDLE, 3, },
    {{0,0},"NtUserRealInternalGetMessage", OK, SYSARG_TYPE_BOOL32, 6,
     {
         {0, sizeof(MSG), W,},
     }
    },
    {{0,0},"NtUserRealWaitMessageEx", OK, SYSARG_TYPE_BOOL32, 2, },
    {{0,0},"NtUserRedrawWindow", OK, SYSARG_TYPE_BOOL32, 4,
     {
         {1, sizeof(RECT), R,},
     }
    },
    {{0,0},"NtUserRegisterClassExWOW", OK|SYSINFO_RET_ZERO_FAIL, DRSYS_TYPE_ATOM, 7,
     {
         {0, sizeof(WNDCLASSEXW), R|CT, SYSARG_TYPE_WNDCLASSEXW},
         {1, sizeof(UNICODE_STRING), R|CT, SYSARG_TYPE_UNICODE_STRING},
         {2, sizeof(UNICODE_STRING), R|CT, SYSARG_TYPE_UNICODE_STRING},
         {3, sizeof(CLSMENUNAME), R|CT, SYSARG_TYPE_CLSMENUNAME},
         {6, sizeof(DWORD), R,},
     }
    },
    {{0,0},"NtUserRegisterHotKey", OK, SYSARG_TYPE_BOOL32, 4, },
    {{0,0},"NtUserRegisterRawInputDevices", OK, SYSARG_TYPE_BOOL32, 3,
     {
         {0, -1, R|SYSARG_SIZE_IN_ELEMENTS, -2},
     }
    },
    {{0,0},"NtUserRegisterTasklist", OK, SYSARG_TYPE_UINT32, 1, },
    {{0,0},"NtUserRegisterUserApiHook", OK, SYSARG_TYPE_BOOL32, 4,
     {
         {0, sizeof(UNICODE_STRING), R|CT, SYSARG_TYPE_UNICODE_STRING},
         {1, sizeof(UNICODE_STRING), R|CT, SYSARG_TYPE_UNICODE_STRING},
     }
    },
    {{0,0},"NtUserRegisterWindowMessage", OK, SYSARG_TYPE_UINT32, 1,
     {
         {0, sizeof(UNICODE_STRING), R|CT, SYSARG_TYPE_UNICODE_STRING},
     }
    },
    {{0,0},"NtUserRemoteConnect", OK, SYSARG_TYPE_UINT32, 3, },
    {{0,0},"NtUserRemoteRedrawRectangle", OK, SYSARG_TYPE_UINT32, 4, },
    {{0,0},"NtUserRemoteRedrawScreen", OK, SYSARG_TYPE_UINT32, 0, },
    {{0,0},"NtUserRemoteStopScreenUpdates", OK, SYSARG_TYPE_UINT32, 0, },
    {{0,0},"NtUserRemoveMenu", OK, SYSARG_TYPE_BOOL32, 3, },
    {{0,0},"NtUserRemoveProp", OK, DRSYS_TYPE_HANDLE, 2, },
    {{0,0},"NtUserResolveDesktop", OK, SYSARG_TYPE_UINT32, 4, },
    {{0,0},"NtUserResolveDesktopForWOW", OK, SYSARG_TYPE_UINT32, 1, },
    /* FIXME i#487: not sure whether #2 is in or out */
    {{0,0},"NtUserSBGetParms", OK, SYSARG_TYPE_BOOL32, 4,
     {
         {2, sizeof(SBDATA), W,},
         {3, SYSARG_SIZE_IN_FIELD, W, offsetof(SCROLLINFO, cbSize)},
     }
    },
    {{0,0},"NtUserScrollDC", OK, SYSARG_TYPE_BOOL32, 7,
     {
         {3, sizeof(RECT), R,},
         {4, sizeof(RECT), R,},
         {6, sizeof(RECT), W,},
     }
    },
    {{0,0},"NtUserScrollWindowEx", OK, SYSARG_TYPE_UINT32, 8,
     {
         {3, sizeof(RECT), R,},
         {4, sizeof(RECT), R,},
         {6, sizeof(RECT), W,},
     }
    },
    {{0,0},"NtUserSelectPalette", OK, DRSYS_TYPE_HANDLE, 3, },
    {{0,0},"NtUserSendInput", OK, SYSARG_TYPE_UINT32, 3,
     {
         {1, -0, R|SYSARG_SIZE_IN_ELEMENTS, -2},
     }
    },
    {{0,0},"NtUserSetActiveWindow", OK, DRSYS_TYPE_HANDLE, 1, },
    {{0,0},"NtUserSetAppImeLevel", OK|SYSINFO_IMM32_DLL, SYSARG_TYPE_UINT32, 2, },
    {{0,0},"NtUserSetCapture", OK, DRSYS_TYPE_HANDLE, 1, },
    {{0,0},"NtUserSetClassLong", OK, DRSYS_TYPE_UNSIGNED_INT, 4, },
    {{0,0},"NtUserSetClassWord", OK, SYSARG_TYPE_UINT16, 3, },
    {{0,0},"NtUserSetClipboardData", OK, DRSYS_TYPE_HANDLE, 3,
     {
         {2, sizeof(SETCLIPBDATA), R},
     }
    },
    {{0,0},"NtUserSetClipboardViewer", OK, DRSYS_TYPE_HANDLE, 1, },
    {{0,0},"NtUserSetConsoleReserveKeys", OK, SYSARG_TYPE_UINT32, 2, },
    {{0,0},"NtUserSetCursor", OK, DRSYS_TYPE_HANDLE, 1, },
    {{0,0},"NtUserSetCursorContents", OK, SYSARG_TYPE_BOOL32, 2,
     {
         {1, sizeof(ICONINFO), R,},
     }
    },
    {{0,0},"NtUserSetCursorIconData", OK, SYSARG_TYPE_BOOL32, 6,
     {
         {1, sizeof(BOOL), R,},
         {2, sizeof(POINT), R,},
     }
    },
    {{0,0},"NtUserSetDbgTag", OK, SYSARG_TYPE_UINT32, 2, },
    {{0,0},"NtUserSetFocus", OK, DRSYS_TYPE_HANDLE, 1, },
    {{0,0},"NtUserSetImeHotKey", OK, SYSARG_TYPE_UINT32, 5, },
    {{0,0},"NtUserSetImeInfoEx", OK|SYSINFO_IMM32_DLL, SYSARG_TYPE_UINT32, 1, },
    {{0,0},"NtUserSetImeOwnerWindow", OK, SYSARG_TYPE_UINT32, 2, },
    {{0,0},"NtUserSetInformationProcess", OK, SYSARG_TYPE_UINT32, 4, },
    {{0,0},"NtUserSetInformationThread", OK, RNTST, 4, },
    {{0,0},"NtUserSetInternalWindowPos", OK, SYSARG_TYPE_UINT32, 4,
     {
         {2, sizeof(RECT), R,},
         {3, sizeof(POINT), R,},
     }
    },
    {{0,0},"NtUserSetKeyboardState", OK, SYSARG_TYPE_BOOL32, 1,
     {
         {0,256*sizeof(BYTE), R,},
     }
    },
    {{0,0},"NtUserSetLayeredWindowAttributes", OK, SYSARG_TYPE_BOOL32, 4, },
    {{0,0},"NtUserSetLogonNotifyWindow", OK, SYSARG_TYPE_BOOL32, 1, },
    {{0,0},"NtUserSetMenu", OK, SYSARG_TYPE_BOOL32, 3, },
    {{0,0},"NtUserSetMenuContextHelpId", OK, SYSARG_TYPE_BOOL32, 2, },
    {{0,0},"NtUserSetMenuDefaultItem", OK, SYSARG_TYPE_BOOL32, 3, },
    {{0,0},"NtUserSetMenuFlagRtoL", OK, SYSARG_TYPE_BOOL32, 1, },
    {{0,0},"NtUserSetObjectInformation", OK, SYSARG_TYPE_BOOL32, 4,
     {
         {2, -3, R,},
     }
    },
    {{0,0},"NtUserSetParent", OK, DRSYS_TYPE_HANDLE, 2, },
    {{0,0},"NtUserSetProcessWindowStation", OK, SYSARG_TYPE_BOOL32, 1, },
    {{0,0},"NtUserSetProp", OK, SYSARG_TYPE_BOOL32, 3, },
    {{0,0},"NtUserSetRipFlags", OK, SYSARG_TYPE_UINT32, 2, },
    {{0,0},"NtUserSetScrollBarInfo", OK, SYSARG_TYPE_BOOL32, 3,
     {
         {2, sizeof(SETSCROLLBARINFO), R,},
     }
    },
    {{0,0},"NtUserSetScrollInfo", OK, SYSARG_TYPE_UINT32, 4,
     {
         /* Special-cased b/c some fields are ignored (i#1299) */
         {2, SYSARG_SIZE_IN_FIELD, SYSARG_NON_MEMARG, offsetof(SCROLLINFO, cbSize)},
     }, &sysnum_UserSetScrollInfo,
    },
    {{0,0},"NtUserSetShellWindowEx", OK, SYSARG_TYPE_BOOL32, 2, },
    {{0,0},"NtUserSetSysColors", OK, SYSARG_TYPE_BOOL32, 4,
     {
         {1, -0, R|SYSARG_SIZE_IN_ELEMENTS, sizeof(INT)},
         {2, -0, R|SYSARG_SIZE_IN_ELEMENTS, sizeof(COLORREF)},
     }
    },
    {{0,0},"NtUserSetSystemCursor", OK, SYSARG_TYPE_BOOL32, 2, },
    {{0,0},"NtUserSetSystemMenu", OK, SYSARG_TYPE_BOOL32, 2, },
    {{0,0},"NtUserSetSystemTimer", OK, DRSYS_TYPE_UNSIGNED_INT, 4, },
    {{0,0},"NtUserSetThreadDesktop", OK, SYSARG_TYPE_BOOL32, 1, },
    {{0,0},"NtUserSetThreadLayoutHandles", OK|SYSINFO_IMM32_DLL, SYSARG_TYPE_UINT32, 2, },
    {{0,0},"NtUserSetThreadState", OK, SYSARG_TYPE_UINT32, 2, },
    {{0,0},"NtUserSetTimer", OK, DRSYS_TYPE_UNSIGNED_INT, 4, },
    {{0,0},"NtUserSetWinEventHook", OK, DRSYS_TYPE_HANDLE, 8,
     {
         {3, sizeof(UNICODE_STRING), R|CT, SYSARG_TYPE_UNICODE_STRING},
     }
    },
    {{0,0},"NtUserSetWindowFNID", OK, SYSARG_TYPE_BOOL32, 2, },
    {{0,0},"NtUserSetWindowLong", OK, SYSARG_TYPE_SINT32, 4, },
    {{0,0},"NtUserSetWindowPlacement", OK, SYSARG_TYPE_BOOL32, 2,
     {
         {1, SYSARG_SIZE_IN_FIELD, R, offsetof(WINDOWPLACEMENT, length)},
     }
    },
    {{0,0},"NtUserSetWindowPos", OK, SYSARG_TYPE_BOOL32, 7, },
    {{0,0},"NtUserSetWindowRgn", OK, SYSARG_TYPE_SINT32, 3, },
    {{0,0},"NtUserSetWindowStationUser", OK, SYSARG_TYPE_UINT32, 4, },
    {{0,0},"NtUserSetWindowWord", OK, SYSARG_TYPE_UINT16, 3, },
    {{0,0},"NtUserSetWindowsHookAW", OK, DRSYS_TYPE_HANDLE, 3, },
    {{0,0},"NtUserSetWindowsHookEx", OK, DRSYS_TYPE_HANDLE, 6,
     {
         {1, sizeof(UNICODE_STRING), R|CT, SYSARG_TYPE_UNICODE_STRING},
     }
    },
    {{0,0},"NtUserShowCaret", OK, SYSARG_TYPE_BOOL32, 1, },
    {{0,0},"NtUserShowScrollBar", OK, SYSARG_TYPE_UINT32, 3, },
    {{0,0},"NtUserShowWindow", OK, SYSARG_TYPE_BOOL32, 2, },
    {{0,0},"NtUserShowWindowAsync", OK, SYSARG_TYPE_BOOL32, 2, },
    {{0,0},"NtUserSoundSentry", OK, SYSARG_TYPE_BOOL32, 0, },
    {{0,0},"NtUserSwitchDesktop", OK, SYSARG_TYPE_BOOL32, 1, },
    {{0,0},"NtUserSystemParametersInfo", OK, SYSARG_TYPE_BOOL32, 1/*rest are optional*/,
     {
         {0,},/*special-cased*/
     }, &sysnum_UserSystemParametersInfo
    },
    {{0,0},"NtUserTestForInteractiveUser", OK, SYSARG_TYPE_UINT32, 1, },
    /* there is a pointer in MENUINFO but it's user-defined */
    {{0,0},"NtUserThunkedMenuInfo", OK, SYSARG_TYPE_BOOL32, 2,
     {
         {1, sizeof(MENUINFO), R,},
     }
    },
    {{0,0},"NtUserThunkedMenuItemInfo", OK, SYSARG_TYPE_BOOL32, 6,
     {
         {4,0, R|CT, SYSARG_TYPE_MENUITEMINFOW},
         {5, sizeof(UNICODE_STRING), R|CT, SYSARG_TYPE_UNICODE_STRING},
     }
    },
    {{0,0},"NtUserToUnicodeEx", OK, SYSARG_TYPE_SINT32, 7,
     {
         {2,0x100*sizeof(BYTE), R,},
         {3, -4, W|SYSARG_SIZE_IN_ELEMENTS, sizeof(wchar_t)},
     }
    },
    {{0,0},"NtUserTrackMouseEvent", OK, SYSARG_TYPE_BOOL32, 1,
     {
         {0,}
     }, &sysnum_UserTrackMouseEvent
    },
    {{0,0},"NtUserTrackPopupMenuEx", OK, SYSARG_TYPE_BOOL32, 6,
     {
         {5, SYSARG_SIZE_IN_FIELD, R, offsetof(TPMPARAMS, cbSize)},
     }
    },
    {{0,0},"NtUserTranslateAccelerator", OK, SYSARG_TYPE_SINT32, 3,
     {
         {2, sizeof(MSG), R,},
     }
    },
    {{0,0},"NtUserTranslateMessage", OK, SYSARG_TYPE_BOOL32, 2,
     {
         {0, sizeof(MSG), R,},
     }
    },
    {{0,0},"NtUserUnhookWinEvent", OK, SYSARG_TYPE_BOOL32, 1, },
    {{0,0},"NtUserUnhookWindowsHookEx", OK, SYSARG_TYPE_BOOL32, 1, },
    {{0,0},"NtUserUnloadKeyboardLayout", OK, SYSARG_TYPE_BOOL32, 1, },
    {{0,0},"NtUserUnlockWindowStation", OK, SYSARG_TYPE_BOOL32, 1, },
    /* FIXME i#487: CLSMENUNAME format is not fully known */
    {{0,0},"NtUserUnregisterClass", UNKNOWN, SYSARG_TYPE_BOOL32, 3,
     {
         {0, sizeof(UNICODE_STRING), R|CT, SYSARG_TYPE_UNICODE_STRING},
         {2, sizeof(CLSMENUNAME), W|CT, SYSARG_TYPE_CLSMENUNAME,},
     }
    },
    {{0,0},"NtUserUnregisterHotKey", OK, SYSARG_TYPE_BOOL32, 2, },
    {{0,0},"NtUserUnregisterUserApiHook", OK, SYSARG_TYPE_BOOL32, 0, },
    {{0,0},"NtUserUpdateInputContext", OK, SYSARG_TYPE_UINT32, 3, },
    {{0,0},"NtUserUpdateInstance", OK, SYSARG_TYPE_UINT32, 3, },
    {{0,0},"NtUserUpdateLayeredWindow", OK, SYSARG_TYPE_BOOL32, 10,
     {
         {2, sizeof(POINT), R,},
         {3, sizeof(SIZE), R,},
         {5, sizeof(POINT), R,},
         {7, sizeof(BLENDFUNCTION), R,},
         {9, sizeof(RECT), R,},
     }
    },
    {{0,0},"NtUserUpdatePerUserSystemParameters", OK, SYSARG_TYPE_BOOL32, 2, },
    {{0,0},"NtUserUserHandleGrantAccess", OK, SYSARG_TYPE_BOOL32, 3, },
    {{0,0},"NtUserValidateHandleSecure", OK, SYSARG_TYPE_BOOL32, 2, },
    {{0,0},"NtUserValidateRect", OK, SYSARG_TYPE_BOOL32, 2,
     {
         {1, sizeof(RECT), R,},
     }
    },
    {{0,0},"NtUserValidateTimerCallback", OK, RNTST, 3, },
    {{0,0},"NtUserVkKeyScanEx", OK, SYSARG_TYPE_UINT32, 3, },
    {{0,0},"NtUserWaitForInputIdle", OK, SYSARG_TYPE_UINT32, 3, },
    {{0,0},"NtUserWaitForMsgAndEvent", OK, SYSARG_TYPE_UINT32, 1, },
    {{0,0},"NtUserWaitMessage", OK, SYSARG_TYPE_BOOL32, 0, },
    {{0,0},"NtUserWin32PoolAllocationStats", OK, SYSARG_TYPE_UINT32, 6, },
    {{0,0},"NtUserWindowFromPhysicalPoint", OK, DRSYS_TYPE_HANDLE, 1, },
    {{0,0},"NtUserWindowFromPoint", OK, DRSYS_TYPE_HANDLE, 2, },
    {{0,0},"NtUserYieldTask", OK, SYSARG_TYPE_UINT32, 0, },

    {{0,0},"NtUserUserConnectToServer", OK, RNTST, 3,
     {
         {0,0, R|CT, SYSARG_TYPE_CSTRING_WIDE},
         {1, -2, WI},
         {2, sizeof(ULONG), R|W},
     }
    },

    /***************************************************/
    /* FIXME i#1095: fill in the unknown info, esp Vista+ */
    {{0,0},"NtUserCallUserpExitWindowsEx", UNKNOWN, DRSYS_TYPE_UNKNOWN, },
    {{0,0},"NtUserCallUserpRegisterLogonProcess", UNKNOWN, DRSYS_TYPE_UNKNOWN, },
    {{0,0},"NtUserDeviceEventWorker", UNKNOWN, DRSYS_TYPE_UNKNOWN, },
    {{0,0},"NtUserEndTask", UNKNOWN, DRSYS_TYPE_UNKNOWN, },
    {{0,0},"NtUserLogon", UNKNOWN, DRSYS_TYPE_UNKNOWN, },
    {{0,0},"NtUserRegisterServicesProcess", UNKNOWN, DRSYS_TYPE_UNKNOWN, },

    /***************************************************/
    /* Added in Vista */
    {{0,0},"NtUserGetProp", OK, RNTST, 2, },
    {{0,0},"NtUserAddClipboardFormatListener", UNKNOWN, DRSYS_TYPE_UNKNOWN, },
    {{0,0},"NtUserCheckAccessForIntegrityLevel", UNKNOWN, DRSYS_TYPE_UNKNOWN, },
    {{0,0},"NtUserCreateDesktopEx", UNKNOWN, DRSYS_TYPE_UNKNOWN, },
    {{0,0},"NtUserDoSoundConnect", UNKNOWN, DRSYS_TYPE_UNKNOWN, },
    {{0,0},"NtUserDoSoundDisconnect", UNKNOWN, DRSYS_TYPE_UNKNOWN, },
    {{0,0},"NtUserDwmGetDxRgn", UNKNOWN, DRSYS_TYPE_UNKNOWN, },
    {{0,0},"NtUserDwmHintDxUpdate", UNKNOWN, DRSYS_TYPE_UNKNOWN, },
    {{0,0},"NtUserDwmStartRedirection", UNKNOWN, DRSYS_TYPE_UNKNOWN, },
    {{0,0},"NtUserDwmStopRedirection", UNKNOWN, DRSYS_TYPE_UNKNOWN, },
    {{0,0},"NtUserEndTouchOperation", UNKNOWN, DRSYS_TYPE_UNKNOWN, },
    {{0,0},"NtUserFrostCrashedWindow", UNKNOWN, DRSYS_TYPE_UNKNOWN, },
    {{0,0},"NtUserGetUpdatedClipboardFormats", UNKNOWN, DRSYS_TYPE_UNKNOWN, },
    {{0,0},"NtUserGetWindowMinimizeRect", UNKNOWN, DRSYS_TYPE_UNKNOWN, },
    {{0,0},"NtUserGetWindowRgnEx", UNKNOWN, DRSYS_TYPE_UNKNOWN, },
    {{0,0},"NtUserGhostWindowFromHungWindow", UNKNOWN, DRSYS_TYPE_UNKNOWN, },
    {{0,0},"NtUserHungWindowFromGhostWindow", UNKNOWN, DRSYS_TYPE_UNKNOWN, },
    {{0,0},"NtUserInternalGetWindowIcon", UNKNOWN, DRSYS_TYPE_UNKNOWN, },
    {{0,0},"NtUserLogicalToPhysicalPoint", UNKNOWN, DRSYS_TYPE_UNKNOWN, },
    {{0,0},"NtUserOpenThreadDesktop", UNKNOWN, DRSYS_TYPE_UNKNOWN, },
    {{0,0},"NtUserPaintMonitor", UNKNOWN, DRSYS_TYPE_UNKNOWN, },
    {{0,0},"NtUserPhysicalToLogicalPoint", UNKNOWN, DRSYS_TYPE_UNKNOWN, },
    {{0,0},"NtUserRegisterErrorReportingDialog", UNKNOWN, DRSYS_TYPE_UNKNOWN, },
    {{0,0},"NtUserRegisterSessionPort", UNKNOWN, DRSYS_TYPE_UNKNOWN, },
    {{0,0},"NtUserRemoveClipboardFormatListener", UNKNOWN, DRSYS_TYPE_UNKNOWN, },
    {{0,0},"NtUserSetMirrorRendering", UNKNOWN, DRSYS_TYPE_UNKNOWN, },
    {{0,0},"NtUserSetProcessDPIAware", UNKNOWN, DRSYS_TYPE_UNKNOWN, },
    {{0,0},"NtUserSetWindowRgnEx", UNKNOWN, DRSYS_TYPE_UNKNOWN, },
    {{0,0},"NtUserShowSystemCursor", UNKNOWN, DRSYS_TYPE_UNKNOWN, },
    {{0,0},"NtUserShutdownBlockReasonCreate", UNKNOWN, DRSYS_TYPE_UNKNOWN, },
    {{0,0},"NtUserShutdownBlockReasonDestroy", UNKNOWN, DRSYS_TYPE_UNKNOWN, },
    {{0,0},"NtUserShutdownBlockReasonQuery", UNKNOWN, DRSYS_TYPE_UNKNOWN, },
    {{0,0},"NtUserUnregisterSessionPort", UNKNOWN, DRSYS_TYPE_UNKNOWN, },
    {{0,0},"NtUserUpdateWindowTransform", UNKNOWN, DRSYS_TYPE_UNKNOWN, },

    /***************************************************/
    /* Added in Win7 */
    {{0,0},"NtUserCalculatePopupWindowPosition", UNKNOWN, DRSYS_TYPE_UNKNOWN, },
    {{0,0},"NtUserChangeWindowMessageFilterEx", UNKNOWN, DRSYS_TYPE_UNKNOWN, },
    {{0,0},"NtUserDesktopHasWatermarkText", UNKNOWN, DRSYS_TYPE_UNKNOWN, },
    {{0,0},"NtUserDisplayConfigGetDeviceInfo", UNKNOWN, DRSYS_TYPE_UNKNOWN, },
    {{0,0},"NtUserDisplayConfigSetDeviceInfo", UNKNOWN, DRSYS_TYPE_UNKNOWN, },
    {{0,0},"NtUserGetDisplayConfigBufferSizes", UNKNOWN, DRSYS_TYPE_UNKNOWN, },
    {{0,0},"NtUserGetGestureConfig", UNKNOWN, DRSYS_TYPE_UNKNOWN, },
    {{0,0},"NtUserGetGestureExtArgs", UNKNOWN, DRSYS_TYPE_UNKNOWN, },
    {{0,0},"NtUserGetGestureInfo", UNKNOWN, DRSYS_TYPE_UNKNOWN, },
    {{0,0},"NtUserGetInputLocaleInfo", UNKNOWN, DRSYS_TYPE_UNKNOWN, },
    {{0,0},"NtUserGetTopLevelWindow", UNKNOWN, DRSYS_TYPE_UNKNOWN, },
    {{0,0},"NtUserGetTouchInputInfo", UNKNOWN, DRSYS_TYPE_UNKNOWN, },
    {{0,0},"NtUserGetWindowCompositionAttribute", UNKNOWN, DRSYS_TYPE_UNKNOWN, },
    {{0,0},"NtUserGetWindowCompositionInfo", UNKNOWN, DRSYS_TYPE_UNKNOWN, },
    {{0,0},"NtUserGetWindowDisplayAffinity", UNKNOWN, DRSYS_TYPE_UNKNOWN, },
    {{0,0},"NtUserHwndQueryRedirectionInfo", UNKNOWN, DRSYS_TYPE_UNKNOWN, },
    {{0,0},"NtUserHwndSetRedirectionInfo", UNKNOWN, DRSYS_TYPE_UNKNOWN, },
    {{0,0},"NtUserInjectGesture", UNKNOWN, DRSYS_TYPE_UNKNOWN, },
    {{0,0},"NtUserIsTopLevelWindow", UNKNOWN, DRSYS_TYPE_UNKNOWN, },
    {{0,0},"NtUserIsTouchWindow", UNKNOWN, DRSYS_TYPE_UNKNOWN, },
    {{0,0},"NtUserMagControl", UNKNOWN, DRSYS_TYPE_UNKNOWN, },
    {{0,0},"NtUserMagGetContextInformation", UNKNOWN, DRSYS_TYPE_UNKNOWN, },
    {{0,0},"NtUserMagSetContextInformation", UNKNOWN, DRSYS_TYPE_UNKNOWN, },
    {{0,0},"NtUserManageGestureHandlerWindow", UNKNOWN, DRSYS_TYPE_UNKNOWN, },
    {{0,0},"NtUserModifyWindowTouchCapability", UNKNOWN, DRSYS_TYPE_UNKNOWN, },
    {{0,0},"NtUserQueryDisplayConfig", UNKNOWN, DRSYS_TYPE_UNKNOWN, },
    {{0,0},"NtUserSendTouchInput", UNKNOWN, DRSYS_TYPE_UNKNOWN, },
    {{0,0},"NtUserSetChildWindowNoActivate", UNKNOWN, DRSYS_TYPE_UNKNOWN, },
    {{0,0},"NtUserSetDisplayConfig", UNKNOWN, DRSYS_TYPE_UNKNOWN, },
    {{0,0},"NtUserSetGestureConfig", UNKNOWN, DRSYS_TYPE_UNKNOWN, },
    {{0,0},"NtUserSetWindowCompositionAttribute", UNKNOWN, DRSYS_TYPE_UNKNOWN, },
    {{0,0},"NtUserSetWindowDisplayAffinity", UNKNOWN, DRSYS_TYPE_UNKNOWN, },
    {{0,0},"NtUserSfmDestroyLogicalSurfaceBinding", UNKNOWN, DRSYS_TYPE_UNKNOWN, },
    {{0,0},"NtUserSfmDxBindSwapChain", UNKNOWN, DRSYS_TYPE_UNKNOWN, },
    {{0,0},"NtUserSfmDxGetSwapChainStats", UNKNOWN, DRSYS_TYPE_UNKNOWN, },
    {{0,0},"NtUserSfmDxOpenSwapChain", UNKNOWN, DRSYS_TYPE_UNKNOWN, },
    {{0,0},"NtUserSfmDxQuerySwapChainBindingStatus", UNKNOWN, DRSYS_TYPE_UNKNOWN, },
    {{0,0},"NtUserSfmDxReleaseSwapChain", UNKNOWN, DRSYS_TYPE_UNKNOWN, },
    {{0,0},"NtUserSfmDxReportPendingBindingsToDwm", UNKNOWN, DRSYS_TYPE_UNKNOWN, },
    {{0,0},"NtUserSfmDxSetSwapChainBindingStatus", UNKNOWN, DRSYS_TYPE_UNKNOWN, },
    {{0,0},"NtUserSfmDxSetSwapChainStats", UNKNOWN, DRSYS_TYPE_UNKNOWN, },
    {{0,0},"NtUserSfmGetLogicalSurfaceBinding", UNKNOWN, DRSYS_TYPE_UNKNOWN, },

    /***************************************************/
    /* Added in Win8 */
    /* FIXME i#1153: fill in details */
    {{0,0},"NtUserAcquireIAMKey", UNKNOWN, DRSYS_TYPE_UNKNOWN, 1, },
    {{0,0},"NtUserAutoPromoteMouseInPointer", UNKNOWN, DRSYS_TYPE_UNKNOWN, 1, },
    {{0,0},"NtUserCanBrokerForceForeground", UNKNOWN, DRSYS_TYPE_UNKNOWN, 1, },
    {{0,0},"NtUserCheckProcessForClipboardAccess", UNKNOWN, DRSYS_TYPE_UNKNOWN, 2, },
    {{0,0},"NtUserCheckProcessSession", UNKNOWN, DRSYS_TYPE_UNKNOWN, 1, },
    {{0,0},"NtUserCreateDCompositionHwndTarget", UNKNOWN, DRSYS_TYPE_UNKNOWN, 4, },
    {{0,0},"NtUserDeferWindowPosAndBand", UNKNOWN, DRSYS_TYPE_UNKNOWN, 10, },
    {{0,0},"NtUserDelegateCapturePointers", UNKNOWN, DRSYS_TYPE_UNKNOWN, 3, },
    {{0,0},"NtUserDelegateInput", UNKNOWN, DRSYS_TYPE_UNKNOWN, 6, },
    {{0,0},"NtUserDestroyDCompositionHwndTarget", UNKNOWN, DRSYS_TYPE_UNKNOWN, 2, },
    {{0,0},"NtUserDisableImmersiveOwner", UNKNOWN, DRSYS_TYPE_UNKNOWN, 1, },
    {{0,0},"NtUserDisableProcessWindowFiltering", UNKNOWN, DRSYS_TYPE_UNKNOWN, 0, },
    {{0,0},"NtUserDiscardPointerFrameMessages", UNKNOWN, DRSYS_TYPE_UNKNOWN, 1, },
    {{0,0},"NtUserDwmGetRemoteSessionOcclusionEvent", UNKNOWN, DRSYS_TYPE_UNKNOWN, 0, },
    {{0,0},"NtUserDwmGetRemoteSessionOcclusionState", UNKNOWN, DRSYS_TYPE_UNKNOWN, 0, },
    {{0,0},"NtUserDwmValidateWindow", UNKNOWN, DRSYS_TYPE_UNKNOWN, 2, },
    {{0,0},"NtUserEnableIAMAccess", UNKNOWN, DRSYS_TYPE_UNKNOWN, 3, },
    {{0,0},"NtUserEnableMouseInPointer", UNKNOWN, DRSYS_TYPE_UNKNOWN, 1, },
    {{0,0},"NtUserEnableMouseInputForCursorSuppression", UNKNOWN, DRSYS_TYPE_UNKNOWN, 1, },
    {{0,0},"NtUserGetAutoRotationState", UNKNOWN, DRSYS_TYPE_UNKNOWN, 1, },
    {{0,0},"NtUserGetCIMSSM", UNKNOWN, DRSYS_TYPE_UNKNOWN, 1, },
    {{0,0},"NtUserGetClipboardAccessToken", UNKNOWN, DRSYS_TYPE_UNKNOWN, 2, },
    {{0,0},"NtUserGetCurrentInputMessageSource", UNKNOWN, DRSYS_TYPE_UNKNOWN, 1, },
    {{0,0},"NtUserGetDesktopID", UNKNOWN, DRSYS_TYPE_UNKNOWN, 2, },
    {{0,0},"NtUserGetDisplayAutoRotationPreferencesByProcessId", UNKNOWN, DRSYS_TYPE_UNKNOWN, 3, },
    {{0,0},"NtUserGetDisplayAutoRotationPreferences", UNKNOWN, DRSYS_TYPE_UNKNOWN, 1, },
    {{0,0},"NtUserGetGlobalIMEStatus", UNKNOWN, DRSYS_TYPE_UNKNOWN, 2, },
    {{0,0},"NtUserGetPointerCursorId", UNKNOWN, DRSYS_TYPE_UNKNOWN, 2, },
    {{0,0},"NtUserGetPointerDeviceCursors", UNKNOWN, DRSYS_TYPE_UNKNOWN, 3, },
    {{0,0},"NtUserGetPointerDeviceProperties", UNKNOWN, DRSYS_TYPE_UNKNOWN, 3, },
    {{0,0},"NtUserGetPointerDeviceRects", UNKNOWN, DRSYS_TYPE_UNKNOWN, 3, },
    {{0,0},"NtUserGetPointerDevices", UNKNOWN, DRSYS_TYPE_UNKNOWN, 2, },
    {{0,0},"NtUserGetPointerDevice", UNKNOWN, DRSYS_TYPE_UNKNOWN, 2, },
    {{0,0},"NtUserGetPointerDeviceCursors", UNKNOWN, DRSYS_TYPE_UNKNOWN, 3, },
    {{0,0},"NtUserGetPointerDeviceProperties", UNKNOWN, DRSYS_TYPE_UNKNOWN, 3, },
    {{0,0},"NtUserGetPointerDeviceRects", UNKNOWN, DRSYS_TYPE_UNKNOWN, 3, },
    {{0,0},"NtUserGetPointerDevices", UNKNOWN, DRSYS_TYPE_UNKNOWN, 2, },
    {{0,0},"NtUserGetPointerInfoList", UNKNOWN, DRSYS_TYPE_UNKNOWN, 8, },
    {{0,0},"NtUserGetPointerType", UNKNOWN, DRSYS_TYPE_UNKNOWN, 2, },
    {{0,0},"NtUserGetProcessUIContextInformation", OK, DRSYS_TYPE_BOOL, 2,
     {
         {0, sizeof(HANDLE), SYSARG_INLINED, DRSYS_TYPE_HANDLE},
         {1, sizeof(PROCESS_UI_CONTEXT), W,},
     }
    },
    {{0,0},"NtUserGetQueueEventStatus", UNKNOWN, DRSYS_TYPE_UNKNOWN, 0, },
    {{0,0},"NtUserGetRawPointerDeviceData", UNKNOWN, DRSYS_TYPE_UNKNOWN, 5, },
    {{0,0},"NtUserGetTouchValidationStatus", UNKNOWN, DRSYS_TYPE_UNKNOWN, 1, },
    {{0,0},"NtUserGetWindowBand", UNKNOWN, DRSYS_TYPE_UNKNOWN, 2, },
    {{0,0},"NtUserGetWindowFeedbackSetting", UNKNOWN, DRSYS_TYPE_UNKNOWN, 5, },
    {{0,0},"NtUserHandleDelegatedInput", UNKNOWN, DRSYS_TYPE_UNKNOWN, 2, },
    {{0,0},"NtUserHidePointerContactVisualization", UNKNOWN, DRSYS_TYPE_UNKNOWN, 1, },
    {{0,0},"NtUserInitializeClientPfnArrays", UNKNOWN, DRSYS_TYPE_UNKNOWN, 4, },
    {{0,0},"NtUserInitializeTouchInjection", UNKNOWN, DRSYS_TYPE_UNKNOWN, 2, },
    {{0,0},"NtUserInitializeTouchInjection", UNKNOWN, DRSYS_TYPE_UNKNOWN, 2, },
    {{0,0},"NtUserInjectTouchInput", UNKNOWN, DRSYS_TYPE_UNKNOWN, 2, },
    {{0,0},"NtUserInternalClipCursor", UNKNOWN, DRSYS_TYPE_UNKNOWN, 2, },
    {{0,0},"NtUserIsMouseInPointerEnabled", UNKNOWN, DRSYS_TYPE_UNKNOWN, 0, },
    {{0,0},"NtUserIsMouseInputEnabled", UNKNOWN, DRSYS_TYPE_UNKNOWN, 0, },
    {{0,0},"NtUserLayoutCompleted", UNKNOWN, DRSYS_TYPE_UNKNOWN, 3, },
    {{0,0},"NtUserPromotePointer", UNKNOWN, DRSYS_TYPE_UNKNOWN, 2, },
    {{0,0},"NtUserQueryBSDRWindow", UNKNOWN, DRSYS_TYPE_UNKNOWN, 0, },
    {{0,0},"NtUserRegisterBSDRWindow", UNKNOWN, DRSYS_TYPE_UNKNOWN, 2, },
    {{0,0},"NtUserRegisterEdgy", UNKNOWN, DRSYS_TYPE_UNKNOWN, 3, },
    {{0,0},"NtUserRegisterPointerDeviceNotifications", UNKNOWN, DRSYS_TYPE_UNKNOWN, 2, },
    {{0,0},"NtUserRegisterPointerInputTarget", UNKNOWN, DRSYS_TYPE_UNKNOWN, 3, },
    {{0,0},"NtUserRegisterTouchHitTestingWindow", UNKNOWN, DRSYS_TYPE_UNKNOWN, 2, },
    {{0,0},"NtUserSendEventMessage", UNKNOWN, DRSYS_TYPE_UNKNOWN, 4, },
    {{0,0},"NtUserSetActiveProcess", UNKNOWN, DRSYS_TYPE_UNKNOWN, 1, },
    {{0,0},"NtUserSetAutoRotation", UNKNOWN, DRSYS_TYPE_UNKNOWN, 1, },
    {{0,0},"NtUserSetBrokeredForeground", UNKNOWN, DRSYS_TYPE_UNKNOWN, 1, },
    {{0,0},"NtUserSetCalibrationData", UNKNOWN, DRSYS_TYPE_UNKNOWN, 4, },
    {{0,0},"NtUserSetDisplayAutoRotationPreferences", UNKNOWN, DRSYS_TYPE_UNKNOWN, 1, },
    {{0,0},"NtUserSetDisplayMapping", UNKNOWN, DRSYS_TYPE_UNKNOWN, 2, },
    {{0,0},"NtUserSetFallbackForeground", UNKNOWN, DRSYS_TYPE_UNKNOWN, 2, },
    {{0,0},"NtUserSetImmersiveBackgroundWindow", UNKNOWN, DRSYS_TYPE_UNKNOWN, 1, },
    {{0,0},"NtUserSetProcessRestrictionExemption", UNKNOWN, DRSYS_TYPE_UNKNOWN, 1, },
    {{0,0},"NtUserSetProcessUIAccessZorder", UNKNOWN, DRSYS_TYPE_UNKNOWN, 0, },
    {{0,0},"NtUserSetThreadInputBlocked", UNKNOWN, DRSYS_TYPE_UNKNOWN, 2, },
    {{0,0},"NtUserSetWindowBand", UNKNOWN, DRSYS_TYPE_UNKNOWN, 3, },
    {{0,0},"NtUserSetWindowCompositionTransition", UNKNOWN, DRSYS_TYPE_UNKNOWN, 6, },
    {{0,0},"NtUserSetWindowFeedbackSetting", UNKNOWN, DRSYS_TYPE_UNKNOWN, 5, },
    {{0,0},"NtUserSignalRedirectionStartComplete", UNKNOWN, DRSYS_TYPE_UNKNOWN, 0, },
    {{0,0},"NtUserSlicerControl", UNKNOWN, DRSYS_TYPE_UNKNOWN, 4, },
    {{0,0},"NtUserUndelegateInput", UNKNOWN, DRSYS_TYPE_UNKNOWN, 2, },
    {{0,0},"NtUserUpdateDefaultDesktopThumbnail", UNKNOWN, DRSYS_TYPE_UNKNOWN, 5, },
    {{0,0},"NtUserWaitAvailableMessageEx", UNKNOWN, DRSYS_TYPE_UNKNOWN, 2, },
    {{0,0},"NtUserWaitForRedirectionStartComplete", UNKNOWN, DRSYS_TYPE_UNKNOWN, 0, },
};
#define NUM_USER32_SYSCALLS \
    (sizeof(syscall_user32_info)/sizeof(syscall_user32_info[0]))

size_t
num_user32_syscalls(void)
{
    return NUM_USER32_SYSCALLS;
}

/***************************************************************************
 * NtUserCall* secondary system call numbers
 */

#define NONE -1

static const char * const usercall_names[] = {
#define USERCALL(type, name, w8, w7, vistaSP2, vistaSP01, w2003, xp, w2k)   #type"."#name,
#include "drsyscall_usercallx.h"
#undef USERCALL
};
#define NUM_USERCALL_NAMES (sizeof(usercall_names)/sizeof(usercall_names[0]))

static const char * const usercall_primary[] = {
#define USERCALL(type, name, w8, w7, vistaSP2, vistaSP01, w2003, xp, w2k)   #type,
#include "drsyscall_usercallx.h"
#undef USERCALL
};

static const int win8_usercall_nums[] = {
#define USERCALL(type, name, w8, w7, vistaSP2, vistaSP01, w2003, xp, w2k)   w8,
#include "drsyscall_usercallx.h"
#undef USERCALL
};

static const int win7_usercall_nums[] = {
#define USERCALL(type, name, w8, w7, vistaSP2, vistaSP01, w2003, xp, w2k)   w7,
#include "drsyscall_usercallx.h"
#undef USERCALL
};

static const int winvistaSP2_usercall_nums[] = {
#define USERCALL(type, name, w8, w7, vistaSP2, vistaSP01, w2003, xp, w2k)   vistaSP2,
#include "drsyscall_usercallx.h"
#undef USERCALL
};

static const int winvistaSP01_usercall_nums[] = {
#define USERCALL(type, name, w8, w7, vistaSP2, vistaSP01, w2003, xp, w2k)   vistaSP01,
#include "drsyscall_usercallx.h"
#undef USERCALL
};

static const int win2003_usercall_nums[] = {
#define USERCALL(type, name, w8, w7, vistaSP2, vistaSP01, w2003, xp, w2k)   w2003,
#include "drsyscall_usercallx.h"
#undef USERCALL
};

static const int winxp_usercall_nums[] = {
#define USERCALL(type, name, w8, w7, vistaSP2, vistaSP01, w2003, xp, w2k)   xp,
#include "drsyscall_usercallx.h"
#undef USERCALL
};

static const int win2k_usercall_nums[] = {
#define USERCALL(type, name, w8, w7, vistaSP2, vistaSP01, w2003, xp, w2k)   w2k,
#include "drsyscall_usercallx.h"
#undef USERCALL
};

/* Secondary system calls for NtUserCall{No, One, Two}Param */
/* FIXME i#1094: the official return type is DWORD_PTR but it would be more useful
 * to give the actual types
 */
syscall_info_t syscall_usercall_info[] = {
    {{0,0},"NtUserCallNoParam.CREATEMENU", OK, DRSYS_TYPE_UNSIGNED_INT, 1, },
    {{0,0},"NtUserCallNoParam.CREATEMENUPOPUP", OK, DRSYS_TYPE_UNSIGNED_INT, 1, },
    {{0,0},"NtUserCallNoParam.DISABLEPROCWNDGHSTING", OK, DRSYS_TYPE_UNSIGNED_INT, 1, },
    {{0,0},"NtUserCallNoParam.MSQCLEARWAKEMASK", OK, DRSYS_TYPE_UNSIGNED_INT, 1, },
    {{0,0},"NtUserCallNoParam.ALLOWFOREGNDACTIVATION", OK, DRSYS_TYPE_UNSIGNED_INT, 1, },
    {{0,0},"NtUserCallNoParam.CREATESYSTEMTHREADS", OK, DRSYS_TYPE_UNSIGNED_INT, 1, },
    {{0,0},"NtUserCallNoParam.UNKNOWN", UNKNOWN, DRSYS_TYPE_UNSIGNED_INT, 1, },
    {{0,0},"NtUserCallNoParam.DESTROY_CARET", OK, DRSYS_TYPE_UNSIGNED_INT, 1, },
    {{0,0},"NtUserCallNoParam.GETDEVICECHANGEINFO", OK, DRSYS_TYPE_UNSIGNED_INT, 1, },
    {{0,0},"NtUserCallNoParam.GETIMESHOWSTATUS", OK, DRSYS_TYPE_UNSIGNED_INT, 1, },
    {{0,0},"NtUserCallNoParam.GETINPUTDESKTOP", OK, DRSYS_TYPE_UNSIGNED_INT, 1, },
    {{0,0},"NtUserCallNoParam.GETMSESSAGEPOS", OK, DRSYS_TYPE_UNSIGNED_INT, 1, },
    {{0,0},"NtUserCallNoParam.GETREMOTEPROCID", OK, DRSYS_TYPE_UNSIGNED_INT, 1, },
    {{0,0},"NtUserCallNoParam.HIDECURSORNOCAPTURE", OK, DRSYS_TYPE_UNSIGNED_INT, 1, },
    {{0,0},"NtUserCallNoParam.LOADCURSANDICOS", OK, DRSYS_TYPE_UNSIGNED_INT, 1, },
    {{0,0},"NtUserCallNoParam.PREPAREFORLOGOFF", OK, DRSYS_TYPE_UNSIGNED_INT, 1, },
    {{0,0},"NtUserCallNoParam.RELEASECAPTURE", OK, DRSYS_TYPE_UNSIGNED_INT, 1, },
    {{0,0},"NtUserCallNoParam.RESETDBLCLICK", OK, DRSYS_TYPE_UNSIGNED_INT, 1, },
    {{0,0},"NtUserCallNoParam.ZAPACTIVEANDFOUS", OK, DRSYS_TYPE_UNSIGNED_INT, 1, },
    {{0,0},"NtUserCallNoParam.REMOTECONSHDWSTOP", OK, DRSYS_TYPE_UNSIGNED_INT, 1, },
    {{0,0},"NtUserCallNoParam.REMOTEDISCONNECT", OK, DRSYS_TYPE_UNSIGNED_INT, 1, },
    {{0,0},"NtUserCallNoParam.REMOTELOGOFF", OK, DRSYS_TYPE_UNSIGNED_INT, 1, },
    {{0,0},"NtUserCallNoParam.REMOTENTSECURITY", OK, DRSYS_TYPE_UNSIGNED_INT, 1, },
    {{0,0},"NtUserCallNoParam.REMOTESHDWSETUP", OK, DRSYS_TYPE_UNSIGNED_INT, 1, },
    {{0,0},"NtUserCallNoParam.REMOTESHDWSTOP", OK, DRSYS_TYPE_UNSIGNED_INT, 1, },
    {{0,0},"NtUserCallNoParam.REMOTEPASSTHRUENABLE", OK, DRSYS_TYPE_UNSIGNED_INT, 1, },
    {{0,0},"NtUserCallNoParam.REMOTEPASSTHRUDISABLE", OK, DRSYS_TYPE_UNSIGNED_INT, 1, },
    {{0,0},"NtUserCallNoParam.REMOTECONNECTSTATE", OK, DRSYS_TYPE_UNSIGNED_INT, 1, },
    {{0,0},"NtUserCallNoParam.UPDATEPERUSERIMMENABLING", OK, DRSYS_TYPE_UNSIGNED_INT, 1, },
    {{0,0},"NtUserCallNoParam.USERPWRCALLOUTWORKER", OK, DRSYS_TYPE_UNSIGNED_INT, 1, },
    {{0,0},"NtUserCallNoParam.WAKERITFORSHTDWN", OK, DRSYS_TYPE_UNSIGNED_INT, 1, },
    {{0,0},"NtUserCallNoParam.INIT_MESSAGE_PUMP", OK, DRSYS_TYPE_UNSIGNED_INT, 1, },
    {{0,0},"NtUserCallNoParam.UNINIT_MESSAGE_PUMP", OK, DRSYS_TYPE_UNSIGNED_INT, 1, },
    {{0,0},"NtUserCallNoParam.LOADUSERAPIHOOK", OK, DRSYS_TYPE_UNSIGNED_INT, 1, },

    {{0,0},"NtUserCallOneParam.BEGINDEFERWNDPOS", OK, DRSYS_TYPE_UNSIGNED_INT, 2, /*int count.  allocates memory but in the kernel*/},
    {{0,0},"NtUserCallOneParam.GETSENDMSGRECVR", UNKNOWN, DRSYS_TYPE_UNSIGNED_INT, 2, },
    {{0,0},"NtUserCallOneParam.WINDOWFROMDC", OK, DRSYS_TYPE_UNSIGNED_INT, 2, /*HDC*/},
    {{0,0},"NtUserCallOneParam.ALLOWSETFOREGND", UNKNOWN, DRSYS_TYPE_UNSIGNED_INT, 2, },
    {{0,0},"NtUserCallOneParam.CREATEEMPTYCUROBJECT", OK, DRSYS_TYPE_UNSIGNED_INT, 2, /*unused*/},
    {{0,0},"NtUserCallOneParam.CREATESYSTEMTHREADS", OK, DRSYS_TYPE_UNSIGNED_INT, 2, /*UINT*/},
    {{0,0},"NtUserCallOneParam.CSDDEUNINITIALIZE", UNKNOWN, DRSYS_TYPE_UNSIGNED_INT, 2, },
    {{0,0},"NtUserCallOneParam.DIRECTEDYIELD", UNKNOWN, DRSYS_TYPE_UNSIGNED_INT, 2, },
    {{0,0},"NtUserCallOneParam.ENUMCLIPBOARDFORMATS", OK, DRSYS_TYPE_UNSIGNED_INT, 2, /*UINT*/},
    {{0,0},"NtUserCallOneParam.GETCURSORPOS", OK, DRSYS_TYPE_UNSIGNED_INT, 2,
     {
         {0, sizeof(POINTL), W},
     }
    },
    {{0,0},"NtUserCallOneParam.GETINPUTEVENT", OK, DRSYS_TYPE_UNSIGNED_INT, 2, /*DWORD*/},
    {{0,0},"NtUserCallOneParam.GETKEYBOARDLAYOUT", OK, DRSYS_TYPE_UNSIGNED_INT, 2, /*DWORD*/},
    {{0,0},"NtUserCallOneParam.GETKEYBOARDTYPE", OK, DRSYS_TYPE_UNSIGNED_INT, 2, /*DWORD*/},
    {{0,0},"NtUserCallOneParam.GETPROCDEFLAYOUT", OK, DRSYS_TYPE_UNSIGNED_INT, 2,
     {
         {0, sizeof(DWORD), W},
     }
    },
    {{0,0},"NtUserCallOneParam.GETQUEUESTATUS", OK, DRSYS_TYPE_UNSIGNED_INT, 2, /*DWORD*/},
    {{0,0},"NtUserCallOneParam.GETWINSTAINFO", UNKNOWN, DRSYS_TYPE_UNSIGNED_INT, 2, },
    {{0,0},"NtUserCallOneParam.HANDLESYSTHRDCREATFAIL", UNKNOWN, DRSYS_TYPE_UNSIGNED_INT, 2, },
    {{0,0},"NtUserCallOneParam.LOCKFOREGNDWINDOW", UNKNOWN, DRSYS_TYPE_UNSIGNED_INT, 2, },
    {{0,0},"NtUserCallOneParam.LOADFONTS", UNKNOWN, DRSYS_TYPE_UNSIGNED_INT, 2, },
    {{0,0},"NtUserCallOneParam.MAPDEKTOPOBJECT", UNKNOWN, DRSYS_TYPE_UNSIGNED_INT, 2, },
    {{0,0},"NtUserCallOneParam.MESSAGEBEEP", OK, DRSYS_TYPE_UNSIGNED_INT, 2, /*LPARAM*/},
    {{0,0},"NtUserCallOneParam.PLAYEVENTSOUND", UNKNOWN, DRSYS_TYPE_UNSIGNED_INT, 2, },
    {{0,0},"NtUserCallOneParam.POSTQUITMESSAGE", OK, DRSYS_TYPE_UNSIGNED_INT, 2, /*int exit code*/},
    {{0,0},"NtUserCallOneParam.PREPAREFORLOGOFF", UNKNOWN, DRSYS_TYPE_UNSIGNED_INT, 2, },
    {{0,0},"NtUserCallOneParam.REALIZEPALETTE", OK, DRSYS_TYPE_UNSIGNED_INT, 2, /*HDC*/},
    {{0,0},"NtUserCallOneParam.REGISTERLPK", UNKNOWN, DRSYS_TYPE_UNSIGNED_INT, 2, },
    {{0,0},"NtUserCallOneParam.REGISTERSYSTEMTHREAD", UNKNOWN, DRSYS_TYPE_UNSIGNED_INT, 2, },
    {{0,0},"NtUserCallOneParam.REMOTERECONNECT", UNKNOWN, DRSYS_TYPE_UNSIGNED_INT, 2, },
    {{0,0},"NtUserCallOneParam.REMOTETHINWIRESTATUS", UNKNOWN, DRSYS_TYPE_UNSIGNED_INT, 2, },
    {{0,0},"NtUserCallOneParam.RELEASEDC", OK, DRSYS_TYPE_UNSIGNED_INT, 2, /*HDC*/
     {
         {0,}
     }
    },
    {{0,0},"NtUserCallOneParam.REMOTENOTIFY", UNKNOWN, DRSYS_TYPE_UNSIGNED_INT, 2, },
    {{0,0},"NtUserCallOneParam.REPLYMESSAGE", OK, DRSYS_TYPE_UNSIGNED_INT, 2, /*LRESULT*/},
    {{0,0},"NtUserCallOneParam.SETCARETBLINKTIME", OK, DRSYS_TYPE_UNSIGNED_INT, 2, /*UINT*/},
    {{0,0},"NtUserCallOneParam.SETDBLCLICKTIME", UNKNOWN, DRSYS_TYPE_UNSIGNED_INT, 2, },
    {{0,0},"NtUserCallOneParam.SETIMESHOWSTATUS", UNKNOWN, DRSYS_TYPE_UNSIGNED_INT, 2, },
    {{0,0},"NtUserCallOneParam.SETMESSAGEEXTRAINFO", OK, DRSYS_TYPE_UNSIGNED_INT, 2, /*LPARAM*/},
    {{0,0},"NtUserCallOneParam.SETPROCDEFLAYOUT", OK, DRSYS_TYPE_UNSIGNED_INT, 2, /*DWORD for PROCESSINFO.dwLayout*/},
    {{0,0},"NtUserCallOneParam.SETWATERMARKSTRINGS", UNKNOWN, DRSYS_TYPE_UNSIGNED_INT, 2, },
    {{0,0},"NtUserCallOneParam.SHOWCURSOR", OK, DRSYS_TYPE_UNSIGNED_INT, 2, /*BOOL*/},
    {{0,0},"NtUserCallOneParam.SHOWSTARTGLASS", UNKNOWN, DRSYS_TYPE_UNSIGNED_INT, 2, },
    {{0,0},"NtUserCallOneParam.SWAPMOUSEBUTTON", OK, DRSYS_TYPE_UNSIGNED_INT, 2, /*BOOL*/},

    {{0,0},"NtUserCallOneParam.UNKNOWN", UNKNOWN, DRSYS_TYPE_UNSIGNED_INT, 2, },
    {{0,0},"NtUserCallOneParam.UNKNOWN", UNKNOWN, DRSYS_TYPE_UNSIGNED_INT, 2, },

    {{0,0},"NtUserCallHwnd.DEREGISTERSHELLHOOKWINDOW", OK, SYSARG_TYPE_UINT32, 2, /*HWND*/},
    {{0,0},"NtUserCallHwnd.DWP_GETENABLEDPOPUP", UNKNOWN, SYSARG_TYPE_UINT32, 2, },
    {{0,0},"NtUserCallHwnd.GETWNDCONTEXTHLPID", OK, SYSARG_TYPE_UINT32, 2, /*HWND*/},
    {{0,0},"NtUserCallHwnd.REGISTERSHELLHOOKWINDOW", OK, SYSARG_TYPE_UINT32, 2, /*HWND*/},
    {{0,0},"NtUserCallHwnd.UNKNOWN", UNKNOWN, SYSARG_TYPE_UINT32, 2, },

    {{0,0},"NtUserCallHwndOpt.SETPROGMANWINDOW", OK, SYSARG_TYPE_UINT32, 2, /*HWND*/},
    {{0,0},"NtUserCallHwndOpt.SETTASKMANWINDOW", OK, SYSARG_TYPE_UINT32, 2, /*HWND*/},

    {{0,0},"NtUserCallHwndParam.GETCLASSICOCUR", UNKNOWN, SYSARG_TYPE_UINT32, 3, },
    {{0,0},"NtUserCallHwndParam.CLEARWINDOWSTATE", UNKNOWN, SYSARG_TYPE_UINT32, 3, },
    {{0,0},"NtUserCallHwndParam.KILLSYSTEMTIMER", OK, SYSARG_TYPE_UINT32, 3, /*HWND, timer id*/},
    {{0,0},"NtUserCallHwndParam.SETDIALOGPOINTER", OK, SYSARG_TYPE_UINT32, 3, /*HWND, BOOL*/ },
    {{0,0},"NtUserCallHwndParam.SETVISIBLE", UNKNOWN, SYSARG_TYPE_UINT32, 3, },
    {{0,0},"NtUserCallHwndParam.SETWNDCONTEXTHLPID", OK, SYSARG_TYPE_UINT32, 3, /*HWND, HANDLE*/},
    {{0,0},"NtUserCallHwndParam.SETWINDOWSTATE", UNKNOWN, SYSARG_TYPE_UINT32, 3, },

    /* XXX: confirm the rest: assuming for now all just take HWND */
    {{0,0},"NtUserCallHwndLock.WINDOWHASSHADOW", OK, SYSARG_TYPE_UINT32, 2, /*HWND*/},
    {{0,0},"NtUserCallHwndLock.ARRANGEICONICWINDOWS", OK, SYSARG_TYPE_UINT32, 2, /*HWND*/},
    {{0,0},"NtUserCallHwndLock.DRAWMENUBAR", OK, SYSARG_TYPE_UINT32, 2, /*HWND*/},
    {{0,0},"NtUserCallHwndLock.CHECKIMESHOWSTATUSINTHRD", OK, SYSARG_TYPE_UINT32, 2, /*HWND*/},
    {{0,0},"NtUserCallHwndLock.GETSYSMENUHANDLE", OK, SYSARG_TYPE_UINT32, 2, /*HWND*/},
    {{0,0},"NtUserCallHwndLock.REDRAWFRAME", OK, SYSARG_TYPE_UINT32, 2, /*HWND*/},
    {{0,0},"NtUserCallHwndLock.REDRAWFRAMEANDHOOK", OK, SYSARG_TYPE_UINT32, 2, /*HWND*/},
    {{0,0},"NtUserCallHwndLock.SETDLGSYSMENU", OK, SYSARG_TYPE_UINT32, 2, /*HWND*/},
    {{0,0},"NtUserCallHwndLock.SETFOREGROUNDWINDOW", OK, SYSARG_TYPE_UINT32, 2, /*HWND*/},
    {{0,0},"NtUserCallHwndLock.SETSYSMENU", OK, SYSARG_TYPE_UINT32, 2, /*HWND*/},
    {{0,0},"NtUserCallHwndLock.UPDATECKIENTRECT", OK, SYSARG_TYPE_UINT32, 2, /*HWND*/},
    {{0,0},"NtUserCallHwndLock.UPDATEWINDOW", OK, SYSARG_TYPE_UINT32, 2, /*HWND*/},
    {{0,0},"NtUserCallHwndLock.UNKNOWN", UNKNOWN, SYSARG_TYPE_UINT32, 2, },

    {{0,0},"NtUserCallTwoParam.ENABLEWINDOW", OK, DRSYS_TYPE_UNSIGNED_INT, 3, /*HWND, BOOL*/},
    {{0,0},"NtUserCallTwoParam.REDRAWTITLE", UNKNOWN, DRSYS_TYPE_UNSIGNED_INT, 3, },
    {{0,0},"NtUserCallTwoParam.SHOWOWNEDPOPUPS", OK, DRSYS_TYPE_UNSIGNED_INT, 3, /*HWND, BOOL*/},
    {{0,0},"NtUserCallTwoParam.SWITCHTOTHISWINDOW", UNKNOWN, DRSYS_TYPE_UNSIGNED_INT, 3, },
    {{0,0},"NtUserCallTwoParam.UPDATEWINDOWS", UNKNOWN, DRSYS_TYPE_UNSIGNED_INT, 3, },

    {{0,0},"NtUserCallHwndParamLock.VALIDATERGN", OK, SYSARG_TYPE_UINT32, 3, /*HWND, HRGN*/},

    {{0,0},"NtUserCallTwoParam.CHANGEWNDMSGFILTER", UNKNOWN, DRSYS_TYPE_UNSIGNED_INT, 3, },
    {{0,0},"NtUserCallTwoParam.GETCURSORPOS", OK, DRSYS_TYPE_UNSIGNED_INT, 3,
     {
         {0, sizeof(POINTL), W},}/*other param is hardcoded as 0x1*/},
    /* XXX i#996: not 100% sure there's not more nuanced behavior to
     * this syscall.  First param looks like flags and 3rd looks like
     * size of buffer.
     */
    {{0,0},"NtUserCallTwoParam.GETHDEVNAME", OK, DRSYS_TYPE_UNSIGNED_INT, 3,
     {
         {1, -2, W},
     }
    },
    {{0,0},"NtUserCallTwoParam.INITANSIOEM", OK, DRSYS_TYPE_UNSIGNED_INT, 3,
     {
         {1,0, W|CT, SYSARG_TYPE_CSTRING_WIDE},
     }
    },
    {{0,0},"NtUserCallTwoParam.NLSSENDIMENOTIFY", UNKNOWN, DRSYS_TYPE_UNSIGNED_INT, 3, },
    {{0,0},"NtUserCallTwoParam.REGISTERGHSTWND", UNKNOWN, DRSYS_TYPE_UNSIGNED_INT, 3, },
    {{0,0},"NtUserCallTwoParam.REGISTERLOGONPROCESS", OK, DRSYS_TYPE_UNSIGNED_INT, 3, /*HANDLE, BOOL*/},
    {{0,0},"NtUserCallTwoParam.REGISTERSYSTEMTHREAD", UNKNOWN, DRSYS_TYPE_UNSIGNED_INT, 3, },
    {{0,0},"NtUserCallTwoParam.REGISTERSBLFROSTWND", UNKNOWN, DRSYS_TYPE_UNSIGNED_INT, 3, },
    {{0,0},"NtUserCallTwoParam.REGISTERUSERHUNGAPPHANDLERS", UNKNOWN, DRSYS_TYPE_UNSIGNED_INT, 3, },
    {{0,0},"NtUserCallTwoParam.SHADOWCLEANUP", UNKNOWN, DRSYS_TYPE_UNSIGNED_INT, 3, },
    {{0,0},"NtUserCallTwoParam.REMOTESHADOWSTART", UNKNOWN, DRSYS_TYPE_UNSIGNED_INT, 3, },
    {{0,0},"NtUserCallTwoParam.SETCARETPOS", OK, DRSYS_TYPE_UNSIGNED_INT, 3, /*int, int*/},
    {{0,0},"NtUserCallTwoParam.SETCURSORPOS", OK, DRSYS_TYPE_UNSIGNED_INT, 3, /*int, int*/},
    {{0,0},"NtUserCallTwoParam.SETPHYSCURSORPOS", UNKNOWN, DRSYS_TYPE_UNSIGNED_INT, 3, },
    {{0,0},"NtUserCallTwoParam.UNHOOKWINDOWSHOOK", OK, DRSYS_TYPE_UNSIGNED_INT, 3, /*int, HOOKPROC*/},
    {{0,0},"NtUserCallTwoParam.WOWCLEANUP", UNKNOWN, DRSYS_TYPE_UNSIGNED_INT, 3, },
};
#define NUM_USERCALL_SYSCALLS \
    (sizeof(syscall_usercall_info)/sizeof(syscall_usercall_info[0]))

size_t
num_usercall_syscalls(void)
{
    return NUM_USERCALL_SYSCALLS;
}

/***************************************************************************
 * TOP-LEVEL
 */

extern void
name2num_entry_add(const char *name, drsys_sysnum_t num, bool dup_Zw);

static void
wingdi_secondary_syscall_setup(void *drcontext)
{
    uint i;
    for (i = 0; i < NUM_USERCALL_SYSCALLS; i++) {
        syscall_info_t *syslist = &syscall_usercall_info[i];
        uint secondary = (uint)
            hashtable_lookup(&usercall_table, (void *)syslist->name);
        if (secondary != 0) {
            const char *skip_primary;
            IF_DEBUG(bool ok =)
                os_syscall_get_num(usercall_primary[i], &syslist->num);
            ASSERT(ok, "failed to get syscall number");
            ASSERT(syslist->num.secondary == 0, "primary should have no secondary");
            syslist->num.secondary = secondary - 1/*+1 in table*/;

            hashtable_add(&systable, (void *) &syslist->num, (void *) syslist);

            /* Add with and without the primary prefix */
            name2num_entry_add(syslist->name, syslist->num, false/*no dup*/);
            skip_primary = strstr(syslist->name, "Param.");
            if (skip_primary != NULL) {
                name2num_entry_add(skip_primary + strlen("Param."),
                                   syslist->num, false/*no dup*/);
            }

            if (syslist->num_out != NULL)
                *syslist->num_out = syslist->num;
            LOG(SYSCALL_VERBOSE, "usercall %-35s = %3d (0x%04x)\n",
                syslist->name, syslist->num, syslist->num);
        } else {
            LOG(SYSCALL_VERBOSE, "WARNING: could not find usercall %s\n", syslist->name);
        }
    }
}

drmf_status_t
drsyscall_wingdi_init(void *drcontext, app_pc ntdll_base, dr_os_version_info_t *ver)
{
    uint i;
    const int *usercalls;
    LOG(1, "Windows version is %d.%d.%d\n", ver->version, ver->service_pack_major,
        ver->service_pack_minor);
    switch (ver->version) {
    case DR_WINDOWS_VERSION_8:     usercalls = win8_usercall_nums;     break;
    case DR_WINDOWS_VERSION_7:     usercalls = win7_usercall_nums;     break;
    case DR_WINDOWS_VERSION_VISTA: {
        if (ver->service_pack_major >= 2)
            usercalls = winvistaSP2_usercall_nums;
        else
            usercalls = winvistaSP01_usercall_nums;
        break;
    }
    case DR_WINDOWS_VERSION_2003:  usercalls = win2003_usercall_nums;  break;
    case DR_WINDOWS_VERSION_XP:    usercalls = winxp_usercall_nums;    break;
    case DR_WINDOWS_VERSION_2000:  usercalls = win2k_usercall_nums;    break;
    case DR_WINDOWS_VERSION_NT:
    default:
        return DRMF_ERROR_INCOMPATIBLE_VERSION;
    }

    /* Set up hashtable to translate usercall names to numbers */
    hashtable_init(&usercall_table, USERCALL_TABLE_HASH_BITS,
                   HASH_STRING, false/*!strdup*/);
    for (i = 0; i < NUM_USERCALL_NAMES; i++) {
        if (usercalls[i] != NONE) {
            IF_DEBUG(bool ok =)
                hashtable_add(&usercall_table, (void *)usercall_names[i],
                              (void *)(usercalls[i] + 1/*avoid 0*/));
            ASSERT(ok, "no dup entries in usercall_table");
        }
    }
    ASSERT(NUM_USERCALL_NAMES == NUM_USERCALL_SYSCALLS, "mismatch in usercall tables");

    wingdi_secondary_syscall_setup(drcontext);

    return DRMF_SUCCESS;
}

void
drsyscall_wingdi_exit(void)
{
    hashtable_delete(&usercall_table);
}

void
drsyscall_wingdi_thread_init(void *drcontext)
{
}

void
drsyscall_wingdi_thread_exit(void *drcontext)
{
}

/***************************************************************************/
/* System calls with wrappers in gdi32.dll.
 * Not all wrappers are exported: xref i#388.
 *
 * When adding new entries, use the NtGdi prefix.
 * When we try to find the wrapper via symbol lookup we try with
 * and without the prefix.
 *
 * Initially obtained via mksystable.pl on VS2008 ntgdi.h.
 * That version was checked in separately to track manual changes.
 *
 * FIXME i#485: issues with table that are not yet resolved:
 *
 * + OUT params with no size where size comes from prior syscall
 *   return value (see FIXMEs in table below): so have to watch pairs
 *   of calls (but what if app is able to compute max size some other
 *   way, maybe caching older call?), unless willing to only check for
 *   unaddr in post-syscall and thus after potential write to
 *   unaddressable memory by kernel (which is what we do today).
 *   Update: there are some of these in NtUser table as well.
 *
 * + missing ", return" annotations: NtGdiExtGetObjectW was missing one,
 *   and I'm afraid other ones that return int or UINT may also.
 *
 * + __out PVOID: for NtGdiGetUFIPathname and NtGdiDxgGenericThunk,
 *   is the PVOID that's written supposed to have a bcount (or ecount)
 *   annotation?  for now treated as PVOID*.
 *
 * + bcount in, ecount out for NtGdiSfmGetNotificationTokens (which is
 *   missing annotations)?  but what is size of token?
 *
 * + the REALIZATION_INFO struct is much larger on win7
 */

static drsys_sysnum_t sysnum_GdiCreatePaletteInternal = {-1,0};
static drsys_sysnum_t sysnum_GdiCheckBitmapBits = {-1,0};
static drsys_sysnum_t sysnum_GdiHfontCreate = {-1,0};
static drsys_sysnum_t sysnum_GdiDoPalette = {-1,0};
static drsys_sysnum_t sysnum_GdiExtTextOutW = {-1,0};
static drsys_sysnum_t sysnum_GdiOpenDCW = {-1,0};
static drsys_sysnum_t sysnum_GdiDescribePixelFormat = {-1,0};
static drsys_sysnum_t sysnum_GdiGetRasterizerCaps = {-1,0};
static drsys_sysnum_t sysnum_GdiPolyPolyDraw = {-1,0};

syscall_info_t syscall_gdi32_info[] = {
    {{0,0},"NtGdiInit", OK, SYSARG_TYPE_BOOL32, 0, },
    {{0,0},"NtGdiSetDIBitsToDeviceInternal", OK, SYSARG_TYPE_SINT32, 16,
     {
         {9, -12, R,},
         {10, sizeof(BITMAPINFO), R|CT, SYSARG_TYPE_BITMAPINFO},
     }
    },
    {{0,0},"NtGdiGetFontResourceInfoInternalW", OK, SYSARG_TYPE_BOOL32, 7,
     {
         {0, -1, R|SYSARG_SIZE_IN_ELEMENTS, sizeof(wchar_t)},
         {4, sizeof(DWORD), W,},
         {5, -3, W,},
     }
    },
    {{0,0},"NtGdiGetGlyphIndicesW", OK, SYSARG_TYPE_UINT32, 5,
     {
         {1, -2, R|SYSARG_SIZE_IN_ELEMENTS, sizeof(wchar_t)},
         {3, -2, W|SYSARG_SIZE_IN_ELEMENTS, sizeof(WORD)},
     }
    },
    {{0,0},"NtGdiGetGlyphIndicesWInternal", OK, SYSARG_TYPE_UINT32, 6,
     {
         {1, -2, R|SYSARG_SIZE_IN_ELEMENTS, sizeof(wchar_t)},
         {3, sizeof(WORD), W,},
     }
    },
    {{0,0},"NtGdiCreatePaletteInternal", OK, DRSYS_TYPE_HANDLE, 2,
     {
         {0,},
     }/*too complex: special-cased*/, &sysnum_GdiCreatePaletteInternal
    },
    {{0,0},"NtGdiArcInternal", OK, SYSARG_TYPE_BOOL32, 10, },
    {{0,0},"NtGdiGetOutlineTextMetricsInternalW", OK, SYSARG_TYPE_UINT32, 4,
     {
         {2, -1, W,},
         {3, sizeof(TMDIFF), W,},
     }
    },
    {{0,0},"NtGdiGetAndSetDCDword", OK, SYSARG_TYPE_BOOL32, 4,
     {
         {3, sizeof(DWORD), W,},
     }
    },
    {{0,0},"NtGdiGetDCObject", OK, DRSYS_TYPE_HANDLE, 2, },
    {{0,0},"NtGdiGetDCforBitmap", OK, DRSYS_TYPE_HANDLE, 1,
     {
         {0,}
     }
    },
    {{0,0},"NtGdiGetMonitorID", OK, SYSARG_TYPE_BOOL32, 3,
     {
         {2, -1, W,},
     }
    },
    {{0,0},"NtGdiGetLinkedUFIs", OK, SYSARG_TYPE_SINT32, 3,
     {
         {1, -2, W|SYSARG_SIZE_IN_ELEMENTS, sizeof(UNIVERSAL_FONT_ID)},
     }
    },
    {{0,0},"NtGdiSetLinkedUFIs", OK, SYSARG_TYPE_BOOL32, 3,
     {
         {1, -2, R|SYSARG_SIZE_IN_ELEMENTS, sizeof(UNIVERSAL_FONT_ID)},
     }
    },
    {{0,0},"NtGdiGetUFI", OK, SYSARG_TYPE_BOOL32, 6,
     {
         {1, sizeof(UNIVERSAL_FONT_ID), W,},
         {2, sizeof(DESIGNVECTOR), W,},
         {3, sizeof(ULONG), W,},
         {4, sizeof(ULONG), W,},
         {5, sizeof(FLONG), W,},
     }
    },
    {{0,0},"NtGdiForceUFIMapping", OK, SYSARG_TYPE_BOOL32, 2,
     {
         {1, sizeof(UNIVERSAL_FONT_ID), R,},
     }
    },
    {{0,0},"NtGdiGetUFIPathname", OK, SYSARG_TYPE_BOOL32, 10,
     {
         {0, sizeof(UNIVERSAL_FONT_ID), R,},
         {1, sizeof(ULONG), W,},
         {2, MAX_PATH * 3, W|SYSARG_SIZE_IN_ELEMENTS, sizeof(wchar_t)},
         {2, -1, WI|SYSARG_SIZE_IN_ELEMENTS, sizeof(wchar_t)},
         {3, sizeof(ULONG), W,},
         {5, sizeof(BOOL), W,},
         {6, sizeof(ULONG), W,},
         {7, sizeof(PVOID), W,},
         {8, sizeof(BOOL), W,},
         {9, sizeof(ULONG), W,},
     }
    },
    {{0,0},"NtGdiAddRemoteFontToDC", OK, SYSARG_TYPE_BOOL32, 4,
     {
         {3, sizeof(UNIVERSAL_FONT_ID), R,},
     }
    },
    {{0,0},"NtGdiAddFontMemResourceEx", OK, DRSYS_TYPE_HANDLE, 5,
     {
         {2, -3, R,},
         {4, sizeof(DWORD), W,},
     }
    },
    {{0,0},"NtGdiRemoveFontMemResourceEx", OK, SYSARG_TYPE_BOOL32, 1, },
    {{0,0},"NtGdiUnmapMemFont", OK, SYSARG_TYPE_BOOL32, 1, },
    {{0,0},"NtGdiRemoveMergeFont", OK, SYSARG_TYPE_BOOL32, 2,
     {
         {1, sizeof(UNIVERSAL_FONT_ID), R,},
     }
    },
    {{0,0},"NtGdiAnyLinkedFonts", OK, SYSARG_TYPE_BOOL32, 0, },
    {{0,0},"NtGdiGetEmbUFI", OK, SYSARG_TYPE_BOOL32, 7,
     {
         {1, sizeof(UNIVERSAL_FONT_ID), W,},
         {2, sizeof(DESIGNVECTOR), W,},
         {3, sizeof(ULONG), W,},
         {4, sizeof(ULONG), W,},
         {5, sizeof(FLONG), W,},
         {6, sizeof(KERNEL_PVOID), W,},
     }
    },
    {{0,0},"NtGdiGetEmbedFonts", OK, SYSARG_TYPE_UINT32, 0, },
    {{0,0},"NtGdiChangeGhostFont", OK, SYSARG_TYPE_BOOL32, 2,
     {
         {0, sizeof(KERNEL_PVOID), R,},
     }
    },
    {{0,0},"NtGdiAddEmbFontToDC", OK, SYSARG_TYPE_BOOL32, 2,
     {
         {1, sizeof(PVOID), R,},
     }
    },
    {{0,0},"NtGdiFontIsLinked", OK, SYSARG_TYPE_BOOL32, 1, },
    /* Return value is really either BOOL or HRGN: dynamic iterator gets it right,
     * and we document the limitations of the static iterators.
     */
    {{0,0},"NtGdiPolyPolyDraw", OK|SYSINFO_RET_ZERO_FAIL|SYSINFO_RET_TYPE_VARIES,
     DRSYS_TYPE_UNSIGNED_INT, 5,
     {
         /* Params 0 and 1 are special-cased as they vary */
         {2, -3, R|SYSARG_SIZE_IN_ELEMENTS, sizeof(ULONG)},
         {3, sizeof(ULONG), SYSARG_INLINED, DRSYS_TYPE_UNSIGNED_INT},
         {4, sizeof(INT),   SYSARG_INLINED, DRSYS_TYPE_SIGNED_INT},
     }, &sysnum_GdiPolyPolyDraw
    },
    {{0,0},"NtGdiDoPalette", OK, SYSARG_TYPE_SINT32, 6,
     {
         {0,},
     },/*special-cased: R or W depending*/ &sysnum_GdiDoPalette
    },
    {{0,0},"NtGdiComputeXformCoefficients", OK, SYSARG_TYPE_BOOL32, 1, },
    {{0,0},"NtGdiGetWidthTable", OK|SYSINFO_RET_MINUS1_FAIL, SYSARG_TYPE_SINT32, 7,
     {
         {2, -3, R|SYSARG_SIZE_IN_ELEMENTS, sizeof(WCHAR)},
         {4, -3, W|SYSARG_SIZE_IN_ELEMENTS, sizeof(USHORT)},
         {5, sizeof(WIDTHDATA), W,},
         {6, sizeof(FLONG), W,},
     }
    },
    {{0,0},"NtGdiDescribePixelFormat", OK, SYSARG_TYPE_SINT32, 4,
     {
         {3, -2, W,},
     }, &sysnum_GdiDescribePixelFormat
    },
    {{0,0},"NtGdiSetPixelFormat", OK, SYSARG_TYPE_BOOL32, 2, },
    {{0,0},"NtGdiSwapBuffers", OK, SYSARG_TYPE_BOOL32, 1, },
    {{0,0},"NtGdiDxgGenericThunk", OK, SYSARG_TYPE_UINT32, 6,
     {
         {2, sizeof(SIZE_T), R|W,},
         {3, sizeof(PVOID), R|W,},
         {4, sizeof(SIZE_T), R|W,},
         {5, sizeof(PVOID), R|W,},
     }
    },
    {{0,0},"NtGdiDdAddAttachedSurface", OK, SYSARG_TYPE_UINT32, 3,
     {
         {2, sizeof(DD_ADDATTACHEDSURFACEDATA), R|W,},
     }
    },
    {{0,0},"NtGdiDdAttachSurface", OK, SYSARG_TYPE_BOOL32, 2, },
    {{0,0},"NtGdiDdBlt", OK, SYSARG_TYPE_UINT32, 3,
     {
         {2, sizeof(DD_BLTDATA), R|W,},
     }
    },
    {{0,0},"NtGdiDdCanCreateSurface", OK, SYSARG_TYPE_UINT32, 2,
     {
         {1, sizeof(DD_CANCREATESURFACEDATA), R|W,},
     }
    },
    {{0,0},"NtGdiDdColorControl", OK, SYSARG_TYPE_UINT32, 2,
     {
         {1, sizeof(DD_COLORCONTROLDATA), R|W,},
     }
    },
    {{0,0},"NtGdiDdCreateDirectDrawObject", OK, DRSYS_TYPE_HANDLE, 1, },
    {{0,0},"NtGdiDdCreateSurface", OK, SYSARG_TYPE_UINT32, 8,
     {
         {1, sizeof(HANDLE), R|HT, DRSYS_TYPE_HANDLE},
         {2, sizeof(DDSURFACEDESC), R|W,},
         {3, sizeof(DD_SURFACE_GLOBAL), R|W,},
         {4, sizeof(DD_SURFACE_LOCAL), R|W,},
         {5, sizeof(DD_SURFACE_MORE), R|W,},
         {6, sizeof(DD_CREATESURFACEDATA), R|W,},
         {7, sizeof(HANDLE), W|HT, DRSYS_TYPE_HANDLE},
     }
    },
    {{0,0},"NtGdiDdChangeSurfacePointer", OK, SYSARG_TYPE_UINT32, 2, },
    {{0,0},"NtGdiDdCreateSurfaceObject", OK, DRSYS_TYPE_HANDLE, 6,
     {
         {2, sizeof(DD_SURFACE_LOCAL), R,},
         {3, sizeof(DD_SURFACE_MORE), R,},
         {4, sizeof(DD_SURFACE_GLOBAL), R,},
     }
    },
    {{0,0},"NtGdiDdDeleteSurfaceObject", OK, SYSARG_TYPE_BOOL32, 1, },
    {{0,0},"NtGdiDdDeleteDirectDrawObject", OK, SYSARG_TYPE_BOOL32, 1, },
    {{0,0},"NtGdiDdDestroySurface", OK, SYSARG_TYPE_UINT32, 2, },
    {{0,0},"NtGdiDdFlip", OK, SYSARG_TYPE_UINT32, 5,
     {
         {4, sizeof(DD_FLIPDATA), R|W,},
     }
    },
    {{0,0},"NtGdiDdGetAvailDriverMemory", OK, SYSARG_TYPE_UINT32, 2,
     {
         {1, sizeof(DD_GETAVAILDRIVERMEMORYDATA), R|W,},
     }
    },
    {{0,0},"NtGdiDdGetBltStatus", OK, SYSARG_TYPE_UINT32, 2,
     {
         {1, sizeof(DD_GETBLTSTATUSDATA), R|W,},
     }
    },
    {{0,0},"NtGdiDdGetDC", OK, DRSYS_TYPE_HANDLE, 2,
     {
         {1, sizeof(PALETTEENTRY), R,},
         },
         },
    {{0,0},"NtGdiDdGetDriverInfo", OK, SYSARG_TYPE_UINT32, 2,
     {
         {1, sizeof(DD_GETDRIVERINFODATA), R|W,},
     }
    },
    {{0,0},"NtGdiDdGetFlipStatus", OK, SYSARG_TYPE_UINT32, 2,
     {
         {1, sizeof(DD_GETFLIPSTATUSDATA), R|W,},
     }
    },
    {{0,0},"NtGdiDdGetScanLine", OK, SYSARG_TYPE_UINT32, 2,
     {
         {1, sizeof(DD_GETSCANLINEDATA), R|W,},
     }
    },
    {{0,0},"NtGdiDdSetExclusiveMode", OK, SYSARG_TYPE_UINT32, 2,
     {
         {1, sizeof(DD_SETEXCLUSIVEMODEDATA), R|W,},
     }
    },
    {{0,0},"NtGdiDdFlipToGDISurface", OK, SYSARG_TYPE_UINT32, 2,
     {
         {1, sizeof(DD_FLIPTOGDISURFACEDATA), R|W,},
     }
    },
    {{0,0},"NtGdiDdLock", OK, SYSARG_TYPE_UINT32, 3,
     {
         {1, sizeof(DD_LOCKDATA), R|W,},
     }
    },
    {{0,0},"NtGdiDdQueryDirectDrawObject", OK, SYSARG_TYPE_BOOL32, 11,
     {
         {1, sizeof(DD_HALINFO), W,},
         {2,3, W|SYSARG_SIZE_IN_ELEMENTS, sizeof(DWORD)},
         {3, sizeof(D3DNTHAL_CALLBACKS), W,},
         {4, sizeof(D3DNTHAL_GLOBALDRIVERDATA), W,},
         {5, sizeof(DD_D3DBUFCALLBACKS), W,},
         {6, sizeof(DDSURFACEDESC), W,},
         {7, sizeof(DWORD), W,},
         {8, sizeof(VIDEOMEMORY), W,},
         {9, sizeof(DWORD), W,},
         {10, sizeof(DWORD), W,},
     }
    },
    {{0,0},"NtGdiDdReenableDirectDrawObject", OK, SYSARG_TYPE_BOOL32, 2,
     {
         {1, sizeof(BOOL), R|W,},
     }
    },
    {{0,0},"NtGdiDdReleaseDC", OK, SYSARG_TYPE_BOOL32, 1,
     {
         {0, sizeof(HANDLE), SYSARG_INLINED, DRSYS_TYPE_HANDLE},
     }
    },
    {{0,0},"NtGdiDdResetVisrgn", OK, SYSARG_TYPE_BOOL32, 2, },
    {{0,0},"NtGdiDdSetColorKey", OK, SYSARG_TYPE_UINT32, 2,
     {
         {1, sizeof(DD_SETCOLORKEYDATA), R|W,},
     }
    },
    {{0,0},"NtGdiDdSetOverlayPosition", OK, SYSARG_TYPE_UINT32, 3,
     {
         {2, sizeof(DD_SETOVERLAYPOSITIONDATA), R|W,},
     }
    },
    {{0,0},"NtGdiDdUnattachSurface", OK, DRSYS_TYPE_VOID, 2, },
    {{0,0},"NtGdiDdUnlock", OK, SYSARG_TYPE_UINT32, 2,
     {
         {1, sizeof(DD_UNLOCKDATA), R|W,},
     }
    },
    {{0,0},"NtGdiDdUpdateOverlay", OK, SYSARG_TYPE_UINT32, 3,
     {
         {2, sizeof(DD_UPDATEOVERLAYDATA), R|W,},
     }
    },
    {{0,0},"NtGdiDdWaitForVerticalBlank", OK, SYSARG_TYPE_UINT32, 2,
     {
         {1, sizeof(DD_WAITFORVERTICALBLANKDATA), R|W,},
     }
    },
    {{0,0},"NtGdiDdGetDxHandle", OK, DRSYS_TYPE_HANDLE, 3, },
    {{0,0},"NtGdiDdSetGammaRamp", OK, SYSARG_TYPE_BOOL32, 3, },
    {{0,0},"NtGdiDdLockD3D", OK, SYSARG_TYPE_UINT32, 2,
     {
         {1, sizeof(DD_LOCKDATA), R|W,},
     }
    },
    {{0,0},"NtGdiDdUnlockD3D", OK, SYSARG_TYPE_UINT32, 2,
     {
         {1, sizeof(DD_UNLOCKDATA), R|W,},
     }
    },
    {{0,0},"NtGdiDdCreateD3DBuffer", OK, SYSARG_TYPE_UINT32, 8,
     {
         {1, sizeof(HANDLE), R|W|HT, DRSYS_TYPE_HANDLE},
         {2, sizeof(DDSURFACEDESC), R|W,},
         {3, sizeof(DD_SURFACE_GLOBAL), R|W,},
         {4, sizeof(DD_SURFACE_LOCAL), R|W,},
         {5, sizeof(DD_SURFACE_MORE), R|W,},
         {6, sizeof(DD_CREATESURFACEDATA), R|W,},
         {7, sizeof(HANDLE), R|W|HT, DRSYS_TYPE_HANDLE},
     }
    },
    {{0,0},"NtGdiDdCanCreateD3DBuffer", OK, SYSARG_TYPE_UINT32, 2,
     {
         {1, sizeof(DD_CANCREATESURFACEDATA), R|W,},
     }
    },
    {{0,0},"NtGdiDdDestroyD3DBuffer", OK, SYSARG_TYPE_UINT32, 1, },
    {{0,0},"NtGdiD3dContextCreate", OK, SYSARG_TYPE_UINT32, 4,
     {
         {3, sizeof(D3DNTHAL_CONTEXTCREATEI), R|W,},
     }
    },
    {{0,0},"NtGdiD3dContextDestroy", OK, SYSARG_TYPE_UINT32, 1,
     {
         {0, sizeof(D3DNTHAL_CONTEXTDESTROYDATA), R,},
     }
    },
    {{0,0},"NtGdiD3dContextDestroyAll", OK, SYSARG_TYPE_UINT32, 1,
     {
         {0, sizeof(D3DNTHAL_CONTEXTDESTROYALLDATA), W,},
     }
    },
    {{0,0},"NtGdiD3dValidateTextureStageState", OK, SYSARG_TYPE_UINT32, 1,
     {
         {0, sizeof(D3DNTHAL_VALIDATETEXTURESTAGESTATEDATA), R|W,},
     }
    },
    {{0,0},"NtGdiD3dDrawPrimitives2", OK, SYSARG_TYPE_UINT32, 7,
     {
         {2, sizeof(D3DNTHAL_DRAWPRIMITIVES2DATA), R|W,},
         {3, sizeof(FLATPTR), R|W,},
         {4, sizeof(DWORD), R|W,},
         {5, sizeof(FLATPTR), R|W,},
         {6, sizeof(DWORD), R|W,},
     }
    },
    {{0,0},"NtGdiDdGetDriverState", OK, SYSARG_TYPE_UINT32, 1,
     {
         {0, sizeof(DD_GETDRIVERSTATEDATA), R|W,},
     }
    },
    {{0,0},"NtGdiDdCreateSurfaceEx", OK, SYSARG_TYPE_UINT32, 3, },
    {{0,0},"NtGdiDvpCanCreateVideoPort", OK, SYSARG_TYPE_UINT32, 2,
     {
         {1, sizeof(DD_CANCREATEVPORTDATA), R|W,},
     }
    },
    {{0,0},"NtGdiDvpColorControl", OK, SYSARG_TYPE_UINT32, 2,
     {
         {1, sizeof(DD_VPORTCOLORDATA), R|W,},
     }
    },
    {{0,0},"NtGdiDvpCreateVideoPort", OK, DRSYS_TYPE_HANDLE, 2,
     {
         {1, sizeof(DD_CREATEVPORTDATA), R|W,},
     }
    },
    {{0,0},"NtGdiDvpDestroyVideoPort", OK, SYSARG_TYPE_UINT32, 2,
     {
         {1, sizeof(DD_DESTROYVPORTDATA), R|W,},
     }
    },
    {{0,0},"NtGdiDvpFlipVideoPort", OK, SYSARG_TYPE_UINT32, 4,
     {
         {3, sizeof(DD_FLIPVPORTDATA), R|W,},
     }
    },
    {{0,0},"NtGdiDvpGetVideoPortBandwidth", OK, SYSARG_TYPE_UINT32, 2,
     {
         {1, sizeof(DD_GETVPORTBANDWIDTHDATA), R|W,},
     }
    },
    {{0,0},"NtGdiDvpGetVideoPortField", OK, SYSARG_TYPE_UINT32, 2,
     {
         {1, sizeof(DD_GETVPORTFIELDDATA), R|W,},
     }
    },
    {{0,0},"NtGdiDvpGetVideoPortFlipStatus", OK, SYSARG_TYPE_UINT32, 2,
     {
         {1, sizeof(DD_GETVPORTFLIPSTATUSDATA), R|W,},
     }
    },
    {{0,0},"NtGdiDvpGetVideoPortInputFormats", OK, SYSARG_TYPE_UINT32, 2,
     {
         {1, sizeof(DD_GETVPORTINPUTFORMATDATA), R|W,},
     }
    },
    {{0,0},"NtGdiDvpGetVideoPortLine", OK, SYSARG_TYPE_UINT32, 2,
     {
         {1, sizeof(DD_GETVPORTLINEDATA), R|W,},
     }
    },
    {{0,0},"NtGdiDvpGetVideoPortOutputFormats", OK, SYSARG_TYPE_UINT32, 2,
     {
         {1, sizeof(DD_GETVPORTOUTPUTFORMATDATA), R|W,},
     }
    },
    {{0,0},"NtGdiDvpGetVideoPortConnectInfo", OK, SYSARG_TYPE_UINT32, 2,
     {
         {1, sizeof(DD_GETVPORTCONNECTDATA), R|W,},
     }
    },
    {{0,0},"NtGdiDvpGetVideoSignalStatus", OK, SYSARG_TYPE_UINT32, 2,
     {
         {1, sizeof(DD_GETVPORTSIGNALDATA), R|W,},
     }
    },
    {{0,0},"NtGdiDvpUpdateVideoPort", OK, SYSARG_TYPE_UINT32, 4,
     {
         {1, sizeof(HANDLE), R|HT, DRSYS_TYPE_HANDLE},
         {2, sizeof(HANDLE), R|HT, DRSYS_TYPE_HANDLE},
         {3, sizeof(DD_UPDATEVPORTDATA), R|W,},
     }
    },
    {{0,0},"NtGdiDvpWaitForVideoPortSync", OK, SYSARG_TYPE_UINT32, 2,
     {
         {1, sizeof(DD_WAITFORVPORTSYNCDATA), R|W,},
     }
    },
    {{0,0},"NtGdiDvpAcquireNotification", OK, SYSARG_TYPE_UINT32, 3,
     {
         {1, sizeof(HANDLE), R|W|HT, DRSYS_TYPE_HANDLE},
         {2, sizeof(DDVIDEOPORTNOTIFY), R,},
     }
    },
    {{0,0},"NtGdiDvpReleaseNotification", OK, SYSARG_TYPE_UINT32, 2, },
    {{0,0},"NtGdiDdGetMoCompGuids", OK, SYSARG_TYPE_UINT32, 2,
     {
         {1, sizeof(DD_GETMOCOMPGUIDSDATA), R|W,},
     }
    },
    {{0,0},"NtGdiDdGetMoCompFormats", OK, SYSARG_TYPE_UINT32, 2,
     {
         {1, sizeof(DD_GETMOCOMPFORMATSDATA), R|W,},
     }
    },
    {{0,0},"NtGdiDdGetMoCompBuffInfo", OK, SYSARG_TYPE_UINT32, 2,
     {
         {1, sizeof(DD_GETMOCOMPCOMPBUFFDATA), R|W,},
     }
    },
    {{0,0},"NtGdiDdGetInternalMoCompInfo", OK, SYSARG_TYPE_UINT32, 2,
     {
         {1, sizeof(DD_GETINTERNALMOCOMPDATA), R|W,},
     }
    },
    {{0,0},"NtGdiDdCreateMoComp", OK, DRSYS_TYPE_HANDLE, 2,
     {
         {1, sizeof(DD_CREATEMOCOMPDATA), R|W,},
     }
    },
    {{0,0},"NtGdiDdDestroyMoComp", OK, SYSARG_TYPE_UINT32, 2,
     {
         {1, sizeof(DD_DESTROYMOCOMPDATA), R|W,},
     }
    },
    {{0,0},"NtGdiDdBeginMoCompFrame", OK, SYSARG_TYPE_UINT32, 2,
     {
         {1, sizeof(DD_BEGINMOCOMPFRAMEDATA), R|W,},
     }
    },
    {{0,0},"NtGdiDdEndMoCompFrame", OK, SYSARG_TYPE_UINT32, 2,
     {
         {1, sizeof(DD_ENDMOCOMPFRAMEDATA), R|W,},
     }
    },
    {{0,0},"NtGdiDdRenderMoComp", OK, SYSARG_TYPE_UINT32, 2,
     {
         {1, sizeof(DD_RENDERMOCOMPDATA), R|W,},
     }
    },
    {{0,0},"NtGdiDdQueryMoCompStatus", OK, SYSARG_TYPE_UINT32, 2,
     {
         {1, sizeof(DD_QUERYMOCOMPSTATUSDATA), R|W,},
     }
    },
    {{0,0},"NtGdiDdAlphaBlt", OK, SYSARG_TYPE_UINT32, 3,
     {
         {2, sizeof(DD_BLTDATA), R|W,},
     }
    },
    {{0,0},"NtGdiAlphaBlend", OK, SYSARG_TYPE_BOOL32, 12, },
    {{0,0},"NtGdiGradientFill", OK, SYSARG_TYPE_BOOL32, 6,
     {
         {1, -2, R|SYSARG_SIZE_IN_ELEMENTS, sizeof(TRIVERTEX)},
     }
    },
    {{0,0},"NtGdiSetIcmMode", OK, SYSARG_TYPE_BOOL32, 3, },
    {{0,0},"NtGdiCreateColorSpace", OK, DRSYS_TYPE_HANDLE, 1,
     {
         {0, sizeof(LOGCOLORSPACEEXW), R,},
     }
    },
    {{0,0},"NtGdiDeleteColorSpace", OK, SYSARG_TYPE_BOOL32, 1,
     {
         {0, sizeof(HANDLE), R|HT, DRSYS_TYPE_HANDLE},
     }
    },
    {{0,0},"NtGdiSetColorSpace", OK, SYSARG_TYPE_BOOL32, 2, },
    {{0,0},"NtGdiCreateColorTransform", OK, DRSYS_TYPE_HANDLE, 8,
     {
         {1, sizeof(LOGCOLORSPACEW), R,},
     }
    },
    {{0,0},"NtGdiDeleteColorTransform", OK, SYSARG_TYPE_BOOL32, 2, },
    {{0,0},"NtGdiCheckBitmapBits", OK, SYSARG_TYPE_BOOL32, 8,
     {
         {0,}/*too complex: special-cased*/,
     }, &sysnum_GdiCheckBitmapBits
    },
    {{0,0},"NtGdiColorCorrectPalette", OK, SYSARG_TYPE_UINT32, 6,
     {
         {4, -3, R|W|SYSARG_SIZE_IN_ELEMENTS, sizeof(PALETTEENTRY)},
     }
    },
    {{0,0},"NtGdiGetColorSpaceforBitmap", OK, DRSYS_TYPE_UNSIGNED_INT, 1, },
    {{0,0},"NtGdiGetDeviceGammaRamp", OK, SYSARG_TYPE_BOOL32, 2,
     {
         {1,256*2*3, W,},
     }
    },
    {{0,0},"NtGdiSetDeviceGammaRamp", OK, SYSARG_TYPE_BOOL32, 2, },
    {{0,0},"NtGdiIcmBrushInfo", OK, SYSARG_TYPE_BOOL32, 8,
     {
         {2, sizeof(BITMAPINFO) + ((/*MAX_COLORTABLE*/256 - 1) * sizeof(RGBQUAD)), R|W,},
         {3, -4, R|SYSARG_LENGTH_INOUT,},
         {4, sizeof(ULONG), R|W,},
         {5, sizeof(DWORD), W,},
         {6, sizeof(BOOL), W,},
     }
    },
    {{0,0},"NtGdiFlush", OK, DRSYS_TYPE_VOID, 0, },
    {{0,0},"NtGdiCreateMetafileDC", OK, DRSYS_TYPE_HANDLE, 1,
     {
         {0,}
     }
    },
    {{0,0},"NtGdiMakeInfoDC", OK, SYSARG_TYPE_BOOL32, 2, },
    {{0,0},"NtGdiCreateClientObj", OK, DRSYS_TYPE_HANDLE, 1, },
    {{0,0},"NtGdiDeleteClientObj", OK, SYSARG_TYPE_BOOL32, 1, },
    {{0,0},"NtGdiGetBitmapBits", OK, SYSARG_TYPE_SINT32, 3,
     {
         {2, -1, W,},
     }
    },
    {{0,0},"NtGdiDeleteObjectApp", OK, SYSARG_TYPE_BOOL32, 1,
     {
         {0,}
     }
    },
    {{0,0},"NtGdiGetPath", OK, SYSARG_TYPE_SINT32, 4,
     {
         {1, -3, W|SYSARG_SIZE_IN_ELEMENTS, sizeof(POINT)},
         {2, -3, W|SYSARG_SIZE_IN_ELEMENTS, sizeof(BYTE)},
     }
    },
    {{0,0},"NtGdiCreateCompatibleDC", OK, DRSYS_TYPE_HANDLE, 1,
     {
         {0,}
     }
    },
    {{0,0},"NtGdiCreateDIBitmapInternal", OK, DRSYS_TYPE_HANDLE, 11,
     {
         {4, -8, R,},
         {5, -7, R,},
     }
    },
    {{0,0},"NtGdiCreateDIBSection", OK, DRSYS_TYPE_HANDLE, 9,
     {
         {3, -5, R,},
         {8, sizeof(PVOID), W,},
     }
    },
    {{0,0},"NtGdiCreateSolidBrush", OK, DRSYS_TYPE_HANDLE, 2, },
    {{0,0},"NtGdiCreateDIBBrush", OK, DRSYS_TYPE_HANDLE, 6, },
    {{0,0},"NtGdiCreatePatternBrushInternal", OK, DRSYS_TYPE_HANDLE, 3, },
    {{0,0},"NtGdiCreateHatchBrushInternal", OK, DRSYS_TYPE_HANDLE, 3, },
    {{0,0},"NtGdiExtCreatePen", OK, DRSYS_TYPE_HANDLE, 11,
     {
         {7, -6, R|SYSARG_SIZE_IN_ELEMENTS, sizeof(ULONG)},
     }
    },
    {{0,0},"NtGdiCreateEllipticRgn", OK, DRSYS_TYPE_HANDLE, 4, },
    {{0,0},"NtGdiCreateRoundRectRgn", OK, DRSYS_TYPE_HANDLE, 6, },
    {{0,0},"NtGdiCreateServerMetaFile", OK, DRSYS_TYPE_HANDLE, 6,
     {
         {2, -1, R,},
     }
    },
    {{0,0},"NtGdiExtCreateRegion", OK, DRSYS_TYPE_HANDLE, 3,
     {
         {0, sizeof(XFORM), R,},
         {2, -1, R,},
     }
    },
    {{0,0},"NtGdiMakeFontDir", OK, SYSARG_TYPE_UINT32, 5,
     {
         {1, -2, W,},
         {3, -4, R,},
     }
    },
    {{0,0},"NtGdiPolyDraw", OK, SYSARG_TYPE_BOOL32, 4,
     {
         {1, -3, R|SYSARG_SIZE_IN_ELEMENTS, sizeof(POINT)},
         {2, -3, R|SYSARG_SIZE_IN_ELEMENTS, sizeof(BYTE)},
     }
    },
    {{0,0},"NtGdiPolyTextOutW", OK, SYSARG_TYPE_BOOL32, 4,
     {
         {1, -2, R|SYSARG_SIZE_IN_ELEMENTS, sizeof(POLYTEXTW)},
     }
    },
    {{0,0},"NtGdiGetServerMetaFileBits", OK, SYSARG_TYPE_UINT32, 7,
     {
         {2, -1, W,},
         {3, sizeof(DWORD), W,},
         {4, sizeof(DWORD), W,},
         {5, sizeof(DWORD), W,},
         {6, sizeof(DWORD), W,},
     }
    },
    {{0,0},"NtGdiEqualRgn", OK, SYSARG_TYPE_BOOL32, 2, },
    {{0,0},"NtGdiGetBitmapDimension", OK, SYSARG_TYPE_BOOL32, 2,
     {
         {1, sizeof(SIZE), W,},
     }
    },
    {{0,0},"NtGdiGetNearestPaletteIndex", OK, SYSARG_TYPE_UINT32, 2, },
    {{0,0},"NtGdiPtVisible", OK, SYSARG_TYPE_BOOL32, 3, },
    {{0,0},"NtGdiRectVisible", OK, SYSARG_TYPE_BOOL32, 2,
     {
         {1, sizeof(RECT), R,},
     }
    },
    {{0,0},"NtGdiRemoveFontResourceW", OK, SYSARG_TYPE_BOOL32, 6,
     {
         {0, -1, R|SYSARG_SIZE_IN_ELEMENTS, sizeof(WCHAR)},
         {5, sizeof(DESIGNVECTOR), R,},
     }
    },
    {{0,0},"NtGdiResizePalette", OK, SYSARG_TYPE_BOOL32, 2, },
    {{0,0},"NtGdiSetBitmapDimension", OK, SYSARG_TYPE_BOOL32, 4,
     {
         {3, sizeof(SIZE), W,},
     }
    },
    {{0,0},"NtGdiOffsetClipRgn", OK, SYSARG_TYPE_SINT32, 3, },
    {{0,0},"NtGdiSetMetaRgn", OK, SYSARG_TYPE_SINT32, 1, },
    {{0,0},"NtGdiSetTextJustification", OK, SYSARG_TYPE_BOOL32, 3, },
    {{0,0},"NtGdiGetAppClipBox", OK, SYSARG_TYPE_SINT32, 2,
     {
         {1, sizeof(RECT), W,},
     }
    },
    {{0,0},"NtGdiGetTextExtentExW", OK, SYSARG_TYPE_BOOL32, 8,
     {
         {1, -2, R|SYSARG_SIZE_IN_ELEMENTS, sizeof(wchar_t)},
         {4, sizeof(ULONG), W,},
         {5, -2, W|SYSARG_SIZE_IN_ELEMENTS, sizeof(ULONG)},
         {5, -4, WI|SYSARG_SIZE_IN_ELEMENTS, sizeof(ULONG)},
         {6, sizeof(SIZE), W,},
     }
    },
    {{0,0},"NtGdiGetCharABCWidthsW", OK, SYSARG_TYPE_BOOL32, 6,
     {
         {3, -2, R|SYSARG_SIZE_IN_ELEMENTS, sizeof(WCHAR)},
         {5, -2, W|SYSARG_SIZE_IN_ELEMENTS, sizeof(ABC)},
     }
    },
    {{0,0},"NtGdiGetCharacterPlacementW", OK, SYSARG_TYPE_UINT32, 6,
     {
         {1, -2, R|SYSARG_SIZE_IN_ELEMENTS, sizeof(wchar_t)},
         {4, sizeof(GCP_RESULTSW), R|W,},
     }
    },
    {{0,0},"NtGdiAngleArc", OK, SYSARG_TYPE_BOOL32, 6, },
    {{0,0},"NtGdiBeginPath", OK, SYSARG_TYPE_BOOL32, 1, },
    {{0,0},"NtGdiSelectClipPath", OK, SYSARG_TYPE_BOOL32, 2, },
    {{0,0},"NtGdiCloseFigure", OK, SYSARG_TYPE_BOOL32, 1, },
    {{0,0},"NtGdiEndPath", OK, SYSARG_TYPE_BOOL32, 1, },
    {{0,0},"NtGdiAbortPath", OK, SYSARG_TYPE_BOOL32, 1, },
    {{0,0},"NtGdiFillPath", OK, SYSARG_TYPE_BOOL32, 1, },
    {{0,0},"NtGdiStrokeAndFillPath", OK, SYSARG_TYPE_BOOL32, 1, },
    {{0,0},"NtGdiStrokePath", OK, SYSARG_TYPE_BOOL32, 1, },
    {{0,0},"NtGdiWidenPath", OK, SYSARG_TYPE_BOOL32, 1, },
    {{0,0},"NtGdiFlattenPath", OK, SYSARG_TYPE_BOOL32, 1, },
    {{0,0},"NtGdiPathToRegion", OK, DRSYS_TYPE_HANDLE, 1, },
    {{0,0},"NtGdiSetMiterLimit", OK, SYSARG_TYPE_BOOL32, 3,
     {
         {2, sizeof(DWORD), R|W,},
     }
    },
    {{0,0},"NtGdiSetFontXform", OK, SYSARG_TYPE_BOOL32, 3, },
    {{0,0},"NtGdiGetMiterLimit", OK, SYSARG_TYPE_BOOL32, 2,
     {
         {1, sizeof(DWORD), W,},
     }
    },
    {{0,0},"NtGdiEllipse", OK, SYSARG_TYPE_BOOL32, 5, },
    {{0,0},"NtGdiRectangle", OK, SYSARG_TYPE_BOOL32, 5, },
    {{0,0},"NtGdiRoundRect", OK, SYSARG_TYPE_BOOL32, 7, },
    {{0,0},"NtGdiPlgBlt", OK, SYSARG_TYPE_BOOL32, 11,
     {
         {1,3, R|SYSARG_SIZE_IN_ELEMENTS, sizeof(POINT)},
     }
    },
    {{0,0},"NtGdiMaskBlt", OK, SYSARG_TYPE_BOOL32, 13, },
    {{0,0},"NtGdiExtFloodFill", OK, SYSARG_TYPE_BOOL32, 5, },
    {{0,0},"NtGdiFillRgn", OK, SYSARG_TYPE_BOOL32, 3, },
    {{0,0},"NtGdiFrameRgn", OK, SYSARG_TYPE_BOOL32, 5, },
    {{0,0},"NtGdiSetPixel", OK, SYSARG_TYPE_UINT32, 4, },
    {{0,0},"NtGdiGetPixel", OK, SYSARG_TYPE_UINT32, 3, },
    {{0,0},"NtGdiStartPage", OK, SYSARG_TYPE_BOOL32, 1, },
    {{0,0},"NtGdiEndPage", OK, SYSARG_TYPE_BOOL32, 1, },
    {{0,0},"NtGdiStartDoc", OK, SYSARG_TYPE_SINT32, 4,
     {
         {1, sizeof(DOCINFOW), R,},
         {2, sizeof(BOOL), W,},
     }
    },
    {{0,0},"NtGdiEndDoc", OK, SYSARG_TYPE_BOOL32, 1, },
    {{0,0},"NtGdiAbortDoc", OK, SYSARG_TYPE_BOOL32, 1, },
    {{0,0},"NtGdiUpdateColors", OK, SYSARG_TYPE_BOOL32, 1, },
    {{0,0},"NtGdiGetCharWidthW", OK, SYSARG_TYPE_BOOL32, 6,
     {
         {3, -2, R|SYSARG_SIZE_IN_ELEMENTS, sizeof(WCHAR)},
         {5, -2, W|SYSARG_SIZE_IN_ELEMENTS, sizeof(ULONG)},
     }
    },
    {{0,0},"NtGdiGetCharWidthInfo", OK, SYSARG_TYPE_BOOL32, 2,
     {
         {1, sizeof(CHWIDTHINFO), W,},
     }
    },
    {{0,0},"NtGdiDrawEscape", OK, SYSARG_TYPE_SINT32, 4,
     {
         {3, -2, R,},
     }
    },
    {{0,0},"NtGdiExtEscape", OK, SYSARG_TYPE_SINT32, 8,
     {
         {1, -2, R|SYSARG_SIZE_IN_ELEMENTS, sizeof(WCHAR)},
         {5, -4, R,},
         {7, -6, W,},
     }
    },
    {{0,0},"NtGdiGetFontData", OK, SYSARG_TYPE_UINT32, 5,
     {
         {3, -4, W,},
         {3, RET, W,},
     }
    },
    {{0,0},"NtGdiGetFontFileData", OK, SYSARG_TYPE_UINT32, 5,
     {
         {2, sizeof(ULONGLONG), R,},
         {3, -4, W,},
     }
    },
    {{0,0},"NtGdiGetFontFileInfo", OK, SYSARG_TYPE_UINT32, 5,
     {
         {2, -3, W,},
         {4, sizeof(SIZE_T), W,},
     }
    },
    {{0,0},"NtGdiGetGlyphOutline", OK, SYSARG_TYPE_UINT32, 8,
     {
         {3, sizeof(GLYPHMETRICS), W,},
         {5, -4, W,},
         {6, sizeof(MAT2), R,},
     }
    },
    {{0,0},"NtGdiGetETM", OK, SYSARG_TYPE_BOOL32, 2,
     {
         {1, sizeof(EXTTEXTMETRIC), W,},
     }
    },
    {{0,0},"NtGdiGetRasterizerCaps", OK, SYSARG_TYPE_BOOL32, 2,
     {
         {0, -1, W,},
     }, &sysnum_GdiGetRasterizerCaps
    },
    {{0,0},"NtGdiGetKerningPairs", OK, SYSARG_TYPE_UINT32, 3,
     {
         {2, -1, W|SYSARG_SIZE_IN_ELEMENTS, sizeof(KERNINGPAIR)},
         {2, RET, W|SYSARG_SIZE_IN_ELEMENTS, sizeof(KERNINGPAIR)},
     }
    },
    {{0,0},"NtGdiMonoBitmap", OK, SYSARG_TYPE_BOOL32, 1, },
    {{0,0},"NtGdiGetObjectBitmapHandle", OK, DRSYS_TYPE_HANDLE, 2,
     {
         {1, sizeof(UINT), W,},
     }
    },
    {{0,0},"NtGdiEnumObjects", OK, SYSARG_TYPE_UINT32, 4,
     {
         {3, -2, W,},
     }
    },
    {{0,0},"NtGdiResetDC", OK, SYSARG_TYPE_BOOL32, 5,
     {
         {1, sizeof(DEVMODEW)/*really var-len*/, R|CT, SYSARG_TYPE_DEVMODEW},
         {2, sizeof(BOOL), W,},
         {3, sizeof(DRIVER_INFO_2W), R,},
         {4, sizeof(PUMDHPDEV *), W,},
     }
    },
    {{0,0},"NtGdiSetBoundsRect", OK, SYSARG_TYPE_UINT32, 3,
     {
         {1, sizeof(RECT), R,},
     }
    },
    {{0,0},"NtGdiGetColorAdjustment", OK, SYSARG_TYPE_BOOL32, 2,
     {
         {1, sizeof(COLORADJUSTMENT), W,},
     }
    },
    {{0,0},"NtGdiSetColorAdjustment", OK, SYSARG_TYPE_BOOL32, 2,
     {
         {1, sizeof(COLORADJUSTMENT), R,},
     }
    },
    {{0,0},"NtGdiCancelDC", OK, SYSARG_TYPE_BOOL32, 1, },
    {{0,0},"NtGdiOpenDCW", OK, DRSYS_TYPE_HANDLE, 7/*8 on Vista+*/,
     {
         {0, sizeof(UNICODE_STRING), R|CT, SYSARG_TYPE_UNICODE_STRING,},
         {1, sizeof(DEVMODEW)/*really var-len*/, R|CT, SYSARG_TYPE_DEVMODEW},
         {2, sizeof(UNICODE_STRING), R|CT, SYSARG_TYPE_UNICODE_STRING,},
         /*arg added in middle in Vista so special-cased*/
     }, &sysnum_GdiOpenDCW
    },
    {{0,0},"NtGdiGetDCDword", OK, SYSARG_TYPE_BOOL32, 3,
     {
         {2, sizeof(DWORD), W,},
     }
    },
    {{0,0},"NtGdiGetDCPoint", OK, SYSARG_TYPE_BOOL32, 3,
     {
         {2, sizeof(POINTL), W,},
     }
    },
    {{0,0},"NtGdiScaleViewportExtEx", OK, SYSARG_TYPE_BOOL32, 6,
     {
         {5, sizeof(SIZE), W,},
     }
    },
    {{0,0},"NtGdiScaleWindowExtEx", OK, SYSARG_TYPE_BOOL32, 6,
     {
         {5, sizeof(SIZE), W,},
     }
    },
    {{0,0},"NtGdiSetVirtualResolution", OK, SYSARG_TYPE_BOOL32, 5, },
    {{0,0},"NtGdiSetSizeDevice", OK, SYSARG_TYPE_BOOL32, 3, },
    {{0,0},"NtGdiGetTransform", OK, SYSARG_TYPE_BOOL32, 3,
     {
         {2, sizeof(XFORM), W,},
     }
    },
    {{0,0},"NtGdiModifyWorldTransform", OK, SYSARG_TYPE_BOOL32, 3,
     {
         {1, sizeof(XFORM), R,},
     }
    },
    {{0,0},"NtGdiCombineTransform", OK, SYSARG_TYPE_BOOL32, 3,
     {
         {0, sizeof(XFORM), W,},
         {1, sizeof(XFORM), R,},
         {2, sizeof(XFORM), R,},
     }
    },
    {{0,0},"NtGdiTransformPoints", OK, SYSARG_TYPE_BOOL32, 5,
     {
         {1, -3, R|SYSARG_SIZE_IN_ELEMENTS, sizeof(POINT)},
         {2, -3, W|SYSARG_SIZE_IN_ELEMENTS, sizeof(POINT)},
     }
    },
    {{0,0},"NtGdiConvertMetafileRect", OK, SYSARG_TYPE_SINT32, 2,
     {
         {1, sizeof(RECTL), R|W,},
     }
    },
    {{0,0},"NtGdiGetTextCharsetInfo", OK, SYSARG_TYPE_SINT32, 3,
     {
         {1, sizeof(FONTSIGNATURE), W,},
     }
    },
    {{0,0},"NtGdiDoBanding", OK, SYSARG_TYPE_BOOL32, 4,
     {
         {2, sizeof(POINTL), W,},
         {3, sizeof(SIZE), W,},
     }
    },
    {{0,0},"NtGdiGetPerBandInfo", OK, SYSARG_TYPE_UINT32, 2,
     {
         {1, sizeof(PERBANDINFO), R|W,},
     }
    },
    {{0,0},"NtGdiGetStats", OK, RNTST, 5,
     {
         {3, -4, W,},
     }
    },
    {{0,0},"NtGdiSetMagicColors", OK, SYSARG_TYPE_BOOL32, 3, },
    {{0,0},"NtGdiSelectBrush", OK, DRSYS_TYPE_HANDLE, 2, },
    {{0,0},"NtGdiSelectPen", OK, DRSYS_TYPE_HANDLE, 2, },
    {{0,0},"NtGdiSelectBitmap", OK, DRSYS_TYPE_HANDLE, 2, },
    {{0,0},"NtGdiSelectFont", OK, DRSYS_TYPE_HANDLE, 2, },
    {{0,0},"NtGdiExtSelectClipRgn", OK, SYSARG_TYPE_SINT32, 3, },
    {{0,0},"NtGdiCreatePen", OK, DRSYS_TYPE_HANDLE, 4,
     {
         {0,},}},
    {{0,0},"NtGdiBitBlt", OK, SYSARG_TYPE_BOOL32, 11, },
    {{0,0},"NtGdiTileBitBlt", OK, SYSARG_TYPE_BOOL32, 7,
     {
         {1, sizeof(RECTL), R,},
         {3, sizeof(RECTL), R,},
         {4, sizeof(POINTL), R,},
     }
    },
    {{0,0},"NtGdiTransparentBlt", OK, SYSARG_TYPE_BOOL32, 11, },
    {{0,0},"NtGdiGetTextExtent", OK, SYSARG_TYPE_BOOL32, 5,
     {
         {1, -2, R|SYSARG_SIZE_IN_ELEMENTS, sizeof(wchar_t)},
         {3, sizeof(SIZE), W,},
     }
    },
    {{0,0},"NtGdiGetTextMetricsW", OK, SYSARG_TYPE_BOOL32, 3,
     {
         {1, -2, W,},
     }
    },
    {{0,0},"NtGdiGetTextFaceW", OK, SYSARG_TYPE_SINT32, 4,
     {
         {2, -1, W|SYSARG_SIZE_IN_ELEMENTS, sizeof(wchar_t)},
         {2, RET, W|SYSARG_SIZE_IN_ELEMENTS, sizeof(wchar_t)},
     }
    },
    {{0,0},"NtGdiGetRandomRgn", OK, SYSARG_TYPE_SINT32, 3, },
    {{0,0},"NtGdiExtTextOutW", OK, SYSARG_TYPE_BOOL32, 9,
     {
         {4, sizeof(RECT), R,},
         {5, -6, R|SYSARG_SIZE_IN_ELEMENTS, sizeof(wchar_t)},
         {7, -6, R|SYSARG_SIZE_IN_ELEMENTS, sizeof(INT)/*can be larger: special-cased*/},
     }, &sysnum_GdiExtTextOutW
    },
    {{0,0},"NtGdiIntersectClipRect", OK, SYSARG_TYPE_SINT32, 5, },
    {{0,0},"NtGdiCreateRectRgn", OK, DRSYS_TYPE_HANDLE, 4, },
    {{0,0},"NtGdiPatBlt", OK, SYSARG_TYPE_BOOL32, 6, },
    {{0,0},"NtGdiPolyPatBlt", OK, SYSARG_TYPE_BOOL32, 5,
     {
         {2, -3, R|SYSARG_SIZE_IN_ELEMENTS, sizeof(POLYPATBLT)},
     }
    },
    {{0,0},"NtGdiUnrealizeObject", OK, SYSARG_TYPE_BOOL32, 1, },
    {{0,0},"NtGdiGetStockObject", OK, DRSYS_TYPE_HANDLE, 1, },
    {{0,0},"NtGdiCreateCompatibleBitmap", OK, DRSYS_TYPE_HANDLE, 3,
     {
         {0,},
     }
    },
    {{0,0},"NtGdiCreateBitmapFromDxSurface", OK, DRSYS_TYPE_HANDLE, 5, },
    {{0,0},"NtGdiBeginGdiRendering", OK, SYSARG_TYPE_BOOL32, 2, },
    {{0,0},"NtGdiEndGdiRendering", OK, SYSARG_TYPE_BOOL32, 3,
     {
         {2, sizeof(BOOL), W,},
     }
    },
    {{0,0},"NtGdiLineTo", OK, SYSARG_TYPE_BOOL32, 3, },
    {{0,0},"NtGdiMoveTo", OK, SYSARG_TYPE_BOOL32, 4,
     {
         {3, sizeof(POINT), W,},
     }
    },
    {{0,0},"NtGdiExtGetObjectW", OK, SYSARG_TYPE_SINT32, 3,
     {
         {2, -1, W},
         {2, RET, W,},
     }
    },
    {{0,0},"NtGdiGetDeviceCaps", OK, SYSARG_TYPE_SINT32, 2, },
    {{0,0},"NtGdiGetDeviceCapsAll", OK, RNTST, 2,
     {
         {1, sizeof(DEVCAPS), W,},
     }
    },
    {{0,0},"NtGdiStretchBlt", OK, SYSARG_TYPE_BOOL32, 12, },
    {{0,0},"NtGdiSetBrushOrg", OK, SYSARG_TYPE_BOOL32, 4,
     {
         {3, sizeof(POINT), W,},
     }
    },
    {{0,0},"NtGdiCreateBitmap", OK, DRSYS_TYPE_HANDLE, 5,
     {
         {4, sizeof(BYTE), R,},
     }
    },
    {{0,0},"NtGdiCreateHalftonePalette", OK, DRSYS_TYPE_HANDLE, 1, },
    {{0,0},"NtGdiRestoreDC", OK, SYSARG_TYPE_BOOL32, 2, },
    {{0,0},"NtGdiExcludeClipRect", OK, SYSARG_TYPE_SINT32, 5, },
    {{0,0},"NtGdiSaveDC", OK, SYSARG_TYPE_SINT32, 1, },
    {{0,0},"NtGdiCombineRgn", OK, SYSARG_TYPE_SINT32, 4, },
    {{0,0},"NtGdiSetRectRgn", OK, SYSARG_TYPE_BOOL32, 5, },
    {{0,0},"NtGdiSetBitmapBits", OK, SYSARG_TYPE_SINT32, 3,
     {
         {2, -1, R,},
     }
    },
    {{0,0},"NtGdiGetDIBitsInternal", OK, SYSARG_TYPE_SINT32, 9,
     {
         {4, -7, W,},
         {5, sizeof(BITMAPINFO), R|W|CT, SYSARG_TYPE_BITMAPINFO},
     }
    },
    {{0,0},"NtGdiOffsetRgn", OK, SYSARG_TYPE_SINT32, 3, },
    {{0,0},"NtGdiGetRgnBox", OK, SYSARG_TYPE_SINT32, 2,
     {
         {1, sizeof(RECT), W,},
     }
    },
    {{0,0},"NtGdiRectInRegion", OK, SYSARG_TYPE_BOOL32, 2,
     {
         {1, sizeof(RECT), R|W,},
     }
    },
    {{0,0},"NtGdiGetBoundsRect", OK, SYSARG_TYPE_UINT32, 3,
     {
         {1, sizeof(RECT), W,},
     }
    },
    {{0,0},"NtGdiPtInRegion", OK, SYSARG_TYPE_BOOL32, 3, },
    {{0,0},"NtGdiGetNearestColor", OK, SYSARG_TYPE_UINT32, 2, },
    {{0,0},"NtGdiGetSystemPaletteUse", OK, SYSARG_TYPE_UINT32, 1, },
    {{0,0},"NtGdiSetSystemPaletteUse", OK, SYSARG_TYPE_UINT32, 2, },
    {{0,0},"NtGdiGetRegionData", OK, SYSARG_TYPE_UINT32, 3,
     {
         {2, -1, W,},
         {2, RET, W,},
     }
    },
    {{0,0},"NtGdiInvertRgn", OK, SYSARG_TYPE_BOOL32, 2, },
    {{0,0},"NtGdiHfontCreate", OK, DRSYS_TYPE_HANDLE, 5,
     {
         {0,},
     },/*special-cased*/ &sysnum_GdiHfontCreate
    },
#if 0 /* for _WIN32_WINNT < 0x0500 == NT which we ignore for now */
    {{0,0},"NtGdiHfontCreate", OK, DRSYS_TYPE_HANDLE, 5,
     {
         {0, sizeof(EXTLOGFONTW), R,},
     }
    },
#endif
    {{0,0},"NtGdiSetFontEnumeration", OK, SYSARG_TYPE_UINT32, 1, },
    {{0,0},"NtGdiEnumFonts", OK, SYSARG_TYPE_BOOL32, 8,
     {
         {4, -3, R|SYSARG_SIZE_IN_ELEMENTS, sizeof(wchar_t)},
         {6, sizeof(ULONG), R|W|SYSARG_IGNORE_IF_NEXT_NULL,},
         {7, -6, WI,},
     }
    },
    {{0,0},"NtGdiQueryFonts", OK, SYSARG_TYPE_SINT32, 3,
     {
         {0, -1, W|SYSARG_SIZE_IN_ELEMENTS, sizeof(UNIVERSAL_FONT_ID)},
         {2, sizeof(LARGE_INTEGER), W,},
     }
    },
    {{0,0},"NtGdiGetCharSet", OK, SYSARG_TYPE_UINT32, 1, },
    {{0,0},"NtGdiEnableEudc", OK, SYSARG_TYPE_BOOL32, 1, },
    {{0,0},"NtGdiEudcLoadUnloadLink", OK, SYSARG_TYPE_BOOL32, 7,
     {
         {0, -1, R|SYSARG_SIZE_IN_ELEMENTS, sizeof(wchar_t)},
         {2, -3, R|SYSARG_SIZE_IN_ELEMENTS, sizeof(wchar_t)},
     }
    },
    {{0,0},"NtGdiGetStringBitmapW", OK, SYSARG_TYPE_UINT32, 5,
     {
         {1, sizeof(wchar_t), R,},
         {4, -3, W,},
     }
    },
    {{0,0},"NtGdiGetEudcTimeStampEx", OK, SYSARG_TYPE_UINT32, 3,
     {
         {0, -1, R|SYSARG_SIZE_IN_ELEMENTS, sizeof(wchar_t)},
     }
    },
    {{0,0},"NtGdiQueryFontAssocInfo", OK, SYSARG_TYPE_UINT32, 1, },
    {{0,0},"NtGdiGetFontUnicodeRanges", OK, SYSARG_TYPE_UINT32, 2,
     {
         {1, RET, W,/*FIXME i#485: pre size from prior syscall ret*/},
     }
    },
    /* FIXME i#485: the REALIZATION_INFO struct is much larger on win7 */
    {{0,0},"NtGdiGetRealizationInfo", UNKNOWN, SYSARG_TYPE_BOOL32, 2,
     {
         {1, sizeof(REALIZATION_INFO), W,},
     }
    },
    {{0,0},"NtGdiAddRemoteMMInstanceToDC", OK, SYSARG_TYPE_BOOL32, 3,
     {
         {1, -2, R,},
     }
    },
    {{0,0},"NtGdiUnloadPrinterDriver", OK, SYSARG_TYPE_BOOL32, 2,
     {
         {0, -1, R,},
     }
    },
    {{0,0},"NtGdiEngAssociateSurface", OK, SYSARG_TYPE_BOOL32, 3, },
    {{0,0},"NtGdiEngEraseSurface", OK, SYSARG_TYPE_BOOL32, 3,
     {
         {0, sizeof(SURFOBJ), R,},
         {1, sizeof(RECTL), R,},
     }
    },
    {{0,0},"NtGdiEngCreateBitmap", OK, DRSYS_TYPE_HANDLE, 5, },
    {{0,0},"NtGdiEngDeleteSurface", OK, SYSARG_TYPE_BOOL32, 1, },
    {{0,0},"NtGdiEngLockSurface", OK, DRSYS_TYPE_POINTER, 1, },
    {{0,0},"NtGdiEngUnlockSurface", OK, DRSYS_TYPE_VOID, 1,
     {
         {0, sizeof(SURFOBJ), R,},
     }
    },
    {{0,0},"NtGdiEngMarkBandingSurface", OK, SYSARG_TYPE_BOOL32, 1, },
    {{0,0},"NtGdiEngCreateDeviceSurface", OK, DRSYS_TYPE_HANDLE, 3, },
    {{0,0},"NtGdiEngCreateDeviceBitmap", OK, DRSYS_TYPE_HANDLE, 3, },
    {{0,0},"NtGdiEngCopyBits", OK, SYSARG_TYPE_BOOL32, 6,
     {
         {0, sizeof(SURFOBJ), R,},
         {1, sizeof(SURFOBJ), R,},
         {2, sizeof(CLIPOBJ), R,},
         {3, sizeof(XLATEOBJ), R,},
         {4, sizeof(RECTL), R,},
         {5, sizeof(POINTL), R,},
     }
    },
    {{0,0},"NtGdiEngStretchBlt", OK, SYSARG_TYPE_BOOL32, 11,
     {
         {0, sizeof(SURFOBJ), R,},
         {1, sizeof(SURFOBJ), R,},
         {2, sizeof(SURFOBJ), R,},
         {3, sizeof(CLIPOBJ), R,},
         {4, sizeof(XLATEOBJ), R,},
         {5, sizeof(COLORADJUSTMENT), R,},
         {6, sizeof(POINTL), R,},
         {7, sizeof(RECTL), R,},
         {8, sizeof(RECTL), R,},
         {9, sizeof(POINTL), R,},
     }
    },
    {{0,0},"NtGdiEngBitBlt", OK, SYSARG_TYPE_BOOL32, 11,
     {
         {0, sizeof(SURFOBJ), R,},
         {1, sizeof(SURFOBJ), R,},
         {2, sizeof(SURFOBJ), R,},
         {3, sizeof(CLIPOBJ), R,},
         {4, sizeof(XLATEOBJ), R,},
         {5, sizeof(RECTL), R,},
         {6, sizeof(POINTL), R,},
         {7, sizeof(POINTL), R,},
         {8, sizeof(BRUSHOBJ), R,},
         {9, sizeof(POINTL), R,},
     }
    },
    {{0,0},"NtGdiEngPlgBlt", OK, SYSARG_TYPE_BOOL32, 11,
     {
         {0, sizeof(SURFOBJ), R,},
         {1, sizeof(SURFOBJ), R,},
         {2, sizeof(SURFOBJ), R,},
         {3, sizeof(CLIPOBJ), R,},
         {4, sizeof(XLATEOBJ), R,},
         {5, sizeof(COLORADJUSTMENT), R,},
         {6, sizeof(POINTL), R,},
         {7, sizeof(POINTFIX), R,},
         {8, sizeof(RECTL), R,},
         {9, sizeof(POINTL), R,},
     }
    },
    {{0,0},"NtGdiEngCreatePalette", OK, DRSYS_TYPE_HANDLE, 6,
     {
         {2, sizeof(ULONG), R,},
     }
    },
    {{0,0},"NtGdiEngDeletePalette", OK, SYSARG_TYPE_BOOL32, 1, },
    {{0,0},"NtGdiEngStrokePath", OK, SYSARG_TYPE_BOOL32, 8,
     {
         {0, sizeof(SURFOBJ), R,},
         {1, sizeof(PATHOBJ), R,},
         {2, sizeof(CLIPOBJ), R,},
         {3, sizeof(XFORMOBJ), R,},
         {4, sizeof(BRUSHOBJ), R,},
         {5, sizeof(POINTL), R,},
         {6, sizeof(LINEATTRS), R,},
     }
    },
    {{0,0},"NtGdiEngFillPath", OK, SYSARG_TYPE_BOOL32, 7,
     {
         {0, sizeof(SURFOBJ), R,},
         {1, sizeof(PATHOBJ), R,},
         {2, sizeof(CLIPOBJ), R,},
         {3, sizeof(BRUSHOBJ), R,},
         {4, sizeof(POINTL), R,},
     }
    },
    {{0,0},"NtGdiEngStrokeAndFillPath", OK, SYSARG_TYPE_BOOL32, 10,
     {
         {0, sizeof(SURFOBJ), R,},
         {1, sizeof(PATHOBJ), R,},
         {2, sizeof(CLIPOBJ), R,},
         {3, sizeof(XFORMOBJ), R,},
         {4, sizeof(BRUSHOBJ), R,},
         {5, sizeof(LINEATTRS), R,},
         {6, sizeof(BRUSHOBJ), R,},
         {7, sizeof(POINTL), R,},
     }
    },
    {{0,0},"NtGdiEngPaint", OK, SYSARG_TYPE_BOOL32, 5,
     {
         {0, sizeof(SURFOBJ), R,},
         {1, sizeof(CLIPOBJ), R,},
         {2, sizeof(BRUSHOBJ), R,},
         {3, sizeof(POINTL), R,},
     }
    },
    {{0,0},"NtGdiEngLineTo", OK, SYSARG_TYPE_BOOL32, 9,
     {
         {0, sizeof(SURFOBJ), R,},
         {1, sizeof(CLIPOBJ), R,},
         {2, sizeof(BRUSHOBJ), R,},
         {7, sizeof(RECTL), R,},
     }
    },
    {{0,0},"NtGdiEngAlphaBlend", OK, SYSARG_TYPE_BOOL32, 7,
     {
         {0, sizeof(SURFOBJ), R,},
         {1, sizeof(SURFOBJ), R,},
         {2, sizeof(CLIPOBJ), R,},
         {3, sizeof(XLATEOBJ), R,},
         {4, sizeof(RECTL), R,},
         {5, sizeof(RECTL), R,},
         {6, sizeof(BLENDOBJ), R,},
     }
    },
    {{0,0},"NtGdiEngGradientFill", OK, SYSARG_TYPE_BOOL32, 10,
     {
         {0, sizeof(SURFOBJ), R,},
         {1, sizeof(CLIPOBJ), R,},
         {2, sizeof(XLATEOBJ), R,},
         {3, -4, R|SYSARG_SIZE_IN_ELEMENTS, sizeof(TRIVERTEX)},
         {7, sizeof(RECTL), R,},
         {8, sizeof(POINTL), R,},
     }
    },
    {{0,0},"NtGdiEngTransparentBlt", OK, SYSARG_TYPE_BOOL32, 8,
     {
         {0, sizeof(SURFOBJ), R,},
         {1, sizeof(SURFOBJ), R,},
         {2, sizeof(CLIPOBJ), R,},
         {3, sizeof(XLATEOBJ), R,},
         {4, sizeof(RECTL), R,},
         {5, sizeof(RECTL), R,},
     }
    },
    {{0,0},"NtGdiEngTextOut", OK, SYSARG_TYPE_BOOL32, 10,
     {
         {0, sizeof(SURFOBJ), R,},
         {1, sizeof(STROBJ), R,},
         {2, sizeof(FONTOBJ), R,},
         {3, sizeof(CLIPOBJ), R,},
         {4, sizeof(RECTL), R,},
         {5, sizeof(RECTL), R,},
         {6, sizeof(BRUSHOBJ), R,},
         {7, sizeof(BRUSHOBJ), R,},
         {8, sizeof(POINTL), R,},
     }
    },
    {{0,0},"NtGdiEngStretchBltROP", OK, SYSARG_TYPE_BOOL32, 13,
     {
         {0, sizeof(SURFOBJ), R,},
         {1, sizeof(SURFOBJ), R,},
         {2, sizeof(SURFOBJ), R,},
         {3, sizeof(CLIPOBJ), R,},
         {4, sizeof(XLATEOBJ), R,},
         {5, sizeof(COLORADJUSTMENT), R,},
         {6, sizeof(POINTL), R,},
         {7, sizeof(RECTL), R,},
         {8, sizeof(RECTL), R,},
         {9, sizeof(POINTL), R,},
         {11, sizeof(BRUSHOBJ), R,},
     }
    },
    {{0,0},"NtGdiXLATEOBJ_cGetPalette", OK, SYSARG_TYPE_UINT32, 4,
     {
         {0, sizeof(XLATEOBJ), R,},
         {3, -2, W|SYSARG_SIZE_IN_ELEMENTS, sizeof(ULONG)},
     }
    },
    {{0,0},"NtGdiCLIPOBJ_cEnumStart", OK, SYSARG_TYPE_UINT32, 5,
     {
         {0, sizeof(CLIPOBJ), R,},
     }
    },
    {{0,0},"NtGdiCLIPOBJ_bEnum", OK, SYSARG_TYPE_BOOL32, 3,
     {
         {0, sizeof(CLIPOBJ), R,},
         {2, -1, W,},
     }
    },
    {{0,0},"NtGdiCLIPOBJ_ppoGetPath", OK, DRSYS_TYPE_POINTER, 1,
     {
         {0, sizeof(CLIPOBJ), R,},
     }
    },
    {{0,0},"NtGdiEngCreateClip", OK, DRSYS_TYPE_POINTER, 0, },
    {{0,0},"NtGdiEngDeleteClip", OK, DRSYS_TYPE_VOID, 1,
     {
         {0, sizeof(CLIPOBJ), R,},
     }
    },
    {{0,0},"NtGdiBRUSHOBJ_pvAllocRbrush", OK, DRSYS_TYPE_POINTER, 2,
     {
         {0, sizeof(BRUSHOBJ), R,},
     }
    },
    {{0,0},"NtGdiBRUSHOBJ_pvGetRbrush", OK, DRSYS_TYPE_POINTER, 1,
     {
         {0, sizeof(BRUSHOBJ), R,},
     }
    },
    {{0,0},"NtGdiBRUSHOBJ_ulGetBrushColor", OK, SYSARG_TYPE_UINT32, 1,
     {
         {0, sizeof(BRUSHOBJ), R,},
     }
    },
    {{0,0},"NtGdiBRUSHOBJ_hGetColorTransform", OK, DRSYS_TYPE_HANDLE, 1,
     {
         {0, sizeof(BRUSHOBJ), R,},
     }
    },
    {{0,0},"NtGdiXFORMOBJ_bApplyXform", OK, SYSARG_TYPE_BOOL32, 5,
     {
         {0, sizeof(XFORMOBJ), R,},
         {3, -2, R|SYSARG_SIZE_IN_ELEMENTS, sizeof(POINTL)},
         {4, -2, W|SYSARG_SIZE_IN_ELEMENTS, sizeof(POINTL)},
     }
    },
    {{0,0},"NtGdiXFORMOBJ_iGetXform", OK, SYSARG_TYPE_UINT32, 2,
     {
         {0, sizeof(XFORMOBJ), R,},
         {1, sizeof(XFORML), W,},
     }
    },
    {{0,0},"NtGdiFONTOBJ_vGetInfo", OK, DRSYS_TYPE_VOID, 3,
     {
         {0, sizeof(FONTOBJ), R,},
         {2, -1, W,},
     }
    },
    {{0,0},"NtGdiFONTOBJ_cGetGlyphs", OK, SYSARG_TYPE_UINT32, 5,
     {
         {0, sizeof(FONTOBJ), R,},
         {3, sizeof(HGLYPH), R,},
         {4, sizeof(GLYPHDATA **), W,},
     }
    },
    {{0,0},"NtGdiFONTOBJ_pxoGetXform", OK, DRSYS_TYPE_POINTER, 1,
     {
         {0, sizeof(FONTOBJ), R,},
     }
    },
    {{0,0},"NtGdiFONTOBJ_pifi", OK, DRSYS_TYPE_POINTER, 1,
     {
         {0, sizeof(FONTOBJ), R,},
     }
    },
    {{0,0},"NtGdiFONTOBJ_pfdg", OK, DRSYS_TYPE_POINTER, 1,
     {
         {0, sizeof(FONTOBJ), R,},
     }
    },
    {{0,0},"NtGdiFONTOBJ_cGetAllGlyphHandles", OK, SYSARG_TYPE_UINT32, 2,
     {
         {0, sizeof(FONTOBJ), R,},
         {1, RET, W|SYSARG_SIZE_IN_ELEMENTS, sizeof(HGLYPH)/*FIXME i#485: pre size from prior syscall ret*/},
     }
    },
    {{0,0},"NtGdiFONTOBJ_pvTrueTypeFontFile", OK, DRSYS_TYPE_POINTER, 2,
     {
         {0, sizeof(FONTOBJ), R,},
         {1, sizeof(ULONG), W,},
     }
    },
    {{0,0},"NtGdiFONTOBJ_pQueryGlyphAttrs", OK, DRSYS_TYPE_POINTER, 2,
     {
         {0, sizeof(FONTOBJ), R,},
     }
    },
    {{0,0},"NtGdiSTROBJ_bEnum", OK, SYSARG_TYPE_BOOL32, 3,
     {
         {0, sizeof(STROBJ), R,},
         {1, sizeof(ULONG), R|W,/*XXX: I'm assuming R: else how know? prior syscall (i#485)?*/},
         {2, -1, WI|SYSARG_SIZE_IN_ELEMENTS, sizeof(PGLYPHPOS)},
     }
    },
    {{0,0},"NtGdiSTROBJ_bEnumPositionsOnly", OK, SYSARG_TYPE_BOOL32, 3,
     {
         {0, sizeof(STROBJ), R,},
         {1, sizeof(ULONG), R|W,/*XXX: I'm assuming R: else how know? prior syscall (i#485)?*/},
         {2, -1, WI|SYSARG_SIZE_IN_ELEMENTS, sizeof(PGLYPHPOS)},
     }
    },
    {{0,0},"NtGdiSTROBJ_vEnumStart", OK, DRSYS_TYPE_VOID, 1,
     {
         {0, sizeof(STROBJ), R,},
     }
    },
    {{0,0},"NtGdiSTROBJ_dwGetCodePage", OK, SYSARG_TYPE_UINT32, 1,
     {
         {0, sizeof(STROBJ), R,},
     }
    },
    {{0,0},"NtGdiSTROBJ_bGetAdvanceWidths", OK, SYSARG_TYPE_BOOL32, 4,
     {
         {0, sizeof(STROBJ), R,},
         {3, -2, W|SYSARG_SIZE_IN_ELEMENTS, sizeof(POINTQF)},
     }
    },
    {{0,0},"NtGdiEngComputeGlyphSet", OK, DRSYS_TYPE_POINTER, 3, },
    {{0,0},"NtGdiXLATEOBJ_iXlate", OK, SYSARG_TYPE_UINT32, 2,
     {
         {0, sizeof(XLATEOBJ), R,},
     }
    },
    {{0,0},"NtGdiXLATEOBJ_hGetColorTransform", OK, DRSYS_TYPE_HANDLE, 1,
     {
         {0, sizeof(XLATEOBJ), R,},
     }
    },
    {{0,0},"NtGdiPATHOBJ_vGetBounds", OK, DRSYS_TYPE_VOID, 2,
     {
         {0, sizeof(PATHOBJ), R,},
         {1, sizeof(RECTFX), W,},
     }
    },
    {{0,0},"NtGdiPATHOBJ_bEnum", OK, SYSARG_TYPE_BOOL32, 2,
     {
         {0, sizeof(PATHOBJ), R,},
         {1, sizeof(PATHDATA), W,},
     }
    },
    {{0,0},"NtGdiPATHOBJ_vEnumStart", OK, DRSYS_TYPE_VOID, 1,
     {
         {0, sizeof(PATHOBJ), R,},
     }
    },
    {{0,0},"NtGdiEngDeletePath", OK, DRSYS_TYPE_VOID, 1,
     {
         {0, sizeof(PATHOBJ), R,},
     }
    },
    {{0,0},"NtGdiPATHOBJ_vEnumStartClipLines", OK, DRSYS_TYPE_VOID, 4,
     {
         {0, sizeof(PATHOBJ), R,},
         {1, sizeof(CLIPOBJ), R,},
         {2, sizeof(SURFOBJ), R,},
         {3, sizeof(LINEATTRS), R,},
     }
    },
    {{0,0},"NtGdiPATHOBJ_bEnumClipLines", OK, SYSARG_TYPE_BOOL32, 3,
     {
         {0, sizeof(PATHOBJ), R,},
         {2, -1, W,},
     }
    },
    {{0,0},"NtGdiEngCheckAbort", OK, SYSARG_TYPE_BOOL32, 1,
     {
         {0, sizeof(SURFOBJ), R,},
     }
    },
    {{0,0},"NtGdiGetDhpdev", OK, DRSYS_TYPE_HANDLE, 1, },
    {{0,0},"NtGdiHT_Get8BPPFormatPalette", OK, SYSARG_TYPE_SINT32, 4,
     {
         {0, RET, W|SYSARG_SIZE_IN_ELEMENTS, sizeof(PALETTEENTRY)/*FIXME i#485: pre size from prior syscall ret*/},
     }
    },
    {{0,0},"NtGdiHT_Get8BPPMaskPalette", OK, SYSARG_TYPE_SINT32, 6,
     {
         {0, RET, W|SYSARG_SIZE_IN_ELEMENTS, sizeof(PALETTEENTRY)/*FIXME i#485: pre size from prior syscall ret*/},
     }
    },
    {{0,0},"NtGdiUpdateTransform", OK, SYSARG_TYPE_BOOL32, 1, },
    {{0,0},"NtGdiSetLayout", OK, SYSARG_TYPE_UINT32, 3, },
    {{0,0},"NtGdiMirrorWindowOrg", OK, SYSARG_TYPE_BOOL32, 1, },
    {{0,0},"NtGdiGetDeviceWidth", OK, SYSARG_TYPE_SINT32, 1, },
    {{0,0},"NtGdiSetPUMPDOBJ", OK, SYSARG_TYPE_BOOL32, 4,
     {
         {2, sizeof(HUMPD), R|W|HT, DRSYS_TYPE_HANDLE},
         {3, sizeof(BOOL), W,},
     }
    },
    {{0,0},"NtGdiBRUSHOBJ_DeleteRbrush", OK, SYSARG_TYPE_BOOL32, 2,
     {
         {0, sizeof(BRUSHOBJ), R,},
         {1, sizeof(BRUSHOBJ), R,},
     }
    },
    {{0,0},"NtGdiUMPDEngFreeUserMem", OK, SYSARG_TYPE_BOOL32, 1,
     {
         {0, sizeof(KERNEL_PVOID), R,},
     }
    },
    {{0,0},"NtGdiSetBitmapAttributes", OK, DRSYS_TYPE_HANDLE, 2, },
    {{0,0},"NtGdiClearBitmapAttributes", OK, DRSYS_TYPE_HANDLE, 2, },
    {{0,0},"NtGdiSetBrushAttributes", OK, DRSYS_TYPE_HANDLE, 2, },
    {{0,0},"NtGdiClearBrushAttributes", OK, DRSYS_TYPE_HANDLE, 2, },
    {{0,0},"NtGdiDrawStream", OK, SYSARG_TYPE_BOOL32, 3, },
    {{0,0},"NtGdiMakeObjectXferable", OK, SYSARG_TYPE_BOOL32, 2, },
    {{0,0},"NtGdiMakeObjectUnXferable", OK, SYSARG_TYPE_BOOL32, 1, },
    {{0,0},"NtGdiSfmGetNotificationTokens", OK, SYSARG_TYPE_BOOL32, 3,
     {
         {1, sizeof(UINT), W,},
         {2, -0, W,},
     }
    },
    {{0,0},"NtGdiSfmRegisterLogicalSurfaceForSignaling", OK, SYSARG_TYPE_BOOL32, 2, },
    {{0,0},"NtGdiDwmGetHighColorMode", OK, SYSARG_TYPE_BOOL32, 1,
     {
         {0, sizeof(DXGI_FORMAT), W,},
     }
    },
    {{0,0},"NtGdiDwmSetHighColorMode", OK, SYSARG_TYPE_BOOL32, 1, },
    {{0,0},"NtGdiDwmCaptureScreen", OK, DRSYS_TYPE_HANDLE, 2,
     {
         {0, sizeof(RECT), R,},
     }
    },
    {{0,0},"NtGdiDdCreateFullscreenSprite", OK, RNTST, 4,
     {
         {2, sizeof(HANDLE), W|HT, DRSYS_TYPE_HANDLE},
         {3, sizeof(HDC), W,},
     }
    },
    {{0,0},"NtGdiDdNotifyFullscreenSpriteUpdate", OK, RNTST, 2, },
    {{0,0},"NtGdiDdDestroyFullscreenSprite", OK, RNTST, 2, },
    {{0,0},"NtGdiDdQueryVisRgnUniqueness", OK, SYSARG_TYPE_UINT32, 0, },

    /***************************************************/
    /* FIXME i#1095: fill in the unknown info, esp Vista+ */
    {{0,0},"NtGdiAddFontResourceW", UNKNOWN, DRSYS_TYPE_UNKNOWN, },
    {{0,0},"NtGdiCheckAndGetBitmapBits", UNKNOWN, DRSYS_TYPE_UNKNOWN, },
    {{0,0},"NtGdiConsoleTextOut", UNKNOWN, DRSYS_TYPE_UNKNOWN, },
    {{0,0},"NtGdiEnumFontChunk", UNKNOWN, DRSYS_TYPE_UNKNOWN, },
    {{0,0},"NtGdiEnumFontClose", UNKNOWN, DRSYS_TYPE_UNKNOWN, },
    {{0,0},"NtGdiEnumFontOpen", UNKNOWN, DRSYS_TYPE_UNKNOWN, },
    {{0,0},"NtGdiFullscreenControl", UNKNOWN, DRSYS_TYPE_UNKNOWN, },
    {{0,0},"NtGdiGetSpoolMessage", UNKNOWN, DRSYS_TYPE_UNKNOWN, },
    {{0,0},"NtGdiInitSpool", UNKNOWN, DRSYS_TYPE_UNKNOWN, },
    {{0,0},"NtGdiSetupPublicCFONT", UNKNOWN, DRSYS_TYPE_UNKNOWN, },
    {{0,0},"NtGdiStretchDIBitsInternal", UNKNOWN, DRSYS_TYPE_UNKNOWN, },

    /***************************************************/
    /* Added in Vista */
    {{0,0},"NtGdiConfigureOPMProtectedOutput", UNKNOWN, DRSYS_TYPE_UNKNOWN, },
    {{0,0},"NtGdiCreateOPMProtectedOutputs", UNKNOWN, DRSYS_TYPE_UNKNOWN, },
    {{0,0},"NtGdiDDCCIGetCapabilitiesString", UNKNOWN, DRSYS_TYPE_UNKNOWN, },
    {{0,0},"NtGdiDDCCIGetCapabilitiesStringLength", UNKNOWN, DRSYS_TYPE_UNKNOWN, },
    {{0,0},"NtGdiDDCCIGetTimingReport", UNKNOWN, DRSYS_TYPE_UNKNOWN, },
    {{0,0},"NtGdiDDCCIGetVCPFeature", UNKNOWN, DRSYS_TYPE_UNKNOWN, },
    {{0,0},"NtGdiDDCCISaveCurrentSettings", UNKNOWN, DRSYS_TYPE_UNKNOWN, },
    {{0,0},"NtGdiDDCCISetVCPFeature", UNKNOWN, DRSYS_TYPE_UNKNOWN, },
    {{0,0},"NtGdiDdDDICheckExclusiveOwnership", UNKNOWN, DRSYS_TYPE_UNKNOWN, },
    {{0,0},"NtGdiDdDDICheckMonitorPowerState", UNKNOWN, DRSYS_TYPE_UNKNOWN, },
    {{0,0},"NtGdiDdDDICheckOcclusion", UNKNOWN, DRSYS_TYPE_UNKNOWN, },
    {{0,0},"NtGdiDdDDICloseAdapter", UNKNOWN, DRSYS_TYPE_UNKNOWN, },
    {{0,0},"NtGdiDdDDICreateAllocation", UNKNOWN, DRSYS_TYPE_UNKNOWN, },
    {{0,0},"NtGdiDdDDICreateContext", UNKNOWN, DRSYS_TYPE_UNKNOWN, },
    {{0,0},"NtGdiDdDDICreateDCFromMemory", UNKNOWN, DRSYS_TYPE_UNKNOWN, },
    {{0,0},"NtGdiDdDDICreateDevice", UNKNOWN, DRSYS_TYPE_UNKNOWN, },
    {{0,0},"NtGdiDdDDICreateOverlay", UNKNOWN, DRSYS_TYPE_UNKNOWN, },
    {{0,0},"NtGdiDdDDICreateSynchronizationObject", UNKNOWN, DRSYS_TYPE_UNKNOWN, },
    {{0,0},"NtGdiDdDDIDestroyAllocation", UNKNOWN, DRSYS_TYPE_UNKNOWN, },
    {{0,0},"NtGdiDdDDIDestroyContext", UNKNOWN, DRSYS_TYPE_UNKNOWN, },
    {{0,0},"NtGdiDdDDIDestroyDCFromMemory", UNKNOWN, DRSYS_TYPE_UNKNOWN, },
    {{0,0},"NtGdiDdDDIDestroyDevice", UNKNOWN, DRSYS_TYPE_UNKNOWN, },
    {{0,0},"NtGdiDdDDIDestroyOverlay", UNKNOWN, DRSYS_TYPE_UNKNOWN, },
    {{0,0},"NtGdiDdDDIDestroySynchronizationObject", UNKNOWN, DRSYS_TYPE_UNKNOWN, },
    {{0,0},"NtGdiDdDDIEscape", UNKNOWN, DRSYS_TYPE_UNKNOWN, },
    {{0,0},"NtGdiDdDDIFlipOverlay", UNKNOWN, DRSYS_TYPE_UNKNOWN, },
    {{0,0},"NtGdiDdDDIGetContextSchedulingPriority", UNKNOWN, DRSYS_TYPE_UNKNOWN, },
    {{0,0},"NtGdiDdDDIGetDeviceState", UNKNOWN, DRSYS_TYPE_UNKNOWN, },
    {{0,0},"NtGdiDdDDIGetDisplayModeList", UNKNOWN, DRSYS_TYPE_UNKNOWN, },
    {{0,0},"NtGdiDdDDIGetMultisampleMethodList", UNKNOWN, DRSYS_TYPE_UNKNOWN, },
    {{0,0},"NtGdiDdDDIGetPresentHistory", UNKNOWN, DRSYS_TYPE_UNKNOWN, },
    {{0,0},"NtGdiDdDDIGetProcessSchedulingPriorityClass", UNKNOWN, DRSYS_TYPE_UNKNOWN, },
    {{0,0},"NtGdiDdDDIGetRuntimeData", UNKNOWN, DRSYS_TYPE_UNKNOWN, },
    {{0,0},"NtGdiDdDDIGetScanLine", UNKNOWN, DRSYS_TYPE_UNKNOWN, },
    {{0,0},"NtGdiDdDDIGetSharedPrimaryHandle", UNKNOWN, DRSYS_TYPE_UNKNOWN, },
    {{0,0},"NtGdiDdDDIInvalidateActiveVidPn", UNKNOWN, DRSYS_TYPE_UNKNOWN, },
    {{0,0},"NtGdiDdDDILock", UNKNOWN, DRSYS_TYPE_UNKNOWN, },
    {{0,0},"NtGdiDdDDIOpenAdapterFromDeviceName", UNKNOWN, DRSYS_TYPE_UNKNOWN, },
    {{0,0},"NtGdiDdDDIOpenAdapterFromHdc", UNKNOWN, DRSYS_TYPE_UNKNOWN, },
    {{0,0},"NtGdiDdDDIOpenResource", UNKNOWN, DRSYS_TYPE_UNKNOWN, },
    {{0,0},"NtGdiDdDDIPollDisplayChildren", UNKNOWN, DRSYS_TYPE_UNKNOWN, },
    {{0,0},"NtGdiDdDDIPresent", UNKNOWN, DRSYS_TYPE_UNKNOWN, },
    {{0,0},"NtGdiDdDDIQueryAdapterInfo", UNKNOWN, DRSYS_TYPE_UNKNOWN, },
    {{0,0},"NtGdiDdDDIQueryAllocationResidency", UNKNOWN, DRSYS_TYPE_UNKNOWN, },
    {{0,0},"NtGdiDdDDIQueryResourceInfo", UNKNOWN, DRSYS_TYPE_UNKNOWN, },
    {{0,0},"NtGdiDdDDIQueryStatistics", UNKNOWN, DRSYS_TYPE_UNKNOWN, },
    {{0,0},"NtGdiDdDDIReleaseProcessVidPnSourceOwners", UNKNOWN, DRSYS_TYPE_UNKNOWN, },
    {{0,0},"NtGdiDdDDIRender", UNKNOWN, DRSYS_TYPE_UNKNOWN, },
    {{0,0},"NtGdiDdDDISetAllocationPriority", UNKNOWN, DRSYS_TYPE_UNKNOWN, },
    {{0,0},"NtGdiDdDDISetContextSchedulingPriority", UNKNOWN, DRSYS_TYPE_UNKNOWN, },
    {{0,0},"NtGdiDdDDISetDisplayMode", UNKNOWN, DRSYS_TYPE_UNKNOWN, },
    {{0,0},"NtGdiDdDDISetDisplayPrivateDriverFormat", UNKNOWN, DRSYS_TYPE_UNKNOWN, },
    {{0,0},"NtGdiDdDDISetGammaRamp", UNKNOWN, DRSYS_TYPE_UNKNOWN, },
    {{0,0},"NtGdiDdDDISetProcessSchedulingPriorityClass", UNKNOWN, DRSYS_TYPE_UNKNOWN, },
    {{0,0},"NtGdiDdDDISetQueuedLimit", UNKNOWN, DRSYS_TYPE_UNKNOWN, },
    {{0,0},"NtGdiDdDDISetVidPnSourceOwner", UNKNOWN, DRSYS_TYPE_UNKNOWN, },
    {{0,0},"NtGdiDdDDISharedPrimaryLockNotification", UNKNOWN, DRSYS_TYPE_UNKNOWN, },
    {{0,0},"NtGdiDdDDISharedPrimaryUnLockNotification", UNKNOWN, DRSYS_TYPE_UNKNOWN, },
    {{0,0},"NtGdiDdDDISignalSynchronizationObject", UNKNOWN, DRSYS_TYPE_UNKNOWN, },
    {{0,0},"NtGdiDdDDIUnlock", UNKNOWN, DRSYS_TYPE_UNKNOWN, },
    {{0,0},"NtGdiDdDDIUpdateOverlay", UNKNOWN, DRSYS_TYPE_UNKNOWN, },
    {{0,0},"NtGdiDdDDIWaitForIdle", UNKNOWN, DRSYS_TYPE_UNKNOWN, },
    {{0,0},"NtGdiDdDDIWaitForSynchronizationObject", UNKNOWN, DRSYS_TYPE_UNKNOWN, },
    {{0,0},"NtGdiDdDDIWaitForVerticalBlankEvent", UNKNOWN, DRSYS_TYPE_UNKNOWN, },
    {{0,0},"NtGdiDestroyOPMProtectedOutput", UNKNOWN, DRSYS_TYPE_UNKNOWN, },
    {{0,0},"NtGdiDestroyPhysicalMonitor", UNKNOWN, DRSYS_TYPE_UNKNOWN, },
    {{0,0},"NtGdiDwmGetDirtyRgn", UNKNOWN, DRSYS_TYPE_UNKNOWN, },
    {{0,0},"NtGdiDwmGetSurfaceData", UNKNOWN, DRSYS_TYPE_UNKNOWN, },
    {{0,0},"NtGdiGetCOPPCompatibleOPMInformation", UNKNOWN, DRSYS_TYPE_UNKNOWN, },
    {{0,0},"NtGdiGetCertificate", UNKNOWN, DRSYS_TYPE_UNKNOWN, },
    {{0,0},"NtGdiGetCertificateSize", UNKNOWN, DRSYS_TYPE_UNKNOWN, },
    {{0,0},"NtGdiGetNumberOfPhysicalMonitors", UNKNOWN, DRSYS_TYPE_UNKNOWN, },
    {{0,0},"NtGdiGetOPMInformation", UNKNOWN, DRSYS_TYPE_UNKNOWN, },
    {{0,0},"NtGdiGetOPMRandomNumber", UNKNOWN, DRSYS_TYPE_UNKNOWN, },
    {{0,0},"NtGdiGetPhysicalMonitorDescription", UNKNOWN, DRSYS_TYPE_UNKNOWN, },
    {{0,0},"NtGdiGetPhysicalMonitors", UNKNOWN, DRSYS_TYPE_UNKNOWN, },
    {{0,0},"NtGdiGetSuggestedOPMProtectedOutputArraySize", UNKNOWN, DRSYS_TYPE_UNKNOWN, },
    {{0,0},"NtGdiSetOPMSigningKeyAndSequenceNumbers", UNKNOWN, DRSYS_TYPE_UNKNOWN, },

    /***************************************************/
    /* Added in Win7 */
    {{0,0},"NtGdiDdDDIAcquireKeyedMutex", UNKNOWN, DRSYS_TYPE_UNKNOWN, },
    {{0,0},"NtGdiDdDDICheckSharedResourceAccess", UNKNOWN, DRSYS_TYPE_UNKNOWN, },
    {{0,0},"NtGdiDdDDICheckVidPnExclusiveOwnership", UNKNOWN, DRSYS_TYPE_UNKNOWN, },
    {{0,0},"NtGdiDdDDIConfigureSharedResource", UNKNOWN, DRSYS_TYPE_UNKNOWN, },
    {{0,0},"NtGdiDdDDICreateKeyedMutex", UNKNOWN, DRSYS_TYPE_UNKNOWN, },
    {{0,0},"NtGdiDdDDIDestroyKeyedMutex", UNKNOWN, DRSYS_TYPE_UNKNOWN, },
    {{0,0},"NtGdiDdDDIGetOverlayState", UNKNOWN, DRSYS_TYPE_UNKNOWN, },
    {{0,0},"NtGdiDdDDIGetPresentQueueEvent", UNKNOWN, DRSYS_TYPE_UNKNOWN, },
    {{0,0},"NtGdiDdDDIOpenKeyedMutex", UNKNOWN, DRSYS_TYPE_UNKNOWN, },
    {{0,0},"NtGdiDdDDIOpenSynchronizationObject", UNKNOWN, DRSYS_TYPE_UNKNOWN, },
    {{0,0},"NtGdiDdDDIReleaseKeyedMutex", UNKNOWN, DRSYS_TYPE_UNKNOWN, },
    {{0,0},"NtGdiGetCodePage", UNKNOWN, DRSYS_TYPE_UNKNOWN, },
    {{0,0},"NtGdiHLSurfGetInformation", UNKNOWN, DRSYS_TYPE_UNKNOWN, },
    {{0,0},"NtGdiHLSurfSetInformation", UNKNOWN, DRSYS_TYPE_UNKNOWN, },

    /***************************************************/
    /* Added in Win8 */
    /* FIXME i#1153: fill in details */
    {{0,0},"NtGdiCreateBitmapFromDxSurface2", UNKNOWN, DRSYS_TYPE_UNKNOWN, 7, },
    {{0,0},"NtGdiCreateSessionMappedDIBSection", UNKNOWN, DRSYS_TYPE_UNKNOWN, 8, },
    {{0,0},"NtGdiDdDDIAcquireKeyedMutex2", UNKNOWN, DRSYS_TYPE_UNKNOWN, 1, },
    {{0,0},"NtGdiDdDDICreateKeyedMutex2", UNKNOWN, DRSYS_TYPE_UNKNOWN, 1, },
    {{0,0},"NtGdiDdDDICreateOutputDupl", UNKNOWN, DRSYS_TYPE_UNKNOWN, 1, },
    {{0,0},"NtGdiDdDDIDestroyOutputDupl", UNKNOWN, DRSYS_TYPE_UNKNOWN, 1, },
    {{0,0},"NtGdiDdDDIEnumAdapters", UNKNOWN, DRSYS_TYPE_UNKNOWN, 1, },
    {{0,0},"NtGdiDdDDIGetContextInProcessSchedulingPriority", UNKNOWN, DRSYS_TYPE_UNKNOWN, 1, },
    {{0,0},"NtGdiDdDDIGetSharedResourceAdapterLuid", UNKNOWN, DRSYS_TYPE_UNKNOWN, 1, },
    {{0,0},"NtGdiDdDDIOfferAllocations", UNKNOWN, DRSYS_TYPE_UNKNOWN, 1, },
    {{0,0},"NtGdiDdDDIOpenAdapterFromLuid", UNKNOWN, DRSYS_TYPE_UNKNOWN, 1, },
    {{0,0},"NtGdiDdDDIOpenKeyedMutex2", UNKNOWN, DRSYS_TYPE_UNKNOWN, 1, },
    {{0,0},"NtGdiDdDDIOpenNtHandleFromName", UNKNOWN, DRSYS_TYPE_UNKNOWN, 1, },
    {{0,0},"NtGdiDdDDIOpenResourceFromNtHandle", UNKNOWN, DRSYS_TYPE_UNKNOWN, 1, },
    {{0,0},"NtGdiDdDDIOpenSyncObjectFromNtHandle", UNKNOWN, DRSYS_TYPE_UNKNOWN, 1, },
    {{0,0},"NtGdiDdDDIOutputDuplGetFrameInfo", UNKNOWN, DRSYS_TYPE_UNKNOWN, 1, },
    {{0,0},"NtGdiDdDDIOutputDuplGetMetaData", UNKNOWN, DRSYS_TYPE_UNKNOWN, 1, },
    {{0,0},"NtGdiDdDDIOutputDuplGetPointerShapeData", UNKNOWN, DRSYS_TYPE_UNKNOWN, 1, },
    {{0,0},"NtGdiDdDDIOutputDuplPresent", UNKNOWN, DRSYS_TYPE_UNKNOWN, 1, },
    {{0,0},"NtGdiDdDDIOutputDuplReleaseFrame", UNKNOWN, DRSYS_TYPE_UNKNOWN, 1, },
    {{0,0},"NtGdiDdDDIPinDirectFlipResources", UNKNOWN, DRSYS_TYPE_UNKNOWN, 1, },
    {{0,0},"NtGdiDdDDIQueryResourceInfoFromNtHandle", UNKNOWN, DRSYS_TYPE_UNKNOWN, 1, },
    {{0,0},"NtGdiDdDDIReclaimAllocations", UNKNOWN, DRSYS_TYPE_UNKNOWN, 1, },
    {{0,0},"NtGdiDdDDIReleaseKeyedMutex2", UNKNOWN, DRSYS_TYPE_UNKNOWN, 1, },
    {{0,0},"NtGdiDdDDISetContextInProcessSchedulingPriority", UNKNOWN, DRSYS_TYPE_UNKNOWN, 1, },
    {{0,0},"NtGdiDdDDISetStereoEnabled", UNKNOWN, DRSYS_TYPE_UNKNOWN, 1, },
    {{0,0},"NtGdiDdDDISetVidPnSourceOwner1", UNKNOWN, DRSYS_TYPE_UNKNOWN, 1, },
    {{0,0},"NtGdiDdDDIShareObjects", UNKNOWN, DRSYS_TYPE_UNKNOWN, 5, },
    {{0,0},"NtGdiDdDDIUnpinDirectFlipResources", UNKNOWN, DRSYS_TYPE_UNKNOWN, 1, },
    {{0,0},"NtGdiDdDDIWaitForVerticalBlankEvent2", UNKNOWN, DRSYS_TYPE_UNKNOWN, 1, },
    {{0,0},"NtGdiDwmCreatedBitmapRemotingOutput", UNKNOWN, DRSYS_TYPE_UNKNOWN, 0, },
    {{0,0},"NtGdiSetUMPDSandboxState", UNKNOWN, DRSYS_TYPE_UNKNOWN, 1, },
};
#define NUM_GDI32_SYSCALLS \
    (sizeof(syscall_gdi32_info)/sizeof(syscall_gdi32_info[0]))

size_t
num_gdi32_syscalls(void)
{
    return NUM_GDI32_SYSCALLS;
}

#undef OK
#undef UNKNOWN
#undef W
#undef R
#undef HT
#undef CT
#undef WI
#undef RET

/***************************************************************************
 * CUSTOM SYSCALL DATA STRUCTURE HANDLING
 */

/* XXX i#488: if too many params can take atoms or strings, should perhaps
 * query to verify really an atom to avoid false negatives with
 * bad string pointers
 */
static bool
is_atom(void *ptr)
{
    /* top 2 bytes are guaranteed to be 0 */
    return ((ptr_uint_t)ptr) < 0x10000;
}

/* XXX i#488: see is_atom comment */
static bool
is_int_resource(void *ptr)
{
    /* top 2 bytes are guaranteed to be 0 */
    return IS_INTRESOURCE(ptr);
}

bool
handle_large_string_access(sysarg_iter_info_t *ii,
                           const syscall_arg_t *arg_info,
                           app_pc start, uint size)
{
    LARGE_STRING ls;
    LARGE_STRING *arg = (LARGE_STRING *) start;
    drsys_param_type_t type_val = DRSYS_TYPE_LARGE_STRING;
    const char *type_name = "LARGE_STRING";
    ASSERT(size == sizeof(LARGE_STRING), "invalid size");
    /* I've seen an atom (or int resource?) here
     * XXX i#488: avoid false neg: not too many of these now though
     * so we allow on all syscalls
     */
    if (is_atom(start))
        return true; /* handled */
    /* we assume OUT fields just have their Buffer as OUT */
    if (ii->arg->pre) {
        if (!report_memarg(ii, arg_info, (byte *)&arg->Length,
                           sizeof(arg->Length), "LARGE_STRING.Length"))
            return true;
        /* this will include LARGE_STRING.bAnsi */
        if (!report_memarg(ii, arg_info,
                           /* we assume no padding (can't take & or offsetof bitfield) */
                           (byte *)&arg->Length + sizeof(arg->Length),
                           sizeof(ULONG/*+bAnsi*/), "LARGE_STRING.MaximumLength"))
            return true;
        if (!report_memarg(ii, arg_info, (byte *)&arg->Buffer,
                           sizeof(arg->Buffer), "LARGE_STRING.Buffer"))
            return true;
    }
    if (safe_read((void*)start, sizeof(ls), &ls)) {
        if (ii->arg->pre) {
            if (!report_memarg_ex(ii, arg_info->param, DRSYS_PARAM_BOUNDS,
                                  (byte *)ls.Buffer, ls.MaximumLength,
                                  "LARGE_STRING capacity", DRSYS_TYPE_LARGE_STRING, NULL,
                                  DRSYS_TYPE_INVALID))
                return true;
            if (TEST(SYSARG_READ, arg_info->flags)) {
                if (!report_memarg(ii, arg_info,
                                   (byte *)ls.Buffer, ls.Length, "LARGE_STRING content"))
                    return true;
            }
        } else if (TEST(SYSARG_WRITE, arg_info->flags)) {
            if (!report_memarg(ii, arg_info,
                               (byte *)ls.Buffer, ls.Length, "LARGE_STRING content"))
                return true;
        }
    } else
        WARN("WARNING: unable to read syscall param\n");
    return true; /* handled */
}

bool
handle_devmodew_access(sysarg_iter_info_t *ii,
                       const syscall_arg_t *arg_info,
                       app_pc start, uint size)
{
    /* DEVMODEW is var-len by windows ver plus optional private driver data appended */
    /* can't use a DEVMODEW as ours may be longer than app's if on older windows */
    char buf[offsetof(DEVMODEW,dmFields)]; /* need dmSize and dmDriverExtra */
    DEVMODEW *safe;
    DEVMODEW *param = (DEVMODEW *) start;
    if (ii->arg->pre) {
        /* XXX: for writes, are we sure all these fields should be set by the caller?
         * That's what my pre-drsyscall code had so going with it for now.
         */
        if (!report_memarg_type(ii, arg_info->param, SYSARG_READ,
                                start, BUFFER_SIZE_BYTES(buf),
                                "DEVMODEW through dmDriverExtra",
                                SYSARG_TYPE_DEVMODEW, NULL))
            return true;
    }
    if (safe_read(start, BUFFER_SIZE_BYTES(buf), buf)) {
        safe = (DEVMODEW *) buf;
        ASSERT(safe->dmSize > offsetof(DEVMODEW, dmFormName), "invalid size");
        /* there's some padding in the middle */
        if (!report_memarg(ii, arg_info, (byte *) &param->dmFields,
                           ((byte *) &param->dmCollate) + sizeof(safe->dmCollate) -
                           (byte *) &param->dmFields,
                           "DEVMODEW dmFields through dmCollate"))
            return true;
        if (!report_memarg(ii, arg_info, (byte *) &param->dmFormName,
                           (start + safe->dmSize) - (byte *) (&param->dmFormName),
                           "DEVMODEW dmFormName onward"))
            return true;
        if (!report_memarg(ii, arg_info, start + safe->dmSize, safe->dmDriverExtra,
                           "DEVMODEW driver extra info"))
            return true;;
    } else
        WARN("WARNING: unable to read syscall param\n");
    return true; /* handled */
}

bool
handle_wndclassexw_access(sysarg_iter_info_t *ii,
                          const syscall_arg_t *arg_info,
                          app_pc start, uint size)
{
    WNDCLASSEXW safe;
    /* i#499: it seems that cbSize is not set for NtUserGetClassInfo when using
     * user32!GetClassInfo so we use sizeof for writes.  I suspect that once
     * they add any more new fields they will start using it.  We could
     * alternatively keep the check here and treat this is a user32.dll bug and
     * suppress it.
     */
    bool use_cbSize = TEST(SYSARG_READ, arg_info->flags);
    if (ii->arg->pre && use_cbSize) {
        if (!report_memarg_type(ii, arg_info->param, SYSARG_READ, start,
                                sizeof(safe.cbSize), "WNDCLASSEX.cbSize",
                                SYSARG_TYPE_WNDCLASSEXW, NULL))
            return true;
    }
    if (safe_read(start, sizeof(safe), &safe)) {
        if (!report_memarg(ii, arg_info, start,
                           use_cbSize ? safe.cbSize : sizeof(WNDCLASSEX), "WNDCLASSEX"))
            return true;
        /* For WRITE there is no capacity here so nothing to check (i#505) */
        if ((ii->arg->pre && TEST(SYSARG_READ, arg_info->flags)) ||
            (!ii->arg->pre && TEST(SYSARG_WRITE, arg_info->flags))) {
                /* lpszMenuName can be from MAKEINTRESOURCE, and
                 * lpszClassName can be an atom
                 */
                if ((!use_cbSize || safe.cbSize > offsetof(WNDCLASSEX, lpszMenuName)) &&
                    !is_atom((void *)safe.lpszMenuName)) {
                    handle_cwstring(ii, "WNDCLASSEXW.lpszMenuName",
                                    (byte *) safe.lpszMenuName, 0,
                                    arg_info->param, arg_info->flags, NULL, true);
                    if (ii->abort)
                        return true;
                }
                if ((!use_cbSize || safe.cbSize > offsetof(WNDCLASSEX, lpszClassName)) &&
                    !is_int_resource((void *)safe.lpszClassName)) {
                    handle_cwstring(ii, "WNDCLASSEXW.lpszClassName",
                                    /* docs say 256 is max length: we read until
                                     * NULL though
                                     */
                                    (byte *) safe.lpszClassName, 0,
                                    arg_info->param, arg_info->flags, NULL, true);
                    if (ii->abort)
                        return true;
                }
        }
    } else
        WARN("WARNING: unable to read syscall param\n");
    return true; /* handled */
}

bool
handle_clsmenuname_access(sysarg_iter_info_t *ii,
                          const syscall_arg_t *arg_info,
                          app_pc start, uint size)
{
    CLSMENUNAME safe;
    if (!report_memarg(ii, arg_info, start, size, "CLSMENUNAME"))
        return true;
    if (ii->arg->pre && !TEST(SYSARG_READ, arg_info->flags)) {
        /* looks like even the UNICODE_STRING is not set up: contains garbage,
         * so presumably kernel creates it and doesn't just write to Buffer
         */
        return true; /* handled */
    }
    /* FIXME i#487: CLSMENUNAME format is not fully known and doesn't seem
     * to match this, on win7 at least
     */
#if 0 /* disabled: see comment above */
    if (safe_read(start, sizeof(safe), &safe)) {
        if (!is_atom(safe.pszClientAnsiMenuName)) {
            handle_cstring(pre, sysnum, "CLSMENUNAME.lpszMenuName",
                           safe.pszClientAnsiMenuName, 0, arg_info->flags,
                           NULL, true);
            if (ii->abort)
                return true;
        }
        if (!is_atom(safe.pwszClientUnicodeMenuName)) {
            handle_cwstring(ii, "CLSMENUNAME.lpszMenuName",
                            (byte *) safe.pwszClientUnicodeMenuName, 0,
                            arg_info->param, arg_info->flags, NULL, true);
            if (ii->abort)
                return true;
        }
        /* XXX: I've seen the pusMenuName pointer itself be an atom, though
         * perhaps should also handle just the Buffer being an atom?
         */
        if (!is_atom(safe.pusMenuName)) {
            handle_unicode_string_access(ii, arg_info,
                                         (byte *) safe.pusMenuName,
                                         sizeof(UNICODE_STRING), false);
            if (ii->abort)
                return true;
        }
    } else
        WARN("WARNING: unable to read syscall param\n");
#endif
    return true; /* handled */
}

bool
handle_menuiteminfow_access(sysarg_iter_info_t *ii,
                            const syscall_arg_t *arg_info,
                            app_pc start, uint size)
{
    MENUITEMINFOW *real = (MENUITEMINFOW *) start;
    MENUITEMINFOW safe;
    bool check_dwTypeData = false;
    /* user must set cbSize for set or get */
    if (ii->arg->pre) {
        if (!report_memarg_type(ii, arg_info->param, SYSARG_READ,
                                start, sizeof(safe.cbSize), "MENUITEMINFOW.cbSize",
                                SYSARG_TYPE_MENUITEMINFOW, NULL))
            return true;
    }
    if (safe_read(start, sizeof(safe), &safe)) {
        if (ii->arg->pre) {
            if (!report_memarg_ex(ii, arg_info->param, DRSYS_PARAM_BOUNDS,
                                  start, safe.cbSize, "MENUITEMINFOW",
                                  DRSYS_TYPE_MENUITEMINFOW, NULL, DRSYS_TYPE_INVALID))
                return true;
        }
        if (TEST(MIIM_BITMAP, safe.fMask) &&
            safe.cbSize > offsetof(MENUITEMINFOW, hbmpItem)) {
            if (!report_memarg(ii, arg_info, (byte *) &real->hbmpItem,
                               sizeof(real->hbmpItem), "MENUITEMINFOW.hbmpItem"))
                return true;
        }
        if (TEST(MIIM_CHECKMARKS, safe.fMask)) {
            if (safe.cbSize > offsetof(MENUITEMINFOW, hbmpChecked)) {
                if (!report_memarg(ii, arg_info, (byte *) &real->hbmpChecked,
                             sizeof(real->hbmpChecked), "MENUITEMINFOW.hbmpChecked"))
                return true;
            }
            if (safe.cbSize > offsetof(MENUITEMINFOW, hbmpUnchecked)) {
                if (!report_memarg(ii, arg_info, (byte *) &real->hbmpUnchecked,
                             sizeof(real->hbmpUnchecked), "MENUITEMINFOW.hbmpUnchecked"))
                    return true;
            }
        }
        if (TEST(MIIM_DATA, safe.fMask) &&
            safe.cbSize > offsetof(MENUITEMINFOW, dwItemData)) {
            if (!report_memarg(ii, arg_info, (byte *) &real->dwItemData,
                               sizeof(real->dwItemData), "MENUITEMINFOW.dwItemData"))
                return true;
        }
        if (TEST(MIIM_FTYPE, safe.fMask) &&
            safe.cbSize > offsetof(MENUITEMINFOW, fType)) {
            if (!report_memarg(ii, arg_info, (byte *) &real->fType,
                               sizeof(real->fType), "MENUITEMINFOW.fType"))
                return true;
        }
        if (TEST(MIIM_ID, safe.fMask) &&
            safe.cbSize > offsetof(MENUITEMINFOW, wID)) {
            if (!report_memarg(ii, arg_info, (byte *) &real->wID,
                               sizeof(real->wID), "MENUITEMINFOW.wID"))
                return true;
        }
        if (TEST(MIIM_STATE, safe.fMask) &&
            safe.cbSize > offsetof(MENUITEMINFOW, fState)) {
            if (!report_memarg(ii, arg_info, (byte *) &real->fState,
                               sizeof(real->fState), "MENUITEMINFOW.fState"))
                return true;
        }
        if (TEST(MIIM_STRING, safe.fMask) &&
            safe.cbSize > offsetof(MENUITEMINFOW, dwTypeData)) {
            if (!report_memarg(ii, arg_info, (byte *) &real->dwTypeData,
                               sizeof(real->dwTypeData), "MENUITEMINFOW.dwTypeData"))
                return true;
            check_dwTypeData = true;
        }
        if (TEST(MIIM_SUBMENU, safe.fMask) &&
            safe.cbSize > offsetof(MENUITEMINFOW, hSubMenu)) {
            if (!report_memarg(ii, arg_info, (byte *) &real->hSubMenu,
                               sizeof(real->hSubMenu), "MENUITEMINFOW.hSubMenu"))
                return true;
        }
        if (TEST(MIIM_TYPE, safe.fMask) &&
            !TESTANY(MIIM_BITMAP | MIIM_FTYPE | MIIM_STRING, safe.fMask)) {
            if (safe.cbSize > offsetof(MENUITEMINFOW, fType)) {
                if (!report_memarg(ii, arg_info, (byte *) &real->fType,
                                   sizeof(real->fType), "MENUITEMINFOW.fType"))
                return true;
            }
            if (safe.cbSize > offsetof(MENUITEMINFOW, dwTypeData)) {
                if (!report_memarg(ii, arg_info, (byte *) &real->dwTypeData,
                                   sizeof(real->dwTypeData), "MENUITEMINFOW.dwTypeData"))
                return true;
                check_dwTypeData = true;
            }
        }
        if (check_dwTypeData) {
            /* kernel sets safe.cch so we don't have to walk the string */
            if (!report_memarg(ii, arg_info, (byte *) safe.dwTypeData,
                               (safe.cch + 1/*null*/) * sizeof(wchar_t),
                               "MENUITEMINFOW.dwTypeData"))
                return true;
        }
    } else
        WARN("WARNING: unable to read syscall param\n");
    return true; /* handled */
}

bool
handle_bitmapinfo_access(sysarg_iter_info_t *ii,
                         const syscall_arg_t *arg_info,
                         app_pc start, uint size)
{
    /* bmiColors is variable-length and the number of entries in the
     * array depends on the values of the biBitCount and biClrUsed 
     * members of the BITMAPINFOHEADER struct.
     */
    BITMAPINFOHEADER bmi;
    size = sizeof(bmi);

    if (safe_read(start, sizeof(bmi), &bmi)) {
        if (bmi.biSize != sizeof(bmi))
            WARN("WARNING: biSize: %d != sizeof(bmi): %d", bmi.biSize, sizeof(bmi));
        switch(bmi.biBitCount) {
        case 0:
            break;
        case 1:
            /* bmiColors contains two entries */
            size += 2*sizeof(RGBQUAD);
            break;
        case 4:
            /* If bmiClrUsed is 0 then bmiColors contains 16 entries,
             * otherwise bmiColors contains the number in bmiClrUsed.
             */
            if (bmi.biClrUsed == 0)
                size += 16*sizeof(RGBQUAD);
            else
                size += bmi.biClrUsed*sizeof(RGBQUAD);
            break;
        case 8:
            /* Same as case 4, except max of 256 entries */
            if (bmi.biClrUsed == 0)
                size += 256*sizeof(RGBQUAD);
            else
                size += bmi.biClrUsed*sizeof(RGBQUAD);
            break;
        case 16:
        case 32:
            /* If biCompression is BI_RGB, then bmiColors is not used. If it is
             * BI_BITFIELDS, then it contains 3 DWORD color masks. If it's a
             * palette-based device, the color table starts immediately following
             * the 3 DWORD color masks.
             */
            if (bmi.biCompression == BI_BITFIELDS)
                size += 3*sizeof(DWORD);
            if (bmi.biClrUsed != 0)
                size += bmi.biClrUsed*sizeof(RGBQUAD);
            break;
        case 24:
            /* bmiColors is not used unless used on pallete-based devices */
            if (bmi.biClrUsed != 0)
                size += bmi.biClrUsed*sizeof(RGBQUAD);
            break;
        default:
            WARN("WARNING: biBitCount should not be %d\n", bmi.biBitCount);
            break;
        }
    }

    if (!report_memarg(ii, arg_info, start, size, NULL))
        return true;
    return true;
}

static void
handle_logfont(sysarg_iter_info_t *ii,
               byte *start, size_t size, int ordinal, uint arg_flags, LOGFONTW *safe)
{
    LOGFONTW *font = (LOGFONTW *) start;
    if (ii->arg->pre && TEST(SYSARG_WRITE, arg_flags)) {
        if (!report_memarg_type(ii, ordinal, arg_flags, start, size, "LOGFONTW",
                                DRSYS_TYPE_LOGFONTW, NULL))
            return;
    } else {
        size_t check_sz;
        if (size == 0) {
            /* i#873: existing code passes in 0 for the size, which violates
             * the MSDN docs, yet the kernel doesn't care and still returns
             * success.  Thus we don't report as an error and we make
             * it work.
             */
            size = sizeof(LOGFONTW);
        }
        check_sz = MIN(size - offsetof(LOGFONTW, lfFaceName),
                       sizeof(font->lfFaceName));
        ASSERT(size >= offsetof(LOGFONTW, lfFaceName), "invalid size");
        if (!report_memarg_type(ii, ordinal, arg_flags, start,
                                offsetof(LOGFONTW, lfFaceName), "LOGFONTW",
                                DRSYS_TYPE_LOGFONTW, NULL))
            return;
        handle_cwstring(ii, "LOGFONTW.lfFaceName",
                        (byte *) &font->lfFaceName, check_sz, ordinal, arg_flags,
                        (safe == NULL) ? NULL : (wchar_t *)&safe->lfFaceName, true);
        if (ii->abort)
            return;
    }
}

static void
handle_nonclientmetrics(sysarg_iter_info_t *ii,
                        byte *start, size_t size_specified,
                        int ordinal, uint arg_flags, NONCLIENTMETRICSW *safe)
{
    NONCLIENTMETRICSW *ptr_arg = (NONCLIENTMETRICSW *) start;
    NONCLIENTMETRICSW *ptr_safe;
    NONCLIENTMETRICSW ptr_local;
    size_t size;
    if (safe != NULL)
        ptr_safe = safe;
    else {
        if (!safe_read(start, sizeof(ptr_local), &ptr_local)) {
            WARN("WARNING: unable to read syscall param\n");
            return;
        }
        ptr_safe = &ptr_local;
    }
    /* Turns out that despite user32!SystemParametersInfoA requiring both uiParam
     * and cbSize, it turns around and calls NtUserSystemParametersInfo w/o
     * initializing cbSize!  Plus, it passes the A size instead of the W size!
     * Ditto on SET where it keeps the A size in the temp struct cbSize.
     * So we don't check that ptr_arg->cbSize is defined for pre-write
     * and we pretty much ignore the uiParam and cbSize values except
     * post-write (kernel puts in the right size).  Crazy.
     */
    LOG(2, "NONCLIENTMETRICSW %s: sizeof(NONCLIENTMETRICSW)=%x, cbSize=%x, uiParam=%x\n",
        TEST(SYSARG_WRITE, arg_flags) ? "write" : "read",
        sizeof(NONCLIENTMETRICSW), ptr_safe->cbSize, size_specified);
    /* win7 seems to set cbSize properly, always */
    if (win_ver.version >= DR_WINDOWS_VERSION_7 ||
        (!ii->arg->pre && TEST(SYSARG_WRITE, arg_flags)))
        size = ptr_safe->cbSize;
    else {
        /* MAX to handle future additions.  I don't think older versions
         * have smaller NONCLIENTMETRICSW than anywhere we're compiling.
         */
        size = MAX(sizeof(NONCLIENTMETRICSW), size_specified);
    }

    if (ii->arg->pre && TEST(SYSARG_WRITE, arg_flags)) {
        if (!report_memarg_type(ii, ordinal, arg_flags, start, size, "NONCLIENTMETRICSW",
                                DRSYS_TYPE_NONCLIENTMETRICSW, NULL))
            return;
    } else {
        size_t offs = 0;
        size_t check_sz = MIN(size, offsetof(NONCLIENTMETRICSW, lfCaptionFont));
        if (!report_memarg_type(ii, ordinal, arg_flags, start, check_sz,
                                "NONCLIENTMETRICSW A",
                                DRSYS_TYPE_NONCLIENTMETRICSW, NULL))
            return;
        offs += check_sz;
        if (offs >= size)
            return;

        check_sz = MIN(size - offs, sizeof(LOGFONTW));
        handle_logfont(ii, (byte *) &ptr_arg->lfCaptionFont,
                       check_sz, ordinal, arg_flags, &ptr_safe->lfCaptionFont);
        if (ii->abort)
            return;
        offs += check_sz;
        if (offs >= size)
            return;

        check_sz = MIN(size - offs, offsetof(NONCLIENTMETRICSW, lfSmCaptionFont) -
                       offsetof(NONCLIENTMETRICSW, iSmCaptionWidth));
        if (!report_memarg_type(ii, ordinal, arg_flags, (byte *) &ptr_arg->iSmCaptionWidth,
                                check_sz, "NONCLIENTMETRICSW B",
                                DRSYS_TYPE_NONCLIENTMETRICSW, NULL))
            return;
        offs += check_sz;
        if (offs >= size)
            return;

        check_sz = MIN(size - offs, sizeof(LOGFONTW));
        handle_logfont(ii, (byte *) &ptr_arg->lfSmCaptionFont,
                       check_sz, ordinal, arg_flags, &ptr_safe->lfSmCaptionFont);
        if (ii->abort)
            return;
        offs += check_sz;
        if (offs >= size)
            return;

        check_sz = MIN(size - offs, offsetof(NONCLIENTMETRICSW, lfMenuFont) -
                       offsetof(NONCLIENTMETRICSW, iMenuWidth));
        if (!report_memarg_type(ii, ordinal, arg_flags, (byte *) &ptr_arg->iMenuWidth,
                                check_sz, "NONCLIENTMETRICSW B",
                                DRSYS_TYPE_NONCLIENTMETRICSW, NULL))
            return;
        offs += check_sz;
        if (offs >= size)
            return;

        check_sz = MIN(size - offs, sizeof(LOGFONTW));
        handle_logfont(ii, (byte *) &ptr_arg->lfMenuFont,
                       check_sz, ordinal, arg_flags, &ptr_safe->lfMenuFont);
        if (ii->abort)
            return;
        offs += check_sz;
        if (offs >= size)
            return;

        check_sz = MIN(size - offs, sizeof(LOGFONTW));
        handle_logfont(ii, (byte *) &ptr_arg->lfStatusFont,
                       check_sz, ordinal, arg_flags, &ptr_safe->lfStatusFont);
        if (ii->abort)
            return;
        offs += check_sz;
        if (offs >= size)
            return;

        check_sz = MIN(size - offs, sizeof(LOGFONTW));
        handle_logfont(ii, (byte *) &ptr_arg->lfMessageFont,
                       check_sz, ordinal, arg_flags, &ptr_safe->lfMessageFont);
        if (ii->abort)
            return;
        offs += check_sz;
        if (offs >= size)
            return;

        /* there is another field on Vista */
        check_sz = size - offs;
        if (!report_memarg_type(ii, ordinal, arg_flags, ((byte *)ptr_arg) + offs,
                                check_sz, "NONCLIENTMETRICSW C",
                                DRSYS_TYPE_NONCLIENTMETRICSW, NULL))
            return;
    }
}

static void
handle_iconmetrics(sysarg_iter_info_t *ii,
                   byte *start, int ordinal, uint arg_flags, ICONMETRICSW *safe)
{
    ICONMETRICSW *ptr_arg = (ICONMETRICSW *) start;
    ICONMETRICSW *ptr_safe;
    ICONMETRICSW ptr_local;
    size_t size;
    if (safe != NULL)
        ptr_safe = safe;
    else {
        if (!safe_read(start, sizeof(ptr_local), &ptr_local)) {
            WARN("WARNING: unable to read syscall param\n");
            return;
        }
        ptr_safe = &ptr_local;
    }
    size = ptr_safe->cbSize;

    if (ii->arg->pre && TEST(SYSARG_WRITE, arg_flags)) {
        if (!report_memarg_type(ii, ordinal, arg_flags, start, size, "ICONMETRICSW",
                                DRSYS_TYPE_ICONMETRICSW, NULL))
            return;
    } else {
        size_t offs = 0;
        size_t check_sz = MIN(size, offsetof(ICONMETRICSW, lfFont));
        if (!report_memarg_type(ii, ordinal, arg_flags, start, check_sz, "ICONMETRICSW A",
                                DRSYS_TYPE_ICONMETRICSW, NULL))
            return;
        offs += check_sz;
        if (offs >= size)
            return;

        check_sz = MIN(size - offs, sizeof(LOGFONTW));
        handle_logfont(ii, (byte *) &ptr_arg->lfFont,
                       check_sz, ordinal, arg_flags, &ptr_safe->lfFont);
        if (ii->abort)
            return;
        offs += check_sz;
        if (offs >= size)
            return;

        /* currently no more args, but here for forward compat */
        check_sz = size - offs;
        if (!report_memarg_type(ii, ordinal, arg_flags, ((byte *)ptr_arg) + offs,
                                check_sz, "ICONMETRICSW B",
                                DRSYS_TYPE_ICONMETRICSW, NULL))
            return;
    }
}

static void
handle_serialkeys(sysarg_iter_info_t *ii,
                  byte *start, int ordinal, uint arg_flags, SERIALKEYSW *safe)
{
    SERIALKEYSW *ptr_safe;
    SERIALKEYSW ptr_local;
    size_t size;
    if (safe != NULL)
        ptr_safe = safe;
    else {
        if (!safe_read(start, sizeof(ptr_local), &ptr_local)) {
            WARN("WARNING: unable to read syscall param\n");
            return;
        }
        ptr_safe = &ptr_local;
    }
    size = ptr_safe->cbSize;
    if (!report_memarg_type(ii, ordinal, arg_flags, start, size, "SERIALKEYSW",
                            DRSYS_TYPE_SERIALKEYSW, NULL))
        return;
    handle_cwstring(ii, "SERIALKEYSW.lpszActivePort",
                    (byte *) ptr_safe->lpszActivePort, 0, ordinal, arg_flags, NULL, true);
    if (ii->abort)
        return;
    handle_cwstring(ii, "SERIALKEYSW.lpszPort",
                    (byte *) ptr_safe->lpszPort, 0, ordinal, arg_flags, NULL, true);
}

static void
handle_cwstring_field(sysarg_iter_info_t *ii, const char *id,
                      int ordinal, uint arg_flags,
                      byte *struct_start, size_t struct_size, size_t cwstring_offs)
{
    wchar_t *ptr;
    if (struct_size <= cwstring_offs)
        return;
    if (!safe_read(struct_start + cwstring_offs, sizeof(ptr), &ptr)) {
        WARN("WARNING: unable to read syscall param\n");
        return;
    }
    handle_cwstring(ii, id, (byte *)ptr, 0, ordinal, arg_flags, NULL, true);
}

bool
wingdi_process_arg(sysarg_iter_info_t *iter_info,
                   const syscall_arg_t *arg_info, app_pc start, uint size)
{
    switch (arg_info->misc) {
    case SYSARG_TYPE_LARGE_STRING:
        return handle_large_string_access(iter_info, arg_info, start, size);
    case SYSARG_TYPE_DEVMODEW:
        return handle_devmodew_access(iter_info, arg_info, start, size);
    case SYSARG_TYPE_WNDCLASSEXW:
        return handle_wndclassexw_access(iter_info, arg_info, start, size);
    case SYSARG_TYPE_CLSMENUNAME:
        return handle_clsmenuname_access(iter_info, arg_info, start, size);
    case SYSARG_TYPE_MENUITEMINFOW:
        return handle_menuiteminfow_access(iter_info, arg_info, start, size);
    case SYSARG_TYPE_BITMAPINFO:
        return handle_bitmapinfo_access(iter_info, arg_info, start, size);
    }
    return false; /* not handled */
}

/***************************************************************************
 * CUSTOM SYSCALL HANDLING
 */

static void
handle_UserSystemParametersInfo(void *drcontext, cls_syscall_t *pt, sysarg_iter_info_t *ii)
{
    UINT uiAction = (UINT) pt->sysarg[0];
    UINT uiParam = (UINT) pt->sysarg[1];
#   define PV_PARAM_ORDINAL 2
    byte *pvParam = (byte *) pt->sysarg[PV_PARAM_ORDINAL];
    bool get = true;
    size_t sz = 0;
    bool uses_pvParam = false; /* also considered used if sz>0 */
    bool uses_uiParam = false;

    switch (uiAction) {
    case SPI_GETBEEP: get = true;  sz = sizeof(BOOL); break;
    case SPI_SETBEEP: get = false; uses_uiParam = true; break;
    case SPI_GETMOUSE: get = true;  sz = 3 * sizeof(INT); break;
    case SPI_SETMOUSE: get = false; sz = 3 * sizeof(INT); break;
    case SPI_GETBORDER: get = true;  sz = sizeof(int); break;
    case SPI_SETBORDER: get = false; uses_uiParam = true; break;
    case SPI_GETKEYBOARDSPEED: get = true;  sz = sizeof(DWORD); break;
    case SPI_SETKEYBOARDSPEED: get = false; uses_uiParam = true; break;
    case SPI_GETSCREENSAVETIMEOUT: get = true;  sz = sizeof(int); break;
    case SPI_SETSCREENSAVETIMEOUT: get = false; uses_uiParam = true; break;
    case SPI_GETSCREENSAVEACTIVE: get = true;  sz = sizeof(BOOL); break;
    case SPI_SETSCREENSAVEACTIVE: get = false; uses_uiParam = true; break;
    /* XXX: no official docs for these 2: */
    case SPI_GETGRIDGRANULARITY: get = true;  sz = sizeof(int); break;
    case SPI_SETGRIDGRANULARITY: get = false; uses_uiParam = true; break;
    case SPI_GETDESKWALLPAPER: {
        /* uiParam is size in characters */
        handle_cwstring(ii, "pvParam", pvParam, uiParam * sizeof(wchar_t),
                        PV_PARAM_ORDINAL, SYSARG_WRITE, NULL, true);
        if (ii->abort)
            return;
        get = true;
        uses_uiParam = true;
        uses_pvParam = true;
        break;
    }
    case SPI_SETDESKWALLPAPER: {
        syscall_arg_t arg = {PV_PARAM_ORDINAL, sizeof(UNICODE_STRING),
                             SYSARG_READ|SYSARG_COMPLEX_TYPE,
                             SYSARG_TYPE_UNICODE_STRING};
        handle_unicode_string_access(ii, &arg, pvParam, sizeof(UNICODE_STRING), false);
        if (ii->abort)
            return;
        get = false;
        uses_pvParam = true;
        break;
    }
    case SPI_SETDESKPATTERN: get = false; break;
    case SPI_GETKEYBOARDDELAY: get = true;  sz = sizeof(int); break;
    case SPI_SETKEYBOARDDELAY: get = false; uses_uiParam = true; break;
    case SPI_ICONHORIZONTALSPACING: {
        if (pvParam != NULL) {
            get = true; 
            sz = sizeof(int);
        } else {
            get = false; 
            uses_uiParam = true;
        }
        break;
    }
    case SPI_ICONVERTICALSPACING: {
        if (pvParam != NULL) {
            get = true; 
            sz = sizeof(int);
        } else {
            get = false; 
            uses_uiParam = true;
        }
        break;
    }
    case SPI_GETICONTITLEWRAP: get = true;  sz = sizeof(BOOL); break;
    case SPI_SETICONTITLEWRAP: get = false; uses_uiParam = true; break;
    case SPI_GETMENUDROPALIGNMENT: get = true;  sz = sizeof(int); break;
    case SPI_SETMENUDROPALIGNMENT: get = false; uses_uiParam = true; break;
    case SPI_SETDOUBLECLKWIDTH: get = false; uses_uiParam = true; break;
    case SPI_SETDOUBLECLKHEIGHT: get = false; uses_uiParam = true; break;
    case SPI_GETICONTITLELOGFONT: {
        handle_logfont(ii, pvParam, uiParam, PV_PARAM_ORDINAL, SYSARG_WRITE, NULL);
        if (ii->abort)
            return;
        get = true;
        uses_uiParam = true;
        uses_pvParam = true;
        break;
    }
    case SPI_SETICONTITLELOGFONT: {
        handle_logfont(ii, pvParam, uiParam, PV_PARAM_ORDINAL, SYSARG_READ, NULL);
        if (ii->abort)
            return;
        get = false;
        uses_uiParam = true;
        uses_pvParam = true;
        break;
    }
    case SPI_SETDOUBLECLICKTIME: get = false; uses_uiParam = true; break;
    case SPI_SETMOUSEBUTTONSWAP: get = false; uses_uiParam = true; break;
    /* XXX: no official docs: */
    case SPI_GETFASTTASKSWITCH: get = true;  sz = sizeof(int); break;
    case SPI_GETDRAGFULLWINDOWS: get = true;  sz = sizeof(BOOL); break;
    case SPI_SETDRAGFULLWINDOWS: get = false; uses_uiParam = true; break;
    case SPI_GETNONCLIENTMETRICS: {
        handle_nonclientmetrics(ii, pvParam, uiParam, PV_PARAM_ORDINAL,
                                SYSARG_WRITE, NULL);
        if (ii->abort)
            return;
        get = true;
        uses_uiParam = true;
        uses_pvParam = true;
        break;
    }
    case SPI_SETNONCLIENTMETRICS: {
        handle_nonclientmetrics(ii, pvParam, uiParam, PV_PARAM_ORDINAL, SYSARG_READ, NULL);
        if (ii->abort)
            return;
        get = false;
        uses_uiParam = true;
        uses_pvParam = true;
        break;
    }
    case SPI_GETMINIMIZEDMETRICS: get = true;  uses_uiParam = true; sz = uiParam; break;
    case SPI_SETMINIMIZEDMETRICS: get = false; uses_uiParam = true; sz = uiParam; break;
    case SPI_GETICONMETRICS: {
        handle_iconmetrics(ii, pvParam, PV_PARAM_ORDINAL, SYSARG_WRITE, NULL);
        if (ii->abort)
            return;
        get = true;
        uses_uiParam = true;
        uses_pvParam = true;
        break;
    }
    case SPI_SETICONMETRICS: {
        handle_iconmetrics(ii, pvParam, PV_PARAM_ORDINAL, SYSARG_READ, NULL);
        if (ii->abort)
            return;
        get = false;
        uses_uiParam = true;
        uses_pvParam = true;
        break;
    }
    case SPI_GETWORKAREA: get = true;  sz = sizeof(RECT); break;
    case SPI_SETWORKAREA: get = false; sz = sizeof(RECT); break;
    case SPI_GETFILTERKEYS: get = true;  uses_uiParam = true; sz = uiParam; break;
    case SPI_SETFILTERKEYS: get = false; uses_uiParam = true; sz = uiParam; break;
    case SPI_GETTOGGLEKEYS: get = true;  uses_uiParam = true; sz = uiParam; break;
    case SPI_SETTOGGLEKEYS: get = false; uses_uiParam = true; sz = uiParam; break;
    case SPI_GETMOUSEKEYS:  get = true;  uses_uiParam = true; sz = uiParam; break;
    case SPI_SETMOUSEKEYS:  get = false; uses_uiParam = true; sz = uiParam; break;
    case SPI_GETSHOWSOUNDS: get = true;  sz = sizeof(BOOL); break;
    case SPI_SETSHOWSOUNDS: get = false; uses_uiParam = true; break;
    case SPI_GETSTICKYKEYS: get = true;  uses_uiParam = true; sz = uiParam; break;
    case SPI_SETSTICKYKEYS: get = false; uses_uiParam = true; sz = uiParam; break;
    case SPI_GETACCESSTIMEOUT: get = true;  uses_uiParam = true; sz = uiParam; break;
    case SPI_SETACCESSTIMEOUT: get = false; uses_uiParam = true; sz = uiParam; break;
    case SPI_GETSERIALKEYS: {
        handle_serialkeys(ii, pvParam, PV_PARAM_ORDINAL, SYSARG_WRITE, NULL);
        if (ii->abort)
            return;
        get = true;
        uses_uiParam = true;
        uses_pvParam = true;
        break;
    }
    case SPI_SETSERIALKEYS: {
        handle_serialkeys(ii, pvParam, PV_PARAM_ORDINAL, SYSARG_READ, NULL);
        if (ii->abort)
            return;
        get = false;
        uses_uiParam = true;
        uses_pvParam = true;
        break;
    }
    case SPI_GETSOUNDSENTRY: {
        handle_cwstring_field(ii, "SOUNDSENTRYW.lpszWindowsEffectDLL",
                              PV_PARAM_ORDINAL, SYSARG_WRITE, pvParam, uiParam,
                              offsetof(SOUNDSENTRYW, lpszWindowsEffectDLL));
        if (ii->abort)
            return;
        /* rest of struct handled through pvParam check below */
        get = true;
        uses_uiParam = true;
        sz = uiParam;
        break;
    }
    case SPI_SETSOUNDSENTRY: {
        handle_cwstring_field(ii, "SOUNDSENTRYW.lpszWindowsEffectDLL",
                              PV_PARAM_ORDINAL, SYSARG_READ, pvParam, uiParam,
                              offsetof(SOUNDSENTRYW, lpszWindowsEffectDLL));
        if (ii->abort)
            return;
        /* rest of struct handled through pvParam check below */
        get = false;
        uses_uiParam = true;
        sz = uiParam;
        break;
    }
    case SPI_GETHIGHCONTRAST: {
        handle_cwstring_field(ii, "HIGHCONTRASTW.lpszDefaultScheme",
                              PV_PARAM_ORDINAL, SYSARG_WRITE, pvParam, uiParam,
                              offsetof(HIGHCONTRASTW, lpszDefaultScheme));
        if (ii->abort)
            return;
        /* rest of struct handled through pvParam check below */
        get = true;
        uses_uiParam = true;
        sz = uiParam;
        break;
    }
    case SPI_SETHIGHCONTRAST: {
        handle_cwstring_field(ii, "HIGHCONTRASTW.lpszDefaultScheme",
                              PV_PARAM_ORDINAL, SYSARG_READ, pvParam, uiParam,
                              offsetof(HIGHCONTRASTW, lpszDefaultScheme));
        if (ii->abort)
            return;
        /* rest of struct handled through pvParam check below */
        get = false;
        uses_uiParam = true;
        sz = uiParam;
        break;
    }
    case SPI_GETKEYBOARDPREF: get = true;  sz = sizeof(BOOL); break;
    case SPI_SETKEYBOARDPREF: get = false; uses_uiParam = true; break;
    case SPI_GETSCREENREADER: get = true;  sz = sizeof(BOOL); break;
    case SPI_SETSCREENREADER: get = false; uses_uiParam = true; break;
    case SPI_GETANIMATION: get = true;  uses_uiParam = true; sz = uiParam; break;
    case SPI_SETANIMATION: get = false; uses_uiParam = true; sz = uiParam; break;
    case SPI_GETFONTSMOOTHING: get = true;  sz = sizeof(BOOL); break;
    case SPI_SETFONTSMOOTHING: get = false; uses_uiParam = true; break;
    case SPI_SETDRAGWIDTH: get = false; uses_uiParam = true; break;
    case SPI_SETDRAGHEIGHT: get = false; uses_uiParam = true; break;
    /* XXX: no official docs: */
    case SPI_SETHANDHELD: get = false; uses_uiParam = true; break;
    case SPI_GETLOWPOWERTIMEOUT: get = true;  sz = sizeof(int); break;
    case SPI_GETPOWEROFFTIMEOUT: get = true;  sz = sizeof(int); break;
    case SPI_SETLOWPOWERTIMEOUT: get = false; uses_uiParam = true; break;
    case SPI_SETPOWEROFFTIMEOUT: get = false; uses_uiParam = true; break;
    case SPI_GETLOWPOWERACTIVE: get = true;  sz = sizeof(BOOL); break;
    case SPI_GETPOWEROFFACTIVE: get = true;  sz = sizeof(BOOL); break;
    case SPI_SETLOWPOWERACTIVE: get = false; uses_uiParam = true; break;
    case SPI_SETPOWEROFFACTIVE: get = false; uses_uiParam = true; break;
    /* XXX: docs say to set uiParam=0 and pvParam=NULL; we don't check init */
    case SPI_SETCURSORS: get = false; break;
    case SPI_SETICONS: get = false; break;
    case SPI_GETDEFAULTINPUTLANG: get = true;  sz = sizeof(HKL); break;
    case SPI_SETDEFAULTINPUTLANG: get = false; sz = sizeof(HKL); break;
    case SPI_SETLANGTOGGLE: get = false; break;
    case SPI_GETMOUSETRAILS: get = true;  sz = sizeof(int); break;
    case SPI_SETMOUSETRAILS: get = false; uses_uiParam = true; break;
    case SPI_GETSNAPTODEFBUTTON: get = true;  sz = sizeof(BOOL); break;
    case SPI_SETSNAPTODEFBUTTON: get = false; uses_uiParam = true; break;
    case SPI_GETMOUSEHOVERWIDTH: get = true;  sz = sizeof(UINT); break;
    case SPI_SETMOUSEHOVERWIDTH: get = false; uses_uiParam = true; break;
    case SPI_GETMOUSEHOVERHEIGHT: get = true;  sz = sizeof(UINT); break;
    case SPI_SETMOUSEHOVERHEIGHT: get = false; uses_uiParam = true; break;
    case SPI_GETMOUSEHOVERTIME: get = true;  sz = sizeof(UINT); break;
    case SPI_SETMOUSEHOVERTIME: get = false; uses_uiParam = true; break;
    case SPI_GETWHEELSCROLLLINES: get = true;  sz = sizeof(UINT); break;
    case SPI_SETWHEELSCROLLLINES: get = false; uses_uiParam = true; break;
    case SPI_GETMENUSHOWDELAY: get = true;  sz = sizeof(DWORD); break;
    case SPI_SETMENUSHOWDELAY: get = false; uses_uiParam = true; break;
    case SPI_GETWHEELSCROLLCHARS: get = true;  sz = sizeof(UINT); break;
    case SPI_SETWHEELSCROLLCHARS: get = false; uses_uiParam = true; break;
    case SPI_GETSHOWIMEUI: get = true;  sz = sizeof(BOOL); break;
    case SPI_SETSHOWIMEUI: get = false; uses_uiParam = true; break;
    case SPI_GETMOUSESPEED: get = true;  sz = sizeof(int); break;
    case SPI_SETMOUSESPEED: get = false; uses_uiParam = true; break;
    case SPI_GETSCREENSAVERRUNNING: get = true;  sz = sizeof(BOOL); break;
    case SPI_SETSCREENSAVERRUNNING: get = false; uses_uiParam = true; break;
    case SPI_GETAUDIODESCRIPTION: get = true;  uses_uiParam = true; sz = uiParam; break;
    /* XXX: docs don't actually say to set uiParam: I'm assuming for symmetry */
    case SPI_SETAUDIODESCRIPTION: get = false; uses_uiParam = true; sz = uiParam; break;
    case SPI_GETSCREENSAVESECURE: get = true;  sz = sizeof(BOOL); break;
    case SPI_SETSCREENSAVESECURE: get = false; uses_uiParam = true; break;
    case SPI_GETHUNGAPPTIMEOUT: get = true;  sz = sizeof(int); break;
    case SPI_SETHUNGAPPTIMEOUT: get = false; uses_uiParam = true; break;
    case SPI_GETWAITTOKILLTIMEOUT: get = true;  sz = sizeof(int); break;
    case SPI_SETWAITTOKILLTIMEOUT: get = false; uses_uiParam = true; break;
    case SPI_GETWAITTOKILLSERVICETIMEOUT: get = true;  sz = sizeof(int); break;
    case SPI_SETWAITTOKILLSERVICETIMEOUT: get = false; uses_uiParam = true; break;
    case SPI_GETMOUSEDOCKTHRESHOLD: get = true;  sz = sizeof(DWORD); break;
    /* Note that many of the sets below use pvParam as either an inlined BOOL
     * or a pointer to a DWORD (why not inlined?), instead of using uiParam
     */
    case SPI_SETMOUSEDOCKTHRESHOLD: get = false; sz = sizeof(DWORD); break;
    /* XXX: docs don't say it writes to pvParam: ret val instead? */
    case SPI_GETPENDOCKTHRESHOLD: get = true;  sz = sizeof(DWORD); break;
    case SPI_SETPENDOCKTHRESHOLD: get = false; sz = sizeof(DWORD); break;
    case SPI_GETWINARRANGING: get = true;  sz = sizeof(BOOL); break;
    case SPI_SETWINARRANGING: get = false; uses_pvParam = true; break;
    /* XXX: docs don't say it writes to pvParam: ret val instead? */
    case SPI_GETMOUSEDRAGOUTTHRESHOLD: get = true;  sz = sizeof(DWORD); break;
    case SPI_SETMOUSEDRAGOUTTHRESHOLD: get = false; sz = sizeof(DWORD); break;
    /* XXX: docs don't say it writes to pvParam: ret val instead? */
    case SPI_GETPENDRAGOUTTHRESHOLD: get = true;  sz = sizeof(DWORD); break;
    case SPI_SETPENDRAGOUTTHRESHOLD: get = false; sz = sizeof(DWORD); break;
    /* XXX: docs don't say it writes to pvParam: ret val instead? */
    case SPI_GETMOUSESIDEMOVETHRESHOLD: get = true;  sz = sizeof(DWORD); break;
    case SPI_SETMOUSESIDEMOVETHRESHOLD: get = false; sz = sizeof(DWORD); break;
    /* XXX: docs don't say it writes to pvParam: ret val instead? */
    case SPI_GETPENSIDEMOVETHRESHOLD: get = true;  sz = sizeof(DWORD); break;
    case SPI_SETPENSIDEMOVETHRESHOLD: get = false; sz = sizeof(DWORD); break;
    case SPI_GETDRAGFROMMAXIMIZE: get = true;  sz = sizeof(BOOL); break;
    case SPI_SETDRAGFROMMAXIMIZE: get = false; uses_pvParam = true; break;
    case SPI_GETSNAPSIZING: get = true;  sz = sizeof(BOOL); break;
    case SPI_SETSNAPSIZING:  get = false; uses_pvParam = true; break;
    case SPI_GETDOCKMOVING: get = true;  sz = sizeof(BOOL); break;
    case SPI_SETDOCKMOVING:  get = false; uses_pvParam = true; break;
    case SPI_GETACTIVEWINDOWTRACKING: get = true;  sz = sizeof(BOOL); break;
    case SPI_SETACTIVEWINDOWTRACKING: get = false; uses_pvParam = true; break;
    case SPI_GETMENUANIMATION: get = true;  sz = sizeof(BOOL); break;
    case SPI_SETMENUANIMATION: get = false; uses_pvParam = true; break;
    case SPI_GETCOMBOBOXANIMATION: get = true;  sz = sizeof(BOOL); break;
    case SPI_SETCOMBOBOXANIMATION: get = false; uses_pvParam = true; break;
    case SPI_GETLISTBOXSMOOTHSCROLLING: get = true;  sz = sizeof(BOOL); break;
    case SPI_SETLISTBOXSMOOTHSCROLLING: get = false; uses_pvParam = true; break;
    case SPI_GETGRADIENTCAPTIONS: get = true;  sz = sizeof(BOOL); break;
    case SPI_SETGRADIENTCAPTIONS: get = false; uses_pvParam = true; break;
    case SPI_GETKEYBOARDCUES: get = true;  sz = sizeof(BOOL); break;
    case SPI_SETKEYBOARDCUES: get = false; uses_pvParam = true; break;
    case SPI_GETACTIVEWNDTRKZORDER: get = true;  sz = sizeof(BOOL); break;
    case SPI_SETACTIVEWNDTRKZORDER: get = false; uses_pvParam = true; break;
    case SPI_GETHOTTRACKING: get = true;  sz = sizeof(BOOL); break;
    case SPI_SETHOTTRACKING: get = false; uses_pvParam = true; break;
    case SPI_GETMENUFADE: get = true;  sz = sizeof(BOOL); break;
    case SPI_SETMENUFADE: get = false; uses_pvParam = true; break;
    case SPI_GETSELECTIONFADE: get = true;  sz = sizeof(BOOL); break;
    case SPI_SETSELECTIONFADE: get = false; uses_pvParam = true; break;
    case SPI_GETTOOLTIPANIMATION: get = true;  sz = sizeof(BOOL); break;
    case SPI_SETTOOLTIPANIMATION: get = false; uses_pvParam = true; break;
    case SPI_GETTOOLTIPFADE: get = true;  sz = sizeof(BOOL); break;
    case SPI_SETTOOLTIPFADE: get = false; uses_pvParam = true; break;
    case SPI_GETCURSORSHADOW: get = true;  sz = sizeof(BOOL); break;
    case SPI_SETCURSORSHADOW: get = false; uses_pvParam = true; break;
    case SPI_GETMOUSESONAR: get = true;  sz = sizeof(BOOL); break;
    case SPI_SETMOUSESONAR: get = false; uses_uiParam = true; break;
    case SPI_GETMOUSECLICKLOCK: get = true;  sz = sizeof(BOOL); break;
    case SPI_SETMOUSECLICKLOCK: get = false; uses_pvParam = true; break;
    case SPI_GETMOUSEVANISH: get = true;  sz = sizeof(BOOL); break;
    case SPI_SETMOUSEVANISH: get = false; uses_uiParam = true; break;
    case SPI_GETFLATMENU: get = true;  sz = sizeof(BOOL); break;
    case SPI_SETFLATMENU: get = false; uses_uiParam = true; break;
    case SPI_GETDROPSHADOW: get = true;  sz = sizeof(BOOL); break;
    case SPI_SETDROPSHADOW: get = false; uses_uiParam = true; break;
    case SPI_GETBLOCKSENDINPUTRESETS: get = true;  sz = sizeof(BOOL); break;
    /* yes this is uiParam in the midst of many pvParams */
    case SPI_SETBLOCKSENDINPUTRESETS: get = false; uses_uiParam = true; break;
    case SPI_GETUIEFFECTS: get = true;  sz = sizeof(BOOL); break;
    case SPI_SETUIEFFECTS: get = false; uses_pvParam = true; break;
    case SPI_GETDISABLEOVERLAPPEDCONTENT: get = true;  sz = sizeof(BOOL); break;
    case SPI_SETDISABLEOVERLAPPEDCONTENT: get = false; uses_uiParam = true; break;
    case SPI_GETCLIENTAREAANIMATION: get = true;  sz = sizeof(BOOL); break;
    case SPI_SETCLIENTAREAANIMATION: get = false; uses_uiParam = true; break;
    case SPI_GETCLEARTYPE: get = true;  sz = sizeof(BOOL); break;
    case SPI_SETCLEARTYPE: get = false; uses_uiParam = true; break;
    case SPI_GETSPEECHRECOGNITION: get = true;  sz = sizeof(BOOL); break;
    case SPI_SETSPEECHRECOGNITION: get = false; uses_uiParam = true; break;
    case SPI_GETFOREGROUNDLOCKTIMEOUT: get = true;  sz = sizeof(DWORD); break;
    case SPI_SETFOREGROUNDLOCKTIMEOUT: get = false; uses_pvParam = true; break;
    case SPI_GETACTIVEWNDTRKTIMEOUT: get = true;  sz = sizeof(DWORD); break;
    case SPI_SETACTIVEWNDTRKTIMEOUT: get = false; uses_pvParam = true; break;
    case SPI_GETFOREGROUNDFLASHCOUNT: get = true;  sz = sizeof(DWORD); break;
    case SPI_SETFOREGROUNDFLASHCOUNT: get = false; uses_pvParam = true; break;
    case SPI_GETCARETWIDTH: get = true;  sz = sizeof(DWORD); break;
    case SPI_SETCARETWIDTH: get = false; uses_pvParam = true; break;
    case SPI_GETMOUSECLICKLOCKTIME: get = true;  sz = sizeof(DWORD); break;
    /* yes this is uiParam in the midst of many pvParams */
    case SPI_SETMOUSECLICKLOCKTIME: get = false; uses_uiParam = true; break;
    case SPI_GETFONTSMOOTHINGTYPE: get = true;  sz = sizeof(UINT); break;
    case SPI_SETFONTSMOOTHINGTYPE: get = false; uses_pvParam = true; break;
    case SPI_GETFONTSMOOTHINGCONTRAST: get = true;  sz = sizeof(UINT); break;
    case SPI_SETFONTSMOOTHINGCONTRAST: get = false; uses_pvParam = true; break;
    case SPI_GETFOCUSBORDERWIDTH: get = true;  sz = sizeof(UINT); break;
    case SPI_SETFOCUSBORDERWIDTH: get = false; uses_pvParam = true; break;
    case SPI_GETFOCUSBORDERHEIGHT: get = true;  sz = sizeof(UINT); break;
    case SPI_SETFOCUSBORDERHEIGHT: get = false; uses_pvParam = true; break;
    case SPI_GETFONTSMOOTHINGORIENTATION: get = true;  sz = sizeof(UINT); break;
    case SPI_SETFONTSMOOTHINGORIENTATION: get = false; uses_pvParam = true; break;
    case SPI_GETMESSAGEDURATION: get = true;  sz = sizeof(ULONG); break;
    case SPI_SETMESSAGEDURATION: get = false; uses_pvParam = true; break;

    /* XXX: unknown behavior */
    case SPI_LANGDRIVER:
    case SPI_SETFASTTASKSWITCH:
    case SPI_SETPENWINDOWS:
    case SPI_GETWINDOWSEXTENSION:
    default:
        WARN("WARNING: unhandled UserSystemParametersInfo uiAction 0x%x\n",
             uiAction);
    }

    /* table entry only checked uiAction for definedness */
    if (uses_uiParam && ii->arg->pre) {
        if (!report_sysarg(ii, 1, SYSARG_READ))
            return;
    }
    if (sz > 0 || uses_pvParam) { /* pvParam is used */
        if (ii->arg->pre) {
            if (!report_sysarg(ii, 2, get ? SYSARG_WRITE : SYSARG_READ))
                return;
        }
        if (get && sz > 0) {
            if (!report_memarg_type(ii, PV_PARAM_ORDINAL, SYSARG_WRITE,
                                    pvParam, sz, "pvParam",
                                    sz == sizeof(int) ? DRSYS_TYPE_INT :
                                    DRSYS_TYPE_STRUCT, NULL))
                return;
        } else if (ii->arg->pre && sz > 0) {
            if (!report_memarg_type(ii, PV_PARAM_ORDINAL, SYSARG_READ, pvParam, sz,
                                    "pvParam", sz == sizeof(int) ? DRSYS_TYPE_INT :
                                    DRSYS_TYPE_STRUCT, NULL))
                return;
        }
    }
    if (!get && ii->arg->pre) /* fWinIni used for all SET codes */
        report_sysarg(ii, 3, SYSARG_READ);
}

static void
handle_UserMenuInfo(void *drcontext, cls_syscall_t *pt, sysarg_iter_info_t *ii)
{
    /* 3rd param is bool saying whether it's Set or Get */
    BOOL set = (BOOL) pt->sysarg[3];
    MENUINFO info;
    /* user must set cbSize for set or get */
    if (ii->arg->pre) {
        if (!report_memarg_type(ii, 1, SYSARG_READ, (byte *) pt->sysarg[1],
                                sizeof(info.cbSize), "MENUINFOW.cbSize",
                                DRSYS_TYPE_INT, NULL))
            return;
    }
    if (ii->arg->pre || !set) {
        if (safe_read((byte *) pt->sysarg[3], sizeof(info), &info)) {
            if (!report_memarg_type(ii, 3, set ? SYSARG_READ : SYSARG_WRITE,
                                    (byte *) pt->sysarg[3], info.cbSize, "MENUINFOW",
                                    DRSYS_TYPE_STRUCT, NULL))
                return;
        } else
            WARN("WARNING: unable to read syscall param\n");
    }
}

static void
handle_UserMenuItemInfo(void *drcontext, cls_syscall_t *pt, sysarg_iter_info_t *ii)
{
    /* 4th param is bool saying whether it's Set or Get */
    BOOL set = (BOOL) pt->sysarg[4];
    syscall_arg_t arg = {3, 0,
                         (set ? SYSARG_READ : SYSARG_WRITE)|SYSARG_COMPLEX_TYPE,
                         SYSARG_TYPE_MENUITEMINFOW};
    handle_menuiteminfow_access(ii, &arg, (byte *) pt->sysarg[3], 0);
}

static void
handle_UserGetAltTabInfo(void *drcontext, cls_syscall_t *pt, sysarg_iter_info_t *ii)
{
    /* buffer is ansi or unicode depending on arg 5; size (arg 4) is in chars */
    BOOL ansi = (BOOL) pt->sysarg[5];
    UINT count = (UINT) pt->sysarg[4];
    report_memarg_type(ii, 3, SYSARG_WRITE, (byte *) pt->sysarg[3],
                       count * (ansi ? sizeof(char) : sizeof(wchar_t)),
                       "pszItemText", ansi ? DRSYS_TYPE_CARRAY : DRSYS_TYPE_CWARRAY, NULL);
}

static void
handle_UserGetRawInputBuffer(void *drcontext, cls_syscall_t *pt, sysarg_iter_info_t *ii)
{
    byte *buf = (byte *) pt->sysarg[0];
    UINT size;
    if (buf == NULL) {
        /* writes out total buffer size needed in bytes to param #1 */
        if (!report_memarg_type(ii, 1, SYSARG_WRITE, (byte *) pt->sysarg[1],
                                sizeof(UINT), "pcbSize", DRSYS_TYPE_INT, NULL))
            return;
    } else {
        if (ii->arg->pre) {
            /* FIXME i#485: we don't know the number of array entries so we
             * can't check addressability pre-syscall: comes from a prior
             * buf==NULL call
             */
        } else if (safe_read((byte *) pt->sysarg[1], sizeof(size), &size)) {
            /* param #1 holds size of each RAWINPUT array entry */
            size = (size * dr_syscall_get_result(drcontext)) +
                /* param #2 holds header size */
                (UINT) pt->sysarg[2];
            if (!report_memarg_type(ii, 0, SYSARG_WRITE, buf, size, "pData",
                                    DRSYS_TYPE_STRUCT, NULL))
                return;
        } else
            WARN("WARNING: unable to read syscall param\n");
    }
}

static void
handle_UserGetRawInputData(void *drcontext, cls_syscall_t *pt, sysarg_iter_info_t *ii)
{
    byte *buf = (byte *) pt->sysarg[2];
    /* arg #3 is either R or W.  when W buf must be NULL and the 2,-3,WI entry
     * will do a safe_read but won't do a check so no false pos.
     */
    if (buf == NULL || ii->arg->pre) {
        uint flags = ((buf == NULL) ? SYSARG_WRITE : SYSARG_READ);
        report_memarg_type(ii, 3, flags, (byte *) pt->sysarg[3], sizeof(UINT),
                           "pcbSize", DRSYS_TYPE_INT, NULL);
    }
}

static void
handle_UserGetRawInputDeviceInfo(void *drcontext, cls_syscall_t *pt,
                                 sysarg_iter_info_t *ii)
{
    UINT uiCommand = (UINT) pt->sysarg[1];
    UINT size;
    if (safe_read((byte *) pt->sysarg[3], sizeof(size), &size)) {
        /* for uiCommand == RIDI_DEVICEINFO we assume pcbSize (3rd param)
         * will be set and we don't bother to check RID_DEVICE_INFO.cbSize
         */
        if (uiCommand == RIDI_DEVICENAME) {
            /* output is a string and size is in chars
             * XXX: I'm assuming a wide string!
             */
            size *= sizeof(wchar_t);
        }
        if (!report_memarg_type(ii, 2, SYSARG_WRITE, (byte *) pt->sysarg[2], size,
                                "pData", DRSYS_TYPE_STRUCT, NULL))
            return;
        if (pt->sysarg[2] == 0) {
            /* XXX i#486: if buffer is not large enough, returns -1 but still
             * sets *pcbSize
             */
            if (!report_memarg_type(ii, 3, SYSARG_WRITE, (byte *) pt->sysarg[3],
                                    sizeof(UINT), "pData", DRSYS_TYPE_INT, NULL))
                return;
        }
    } else
        WARN("WARNING: unable to read syscall param\n");
}

static void
handle_UserTrackMouseEvent(void *drcontext, cls_syscall_t *pt, sysarg_iter_info_t *ii)
{
    DWORD dwFlags = (BOOL) pt->sysarg[3];
    TRACKMOUSEEVENT *safe;
    byte buf[offsetof(TRACKMOUSEEVENT, dwFlags) + sizeof(safe->dwFlags)];
    /* user must set cbSize and dwFlags */
    if (ii->arg->pre) {
        if (!report_memarg_type(ii, 0, SYSARG_READ, (byte *) pt->sysarg[0],
                                offsetof(TRACKMOUSEEVENT, dwFlags) + sizeof(safe->dwFlags),
                                "TRACKMOUSEEVENT cbSize+dwFlags",
                                DRSYS_TYPE_STRUCT, NULL))
            return;
    }
    if (safe_read((byte *) pt->sysarg[0], BUFFER_SIZE_BYTES(buf), buf)) {
        uint flags;
        safe = (TRACKMOUSEEVENT *) buf;
        /* XXX: for non-TME_QUERY are the other fields read? */
        flags = TEST(TME_QUERY, safe->dwFlags) ? SYSARG_WRITE : SYSARG_READ;
        if ((flags == SYSARG_WRITE || ii->arg->pre) &&
            safe->cbSize > BUFFER_SIZE_BYTES(buf)) {
            if (!report_memarg_type(ii, 0, flags,
                                    ((byte *)pt->sysarg[0]) + BUFFER_SIZE_BYTES(buf),
                                    safe->cbSize - BUFFER_SIZE_BYTES(buf),
                                    "TRACKMOUSEEVENT post-dwFlags",
                                    DRSYS_TYPE_STRUCT, NULL))
                return;
        }
    } else
        WARN("WARNING: unable to read syscall param\n");
}

static void
handle_UserMessageCall(void *drcontext, cls_syscall_t *pt, sysarg_iter_info_t *ii)
{
    /* i#1249: behavior depends on both 2nd param (WM_* and other message codes)
     * and 6th param (major action requested: FNID_* codes).
     * See comments in table: if enough of these turn out to be different we
     * might want a secondary table(s) instead.
     */
#   define ORD_WPARAM 2
#   define ORD_LPARAM 3
#   define ORD_RESULT 4
    UINT msg = (DWORD) pt->sysarg[1];
    WPARAM wparam = (WPARAM) pt->sysarg[ORD_WPARAM];
    LPARAM lparam = (LPARAM) pt->sysarg[ORD_LPARAM];
    ULONG_PTR result = (ULONG_PTR) pt->sysarg[ORD_RESULT];
    DWORD type = (DWORD) pt->sysarg[5];
    BOOL ansi = (BOOL) pt->sysarg[6];
    bool result_written = true;

    /* First, handle result param: whether read or written */
    if (type == FNID_SENDMESSAGECALLBACK ||
        type == FNID_SENDMESSAGEFF ||
        type == FNID_SENDMESSAGEWTOOPTION)
        result_written = false;
    if (!report_memarg_type(ii, ORD_RESULT, result_written ? SYSARG_WRITE : SYSARG_READ,
                            (byte *) result, sizeof(result), "ResultInfo",
                            DRSYS_TYPE_UNSIGNED_INT, "ULONG_PTR"))
        return;

    /* Now handle memory params in the msg code.  We assume all FNID_* take in
     * codes in the same namespace and that we can ignore "type" here.
     * Some will fail on these codes (e.g., FNID_SCROLLBAR won't accept WM_GETTEXT)
     * but we'll live with doing the wrong unaddr check pre-syscall for that.
     */
    switch (msg) {
    case WM_COPYDATA: {
        COPYDATASTRUCT safe;
        if (!report_memarg_type(ii, ORD_LPARAM, SYSARG_READ,
                                (byte *) lparam, sizeof(COPYDATASTRUCT),
                                "WM_COPYDATA", DRSYS_TYPE_STRUCT, "COPYDATASTRUCT"))
            return;
        if (safe_read((byte *) lparam, sizeof(safe), &safe) &&
            !report_memarg_type(ii, ORD_LPARAM, SYSARG_READ,
                                (byte *) safe.lpData, safe.cbData,
                                "COPYDATASTRUCT.lpData", DRSYS_TYPE_VOID, NULL))
            return;
      break;
    }
    /* XXX: I'm assuming WM_CREATE and WM_NCCREATE are only passed from the
     * kernel to the app and never the other way so I'm not handling here
     * (CREATESTRUCT is complex to handle).
     */
    case WM_GETMINMAXINFO: {
        if (!report_memarg_type(ii, ORD_LPARAM, SYSARG_READ|SYSARG_WRITE,
                                (byte *) lparam, sizeof(MINMAXINFO),
                                "WM_GETMINMAXINFO", DRSYS_TYPE_STRUCT, "MINMAXINFO"))
            return;
        break;
    }
    case WM_GETTEXT: {
        if (ansi) {
            handle_cstring(ii, ORD_LPARAM, SYSARG_WRITE, "WM_GETTEXT buffer",
                           (byte *) lparam, wparam, NULL, true);
        } else {
            handle_cwstring(ii, "WM_GETTEXT buffer", (byte *) lparam,
                            wparam*sizeof(wchar_t), ORD_LPARAM, SYSARG_WRITE, NULL, true);
        }
        if (ii->abort)
            return;
        break;
    }
    case WM_SETTEXT: {
        if (ansi) {
            handle_cstring(ii, ORD_LPARAM, SYSARG_READ, "WM_SETTEXT string",
                           (byte *) lparam, 0, NULL, true);
        } else {
            handle_cwstring(ii, "WM_GETTEXT string", (byte *) lparam, 0,
                            ORD_LPARAM, SYSARG_READ, NULL, true);
        }
        if (ii->abort)
            return;
        break;
    }
    case WM_NCCALCSIZE: {
        BOOL complex = (BOOL) wparam;
        if (complex) {
            NCCALCSIZE_PARAMS safe;
            if (!report_memarg_type(ii, ORD_LPARAM, SYSARG_READ|SYSARG_WRITE,
                                    (byte *) lparam, sizeof(NCCALCSIZE_PARAMS),
                                    "WM_NCCALCSIZE", DRSYS_TYPE_STRUCT,
                                    "NCCALCSIZE_PARAMS"))
                return;
            if (safe_read((byte *) lparam, sizeof(safe), &safe) &&
                !report_memarg_type(ii, ORD_LPARAM, SYSARG_WRITE,
                                    (byte *) safe.lppos, sizeof(WINDOWPOS),
                                    "NCCALCSIZE_PARAMS.lppos", DRSYS_TYPE_STRUCT,
                                    "WINDOWPOS"))
                return;
        } else {
            if (!report_memarg_type(ii, ORD_LPARAM, SYSARG_READ|SYSARG_WRITE,
                                    (byte *) lparam, sizeof(RECT),
                                    "WM_NCCALCSIZE", DRSYS_TYPE_STRUCT, "RECT"))
                return;
        }
        break;
    }
    case WM_STYLECHANGED: {
        if (!report_memarg_type(ii, ORD_LPARAM, SYSARG_READ,
                                (byte *) lparam, sizeof(STYLESTRUCT),
                                "WM_STYLECHANGED", DRSYS_TYPE_STRUCT, "STYLESTRUCT"))
            return;
        break;
    }
    case WM_STYLECHANGING: {
        /* XXX: only some fields are written */
        if (!report_memarg_type(ii, ORD_LPARAM, SYSARG_READ|SYSARG_WRITE,
                                (byte *) lparam, sizeof(STYLESTRUCT),
                                "WM_STYLECHANGING", DRSYS_TYPE_STRUCT, "STYLESTRUCT"))
            return;
        break;
    }
    case WM_WINDOWPOSCHANGED: {
        if (!report_memarg_type(ii, ORD_LPARAM, SYSARG_READ,
                                (byte *) lparam, sizeof(WINDOWPOS),
                                "WM_WINDOWPOSCHANGED", DRSYS_TYPE_STRUCT, "WINDOWPOS"))
            return;
        break;
    }
    case WM_WINDOWPOSCHANGING: {
        /* XXX: only some fields are written */
        if (!report_memarg_type(ii, ORD_LPARAM, SYSARG_READ|SYSARG_WRITE,
                                (byte *) lparam, sizeof(WINDOWPOS),
                                "WM_WINDOWPOSCHANGING", DRSYS_TYPE_STRUCT, "WINDOWPOS"))
            return;
        break;
    }
    }
#   undef ORD_WPARAM
#   undef ORD_LPARAM
#   undef ORD_RESULT
}

static void
handle_accel_array(void *drcontext, cls_syscall_t *pt, sysarg_iter_info_t *ii,
                   ACCEL *array, ULONG count, uint arg_flags)
{
    ULONG i;
    /* first field is BYTE followed by WORD so we have padding to skip */
    for (i = 0; i < count; i++) {
        if (!report_memarg_ex(ii, 0, mode_from_flags(arg_flags),
                              (byte *) &array[i].fVirt, sizeof(array[i].fVirt),
                              "ACCEL.fVirt", DRSYS_TYPE_UNSIGNED_INT, NULL,
                              DRSYS_TYPE_STRUCT))
            return;
        if (!report_memarg_ex(ii, 0, mode_from_flags(arg_flags),
                              (byte *) &array[i].key, sizeof(array[i].key),
                              "ACCEL.key", DRSYS_TYPE_SIGNED_INT, NULL,
                              DRSYS_TYPE_STRUCT))
            return;
        if (!report_memarg_ex(ii, 0, mode_from_flags(arg_flags),
                              (byte *) &array[i].cmd, sizeof(array[i].cmd),
                              "ACCEL.cmd", DRSYS_TYPE_SIGNED_INT, NULL,
                              DRSYS_TYPE_STRUCT))
            return;
    }    
}

static void
handle_UserCreateAcceleratorTable(void *drcontext, cls_syscall_t *pt,
                                  sysarg_iter_info_t *ii)
{
    ACCEL *array = (ACCEL *) pt->sysarg[0];
    ULONG count = (ULONG) pt->sysarg[1];
    handle_accel_array(drcontext, pt, ii, array, count, SYSARG_READ);
}

static void
handle_UserCopyAcceleratorTable(void *drcontext, cls_syscall_t *pt,
                                sysarg_iter_info_t *ii)
{
    ACCEL *array = (ACCEL *) pt->sysarg[1];
    ULONG count = (ULONG) pt->sysarg[2];
    handle_accel_array(drcontext, pt, ii, array, count, SYSARG_WRITE);
}

static void
handle_UserSetScrollInfo(void *drcontext, cls_syscall_t *pt, sysarg_iter_info_t *ii)
{
    /* Special-cased b/c some fields are ignored (i#1299) */
    SCROLLINFO *si = (SCROLLINFO *) pt->sysarg[2];
    SCROLLINFO safe;
    if (!ii->arg->pre)
        return;
    /* User must set cbSize and fMask */
    if (!report_memarg_type(ii, 0, SYSARG_READ, (byte *) si,
                            offsetof(SCROLLINFO, fMask) + sizeof(si->fMask),
                            "SCROLLINFO cbSize+fMask",
                            DRSYS_TYPE_STRUCT, "SCROLLINFO"))
        return;
    if (safe_read((byte *) si, sizeof(safe), &safe)) {
        if (TEST(SIF_RANGE, safe.fMask) && safe.cbSize >= offsetof(SCROLLINFO, nPage)) {
            if (!report_memarg_type(ii, 0, SYSARG_READ, (byte *) &si->nMin,
                                    sizeof(si->nMin) + sizeof(si->nMax),
                                    "SCROLLINFO nMin+nMax", DRSYS_TYPE_STRUCT,
                                    "SCROLLINFO"))
                return;
        }
        if (TEST(SIF_PAGE, safe.fMask) && safe.cbSize >= offsetof(SCROLLINFO, nPos)) {
            if (!report_memarg_type(ii, 0, SYSARG_READ, (byte *) &si->nPage,
                                    sizeof(si->nPage), "SCROLLINFO.nPage",
                                    DRSYS_TYPE_STRUCT, "SCROLLINFO"))
                return;
        }
        if (TEST(SIF_POS, safe.fMask) && safe.cbSize >= offsetof(SCROLLINFO, nTrackPos)) {
            if (!report_memarg_type(ii, 0, SYSARG_READ, (byte *) &si->nPos,
                                    sizeof(si->nPos), "SCROLLINFO.nPos",
                                    DRSYS_TYPE_STRUCT, "SCROLLINFO"))
                return;
        }
        /* nTrackPos is ignored on setting, even if SIF_TRACKPOS is set */
    }
}

static void
handle_GdiHfontCreate(void *drcontext, cls_syscall_t *pt, sysarg_iter_info_t *ii)
{
    ENUMLOGFONTEXDVW dvw;
    ENUMLOGFONTEXDVW *real_dvw = (ENUMLOGFONTEXDVW *) pt->sysarg[0];
    if (ii->arg->pre && safe_read((byte *) pt->sysarg[0], sizeof(dvw), &dvw)) {
        uint i;
        byte *start = (byte *) pt->sysarg[0];
        ULONG total_size = (ULONG) pt->sysarg[1];
        /* Would be: {0,-1,R,}
         * Except not all fields need to be defined.
         * If any other syscall turns out to have this param type should
         * turn this into a type handler and not a syscall handler.
         */
        if (!report_memarg_ex(ii, 0, DRSYS_PARAM_BOUNDS, start,
                              total_size, "ENUMLOGFONTEXDVW", DRSYS_TYPE_STRUCT, NULL,
                              DRSYS_TYPE_INVALID))
            return;

        ASSERT(offsetof(ENUMLOGFONTEXDVW, elfEnumLogfontEx) == 0 &&
               offsetof(ENUMLOGFONTEXW, elfLogFont) == 0, "logfont structs changed");
        handle_logfont(ii, start, sizeof(LOGFONTW), 0, SYSARG_READ,
                       &dvw.elfEnumLogfontEx.elfLogFont);
        if (ii->abort)
            return;

        start = (byte *) &real_dvw->elfEnumLogfontEx.elfFullName;
        for (i = 0;
             i < sizeof(dvw.elfEnumLogfontEx.elfFullName)/sizeof(wchar_t) &&
                 dvw.elfEnumLogfontEx.elfFullName[i] != L'\0';
             i++)
            ; /* nothing */
        if (!report_memarg_type(ii, 0, SYSARG_READ, start, i * sizeof(wchar_t),
                                "ENUMLOGFONTEXW.elfFullName", DRSYS_TYPE_CWARRAY, NULL))
            return;

        start = (byte *) &real_dvw->elfEnumLogfontEx.elfStyle;
        for (i = 0;
             i < sizeof(dvw.elfEnumLogfontEx.elfStyle)/sizeof(wchar_t) &&
                 dvw.elfEnumLogfontEx.elfStyle[i] != L'\0';
             i++)
            ; /* nothing */
        if (!report_memarg_type(ii, 0, SYSARG_READ, start, i * sizeof(wchar_t),
                                "ENUMLOGFONTEXW.elfStyle", DRSYS_TYPE_CWARRAY, NULL))
            return;

        start = (byte *) &real_dvw->elfEnumLogfontEx.elfScript;
        for (i = 0;
             i < sizeof(dvw.elfEnumLogfontEx.elfScript)/sizeof(wchar_t) &&
                 dvw.elfEnumLogfontEx.elfScript[i] != L'\0';
             i++)
            ; /* nothing */
        if (!report_memarg_type(ii, 0, SYSARG_READ, start, i * sizeof(wchar_t),
                                "ENUMLOGFONTEXW.elfScript", DRSYS_TYPE_CWARRAY, NULL))
            return;

        /* the dvValues of DESIGNVECTOR are optional: from 0 to 64 bytes */
        start = (byte *) &real_dvw->elfDesignVector;
        if (dvw.elfDesignVector.dvNumAxes > MM_MAX_NUMAXES) {
            dvw.elfDesignVector.dvNumAxes = MM_MAX_NUMAXES;
            WARN("WARNING: NtGdiHfontCreate design vector larger than max\n");
        }
        if ((start + offsetof(DESIGNVECTOR, dvValues) +
             dvw.elfDesignVector.dvNumAxes * sizeof(LONG)) -
            (byte*) pt->sysarg[0] != total_size) {
            WARN("WARNING: NtGdiHfontCreate total size doesn't match\n");
        }
        if (!report_memarg_type(ii, 0, SYSARG_READ, start,
                                offsetof(DESIGNVECTOR, dvValues) +
                                dvw.elfDesignVector.dvNumAxes * sizeof(LONG),
                                "DESIGNVECTOR", DRSYS_TYPE_STRUCT, NULL))
            return;
    } else if (ii->arg->pre)
        WARN("WARNING: unable to read NtGdiHfontCreate param\n");
}

static void
handle_GdiDoPalette(void *drcontext, cls_syscall_t *pt, sysarg_iter_info_t *ii)
{
    /* Entry would read: {3,-2,R|SYSARG_SIZE_IN_ELEMENTS,sizeof(PALETTEENTRY)}
     * But pPalEntries is an OUT param if !bInbound.
     * It's a convenient arg: else would have to look at iFunc.
     */
    WORD cEntries = (WORD) pt->sysarg[2];
    PALETTEENTRY *pPalEntries = (PALETTEENTRY *) pt->sysarg[3];
    bool bInbound = (bool) pt->sysarg[5];
    if (bInbound && ii->arg->pre) {
        if (!report_memarg_type(ii, 3, SYSARG_READ, (byte *) pPalEntries,
                                cEntries * sizeof(PALETTEENTRY), "pPalEntries",
                                DRSYS_TYPE_STRUCT, NULL))
            return;
    } else if (!bInbound) {
        if (!report_memarg_type(ii, 3, SYSARG_WRITE, (byte *) pPalEntries,
                                cEntries * sizeof(PALETTEENTRY), "pPalEntries",
                                DRSYS_TYPE_STRUCT, NULL))
            return;
    }
}

static void
handle_GdiOpenDCW(void *drcontext, cls_syscall_t *pt, sysarg_iter_info_t *ii)
{
    /* An extra arg "BOOL bDisplay" was added as arg #4 in Vista so
     * we have to special-case the subsequent args, which for Vista+ are:
     *   {6,sizeof(DRIVER_INFO_2W),R,}, {7,sizeof(PUMDHPDEV *),W,},
     */
    uint num_driver = 5;
    uint num_pump = 6;
    if (win_ver.version >= DR_WINDOWS_VERSION_VISTA) {
        if (ii->arg->pre) {
            if (!report_sysarg(ii, 7, SYSARG_WRITE))
                return;
        }
        num_driver = 6;
        num_pump = 7;
    }
    if (ii->arg->pre) {
        if (!report_memarg_type(ii, num_driver, SYSARG_READ,
                                (byte *) pt->sysarg[num_driver], sizeof(DRIVER_INFO_2W),
                                "DRIVER_INFO_2W", DRSYS_TYPE_STRUCT, NULL))
            return;
    }
    report_memarg_type(ii, num_pump, SYSARG_WRITE, (byte *) pt->sysarg[num_pump],
                       sizeof(PUMDHPDEV *), "PUMDHPDEV*", DRSYS_TYPE_STRUCT, NULL);
}

/* Params 0 and 1 and the return type vary */
static void
handle_GdiPolyPolyDraw(void *drcontext, cls_syscall_t *pt, sysarg_iter_info_t *ii)
{
    ULONG *counts = (ULONG *) pt->sysarg[2];
    ULONG num_counts = (ULONG) pt->sysarg[3];
    int ifunc = (int) pt->sysarg[4];
    ULONG num_points = 0;
    ULONG i;
    if (ifunc == GdiPolyPolyRgn) {
        /* Param 0 == fill mode enum value:
         *   {0, sizeof(POLYFUNCTYPE), SYSARG_INLINED, DRSYS_TYPE_SIGNED_INT}
         */
        report_sysarg_type(ii, 0, SYSARG_READ, sizeof(POLYFUNCTYPE),
                           DRSYS_TYPE_SIGNED_INT, "POLYFUNCTYPE");
    } else {
        /* Param 0 == HDC:
         *   {0, sizeof(HDC), SYSARG_INLINED, DRSYS_TYPE_HANDLE}
         */
        report_sysarg_type(ii, 0, SYSARG_READ, sizeof(HDC), DRSYS_TYPE_HANDLE, "HDC");
    }
    /* The length of the POINT array has to be dynamically computed */
    for (i = 0; i < num_counts; i++) {
        ULONG count;
        if (safe_read(&counts[i], sizeof(count), &count)) {
            num_points += count;
        }
    }
    /* Param 1 == POINT*.
     * XXX: how indicate an array of structs?
     */
    report_sysarg_type(ii, 1, SYSARG_READ, sizeof(PPOINT), DRSYS_TYPE_STRUCT, "POINT");
    if (!report_memarg_type(ii, 1, SYSARG_READ,
                            (byte *) pt->sysarg[1], num_points * sizeof(POINT),
                            "PPOINT", DRSYS_TYPE_STRUCT, "POINT"))
        return;

    switch (ifunc) {
    case GdiPolyBezier:
    case GdiPolyLineTo:
    case GdiPolyBezierTo:
        if (num_counts != 1)
            WARN("WARNING: NtGdiPolyPolyDraw: expected 1 count for single polygons\n");
        break;
    case GdiPolyPolygon:
    case GdiPolyPolyLine:
    case GdiPolyPolyRgn:
        break;
    default:
        WARN("WARNING: NtGdiPolyPolyDraw: unknown ifunc %d\n", ifunc);
    }

    if (ifunc == GdiPolyPolyRgn) {
        /* Returns HRGN */
        report_sysarg_return(drcontext, ii, sizeof(HRGN), DRSYS_TYPE_HANDLE, "HRGN");
    } else {
        /* Returns BOOL */
        report_sysarg_return(drcontext, ii, sizeof(BOOL), DRSYS_TYPE_BOOL, NULL);
    }
}

void
wingdi_shadow_process_syscall(void *drcontext, cls_syscall_t *pt, sysarg_iter_info_t *ii)
{
    /* handlers here do not check for success so we check up front */
    if (!ii->arg->pre) {
        if (!os_syscall_succeeded(ii->arg->sysnum, pt->sysinfo,
                                  dr_syscall_get_result(drcontext)))
            return;
    }
    if (drsys_sysnums_equal(&ii->arg->sysnum, &sysnum_UserSystemParametersInfo)) {
        handle_UserSystemParametersInfo(drcontext, pt, ii);
    } else if (drsys_sysnums_equal(&ii->arg->sysnum, &sysnum_UserMenuInfo)) {
        handle_UserMenuInfo(drcontext, pt, ii);
    } else if (drsys_sysnums_equal(&ii->arg->sysnum, &sysnum_UserMenuItemInfo)) {
        handle_UserMenuItemInfo(drcontext, pt, ii);
    } else if (drsys_sysnums_equal(&ii->arg->sysnum, &sysnum_UserGetAltTabInfo)) {
        handle_UserGetAltTabInfo(drcontext, pt, ii);
    } else if (drsys_sysnums_equal(&ii->arg->sysnum, &sysnum_UserGetRawInputBuffer)) {
        handle_UserGetRawInputBuffer(drcontext, pt, ii);
    } else if (drsys_sysnums_equal(&ii->arg->sysnum, &sysnum_UserGetRawInputData)) {
        handle_UserGetRawInputData(drcontext, pt, ii);
    } else if (drsys_sysnums_equal(&ii->arg->sysnum, &sysnum_UserGetRawInputDeviceInfo)) {
        handle_UserGetRawInputDeviceInfo(drcontext, pt, ii);
    } else if (drsys_sysnums_equal(&ii->arg->sysnum, &sysnum_UserTrackMouseEvent)) {
        handle_UserTrackMouseEvent(drcontext, pt, ii);
    } else if (drsys_sysnums_equal(&ii->arg->sysnum, &sysnum_UserCreateWindowStation) ||
               drsys_sysnums_equal(&ii->arg->sysnum, &sysnum_UserLoadKeyboardLayoutEx)) {
        /* Vista SP1 added one arg (both were 7, now 8)
         * FIXME i#487: figure out what it is and whether we need to process it
         * for each of the two syscalls.
         * Also check whether it's defined after first deciding whether
         * we're on SP1: use core's method of checking for export?
         */
    } else if (drsys_sysnums_equal(&ii->arg->sysnum, &sysnum_UserMessageCall)) {
        handle_UserMessageCall(drcontext, pt, ii);
    } else if (drsys_sysnums_equal(&ii->arg->sysnum,
                                   &sysnum_UserCreateAcceleratorTable)) {
        handle_UserCreateAcceleratorTable(drcontext, pt, ii);
    } else if (drsys_sysnums_equal(&ii->arg->sysnum, &sysnum_UserCopyAcceleratorTable)) {
        handle_UserCopyAcceleratorTable(drcontext, pt, ii);
    } else if (drsys_sysnums_equal(&ii->arg->sysnum, &sysnum_UserSetScrollInfo)) {
        handle_UserSetScrollInfo(drcontext, pt, ii);
    } else if (drsys_sysnums_equal(&ii->arg->sysnum, &sysnum_GdiCreatePaletteInternal)) {
        /* Entry would read: {0,cEntries * 4  + 4,R,} but see comment in ntgdi.h */
        if (ii->arg->pre) {
            UINT cEntries = (UINT) pt->sysarg[1];
            report_memarg_type(ii, 1, SYSARG_READ, (byte *)pt->sysarg[0],
                               sizeof(LOGPALETTE) - sizeof(PALETTEENTRY) +
                               sizeof(PALETTEENTRY) * cEntries, "pLogPal",
                               DRSYS_TYPE_STRUCT, NULL);
        }
    } else if (drsys_sysnums_equal(&ii->arg->sysnum, &sysnum_GdiCheckBitmapBits)) {
        /* Entry would read: {7,dwWidth * dwHeight,W,} */
        DWORD dwWidth = (DWORD) pt->sysarg[4];
        DWORD dwHeight = (DWORD) pt->sysarg[5];
        report_memarg_type(ii, 7, SYSARG_WRITE, (byte *)pt->sysarg[7],
                           dwWidth * dwHeight, "paResults", DRSYS_TYPE_STRUCT, NULL);
    } else if (drsys_sysnums_equal(&ii->arg->sysnum, &sysnum_GdiHfontCreate)) {
        handle_GdiHfontCreate(drcontext, pt, ii);
    } else if (drsys_sysnums_equal(&ii->arg->sysnum, &sysnum_GdiDoPalette)) {
        handle_GdiDoPalette(drcontext, pt, ii);
    } else if (drsys_sysnums_equal(&ii->arg->sysnum, &sysnum_GdiExtTextOutW)) {
        UINT fuOptions = (UINT) pt->sysarg[3];
        int cwc = (int) pt->sysarg[6];
        INT *pdx = (INT *) pt->sysarg[7];
        if (ii->arg->pre && TEST(ETO_PDY, fuOptions)) {
            /* pdx contains pairs of INTs.  regular entry already checked
             * size of singletons of INTs so here we check the extra size.
             */
            report_memarg_type(ii, 7, SYSARG_READ, ((byte *)pdx) + cwc*sizeof(INT),
                               cwc*sizeof(INT), "pdx extra size from ETO_PDY",
                               DRSYS_TYPE_STRUCT, NULL);
        }
    } else if (drsys_sysnums_equal(&ii->arg->sysnum, &sysnum_GdiOpenDCW)) {
        handle_GdiOpenDCW(drcontext, pt, ii);
    } else if (drsys_sysnums_equal(&ii->arg->sysnum, &sysnum_GdiPolyPolyDraw)) {
        handle_GdiPolyPolyDraw(drcontext, pt, ii);
    } 
}

bool
wingdi_syscall_succeeded(drsys_sysnum_t sysnum, syscall_info_t *info, ptr_int_t res,
                         bool *success OUT)
{
    /* Custom success criteria */
    if (drsys_sysnums_equal(&sysnum, &sysnum_GdiDescribePixelFormat)) {
        *success = (res > 0);
        return true;
    } else if (drsys_sysnums_equal(&sysnum, &sysnum_GdiGetRasterizerCaps)) {
        *success = (res == 1);
        return true;
    }
    /* XXX: should all uint return types have SYSINFO_RET_ZERO_FAIL? */
    return false;
}

