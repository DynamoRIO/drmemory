/* **********************************************************
 * Copyright (c) 2011 Google, Inc.  All rights reserved.
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
#include "drmemory.h"
#include "syscall.h"
#include "syscall_os.h"
#include "readwrite.h"
#include "shadow.h"
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

#define OK (SYSINFO_ALL_PARAMS_KNOWN)
#define UNKNOWN 0
#define W (SYSARG_WRITE)
#define R (SYSARG_READ)
#define CT (SYSARG_COMPLEX_TYPE)
#define WI (SYSARG_WRITE | SYSARG_LENGTH_INOUT)
#define IB (SYSARG_INLINED_BOOLEAN)
#define RET (SYSARG_POST_SIZE_RETVAL)

/* System calls with wrappers in kernel32.dll (on win7 these are duplicated
 * in kernelbase.dll as well but w/ the same syscall number)
 * Not all wrappers are exported: xref i#388.
 */
syscall_info_t syscall_kernel32_info[] = {
    /* wchar_t *locale OUT, size_t locale_sz (assuming size in bytes) */
    {0,"NtWow64CsrBasepNlsGetUserInfo", OK, 8, {{0,-1,W|CT,SYSARG_TYPE_CSTRING_WIDE}, }},

    /* Takes a single param that's a pointer to a struct that has a PHANDLE at offset
     * 0x7c where the base of a new mmap is stored by the kernel.  We handle that by
     * waiting for RtlCreateActivationContext (i#352).  We don't know of any written
     * values in the rest of the struct or its total size so we ignore it for now and
     * use this entry to avoid "unknown syscall" warnings.
     *
     * XXX: there are 4+ wchar_t* input strings in the struct: should check them.
     */
    {0,"NtWow64CsrBasepCreateActCtx", OK, 4, },
};
#define NUM_KERNEL32_SYSCALLS \
    (sizeof(syscall_kernel32_info)/sizeof(syscall_kernel32_info[0]))

size_t
num_kernel32_syscalls(void)
{
    return NUM_KERNEL32_SYSCALLS;
}

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

static int sysnum_UserSystemParametersInfo = -1;
static int sysnum_UserMenuInfo = -1;
static int sysnum_UserMenuItemInfo = -1;
static int sysnum_UserGetAltTabInfo = -1;
static int sysnum_UserGetRawInputBuffer = -1;
static int sysnum_UserGetRawInputData = -1;
static int sysnum_UserGetRawInputDeviceInfo = -1;
static int sysnum_UserTrackMouseEvent = -1;
static int sysnum_UserCreateWindowStation = -1;
static int sysnum_UserLoadKeyboardLayoutEx = -1;
static int sysnum_UserCallTwoParam = -1;

syscall_info_t syscall_user32_info[] = {
    {0,"NtUserActivateKeyboardLayout", OK, 8, },
    {0,"NtUserAlterWindowStyle", OK, 12, },
    {0,"NtUserAssociateInputContext", OK|SYSINFO_IMM32_DLL, 12, },
    {0,"NtUserAttachThreadInput", OK, 12, },
    {0,"NtUserBeginPaint", OK|SYSINFO_RET_ZERO_FAIL, 8, {{1,sizeof(PAINTSTRUCT),W,}, }},
    {0,"NtUserBitBltSysBmp", OK, 32, },
    {0,"NtUserBlockInput", OK, 4, },
    {0,"NtUserBuildHimcList", OK|SYSINFO_IMM32_DLL, 16, {{2,-1,W|SYSARG_SIZE_IN_ELEMENTS,sizeof(HIMC)}, {3,sizeof(UINT),W}, }},
    {0,"NtUserBuildHwndList", OK, 28, {{2,0,IB,}, {5,-6,WI|SYSARG_SIZE_IN_ELEMENTS,sizeof(HWND)}, {6,sizeof(ULONG),R|W,}, }},
    {0,"NtUserBuildMenuItemList", OK, 16, {{1,-2,W,}, }},
    {0,"NtUserBuildNameList", OK, 16, {{2,-1,W,}, {2,-3,WI,}, {3,sizeof(ULONG),W,}, }},
    {0,"NtUserBuildPropList", OK, 16, {{1,-2,W,}, {1,-3,WI,}, {3,sizeof(DWORD),W,}, }},
    {0,"NtUserCalcMenuBar", OK, 20, },
    /* FIXME i#389: NtUserCall* take in a code and perform a variety of tasks */
    {0,"NtUserCallHwnd", UNKNOWN, 8, },
    {0,"NtUserCallHwndLock", UNKNOWN, 8, },
    {0,"NtUserCallHwndOpt", UNKNOWN, 8, },
    {0,"NtUserCallHwndParam", UNKNOWN, 12, },
    {0,"NtUserCallHwndParamLock", UNKNOWN, 12, },
    {0,"NtUserCallMsgFilter", UNKNOWN, 8, {{0,sizeof(MSG),R|W,}, }},
    {0,"NtUserCallNextHookEx", UNKNOWN, 16, },
    {0,"NtUserCallNoParam", UNKNOWN, 4, },
    {0,"NtUserCallOneParam", UNKNOWN, 8, },
    {0,"NtUserCallTwoParam", UNKNOWN, 12, {{0,}}, &sysnum_UserCallTwoParam},
    {0,"NtUserChangeClipboardChain", OK, 8, },
    {0,"NtUserChangeDisplaySettings", OK, 20, {{0,sizeof(UNICODE_STRING),R|CT,SYSARG_TYPE_UNICODE_STRING}, {1,sizeof(DEVMODEW)/*really var-len*/,R|CT,SYSARG_TYPE_DEVMODEW}, {4,-5,W,}, }},
    {0,"NtUserCheckDesktopByThreadId", OK, 4, },
    {0,"NtUserCheckImeHotKey", OK, 8, },
    {0,"NtUserCheckMenuItem", OK, 12, },
    {0,"NtUserCheckWindowThreadDesktop", OK, 12, },
    {0,"NtUserChildWindowFromPointEx", OK, 16, },
    {0,"NtUserClipCursor", OK, 4, {{0,sizeof(RECT),R,}, }},
    {0,"NtUserCloseClipboard", OK, 0, },
    {0,"NtUserCloseDesktop", OK, 4, },
    {0,"NtUserCloseWindowStation", OK, 4, },
    {0,"NtUserConsoleControl", OK, 12, },
    {0,"NtUserConvertMemHandle", OK, 8, },
    {0,"NtUserCopyAcceleratorTable", OK, 12, {{1,-2,W|SYSARG_SIZE_IN_ELEMENTS,sizeof(ACCEL)}, }},
    {0,"NtUserCountClipboardFormats", OK, 0, },
    {0,"NtUserCreateAcceleratorTable", OK, 8, {{0,-1,R|SYSARG_SIZE_IN_ELEMENTS,sizeof(ACCEL)}, }},
    {0,"NtUserCreateCaret", OK, 16, },
    {0,"NtUserCreateDesktop", OK, 20, {{0,sizeof(OBJECT_ATTRIBUTES),R|CT,SYSARG_TYPE_OBJECT_ATTRIBUTES}, {1,sizeof(UNICODE_STRING),R|CT,SYSARG_TYPE_UNICODE_STRING}, {2,sizeof(DEVMODEW)/*really var-len*/,R|CT,SYSARG_TYPE_DEVMODEW}, }},
    {0,"NtUserCreateInputContext", OK|SYSINFO_IMM32_DLL, 4, },
    {0,"NtUserCreateLocalMemHandle", OK, 16, {{1,-2,W}, {3,sizeof(UINT),W}, }},
    {0,"NtUserCreateWindowEx", OK, 60, {{1,sizeof(LARGE_STRING),R|CT,SYSARG_TYPE_LARGE_STRING}, {2,sizeof(LARGE_STRING),R|CT,SYSARG_TYPE_LARGE_STRING}, {3,sizeof(LARGE_STRING),R|CT,SYSARG_TYPE_LARGE_STRING}, }},
    {0,"NtUserCreateWindowStation", OK, 28, {{0,sizeof(OBJECT_ATTRIBUTES),R|CT,SYSARG_TYPE_OBJECT_ATTRIBUTES}, }, &sysnum_UserCreateWindowStation},
    {0,"NtUserCtxDisplayIOCtl", OK, 12, },
    {0,"NtUserDdeGetQualityOfService", OK, 12, {{2,sizeof(SECURITY_QUALITY_OF_SERVICE),W,}, }},
    {0,"NtUserDdeInitialize", OK, 20, },
    {0,"NtUserDdeSetQualityOfService", OK, 12, {{1,sizeof(SECURITY_QUALITY_OF_SERVICE),R,}, {2,sizeof(SECURITY_QUALITY_OF_SERVICE),W,}, }},
    {0,"NtUserDefSetText", OK, 8, {{1,sizeof(LARGE_STRING),R|CT,SYSARG_TYPE_LARGE_STRING}, }},
    {0,"NtUserDeferWindowPos", OK, 32, },
    {0,"NtUserDeleteMenu", OK, 12, },
    {0,"NtUserDestroyAcceleratorTable", OK, 4, },
    {0,"NtUserDestroyCursor", OK, 8, },
    {0,"NtUserDestroyInputContext", OK|SYSINFO_IMM32_DLL, 4, },
    {0,"NtUserDestroyMenu", OK, 4, },
    {0,"NtUserDestroyWindow", OK, 4, },
    {0,"NtUserDisableThreadIme", OK|SYSINFO_IMM32_DLL, 4, },
    {0,"NtUserDispatchMessage", OK, 4, {{0,sizeof(MSG),R,}, }},
    {0,"NtUserDragDetect", OK, 8, },
    {0,"NtUserDragObject", OK, 20, },
    {0,"NtUserDrawAnimatedRects", OK, 16, {{2,sizeof(RECT),R,}, {3,sizeof(RECT),R,}, }},
    {0,"NtUserDrawCaption", OK, 16, {{2,sizeof(RECT),R,}, }},
    {0,"NtUserDrawCaptionTemp", OK, 28, {{2,sizeof(RECT),R,}, {5,sizeof(UNICODE_STRING),R|CT,SYSARG_TYPE_UNICODE_STRING}, }},
    {0,"NtUserDrawIconEx", OK, 44, /*XXX: 10th arg is pointer?*/ },
    {0,"NtUserDrawMenuBarTemp", OK, 20, {{2,sizeof(RECT),R,}, }},
    {0,"NtUserEmptyClipboard", OK, 0, },
    {0,"NtUserEnableMenuItem", OK, 12, },
    {0,"NtUserEnableScrollBar", OK, 12, },
    {0,"NtUserEndDeferWindowPosEx", OK, 8, },
    {0,"NtUserEndMenu", OK, 0, },
    {0,"NtUserEndPaint", OK, 8, {{1,sizeof(PAINTSTRUCT),R,}, }},
    {0,"NtUserEnumDisplayDevices", OK, 16, {{0,sizeof(UNICODE_STRING),R|CT,SYSARG_TYPE_UNICODE_STRING}, {2,SYSARG_SIZE_IN_FIELD,W,offsetof(DISPLAY_DEVICEW,cb)}, }},
    {0,"NtUserEnumDisplayMonitors", OK, 20, {{1,sizeof(RECT),R,},/*experimentally this matches win32 API version so no more mem args*/ }},
    {0,"NtUserEnumDisplaySettings", OK, 16, {{0,sizeof(UNICODE_STRING),R|CT,SYSARG_TYPE_UNICODE_STRING}, {2,sizeof(DEVMODEW)/*really var-len*/,W|CT,SYSARG_TYPE_DEVMODEW}, }},
    {0,"NtUserEvent", OK, 4, },
    {0,"NtUserExcludeUpdateRgn", OK, 8, },
    {0,"NtUserFillWindow", OK, 16, },
    {0,"NtUserFindExistingCursorIcon", OK, 16, },
    {0,"NtUserFindWindowEx", OK, 20, {{2,sizeof(UNICODE_STRING),R|CT,SYSARG_TYPE_UNICODE_STRING}, {3,sizeof(UNICODE_STRING),R|CT,SYSARG_TYPE_UNICODE_STRING}, }},
    {0,"NtUserFlashWindowEx", OK, 4, {{0,SYSARG_SIZE_IN_FIELD,R,offsetof(FLASHWINFO,cbSize)}, }},
    {0,"NtUserGetAltTabInfo", OK, 24, {{2,SYSARG_SIZE_IN_FIELD,W,offsetof(ALTTABINFO,cbSize)}, /*buffer is ansi or unicode so special-cased*/}, &sysnum_UserGetAltTabInfo},
    {0,"NtUserGetAncestor", OK, 8, },
    {0,"NtUserGetAppImeLevel", OK|SYSINFO_IMM32_DLL, 4, },
    {0,"NtUserGetAsyncKeyState", OK, 4, },
    {0,"NtUserGetAtomName", OK, 8, {{1,sizeof(UNICODE_STRING),W|CT,SYSARG_TYPE_UNICODE_STRING_NOLEN/*i#490*/}, }},
    {0,"NtUserGetCPD", OK, 12, },
    {0,"NtUserGetCaretBlinkTime", OK, 0, },
    {0,"NtUserGetCaretPos", OK, 4, {{0,sizeof(POINT),W,}, }},
    {0,"NtUserGetClassInfo", OK, 20, {{1,sizeof(UNICODE_STRING),R|CT,SYSARG_TYPE_UNICODE_STRING}, {2,sizeof(WNDCLASSEXW),W|CT,SYSARG_TYPE_WNDCLASSEXW}, {3,sizeof(PWSTR)/*pointer to existing string (ansi or unicode) is copied*/,W,}, }},
    {0,"NtUserGetClassInfoEx", OK, 20, {{1,sizeof(UNICODE_STRING),R|CT,SYSARG_TYPE_UNICODE_STRING}, {2,sizeof(WNDCLASSEXW),W|CT,SYSARG_TYPE_WNDCLASSEXW}, {3,sizeof(PWSTR)/*pointer to existing string (ansi or unicode) is copied*/,W,}, }},
    {0,"NtUserGetClassLong", OK, 12, },
    {0,"NtUserGetClassName", OK, 12, {{2,sizeof(UNICODE_STRING),W|CT,SYSARG_TYPE_UNICODE_STRING_NOLEN/*i#490*/}, }},
    {0,"NtUserGetClipCursor", OK, 4, {{0,sizeof(RECT),W,}, }},
    /* FIXME i#487: exact layout of returned struct is not known */
    {0,"NtUserGetClipboardData", OK, 8, {{1,12,W,}, }},
    {0,"NtUserGetClipboardFormatName", OK, 12, {{1,sizeof(UNICODE_STRING),W|CT,SYSARG_TYPE_UNICODE_STRING}, /*3rd param is max count but should be able to ignore*/}},
    {0,"NtUserGetClipboardOwner", OK, 0, },
    {0,"NtUserGetClipboardSequenceNumber", OK, 0, },
    {0,"NtUserGetClipboardViewer", OK, 0, },
    {0,"NtUserGetComboBoxInfo", OK, 8, {{1,SYSARG_SIZE_IN_FIELD,W,offsetof(COMBOBOXINFO,cbSize)}, }},
    {0,"NtUserGetControlBrush", OK, 12, },
    {0,"NtUserGetControlColor", OK, 16, },
    {0,"NtUserGetCursorFrameInfo", OK, 16, },
    {0,"NtUserGetCursorInfo", OK, 4, {{0,SYSARG_SIZE_IN_FIELD,W,offsetof(CURSORINFO,cbSize)}, }},
    {0,"NtUserGetDC", OK|SYSINFO_RET_ZERO_FAIL, 4, },
    {0,"NtUserGetDCEx", OK|SYSINFO_RET_ZERO_FAIL, 12, },
    {0,"NtUserGetDoubleClickTime", OK, 0, },
    {0,"NtUserGetForegroundWindow", OK, 0, },
    {0,"NtUserGetGUIThreadInfo", OK, 8, {{1,SYSARG_SIZE_IN_FIELD,W,offsetof(GUITHREADINFO,cbSize)}, }},
    {0,"NtUserGetGuiResources", OK, 8, },
    {0,"NtUserGetIconInfo", OK, 24, {{1,sizeof(ICONINFO),W,}, {2,sizeof(UNICODE_STRING),W|CT,SYSARG_TYPE_UNICODE_STRING_NOLEN/*i#490*/}, {3,sizeof(UNICODE_STRING),W|CT,SYSARG_TYPE_UNICODE_STRING}, {4,sizeof(DWORD),W,}, }},
    {0,"NtUserGetIconSize", OK, 16, {{2,sizeof(LONG),W,}, {3,sizeof(LONG),W,}, }},
    {0,"NtUserGetImeHotKey", OK, 16, },
    /* FIXME i#487: 1st param is OUT but shape is unknown */
    {0,"NtUserGetImeInfoEx", UNKNOWN|SYSINFO_IMM32_DLL, 8, },
    {0,"NtUserGetInternalWindowPos", OK, 12, {{1,sizeof(RECT),W,}, {2,sizeof(POINT),W,}, }},
    {0,"NtUserGetKeyNameText", OK, 12, {{1,-2,W|SYSARG_SIZE_IN_ELEMENTS,sizeof(wchar_t)}, {1,RET,W|SYSARG_SIZE_IN_ELEMENTS,sizeof(wchar_t)}, }},
    {0,"NtUserGetKeyState", OK, 4, },
    {0,"NtUserGetKeyboardLayout", OK, 4, },
    {0,"NtUserGetKeyboardLayoutList", OK, 8, {{1,-0,W|SYSARG_SIZE_IN_ELEMENTS,sizeof(HKL)}, {1,RET,W|SYSARG_NO_WRITE_IF_COUNT_0|SYSARG_SIZE_IN_ELEMENTS,sizeof(HKL)}, }},
    {0,"NtUserGetKeyboardLayoutName", OK, 4, {{0,KL_NAMELENGTH*sizeof(wchar_t),W|CT,SYSARG_TYPE_CSTRING_WIDE}, }},
    {0,"NtUserGetKeyboardState", OK, 4, {{0,sizeof(BYTE),W,}, }},
    {0,"NtUserGetKeyboardType", OK, 4, },
    {0,"NtUserGetLastInputInfo", OK, 4, {{0,SYSARG_SIZE_IN_FIELD,W,offsetof(LASTINPUTINFO,cbSize)}, }},
    {0,"NtUserGetLayeredWindowAttributes", OK, 16, {{1,sizeof(COLORREF),W,}, {2,sizeof(BYTE),W,}, {3,sizeof(DWORD),W,}, }},
    {0,"NtUserGetListBoxInfo", OK, 4, },
    {0,"NtUserGetMenuBarInfo", OK, 16, {{3,SYSARG_SIZE_IN_FIELD,W,offsetof(MENUBARINFO,cbSize)}, }},
    {0,"NtUserGetMenuDefaultItem", OK, 12, },
    {0,"NtUserGetMenuIndex", OK, 8, },
    {0,"NtUserGetMenuItemRect", OK, 16, {{3,sizeof(RECT),W,}, }},
    {0,"NtUserGetMessage", OK, 16, {{0,sizeof(MSG),W,}, }},
    {0,"NtUserGetMinMaxInfo", OK, 12, {{1,sizeof(MINMAXINFO),W,}, }},
    {0,"NtUserGetMonitorInfo", OK, 8, {{1,SYSARG_SIZE_IN_FIELD,W,offsetof(MONITORINFO,cbSize)}, }},
    {0,"NtUserGetMouseMovePointsEx", OK, 20, {{1,-0,R,}, {2,-3,W|SYSARG_SIZE_IN_ELEMENTS,-0}, }},
    {0,"NtUserGetObjectInformation", OK|SYSINFO_RET_SMALL_WRITE_LAST, 20, {{2,-3,W}, {2,-4,WI}, {4,sizeof(DWORD),W}, }},
    {0,"NtUserGetOpenClipboardWindow", OK, 0, },
    {0,"NtUserGetPriorityClipboardFormat", OK, 8, {{0,-1,R|SYSARG_SIZE_IN_ELEMENTS,sizeof(UINT)}, }},
    {0,"NtUserGetProcessWindowStation", OK, 0, },
    {0,"NtUserGetRawInputBuffer", OK, 12, {{0,}}, /*special-cased; FIXME: i#485: see handler*/ &sysnum_UserGetRawInputBuffer},
    {0,"NtUserGetRawInputData", OK, 20, {{2,-3,WI,}, {2,RET,W}, /*arg 3 is R or W => special-cased*/ }, &sysnum_UserGetRawInputData},
    {0,"NtUserGetRawInputDeviceInfo", OK, 16, {{0,}}, &sysnum_UserGetRawInputDeviceInfo},
    {0,"NtUserGetRawInputDeviceList", OK, 12, {{0,-1,WI|SYSARG_SIZE_IN_ELEMENTS,-2}, {1,sizeof(UINT),R|W,/*really not written when #0!=NULL but harmless; ditto below and probably elsewhere in table*/}, }},
    {0,"NtUserGetRegisteredRawInputDevices", OK, 12, {{0,-1,WI|SYSARG_SIZE_IN_ELEMENTS,-2}, {1,sizeof(UINT),R|W,}, }},
    {0,"NtUserGetScrollBarInfo", OK, 12, {{2,SYSARG_SIZE_IN_FIELD,W,offsetof(SCROLLBARINFO,cbSize)}, }},
    {0,"NtUserGetSystemMenu", OK, 8, },
    /* FIXME i#487: on WOW64 XP and Vista (but not win7) this makes a 0x2xxx syscall
     * instead of invoking NtUserGetThreadDesktop: is it really different?
     */
    {0,"NtUserGetThreadDesktop", OK|SYSINFO_REQUIRES_PREFIX, 8, },
    {0,"GetThreadDesktop", OK, 8, },
    {0,"NtUserGetThreadState", OK, 4, },
    {0,"NtUserGetTitleBarInfo", OK, 8, {{1,SYSARG_SIZE_IN_FIELD,W,offsetof(TITLEBARINFO,cbSize)}, }},
    {0,"NtUserGetUpdateRect", OK, 12, {{1,sizeof(RECT),W,}, }},
    {0,"NtUserGetUpdateRgn", OK, 12, },
    {0,"NtUserGetWOWClass", OK, 8, {{1,sizeof(UNICODE_STRING),R|CT,SYSARG_TYPE_UNICODE_STRING}, }},
    {0,"NtUserGetWindowDC", OK|SYSINFO_RET_ZERO_FAIL, 4, },
    {0,"NtUserGetWindowPlacement", OK, 8, {{1,SYSARG_SIZE_IN_FIELD,W,offsetof(WINDOWPLACEMENT,length)}, }},
    {0,"NtUserHardErrorControl", OK, 12, },
    {0,"NtUserHideCaret", OK, 4, },
    {0,"NtUserHiliteMenuItem", OK, 16, },
    {0,"NtUserImpersonateDdeClientWindow", OK, 8, },
    {0,"NtUserInitTask", OK, 48, },
    {0,"NtUserInitialize", OK, 12, },
    /* FIXME i#487: not sure whether these are arrays and if so how long they are */
    {0,"NtUserInitializeClientPfnArrays", UNKNOWN, 16, {{0,sizeof(PFNCLIENT),R,}, {1,sizeof(PFNCLIENT),R,}, {2,sizeof(PFNCLIENTWORKER),R,}, }},
    {0,"NtUserInternalGetWindowText", OK, 12, {{1,-2,W|SYSARG_SIZE_IN_ELEMENTS,sizeof(wchar_t)},{1,0,W|CT,SYSARG_TYPE_CSTRING_WIDE}, }},
    {0,"NtUserInvalidateRect", OK, 12, {{1,sizeof(RECT),R,}, }},
    {0,"NtUserInvalidateRgn", OK, 12, },
    {0,"NtUserIsClipboardFormatAvailable", OK, 4, },
    {0,"NtUserKillTimer", OK, 8, },
    {0,"NtUserLoadKeyboardLayoutEx", OK, 28, {{2,sizeof(UNICODE_STRING),R|CT,SYSARG_TYPE_UNICODE_STRING}, {4,sizeof(UNICODE_STRING),R|CT,SYSARG_TYPE_UNICODE_STRING}, }, &sysnum_UserLoadKeyboardLayoutEx},
    {0,"NtUserLockWindowStation", OK, 4, },
    {0,"NtUserLockWindowUpdate", OK, 4, },
    {0,"NtUserLockWorkStation", OK, 0, },
    {0,"NtUserMNDragLeave", OK, 0, },
    {0,"NtUserMNDragOver", OK, 8, },
    {0,"NtUserMapVirtualKeyEx", OK, 16, },
    {0,"NtUserMenuInfo", OK, 12, {{0,}/*can be R or W*/}, &sysnum_UserMenuInfo },
    {0,"NtUserMenuItemFromPoint", OK, 16, },
    {0,"NtUserMenuItemInfo", OK, 20, {{0,}/*can be R or W*/}, &sysnum_UserMenuItemInfo },
    {0,"NtUserMessageCall", OK, 28, },
    {0,"NtUserMinMaximize", OK, 12, },
    {0,"NtUserModifyUserStartupInfoFlags", OK, 8, },
    {0,"NtUserMonitorFromPoint", OK, 8, },
    {0,"NtUserMonitorFromRect", OK, 8, {{0,sizeof(RECT),R,}, }},
    {0,"NtUserMonitorFromWindow", OK, 8, },
    {0,"NtUserMoveWindow", OK, 24, },
    {0,"NtUserNotifyIMEStatus", OK, 12, },
    {0,"NtUserNotifyProcessCreate", OK, 16, },
    {0,"NtUserNotifyWinEvent", OK, 16, },
    {0,"NtUserOpenClipboard", OK, 8, },
    {0,"NtUserOpenDesktop", OK, 12, {{0,sizeof(OBJECT_ATTRIBUTES),R|CT,SYSARG_TYPE_OBJECT_ATTRIBUTES}, }},
    {0,"NtUserOpenInputDesktop", OK, 12, },
    {0,"NtUserOpenWindowStation", OK, 8, {{0,sizeof(OBJECT_ATTRIBUTES),R|CT,SYSARG_TYPE_OBJECT_ATTRIBUTES}, }},
    {0,"NtUserPaintDesktop", OK, 4, },
    {0,"NtUserPaintMenuBar", OK, 24, },
    {0,"NtUserPeekMessage", OK, 20, {{0,sizeof(MSG),W,}, }},
    {0,"NtUserPostMessage", OK, 16, },
    {0,"NtUserPostThreadMessage", OK, 16, },
    {0,"NtUserPrintWindow", OK, 12, },
    /* FIXME i#487: lots of pointers inside USERCONNECT */
    {0,"NtUserProcessConnect", UNKNOWN, 12, {{1,sizeof(USERCONNECT),W,}, }},
    {0,"NtUserQueryInformationThread", OK, 20, },
    {0,"NtUserQueryInputContext", OK|SYSINFO_IMM32_DLL, 8, },
    {0,"NtUserQuerySendMessage", OK, 4, },
    {0,"NtUserQueryUserCounters", OK, 20, },
    {0,"NtUserQueryWindow", OK, 8, },
    {0,"NtUserRealChildWindowFromPoint", OK, 12, },
    {0,"NtUserRealInternalGetMessage", OK, 24, {{0,sizeof(MSG),W,}, }},
    {0,"NtUserRealWaitMessageEx", OK, 8, },
    {0,"NtUserRedrawWindow", OK, 16, {{1,sizeof(RECT),R,}, }},
    {0,"NtUserRegisterClassExWOW", OK|SYSINFO_RET_ZERO_FAIL, 28, {{0,sizeof(WNDCLASSEXW),R|CT,SYSARG_TYPE_WNDCLASSEXW}, {1,sizeof(UNICODE_STRING),R|CT,SYSARG_TYPE_UNICODE_STRING}, {2,sizeof(UNICODE_STRING),R|CT,SYSARG_TYPE_UNICODE_STRING}, {3,sizeof(CLSMENUNAME),R|CT,SYSARG_TYPE_CLSMENUNAME}, {6,sizeof(DWORD),R,}, }},
    {0,"NtUserRegisterHotKey", OK, 16, },
    {0,"NtUserRegisterRawInputDevices", OK, 12, {{0,-1,R|SYSARG_SIZE_IN_ELEMENTS,-2}, }},
    {0,"NtUserRegisterTasklist", OK, 4, },
    {0,"NtUserRegisterUserApiHook", OK, 16, {{0,sizeof(UNICODE_STRING),R|CT,SYSARG_TYPE_UNICODE_STRING}, {1,sizeof(UNICODE_STRING),R|CT,SYSARG_TYPE_UNICODE_STRING}, }},
    {0,"NtUserRegisterWindowMessage", OK, 4, {{0,sizeof(UNICODE_STRING),R|CT,SYSARG_TYPE_UNICODE_STRING}, }},
    {0,"NtUserRemoteConnect", OK, 12, },
    {0,"NtUserRemoteRedrawRectangle", OK, 16, },
    {0,"NtUserRemoteRedrawScreen", OK, 0, },
    {0,"NtUserRemoteStopScreenUpdates", OK, 0, },
    {0,"NtUserRemoveMenu", OK, 12, },
    {0,"NtUserRemoveProp", OK, 8, },
    {0,"NtUserResolveDesktop", OK, 16, },
    {0,"NtUserResolveDesktopForWOW", OK, 4, },
    /* FIXME i#487: not sure whether #2 is in or out */
    {0,"NtUserSBGetParms", OK, 16, {{2,sizeof(SBDATA),W,}, {3,SYSARG_SIZE_IN_FIELD,W,offsetof(SCROLLINFO,cbSize)}, }},
    {0,"NtUserScrollDC", OK, 28, {{3,sizeof(RECT),R,}, {4,sizeof(RECT),R,}, {6,sizeof(RECT),W,}, }},
    {0,"NtUserScrollWindowEx", OK, 32, {{3,sizeof(RECT),R,}, {4,sizeof(RECT),R,}, {6,sizeof(RECT),W,}, }},
    {0,"NtUserSelectPalette", OK, 12, },
    {0,"NtUserSendInput", OK, 12, {{1,-0,R|SYSARG_SIZE_IN_ELEMENTS,-2}, }},
    {0,"NtUserSetActiveWindow", OK, 4, },
    {0,"NtUserSetAppImeLevel", OK|SYSINFO_IMM32_DLL, 8, },
    {0,"NtUserSetCapture", OK, 4, },
    {0,"NtUserSetClassLong", OK, 16, },
    {0,"NtUserSetClassWord", OK, 12, },
    {0,"NtUserSetClipboardData", OK, 12, },
    {0,"NtUserSetClipboardViewer", OK, 4, },
    {0,"NtUserSetConsoleReserveKeys", OK, 8, },
    {0,"NtUserSetCursor", OK, 4, },
    {0,"NtUserSetCursorContents", OK, 8, {{1,sizeof(ICONINFO),R,}, }},
    {0,"NtUserSetCursorIconData", OK, 24, {{1,sizeof(BOOL),R,}, {2,sizeof(POINT),R,}, }},
    {0,"NtUserSetDbgTag", OK, 8, },
    {0,"NtUserSetFocus", OK, 4, },
    {0,"NtUserSetImeHotKey", OK, 20, },
    {0,"NtUserSetImeInfoEx", OK|SYSINFO_IMM32_DLL, 4, },
    {0,"NtUserSetImeOwnerWindow", OK, 8, },
    {0,"NtUserSetInformationProcess", OK, 16, },
    {0,"NtUserSetInformationThread", OK, 16, },
    {0,"NtUserSetInternalWindowPos", OK, 16, {{2,sizeof(RECT),R,}, {3,sizeof(POINT),R,}, }},
    {0,"NtUserSetKeyboardState", OK, 4, {{0,256*sizeof(BYTE),R,}, }},
    {0,"NtUserSetLayeredWindowAttributes", OK, 16, },
    {0,"NtUserSetLogonNotifyWindow", OK, 4, },
    {0,"NtUserSetMenu", OK, 12, },
    {0,"NtUserSetMenuContextHelpId", OK, 8, },
    {0,"NtUserSetMenuDefaultItem", OK, 12, },
    {0,"NtUserSetMenuFlagRtoL", OK, 4, },
    {0,"NtUserSetObjectInformation", OK, 16, {{2,-3,R,}, }},
    {0,"NtUserSetParent", OK, 8, },
    {0,"NtUserSetProcessWindowStation", OK, 4, },
    {0,"NtUserSetProp", OK, 12, },
    {0,"NtUserSetRipFlags", OK, 8, },
    {0,"NtUserSetScrollBarInfo", OK, 12, {{2,sizeof(SETSCROLLBARINFO),R,}, }},
    {0,"NtUserSetScrollInfo", OK, 16, {{2,SYSARG_SIZE_IN_FIELD,R,offsetof(SCROLLINFO,cbSize)}, }},
    {0,"NtUserSetShellWindowEx", OK, 8, },
    {0,"NtUserSetSysColors", OK, 16, {{1,-0,R|SYSARG_SIZE_IN_ELEMENTS,sizeof(INT)}, {2,-0,R|SYSARG_SIZE_IN_ELEMENTS,sizeof(COLORREF)}, }},
    {0,"NtUserSetSystemCursor", OK, 8, },
    {0,"NtUserSetSystemMenu", OK, 8, },
    {0,"NtUserSetSystemTimer", OK, 16, },
    {0,"NtUserSetThreadDesktop", OK, 4, },
    {0,"NtUserSetThreadLayoutHandles", OK|SYSINFO_IMM32_DLL, 8, },
    {0,"NtUserSetThreadState", OK, 8, },
    {0,"NtUserSetTimer", OK, 16, },
    {0,"NtUserSetWinEventHook", OK, 32, {{3,sizeof(UNICODE_STRING),R|CT,SYSARG_TYPE_UNICODE_STRING}, }},
    {0,"NtUserSetWindowFNID", OK, 8, },
    {0,"NtUserSetWindowLong", OK, 16, },
    {0,"NtUserSetWindowPlacement", OK, 8, {{1,SYSARG_SIZE_IN_FIELD,R,offsetof(WINDOWPLACEMENT,length)}, }},
    {0,"NtUserSetWindowPos", OK, 28, },
    {0,"NtUserSetWindowRgn", OK, 12, },
    {0,"NtUserSetWindowStationUser", OK, 16, },
    {0,"NtUserSetWindowWord", OK, 12, },
    {0,"NtUserSetWindowsHookAW", OK, 12, },
    {0,"NtUserSetWindowsHookEx", OK, 24, {{1,sizeof(UNICODE_STRING),R|CT,SYSARG_TYPE_UNICODE_STRING}, }},
    {0,"NtUserShowCaret", OK, 4, },
    {0,"NtUserShowScrollBar", OK, 12, },
    {0,"NtUserShowWindow", OK, 8, },
    {0,"NtUserShowWindowAsync", OK, 8, },
    {0,"NtUserSoundSentry", OK, 0, },
    {0,"NtUserSwitchDesktop", OK, 4, },
    {0,"NtUserSystemParametersInfo", OK, 4/*rest are optional*/, {{0,},/*special-cased*/ }, &sysnum_UserSystemParametersInfo},
    {0,"NtUserTestForInteractiveUser", OK, 4, },
    /* there is a pointer in MENUINFO but it's user-defined */
    {0,"NtUserThunkedMenuInfo", OK, 8, {{1,sizeof(MENUINFO),R,}, }},
    {0,"NtUserThunkedMenuItemInfo", OK, 24, {{4,0,R|CT,SYSARG_TYPE_MENUITEMINFOW}, {5,sizeof(UNICODE_STRING),R|CT,SYSARG_TYPE_UNICODE_STRING}, }},
    {0,"NtUserToUnicodeEx", OK, 28, {{2,0x100*sizeof(BYTE),R,}, {3,-4,W|SYSARG_SIZE_IN_ELEMENTS,sizeof(wchar_t)}, }},
    {0,"NtUserTrackMouseEvent", OK, 4, {{0,}}, &sysnum_UserTrackMouseEvent},
    {0,"NtUserTrackPopupMenuEx", OK, 24, {{5,SYSARG_SIZE_IN_FIELD,R,offsetof(TPMPARAMS,cbSize)}, }},
    {0,"NtUserTranslateAccelerator", OK, 12, {{2,sizeof(MSG),R,}, }},
    {0,"NtUserTranslateMessage", OK, 8, {{0,sizeof(MSG),R,}, }},
    {0,"NtUserUnhookWinEvent", OK, 4, },
    {0,"NtUserUnhookWindowsHookEx", OK, 4, },
    {0,"NtUserUnloadKeyboardLayout", OK, 4, },
    {0,"NtUserUnlockWindowStation", OK, 4, },
    /* FIXME i#487: CLSMENUNAME format is not fully known */
    {0,"NtUserUnregisterClass", UNKNOWN, 12, {{0,sizeof(UNICODE_STRING),R|CT,SYSARG_TYPE_UNICODE_STRING}, {2,sizeof(CLSMENUNAME),W|CT,SYSARG_TYPE_CLSMENUNAME,}, }},
    {0,"NtUserUnregisterHotKey", OK, 8, },
    {0,"NtUserUnregisterUserApiHook", OK, 0, },
    {0,"NtUserUpdateInputContext", OK, 12, },
    {0,"NtUserUpdateInstance", OK, 12, },
    {0,"NtUserUpdateLayeredWindow", OK, 40, {{2,sizeof(POINT),R,}, {3,sizeof(SIZE),R,}, {5,sizeof(POINT),R,}, {7,sizeof(BLENDFUNCTION),R,}, {9,sizeof(RECT),R,}, }},
    {0,"NtUserUpdatePerUserSystemParameters", OK, 8, },
    {0,"NtUserUserHandleGrantAccess", OK, 12, },
    {0,"NtUserValidateHandleSecure", OK, 8, },
    {0,"NtUserValidateRect", OK, 8, {{1,sizeof(RECT),R,}, }},
    {0,"NtUserValidateTimerCallback", OK, 12, },
    {0,"NtUserVkKeyScanEx", OK, 12, },
    {0,"NtUserWaitForInputIdle", OK, 12, },
    {0,"NtUserWaitForMsgAndEvent", OK, 4, },
    {0,"NtUserWaitMessage", OK, 0, },
    {0,"NtUserWin32PoolAllocationStats", OK, 24, },
    {0,"NtUserWindowFromPhysicalPoint", OK, 4, },
    {0,"NtUserWindowFromPoint", OK, 8, },
    {0,"NtUserYieldTask", OK, 0, },

    {0,"NtUserUserConnectToServer", OK, 12, {{0,0,R|CT,SYSARG_TYPE_CSTRING_WIDE}, {1,-2,WI}, {2,sizeof(ULONG),R}, }},
    {0,"NtUserGetProp", OK, 8, },

};
#define NUM_USER32_SYSCALLS \
    (sizeof(syscall_user32_info)/sizeof(syscall_user32_info[0]))

size_t
num_user32_syscalls(void)
{
    return NUM_USER32_SYSCALLS;
}

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

static int sysnum_GdiCreatePaletteInternal = -1;
static int sysnum_GdiCheckBitmapBits = -1;
static int sysnum_GdiCreateDIBSection = -1;
static int sysnum_GdiHfontCreate = -1;
static int sysnum_GdiDoPalette = -1;
static int sysnum_GdiExtTextOutW = -1;
static int sysnum_GdiOpenDCW = -1;

syscall_info_t syscall_gdi32_info[] = {
    {0,"NtGdiInit", OK, 0, },
    {0,"NtGdiSetDIBitsToDeviceInternal", OK, 64, {{9,-12,R,}, {10,sizeof(BITMAPINFO),R,}, }},
    {0,"NtGdiGetFontResourceInfoInternalW", OK, 28, {{0,-1,R|SYSARG_SIZE_IN_ELEMENTS,sizeof(wchar_t)}, {4,sizeof(DWORD),W,}, {5,-3,W,}, }},
    {0,"NtGdiGetGlyphIndicesW", OK, 20, {{1,-2,R|SYSARG_SIZE_IN_ELEMENTS,sizeof(wchar_t)}, {3,-2,W|SYSARG_SIZE_IN_ELEMENTS,sizeof(WORD)}, }},
    {0,"NtGdiGetGlyphIndicesWInternal", OK, 24, {{1,-2,R|SYSARG_SIZE_IN_ELEMENTS,sizeof(wchar_t)}, {3,sizeof(WORD),W,}, }},
    {0,"NtGdiCreatePaletteInternal", OK, 8, {{0,},}/*too complex: special-cased*/, &sysnum_GdiCreatePaletteInternal},
    {0,"NtGdiArcInternal", OK, 40, },
    {0,"NtGdiGetOutlineTextMetricsInternalW", OK, 16, {{2,-1,W,}, {3,sizeof(TMDIFF),W,}, }},
    {0,"NtGdiGetAndSetDCDword", OK, 16, {{3,sizeof(DWORD),W,}, }},
    {0,"NtGdiGetDCObject", OK, 8, },
    {0,"NtGdiGetDCforBitmap", OK, 4, },
    {0,"NtGdiGetMonitorID", OK, 12, {{2,-1,W,}, }},
    {0,"NtGdiGetLinkedUFIs", OK, 12, {{1,-2,W|SYSARG_SIZE_IN_ELEMENTS,sizeof(UNIVERSAL_FONT_ID)}, }},
    {0,"NtGdiSetLinkedUFIs", OK, 12, {{1,-2,R|SYSARG_SIZE_IN_ELEMENTS,sizeof(UNIVERSAL_FONT_ID)}, }},
    {0,"NtGdiGetUFI", OK, 24, {{1,sizeof(UNIVERSAL_FONT_ID),W,}, {2,sizeof(DESIGNVECTOR),W,}, {3,sizeof(ULONG),W,}, {4,sizeof(ULONG),W,}, {5,sizeof(FLONG),W,}, }},
    {0,"NtGdiForceUFIMapping", OK, 8, {{1,sizeof(UNIVERSAL_FONT_ID),R,}, }},
    {0,"NtGdiGetUFIPathname", OK, 40, {{0,sizeof(UNIVERSAL_FONT_ID),R,}, {1,sizeof(ULONG),W,}, {2,MAX_PATH * 3,W|SYSARG_SIZE_IN_ELEMENTS,sizeof(wchar_t)}, {2,-1,WI|SYSARG_SIZE_IN_ELEMENTS,sizeof(wchar_t)}, {3,sizeof(ULONG),W,}, {5,sizeof(BOOL),W,}, {6,sizeof(ULONG),W,}, {7,sizeof(PVOID),W,}, {8,sizeof(BOOL),W,}, {9,sizeof(ULONG),W,}, }},
    {0,"NtGdiAddRemoteFontToDC", OK, 16, {{3,sizeof(UNIVERSAL_FONT_ID),R,}, }},
    {0,"NtGdiAddFontMemResourceEx", OK, 20, {{2,-3,R,}, {4,sizeof(DWORD),W,}, }},
    {0,"NtGdiRemoveFontMemResourceEx", OK, 4, },
    {0,"NtGdiUnmapMemFont", OK, 4, },
    {0,"NtGdiRemoveMergeFont", OK, 8, {{1,sizeof(UNIVERSAL_FONT_ID),R,}, }},
    {0,"NtGdiAnyLinkedFonts", OK, 0, },
    {0,"NtGdiGetEmbUFI", OK, 28, {{1,sizeof(UNIVERSAL_FONT_ID),W,}, {2,sizeof(DESIGNVECTOR),W,}, {3,sizeof(ULONG),W,}, {4,sizeof(ULONG),W,}, {5,sizeof(FLONG),W,}, {6,sizeof(KERNEL_PVOID),W,}, }},
    {0,"NtGdiGetEmbedFonts", OK, 0, },
    {0,"NtGdiChangeGhostFont", OK, 8, {{0,sizeof(KERNEL_PVOID),R,}, }},
    {0,"NtGdiAddEmbFontToDC", OK, 8, {{1,sizeof(PVOID),R,}, }},
    {0,"NtGdiFontIsLinked", OK, 4, },
    {0,"NtGdiPolyPolyDraw", OK, 20, {{1,sizeof(POINT),R,}, {2,-3,R|SYSARG_SIZE_IN_ELEMENTS,sizeof(ULONG)}, }},
    {0,"NtGdiDoPalette", OK, 24, {{0,},},/*special-cased: R or W depending*/ &sysnum_GdiDoPalette},
    {0,"NtGdiComputeXformCoefficients", OK, 4, },
    {0,"NtGdiGetWidthTable", OK, 28, {{2,-3,R|SYSARG_SIZE_IN_ELEMENTS,sizeof(WCHAR)}, {4,-3,W|SYSARG_SIZE_IN_ELEMENTS,sizeof(USHORT)}, {5,sizeof(WIDTHDATA),W,}, {6,sizeof(FLONG),W,}, }},
    {0,"NtGdiDescribePixelFormat", OK, 16, {{3,-2,W,}, }},
    {0,"NtGdiSetPixelFormat", OK, 8, },
    {0,"NtGdiSwapBuffers", OK, 4, },
    {0,"NtGdiDxgGenericThunk", OK, 24, {{2,sizeof(SIZE_T),R|W,}, {3,sizeof(PVOID),R|W,}, {4,sizeof(SIZE_T),R|W,}, {5,sizeof(PVOID),R|W,}, }},
    {0,"NtGdiDdAddAttachedSurface", OK, 12, {{2,sizeof(DD_ADDATTACHEDSURFACEDATA),R|W,}, }},
    {0,"NtGdiDdAttachSurface", OK, 8, },
    {0,"NtGdiDdBlt", OK, 12, {{2,sizeof(DD_BLTDATA),R|W,}, }},
    {0,"NtGdiDdCanCreateSurface", OK, 8, {{1,sizeof(DD_CANCREATESURFACEDATA),R|W,}, }},
    {0,"NtGdiDdColorControl", OK, 8, {{1,sizeof(DD_COLORCONTROLDATA),R|W,}, }},
    {0,"NtGdiDdCreateDirectDrawObject", OK, 4, },
    {0,"NtGdiDdCreateSurface", OK, 32, {{1,sizeof(HANDLE),R,}, {2,sizeof(DDSURFACEDESC),R|W,}, {3,sizeof(DD_SURFACE_GLOBAL),R|W,}, {4,sizeof(DD_SURFACE_LOCAL),R|W,}, {5,sizeof(DD_SURFACE_MORE),R|W,}, {6,sizeof(DD_CREATESURFACEDATA),R|W,}, {7,sizeof(HANDLE),W,}, }},
    {0,"NtGdiDdChangeSurfacePointer", OK, 8, },
    {0,"NtGdiDdCreateSurfaceObject", OK, 24, {{2,sizeof(DD_SURFACE_LOCAL),R,}, {3,sizeof(DD_SURFACE_MORE),R,}, {4,sizeof(DD_SURFACE_GLOBAL),R,}, }},
    {0,"NtGdiDdDeleteSurfaceObject", OK, 4, },
    {0,"NtGdiDdDeleteDirectDrawObject", OK, 4, },
    {0,"NtGdiDdDestroySurface", OK, 8, },
    {0,"NtGdiDdFlip", OK, 20, {{4,sizeof(DD_FLIPDATA),R|W,}, }},
    {0,"NtGdiDdGetAvailDriverMemory", OK, 8, {{1,sizeof(DD_GETAVAILDRIVERMEMORYDATA),R|W,}, }},
    {0,"NtGdiDdGetBltStatus", OK, 8, {{1,sizeof(DD_GETBLTSTATUSDATA),R|W,}, }},
    {0,"NtGdiDdGetDC", OK, 8, {{1,sizeof(PALETTEENTRY),R,}, }},
    {0,"NtGdiDdGetDriverInfo", OK, 8, {{1,sizeof(DD_GETDRIVERINFODATA),R|W,}, }},
    {0,"NtGdiDdGetFlipStatus", OK, 8, {{1,sizeof(DD_GETFLIPSTATUSDATA),R|W,}, }},
    {0,"NtGdiDdGetScanLine", OK, 8, {{1,sizeof(DD_GETSCANLINEDATA),R|W,}, }},
    {0,"NtGdiDdSetExclusiveMode", OK, 8, {{1,sizeof(DD_SETEXCLUSIVEMODEDATA),R|W,}, }},
    {0,"NtGdiDdFlipToGDISurface", OK, 8, {{1,sizeof(DD_FLIPTOGDISURFACEDATA),R|W,}, }},
    {0,"NtGdiDdLock", OK, 12, {{1,sizeof(DD_LOCKDATA),R|W,}, }},
    {0,"NtGdiDdQueryDirectDrawObject", OK, 44, {{1,sizeof(DD_HALINFO),W,}, {2,3,W|SYSARG_SIZE_IN_ELEMENTS,sizeof(DWORD)}, {3,sizeof(D3DNTHAL_CALLBACKS),W,}, {4,sizeof(D3DNTHAL_GLOBALDRIVERDATA),W,}, {5,sizeof(DD_D3DBUFCALLBACKS),W,}, {6,sizeof(DDSURFACEDESC),W,}, {7,sizeof(DWORD),W,}, {8,sizeof(VIDEOMEMORY),W,}, {9,sizeof(DWORD),W,}, {10,sizeof(DWORD),W,}, }},
    {0,"NtGdiDdReenableDirectDrawObject", OK, 8, {{1,sizeof(BOOL),R|W,}, }},
    {0,"NtGdiDdReleaseDC", OK, 4, },
    {0,"NtGdiDdResetVisrgn", OK, 8, },
    {0,"NtGdiDdSetColorKey", OK, 8, {{1,sizeof(DD_SETCOLORKEYDATA),R|W,}, }},
    {0,"NtGdiDdSetOverlayPosition", OK, 12, {{2,sizeof(DD_SETOVERLAYPOSITIONDATA),R|W,}, }},
    {0,"NtGdiDdUnattachSurface", OK, 8, },
    {0,"NtGdiDdUnlock", OK, 8, {{1,sizeof(DD_UNLOCKDATA),R|W,}, }},
    {0,"NtGdiDdUpdateOverlay", OK, 12, {{2,sizeof(DD_UPDATEOVERLAYDATA),R|W,}, }},
    {0,"NtGdiDdWaitForVerticalBlank", OK, 8, {{1,sizeof(DD_WAITFORVERTICALBLANKDATA),R|W,}, }},
    {0,"NtGdiDdGetDxHandle", OK, 12, },
    {0,"NtGdiDdSetGammaRamp", OK, 12, },
    {0,"NtGdiDdLockD3D", OK, 8, {{1,sizeof(DD_LOCKDATA),R|W,}, }},
    {0,"NtGdiDdUnlockD3D", OK, 8, {{1,sizeof(DD_UNLOCKDATA),R|W,}, }},
    {0,"NtGdiDdCreateD3DBuffer", OK, 32, {{1,sizeof(HANDLE),R|W,}, {2,sizeof(DDSURFACEDESC),R|W,}, {3,sizeof(DD_SURFACE_GLOBAL),R|W,}, {4,sizeof(DD_SURFACE_LOCAL),R|W,}, {5,sizeof(DD_SURFACE_MORE),R|W,}, {6,sizeof(DD_CREATESURFACEDATA),R|W,}, {7,sizeof(HANDLE),R|W,}, }},
    {0,"NtGdiDdCanCreateD3DBuffer", OK, 8, {{1,sizeof(DD_CANCREATESURFACEDATA),R|W,}, }},
    {0,"NtGdiDdDestroyD3DBuffer", OK, 4, },
    {0,"NtGdiD3dContextCreate", OK, 16, {{3,sizeof(D3DNTHAL_CONTEXTCREATEI),R|W,}, }},
    {0,"NtGdiD3dContextDestroy", OK, 4, {{0,sizeof(D3DNTHAL_CONTEXTDESTROYDATA),R,}, }},
    {0,"NtGdiD3dContextDestroyAll", OK, 4, {{0,sizeof(D3DNTHAL_CONTEXTDESTROYALLDATA),W,}, }},
    {0,"NtGdiD3dValidateTextureStageState", OK, 4, {{0,sizeof(D3DNTHAL_VALIDATETEXTURESTAGESTATEDATA),R|W,}, }},
    {0,"NtGdiD3dDrawPrimitives2", OK, 28, {{2,sizeof(D3DNTHAL_DRAWPRIMITIVES2DATA),R|W,}, {3,sizeof(FLATPTR),R|W,}, {4,sizeof(DWORD),R|W,}, {5,sizeof(FLATPTR),R|W,}, {6,sizeof(DWORD),R|W,}, }},
    {0,"NtGdiDdGetDriverState", OK, 4, {{0,sizeof(DD_GETDRIVERSTATEDATA),R|W,}, }},
    {0,"NtGdiDdCreateSurfaceEx", OK, 12, },
    {0,"NtGdiDvpCanCreateVideoPort", OK, 8, {{1,sizeof(DD_CANCREATEVPORTDATA),R|W,}, }},
    {0,"NtGdiDvpColorControl", OK, 8, {{1,sizeof(DD_VPORTCOLORDATA),R|W,}, }},
    {0,"NtGdiDvpCreateVideoPort", OK, 8, {{1,sizeof(DD_CREATEVPORTDATA),R|W,}, }},
    {0,"NtGdiDvpDestroyVideoPort", OK, 8, {{1,sizeof(DD_DESTROYVPORTDATA),R|W,}, }},
    {0,"NtGdiDvpFlipVideoPort", OK, 16, {{3,sizeof(DD_FLIPVPORTDATA),R|W,}, }},
    {0,"NtGdiDvpGetVideoPortBandwidth", OK, 8, {{1,sizeof(DD_GETVPORTBANDWIDTHDATA),R|W,}, }},
    {0,"NtGdiDvpGetVideoPortField", OK, 8, {{1,sizeof(DD_GETVPORTFIELDDATA),R|W,}, }},
    {0,"NtGdiDvpGetVideoPortFlipStatus", OK, 8, {{1,sizeof(DD_GETVPORTFLIPSTATUSDATA),R|W,}, }},
    {0,"NtGdiDvpGetVideoPortInputFormats", OK, 8, {{1,sizeof(DD_GETVPORTINPUTFORMATDATA),R|W,}, }},
    {0,"NtGdiDvpGetVideoPortLine", OK, 8, {{1,sizeof(DD_GETVPORTLINEDATA),R|W,}, }},
    {0,"NtGdiDvpGetVideoPortOutputFormats", OK, 8, {{1,sizeof(DD_GETVPORTOUTPUTFORMATDATA),R|W,}, }},
    {0,"NtGdiDvpGetVideoPortConnectInfo", OK, 8, {{1,sizeof(DD_GETVPORTCONNECTDATA),R|W,}, }},
    {0,"NtGdiDvpGetVideoSignalStatus", OK, 8, {{1,sizeof(DD_GETVPORTSIGNALDATA),R|W,}, }},
    {0,"NtGdiDvpUpdateVideoPort", OK, 16, {{1,sizeof(HANDLE),R,}, {2,sizeof(HANDLE),R,}, {3,sizeof(DD_UPDATEVPORTDATA),R|W,}, }},
    {0,"NtGdiDvpWaitForVideoPortSync", OK, 8, {{1,sizeof(DD_WAITFORVPORTSYNCDATA),R|W,}, }},
    {0,"NtGdiDvpAcquireNotification", OK, 12, {{1,sizeof(HANDLE),R|W,}, {2,sizeof(DDVIDEOPORTNOTIFY),R,}, }},
    {0,"NtGdiDvpReleaseNotification", OK, 8, },
    {0,"NtGdiDdGetMoCompGuids", OK, 8, {{1,sizeof(DD_GETMOCOMPGUIDSDATA),R|W,}, }},
    {0,"NtGdiDdGetMoCompFormats", OK, 8, {{1,sizeof(DD_GETMOCOMPFORMATSDATA),R|W,}, }},
    {0,"NtGdiDdGetMoCompBuffInfo", OK, 8, {{1,sizeof(DD_GETMOCOMPCOMPBUFFDATA),R|W,}, }},
    {0,"NtGdiDdGetInternalMoCompInfo", OK, 8, {{1,sizeof(DD_GETINTERNALMOCOMPDATA),R|W,}, }},
    {0,"NtGdiDdCreateMoComp", OK, 8, {{1,sizeof(DD_CREATEMOCOMPDATA),R|W,}, }},
    {0,"NtGdiDdDestroyMoComp", OK, 8, {{1,sizeof(DD_DESTROYMOCOMPDATA),R|W,}, }},
    {0,"NtGdiDdBeginMoCompFrame", OK, 8, {{1,sizeof(DD_BEGINMOCOMPFRAMEDATA),R|W,}, }},
    {0,"NtGdiDdEndMoCompFrame", OK, 8, {{1,sizeof(DD_ENDMOCOMPFRAMEDATA),R|W,}, }},
    {0,"NtGdiDdRenderMoComp", OK, 8, {{1,sizeof(DD_RENDERMOCOMPDATA),R|W,}, }},
    {0,"NtGdiDdQueryMoCompStatus", OK, 8, {{1,sizeof(DD_QUERYMOCOMPSTATUSDATA),R|W,}, }},
    {0,"NtGdiDdAlphaBlt", OK, 12, {{2,sizeof(DD_BLTDATA),R|W,}, }},
    {0,"NtGdiAlphaBlend", OK, 48, },
    {0,"NtGdiGradientFill", OK, 24, {{1,-2,R|SYSARG_SIZE_IN_ELEMENTS,sizeof(TRIVERTEX)}, }},
    {0,"NtGdiSetIcmMode", OK, 12, },
    {0,"NtGdiCreateColorSpace", OK, 4, {{0,sizeof(LOGCOLORSPACEEXW),R,}, }},
    {0,"NtGdiDeleteColorSpace", OK, 4, },
    {0,"NtGdiSetColorSpace", OK, 8, },
    {0,"NtGdiCreateColorTransform", OK, 32, {{1,sizeof(LOGCOLORSPACEW),R,}, }},
    {0,"NtGdiDeleteColorTransform", OK, 8, },
    {0,"NtGdiCheckBitmapBits", OK, 32, {{0,}/*too complex: special-cased*/, }, &sysnum_GdiCheckBitmapBits},
    {0,"NtGdiColorCorrectPalette", OK, 24, {{4,-3,R|W|SYSARG_SIZE_IN_ELEMENTS,sizeof(PALETTEENTRY)}, }},
    {0,"NtGdiGetColorSpaceforBitmap", OK, 4, },
    {0,"NtGdiGetDeviceGammaRamp", OK, 8, {{1,256*2*3,W,}, }},
    {0,"NtGdiSetDeviceGammaRamp", OK, 8, },
    {0,"NtGdiIcmBrushInfo", OK, 32, {{2,sizeof(BITMAPINFO) + ((/*MAX_COLORTABLE*/256 - 1) * sizeof(RGBQUAD)),R|W,}, {3,-4,R|SYSARG_LENGTH_INOUT,}, {4,sizeof(ULONG),R|W,}, {5,sizeof(DWORD),W,}, {6,sizeof(BOOL),W,}, }},
    {0,"NtGdiFlush", OK, 0, },
    {0,"NtGdiCreateMetafileDC", OK, 4, },
    {0,"NtGdiMakeInfoDC", OK, 8, },
    {0,"NtGdiCreateClientObj", OK, 4, },
    {0,"NtGdiDeleteClientObj", OK, 4, },
    {0,"NtGdiGetBitmapBits", OK, 12, {{2,-1,W,}, }},
    {0,"NtGdiDeleteObjectApp", OK, 4, },
    {0,"NtGdiGetPath", OK, 16, {{1,-3,W|SYSARG_SIZE_IN_ELEMENTS,sizeof(POINT)}, {2,-3,W|SYSARG_SIZE_IN_ELEMENTS,sizeof(BYTE)}, }},
    {0,"NtGdiCreateCompatibleDC", OK, 4, },
    {0,"NtGdiCreateDIBitmapInternal", OK, 44, {{4,-8,R,}, {5,-7,R,}, }},
    {0,"NtGdiCreateDIBSection", OK|SYSINFO_RET_ZERO_FAIL, 36, {{3,-5,R,}, {8,sizeof(PVOID),W,}, }, &sysnum_GdiCreateDIBSection},
    {0,"NtGdiCreateSolidBrush", OK, 8, },
    {0,"NtGdiCreateDIBBrush", OK, 24, },
    {0,"NtGdiCreatePatternBrushInternal", OK, 12, },
    {0,"NtGdiCreateHatchBrushInternal", OK, 12, },
    {0,"NtGdiExtCreatePen", OK, 44, {{7,-6,R|SYSARG_SIZE_IN_ELEMENTS,sizeof(ULONG)}, }},
    {0,"NtGdiCreateEllipticRgn", OK, 16, },
    {0,"NtGdiCreateRoundRectRgn", OK, 24, },
    {0,"NtGdiCreateServerMetaFile", OK, 24, {{2,-1,R,}, }},
    {0,"NtGdiExtCreateRegion", OK, 12, {{0,sizeof(XFORM),R,}, {2,-1,R,}, }},
    {0,"NtGdiMakeFontDir", OK, 20, {{1,-2,W,}, {3,-4,R,}, }},
    {0,"NtGdiPolyDraw", OK, 16, {{1,-3,R|SYSARG_SIZE_IN_ELEMENTS,sizeof(POINT)}, {2,-3,R|SYSARG_SIZE_IN_ELEMENTS,sizeof(BYTE)}, }},
    {0,"NtGdiPolyTextOutW", OK, 16, {{1,-2,R|SYSARG_SIZE_IN_ELEMENTS,sizeof(POLYTEXTW)}, }},
    {0,"NtGdiGetServerMetaFileBits", OK, 28, {{2,-1,W,}, {3,sizeof(DWORD),W,}, {4,sizeof(DWORD),W,}, {5,sizeof(DWORD),W,}, {6,sizeof(DWORD),W,}, }},
    {0,"NtGdiEqualRgn", OK, 8, },
    {0,"NtGdiGetBitmapDimension", OK, 8, {{1,sizeof(SIZE),W,}, }},
    {0,"NtGdiGetNearestPaletteIndex", OK, 8, },
    {0,"NtGdiPtVisible", OK, 12, },
    {0,"NtGdiRectVisible", OK, 8, {{1,sizeof(RECT),R,}, }},
    {0,"NtGdiRemoveFontResourceW", OK, 24, {{0,-1,R|SYSARG_SIZE_IN_ELEMENTS,sizeof(WCHAR)}, {5,sizeof(DESIGNVECTOR),R,}, }},
    {0,"NtGdiResizePalette", OK, 8, },
    {0,"NtGdiSetBitmapDimension", OK, 16, {{3,sizeof(SIZE),W,}, }},
    {0,"NtGdiOffsetClipRgn", OK, 12, },
    {0,"NtGdiSetMetaRgn", OK, 4, },
    {0,"NtGdiSetTextJustification", OK, 12, },
    {0,"NtGdiGetAppClipBox", OK, 8, {{1,sizeof(RECT),W,}, }},
    {0,"NtGdiGetTextExtentExW", OK, 32, {{1,-2,R|SYSARG_SIZE_IN_ELEMENTS,sizeof(wchar_t)}, {4,sizeof(ULONG),W,}, {5,-2,W|SYSARG_SIZE_IN_ELEMENTS,sizeof(ULONG)}, {5,-4,WI|SYSARG_SIZE_IN_ELEMENTS,sizeof(ULONG)}, {6,sizeof(SIZE),W,}, }},
    {0,"NtGdiGetCharABCWidthsW", OK, 24, {{3,-2,R|SYSARG_SIZE_IN_ELEMENTS,sizeof(WCHAR)}, {5,-2,W|SYSARG_SIZE_IN_ELEMENTS,sizeof(ABC)}, }},
    {0,"NtGdiGetCharacterPlacementW", OK, 24, {{1,-2,R|SYSARG_SIZE_IN_ELEMENTS,sizeof(wchar_t)}, {4,sizeof(GCP_RESULTSW),R|W,}, }},
    {0,"NtGdiAngleArc", OK, 24, },
    {0,"NtGdiBeginPath", OK, 4, },
    {0,"NtGdiSelectClipPath", OK, 8, },
    {0,"NtGdiCloseFigure", OK, 4, },
    {0,"NtGdiEndPath", OK, 4, },
    {0,"NtGdiAbortPath", OK, 4, },
    {0,"NtGdiFillPath", OK, 4, },
    {0,"NtGdiStrokeAndFillPath", OK, 4, },
    {0,"NtGdiStrokePath", OK, 4, },
    {0,"NtGdiWidenPath", OK, 4, },
    {0,"NtGdiFlattenPath", OK, 4, },
    {0,"NtGdiPathToRegion", OK, 4, },
    {0,"NtGdiSetMiterLimit", OK, 12, {{2,sizeof(DWORD),R|W,}, }},
    {0,"NtGdiSetFontXform", OK, 12, },
    {0,"NtGdiGetMiterLimit", OK, 8, {{1,sizeof(DWORD),W,}, }},
    {0,"NtGdiEllipse", OK, 20, },
    {0,"NtGdiRectangle", OK, 20, },
    {0,"NtGdiRoundRect", OK, 28, },
    {0,"NtGdiPlgBlt", OK, 44, {{1,3,R|SYSARG_SIZE_IN_ELEMENTS,sizeof(POINT)}, }},
    {0,"NtGdiMaskBlt", OK, 52, },
    {0,"NtGdiExtFloodFill", OK, 20, },
    {0,"NtGdiFillRgn", OK, 12, },
    {0,"NtGdiFrameRgn", OK, 20, },
    {0,"NtGdiSetPixel", OK, 16, },
    {0,"NtGdiGetPixel", OK, 12, },
    {0,"NtGdiStartPage", OK, 4, },
    {0,"NtGdiEndPage", OK, 4, },
    {0,"NtGdiStartDoc", OK, 16, {{1,sizeof(DOCINFOW),R,}, {2,sizeof(BOOL),W,}, }},
    {0,"NtGdiEndDoc", OK, 4, },
    {0,"NtGdiAbortDoc", OK, 4, },
    {0,"NtGdiUpdateColors", OK, 4, },
    {0,"NtGdiGetCharWidthW", OK, 24, {{3,-2,R|SYSARG_SIZE_IN_ELEMENTS,sizeof(WCHAR)}, {5,-2,W|SYSARG_SIZE_IN_ELEMENTS,sizeof(ULONG)}, }},
    {0,"NtGdiGetCharWidthInfo", OK, 8, {{1,sizeof(CHWIDTHINFO),W,}, }},
    {0,"NtGdiDrawEscape", OK, 16, {{3,-2,R,}, }},
    {0,"NtGdiExtEscape", OK, 32, {{1,-2,R|SYSARG_SIZE_IN_ELEMENTS,sizeof(WCHAR)}, {5,-4,R,}, {7,-6,W,}, }},
    {0,"NtGdiGetFontData", OK, 20, {{3,-4,W,}, {3,RET,W,}, }},
    {0,"NtGdiGetFontFileData", OK, 20, {{2,sizeof(ULONGLONG),R,}, {3,-4,W,}, }},
    {0,"NtGdiGetFontFileInfo", OK, 20, {{2,-3,W,}, {4,sizeof(SIZE_T),W,}, }},
    {0,"NtGdiGetGlyphOutline", OK, 32, {{3,sizeof(GLYPHMETRICS),W,}, {5,-4,W,}, {6,sizeof(MAT2),R,}, }},
    {0,"NtGdiGetETM", OK, 8, {{1,sizeof(EXTTEXTMETRIC),W,}, }},
    {0,"NtGdiGetRasterizerCaps", OK, 8, {{0,-1,W,}, }},
    {0,"NtGdiGetKerningPairs", OK, 12, {{2,-1,W|SYSARG_SIZE_IN_ELEMENTS,sizeof(KERNINGPAIR)}, {2,RET,W|SYSARG_SIZE_IN_ELEMENTS,sizeof(KERNINGPAIR)}, }},
    {0,"NtGdiMonoBitmap", OK, 4, },
    {0,"NtGdiGetObjectBitmapHandle", OK, 8, {{1,sizeof(UINT),W,}, }},
    {0,"NtGdiEnumObjects", OK, 16, {{3,-2,W,}, }},
    {0,"NtGdiResetDC", OK, 20, {{1,sizeof(DEVMODEW)/*really var-len*/,R|CT,SYSARG_TYPE_DEVMODEW}, {2,sizeof(BOOL),W,}, {3,sizeof(DRIVER_INFO_2W),R,}, {4,sizeof(PUMDHPDEV *),W,}, }},
    {0,"NtGdiSetBoundsRect", OK, 12, {{1,sizeof(RECT),R,}, }},
    {0,"NtGdiGetColorAdjustment", OK, 8, {{1,sizeof(COLORADJUSTMENT),W,}, }},
    {0,"NtGdiSetColorAdjustment", OK, 8, {{1,sizeof(COLORADJUSTMENT),R,}, }},
    {0,"NtGdiCancelDC", OK, 4, },
    {0,"NtGdiOpenDCW", OK, 28/*32 on Vista+*/, {{0,sizeof(UNICODE_STRING),R|CT,SYSARG_TYPE_UNICODE_STRING,}, {1,sizeof(DEVMODEW)/*really var-len*/,R|CT,SYSARG_TYPE_DEVMODEW}, {2,sizeof(UNICODE_STRING),R|CT,SYSARG_TYPE_UNICODE_STRING,}, /*arg added in middle in Vista so special-cased*/}, &sysnum_GdiOpenDCW},
    {0,"NtGdiGetDCDword", OK, 12, {{2,sizeof(DWORD),W,}, }},
    {0,"NtGdiGetDCPoint", OK, 12, {{2,sizeof(POINTL),W,}, }},
    {0,"NtGdiScaleViewportExtEx", OK, 24, {{5,sizeof(SIZE),W,}, }},
    {0,"NtGdiScaleWindowExtEx", OK, 24, {{5,sizeof(SIZE),W,}, }},
    {0,"NtGdiSetVirtualResolution", OK, 20, },
    {0,"NtGdiSetSizeDevice", OK, 12, },
    {0,"NtGdiGetTransform", OK, 12, {{2,sizeof(XFORM),W,}, }},
    {0,"NtGdiModifyWorldTransform", OK, 12, {{1,sizeof(XFORM),R,}, }},
    {0,"NtGdiCombineTransform", OK, 12, {{0,sizeof(XFORM),W,}, {1,sizeof(XFORM),R,}, {2,sizeof(XFORM),R,}, }},
    {0,"NtGdiTransformPoints", OK, 20, {{1,-3,R|SYSARG_SIZE_IN_ELEMENTS,sizeof(POINT)}, {2,-3,W|SYSARG_SIZE_IN_ELEMENTS,sizeof(POINT)}, }},
    {0,"NtGdiConvertMetafileRect", OK, 8, {{1,sizeof(RECTL),R|W,}, }},
    {0,"NtGdiGetTextCharsetInfo", OK, 12, {{1,sizeof(FONTSIGNATURE),W,}, }},
    {0,"NtGdiDoBanding", OK, 16, {{2,sizeof(POINTL),W,}, {3,sizeof(SIZE),W,}, }},
    {0,"NtGdiGetPerBandInfo", OK, 8, {{1,sizeof(PERBANDINFO),R|W,}, }},
    {0,"NtGdiGetStats", OK, 20, {{3,-4,W,}, }},
    {0,"NtGdiSetMagicColors", OK, 12, },
    {0,"NtGdiSelectBrush", OK, 8, },
    {0,"NtGdiSelectPen", OK, 8, },
    {0,"NtGdiSelectBitmap", OK, 8, },
    {0,"NtGdiSelectFont", OK, 8, },
    {0,"NtGdiExtSelectClipRgn", OK, 12, },
    {0,"NtGdiCreatePen", OK, 16, },
    {0,"NtGdiBitBlt", OK, 44, },
    {0,"NtGdiTileBitBlt", OK, 28, {{1,sizeof(RECTL),R,}, {3,sizeof(RECTL),R,}, {4,sizeof(POINTL),R,}, }},
    {0,"NtGdiTransparentBlt", OK, 44, },
    {0,"NtGdiGetTextExtent", OK, 20, {{1,-2,R|SYSARG_SIZE_IN_ELEMENTS,sizeof(wchar_t)}, {3,sizeof(SIZE),W,}, }},
    {0,"NtGdiGetTextMetricsW", OK, 12, {{1,-2,W,}, }},
    {0,"NtGdiGetTextFaceW", OK, 16, {{2,-1,W|SYSARG_SIZE_IN_ELEMENTS,sizeof(wchar_t)}, {2,RET,W|SYSARG_SIZE_IN_ELEMENTS,sizeof(wchar_t)}, }},
    {0,"NtGdiGetRandomRgn", OK, 12, },
    {0,"NtGdiExtTextOutW", OK, 36, {{4,sizeof(RECT),R,}, {5,-6,R|SYSARG_SIZE_IN_ELEMENTS,sizeof(wchar_t)}, {7,-6,R|SYSARG_SIZE_IN_ELEMENTS,sizeof(INT)/*can be larger: special-cased*/}, }, &sysnum_GdiExtTextOutW},
    {0,"NtGdiIntersectClipRect", OK, 20, },
    {0,"NtGdiCreateRectRgn", OK, 16, },
    {0,"NtGdiPatBlt", OK, 24, },
    {0,"NtGdiPolyPatBlt", OK, 20, {{2,-3,R|SYSARG_SIZE_IN_ELEMENTS,sizeof(POLYPATBLT)}, }},
    {0,"NtGdiUnrealizeObject", OK, 4, },
    {0,"NtGdiGetStockObject", OK, 4, },
    {0,"NtGdiCreateCompatibleBitmap", OK, 12, },
    {0,"NtGdiCreateBitmapFromDxSurface", OK, 20, },
    {0,"NtGdiBeginGdiRendering", OK, 8, },
    {0,"NtGdiEndGdiRendering", OK, 12, {{2,sizeof(BOOL),W,}, }},
    {0,"NtGdiLineTo", OK, 12, },
    {0,"NtGdiMoveTo", OK, 16, {{3,sizeof(POINT),W,}, }},
    {0,"NtGdiExtGetObjectW", OK, 12, {{2,-1,W}, {2,RET,W,}, }},
    {0,"NtGdiGetDeviceCaps", OK, 8, },
    {0,"NtGdiGetDeviceCapsAll", OK, 8, {{1,sizeof(DEVCAPS),W,}, }},
    {0,"NtGdiStretchBlt", OK, 48, },
    {0,"NtGdiSetBrushOrg", OK, 16, {{3,sizeof(POINT),W,}, }},
    {0,"NtGdiCreateBitmap", OK, 20, {{4,sizeof(BYTE),R,}, }},
    {0,"NtGdiCreateHalftonePalette", OK, 4, },
    {0,"NtGdiRestoreDC", OK, 8, },
    {0,"NtGdiExcludeClipRect", OK, 20, },
    {0,"NtGdiSaveDC", OK, 4, },
    {0,"NtGdiCombineRgn", OK, 16, },
    {0,"NtGdiSetRectRgn", OK, 20, },
    {0,"NtGdiSetBitmapBits", OK, 12, {{2,-1,R,}, }},
    {0,"NtGdiGetDIBitsInternal", OK, 36, {{4,-7,W,}, {5,sizeof(BITMAPINFO),R|W,}, }},
    {0,"NtGdiOffsetRgn", OK, 12, },
    {0,"NtGdiGetRgnBox", OK, 8, {{1,sizeof(RECT),W,}, }},
    {0,"NtGdiRectInRegion", OK, 8, {{1,sizeof(RECT),R|W,}, }},
    {0,"NtGdiGetBoundsRect", OK, 12, {{1,sizeof(RECT),W,}, }},
    {0,"NtGdiPtInRegion", OK, 12, },
    {0,"NtGdiGetNearestColor", OK, 8, },
    {0,"NtGdiGetSystemPaletteUse", OK, 4, },
    {0,"NtGdiSetSystemPaletteUse", OK, 8, },
    {0,"NtGdiGetRegionData", OK, 12, {{2,-1,W,}, {2,RET,W,}, }},
    {0,"NtGdiInvertRgn", OK, 8, },
    {0,"NtGdiHfontCreate", OK, 20, {{0,}, },/*special-cased*/ &sysnum_GdiHfontCreate},
#if 0 /* for _WIN32_WINNT < 0x0500 == NT which we ignore for now */
    {0,"NtGdiHfontCreate", OK, 20, {{0,sizeof(EXTLOGFONTW),R,}, }},
#endif
    {0,"NtGdiSetFontEnumeration", OK, 4, },
    {0,"NtGdiEnumFonts", OK, 32, {{4,-3,R|SYSARG_SIZE_IN_ELEMENTS,sizeof(wchar_t)}, {6,sizeof(ULONG),R|W,}, {7,-6,WI,}, }},
    {0,"NtGdiQueryFonts", OK, 12, {{0,-1,W|SYSARG_SIZE_IN_ELEMENTS,sizeof(UNIVERSAL_FONT_ID)}, {2,sizeof(LARGE_INTEGER),W,}, }},
    {0,"NtGdiGetCharSet", OK, 4, },
    {0,"NtGdiEnableEudc", OK, 4, },
    {0,"NtGdiEudcLoadUnloadLink", OK, 28, {{0,-1,R|SYSARG_SIZE_IN_ELEMENTS,sizeof(wchar_t)}, {2,-3,R|SYSARG_SIZE_IN_ELEMENTS,sizeof(wchar_t)}, }},
    {0,"NtGdiGetStringBitmapW", OK, 20, {{1,sizeof(wchar_t),R,}, {4,-3,W,}, }},
    {0,"NtGdiGetEudcTimeStampEx", OK, 12, {{0,-1,R|SYSARG_SIZE_IN_ELEMENTS,sizeof(wchar_t)}, }},
    {0,"NtGdiQueryFontAssocInfo", OK, 4, },
    {0,"NtGdiGetFontUnicodeRanges", OK, 8, {{1,RET,W,/*FIXME i#485: pre size from prior syscall ret*/}, }},
    /* FIXME i#485: the REALIZATION_INFO struct is much larger on win7 */
    {0,"NtGdiGetRealizationInfo", UNKNOWN, 8, {{1,sizeof(REALIZATION_INFO),W,}, }},
    {0,"NtGdiAddRemoteMMInstanceToDC", OK, 12, {{1,-2,R,}, }},
    {0,"NtGdiUnloadPrinterDriver", OK, 8, {{0,-1,R,}, }},
    {0,"NtGdiEngAssociateSurface", OK, 12, },
    {0,"NtGdiEngEraseSurface", OK, 12, {{0,sizeof(SURFOBJ),R,}, {1,sizeof(RECTL),R,}, }},
    {0,"NtGdiEngCreateBitmap", OK, 20, },
    {0,"NtGdiEngDeleteSurface", OK, 4, },
    {0,"NtGdiEngLockSurface", OK, 4, },
    {0,"NtGdiEngUnlockSurface", OK, 4, {{0,sizeof(SURFOBJ),R,}, }},
    {0,"NtGdiEngMarkBandingSurface", OK, 4, },
    {0,"NtGdiEngCreateDeviceSurface", OK, 12, },
    {0,"NtGdiEngCreateDeviceBitmap", OK, 12, },
    {0,"NtGdiEngCopyBits", OK, 24, {{0,sizeof(SURFOBJ),R,}, {1,sizeof(SURFOBJ),R,}, {2,sizeof(CLIPOBJ),R,}, {3,sizeof(XLATEOBJ),R,}, {4,sizeof(RECTL),R,}, {5,sizeof(POINTL),R,}, }},
    {0,"NtGdiEngStretchBlt", OK, 44, {{0,sizeof(SURFOBJ),R,}, {1,sizeof(SURFOBJ),R,}, {2,sizeof(SURFOBJ),R,}, {3,sizeof(CLIPOBJ),R,}, {4,sizeof(XLATEOBJ),R,}, {5,sizeof(COLORADJUSTMENT),R,}, {6,sizeof(POINTL),R,}, {7,sizeof(RECTL),R,}, {8,sizeof(RECTL),R,}, {9,sizeof(POINTL),R,}, }},
    {0,"NtGdiEngBitBlt", OK, 44, {{0,sizeof(SURFOBJ),R,}, {1,sizeof(SURFOBJ),R,}, {2,sizeof(SURFOBJ),R,}, {3,sizeof(CLIPOBJ),R,}, {4,sizeof(XLATEOBJ),R,}, {5,sizeof(RECTL),R,}, {6,sizeof(POINTL),R,}, {7,sizeof(POINTL),R,}, {8,sizeof(BRUSHOBJ),R,}, {9,sizeof(POINTL),R,}, }},
    {0,"NtGdiEngPlgBlt", OK, 44, {{0,sizeof(SURFOBJ),R,}, {1,sizeof(SURFOBJ),R,}, {2,sizeof(SURFOBJ),R,}, {3,sizeof(CLIPOBJ),R,}, {4,sizeof(XLATEOBJ),R,}, {5,sizeof(COLORADJUSTMENT),R,}, {6,sizeof(POINTL),R,}, {7,sizeof(POINTFIX),R,}, {8,sizeof(RECTL),R,}, {9,sizeof(POINTL),R,}, }},
    {0,"NtGdiEngCreatePalette", OK, 24, {{2,sizeof(ULONG),R,}, }},
    {0,"NtGdiEngDeletePalette", OK, 4, },
    {0,"NtGdiEngStrokePath", OK, 32, {{0,sizeof(SURFOBJ),R,}, {1,sizeof(PATHOBJ),R,}, {2,sizeof(CLIPOBJ),R,}, {3,sizeof(XFORMOBJ),R,}, {4,sizeof(BRUSHOBJ),R,}, {5,sizeof(POINTL),R,}, {6,sizeof(LINEATTRS),R,}, }},
    {0,"NtGdiEngFillPath", OK, 28, {{0,sizeof(SURFOBJ),R,}, {1,sizeof(PATHOBJ),R,}, {2,sizeof(CLIPOBJ),R,}, {3,sizeof(BRUSHOBJ),R,}, {4,sizeof(POINTL),R,}, }},
    {0,"NtGdiEngStrokeAndFillPath", OK, 40, {{0,sizeof(SURFOBJ),R,}, {1,sizeof(PATHOBJ),R,}, {2,sizeof(CLIPOBJ),R,}, {3,sizeof(XFORMOBJ),R,}, {4,sizeof(BRUSHOBJ),R,}, {5,sizeof(LINEATTRS),R,}, {6,sizeof(BRUSHOBJ),R,}, {7,sizeof(POINTL),R,}, }},
    {0,"NtGdiEngPaint", OK, 20, {{0,sizeof(SURFOBJ),R,}, {1,sizeof(CLIPOBJ),R,}, {2,sizeof(BRUSHOBJ),R,}, {3,sizeof(POINTL),R,}, }},
    {0,"NtGdiEngLineTo", OK, 36, {{0,sizeof(SURFOBJ),R,}, {1,sizeof(CLIPOBJ),R,}, {2,sizeof(BRUSHOBJ),R,}, {7,sizeof(RECTL),R,}, }},
    {0,"NtGdiEngAlphaBlend", OK, 28, {{0,sizeof(SURFOBJ),R,}, {1,sizeof(SURFOBJ),R,}, {2,sizeof(CLIPOBJ),R,}, {3,sizeof(XLATEOBJ),R,}, {4,sizeof(RECTL),R,}, {5,sizeof(RECTL),R,}, {6,sizeof(BLENDOBJ),R,}, }},
    {0,"NtGdiEngGradientFill", OK, 40, {{0,sizeof(SURFOBJ),R,}, {1,sizeof(CLIPOBJ),R,}, {2,sizeof(XLATEOBJ),R,}, {3,-4,R|SYSARG_SIZE_IN_ELEMENTS,sizeof(TRIVERTEX)}, {7,sizeof(RECTL),R,}, {8,sizeof(POINTL),R,}, }},
    {0,"NtGdiEngTransparentBlt", OK, 32, {{0,sizeof(SURFOBJ),R,}, {1,sizeof(SURFOBJ),R,}, {2,sizeof(CLIPOBJ),R,}, {3,sizeof(XLATEOBJ),R,}, {4,sizeof(RECTL),R,}, {5,sizeof(RECTL),R,}, }},
    {0,"NtGdiEngTextOut", OK, 40, {{0,sizeof(SURFOBJ),R,}, {1,sizeof(STROBJ),R,}, {2,sizeof(FONTOBJ),R,}, {3,sizeof(CLIPOBJ),R,}, {4,sizeof(RECTL),R,}, {5,sizeof(RECTL),R,}, {6,sizeof(BRUSHOBJ),R,}, {7,sizeof(BRUSHOBJ),R,}, {8,sizeof(POINTL),R,}, }},
    {0,"NtGdiEngStretchBltROP", OK, 52, {{0,sizeof(SURFOBJ),R,}, {1,sizeof(SURFOBJ),R,}, {2,sizeof(SURFOBJ),R,}, {3,sizeof(CLIPOBJ),R,}, {4,sizeof(XLATEOBJ),R,}, {5,sizeof(COLORADJUSTMENT),R,}, {6,sizeof(POINTL),R,}, {7,sizeof(RECTL),R,}, {8,sizeof(RECTL),R,}, {9,sizeof(POINTL),R,}, {11,sizeof(BRUSHOBJ),R,}, }},
    {0,"NtGdiXLATEOBJ_cGetPalette", OK, 16, {{0,sizeof(XLATEOBJ),R,}, {3,-2,W|SYSARG_SIZE_IN_ELEMENTS,sizeof(ULONG)}, }},
    {0,"NtGdiCLIPOBJ_cEnumStart", OK, 20, {{0,sizeof(CLIPOBJ),R,}, }},
    {0,"NtGdiCLIPOBJ_bEnum", OK, 12, {{0,sizeof(CLIPOBJ),R,}, {2,-1,W,}, }},
    {0,"NtGdiCLIPOBJ_ppoGetPath", OK, 4, {{0,sizeof(CLIPOBJ),R,}, }},
    {0,"NtGdiEngCreateClip", OK, 0, },
    {0,"NtGdiEngDeleteClip", OK, 4, {{0,sizeof(CLIPOBJ),R,}, }},
    {0,"NtGdiBRUSHOBJ_pvAllocRbrush", OK, 8, {{0,sizeof(BRUSHOBJ),R,}, }},
    {0,"NtGdiBRUSHOBJ_pvGetRbrush", OK, 4, {{0,sizeof(BRUSHOBJ),R,}, }},
    {0,"NtGdiBRUSHOBJ_ulGetBrushColor", OK, 4, {{0,sizeof(BRUSHOBJ),R,}, }},
    {0,"NtGdiBRUSHOBJ_hGetColorTransform", OK, 4, {{0,sizeof(BRUSHOBJ),R,}, }},
    {0,"NtGdiXFORMOBJ_bApplyXform", OK, 20, {{0,sizeof(XFORMOBJ),R,}, {3,-2,R|SYSARG_SIZE_IN_ELEMENTS,sizeof(POINTL)}, {4,-2,W|SYSARG_SIZE_IN_ELEMENTS,sizeof(POINTL)}, }},
    {0,"NtGdiXFORMOBJ_iGetXform", OK, 8, {{0,sizeof(XFORMOBJ),R,}, {1,sizeof(XFORML),W,}, }},
    {0,"NtGdiFONTOBJ_vGetInfo", OK, 12, {{0,sizeof(FONTOBJ),R,}, {2,-1,W,}, }},
    {0,"NtGdiFONTOBJ_cGetGlyphs", OK, 20, {{0,sizeof(FONTOBJ),R,}, {3,sizeof(HGLYPH),R,}, {4,sizeof(GLYPHDATA **),W,}, }},
    {0,"NtGdiFONTOBJ_pxoGetXform", OK, 4, {{0,sizeof(FONTOBJ),R,}, }},
    {0,"NtGdiFONTOBJ_pifi", OK, 4, {{0,sizeof(FONTOBJ),R,}, }},
    {0,"NtGdiFONTOBJ_pfdg", OK, 4, {{0,sizeof(FONTOBJ),R,}, }},
    {0,"NtGdiFONTOBJ_cGetAllGlyphHandles", OK, 8, {{0,sizeof(FONTOBJ),R,}, {1,RET,W|SYSARG_SIZE_IN_ELEMENTS,sizeof(HGLYPH)/*FIXME i#485: pre size from prior syscall ret*/}, }},
    {0,"NtGdiFONTOBJ_pvTrueTypeFontFile", OK, 8, {{0,sizeof(FONTOBJ),R,}, {1,sizeof(ULONG),W,}, }},
    {0,"NtGdiFONTOBJ_pQueryGlyphAttrs", OK, 8, {{0,sizeof(FONTOBJ),R,}, }},
    {0,"NtGdiSTROBJ_bEnum", OK, 12, {{0,sizeof(STROBJ),R,}, {1,sizeof(ULONG),R|W,/*XXX: I'm assuming R: else how know? prior syscall (i#485)?*/}, {2,-1,WI|SYSARG_SIZE_IN_ELEMENTS,sizeof(PGLYPHPOS)}, }},
    {0,"NtGdiSTROBJ_bEnumPositionsOnly", OK, 12, {{0,sizeof(STROBJ),R,}, {1,sizeof(ULONG),R|W,/*XXX: I'm assuming R: else how know? prior syscall (i#485)?*/}, {2,-1,WI|SYSARG_SIZE_IN_ELEMENTS,sizeof(PGLYPHPOS)}, }},
    {0,"NtGdiSTROBJ_vEnumStart", OK, 4, {{0,sizeof(STROBJ),R,}, }},
    {0,"NtGdiSTROBJ_dwGetCodePage", OK, 4, {{0,sizeof(STROBJ),R,}, }},
    {0,"NtGdiSTROBJ_bGetAdvanceWidths", OK, 16, {{0,sizeof(STROBJ),R,}, {3,-2,W|SYSARG_SIZE_IN_ELEMENTS,sizeof(POINTQF)}, }},
    {0,"NtGdiEngComputeGlyphSet", OK, 12, },
    {0,"NtGdiXLATEOBJ_iXlate", OK, 8, {{0,sizeof(XLATEOBJ),R,}, }},
    {0,"NtGdiXLATEOBJ_hGetColorTransform", OK, 4, {{0,sizeof(XLATEOBJ),R,}, }},
    {0,"NtGdiPATHOBJ_vGetBounds", OK, 8, {{0,sizeof(PATHOBJ),R,}, {1,sizeof(RECTFX),W,}, }},
    {0,"NtGdiPATHOBJ_bEnum", OK, 8, {{0,sizeof(PATHOBJ),R,}, {1,sizeof(PATHDATA),W,}, }},
    {0,"NtGdiPATHOBJ_vEnumStart", OK, 4, {{0,sizeof(PATHOBJ),R,}, }},
    {0,"NtGdiEngDeletePath", OK, 4, {{0,sizeof(PATHOBJ),R,}, }},
    {0,"NtGdiPATHOBJ_vEnumStartClipLines", OK, 16, {{0,sizeof(PATHOBJ),R,}, {1,sizeof(CLIPOBJ),R,}, {2,sizeof(SURFOBJ),R,}, {3,sizeof(LINEATTRS),R,}, }},
    {0,"NtGdiPATHOBJ_bEnumClipLines", OK, 12, {{0,sizeof(PATHOBJ),R,}, {2,-1,W,}, }},
    {0,"NtGdiEngCheckAbort", OK, 4, {{0,sizeof(SURFOBJ),R,}, }},
    {0,"NtGdiGetDhpdev", OK, 4, },
    {0,"NtGdiHT_Get8BPPFormatPalette", OK, 16, {{0,RET,W|SYSARG_SIZE_IN_ELEMENTS,sizeof(PALETTEENTRY)/*FIXME i#485: pre size from prior syscall ret*/}, }},
    {0,"NtGdiHT_Get8BPPMaskPalette", OK, 24, {{0,RET,W|SYSARG_SIZE_IN_ELEMENTS,sizeof(PALETTEENTRY)/*FIXME i#485: pre size from prior syscall ret*/}, }},
    {0,"NtGdiUpdateTransform", OK, 4, },
    {0,"NtGdiSetLayout", OK, 12, },
    {0,"NtGdiMirrorWindowOrg", OK, 4, },
    {0,"NtGdiGetDeviceWidth", OK, 4, },
    {0,"NtGdiSetPUMPDOBJ", OK, 16, {{2,sizeof(HUMPD),R|W,}, {3,sizeof(BOOL),W,}, }},
    {0,"NtGdiBRUSHOBJ_DeleteRbrush", OK, 8, {{0,sizeof(BRUSHOBJ),R,}, {1,sizeof(BRUSHOBJ),R,}, }},
    {0,"NtGdiUMPDEngFreeUserMem", OK, 4, {{0,sizeof(KERNEL_PVOID),R,}, }},
    {0,"NtGdiSetBitmapAttributes", OK, 8, },
    {0,"NtGdiClearBitmapAttributes", OK, 8, },
    {0,"NtGdiSetBrushAttributes", OK, 8, },
    {0,"NtGdiClearBrushAttributes", OK, 8, },
    {0,"NtGdiDrawStream", OK, 12, },
    {0,"NtGdiMakeObjectXferable", OK, 8, },
    {0,"NtGdiMakeObjectUnXferable", OK, 4, },
    {0,"NtGdiSfmGetNotificationTokens", OK, 12, {{1,sizeof(UINT),W,}, {2,-0,W,}, }},
    {0,"NtGdiSfmRegisterLogicalSurfaceForSignaling", OK, 8, },
    {0,"NtGdiDwmGetHighColorMode", OK, 4, {{0,sizeof(DXGI_FORMAT),W,}, }},
    {0,"NtGdiDwmSetHighColorMode", OK, 4, },
    {0,"NtGdiDwmCaptureScreen", OK, 8, {{0,sizeof(RECT),R,}, }},
    {0,"NtGdiDdCreateFullscreenSprite", OK, 16, {{2,sizeof(HANDLE),W,}, {3,sizeof(HDC),W,}, }},
    {0,"NtGdiDdNotifyFullscreenSpriteUpdate", OK, 8, },
    {0,"NtGdiDdDestroyFullscreenSprite", OK, 8, },
    {0,"NtGdiDdQueryVisRgnUniqueness", OK, 0, },

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
#undef CT
#undef WI
#undef IB
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

extern bool
handle_unicode_string_access(bool pre, int sysnum, dr_mcontext_t *mc,
                             uint arg_num, const syscall_arg_t *arg_info,
                             app_pc start, uint size, bool ignore_len);

extern bool
handle_cwstring(bool pre, int sysnum, dr_mcontext_t *mc, const char *id,
                byte *start, size_t size, uint arg_flags, wchar_t *safe,
                bool check_addr);


bool
handle_large_string_access(bool pre, int sysnum, dr_mcontext_t *mc,
                             uint arg_num,
                             const syscall_arg_t *arg_info,
                             app_pc start, uint size)
{
    uint check_type = SYSARG_CHECK_TYPE(arg_info->flags, pre);
    LARGE_STRING ls;
    LARGE_STRING *arg = (LARGE_STRING *) start;
    ASSERT(size == sizeof(LARGE_STRING), "invalid size");
    /* I've seen an atom (or int resource?) here
     * XXX i#488: avoid false neg: not too many of these now though
     * so we allow on all syscalls
     */
    if (is_atom(start))
        return true; /* handled */
    /* we assume OUT fields jlst have their Buffer as OUT */
    if (pre) {
        check_sysmem(MEMREF_CHECK_DEFINEDNESS, sysnum, (byte *)&arg->Length,
                     sizeof(arg->Length), mc, "LARGE_STRING.Length");
        /* i#489: LARGE_STRING.MaximumLength and LARGE_STRING.bAnsi end
         * up initialized by a series of bit manips that fool us
         * so we don't check here
         */
        check_sysmem(MEMREF_CHECK_DEFINEDNESS, sysnum, (byte *)&arg->Buffer,
                     sizeof(arg->Buffer), mc, "LARGE_STRING.Buffer");
    }
    if (safe_read((void*)start, sizeof(ls), &ls)) {
        if (pre) {
            LOG(SYSCALL_VERBOSE,
                "LARGE_STRING Buffer="PFX" Length=%d MaximumLength=%d\n",
                (byte *)ls.Buffer, ls.Length, ls.MaximumLength);
            /* See i#489 notes above: check for undef if looks "suspicious": weak,
             * but simpler and more efficient than pattern match on every bb.
             */
            if (ls.MaximumLength > ls.Length &&
                ls.MaximumLength > 1024 /* suspicious */) {
                check_sysmem(MEMREF_CHECK_DEFINEDNESS, sysnum, start + sizeof(arg->Length),
                             sizeof(ULONG/*+bAnsi*/), mc, "LARGE_STRING.MaximumLength");
            } else {
                shadow_set_range(start + sizeof(arg->Length),
                                 (byte *)&arg->Buffer, SHADOW_DEFINED);
            }
            check_sysmem(MEMREF_CHECK_ADDRESSABLE, sysnum,
                         (byte *)ls.Buffer, ls.MaximumLength, mc,
                         "LARGE_STRING capacity");
            if (TEST(SYSARG_READ, arg_info->flags)) {
                check_sysmem(MEMREF_CHECK_DEFINEDNESS, sysnum,
                             (byte *)ls.Buffer, ls.Length, mc, "LARGE_STRING content");
            }
        } else if (TEST(SYSARG_WRITE, arg_info->flags)) {
            check_sysmem(MEMREF_WRITE, sysnum, (byte *)ls.Buffer, ls.Length, mc,
                          "LARGE_STRING content");
        }
    } else
        WARN("WARNING: unable to read syscall param\n");
    return true; /* handled */
}

bool
handle_devmodew_access(bool pre, int sysnum, dr_mcontext_t *mc,
                       uint arg_num,
                       const syscall_arg_t *arg_info,
                       app_pc start, uint size)
{
    /* DEVMODEW is var-len by windows ver plus optional private driver data appended */
    uint check_type = SYSARG_CHECK_TYPE(arg_info->flags, pre);
    /* can't use a DEVMODEW as ours may be longer than app's if on older windows */
    char buf[offsetof(DEVMODEW,dmFields)]; /* need dmSize and dmDriverExtra */
    DEVMODEW *safe;
    DEVMODEW *param = (DEVMODEW *) start;
    if (pre) {
        check_sysmem(MEMREF_CHECK_DEFINEDNESS, sysnum, start,
                     BUFFER_SIZE_BYTES(buf), mc, "DEVMODEW through dmDriverExtra");
    }
    if (safe_read(start, BUFFER_SIZE_BYTES(buf), buf)) {
        safe = (DEVMODEW *) buf;
        ASSERT(safe->dmSize > offsetof(DEVMODEW, dmFormName), "invalid size");
        /* there's some padding in the middle */
        check_sysmem(check_type, sysnum, (byte *) &param->dmFields,
                     ((byte *) &param->dmCollate) + sizeof(safe->dmCollate) -
                     (byte *) &param->dmFields,
                     mc, "DEVMODEW dmFields through dmCollate");
        check_sysmem(check_type, sysnum, (byte *) &param->dmFormName,
                     (start + safe->dmSize) - (byte *) (&param->dmFormName),
                     mc, "DEVMODEW dmFormName onward");
        check_sysmem(check_type, sysnum, start + safe->dmSize, safe->dmDriverExtra,
                     mc, "DEVMODEW driver extra info");
    } else
        WARN("WARNING: unable to read syscall param\n");
    return true; /* handled */
}

bool
handle_wndclassexw_access(bool pre, int sysnum, dr_mcontext_t *mc,
                          uint arg_num,
                          const syscall_arg_t *arg_info,
                          app_pc start, uint size)
{
    uint check_type = SYSARG_CHECK_TYPE(arg_info->flags, pre);
    WNDCLASSEXW safe;
    /* i#499: it seems that cbSize is not set for NtUserGetClassInfo when using
     * user32!GetClassInfo so we use sizeof for writes.  I suspect that once
     * they add any more new fields they will start using it.  We could
     * alternatively keep the check here and treat this is a user32.dll bug and
     * suppress it.
     */
    bool use_cbSize = TEST(SYSARG_READ, arg_info->flags);
    if (pre && use_cbSize) {
        check_sysmem(MEMREF_CHECK_DEFINEDNESS, sysnum, start,
                     sizeof(safe.cbSize), mc, "WNDCLASSEX.cbSize");
    }
    if (safe_read(start, sizeof(safe), &safe)) {
        check_sysmem(check_type, sysnum, start,
                     use_cbSize ? safe.cbSize : sizeof(WNDCLASSEX), mc, "WNDCLASSEX");
        /* For WRITE there is no capacity here so nothing to check (i#505) */
        if ((pre && TEST(SYSARG_READ, arg_info->flags)) ||
            (!pre && TEST(SYSARG_WRITE, arg_info->flags))) {
                /* lpszMenuName can be from MAKEINTRESOURCE, and
                 * lpszClassName can be an atom
                 */
                if ((!use_cbSize || safe.cbSize > offsetof(WNDCLASSEX, lpszMenuName)) &&
                    !is_atom((void *)safe.lpszMenuName)) {
                    handle_cwstring(pre, sysnum, mc, "WNDCLASSEXW.lpszMenuName",
                                    (byte *) safe.lpszMenuName, 0, arg_info->flags,
                                    NULL, true);
                }
                if ((!use_cbSize || safe.cbSize > offsetof(WNDCLASSEX, lpszClassName)) &&
                    !is_int_resource((void *)safe.lpszClassName)) {
                    handle_cwstring(pre, sysnum, mc, "WNDCLASSEXW.lpszClassName",
                                    /* docs say 256 is max length: we read until
                                     * NULL though
                                     */
                                    (byte *) safe.lpszClassName, 0, arg_info->flags,
                                    NULL, true);
                }
        }
    } else
        WARN("WARNING: unable to read syscall param\n");
    return true; /* handled */
}

bool
handle_clsmenuname_access(bool pre, int sysnum, dr_mcontext_t *mc,
                          uint arg_num,
                          const syscall_arg_t *arg_info,
                          app_pc start, uint size)
{
    uint check_type = SYSARG_CHECK_TYPE(arg_info->flags, pre);
    CLSMENUNAME safe;
    check_sysmem(check_type, sysnum, start, size, mc, "CLSMENUNAME");
    if (pre && !TEST(SYSARG_READ, arg_info->flags)) {
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
            handle_cstring(pre, sysnum, mc, "CLSMENUNAME.lpszMenuName",
                           safe.pszClientAnsiMenuName, 0, arg_info->flags,
                           NULL, true);
        }
        if (!is_atom(safe.pwszClientUnicodeMenuName)) {
            handle_cwstring(pre, sysnum, mc, "CLSMENUNAME.lpszMenuName",
                            (byte *) safe.pwszClientUnicodeMenuName, 0, arg_info->flags,
                            NULL, true);
        }
        /* XXX: I've seen the pusMenuName pointer itself be an atom, though
         * perhaps should also handle just the Buffer being an atom?
         */
        if (!is_atom(safe.pusMenuName)) {
            handle_unicode_string_access(pre, sysnum, mc, arg_num, arg_info,
                                         (byte *) safe.pusMenuName,
                                         sizeof(UNICODE_STRING), false);
        }
    } else
        WARN("WARNING: unable to read syscall param\n");
#endif
    return true; /* handled */
}

bool
handle_menuiteminfow_access(bool pre, int sysnum, dr_mcontext_t *mc,
                            uint arg_num,
                            const syscall_arg_t *arg_info,
                            app_pc start, uint size)
{
    uint check_type = SYSARG_CHECK_TYPE(arg_info->flags, pre);
    MENUITEMINFOW *real = (MENUITEMINFOW *) start;
    MENUITEMINFOW safe;
    bool check_dwTypeData = false;
    /* user must set cbSize for set or get */
    if (pre) {
        check_sysmem(MEMREF_CHECK_DEFINEDNESS, sysnum, start,
                     sizeof(safe.cbSize), mc, "MENUITEMINFOW.cbSize");
    }
    if (safe_read(start, sizeof(safe), &safe)) {
        if (pre) {
            check_sysmem(MEMREF_CHECK_ADDRESSABLE, sysnum, start,
                         safe.cbSize, mc, "MENUITEMINFOW");
        }
        if (TEST(MIIM_BITMAP, safe.fMask) &&
            safe.cbSize > offsetof(MENUITEMINFOW, hbmpItem)) {
            check_sysmem(check_type, sysnum, (byte *) &real->hbmpItem,
                         sizeof(real->hbmpItem), mc, "MENUITEMINFOW.hbmpItem");
        }
        if (TEST(MIIM_CHECKMARKS, safe.fMask)) {
            if (safe.cbSize > offsetof(MENUITEMINFOW, hbmpChecked)) {
                check_sysmem(check_type, sysnum, (byte *) &real->hbmpChecked,
                             sizeof(real->hbmpChecked), mc, "MENUITEMINFOW.hbmpChecked");
            }
            if (safe.cbSize > offsetof(MENUITEMINFOW, hbmpUnchecked)) {
                check_sysmem(check_type, sysnum, (byte *) &real->hbmpUnchecked,
                             sizeof(real->hbmpUnchecked), mc,
                             "MENUITEMINFOW.hbmpUnchecked");
            }
        }
        if (TEST(MIIM_DATA, safe.fMask) &&
            safe.cbSize > offsetof(MENUITEMINFOW, dwItemData)) {
            check_sysmem(check_type, sysnum, (byte *) &real->dwItemData,
                         sizeof(real->dwItemData), mc, "MENUITEMINFOW.dwItemData");
        }
        if (TEST(MIIM_FTYPE, safe.fMask) &&
            safe.cbSize > offsetof(MENUITEMINFOW, fType)) {
            check_sysmem(check_type, sysnum, (byte *) &real->fType,
                         sizeof(real->fType), mc, "MENUITEMINFOW.fType");
        }
        if (TEST(MIIM_ID, safe.fMask) &&
            safe.cbSize > offsetof(MENUITEMINFOW, wID)) {
            check_sysmem(check_type, sysnum, (byte *) &real->wID,
                         sizeof(real->wID), mc, "MENUITEMINFOW.wID");
        }
        if (TEST(MIIM_STATE, safe.fMask) &&
            safe.cbSize > offsetof(MENUITEMINFOW, fState)) {
            check_sysmem(check_type, sysnum, (byte *) &real->fState,
                         sizeof(real->fState), mc, "MENUITEMINFOW.fState");
        }
        if (TEST(MIIM_STRING, safe.fMask) &&
            safe.cbSize > offsetof(MENUITEMINFOW, dwTypeData)) {
            check_sysmem(check_type, sysnum, (byte *) &real->dwTypeData,
                         sizeof(real->dwTypeData), mc, "MENUITEMINFOW.dwTypeData");
            check_dwTypeData = true;
        }
        if (TEST(MIIM_SUBMENU, safe.fMask) &&
            safe.cbSize > offsetof(MENUITEMINFOW, hSubMenu)) {
            check_sysmem(check_type, sysnum, (byte *) &real->hSubMenu,
                         sizeof(real->hSubMenu), mc, "MENUITEMINFOW.hSubMenu");
        }
        if (TEST(MIIM_TYPE, safe.fMask) &&
            !TESTANY(MIIM_BITMAP | MIIM_FTYPE | MIIM_STRING, safe.fMask)) {
            if (safe.cbSize > offsetof(MENUITEMINFOW, fType)) {
                check_sysmem(check_type, sysnum, (byte *) &real->fType,
                             sizeof(real->fType), mc, "MENUITEMINFOW.fType");
            }
            if (safe.cbSize > offsetof(MENUITEMINFOW, dwTypeData)) {
                check_sysmem(check_type, sysnum, (byte *) &real->dwTypeData,
                             sizeof(real->dwTypeData), mc, "MENUITEMINFOW.dwTypeData");
                check_dwTypeData = true;
            }
        }
        if (check_dwTypeData) {
            /* kernel sets safe.cch so we don't have to walk the string */
            check_sysmem(check_type, sysnum, (byte *) safe.dwTypeData,
                         (safe.cch + 1/*null*/) * sizeof(wchar_t),
                         mc, "MENUITEMINFOW.dwTypeData");
        }
    } else
        WARN("WARNING: unable to read syscall param\n");
    return true; /* handled */
}

static void
handle_logfont(bool pre, void *drcontext, int sysnum, dr_mcontext_t *mc,
               byte *start, size_t size, uint arg_flags, LOGFONTW *safe)
{
    uint check_type = SYSARG_CHECK_TYPE(arg_flags, pre);
    LOGFONTW *font = (LOGFONTW *) start;
    if (pre && TEST(SYSARG_WRITE, arg_flags)) {
        check_sysmem(check_type, sysnum, start, size, mc, "LOGFONTW");
    } else {
        size_t check_sz = MIN(size - offsetof(LOGFONTW, lfFaceName),
                              sizeof(font->lfFaceName));
        ASSERT(size >= offsetof(LOGFONTW, lfFaceName), "invalid size");
        check_sysmem(check_type, sysnum, start,
                     offsetof(LOGFONTW, lfFaceName), mc, "LOGFONTW");
        handle_cwstring(pre, sysnum, mc, "LOGFONTW.lfFaceName",
                        (byte *) &font->lfFaceName, check_sz, arg_flags,
                        (safe == NULL) ? NULL : (wchar_t *)&safe->lfFaceName, true);
    }
}

static void
handle_nonclientmetrics(bool pre, void *drcontext, int sysnum, dr_mcontext_t *mc,
                        byte *start, uint arg_flags, NONCLIENTMETRICSW *safe)
{
    NONCLIENTMETRICSW *ptr_arg = (NONCLIENTMETRICSW *) start;
    NONCLIENTMETRICSW *ptr_safe;
    NONCLIENTMETRICSW ptr_local;
    uint check_type = SYSARG_CHECK_TYPE(arg_flags, pre);
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

    if (pre && TEST(SYSARG_WRITE, arg_flags)) {
        check_sysmem(check_type, sysnum, start, size, mc, "NONCLIENTMETRICSW");
    } else {
        size_t offs = 0;
        size_t check_sz = MIN(size, offsetof(NONCLIENTMETRICSW, lfCaptionFont));
        check_sysmem(check_type, sysnum, start, check_sz, mc, "NONCLIENTMETRICSW A");
        offs += check_sz;
        if (offs >= size)
            return;

        check_sz = MIN(size - offs, sizeof(LOGFONTW));
        handle_logfont(pre, drcontext, sysnum, mc, (byte *) &ptr_arg->lfCaptionFont,
                       check_sz, arg_flags, &ptr_safe->lfCaptionFont);
        offs += check_sz;
        if (offs >= size)
            return;

        check_sz = MIN(size - offs, offsetof(NONCLIENTMETRICSW, lfSmCaptionFont) -
                       offsetof(NONCLIENTMETRICSW, iSmCaptionWidth));
        check_sysmem(check_type, sysnum, (byte *) &ptr_arg->iSmCaptionWidth,
                     check_sz, mc, "NONCLIENTMETRICSW B");
        offs += check_sz;
        if (offs >= size)
            return;

        check_sz = MIN(size - offs, sizeof(LOGFONTW));
        handle_logfont(pre, drcontext, sysnum, mc, (byte *) &ptr_arg->lfSmCaptionFont,
                       check_sz, arg_flags, &ptr_safe->lfSmCaptionFont);
        offs += check_sz;
        if (offs >= size)
            return;

        check_sz = MIN(size - offs, offsetof(NONCLIENTMETRICSW, lfMenuFont) -
                       offsetof(NONCLIENTMETRICSW, iMenuWidth));
        check_sysmem(check_type, sysnum, (byte *) &ptr_arg->iMenuWidth,
                     check_sz, mc, "NONCLIENTMETRICSW B");
        offs += check_sz;
        if (offs >= size)
            return;

        check_sz = MIN(size - offs, sizeof(LOGFONTW));
        handle_logfont(pre, drcontext, sysnum, mc, (byte *) &ptr_arg->lfMenuFont,
                       check_sz, arg_flags, &ptr_safe->lfMenuFont);
        offs += check_sz;
        if (offs >= size)
            return;

        check_sz = MIN(size - offs, sizeof(LOGFONTW));
        handle_logfont(pre, drcontext, sysnum, mc, (byte *) &ptr_arg->lfStatusFont,
                       check_sz, arg_flags, &ptr_safe->lfStatusFont);
        offs += check_sz;
        if (offs >= size)
            return;

        check_sz = MIN(size - offs, sizeof(LOGFONTW));
        handle_logfont(pre, drcontext, sysnum, mc, (byte *) &ptr_arg->lfMessageFont,
                       check_sz, arg_flags, &ptr_safe->lfMessageFont);
        offs += check_sz;
        if (offs >= size)
            return;

        /* there is another field on Vista */
        check_sz = size - offs;
        check_sysmem(check_type, sysnum, ((byte *)ptr_arg) + offs,
                     check_sz, mc, "NONCLIENTMETRICSW C");
    }
}

static void
handle_iconmetrics(bool pre, void *drcontext, int sysnum, dr_mcontext_t *mc,
                        byte *start, uint arg_flags, ICONMETRICSW *safe)
{
    ICONMETRICSW *ptr_arg = (ICONMETRICSW *) start;
    ICONMETRICSW *ptr_safe;
    ICONMETRICSW ptr_local;
    uint check_type = SYSARG_CHECK_TYPE(arg_flags, pre);
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

    if (pre && TEST(SYSARG_WRITE, arg_flags)) {
        check_sysmem(check_type, sysnum, start, size, mc, "ICONMETRICSW");
    } else {
        size_t offs = 0;
        size_t check_sz = MIN(size, offsetof(ICONMETRICSW, lfFont));
        check_sysmem(check_type, sysnum, start, check_sz, mc, "ICONMETRICSW A");
        offs += check_sz;
        if (offs >= size)
            return;

        check_sz = MIN(size - offs, sizeof(LOGFONTW));
        handle_logfont(pre, drcontext, sysnum, mc, (byte *) &ptr_arg->lfFont,
                       check_sz, arg_flags, &ptr_safe->lfFont);
        offs += check_sz;
        if (offs >= size)
            return;

        /* currently no more args, but here for forward compat */
        check_sz = size - offs;
        check_sysmem(check_type, sysnum, ((byte *)ptr_arg) + offs,
                     check_sz, mc, "ICONMETRICSW B");
    }
}

static void
handle_serialkeys(bool pre, void *drcontext, int sysnum, dr_mcontext_t *mc,
                  byte *start, uint arg_flags, SERIALKEYSW *safe)
{
    SERIALKEYSW *ptr_safe;
    SERIALKEYSW ptr_local;
    uint check_type = SYSARG_CHECK_TYPE(arg_flags, pre);
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
    check_sysmem(check_type, sysnum, start, size, mc, "SERIALKEYSW");
    handle_cwstring(pre, sysnum, mc, "SERIALKEYSW.lpszActivePort",
                    (byte *) ptr_safe->lpszActivePort, 0, arg_flags, NULL, true);
    handle_cwstring(pre, sysnum, mc, "SERIALKEYSW.lpszPort",
                    (byte *) ptr_safe->lpszPort, 0, arg_flags, NULL, true);
}

static void
handle_cwstring_field(bool pre, int sysnum, dr_mcontext_t *mc, const char *id,
                      uint arg_flags,
                      byte *struct_start, size_t struct_size, size_t cwstring_offs)
{
    wchar_t *ptr;
    uint check_type = SYSARG_CHECK_TYPE(arg_flags, pre);
    if (struct_size <= cwstring_offs)
        return;
    if (!safe_read(struct_start + cwstring_offs, sizeof(ptr), &ptr)) {
        WARN("WARNING: unable to read syscall param\n");
        return;
    }
    handle_cwstring(pre, sysnum, mc, id, (byte *)ptr, 0, arg_flags, NULL, true);
}

bool
wingdi_process_syscall_arg(bool pre, int sysnum, dr_mcontext_t *mc, uint arg_num,
                           const syscall_arg_t *arg_info, app_pc start, uint size)
{
    switch (arg_info->misc) {
    case SYSARG_TYPE_LARGE_STRING:
        return handle_large_string_access(pre, sysnum, mc, arg_num,
                                          arg_info, start, size);
    case SYSARG_TYPE_DEVMODEW:
        return handle_devmodew_access(pre, sysnum, mc, arg_num, arg_info, start, size);
    case SYSARG_TYPE_WNDCLASSEXW:
        return handle_wndclassexw_access(pre, sysnum, mc, arg_num,
                                         arg_info, start, size);
    case SYSARG_TYPE_CLSMENUNAME:
        return handle_clsmenuname_access(pre, sysnum, mc, arg_num,
                                         arg_info, start, size);
    case SYSARG_TYPE_MENUITEMINFOW:
        return handle_menuiteminfow_access(pre, sysnum, mc, arg_num,
                                           arg_info, start, size);
    }
    return false; /* not handled */
}

/***************************************************************************
 * CUSTOM SYSCALL HANDLING
 */

static bool
handle_UserSystemParametersInfo(bool pre, void *drcontext, int sysnum, per_thread_t *pt,
                                dr_mcontext_t *mc)
{
    UINT uiAction = (UINT) pt->sysarg[0];
    UINT uiParam = (UINT) pt->sysarg[1];
    byte *pvParam = (byte *) pt->sysarg[2];
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
        handle_cwstring(pre, sysnum, mc, "pvParam", pvParam,
                        uiParam * sizeof(wchar_t), SYSARG_WRITE, NULL, true);
        get = true;
        uses_uiParam = true;
        uses_pvParam = true;
        break;
    }
    case SPI_SETDESKWALLPAPER: {
        syscall_arg_t arg = {0, sizeof(UNICODE_STRING),
                             SYSARG_READ|SYSARG_COMPLEX_TYPE,
                             SYSARG_TYPE_UNICODE_STRING};
        handle_unicode_string_access(pre, sysnum, mc, 0/*unused*/,
                                     &arg, pvParam, sizeof(UNICODE_STRING), false);
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
        handle_logfont(pre, drcontext, sysnum, mc, pvParam,
                       uiParam, SYSARG_WRITE, NULL);
        get = true;
        uses_uiParam = true;
        uses_pvParam = true;
        break;
    }
    case SPI_SETICONTITLELOGFONT: {
        handle_logfont(pre, drcontext, sysnum, mc, pvParam,
                       uiParam, SYSARG_READ, NULL);
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
        handle_nonclientmetrics(pre, drcontext, sysnum, mc, pvParam,
                                SYSARG_WRITE, NULL);
        get = true;
        uses_uiParam = true;
        uses_pvParam = true;
        break;
    }
    case SPI_SETNONCLIENTMETRICS: {
        handle_nonclientmetrics(pre, drcontext, sysnum, mc, pvParam,
                                SYSARG_READ, NULL);
        get = false;
        uses_uiParam = true;
        uses_pvParam = true;
        break;
    }
    case SPI_GETMINIMIZEDMETRICS: get = true;  uses_uiParam = true; sz = uiParam; break;
    case SPI_SETMINIMIZEDMETRICS: get = false; uses_uiParam = true; sz = uiParam; break;
    case SPI_GETICONMETRICS: {
        handle_iconmetrics(pre, drcontext, sysnum, mc, pvParam, SYSARG_WRITE, NULL);
        get = true;
        uses_uiParam = true;
        uses_pvParam = true;
        break;
    }
    case SPI_SETICONMETRICS: {
        handle_iconmetrics(pre, drcontext, sysnum, mc, pvParam, SYSARG_READ, NULL);
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
        handle_serialkeys(pre, drcontext, sysnum, mc, pvParam, SYSARG_WRITE, NULL);
        get = true;
        uses_uiParam = true;
        uses_pvParam = true;
        break;
    }
    case SPI_SETSERIALKEYS: {
        handle_serialkeys(pre, drcontext, sysnum, mc, pvParam, SYSARG_READ, NULL);
        get = false;
        uses_uiParam = true;
        uses_pvParam = true;
        break;
    }
    case SPI_GETSOUNDSENTRY: {
        handle_cwstring_field(pre, sysnum, mc, "SOUNDSENTRYW.lpszWindowsEffectDLL",
                              SYSARG_WRITE, pvParam, uiParam,
                              offsetof(SOUNDSENTRYW, lpszWindowsEffectDLL));
        /* rest of struct handled through pvParam check below */
        get = true;
        uses_uiParam = true;
        sz = uiParam;
        break;
    }
    case SPI_SETSOUNDSENTRY: {
        handle_cwstring_field(pre, sysnum, mc, "SOUNDSENTRYW.lpszWindowsEffectDLL",
                              SYSARG_READ, pvParam, uiParam,
                              offsetof(SOUNDSENTRYW, lpszWindowsEffectDLL));
        /* rest of struct handled through pvParam check below */
        get = false;
        uses_uiParam = true;
        sz = uiParam;
        break;
    }
    case SPI_GETHIGHCONTRAST: {
        handle_cwstring_field(pre, sysnum, mc, "HIGHCONTRASTW.lpszDefaultScheme",
                              SYSARG_WRITE, pvParam, uiParam,
                              offsetof(HIGHCONTRASTW, lpszDefaultScheme));
        /* rest of struct handled through pvParam check below */
        get = true;
        uses_uiParam = true;
        sz = uiParam;
        break;
    }
    case SPI_SETHIGHCONTRAST: {
        handle_cwstring_field(pre, sysnum, mc, "HIGHCONTRASTW.lpszDefaultScheme",
                              SYSARG_READ, pvParam, uiParam,
                              offsetof(HIGHCONTRASTW, lpszDefaultScheme));
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
    if (uses_uiParam && pre)
        check_sysparam_defined(sysnum, 1, mc, sizeof(reg_t));
    if (sz > 0 || uses_pvParam) { /* pvParam is used */
        if (pre)
            check_sysparam_defined(sysnum, 2, mc, sizeof(reg_t));
        if (get && sz > 0) {
            check_sysmem(pre ? MEMREF_CHECK_ADDRESSABLE : MEMREF_WRITE, sysnum, 
                         pvParam, sz, mc, "pvParam");
        } else if (pre && sz > 0)
            check_sysmem(MEMREF_CHECK_DEFINEDNESS, sysnum, pvParam, sz, mc, "pvParam");
    }
    if (!get && pre) /* fWinIni used for all SET codes */
        check_sysparam_defined(sysnum, 3, mc, sizeof(reg_t));

    return true;
}

static bool
handle_UserMenuInfo(bool pre, void *drcontext, int sysnum, per_thread_t *pt,
                        dr_mcontext_t *mc)
{
    /* 3rd param is bool saying whether it's Set or Get */
    BOOL set = (BOOL) pt->sysarg[3];
    uint check_type = SYSARG_CHECK_TYPE(set ? SYSARG_READ : SYSARG_WRITE, pre);
    MENUINFO info;
    /* user must set cbSize for set or get */
    if (pre) {
        check_sysmem(MEMREF_CHECK_DEFINEDNESS, sysnum, (byte *) pt->sysarg[1],
                     sizeof(info.cbSize), mc, "MENUINFOW.cbSize");
    }
    if (safe_read((byte *) pt->sysarg[3], sizeof(info), &info)) {
        check_sysmem(check_type, sysnum, (byte *) pt->sysarg[3],
                     info.cbSize, mc, "MENUINFOW");
    } else
        WARN("WARNING: unable to read syscall param\n");
    return true;
}

static bool
handle_UserMenuItemInfo(bool pre, void *drcontext, int sysnum, per_thread_t *pt,
                        dr_mcontext_t *mc)
{
    /* 4th param is bool saying whether it's Set or Get */
    BOOL set = (BOOL) pt->sysarg[4];
    syscall_arg_t arg = {0, 0,
                         (set ? SYSARG_READ : SYSARG_WRITE)|SYSARG_COMPLEX_TYPE,
                         SYSARG_TYPE_MENUITEMINFOW};
    handle_menuiteminfow_access(pre, sysnum, mc, 0/*unused*/,
                                &arg, (byte *) pt->sysarg[3], 0);
    return true;
}

static bool
handle_UserGetAltTabInfo(bool pre, void *drcontext, int sysnum, per_thread_t *pt,
                         dr_mcontext_t *mc)
{
    /* buffer is ansi or unicode depending on arg 5; size (arg 4) is in chars */
    BOOL ansi = (BOOL) pt->sysarg[5];
    uint check_type = SYSARG_CHECK_TYPE(SYSARG_WRITE, pre);
    UINT count = (UINT) pt->sysarg[4];
    check_sysmem(check_type, sysnum, (byte *) pt->sysarg[3],
                 count * (ansi ? sizeof(char) : sizeof(wchar_t)),
                 mc, "pszItemText");
    return true;
}

static bool
handle_UserGetRawInputBuffer(bool pre, void *drcontext, int sysnum, per_thread_t *pt,
                             dr_mcontext_t *mc)
{
    uint check_type = SYSARG_CHECK_TYPE(SYSARG_WRITE, pre);
    byte *buf = (byte *) pt->sysarg[0];
    UINT size;
    if (buf == NULL) {
        /* writes out total buffer size needed in bytes to param #1 */
        check_sysmem(check_type, sysnum, (byte *) pt->sysarg[1],
                     sizeof(UINT), mc, "pcbSize");
    } else {
        if (pre) {
            /* FIXME i#485: we don't know the number of array entries so we
             * can't check addressability pre-syscall: comes from a prior
             * buf==NULL call
             */
        } else if (safe_read((byte *) pt->sysarg[1], sizeof(size), &size)) {
            /* param #1 holds size of each RAWINPUT array entry */
            size = (size * dr_syscall_get_result(drcontext)) +
                /* param #2 holds header size */
                (UINT) pt->sysarg[2];
            check_sysmem(check_type, sysnum, buf, size, mc, "pData");
        } else
            WARN("WARNING: unable to read syscall param\n");
    }
    return true;
}

static bool
handle_UserGetRawInputData(bool pre, void *drcontext, int sysnum, per_thread_t *pt,
                           dr_mcontext_t *mc)
{
    byte *buf = (byte *) pt->sysarg[2];
    /* arg #3 is either R or W.  when W buf must be NULL and the 2,-3,WI entry
     * will do a safe_read but won't do a check so no false pos.
     */
    uint check_type = SYSARG_CHECK_TYPE((buf == NULL) ? SYSARG_WRITE : SYSARG_READ, pre);
    check_sysmem(check_type, sysnum, (byte *) pt->sysarg[3], sizeof(UINT), mc, "pcbSize");
    return true;
}

static bool
handle_UserGetRawInputDeviceInfo(bool pre, void *drcontext, int sysnum, per_thread_t *pt,
                                 dr_mcontext_t *mc)
{
    uint check_type = SYSARG_CHECK_TYPE(SYSARG_WRITE, pre);
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
        check_sysmem(check_type, sysnum, (byte *) pt->sysarg[2], size, mc, "pData");
        if (pt->sysarg[2] == 0) {
            /* XXX i#486: if buffer is not large enough, returns -1 but still
             * sets *pcbSize
             */
            check_sysmem(check_type, sysnum, (byte *) pt->sysarg[3],
                         sizeof(UINT), mc, "pData");
        }
    } else
        WARN("WARNING: unable to read syscall param\n");
    return true;
}

static bool
handle_UserTrackMouseEvent(bool pre, void *drcontext, int sysnum, per_thread_t *pt,
                           dr_mcontext_t *mc)
{
    DWORD dwFlags = (BOOL) pt->sysarg[3];
    TRACKMOUSEEVENT *safe;
    byte buf[offsetof(TRACKMOUSEEVENT, dwFlags) + sizeof(safe->dwFlags)];
    /* user must set cbSize and dwFlags */
    if (pre) {
        check_sysmem(MEMREF_CHECK_DEFINEDNESS, sysnum, (byte *) pt->sysarg[0],
                     offsetof(TRACKMOUSEEVENT, dwFlags) + sizeof(safe->dwFlags),
                     mc, "TRACKMOUSEEVENT cbSize+dwFlags");
    }
    if (safe_read((byte *) pt->sysarg[0], BUFFER_SIZE_BYTES(buf), buf)) {
        uint check_type;
        safe = (TRACKMOUSEEVENT *) buf;
        /* XXX: for non-TME_QUERY are the other fields read? */
        check_type = SYSARG_CHECK_TYPE(TEST(TME_QUERY, safe->dwFlags) ?
                                       SYSARG_WRITE : SYSARG_READ, pre);
        if (safe->cbSize > BUFFER_SIZE_BYTES(buf)) {
            check_sysmem(check_type, sysnum,
                         ((byte *)pt->sysarg[0]) + BUFFER_SIZE_BYTES(buf),
                         safe->cbSize - BUFFER_SIZE_BYTES(buf), mc,
                         "TRACKMOUSEEVENT post-dwFlags");
        }
    } else
        WARN("WARNING: unable to read syscall param\n");
    return true;
}

static bool
handle_UserCallTwoParam(bool pre, void *drcontext, int sysnum, per_thread_t *pt,
                        dr_mcontext_t *mc)
{
    DWORD code = (DWORD) pt->sysarg[2];
    /* FIXME i#389: codes vary by platform so need a per-OS table, and need
     * to handle the rest of them
     */
    if (get_windows_version() == DR_WINDOWS_VERSION_7 &&
        code == 0x6a /* TWOPARAM_ROUTINE_INITANSIOEM */) {
        /* 2nd param is an OUT wide string */
        handle_cwstring(pre, sysnum, mc, "TWOPARAM_ROUTINE_INITANSIOEM",
                        (byte *) pt->sysarg[1], 0, SYSARG_WRITE, NULL, true);
    }
    return true;
}

static bool
handle_GdiCreateDIBSection(bool pre, void *drcontext, int sysnum, per_thread_t *pt,
                           dr_mcontext_t *mc)
{
    byte *dib;
    if (pre)
        return true;
    if (safe_read((byte *) pt->sysarg[8], sizeof(dib), &dib)) {
        /* XXX: move this into common/alloc.c since that's currently
         * driving all the known allocs, heap and otherwise
         */
        byte *dib_base;
        size_t dib_size;
        if (dr_query_memory(dib, &dib_base, &dib_size, NULL)) {
            LOG(SYSCALL_VERBOSE, "NtGdiCreateDIBSection created "PFX"-"PFX"\n",
                dib_base, dib_base+dib_size);
            client_handle_mmap(pt, dib_base, dib_size,
                               /* XXX: may not be file-backed but treating as
                                * all-defined and non-heap which is what this param
                                * does today.  could do dr_virtual_query().
                                */
                               true/*file-backed*/);
        } else
            WARN("WARNING: unable to query DIB section "PFX"\n", dib);
    } else
        WARN("WARNING: unable to read NtGdiCreateDIBSection param\n");
    /* When passed-in section pointer is NULL, the return value is
     * HBITMAP but doesn't seem to be a real memory address, which is
     * odd, b/c presumably when a section is used it would be a real
     * memory address, right?  The value is typically large so clearly
     * not just a table index.  Xref i#539.
     */
    return true;
}

static bool
handle_GdiHfontCreate(bool pre, void *drcontext, int sysnum, per_thread_t *pt,
                      dr_mcontext_t *mc)
{
    ENUMLOGFONTEXDVW dvw;
    ENUMLOGFONTEXDVW *real_dvw = (ENUMLOGFONTEXDVW *) pt->sysarg[0];
    if (pre && safe_read((byte *) pt->sysarg[0], sizeof(dvw), &dvw)) {
        uint i;
        byte *start = (byte *) pt->sysarg[0];
        ULONG total_size = (ULONG) pt->sysarg[1];
        /* Would be: {0,-1,R,}
         * Except not all fields need to be defined.
         * If any other syscall turns out to have this param type should
         * turn this into a type handler and not a syscall handler.
         */
        check_sysmem(MEMREF_CHECK_ADDRESSABLE, sysnum, start,
                     total_size, mc, "ENUMLOGFONTEXDVW");

        ASSERT(offsetof(ENUMLOGFONTEXDVW, elfEnumLogfontEx) == 0 &&
               offsetof(ENUMLOGFONTEXW, elfLogFont) == 0, "logfont structs changed");
        handle_logfont(pre, drcontext, sysnum, mc, start,
                       sizeof(LOGFONTW), SYSARG_READ, &dvw.elfEnumLogfontEx.elfLogFont);

        start = (byte *) &real_dvw->elfEnumLogfontEx.elfFullName;
        for (i = 0;
             i < sizeof(dvw.elfEnumLogfontEx.elfFullName)/sizeof(wchar_t) &&
                 dvw.elfEnumLogfontEx.elfFullName[i] != L'\0';
             i++)
            ; /* nothing */
        check_sysmem(MEMREF_CHECK_DEFINEDNESS, sysnum, start,
                     i * sizeof(wchar_t), mc, "ENUMLOGFONTEXW.elfFullName");

        start = (byte *) &real_dvw->elfEnumLogfontEx.elfStyle;
        for (i = 0;
             i < sizeof(dvw.elfEnumLogfontEx.elfStyle)/sizeof(wchar_t) &&
                 dvw.elfEnumLogfontEx.elfStyle[i] != L'\0';
             i++)
            ; /* nothing */
        check_sysmem(MEMREF_CHECK_DEFINEDNESS, sysnum, start,
                     i * sizeof(wchar_t), mc, "ENUMLOGFONTEXW.elfStyle");

        start = (byte *) &real_dvw->elfEnumLogfontEx.elfScript;
        for (i = 0;
             i < sizeof(dvw.elfEnumLogfontEx.elfScript)/sizeof(wchar_t) &&
                 dvw.elfEnumLogfontEx.elfScript[i] != L'\0';
             i++)
            ; /* nothing */
        check_sysmem(MEMREF_CHECK_DEFINEDNESS, sysnum, start,
                     i * sizeof(wchar_t), mc, "ENUMLOGFONTEXW.elfScript");

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
        check_sysmem(MEMREF_CHECK_DEFINEDNESS, sysnum, start,
                     offsetof(DESIGNVECTOR, dvValues) +
                     dvw.elfDesignVector.dvNumAxes * sizeof(LONG),
                     mc, "DESIGNVECTOR");
    } else if (pre)
        WARN("WARNING: unable to read NtGdiHfontCreate param\n");
    return true;
}

static bool
handle_GdiDoPalette(bool pre, void *drcontext, int sysnum, per_thread_t *pt,
                    dr_mcontext_t *mc)
{
    /* Entry would read: {3,-2,R|SYSARG_SIZE_IN_ELEMENTS,sizeof(PALETTEENTRY)}
     * But pPalEntries is an OUT param if !bInbound.
     * It's a convenient arg: else would have to look at iFunc.
     */
    WORD cEntries = (WORD) pt->sysarg[2];
    PALETTEENTRY *pPalEntries = (PALETTEENTRY *) pt->sysarg[3];
    bool bInbound = (bool) pt->sysarg[5];
    if (bInbound && pre) {
        check_sysmem(MEMREF_CHECK_DEFINEDNESS, sysnum, (byte *) pPalEntries,
                     cEntries * sizeof(PALETTEENTRY), mc, "pPalEntries");
    } else if (!bInbound) {
        check_sysmem(pre ? MEMREF_CHECK_ADDRESSABLE : MEMREF_WRITE, sysnum,
                     (byte *) pPalEntries,
                     cEntries * sizeof(PALETTEENTRY), mc, "pPalEntries");
    }
    return true;
}

static bool
handle_GdiOpenDCW(bool pre, void *drcontext, int sysnum, per_thread_t *pt,
                  dr_mcontext_t *mc)
{
    /* An extra arg "BOOL bDisplay" was added as arg #4 in Vista so
     * we have to special-case the subsequent args, which for Vista+ are:
     *   {6,sizeof(DRIVER_INFO_2W),R,}, {7,sizeof(PUMDHPDEV *),W,},
     */
    uint num_driver = 5;
    uint num_pump = 6;
    if (running_on_Vista_or_later()) {
        if (pre)
            check_sysparam_defined(sysnum, 7, mc, sizeof(reg_t));
        num_driver = 6;
        num_pump = 7;
    }
    if (pre) {
        check_sysmem(MEMREF_CHECK_DEFINEDNESS, sysnum,
                     (byte *) pt->sysarg[num_driver], sizeof(DRIVER_INFO_2W),
                     mc, "DRIVER_INFO_2W");
    }
    check_sysmem(pre ? MEMREF_CHECK_ADDRESSABLE : MEMREF_WRITE, sysnum,
                 (byte *) pt->sysarg[num_pump], sizeof(PUMDHPDEV *),
                 mc, "PUMDHPDEV*");
    return true;
}

bool
wingdi_process_syscall(bool pre, void *drcontext, int sysnum, per_thread_t *pt,
                       dr_mcontext_t *mc)
{
    /* handlers here do not check for success so we check up front */
    if (!pre) {
        syscall_info_t *sysinfo = syscall_lookup(sysnum);
        if (!os_syscall_succeeded(sysnum, sysinfo, dr_syscall_get_result(drcontext)))
            return true;
    }
    if (sysnum == sysnum_UserSystemParametersInfo) {
        return handle_UserSystemParametersInfo(pre, drcontext, sysnum, pt, mc);
    } else if (sysnum == sysnum_UserMenuInfo) {
        return handle_UserMenuInfo(pre, drcontext, sysnum, pt, mc);
    } else if (sysnum == sysnum_UserMenuItemInfo) {
        return handle_UserMenuItemInfo(pre, drcontext, sysnum, pt, mc);
    } else if (sysnum == sysnum_UserGetAltTabInfo) {
        return handle_UserGetAltTabInfo(pre, drcontext, sysnum, pt, mc);
    } else if (sysnum == sysnum_UserGetRawInputBuffer) {
        return handle_UserGetRawInputBuffer(pre, drcontext, sysnum, pt, mc);
    } else if (sysnum == sysnum_UserGetRawInputData) {
        return handle_UserGetRawInputData(pre, drcontext, sysnum, pt, mc);
    } else if (sysnum == sysnum_UserGetRawInputDeviceInfo) {
        return handle_UserGetRawInputDeviceInfo(pre, drcontext, sysnum, pt, mc);
    } else if (sysnum == sysnum_UserTrackMouseEvent) {
        return handle_UserTrackMouseEvent(pre, drcontext, sysnum, pt, mc);
    } else if (sysnum == sysnum_UserCreateWindowStation ||
               sysnum == sysnum_UserLoadKeyboardLayoutEx) {
        /* Vista SP1 added one arg (both were 7, now 8)
         * FIXME i#487: figure out what it is and whether we need to process it
         * for each of the two syscalls.
         * Also check whether it's defined after first deciding whether
         * we're on SP1: use core's method of checking for export?
         */
    } else if (sysnum == sysnum_UserCallTwoParam) {
        return handle_UserCallTwoParam(pre, drcontext, sysnum, pt, mc);
    } else if (sysnum == sysnum_GdiCreatePaletteInternal) {
        /* Entry would read: {0,cEntries * 4  + 4,R,} but see comment in ntgdi.h */
        if (pre) {
            UINT cEntries = (UINT) pt->sysarg[1];
            check_sysmem(MEMREF_CHECK_DEFINEDNESS, sysnum, (byte *)pt->sysarg[0],
                         sizeof(LOGPALETTE) - sizeof(PALETTEENTRY) +
                         sizeof(PALETTEENTRY) * cEntries, mc, "pLogPal");
        }
    } else if (sysnum == sysnum_GdiCheckBitmapBits) {
        /* Entry would read: {7,dwWidth * dwHeight,W,} */
        DWORD dwWidth = (DWORD) pt->sysarg[4];
        DWORD dwHeight = (DWORD) pt->sysarg[5];
        check_sysmem(pre ? MEMREF_CHECK_ADDRESSABLE : MEMREF_WRITE, sysnum,
                     (byte *)pt->sysarg[7], dwWidth * dwHeight, mc, "paResults");
    } else if (sysnum == sysnum_GdiCreateDIBSection) {
        return handle_GdiCreateDIBSection(pre, drcontext, sysnum, pt, mc);
    } else if (sysnum == sysnum_GdiHfontCreate) {
        return handle_GdiHfontCreate(pre, drcontext, sysnum, pt, mc);
    } else if (sysnum == sysnum_GdiDoPalette) {
        return handle_GdiDoPalette(pre, drcontext, sysnum, pt, mc);
    } else if (sysnum == sysnum_GdiExtTextOutW) {
        UINT fuOptions = (UINT) pt->sysarg[3];
        int cwc = (int) pt->sysarg[6];
        INT *pdx = (INT *) pt->sysarg[7];
        if (pre && TEST(ETO_PDY, fuOptions)) {
            /* pdx contains pairs of INTs.  regular entry already checked
             * size of singletons of INTs so here we check the extra size.
             */
            check_sysmem(MEMREF_CHECK_DEFINEDNESS, sysnum, ((byte *)pdx) + cwc*sizeof(INT),
                         cwc*sizeof(INT), mc, "pdx extra size from ETO_PDY");
        }
    } else if (sysnum == sysnum_GdiOpenDCW) {
        return handle_GdiOpenDCW(pre, drcontext, sysnum, pt, mc);
    }

    return true; /* execute syscall */
}

