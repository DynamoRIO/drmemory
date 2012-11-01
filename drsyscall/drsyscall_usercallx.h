/* **********************************************************
 * Copyright (c) 2011-2012 Google, Inc.  All rights reserved.
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

/* Secondary system calls for:
 *   NtUserCallHwnd
 *   NtUserCallHwndLock
 *   NtUserCallHwndOpt
 *   NtUserCallHwndParam
 *   NtUserCallHwndParamLock
 *   NtUserCallMsgFilter
 *   NtUserCallNextHookEx
 *   NtUserCallNoParam
 *   NtUserCallOneParam
 *   NtUserCallTwoParam
 * Initial added as part of i#389.
 */

/* Numbers are for 5 platforms:
 * USERCALL(type, name, w7, vistaSP2, vistaSP01, 2003, xp, w2k)
 *
 * We assume 64-bit matches 32-bit.
 *
 * FIXME i#728:
 * + get the syscall numbers for Windows 2000
 * + verify all the intermediate calls for Windows 7.
 *   for i#389 I verified calls at a number of points throughout the list.
 * + verify all the intermediate calls for Vista SP2.
 *   for i#819 I verified calls made by NtUserTests in app_suite.
 * + determine the currently-unknown calls: there are a small number whose names
 *   and params are unknown
 */

/* N.B.: this list must contain the same number of entries as syscall_usercall_info[]
 * in syscall_wingdi.c
 */
USERCALL(NtUserCallNoParam, CREATEMENU,                     0x00, 0x00, 0x00, 0x00, 0x00, NONE)
USERCALL(NtUserCallNoParam, CREATEMENUPOPUP,                0x01, 0x01, 0x01, 0x01, 0x01, NONE)
USERCALL(NtUserCallNoParam, DISABLEPROCWNDGHSTING,          0x07, 0x07, 0x06, 0x02, 0x02, NONE)
USERCALL(NtUserCallNoParam, MSQCLEARWAKEMASK,               0x03, 0x03, 0x03, 0x03, 0x03, NONE)
USERCALL(NtUserCallNoParam, ALLOWFOREGNDACTIVATION,         0x02, 0x02, 0x02, 0x04, 0x04, NONE)
USERCALL(NtUserCallNoParam, CREATESYSTEMTHREADS,            NONE, NONE, 0x04, NONE, NONE, NONE)
/* XXX i#484: win7 seems to have added something here since the rest are all shifted */
USERCALL(NtUserCallNoParam, UNKNOWN,                        0x05, 0x05, NONE, NONE, NONE, NONE)
USERCALL(NtUserCallNoParam, DESTROY_CARET,                  0x06, 0x06, 0x05, 0x05, 0x05, NONE)
USERCALL(NtUserCallNoParam, GETDEVICECHANGEINFO,            0x08, 0x08, 0x07, 0x06, 0x06, NONE)
USERCALL(NtUserCallNoParam, GETIMESHOWSTATUS,               0x09, 0x09, 0x08, 0x07, 0x07, NONE)
USERCALL(NtUserCallNoParam, GETINPUTDESKTOP,                0x0a, 0x0a, 0x09, 0x08, 0x08, NONE)
USERCALL(NtUserCallNoParam, GETMESSAGEPOS,                  0x0b, 0x0b, 0x0a, 0x09, 0x09, NONE)
USERCALL(NtUserCallNoParam, GETREMOTEPROCID,                NONE, NONE, NONE, 0x0a, 0x0a, NONE)
USERCALL(NtUserCallNoParam, HIDECURSORNOCAPTURE,            0x0d, 0x0d, 0x0c, 0x0b, 0x0b, NONE)
USERCALL(NtUserCallNoParam, LOADCURSANDICOS,                0x0e, 0x0e, 0x0d, 0x0c, 0x0c, NONE)
USERCALL(NtUserCallNoParam, PREPAREFORLOGOFF,               0x10, 0x10, 0x0f, NONE, NONE, NONE)
USERCALL(NtUserCallNoParam, RELEASECAPTURE,                 0x11, 0x11, 0x10, 0x0d, 0x0d, NONE)
USERCALL(NtUserCallNoParam, RESETDBLCLICK,                  0x12, 0x12, 0x11, 0x0e, 0x0e, NONE)
USERCALL(NtUserCallNoParam, ZAPACTIVEANDFOUS,               0x13, 0x13, 0x12, 0x0f, 0x0f, NONE)
USERCALL(NtUserCallNoParam, REMOTECONSHDWSTOP,              0x14, 0x14, 0x13, 0x10, 0x10, NONE)
USERCALL(NtUserCallNoParam, REMOTEDISCONNECT,               0x15, 0x15, 0x14, 0x11, 0x11, NONE)
USERCALL(NtUserCallNoParam, REMOTELOGOFF,                   0x16, 0x16, 0x15, 0x12, 0x12, NONE)
USERCALL(NtUserCallNoParam, REMOTENTSECURITY,               0x17, 0x17, 0x16, 0x13, 0x13, NONE)
USERCALL(NtUserCallNoParam, REMOTESHDWSETUP,                0x18, 0x18, 0x17, 0x14, 0x14, NONE)
USERCALL(NtUserCallNoParam, REMOTESHDWSTOP,                 0x19, 0x19, 0x18, 0x15, 0x15, NONE)
USERCALL(NtUserCallNoParam, REMOTEPASSTHRUENABLE,           0x1a, 0x1a, 0x19, 0x16, 0x16, NONE)
USERCALL(NtUserCallNoParam, REMOTEPASSTHRUDISABLE,          0x1b, 0x1b, 0x1a, 0x17, 0x17, NONE)
USERCALL(NtUserCallNoParam, REMOTECONNECTSTATE,             0x1c, 0x1c, 0x1b, 0x18, 0x18, NONE)
USERCALL(NtUserCallNoParam, UPDATEPERUSERIMMENABLING,       0x1d, 0x1d, 0x1c, 0x19, 0x19, NONE)
USERCALL(NtUserCallNoParam, USERPWRCALLOUTWORKER,           0x1e, 0x1e, 0x1d, 0x1a, 0x1a, NONE)
USERCALL(NtUserCallNoParam, WAKERITFORSHTDWN,               0x1f, 0x1f, 0x1e, NONE, NONE, NONE)
USERCALL(NtUserCallNoParam, INIT_MESSAGE_PUMP,              0x20, 0x20, 0x1f, 0x1b, 0x1b, NONE)
USERCALL(NtUserCallNoParam, UNINIT_MESSAGE_PUMP,            0x21, 0x21, 0x20, 0x1c, 0x1c, NONE)
USERCALL(NtUserCallNoParam, LOADUSERAPIHOOK,                0x0f, 0x0f, 0x0e, 0x1d, 0x1d, NONE)
USERCALL(NtUserCallOneParam, BEGINDEFERWNDPOS,              0x22, 0x22, 0x21, 0x1e, 0x1e, NONE)
USERCALL(NtUserCallOneParam, GETSENDMSGRECVR,               0x23, 0x23, 0x22, NONE, NONE, NONE)
USERCALL(NtUserCallOneParam, WINDOWFROMDC,                  0x24, 0x24, 0x23, 0x1f, 0x1f, NONE)
USERCALL(NtUserCallOneParam, ALLOWSETFOREGND,               0x25, 0x25, 0x24, 0x20, 0x20, NONE)
USERCALL(NtUserCallOneParam, CREATEEMPTYCUROBJECT,          0x26, 0x26, 0x25, 0x21, 0x21, NONE)
USERCALL(NtUserCallOneParam, CREATESYSTEMTHREADS,           0x05, 0x05, NONE, 0x22, 0x22, NONE)
USERCALL(NtUserCallOneParam, CSDDEUNINITIALIZE,             0x27, 0x27, 0x26, 0x23, 0x23, NONE)
USERCALL(NtUserCallOneParam, DIRECTEDYIELD,                 0x28, 0x28, 0x27, 0x24, 0x24, NONE)
USERCALL(NtUserCallOneParam, ENUMCLIPBOARDFORMATS,          0x29, 0x29, 0x28, 0x25, 0x25, NONE)
USERCALL(NtUserCallOneParam, GETCURSORPOS,                  NONE, NONE, NONE, 0x26, 0x26, NONE)
USERCALL(NtUserCallOneParam, GETINPUTEVENT,                 0x2a, 0x2a, 0x29, 0x27, 0x27, NONE)
USERCALL(NtUserCallOneParam, GETKEYBOARDLAYOUT,             0x2b, 0x2b, 0x2a, 0x28, 0x28, NONE)
USERCALL(NtUserCallOneParam, GETKEYBOARDTYPE,               0x2c, 0x2c, 0x2b, 0x29, 0x29, NONE)
USERCALL(NtUserCallOneParam, GETPROCDEFLAYOUT,              0x2d, 0x2d, 0x2c, 0x2a, 0x2a, NONE)
USERCALL(NtUserCallOneParam, GETQUEUESTATUS,                0x2e, 0x2e, 0x2d, 0x2b, 0x2b, NONE)
USERCALL(NtUserCallOneParam, GETWINSTAINFO,                 0x2f, 0x2f, 0x2e, 0x2c, 0x2c, NONE)
USERCALL(NtUserCallOneParam, HANDLESYSTHRDCREATFAIL,        0x0c, 0x0c, 0x0b, 0x2d, 0x2d, NONE)
USERCALL(NtUserCallOneParam, LOCKFOREGNDWINDOW,             0x30, 0x30, 0x2f, 0x2e, 0x2e, NONE)
USERCALL(NtUserCallOneParam, LOADFONTS,                     0x31, 0x31, 0x30, 0x2f, 0x2f, NONE)
USERCALL(NtUserCallOneParam, MAPDEKTOPOBJECT,               0x32, 0x32, 0x31, 0x30, 0x30, NONE)
USERCALL(NtUserCallOneParam, MESSAGEBEEP,                   0x33, 0x33, 0x32, 0x31, 0x31, NONE)
USERCALL(NtUserCallOneParam, PLAYEVENTSOUND,                0x34, 0x34, 0x33, 0x32, 0x32, NONE)
USERCALL(NtUserCallOneParam, POSTQUITMESSAGE,               0x35, 0x35, 0x34, 0x33, 0x33, NONE)
USERCALL(NtUserCallOneParam, PREPAREFORLOGOFF,              0x10, 0x10, 0x0f, 0x34, 0x34, NONE)
USERCALL(NtUserCallOneParam, REALIZEPALETTE,                0x36, 0x36, 0x35, 0x35, 0x35, NONE)
USERCALL(NtUserCallOneParam, REGISTERLPK,                   0x37, 0x37, 0x36, 0x36, 0x36, NONE)
USERCALL(NtUserCallOneParam, REGISTERSYSTEMTHREAD,          0x38, 0x38, 0x37, NONE, NONE, NONE)
USERCALL(NtUserCallOneParam, REMOTERECONNECT,               0x39, 0x39, 0x38, 0x37, 0x37, NONE)
USERCALL(NtUserCallOneParam, REMOTETHINWIRESTATUS,          0x3a, 0x3a, 0x39, 0x38, 0x38, NONE)
USERCALL(NtUserCallOneParam, RELEASEDC,                     0x3b, 0x3b, 0x3a, 0x39, 0x39, NONE)
USERCALL(NtUserCallOneParam, REMOTENOTIFY,                  0x3c, 0x3c, 0x3b, NONE, NONE, NONE)
USERCALL(NtUserCallOneParam, REPLYMESSAGE,                  0x3d, 0x3d, 0x3c, 0x3a, 0x3a, NONE)
USERCALL(NtUserCallOneParam, SETCARETBLINKTIME,             0x3e, 0x3e, 0x3d, 0x3b, 0x3b, NONE)
USERCALL(NtUserCallOneParam, SETDBLCLICKTIME,               0x3f, 0x3f, 0x3e, 0x3c, 0x3c, NONE)
USERCALL(NtUserCallOneParam, SETIMESHOWSTATUS,              NONE, NONE, NONE, 0x3d, 0x3d, NONE)
USERCALL(NtUserCallOneParam, SETMESSAGEEXTRAINFO,           0x40, 0x40, 0x3f, 0x3e, 0x3e, NONE)
USERCALL(NtUserCallOneParam, SETPROCDEFLAYOUT,              0x41, 0x41, 0x40, 0x3f, 0x3f, NONE)
USERCALL(NtUserCallOneParam, SETWATERMARKSTRINGS,           0x42, 0x42, 0x41, NONE, NONE, NONE)
USERCALL(NtUserCallOneParam, SHOWCURSOR,                    0x43, 0x43, 0x42, 0x40, 0x40, NONE)
USERCALL(NtUserCallOneParam, SHOWSTARTGLASS,                0x44, 0x44, 0x43, 0x41, 0x41, NONE)
USERCALL(NtUserCallOneParam, SWAPMOUSEBUTTON,               0x45, 0x45, 0x44, 0x42, 0x42, NONE)
USERCALL(NtUserCallOneParam, UNKNOWNA,                      0x46, 0x46, 0x45, 0x43, 0x43, NONE)
USERCALL(NtUserCallOneParam, UNKNOWNB,                      NONE, NONE, NONE, 0x44, 0x44, NONE)
USERCALL(NtUserCallHwnd, DEREGISTERSHELLHOOKWINDOW,         0x47, 0x47, 0x46, 0x45, 0x45, NONE)
USERCALL(NtUserCallHwnd, DWP_GETENABLEDPOPUP,               0x48, 0x48, 0x47, 0x46, 0x46, NONE)
USERCALL(NtUserCallHwnd, GETWNDCONTEXTHLPID,                0x49, 0x49, 0x48, 0x47, 0x47, NONE)
USERCALL(NtUserCallHwnd, REGISTERSHELLHOOKWINDOW,           0x4a, 0x4a, 0x49, 0x48, 0x48, NONE)
USERCALL(NtUserCallHwnd, UNKNOWN,                           0x4b, 0x4b, 0x4a, 0x49, 0x49, NONE)
USERCALL(NtUserCallHwndOpt, SETPROGMANWINDOW,               0x4c, 0x4c, 0x4b, 0x4a, 0x4a, NONE)
USERCALL(NtUserCallHwndOpt, SETTASKMANWINDOW,               0x4d, 0x4d, 0x4c, 0x4b, 0x4b, NONE)
USERCALL(NtUserCallHwndParam, GETCLASSICOCUR,               0x4e, 0x4e, 0x4d, 0x4c, 0x4c, NONE)
USERCALL(NtUserCallHwndParam, CLEARWINDOWSTATE,             0x4f, 0x4f, 0x4e, 0x4d, 0x4d, NONE)
USERCALL(NtUserCallHwndParam, KILLSYSTEMTIMER,              0x50, 0x50, 0x4f, 0x4e, 0x4e, NONE)
USERCALL(NtUserCallHwndParam, SETDIALOGPOINTER,             0x51, 0x51, 0x50, 0x4f, 0x4f, NONE)
USERCALL(NtUserCallHwndParam, SETVISIBLE,                   0x52, 0x52, 0x51, 0x50, 0x50, NONE)
USERCALL(NtUserCallHwndParam, SETWNDCONTEXTHLPID,           0x53, 0x53, 0x52, 0x51, 0x51, NONE)
USERCALL(NtUserCallHwndParam, SETWINDOWSTATE,               0x54, 0x54, 0x53, 0x52, 0x52, NONE)
USERCALL(NtUserCallHwndLock, WINDOWHASSHADOW,               0x55, 0x55, 0x54, 0x53, 0x53, NONE)
USERCALL(NtUserCallHwndLock, ARRANGEICONICWINDOWS,          0x56, 0x56, 0x55, 0x54, 0x54, NONE)
USERCALL(NtUserCallHwndLock, DRAWMENUBAR,                   0x57, 0x57, 0x56, 0x55, 0x55, NONE)
USERCALL(NtUserCallHwndLock, CHECKIMESHOWSTATUSINTHRD,      0x58, 0x58, 0x57, 0x56, 0x56, NONE)
USERCALL(NtUserCallHwndLock, GETSYSMENUHANDLE,              0x59, 0x59, 0x58, 0x57, 0x57, NONE)
USERCALL(NtUserCallHwndLock, REDRAWFRAME,                   0x5a, 0x5a, 0x59, 0x58, 0x58, NONE)
USERCALL(NtUserCallHwndLock, REDRAWFRAMEANDHOOK,            0x5b, 0x5b, 0x5a, 0x59, 0x59, NONE)
USERCALL(NtUserCallHwndLock, SETDLGSYSMENU,                 0x5c, 0x5c, 0x5b, 0x5a, 0x5a, NONE)
USERCALL(NtUserCallHwndLock, SETFOREGROUNDWINDOW,           0x5d, 0x5d, 0x5c, 0x5b, 0x5b, NONE)
USERCALL(NtUserCallHwndLock, SETSYSMENU,                    0x5e, 0x5e, 0x5d, 0x5c, 0x5c, NONE)
USERCALL(NtUserCallHwndLock, UPDATECKIENTRECT,              0x5f, 0x5f, 0x5e, 0x5d, 0x5d, NONE)
USERCALL(NtUserCallHwndLock, UPDATEWINDOW,                  0x60, 0x60, 0x5f, 0x5e, 0x5e, NONE)
USERCALL(NtUserCallHwndLock, UNKNOWN,                       0x61, 0x61, 0x60, 0x5f, 0x5f, NONE)
USERCALL(NtUserCallTwoParam, ENABLEWINDOW,                  0x62, 0x62, 0x61, 0x60, 0x60, NONE)
USERCALL(NtUserCallTwoParam, REDRAWTITLE,                   0x63, 0x63, 0x62, 0x61, 0x61, NONE)
USERCALL(NtUserCallTwoParam, SHOWOWNEDPOPUPS,               0x64, 0x64, 0x63, 0x62, 0x62, NONE)
USERCALL(NtUserCallTwoParam, SWITCHTOTHISWINDOW,            0x65, 0x65, 0x64, 0x63, 0x63, NONE)
USERCALL(NtUserCallTwoParam, UPDATEWINDOWS,                 0x66, 0x66, 0x65, 0x64, 0x64, NONE)
USERCALL(NtUserCallHwndLockParam, VALIDATERGN,              0x67, 0x67, 0x66, 0x65, 0x65, NONE)
USERCALL(NtUserCallTwoParam, CHANGEWNDMSGFILTER,            0x68, 0x68, 0x67, NONE, NONE, NONE)
USERCALL(NtUserCallTwoParam, GETCURSORPOS,                  0x69, 0x69, 0x68, NONE, NONE, NONE)
USERCALL(NtUserCallTwoParam, GETHDEVNAME,                   0x6a, 0x6a, 0x69, 0x66, 0x66, NONE)
USERCALL(NtUserCallTwoParam, INITANSIOEM,                   0x6b, 0x6b, 0x6a, 0x67, 0x67, NONE)
USERCALL(NtUserCallTwoParam, NLSSENDIMENOTIFY,              0x6c, 0x6c, 0x6b, 0x68, 0x68, NONE)
USERCALL(NtUserCallTwoParam, REGISTERGHSTWND,               0x6d, 0x6d, 0x6c, NONE, NONE, NONE)
USERCALL(NtUserCallTwoParam, REGISTERLOGONPROCESS,          0x6e, 0x6e, 0x6d, 0x69, 0x69, NONE)
USERCALL(NtUserCallTwoParam, REGISTERSYSTEMTHREAD,          NONE, NONE, NONE, 0x6a, 0x6a, NONE)
USERCALL(NtUserCallTwoParam, REGISTERSBLFROSTWND,           0x6f, 0x6f, 0x6e, NONE, NONE, NONE)
USERCALL(NtUserCallTwoParam, REGISTERUSERHUNGAPPHANDLERS,   0x70, 0x70, 0x6f, 0x6b, 0x6b, NONE)
USERCALL(NtUserCallTwoParam, SHADOWCLEANUP,                 0x71, 0x71, 0x70, 0x6c, 0x6c, NONE)
USERCALL(NtUserCallTwoParam, REMOTESHADOWSTART,             0x72, 0x72, 0x71, 0x6d, 0x6d, NONE)
USERCALL(NtUserCallTwoParam, SETCARETPOS,                   0x73, 0x73, 0x72, 0x6e, 0x6e, NONE)
USERCALL(NtUserCallTwoParam, SETCURSORPOS,                  0x74, 0x74, 0x73, 0x6f, 0x6f, NONE)
USERCALL(NtUserCallTwoParam, SETPHYSCURSORPOS,              0x75, 0x75, 0x74, NONE, NONE, NONE)
USERCALL(NtUserCallTwoParam, UNHOOKWINDOWSHOOK,             0x76, 0x76, 0x75, 0x70, 0x70, NONE)
USERCALL(NtUserCallTwoParam, WOWCLEANUP,                    0x77, 0x77, 0x76, 0x71, 0x71, NONE)
