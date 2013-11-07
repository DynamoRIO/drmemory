/* **********************************************************
 * Copyright (c) 2012-2013 Google, Inc.  All rights reserved.
 * **********************************************************/

/* Dr. Memory: the memory debugger
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation;
 * version 2.1 of the License, and no later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * Library General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

/* Routines for determining the version of Windows we're running on.
 */

#include <windows.h>

#include "os_version_win.h"

WinVersion GetWindowsVersion() {
    OSVERSIONINFOEX os_ver;
    memset(&os_ver, 0, sizeof(os_ver));
    os_ver.dwOSVersionInfoSize = sizeof(os_ver);
    BOOL success = GetVersionEx((LPOSVERSIONINFO)&os_ver);
    if (!success) {
        return WIN_UNKNOWN;
    }
    if (os_ver.dwMajorVersion >= 6 && os_ver.dwMinorVersion > 3) {
        return WIN_HIGHER;
    } else if (os_ver.dwMajorVersion == 6 && os_ver.dwMinorVersion == 3) {
        return WIN_8_1;
    } else if (os_ver.dwMajorVersion == 6 && os_ver.dwMinorVersion == 2) {
        return WIN_8;
    } else if (os_ver.dwMajorVersion == 6 && os_ver.dwMinorVersion == 1) {
        return WIN_7;
    } else if (os_ver.dwMajorVersion == 6 && os_ver.dwMinorVersion == 0) {
        return WIN_VISTA;
    } else if (os_ver.dwMajorVersion == 5) {
        return WIN_XP;
    } else {
        return WIN_UNKNOWN;
    }
}
