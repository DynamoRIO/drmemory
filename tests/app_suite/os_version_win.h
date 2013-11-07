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

#ifndef OS_VERSION_WIN_H_
#define OS_VERSION_WIN_H_ 1

/* Routines for determining the version of Windows we're running on.
 */

/* Enum of known Windows major releases ordered by release date.  This abstracts
 * away the complexities of GetVersionEx.  Don't worry about binary compat or
 * completeness, just add new versions as we need to detect them.
 */
enum WinVersion {
    WIN_UNKNOWN = 0,
    WIN_XP,
    WIN_VISTA,
    WIN_7,
    WIN_8,
    WIN_8_1,
    WIN_HIGHER,
};

WinVersion GetWindowsVersion();

#endif /* OS_VERSION_WIN_H_ */
