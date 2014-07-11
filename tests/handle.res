# **********************************************************
# Copyright (c) 2012-2013 Google, Inc.  All rights reserved.
# **********************************************************
#
# Dr. Memory: the memory debugger
#
# This library is free software; you can redistribute it and/or
# modify it under the terms of the GNU Lesser General Public
# License as published by the Free Software Foundation;
# version 2.1 of the License, and no later version.
#
# This library is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
# Library General Public License for more details.
#
# You should have received a copy of the GNU Lesser General Public
# License along with this library; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
#
%OUT_OF_ORDER
# the handle leak is reported by iterating a hashtable, which has non-det order,
# so use OUT_OF_ORDER instead
Error #1: HANDLE LEAK:
Error #2: HANDLE LEAK:
Error #3: HANDLE LEAK:
Error #4: HANDLE LEAK:
Error #5: HANDLE LEAK:
Error #6: HANDLE LEAK:
Error #7: HANDLE LEAK:
Error #8: HANDLE LEAK:
Error #9: HANDLE LEAK:
Error #10: HANDLE LEAK:
Error #11: HANDLE LEAK:
Error #12: HANDLE LEAK:
Error #13: HANDLE LEAK:
Error #14: HANDLE LEAK:
Error #15: HANDLE LEAK:
Error #16: HANDLE LEAK:
Error #17: HANDLE LEAK:
Error #18: HANDLE LEAK:

system call NtUserGetDC
system call NtGdiCreatePen
system call NtGdiCreateCompatibleBitmap
system call NtGdiCreateCompatibleDC
system call NtGdiCreateBitmap
system call NtGdiDeleteClientObj
system call NtCreateThreadEx
system call NtCreateFile
system call NtOpenFile
system call NtUserCreateWindowEx
system call NtCreateSection
system call NtOpenProcess
system call NtDuplicateObject
system call NtUserOpenDesktop
system call NtUserCreateDesktop
system call NtUserOpenInputDesktop
system call NtUserOpenWindowStation
system call NtUserCreateWindowStation


test_file_handles
test_file_handles
test_file_handles
test_gdi_handles
test_gdi_handles
test_gdi_handles
test_thread_handles
test_window_handles
test_process_handles
test_process_handles
test_desktop_handles
test_desktop_handles
test_desktop_handles
test_desktop_handles
test_desktop_handles
# NtGdiCreateBitmap and NtUserGetDC did not have test_gdi_handles on callstack

main
main
main
main
main
main
main
main
main
main
main
main

_beginthreadex
CreateFileA
FindFirstFileA
CreateWindowExA
CreateToolhelp32Snapshot
