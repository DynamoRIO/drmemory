# **********************************************************
# Copyright (c) 2012 Google, Inc.  All rights reserved.
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
Error #1: WARNING: Handle usage error:
system call NtUserGetDC
main
handle.cpp:57

Error #2: WARNING: Handle usage error:
system call NtGdiCreatePen
test_gdi_handles
handle.cpp:38
main
handle.cpp:57

Error #3: WARNING: Handle usage error:
system call NtGdiCreateCompatibleBitmap
test_gdi_handles
handle.cpp:42
main
handle.cpp:57

Error #4: WARNING: Handle usage error:
system call NtGdiCreateCompatibleDC
test_gdi_handles
handle.cpp:36
main
handle.cpp:57

Error #5: WARNING: Handle usage error:
system call NtGdiCreateBitmap
main
handle.cpp:57
