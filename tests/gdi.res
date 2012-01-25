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

# FIXME i#764: disabled for pre-win7
%EMPTY_OK

Error #1: WARNING: GDI usage error: free mismatch for DC: use ReleaseDC only for GetDC and DeleteDC only for CreateDC
system call NtGdiDeleteObjectApp
GDI32.dll!DeleteDC
test_DC_free
gdi.cpp:45
main
gdi.cpp:200

Error #2: WARNING: GDI usage error: free mismatch for DC: use ReleaseDC only for GetDC and DeleteDC only for CreateDC
system call NtUserCallOneParam.RELEASEDC
test_DC_free
gdi.cpp:51
main
gdi.cpp:200

Error #3: WARNING: GDI usage error: DC used for select was created by now-dead thread
system call NtGdiSelectBitmap
test_DC_threads
gdi.cpp:101
main
gdi.cpp:202

Error #4: WARNING: GDI usage error: DC used for select was created by now-dead thread
system call NtGdiSelectBitmap
test_DC_threads
gdi.cpp:102
main
gdi.cpp:202

Error #5: WARNING: GDI usage error: DC created by one thread
system call NtGdiSelectBitmap
thread_select
gdi.cpp:72

Error #6: WARNING: GDI usage error: DC created by one thread
system call NtGdiSelectBitmap
thread_select
gdi.cpp:73

Error #7: WARNING: GDI usage error: ReleaseDC for DC called from different thread
system call NtUserCallOneParam.RELEASEDC
thread_release
gdi.cpp:83

Error #8: WARNING: GDI usage error: deleting an object that is selected into DC
system call NtGdiDeleteObjectApp
test_DC_objdel
gdi.cpp:154
main
gdi.cpp:204

Error #9: WARNING: GDI usage error: same bitmap selected into two different DC's and
system call NtGdiSelectBitmap
test_DC_bitmap
gdi.cpp:174
main
gdi.cpp:206

Error #10: WARNING: GDI usage error: DC that contains selected object being deleted
system call NtGdiDeleteObjectApp
GDI32.dll!DeleteDC
test_DC_bitmap
gdi.cpp:175
main
gdi.cpp:206
