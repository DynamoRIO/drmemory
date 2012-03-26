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

Error #1: WARNING: GDI usage error: free mismatch for DC: use ReleaseDC only for GetDC and DeleteDC only for CreateDC
system call NtGdiDeleteObjectApp
GDI32.dll!DeleteDC
test_DC_free
gdi.cpp:45
main
gdi.cpp:206

Error #2: WARNING: GDI usage error: free mismatch for DC: use ReleaseDC only for GetDC and DeleteDC only for CreateDC
system call NtUserCallOneParam.RELEASEDC
test_DC_free
gdi.cpp:51
main
gdi.cpp:206

Error #3: WARNING: GDI usage error: DC used for select was created by now-exited thread
test_DC_threads
gdi.cpp:101
main
gdi.cpp:208

Error #4: WARNING: GDI usage error: DC used for select was created by now-exited thread
test_DC_threads
gdi.cpp:103
main
gdi.cpp:208

Error #5: WARNING: GDI usage error: DC created by one thread
thread_select
gdi.cpp:72

Error #6: WARNING: GDI usage error: DC created by one thread
thread_select
gdi.cpp:73

Error #7: WARNING: GDI usage error: ReleaseDC for DC called from different thread
system call NtUserCallOneParam.RELEASEDC
thread_release
gdi.cpp:83

Error #8: WARNING: GDI usage error: deleting an object that is selected into DC
test_DC_objdel
gdi.cpp:148
main
gdi.cpp:210

Error #9: WARNING: GDI usage error: deleting an object that is selected into DC
system call NtGdiDeleteObjectApp
test_DC_objdel
gdi.cpp:158
main
gdi.cpp:210

Error #10: WARNING: GDI usage error: same bitmap selected into two different DC's and
test_DC_bitmap
gdi.cpp:179
main
gdi.cpp:212

Error #11: WARNING: GDI usage error: DC that contains selected object being deleted
system call NtGdiDeleteObjectApp
GDI32.dll!DeleteDC
test_DC_bitmap
gdi.cpp:181
main
gdi.cpp:212

Error #12: WARNING: GDI usage error: DC that contains selected object being deleted
test_DC_select
gdi.cpp:198
main
gdi.cpp:214

Error #13: WARNING: GDI usage error: deleting an object that is selected into DC
test_DC_select
gdi.cpp:199
main
gdi.cpp:214
