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

Error #1: GDI USAGE ERROR: free mismatch for DC: use ReleaseDC only for GetDC and DeleteDC only for CreateDC
system call NtGdiDeleteObjectApp
GDI32.dll!DeleteDC
test_DC_free
gdi.cpp:45
main
gdi.cpp:241
DC was allocated here:
gdi.cpp:39

Error #2: GDI USAGE ERROR: free mismatch for DC: use ReleaseDC only for GetDC and DeleteDC only for CreateDC
system call NtUserCallOneParam.RELEASEDC
test_DC_free
gdi.cpp:51
main
gdi.cpp:241
DC was allocated here:
gdi.cpp:49

Error #3: GDI USAGE ERROR: DC used for select was created by now-exited thread
test_DC_threads
gdi.cpp:101
main
gdi.cpp:243
DC was allocated here:
gdi.cpp:59

Error #4: GDI USAGE ERROR: DC used for select was created by now-exited thread
test_DC_threads
gdi.cpp:103
main
gdi.cpp:243
DC was allocated here:
gdi.cpp:59

Error #5: GDI USAGE ERROR: DC created by one thread
thread_select
gdi.cpp:72
DC was allocated here:
gdi.cpp:120

Error #6: GDI USAGE ERROR: DC created by one thread
thread_select
gdi.cpp:73
DC was allocated here:
gdi.cpp:120

Error #7: GDI USAGE ERROR: ReleaseDC for DC called from different thread
system call NtUserCallOneParam.RELEASEDC
thread_release
gdi.cpp:83
DC was allocated here:
gdi.cpp:92

Error #8: GDI USAGE ERROR: deleting a drawing object that is selected into DC
test_DC_objdel
gdi.cpp:148
main
gdi.cpp:245
DC was allocated here:
gdi.cpp:145

Error #9: GDI USAGE ERROR: same bitmap selected into two different DC's and
test_DC_bitmap
gdi.cpp:179
main
gdi.cpp:247

Error #10: GDI USAGE ERROR: DC that contains selected object being deleted
system call NtGdiDeleteObjectApp
GDI32.dll!DeleteDC
test_DC_bitmap
gdi.cpp:181
main
gdi.cpp:247
DC was allocated here:
gdi.cpp:171

Error #11: GDI USAGE ERROR: DC that contains selected object being deleted
test_DC_select
gdi.cpp:198
main
gdi.cpp:249
DC was allocated here:
gdi.cpp:195

Error #12: GDI USAGE ERROR: deleting a drawing object that is selected into DC
test_DC_select
gdi.cpp:199
main
gdi.cpp:249
