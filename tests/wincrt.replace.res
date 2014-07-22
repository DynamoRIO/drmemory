# **********************************************************
# Copyright (c) 2011-2013 Google, Inc.  All rights reserved.
# Copyright (c) 2010 VMware, Inc.  All rights reserved.
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
Error #1: UNADDRESSABLE ACCESS beyond heap bounds: reading 1 byte(s)
wincrt.cpp:42
Error #2: UNADDRESSABLE ACCESS beyond heap bounds: reading 1 byte(s)
wincrt.cpp:43
Error #3: UNADDRESSABLE ACCESS beyond heap bounds: reading 1 byte(s)
wincrt.cpp:44
Error #4: UNADDRESSABLE ACCESS beyond heap bounds: reading 1 byte(s)
wincrt.cpp:45
Error #5: UNADDRESSABLE ACCESS beyond heap bounds: writing 1 byte(s)
wincrt.cpp:100
# errors from -replace_malloc i#1197:
Error #6: INVALID HEAP ARGUMENT: allocated with C library layer, queried with Windows API layer
replace_RtlSizeHeap
rtl_mismatch_test
wincrt.cpp:114
memory was allocated here:
replace_malloc
rtl_mismatch_test
wincrt.cpp:113
Error #7: INVALID HEAP ARGUMENT: allocated with Windows API layer, queried with C library layer
replace_malloc_usable_size
rtl_mismatch_test
wincrt.cpp:117
memory was allocated here:
replace_RtlAllocateHeap
rtl_mismatch_test
wincrt.cpp:116
