# **********************************************************
# Copyright (c) 2015-2018 Google, Inc.  All rights reserved.
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
memalign.c:75
Note: refers to 0 byte(s) beyond last valid byte in prior malloc

Error #2: UNADDRESSABLE ACCESS beyond heap bounds: reading 1 byte(s)
memalign.c:91
Note: refers to 0 byte(s) beyond last valid byte in prior malloc

Error #3: WARNING: heap allocation failed
memalign.c:95

Error #4: UNADDRESSABLE ACCESS beyond heap bounds: reading 1 byte(s)
memalign.c:104

%if !MACOS
Error #5: UNADDRESSABLE ACCESS beyond heap bounds: reading 1 byte(s)
memalign.c:112
Note: refers to 0 byte(s) beyond last valid byte in prior malloc
%endif

: UNADDRESSABLE ACCESS beyond heap bounds: reading 1 byte(s)
memalign.c:120
Note: refers to 0 byte(s) beyond last valid byte in prior malloc

%if !MACOS
: UNADDRESSABLE ACCESS beyond heap bounds: reading 1 byte(s)
memalign.c:129
%endif
