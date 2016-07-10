# **********************************************************
# Copyright (c) 2010-2016 Google, Inc.  All rights reserved.
# Copyright (c) 2009-2010 VMware, Inc.  All rights reserved.
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
memalign.c:70
Note: refers to 1 byte(s) before next malloc

Error #2: UNADDRESSABLE ACCESS beyond heap bounds: reading 1 byte(s)
memalign.c:71
Note: refers to 0 byte(s) beyond last valid byte in prior malloc

Error #3: UNADDRESSABLE ACCESS beyond heap bounds: reading 1 byte(s)
memalign.c:86
Note: refers to 1 byte(s) before next malloc

Error #4: UNADDRESSABLE ACCESS beyond heap bounds: reading 1 byte(s)
memalign.c:87
Note: refers to 0 byte(s) beyond last valid byte in prior malloc

Error #5: WARNING: heap allocation failed
memalign.c:91

Error #6: UNADDRESSABLE ACCESS beyond heap bounds: reading 1 byte(s)
memalign.c:99
Note: refers to 1 byte(s) before next malloc

Error #7: UNADDRESSABLE ACCESS beyond heap bounds: reading 1 byte(s)
memalign.c:100

%if !MACOS
Error #8: UNADDRESSABLE ACCESS beyond heap bounds: reading 1 byte(s)
memalign.c:107
Note: refers to 1 byte(s) before next malloc

Error #9: UNADDRESSABLE ACCESS beyond heap bounds: reading 1 byte(s)
memalign.c:108
Note: refers to 0 byte(s) beyond last valid byte in prior malloc
%endif

: UNADDRESSABLE ACCESS beyond heap bounds: reading 1 byte(s)
memalign.c:115
Note: refers to 1 byte(s) before next malloc

: UNADDRESSABLE ACCESS beyond heap bounds: reading 1 byte(s)
memalign.c:116
Note: refers to 0 byte(s) beyond last valid byte in prior malloc

%if !MACOS
: UNADDRESSABLE ACCESS beyond heap bounds: reading 1 byte(s)
memalign.c:123
Note: refers to 1 byte(s) before next malloc

: UNADDRESSABLE ACCESS beyond heap bounds: reading 1 byte(s)
memalign.c:125
%endif
