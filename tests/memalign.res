# **********************************************************
# Copyright (c) 2010-2018 Google, Inc.  All rights reserved.
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
memalign.c:74
Note: refers to 1 byte(s) before next malloc

Error #2: UNADDRESSABLE ACCESS beyond heap bounds: reading 1 byte(s)
memalign.c:75
Note: refers to 0 byte(s) beyond last valid byte in prior malloc

Error #3: UNADDRESSABLE ACCESS beyond heap bounds: reading 1 byte(s)
memalign.c:90
Note: refers to 1 byte(s) before next malloc

Error #4: UNADDRESSABLE ACCESS beyond heap bounds: reading 1 byte(s)
memalign.c:91
Note: refers to 0 byte(s) beyond last valid byte in prior malloc

Error #5: WARNING: heap allocation failed
memalign.c:95

Error #6: UNADDRESSABLE ACCESS beyond heap bounds: reading 1 byte(s)
memalign.c:103
Note: refers to 1 byte(s) before next malloc

Error #7: UNADDRESSABLE ACCESS beyond heap bounds: reading 1 byte(s)
memalign.c:104

%if !MACOS
Error #8: UNADDRESSABLE ACCESS beyond heap bounds: reading 1 byte(s)
memalign.c:111
Note: refers to 1 byte(s) before next malloc

Error #9: UNADDRESSABLE ACCESS beyond heap bounds: reading 1 byte(s)
memalign.c:112
Note: refers to 0 byte(s) beyond last valid byte in prior malloc
%endif

: UNADDRESSABLE ACCESS beyond heap bounds: reading 1 byte(s)
memalign.c:119
Note: refers to 1 byte(s) before next malloc

: UNADDRESSABLE ACCESS beyond heap bounds: reading 1 byte(s)
memalign.c:120
Note: refers to 0 byte(s) beyond last valid byte in prior malloc

%if !MACOS
: UNADDRESSABLE ACCESS beyond heap bounds: reading 1 byte(s)
memalign.c:127
Note: refers to 1 byte(s) before next malloc

: UNADDRESSABLE ACCESS beyond heap bounds: reading 1 byte(s)
memalign.c:129
%endif
