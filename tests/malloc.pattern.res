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
# This is malloc.res minus leaks and uninits with updated error number.
Error #1: UNADDRESSABLE ACCESS beyond heap bounds: reading 1 byte(s)
malloc.c:112
Error #2: INVALID HEAP ARGUMENT
malloc.c:180
%if WINDOWS
Error #3: WARNING: heap allocation failed
malloc.c:192
Error #4: UNADDRESSABLE ACCESS beyond heap bounds: reading 4 byte(s)
malloc.c:200
Error #5: INVALID HEAP ARGUMENT
%endif
%if WINDOWS_PRE_8
malloc.c:204
%endif
%if WINDOWS_8_PLUS
malloc.c:206
%endif
: UNADDRESSABLE ACCESS: reading 1 byte(s)
malloc.c:253
