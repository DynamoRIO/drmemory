# **********************************************************
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
Error #1: UNADDRESSABLE ACCESS: reading 1 byte(s)
malloc.c:95
Error #2: UNINITIALIZED READ
malloc.c:105
Error #3: UNINITIALIZED READ
malloc.c:118
Error #4: INVALID FREE
!if WINDOWS
# addr2line and winsyms report slightly different results here
malloc.c:160
!endif
!if UNIX
malloc.c:161
!endif
!if UNIX
# on unix free touches the invalid address; not so on winxp it seems
Error #5: UNADDRESSABLE ACCESS: reading 4 byte(s)
malloc.c:161
!endif
