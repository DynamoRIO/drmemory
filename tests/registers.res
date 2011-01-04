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
!if WINDOWS
Error #1: UNINITIALIZED READ: reading register eflags
registers.c:194
Error #2: UNINITIALIZED READ: reading register eflags
registers.c:201
Error #3: UNINITIALIZED READ: reading 1 byte
registers.c:221
Error #4: UNINITIALIZED READ: reading 1 byte(s)
registers.c:259
Error #5: UNINITIALIZED READ: reading register eflags
registers.c:305
Error #6: UNINITIALIZED READ: reading register eflags
registers.c:309
Error #7: UNINITIALIZED READ: reading register cl
registers.c:314
!endif
!if UNIX
Error #1: UNINITIALIZED READ: reading register eflags
registers.c:211
Error #2: UNINITIALIZED READ: reading register eflags
registers.c:218
Error #3: UNINITIALIZED READ: reading register eax
registers.c:221
Error #4: UNINITIALIZED READ: reading 1 byte(s)
registers.c:283
Error #5: UNINITIALIZED READ: reading register eflags
registers.c:321
Error #6: UNINITIALIZED READ: reading register eflags
registers.c:325
Error #7: UNINITIALIZED READ: reading register cl
registers.c:330
!endif
Error #8: UNINITIALIZED READ: reading register ecx
registers.c:359
Error #9: UNINITIALIZED READ: reading 8 byte(s)
registers.c:384
Error #8: LEAK 15 direct bytes + 0 indirect bytes
Error #9: LEAK 15 direct bytes + 0 indirect bytes
