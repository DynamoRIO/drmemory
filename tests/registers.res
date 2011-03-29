# **********************************************************
# Copyright (c) 2011 Google, Inc.  All rights reserved.
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
registers.c:195
Error #2: UNINITIALIZED READ: reading register eflags
registers.c:202
Error #3: UNINITIALIZED READ: reading 1 byte
registers.c:222
Error #4: UNINITIALIZED READ: reading 1 byte(s)
registers.c:260
Error #5: UNINITIALIZED READ: reading register eflags
registers.c:306
Error #6: UNINITIALIZED READ: reading register eflags
registers.c:310
Error #7: UNINITIALIZED READ: reading register cl
registers.c:315
Error #8: UNINITIALIZED READ: reading register ecx
registers.c:349
Error #9: UNINITIALIZED READ: reading 8 byte(s)
registers.c:379
!endif
!if UNIX
Error #1: UNINITIALIZED READ: reading register eflags
registers.c:212
Error #2: UNINITIALIZED READ: reading register eflags
registers.c:219
Error #3: UNINITIALIZED READ: reading register eax
registers.c:222
Error #4: UNINITIALIZED READ: reading 1 byte(s)
registers.c:284
Error #5: UNINITIALIZED READ: reading register eflags
registers.c:322
Error #6: UNINITIALIZED READ: reading register eflags
registers.c:326
Error #7: UNINITIALIZED READ: reading register cl
registers.c:331
Error #8: UNINITIALIZED READ: reading register ecx
registers.c:360
Error #9: UNINITIALIZED READ: reading 8 byte(s)
registers.c:385
!endif
Error #10: LEAK 15 direct bytes + 0 indirect bytes
Error #11: LEAK 15 direct bytes + 0 indirect bytes
