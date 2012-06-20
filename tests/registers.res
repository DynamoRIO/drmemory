# **********************************************************
# Copyright (c) 2011-2012 Google, Inc.  All rights reserved.
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
%if WINDOWS
Error #1: UNINITIALIZED READ: reading register eflags
registers.c:201
Error #2: UNINITIALIZED READ: reading register eflags
registers.c:208
Error #3: UNINITIALIZED READ: reading 2 byte(s)
registers.c:228
Error #4: UNINITIALIZED READ: reading register ax
registers.c:485
Error #5: UNINITIALIZED READ: reading register dx
registers.c:502
Error #6: UNINITIALIZED READ: reading 1 byte(s)
registers.c:573
Error #7: UNINITIALIZED READ: reading 1 byte(s)
registers.c:266
Error #8: UNINITIALIZED READ: reading register eflags
registers.c:312
Error #9: UNINITIALIZED READ: reading register eflags
registers.c:316
Error #10: UNINITIALIZED READ: reading register cl
registers.c:321
Error #11: UNINITIALIZED READ: reading register ecx
registers.c:355
Error #12: UNINITIALIZED READ: reading 8 byte(s)
registers.c:385
Error #13: UNADDRESSABLE ACCESS: reading 1 byte(s)
registers.c:599
Error #14: UNADDRESSABLE ACCESS: reading 1 byte(s)
registers.c:611
%endif
%if UNIX
Error #1: UNINITIALIZED READ: reading register eflags
registers.c:218
Error #2: UNINITIALIZED READ: reading register eflags
registers.c:225
Error #3: UNINITIALIZED READ: reading register eax
registers.c:228
Error #4: UNINITIALIZED READ: reading register ax
registers.c:546
Error #5: UNINITIALIZED READ: reading register dx
registers.c:563
Error #6: UNINITIALIZED READ: reading register eax
registers.c:573
Error #7: UNINITIALIZED READ: reading 1 byte(s)
registers.c:290
Error #8: UNINITIALIZED READ: reading register eflags
registers.c:328
Error #9: UNINITIALIZED READ: reading register eflags
registers.c:332
Error #10: UNINITIALIZED READ: reading register cl
registers.c:337
Error #11: UNINITIALIZED READ: reading register ecx
registers.c:366
Error #12: UNINITIALIZED READ: reading 8 byte(s)
registers.c:391
Error #13: UNADDRESSABLE ACCESS: reading 1 byte(s)
registers.c:641
Error #14: UNADDRESSABLE ACCESS: reading 1 byte(s)
registers.c:652
%endif
%OUT_OF_ORDER
: LEAK 15 direct bytes + 0 indirect bytes
: LEAK 15 direct bytes + 0 indirect bytes
