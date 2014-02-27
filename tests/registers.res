# **********************************************************
# Copyright (c) 2011-2014 Google, Inc.  All rights reserved.
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
registers.c:101
Error #2: UNINITIALIZED READ: reading register eflags
registers.c:108
Error #3: UNINITIALIZED READ: reading 2 byte(s)
registers.c:128
Error #4: UNINITIALIZED READ: reading register ax
registers.c_asm.asm:1141
Error #5: UNINITIALIZED READ: reading register dx
registers.c_asm.asm:1158
Error #6: UNINITIALIZED READ: reading register ah
registers.c_asm.asm:1188
Error #7: UNINITIALIZED READ: reading 1 byte(s)
registers.c:341
Error #8: UNINITIALIZED READ: reading 1 byte(s)
registers.c:166
Error #9: UNINITIALIZED READ: reading register eflags
registers.c:212
Error #10: UNINITIALIZED READ: reading register eflags
registers.c:216
Error #11: UNINITIALIZED READ: reading register cl
registers.c:221
Error #12: UNINITIALIZED READ: reading register ecx
registers.c:255
Error #13: UNINITIALIZED READ: reading 8 byte(s)
registers.c:285
Error #14: UNADDRESSABLE ACCESS: reading 1 byte(s)
registers.c:367
Error #15: UNADDRESSABLE ACCESS: reading 1 byte(s)
registers.c:379
%endif
%if UNIX
Error #1: UNINITIALIZED READ: reading register eflags
registers.c:118
Error #2: UNINITIALIZED READ: reading register eflags
registers.c:125
Error #3: UNINITIALIZED READ: reading register eax
registers.c:128
Error #4: UNINITIALIZED READ: reading register ax
registers.c_asm.asm:742
Error #5: UNINITIALIZED READ: reading register dx
registers.c_asm.asm:759
Error #6: UNINITIALIZED READ: reading register ah
registers.c_asm.asm:789
Error #7: UNINITIALIZED READ: reading register eax
registers.c:341
Error #8: UNINITIALIZED READ: reading 1 byte(s)
registers.c:190
Error #9: UNINITIALIZED READ: reading register eflags
registers.c:228
Error #10: UNINITIALIZED READ: reading register eflags
registers.c:232
Error #11: UNINITIALIZED READ: reading register cl
registers.c:237
Error #12: UNINITIALIZED READ: reading register ecx
registers.c:266
Error #13: UNINITIALIZED READ: reading 8 byte(s)
registers.c:291
Error #14: UNADDRESSABLE ACCESS: reading 1 byte(s)
registers.c:409
Error #15: UNADDRESSABLE ACCESS: reading 1 byte(s)
registers.c:420
%endif
Error #16: UNINITIALIZED READ: reading register eax
registers.c:484
%OUT_OF_ORDER
: LEAK 15 direct bytes + 0 indirect bytes
: LEAK 15 direct bytes + 0 indirect bytes
