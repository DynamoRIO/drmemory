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
registers.c:100
Error #2: UNINITIALIZED READ: reading register eflags
registers.c:107
Error #3: UNINITIALIZED READ: reading 2 byte(s)
registers.c:127
Error #4: UNINITIALIZED READ: reading register ax
registers.c_asm.asm:1119
Error #5: UNINITIALIZED READ: reading register dx
registers.c_asm.asm:1136
Error #6: UNINITIALIZED READ: reading register ah
registers.c_asm.asm:1166
Error #7: UNINITIALIZED READ: reading 1 byte(s)
registers.c:340
Error #8: UNINITIALIZED READ: reading 1 byte(s)
registers.c:165
Error #9: UNINITIALIZED READ: reading register eflags
registers.c:211
Error #10: UNINITIALIZED READ: reading register eflags
registers.c:215
Error #11: UNINITIALIZED READ: reading register cl
registers.c:220
Error #12: UNINITIALIZED READ: reading register ecx
registers.c:254
Error #13: UNINITIALIZED READ: reading 8 byte(s)
registers.c:284
Error #14: UNADDRESSABLE ACCESS: reading 1 byte(s)
registers.c:366
Error #15: UNADDRESSABLE ACCESS: reading 1 byte(s)
registers.c:378
%endif
%if UNIX
Error #1: UNINITIALIZED READ: reading register eflags
registers.c:117
Error #2: UNINITIALIZED READ: reading register eflags
registers.c:124
Error #3: UNINITIALIZED READ: reading register eax
registers.c:127
Error #4: UNINITIALIZED READ: reading register ax
registers.c_asm.asm:720
Error #5: UNINITIALIZED READ: reading register dx
registers.c_asm.asm:737
Error #6: UNINITIALIZED READ: reading register ah
registers.c_asm.asm:767
Error #7: UNINITIALIZED READ: reading register eax
registers.c:340
Error #8: UNINITIALIZED READ: reading 1 byte(s)
registers.c:189
Error #9: UNINITIALIZED READ: reading register eflags
registers.c:227
Error #10: UNINITIALIZED READ: reading register eflags
registers.c:231
Error #11: UNINITIALIZED READ: reading register cl
registers.c:236
Error #12: UNINITIALIZED READ: reading register ecx
registers.c:265
Error #13: UNINITIALIZED READ: reading 8 byte(s)
registers.c:290
Error #14: UNADDRESSABLE ACCESS: reading 1 byte(s)
registers.c:408
Error #15: UNADDRESSABLE ACCESS: reading 1 byte(s)
registers.c:419
%endif
Error #16: UNINITIALIZED READ: reading register eax
registers.c:483
%OUT_OF_ORDER
: LEAK 15 direct bytes + 0 indirect bytes
: LEAK 15 direct bytes + 0 indirect bytes
