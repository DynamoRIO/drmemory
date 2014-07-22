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
registers.c_asm.asm:977
Error #2: UNINITIALIZED READ: reading register eflags
registers.c_asm.asm:984
Error #3: UNINITIALIZED READ: reading 2 byte(s)
registers.c:98
Error #4: UNINITIALIZED READ: reading register ax
registers.c_asm.asm:1197
Error #5: UNINITIALIZED READ: reading register dx
registers.c_asm.asm:1214
Error #6: UNINITIALIZED READ: reading register ah
registers.c_asm.asm:1244
Error #7: UNINITIALIZED READ: reading 1 byte(s)
registers.c:265
Error #8: UNINITIALIZED READ: reading 1 byte(s)
registers.c_asm.asm:953
Error #9: UNINITIALIZED READ: reading register eflags
registers.c:136
Error #10: UNINITIALIZED READ: reading register eflags
registers.c:140
Error #11: UNINITIALIZED READ: reading register cl
registers.c:145
Error #12: UNINITIALIZED READ: reading register ecx
registers.c:179
Error #13: UNINITIALIZED READ: reading 8 byte(s)
registers.c:209
Error #14: UNADDRESSABLE ACCESS beyond heap bounds: reading 1 byte(s)
registers.c_asm.asm:1002
Error #15: UNADDRESSABLE ACCESS beyond heap bounds: reading 1 byte(s)
registers.c_asm.asm:1014
Error #16: UNADDRESSABLE ACCESS beyond heap bounds: reading 1 byte(s)
registers.c_asm.asm:1027
Error #17: UNADDRESSABLE ACCESS beyond heap bounds: reading 1 byte(s)
registers.c_asm.asm:1028
%endif
%if UNIX
Error #1: UNINITIALIZED READ: reading register eflags
registers.c_asm.asm:516
Error #2: UNINITIALIZED READ: reading register eflags
registers.c_asm.asm:523
Error #3: UNINITIALIZED READ: reading register eax
registers.c:98
Error #4: UNINITIALIZED READ: reading register ax
registers.c_asm.asm:751
Error #5: UNINITIALIZED READ: reading register dx
registers.c_asm.asm:768
Error #6: UNINITIALIZED READ: reading register ah
registers.c_asm.asm:798
Error #7: UNINITIALIZED READ: reading register eax
registers.c:265
Error #8: UNINITIALIZED READ: reading 1 byte(s)
registers.c_asm.asm:489
Error #9: UNINITIALIZED READ: reading register eflags
registers.c:152
Error #10: UNINITIALIZED READ: reading register eflags
registers.c:156
Error #11: UNINITIALIZED READ: reading register cl
registers.c:161
Error #12: UNINITIALIZED READ: reading register ecx
registers.c:190
Error #13: UNINITIALIZED READ: reading 8 byte(s)
registers.c:215
Error #14: UNADDRESSABLE ACCESS beyond heap bounds: reading 1 byte(s)
registers.c_asm.asm:544
Error #15: UNADDRESSABLE ACCESS beyond heap bounds: reading 1 byte(s)
registers.c_asm.asm:556
Error #16: UNADDRESSABLE ACCESS beyond heap bounds: reading 1 byte(s)
registers.c_asm.asm:569
Error #17: UNADDRESSABLE ACCESS beyond heap bounds: reading 1 byte(s)
registers.c_asm.asm:570
%endif
Error #18: UNINITIALIZED READ: reading register eax
registers.c:325
Error #19: UNINITIALIZED READ: reading register
registers.c:369
Error #20: UNINITIALIZED READ: reading register
registers.c:390
%if WINDOWS
Error #21: UNINITIALIZED READ: reading 1 byte(s)
registers.c_asm.asm:1415
Error #22: UNINITIALIZED READ: reading 1 byte(s)
registers.c_asm.asm:1429
Error #23: UNINITIALIZED READ: reading 2 byte(s)
registers.c_asm.asm:1443
Error #24: UNINITIALIZED READ: reading 2 byte(s)
registers.c_asm.asm:1457
%endif
%if UNIX
Error #21: UNINITIALIZED READ: reading 1 byte(s)
registers.c_asm.asm:987
Error #22: UNINITIALIZED READ: reading 1 byte(s)
registers.c_asm.asm:1001
Error #23: UNINITIALIZED READ: reading 2 byte(s)
registers.c_asm.asm:1015
Error #24: UNINITIALIZED READ: reading 2 byte(s)
registers.c_asm.asm:1029
%endif
%OUT_OF_ORDER
: LEAK 15 direct bytes + 0 indirect bytes
: LEAK 15 direct bytes + 0 indirect bytes
