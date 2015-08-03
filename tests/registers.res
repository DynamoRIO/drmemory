# **********************************************************
# Copyright (c) 2011-2015 Google, Inc.  All rights reserved.
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
registers.c_asm.asm:1225
Error #2: UNINITIALIZED READ: reading register eflags
registers.c_asm.asm:1232
Error #3: UNINITIALIZED READ: reading 2 byte(s)
registers.c:104
Error #4: UNINITIALIZED READ: reading register ax
registers.c_asm.asm:1452
Error #5: UNINITIALIZED READ: reading register dx
registers.c_asm.asm:1469
Error #6: UNINITIALIZED READ: reading register ah
registers.c_asm.asm:1499
Error #7: UNINITIALIZED READ: reading 1 byte(s)
registers.c:187
Error #8: UNINITIALIZED READ: reading 1 byte(s)
registers.c_asm.asm:1201
Error #9: UNINITIALIZED READ: reading register eflags
registers.c_asm.asm:1026
Error #10: UNINITIALIZED READ: reading register eflags
registers.c_asm.asm:1030
Error #11: UNINITIALIZED READ: reading register cl
registers.c_asm.asm:1035
Error #12: UNINITIALIZED READ: reading register ecx
registers.c_asm.asm:1055
Error #13: UNINITIALIZED READ: reading 8 byte(s)
registers.c_asm.asm:1086
Error #14: UNADDRESSABLE ACCESS beyond heap bounds: reading 1 byte(s)
registers.c_asm.asm:1252
Error #15: UNADDRESSABLE ACCESS beyond heap bounds: reading 1 byte(s)
registers.c_asm.asm:1264
Error #16: UNADDRESSABLE ACCESS beyond heap bounds: reading 1 byte(s)
registers.c_asm.asm:1277
Error #17: UNADDRESSABLE ACCESS beyond heap bounds: reading 1 byte(s)
registers.c_asm.asm:1278
%endif
%if UNIX
Error #1: UNINITIALIZED READ: reading register eflags
registers.c_asm.asm:580
Error #2: UNINITIALIZED READ: reading register eflags
registers.c_asm.asm:587
Error #3: UNINITIALIZED READ: reading register eax
registers.c:104
Error #4: UNINITIALIZED READ: reading register ax
registers.c_asm.asm:816
Error #5: UNINITIALIZED READ: reading register dx
registers.c_asm.asm:833
Error #6: UNINITIALIZED READ: reading register ah
registers.c_asm.asm:863
Error #7: UNINITIALIZED READ: reading register eax
registers.c:187
Error #8: UNINITIALIZED READ: reading 1 byte(s)
registers.c_asm.asm:553
Error #9: UNINITIALIZED READ: reading register eflags
registers.c_asm.asm:364
Error #10: UNINITIALIZED READ: reading register eflags
registers.c_asm.asm:368
Error #11: UNINITIALIZED READ: reading register cl
registers.c_asm.asm:373
Error #12: UNINITIALIZED READ: reading register ecx
registers.c_asm.asm:396
Error #13: UNINITIALIZED READ: reading 8 byte(s)
registers.c_asm.asm:429
Error #14: UNADDRESSABLE ACCESS beyond heap bounds: reading 1 byte(s)
registers.c_asm.asm:609
Error #15: UNADDRESSABLE ACCESS beyond heap bounds: reading 1 byte(s)
registers.c_asm.asm:621
Error #16: UNADDRESSABLE ACCESS beyond heap bounds: reading 1 byte(s)
registers.c_asm.asm:634
Error #17: UNADDRESSABLE ACCESS beyond heap bounds: reading 1 byte(s)
registers.c_asm.asm:635
%endif
Error #18: UNINITIALIZED READ: reading register eax
registers.c:223
%if UNIX
Error #19: UNINITIALIZED READ: reading register ecx
registers.c_asm.asm:967
%endif
%if WINDOWS
Error #19: UNINITIALIZED READ: reading register ecx
registers.c_asm.asm:1594
%endif
Error #20: UNINITIALIZED READ: reading register
registers.c:267
Error #21: UNINITIALIZED READ: reading register
registers.c:288
%if WINDOWS
Error #22: UNINITIALIZED READ: reading 1 byte(s)
registers.c_asm.asm:1679
Error #23: UNINITIALIZED READ: reading 1 byte(s)
registers.c_asm.asm:1693
Error #24: UNINITIALIZED READ: reading 2 byte(s)
registers.c_asm.asm:1707
Error #25: UNINITIALIZED READ: reading 2 byte(s)
registers.c_asm.asm:1721
%endif
%if UNIX
Error #22: UNINITIALIZED READ: reading 1 byte(s)
registers.c_asm.asm:1061
Error #23: UNINITIALIZED READ: reading 1 byte(s)
registers.c_asm.asm:1075
Error #24: UNINITIALIZED READ: reading 2 byte(s)
registers.c_asm.asm:1089
Error #25: UNINITIALIZED READ: reading 2 byte(s)
registers.c_asm.asm:1103
%endif
%OUT_OF_ORDER
: LEAK 15 direct bytes + 0 indirect bytes
: LEAK 15 direct bytes + 0 indirect bytes
