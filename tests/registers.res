# **********************************************************
# Copyright (c) 2011-2019 Google, Inc.  All rights reserved.
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
registers.c_asm.asm:1353
Error #2: UNINITIALIZED READ: reading register eflags
registers.c_asm.asm:1360
Error #3: UNINITIALIZED READ: reading 2 byte(s)
registers.c:104
Error #4: UNINITIALIZED READ: reading register ax
registers.c_asm.asm:1580
Error #5: UNINITIALIZED READ: reading register dx
registers.c_asm.asm:1597
Error #6: UNINITIALIZED READ: reading register ah
registers.c_asm.asm:1627
Error #7: UNINITIALIZED READ: reading 1 byte(s)
registers.c:187
Error #8: UNINITIALIZED READ: reading 1 byte(s)
registers.c_asm.asm:1329
Error #9: UNINITIALIZED READ: reading register eflags
registers.c_asm.asm:1154
Error #10: UNINITIALIZED READ: reading register eflags
registers.c_asm.asm:1158
Error #11: UNINITIALIZED READ: reading register cl
registers.c_asm.asm:1163
Error #12: UNINITIALIZED READ: reading register xcx
registers.c_asm.asm:1183
Error #13: UNINITIALIZED READ: reading 8 byte(s)
registers.c_asm.asm:1214
Error #14: UNADDRESSABLE ACCESS beyond heap bounds: reading 1 byte(s)
registers.c_asm.asm:1380
Error #15: UNADDRESSABLE ACCESS beyond heap bounds: reading 1 byte(s)
registers.c_asm.asm:1392
Error #16: UNADDRESSABLE ACCESS beyond heap bounds: reading 1 byte(s)
registers.c_asm.asm:1405
Error #17: UNADDRESSABLE ACCESS beyond heap bounds: reading 1 byte(s)
registers.c_asm.asm:1406
%endif
%if UNIX
Error #1: UNINITIALIZED READ: reading register eflags
registers.c_asm.asm:583
Error #2: UNINITIALIZED READ: reading register eflags
registers.c_asm.asm:590
Error #3: UNINITIALIZED READ: reading register eax
registers.c:104
Error #4: UNINITIALIZED READ: reading register ax
registers.c_asm.asm:819
Error #5: UNINITIALIZED READ: reading register dx
registers.c_asm.asm:836
Error #6: UNINITIALIZED READ: reading register ah
registers.c_asm.asm:866
Error #7: UNINITIALIZED READ: reading register eax
registers.c:187
Error #8: UNINITIALIZED READ: reading 1 byte(s)
registers.c_asm.asm:556
Error #9: UNINITIALIZED READ: reading register eflags
registers.c_asm.asm:367
Error #10: UNINITIALIZED READ: reading register eflags
registers.c_asm.asm:371
Error #11: UNINITIALIZED READ: reading register cl
registers.c_asm.asm:376
Error #12: UNINITIALIZED READ: reading register xcx
registers.c_asm.asm:399
Error #13: UNINITIALIZED READ: reading 8 byte(s)
registers.c_asm.asm:432
Error #14: UNADDRESSABLE ACCESS beyond heap bounds: reading 1 byte(s)
registers.c_asm.asm:612
Error #15: UNADDRESSABLE ACCESS beyond heap bounds: reading 1 byte(s)
registers.c_asm.asm:624
Error #16: UNADDRESSABLE ACCESS beyond heap bounds: reading 1 byte(s)
registers.c_asm.asm:637
Error #17: UNADDRESSABLE ACCESS beyond heap bounds: reading 1 byte(s)
registers.c_asm.asm:638
%endif
Error #18: UNINITIALIZED READ: reading register eax
registers.c:223
%if UNIX
Error #19: UNINITIALIZED READ: reading register ecx
registers.c_asm.asm:970
%endif
%if WINDOWS
Error #19: UNINITIALIZED READ: reading register ecx
registers.c_asm.asm:1722
%endif
Error #20: UNINITIALIZED READ: reading register
registers.c:267
Error #21: UNINITIALIZED READ: reading register
registers.c:288
%if WINDOWS
Error #22: UNINITIALIZED READ: reading 1 byte(s)
registers.c_asm.asm:1807
Error #23: UNINITIALIZED READ: reading 1 byte(s)
registers.c_asm.asm:1821
Error #24: UNINITIALIZED READ: reading 2 byte(s)
registers.c_asm.asm:1835
Error #25: UNINITIALIZED READ: reading 2 byte(s)
registers.c_asm.asm:1849
Error #26: UNINITIALIZED READ: reading register eax
registers.c_asm.asm:1884
%endif
%if UNIX
Error #22: UNINITIALIZED READ: reading 1 byte(s)
registers.c_asm.asm:1064
Error #23: UNINITIALIZED READ: reading 1 byte(s)
registers.c_asm.asm:1078
Error #24: UNINITIALIZED READ: reading 2 byte(s)
registers.c_asm.asm:1092
Error #25: UNINITIALIZED READ: reading 2 byte(s)
registers.c_asm.asm:1106
Error #26: UNINITIALIZED READ: reading register eax
registers.c_asm.asm:1076
%endif
%OUT_OF_ORDER
: LEAK 15 direct bytes + 0 indirect bytes
: LEAK 15 direct bytes + 0 indirect bytes
