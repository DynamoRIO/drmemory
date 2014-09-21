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
registers.c_asm.asm:1019
Error #2: UNINITIALIZED READ: reading register eflags
registers.c_asm.asm:1026
Error #3: UNINITIALIZED READ: reading 2 byte(s)
registers.c:104
Error #4: UNINITIALIZED READ: reading register ax
registers.c_asm.asm:1246
Error #5: UNINITIALIZED READ: reading register dx
registers.c_asm.asm:1263
Error #6: UNINITIALIZED READ: reading register ah
registers.c_asm.asm:1293
Error #7: UNINITIALIZED READ: reading 1 byte(s)
registers.c:187
Error #8: UNINITIALIZED READ: reading 1 byte(s)
registers.c_asm.asm:995
Error #9: UNINITIALIZED READ: reading register eflags
registers.c_asm.asm:835
Error #10: UNINITIALIZED READ: reading register eflags
registers.c_asm.asm:839
Error #11: UNINITIALIZED READ: reading register cl
registers.c_asm.asm:844
Error #12: UNINITIALIZED READ: reading register ecx
registers.c_asm.asm:864
Error #13: UNINITIALIZED READ: reading 8 byte(s)
registers.c_asm.asm:888
Error #14: UNADDRESSABLE ACCESS beyond heap bounds: reading 1 byte(s)
registers.c_asm.asm:1046
Error #15: UNADDRESSABLE ACCESS beyond heap bounds: reading 1 byte(s)
registers.c_asm.asm:1058
Error #16: UNADDRESSABLE ACCESS beyond heap bounds: reading 1 byte(s)
registers.c_asm.asm:1071
Error #17: UNADDRESSABLE ACCESS beyond heap bounds: reading 1 byte(s)
registers.c_asm.asm:1072
%endif
%if UNIX
Error #1: UNINITIALIZED READ: reading register eflags
registers.c_asm.asm:565
Error #2: UNINITIALIZED READ: reading register eflags
registers.c_asm.asm:572
Error #3: UNINITIALIZED READ: reading register eax
registers.c:104
Error #4: UNINITIALIZED READ: reading register ax
registers.c_asm.asm:801
Error #5: UNINITIALIZED READ: reading register dx
registers.c_asm.asm:818
Error #6: UNINITIALIZED READ: reading register ah
registers.c_asm.asm:848
Error #7: UNINITIALIZED READ: reading register eax
registers.c:187
Error #8: UNINITIALIZED READ: reading 1 byte(s)
registers.c_asm.asm:538
Error #9: UNINITIALIZED READ: reading register eflags
registers.c_asm.asm:364
Error #10: UNINITIALIZED READ: reading register eflags
registers.c_asm.asm:368
Error #11: UNINITIALIZED READ: reading register cl
registers.c_asm.asm:373
Error #12: UNINITIALIZED READ: reading register ecx
registers.c_asm.asm:396
Error #13: UNINITIALIZED READ: reading 8 byte(s)
registers.c_asm.asm:422
Error #14: UNADDRESSABLE ACCESS beyond heap bounds: reading 1 byte(s)
registers.c_asm.asm:594
Error #15: UNADDRESSABLE ACCESS beyond heap bounds: reading 1 byte(s)
registers.c_asm.asm:606
Error #16: UNADDRESSABLE ACCESS beyond heap bounds: reading 1 byte(s)
registers.c_asm.asm:619
Error #17: UNADDRESSABLE ACCESS beyond heap bounds: reading 1 byte(s)
registers.c_asm.asm:620
%endif
Error #18: UNINITIALIZED READ: reading register eax
registers.c:223
%if UNIX
Error #19: UNINITIALIZED READ: reading register ecx
registers.c_asm.asm:952
%endif
%if WINDOWS
Error #19: UNINITIALIZED READ: reading register ecx
registers.c_asm.asm:1388
%endif
Error #20: UNINITIALIZED READ: reading register
registers.c:267
Error #21: UNINITIALIZED READ: reading register
registers.c:288
%if WINDOWS
Error #22: UNINITIALIZED READ: reading 1 byte(s)
registers.c_asm.asm:1473
Error #23: UNINITIALIZED READ: reading 1 byte(s)
registers.c_asm.asm:1487
Error #24: UNINITIALIZED READ: reading 2 byte(s)
registers.c_asm.asm:1501
Error #25: UNINITIALIZED READ: reading 2 byte(s)
registers.c_asm.asm:1515
%endif
%if UNIX
Error #22: UNINITIALIZED READ: reading 1 byte(s)
registers.c_asm.asm:1046
Error #23: UNINITIALIZED READ: reading 1 byte(s)
registers.c_asm.asm:1060
Error #24: UNINITIALIZED READ: reading 2 byte(s)
registers.c_asm.asm:1074
Error #25: UNINITIALIZED READ: reading 2 byte(s)
registers.c_asm.asm:1088
%endif
%OUT_OF_ORDER
: LEAK 15 direct bytes + 0 indirect bytes
: LEAK 15 direct bytes + 0 indirect bytes
