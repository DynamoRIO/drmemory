# **********************************************************
# Copyright (c) 2011-2016 Google, Inc.  All rights reserved.
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
# FIXME: for instr "inc 0x00000080(%eax) -> 0x00000080(%eax)"
# shadow mode reports "reading 1 byte(s)" error
# while pattern mode reports "writing 1 byte(s)" error.
%if WINDOWS
Error #1: UNADDRESSABLE ACCESS beyond heap bounds:
registers.c_asm.asm:1380
Error #2: UNADDRESSABLE ACCESS beyond heap bounds:
registers.c_asm.asm:1392
%endif
%if UNIX
Error #1: UNADDRESSABLE ACCESS beyond heap bounds:
registers.c_asm.asm:612
Error #2: UNADDRESSABLE ACCESS beyond heap bounds:
registers.c_asm.asm:624
%endif
