# **********************************************************
# Copyright (c) 2011 Google, Inc.  All rights reserved.
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
Error #1: UNADDRESSABLE ACCESS: reading 10 byte(s)
system call open
unaddr_open
unix_syscalls.c:65
overlaps memory that was freed

Error #2: UNINITIALIZED READ: reading 10 byte(s)
system call open
uninit_open
unix_syscalls.c:84

Error #3: UNADDRESSABLE ACCESS: reading 12 byte(s)
system call finit_module
unaddr_finit_module
unix_syscalls.c:160
overlaps memory that was freed

Error #4: UNINITIALIZED READ: reading 6 byte(s)
system call finit_module
uninit_finit_module
unix_syscalls.c:149

Error #5: UNADDRESSABLE ACCESS: reading 1 byte(s)
system call execve
unaddr_uninit_execve
unix_syscalls.c:176
overlaps memory that was freed

Error #6: UNINITIALIZED READ: reading 1 byte(s)
system call execve
unaddr_uninit_execve
unix_syscalls.c:176
