# **********************************************************
# Copyright (c) 2011-2014 Google, Inc.  All rights reserved.
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
Error #1: UNADDRESSABLE ACCESS of freed memory: reading 10 byte(s)
system call open
unaddr_open
syscalls_unix.c:71
overlaps memory that was freed

Error #2: UNADDRESSABLE ACCESS: reading 1 byte(s)
system call open
wild_open
syscalls_unix.c:85

Error #3: UNINITIALIZED READ: reading 10 byte(s)
system call open
uninit_open
syscalls_unix.c:105

Error #4: UNADDRESSABLE ACCESS of freed memory: reading 12 byte(s)
system call finit_module
unaddr_finit_module
syscalls_unix.c:184
overlaps memory that was freed

# Number of bytes can vary depending on where 1st null char happens to be:
Error #5: UNINITIALIZED READ: reading
system call finit_module
uninit_finit_module
syscalls_unix.c:172

Error #6: UNADDRESSABLE ACCESS of freed memory: reading 1 byte(s)
system call execve
unaddr_uninit_execve
syscalls_unix.c:201
overlaps memory that was freed

Error #7: UNINITIALIZED READ: reading 1 byte(s)
system call execve
unaddr_uninit_execve
syscalls_unix.c:201

Error #8: UNINITIALIZED READ: reading 20 byte(s)
system call process_vm_readv
unaddr_process_vm_readv_writev
syscalls_unix.c:236

Error #9: UNADDRESSABLE ACCESS beyond heap bounds: writing 2 byte(s)
system call process_vm_readv
unaddr_process_vm_readv_writev
syscalls_unix.c:236

Error #10: UNINITIALIZED READ: reading 10 byte(s)
system call process_vm_writev
unaddr_process_vm_readv_writev
syscalls_unix.c:238

Error #11: UNADDRESSABLE ACCESS beyond heap bounds: reading 2 byte(s)
system call process_vm_writev
unaddr_process_vm_readv_writev
syscalls_unix.c:238
