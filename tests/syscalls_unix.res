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
syscalls_unix.c:66
overlaps memory that was freed

Error #2: UNINITIALIZED READ: reading 10 byte(s)
system call open
uninit_open
syscalls_unix.c:85

Error #3: UNADDRESSABLE ACCESS of freed memory: reading 12 byte(s)
system call finit_module
unaddr_finit_module
syscalls_unix.c:161
overlaps memory that was freed

# Number of bytes can vary depending on where 1st null char happens to be:
Error #4: UNINITIALIZED READ: reading
system call finit_module
uninit_finit_module
syscalls_unix.c:150

Error #5: UNADDRESSABLE ACCESS of freed memory: reading 1 byte(s)
system call execve
unaddr_uninit_execve
syscalls_unix.c:177
overlaps memory that was freed

Error #6: UNINITIALIZED READ: reading 1 byte(s)
system call execve
unaddr_uninit_execve
syscalls_unix.c:177

Error #7: UNINITIALIZED READ: reading 20 byte(s)
system call process_vm_readv
unaddr_process_vm_readv_writev
syscalls_unix.c:211

Error #8: UNADDRESSABLE ACCESS: writing 2 byte(s)
system call process_vm_readv
unaddr_process_vm_readv_writev
syscalls_unix.c:211

Error #9: UNINITIALIZED READ: reading 10 byte(s)
system call process_vm_writev
unaddr_process_vm_readv_writev
syscalls_unix.c:213

Error #10: UNADDRESSABLE ACCESS: reading 2 byte(s)
system call process_vm_writev
unaddr_process_vm_readv_writev
syscalls_unix.c:213
