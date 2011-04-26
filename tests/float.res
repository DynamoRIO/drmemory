# **********************************************************
# Copyright (c) 2011 Google, Inc.  All rights reserved.
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
Error #1: UNINITIALIZED READ: reading 4 byte(s)
%if WINDOWS
# raises on the load since uses fld instead of mov
float.c:37
%endif
%if UNIX
float.c:38
%endif
Error #2: UNINITIALIZED READ: reading 8 byte(s)
float.c:43
Error #3: UNINITIALIZED READ: reading 4 byte(s)
float.c:45
Error #4: UNINITIALIZED READ: reading 4 byte(s)
float.c:47
Error #5: UNINITIALIZED READ: reading 8 byte(s)
float.c:49
# PR 473614: cl's /RTC1 fills all locals w/ 0xcccccccc
%if UNIX
Error #6: UNINITIALIZED READ: reading 8 byte(s)
float.c:55
%endif
