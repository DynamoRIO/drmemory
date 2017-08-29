# **********************************************************
# Copyright (c) 2011-2017 Google, Inc.  All rights reserved.
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
float.c:39
Error #2: UNINITIALIZED READ: reading 8 byte(s)
float.c:46
Error #3: UNINITIALIZED READ: reading 4 byte(s)
float.c:50
Error #4: UNINITIALIZED READ: reading 4 byte(s)
float.c:54
Error #5: UNINITIALIZED READ: reading 8 byte(s)
float.c:58
# PR 473614: cl's /RTC1 fills all locals w/ 0xcccccccc
# but /RTC1 is now off (for i#545) so re-enabling
# This is sometimes memory and sometimes xmm1 (x64).
Error #6: UNINITIALIZED READ: reading
float.c:65
