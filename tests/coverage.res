# **********************************************************
# Copyright (c) 2013-2014 Google, Inc.  All rights reserved.
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
Error #1: UNADDRESSABLE ACCESS of freed memory: reading 1 byte(s)
free.c:81
# no "prev lower malloc" when enable DR's private loader
that was freed

Error #2: UNADDRESSABLE ACCESS of freed memory: writing 1 byte(s)
free.c:87
# whether have "prev lower malloc" is nondet
that was freed

Error #3: UNADDRESSABLE ACCESS of freed memory: writing 1 byte(s)
free.c:94
0 byte(s) beyond memory that was freed
