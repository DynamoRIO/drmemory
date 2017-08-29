# **********************************************************
# Copyright (c) 2011-2017 Google, Inc.  All rights reserved.
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
%if X32
Error #1: LEAK 4 direct bytes + 4 indirect bytes
%endif
%if X64
Error #1: LEAK 8 direct bytes + 8 indirect bytes
%endif
# Either allocation site could be the root, it depends which had the lower
# memory address.
%ANYLINE
leakcycle.cpp:60
leakcycle.cpp:68
%ENDANYLINE
