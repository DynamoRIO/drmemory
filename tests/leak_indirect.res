# **********************************************************
# Copyright (c) 2016-2017 Google, Inc.  All rights reserved.
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
%OUT_OF_ORDER
%if X32
: LEAK 16 direct bytes + 48 indirect bytes
leak_indirect.c:48
: POSSIBLE LEAK 16 direct bytes + 0 indirect bytes
leak_indirect.c:53
: LEAK 16 direct bytes + 16 indirect bytes
leak_indirect.c:54
%endif
%if X64
: LEAK 32 direct bytes + 96 indirect bytes
leak_indirect.c:48
: POSSIBLE LEAK 32 direct bytes + 0 indirect bytes
leak_indirect.c:53
: LEAK 32 direct bytes + 32 indirect bytes
leak_indirect.c:54
%endif
