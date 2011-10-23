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
Error #1: UNINITIALIZED READ
cs2bug.cpp:31
Error #2: UNADDRESSABLE ACCESS: writing 4 byte(s)
cs2bug.cpp:39
Error #3: INVALID HEAP ARGUMENT: wrong free/delete/delete[] called
cs2bug.cpp:40
Error #4: INVALID HEAP ARGUMENT: wrong free/delete/delete[] called
cs2bug.cpp:122
Error #5: INVALID HEAP ARGUMENT: wrong free/delete/delete[] called
cs2bug.cpp:124
Error #6: INVALID HEAP ARGUMENT: wrong free/delete/delete[] called
cs2bug.cpp:126
Error #7: INVALID HEAP ARGUMENT: wrong free/delete/delete[] called
cs2bug.cpp:128
%if UNIX
Error #8: LEAK 4 direct bytes + 19 indirect bytes
cs2bug.cpp:102
Error #9: LEAK 4 direct bytes + 0 indirect bytes
cs2bug.cpp:30
%endif
%if WINDOWS
# FIXME PR 587093: string code disabled for now
Error #8: LEAK 4 direct bytes + 0 indirect bytes
cs2bug.cpp:30
%endif
# ensure reachable leaks are printed, and after regular leaks
REACHABLE LEAK
REACHABLE LEAK
REACHABLE LEAK
