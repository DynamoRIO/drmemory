# **********************************************************
# Copyright (c) 2011-2013 Google, Inc.  All rights reserved.
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
: UNINITIALIZED READ
cs2bug.cpp:83
: UNADDRESSABLE ACCESS: reading 4 byte(s)
cs2bug.cpp:91
: INVALID HEAP ARGUMENT: allocated with operator new[], freed with operator delete
cs2bug.cpp:93
memory was allocated here:
cs2bug.cpp:87
%OPTIONAL # Not present on Linux when wrapping b/c operator new turns 0 into 1
: UNADDRESSABLE ACCESS: writing 1 byte(s)
cs2bug.cpp:97
refers to 1 byte(s) beyond last valid byte in prior malloc
%ENDOPTIONAL
: UNADDRESSABLE ACCESS: writing 1 byte(s)
cs2bug.cpp:101
%ANYLINE
# Linux wrap will say "1", else "2"
refers to 1 byte(s) beyond last valid byte in prior malloc
refers to 2 byte(s) beyond last valid byte in prior malloc
%ENDANYLINE
: UNADDRESSABLE ACCESS: writing 1 byte(s)
cs2bug.cpp:105
refers to 1 byte(s) beyond last valid byte in prior malloc
##################################################
# test_mismatch_int()
: INVALID HEAP ARGUMENT: allocated with operator new[], freed with operator delete
cs2bug.cpp:214
memory was allocated here:
cs2bug.cpp:212
: INVALID HEAP ARGUMENT: allocated with operator new[], freed with free
cs2bug.cpp:217
memory was allocated here:
cs2bug.cpp:215
: INVALID HEAP ARGUMENT: allocated with malloc, freed with operator delete
cs2bug.cpp:220
memory was allocated here:
cs2bug.cpp:218
: INVALID HEAP ARGUMENT: allocated with malloc, freed with operator delete[]
cs2bug.cpp:223
memory was allocated here:
cs2bug.cpp:221
##################################################
# leaks
: LEAK 4 direct bytes + 0 indirect bytes
cs2bug.cpp:82
