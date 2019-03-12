# **********************************************************
# Copyright (c) 2011-2019 Google, Inc.  All rights reserved.
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
cs2bug.cpp:87
: UNADDRESSABLE ACCESS beyond heap bounds: reading 4 byte(s)
cs2bug.cpp:95
: INVALID HEAP ARGUMENT: allocated with operator new[], freed with operator delete
cs2bug.cpp:97
memory was allocated here:
cs2bug.cpp:91
: UNADDRESSABLE ACCESS beyond heap bounds: writing 1 byte(s)
cs2bug.cpp:101
refers to 0 byte(s) beyond last valid byte in prior malloc
: UNADDRESSABLE ACCESS beyond heap bounds: writing 1 byte(s)
cs2bug.cpp:105
refers to 1 byte(s) beyond last valid byte in prior malloc
: UNADDRESSABLE ACCESS beyond heap bounds: writing 1 byte(s)
cs2bug.cpp:109
refers to 0 byte(s) beyond last valid byte in prior malloc
##################################################
# test_mismatch_dtr()
: INVALID HEAP ARGUMENT: allocated with operator new[], freed with operator delete
cs2bug.cpp:197
memory was allocated here:
cs2bug.cpp:195
%OPTIONAL # Linux
: INVALID HEAP ARGUMENT to free
%ENDOPTIONAL
: INVALID HEAP ARGUMENT: allocated with operator new[], freed with free
cs2bug.cpp:200
memory was allocated here:
cs2bug.cpp:198
%OPTIONAL # only when wrapping
: UNINITIALIZED READ
cs2bug.cpp:116
cs2bug.cpp:203
%ENDOPTIONAL
: INVALID HEAP ARGUMENT: allocated with malloc, freed with operator delete
cs2bug.cpp:203
memory was allocated here:
cs2bug.cpp:201
%OPTIONAL # VS2008 Win7
: UNINITIALIZED READ
cs2bug.cpp:203
%ENDOPTIONAL
: UNADDRESSABLE ACCESS
cs2bug.cpp:206
%OPTIONAL
# MinGW xp64 crashes rather than reporting final mismatch
: UNADDRESSABLE ACCESS
cs2bug.cpp:206
%ENDOPTIONAL
%OPTIONAL
: INVALID HEAP ARGUMENT: allocated with malloc, freed with operator delete[]
cs2bug.cpp:206
memory was allocated here:
cs2bug.cpp:204
%ENDOPTIONAL
%OPTIONAL # Linux
: INVALID HEAP ARGUMENT to free
%ENDOPTIONAL
##################################################
# test_mismatch_int()
: INVALID HEAP ARGUMENT: allocated with operator new[], freed with operator delete
cs2bug.cpp:218
memory was allocated here:
cs2bug.cpp:216
: INVALID HEAP ARGUMENT: allocated with operator new[], freed with free
cs2bug.cpp:221
memory was allocated here:
cs2bug.cpp:219
: INVALID HEAP ARGUMENT: allocated with malloc, freed with operator delete
cs2bug.cpp:224
memory was allocated here:
cs2bug.cpp:222
: INVALID HEAP ARGUMENT: allocated with malloc, freed with operator delete[]
cs2bug.cpp:227
memory was allocated here:
cs2bug.cpp:225
##################################################
# leaks
%OUT_OF_ORDER
: LEAK 4 direct bytes + 0 indirect bytes
cs2bug.cpp:86
%if UNIX
# FIXME PR 587093: string code disabled for now on Windows
%if X32
: LEAK 4 direct bytes + 19 indirect bytes
%endif
%if X64
: LEAK 8 direct bytes + 31 indirect bytes
%endif
cs2bug.cpp:172
# Nested %if is only supported with "endif UNIX".
%endif UNIX
%OPTIONAL # Linux/VS2005
%if X32
: LEAK 88 direct bytes + 168 indirect bytes
%endif
%if X64
: LEAK 120 direct bytes + 168 indirect bytes
%endif
cs2bug.cpp:195
%ENDOPTIONAL
%if X32
: LEAK 88 direct bytes + 196 indirect bytes
%endif
%if X64
: LEAK 120 direct bytes + 196 indirect bytes
%endif
cs2bug.cpp:198
: LEAK 42 direct bytes + 0 indirect bytes
cs2bug.cpp:204
