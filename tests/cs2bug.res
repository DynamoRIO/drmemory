# **********************************************************
# Copyright (c) 2011-2012 Google, Inc.  All rights reserved.
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
##################################################
# test_mismatch_dtr()
: INVALID HEAP ARGUMENT: allocated with operator new[], freed with operator delete
cs2bug.cpp:180
memory was allocated here:
cs2bug.cpp:178
%OPTIONAL # Linux
: INVALID HEAP ARGUMENT to free()
%ENDOPTIONAL
: INVALID HEAP ARGUMENT: allocated with operator new[], freed with free
cs2bug.cpp:183
memory was allocated here:
cs2bug.cpp:181
%OPTIONAL # only when wrapping
: UNINITIALIZED READ
cs2bug.cpp:99
cs2bug.cpp:186
%ENDOPTIONAL
: INVALID HEAP ARGUMENT: allocated with malloc, freed with operator delete
cs2bug.cpp:186
memory was allocated here:
cs2bug.cpp:184
%OPTIONAL # VS2008 Win7
: UNINITIALIZED READ
cs2bug.cpp:186
%ENDOPTIONAL
: UNADDRESSABLE ACCESS
cs2bug.cpp:189
%OPTIONAL
# MinGW xp64 crashes rather than reporting final mismatch
: UNADDRESSABLE ACCESS
cs2bug.cpp:189
%ENDOPTIONAL
%OPTIONAL
: INVALID HEAP ARGUMENT: allocated with malloc, freed with operator delete[]
cs2bug.cpp:189
memory was allocated here:
cs2bug.cpp:187
%ENDOPTIONAL
%OPTIONAL # Linux
: INVALID HEAP ARGUMENT to free()
%ENDOPTIONAL
##################################################
# test_mismatch_int()
: INVALID HEAP ARGUMENT: allocated with operator new[], freed with operator delete
cs2bug.cpp:201
memory was allocated here:
cs2bug.cpp:199
: INVALID HEAP ARGUMENT: allocated with operator new[], freed with free
cs2bug.cpp:204
memory was allocated here:
cs2bug.cpp:202
: INVALID HEAP ARGUMENT: allocated with malloc, freed with operator delete
cs2bug.cpp:207
memory was allocated here:
cs2bug.cpp:205
: INVALID HEAP ARGUMENT: allocated with malloc, freed with operator delete[]
cs2bug.cpp:210
memory was allocated here:
cs2bug.cpp:208
##################################################
# leaks
%OUT_OF_ORDER
: LEAK 4 direct bytes + 0 indirect bytes
cs2bug.cpp:82
%if UNIX
# FIXME PR 587093: string code disabled for now on Windows
: LEAK 4 direct bytes + 19 indirect bytes
cs2bug.cpp:155
%endif
%OPTIONAL # Linux/VS2005
: LEAK 88 direct bytes + 168 indirect bytes
cs2bug.cpp:178
%ENDOPTIONAL
: LEAK 88 direct bytes + 196 indirect bytes
cs2bug.cpp:181
: LEAK 7 direct bytes + 0 indirect bytes
cs2bug.cpp:187
