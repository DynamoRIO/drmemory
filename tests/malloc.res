# **********************************************************
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
Error #1: UNADDRESSABLE ACCESS: reading 1 byte(s)
Note: prev lower malloc
malloc.c:95
Error #2: UNINITIALIZED READ
malloc.c:105
Error #3: UNINITIALIZED READ
malloc.c:118
Error #4: INVALID HEAP ARGUMENT
!if WINDOWS
# addr2line and winsyms report slightly different results here
malloc.c:162
!endif
!if UNIX
malloc.c:163
Error #5: LEAK 42 direct bytes + 17 indirect bytes
malloc.c:212
Error #6: LEAK 16 direct bytes + 48 indirect bytes
malloc.c:244
Error #7: POSSIBLE LEAK 16 direct bytes + 0 indirect bytes
malloc.c:249
Error #8: LEAK 16 direct bytes + 16 indirect bytes
malloc.c:250
!endif
!if WINDOWS
Error #5: WARNING: heap allocation failed
malloc.c:174
Error #6: INVALID HEAP ARGUMENT
malloc.c:181
# FIXME: should we remove the auto-escaping of regex chars in
# this file, and then we can use them: "Error #(5|6)"?
# for now just removing error#
!endif
# must be outside of if..endif
!OUT_OF_ORDER
!if WINDOWS
: LEAK 42 direct bytes + 17 indirect bytes
malloc.c:212
: LEAK 16 direct bytes + 48 indirect bytes
malloc.c:244
: POSSIBLE LEAK 16 direct bytes + 0 indirect bytes
malloc.c:249
: LEAK 16 direct bytes + 16 indirect bytes
malloc.c:250
!endif
