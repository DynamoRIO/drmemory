# **********************************************************
# Copyright (c) 2010-2016 Google, Inc.  All rights reserved.
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
Error #1: UNADDRESSABLE ACCESS beyond heap bounds: reading 1 byte(s)
malloc.c:112
Note: prev lower malloc
Error #2: UNINITIALIZED READ
malloc.c:122
Error #3: UNINITIALIZED READ
malloc.c:135
Error #4: INVALID HEAP ARGUMENT
malloc.c:180
%if WINDOWS
Error #5: WARNING: heap allocation failed
malloc.c:192
%endif
%if WINDOWS_PRE_8
malloc.c:204
%endif
%if WINDOWS_8_PLUS
malloc.c:206
%endif
: LEAK 42 direct bytes + 17 indirect bytes
malloc.c:240
# summary isn't in stdout when we check it so we check summary in results.txt
ERRORS FOUND:
      1 unique,    20 total unaddressable access(es)
      2 unique,     2 total uninitialized access(es)
%if WINDOWS
# we have an extra test for invalid heap params
      2 unique,     2 total invalid heap argument(s)
# we get a warning about heap alloc failing from HeapReAlloc(,NULL,)
      1 unique,     1 total warning(s)
%endif
%if UNIX
      1 unique,     1 total invalid heap argument(s)
      0 unique,     0 total warning(s)
%endif
      1 unique,     1 total,     59 byte(s) of leak(s)
      0 unique,     0 total,      0 byte(s) of possible leak(s)
