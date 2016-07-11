# **********************************************************
# Copyright (c) 2010-2013 Google, Inc.  All rights reserved.
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
Error #1: INVALID HEAP ARGUMENT
%if WINDOWS
# addr2line and winsyms report slightly different results here
malloc.c:166
%endif
%if UNIX
malloc.c:180
%endif
%if WINDOWS
Error #2: WARNING: heap allocation failed
malloc.c:192
%endif
%if WINDOWS_PRE_8
malloc.c:204
%endif
%if WINDOWS_8_PLUS
malloc.c:206
%endif
%if WINDOWS
# FIXME: should we remove the auto-escaping of regex chars in
# this file, and then we can use them: "Error #(5|6)"?
Error #4: LEAK 42 bytes
malloc.c:219
Error #5: LEAK 17 bytes
malloc.c:202
%endif
%if UNIX
Error #2: LEAK 17 bytes
malloc.c:202
Error #3: LEAK 42 bytes
malloc.c:219
%endif
