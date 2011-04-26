# **********************************************************
# Copyright (c) 2010-2011 Google, Inc.  All rights reserved.
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

Error #1: UNINITIALIZED READ: reading register
suppress!do_uninit_read
suppress.c:53
suppress!uninit_test1
suppress.c:59
suppress!test
suppress.c:213
suppress!main
suppress.c:247

Error #2: UNINITIALIZED READ: reading register
suppress!do_uninit_read
suppress.c:53
suppress!uninit_test2
suppress.c:64
suppress!test
suppress.c:214
suppress!main
suppress.c:247

Error #3: UNINITIALIZED READ: reading register
suppress!do_uninit_read
suppress.c:53
suppress!uninit_test3
suppress.c:69
suppress!test
suppress.c:215
suppress!main
suppress.c:247

Error #4: UNINITIALIZED READ: reading register
suppress!do_uninit_read
suppress.c:53
suppress!uninit_test4
suppress.c:74
suppress!test
suppress.c:216
suppress!main
suppress.c:247

Error #5: UNINITIALIZED READ: reading register
suppress!do_uninit_read
suppress.c:53
suppress!uninit_test5
suppress.c:79
suppress!test
suppress.c:217
suppress!main
suppress.c:247

Error #6: UNINITIALIZED READ: reading register
suppress!do_uninit_read
suppress.c:53
suppress!do_uninit_read_with_intermediate_frames
suppress.c:87
suppress!do_uninit_read_with_intermediate_frames
suppress.c:85
suppress!do_uninit_read_with_intermediate_frames
suppress.c:85
suppress!do_uninit_read_with_intermediate_frames
suppress.c:85
suppress!do_uninit_read_with_intermediate_frames
suppress.c:85
suppress!uninit_test6
suppress.c:92
suppress!test
suppress.c:218
suppress!main
suppress.c:247

Error #7: UNINITIALIZED READ: reading register
suppress!do_uninit_read
suppress.c:53
suppress!do_uninit_read_with_intermediate_frames
suppress.c:87
suppress!do_uninit_read_with_intermediate_frames
suppress.c:85
suppress!do_uninit_read_with_intermediate_frames
suppress.c:85
suppress!do_uninit_read_with_intermediate_frames
suppress.c:85
suppress!do_uninit_read_with_intermediate_frames
suppress.c:85
suppress!uninit_test7
suppress.c:97
suppress!test
suppress.c:219
suppress!main
suppress.c:247

Error #8: UNADDRESSABLE ACCESS: reading 4 byte(s)
# non-det so disabling: Note: prev lower malloc:
overlaps freed memory
suppress!unaddr_test1
suppress.c:104
suppress!test
suppress.c:223
suppress!main
suppress.c:247

Error #9: UNADDRESSABLE ACCESS: reading 4 byte(s)
# non-det so disabling: Note: prev lower malloc:
overlaps freed memory
suppress!unaddr_test2
suppress.c:111
suppress!test
suppress.c:224
suppress!main
suppress.c:247

Error #10: UNADDRESSABLE ACCESS: reading 4 byte(s)
# non-det so disabling: Note: prev lower malloc:
overlaps freed memory
suppress!unaddr_test3
suppress.c:118
suppress!test
suppress.c:225
suppress!main
suppress.c:247

Error #11: UNADDRESSABLE ACCESS: reading 4 byte(s)
# non-det so disabling: Note: prev lower malloc:
overlaps freed memory
suppress!unaddr_test4
suppress.c:125
suppress!test
suppress.c:226
suppress!main
suppress.c:247

Error #12: WARNING: heap allocation failed
suppress!warning_test1
suppress.c:173
suppress!test
suppress.c:236
suppress!main
suppress.c:247

Error #13: UNADDRESSABLE ACCESS: reading 4 byte(s)
# non-det so disabling: Note: next higher malloc:
suppress!invalid_free_test1
suppress.c:192
suppress!test
suppress.c:239
suppress!main
suppress.c:247

Error #14: UNADDRESSABLE ACCESS: reading 4 byte(s)
# non-det so disabling: Note: next higher malloc:
suppress!invalid_free_test1
suppress.c:194
suppress!test
suppress.c:239
suppress!main
suppress.c:247

Error #15: INVALID HEAP ARGUMENT: 
suppress!invalid_free_test1
%if WINDOWS
suppress.c:200
%endif
%if UNIX
suppress.c:201
%endif
suppress!test
suppress.c:239
suppress!main
suppress.c:247

# these are sometimes out of order
%OUT_OF_ORDER

: LEAK 4 direct bytes + 0 indirect bytes
suppress!leak_test1
suppress.c:131
suppress!test
suppress.c:228
suppress!main
suppress.c:247

: LEAK 4 direct bytes + 0 indirect bytes
suppress!leak_test2
suppress.c:137
suppress!test
suppress.c:229
suppress!main
suppress.c:247

: LEAK 4 direct bytes + 0 indirect bytes
suppress!leak_test3
suppress.c:143
suppress!test
suppress.c:230
suppress!main
suppress.c:247

: LEAK 4 direct bytes + 0 indirect bytes
suppress!leak_test4
suppress.c:149
suppress!test
suppress.c:231
suppress!main
suppress.c:247

: POSSIBLE LEAK 16 direct bytes + 0 indirect bytes
suppress!possible_leak_test1
suppress.c:157
suppress!test
suppress.c:233
suppress!main
suppress.c:247

: POSSIBLE LEAK 16 direct bytes + 0 indirect bytes
suppress!possible_leak_test2
suppress.c:165
suppress!test
suppress.c:234
suppress!main
suppress.c:247

%if DRSYMS
# w/o drsyms we can't get RtlpHeapFailureInfo (i#292)
# this will also happen on machines w/o private syms for ntdll
: LEAK 32 direct bytes + 0 indirect bytes
suppress!invalid_free_test1
suppress.c:182
suppress!test
suppress.c:239
suppress!main
suppress.c:247
%endif

%if CYGWIN_PREVISTA
: LEAK 32 direct bytes + 0 indirect bytes
suppress!invalid_free_test1
suppress.c:182
suppress!test
suppress.c:239
suppress!main
suppress.c:247
%endif

%if UNIX
: LEAK 32 direct bytes + 0 indirect bytes
suppress!invalid_free_test1
suppress.c:182
suppress!test
suppress.c:239
suppress!main
suppress.c:247
%endif
