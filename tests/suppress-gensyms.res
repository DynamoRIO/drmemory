# **********************************************************
# Copyright (c) 2010 Google, Inc.  All rights reserved.
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
suppress.c:52
suppress!uninit_test1
suppress.c:58
suppress!test
suppress.c:192
suppress!main
suppress.c:223

Error #2: UNINITIALIZED READ: reading register
suppress!do_uninit_read
suppress.c:52
suppress!uninit_test2
suppress.c:63
suppress!test
suppress.c:193
suppress!main
suppress.c:223

Error #3: UNINITIALIZED READ: reading register
suppress!do_uninit_read
suppress.c:52
suppress!uninit_test3
suppress.c:68
suppress!test
suppress.c:194
suppress!main
suppress.c:223

Error #4: UNINITIALIZED READ: reading register
suppress!do_uninit_read
suppress.c:52
suppress!uninit_test4
suppress.c:73
suppress!test
suppress.c:195
suppress!main
suppress.c:223

Error #5: UNINITIALIZED READ: reading register
suppress!do_uninit_read
suppress.c:52
suppress!uninit_test5
suppress.c:78
suppress!test
suppress.c:196
suppress!main
suppress.c:223

Error #6: UNINITIALIZED READ: reading register
suppress!do_uninit_read
suppress.c:52
suppress!do_uninit_read_with_intermediate_frames
suppress.c:86
suppress!do_uninit_read_with_intermediate_frames
suppress.c:84
suppress!do_uninit_read_with_intermediate_frames
suppress.c:84
suppress!do_uninit_read_with_intermediate_frames
suppress.c:84
suppress!do_uninit_read_with_intermediate_frames
suppress.c:84
suppress!uninit_test6
suppress.c:91
suppress!test
suppress.c:197
suppress!main
suppress.c:223

Error #7: UNINITIALIZED READ: reading register
suppress!do_uninit_read
suppress.c:52
suppress!do_uninit_read_with_intermediate_frames
suppress.c:86
suppress!do_uninit_read_with_intermediate_frames
suppress.c:84
suppress!do_uninit_read_with_intermediate_frames
suppress.c:84
suppress!do_uninit_read_with_intermediate_frames
suppress.c:84
suppress!do_uninit_read_with_intermediate_frames
suppress.c:84
suppress!uninit_test7
suppress.c:96
suppress!test
suppress.c:198
suppress!main
suppress.c:223

Error #8: UNADDRESSABLE ACCESS: reading 4 byte(s)
Note: prev lower malloc:
overlaps freed memory
suppress!unaddr_test1
suppress.c:103
suppress!test
suppress.c:202
suppress!main
suppress.c:223

Error #9: UNADDRESSABLE ACCESS: reading 4 byte(s)
Note: prev lower malloc:
overlaps freed memory
suppress!unaddr_test2
suppress.c:110
suppress!test
suppress.c:203
suppress!main
suppress.c:223

Error #10: UNADDRESSABLE ACCESS: reading 4 byte(s)
Note: prev lower malloc:
overlaps freed memory
suppress!unaddr_test3
suppress.c:117
suppress!test
suppress.c:204
suppress!main
suppress.c:223

Error #11: UNADDRESSABLE ACCESS: reading 4 byte(s)
Note: prev lower malloc:
overlaps freed memory
suppress!unaddr_test4
suppress.c:124
suppress!test
suppress.c:205
suppress!main
suppress.c:223

Error #12: WARNING: heap allocation failed
suppress!warning_test1
suppress.c:156
suppress!test
suppress.c:212
suppress!main
suppress.c:223

Error #13: UNADDRESSABLE ACCESS: reading 4 byte(s)
Note: next higher malloc:
suppress!invalid_free_test1
suppress.c:175
suppress!test
suppress.c:215
suppress!main
suppress.c:223

Error #14: UNADDRESSABLE ACCESS: reading 4 byte(s)
Note: next higher malloc:
suppress!invalid_free_test1
suppress.c:177
suppress!test
suppress.c:215
suppress!main
suppress.c:223

Error #15: INVALID HEAP ARGUMENT: 
suppress!invalid_free_test1
!if WINDOWS
suppress.c:179
!endif
!if UNIX
suppress.c:180
!endif
suppress!test
suppress.c:215
suppress!main
suppress.c:223

Error #16: LEAK 4 direct bytes + 0 indirect bytes
suppress!leak_test1
suppress.c:130
suppress!test
suppress.c:207
suppress!main
suppress.c:223

Error #17: LEAK 4 direct bytes + 0 indirect bytes
suppress!leak_test2
suppress.c:136
suppress!test
suppress.c:208
suppress!main
suppress.c:223

# these are sometimes out of order
: LEAK 4 direct bytes + 0 indirect bytes
suppress!leak_test3
suppress.c:142
suppress!test
suppress.c:209
suppress!main
suppress.c:223

: LEAK 32 direct bytes + 0 indirect bytes
suppress!invalid_free_test1
suppress.c:165
suppress!test
suppress.c:215
suppress!main
suppress.c:223

: LEAK 4 direct bytes + 0 indirect bytes
suppress!leak_test4
suppress.c:148
suppress!test
suppress.c:210
suppress!main
suppress.c:223
