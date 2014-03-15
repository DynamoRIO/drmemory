# **********************************************************
# Copyright (c) 2010-2014 Google, Inc.  All rights reserved.
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
suppress.c:59
suppress!uninit_test1
suppress.c:65
suppress!test
suppress.c
suppress!main
suppress.c

Error #2: UNINITIALIZED READ: reading register
suppress!do_uninit_read
suppress.c:59
suppress!uninit_test2
suppress.c:70
suppress!test
suppress.c
suppress!main
suppress.c

Error #3: UNINITIALIZED READ: reading register
suppress!do_uninit_read
suppress.c:59
suppress!uninit_test3
suppress.c:75
suppress!test
suppress.c
suppress!main
suppress.c

Error #4: UNINITIALIZED READ: reading register
suppress!do_uninit_read
suppress.c:59
suppress!uninit_test4
suppress.c:80
suppress!test
suppress.c
suppress!main
suppress.c

Error #5: UNINITIALIZED READ: reading register
suppress!do_uninit_read
suppress.c:59
suppress!uninit_test5
suppress.c:85
suppress!test
suppress.c
suppress!main
suppress.c

Error #6: UNINITIALIZED READ: reading register
suppress!do_uninit_read
suppress.c:59
suppress!do_uninit_read_with_intermediate_frames
suppress.c:93
suppress!do_uninit_read_with_intermediate_frames
suppress.c:91
suppress!do_uninit_read_with_intermediate_frames
suppress.c:91
suppress!do_uninit_read_with_intermediate_frames
suppress.c:91
suppress!do_uninit_read_with_intermediate_frames
suppress.c:91
suppress!uninit_test6
suppress.c:98
suppress!test
suppress.c
suppress!main
suppress.c

Error #7: UNINITIALIZED READ: reading register
suppress!do_uninit_read
suppress.c:59
suppress!do_uninit_read_with_intermediate_frames
suppress.c:93
suppress!do_uninit_read_with_intermediate_frames
suppress.c:91
suppress!do_uninit_read_with_intermediate_frames
suppress.c:91
suppress!do_uninit_read_with_intermediate_frames
suppress.c:91
suppress!do_uninit_read_with_intermediate_frames
suppress.c:91
suppress!uninit_test7
suppress.c:103
suppress!test
suppress.c
suppress!main
suppress.c

Error #8: UNADDRESSABLE ACCESS: reading 4 byte(s)
suppress!unaddr_test1
suppress.c:110
suppress!test
suppress.c
suppress!main
suppress.c
# non-det so disabling: Note: prev lower malloc:
that was freed

Error #9: UNADDRESSABLE ACCESS: reading 4 byte(s)
suppress!unaddr_test2
suppress.c:117
suppress!test
suppress.c
suppress!main
suppress.c
# non-det so disabling: Note: prev lower malloc:
that was freed

Error #10: UNADDRESSABLE ACCESS: reading 4 byte(s)
suppress!unaddr_test3
suppress.c:124
suppress!test
suppress.c
suppress!main
suppress.c
# non-det so disabling: Note: prev lower malloc:
that was freed

Error #11: UNADDRESSABLE ACCESS: reading 4 byte(s)
suppress!unaddr_test4
suppress.c:131
suppress!test
suppress.c
suppress!main
suppress.c
# non-det so disabling: Note: prev lower malloc:
that was freed

Error #12: WARNING: heap allocation failed
suppress!warning_test1
suppress.c:179
suppress!test
suppress.c
suppress!main
suppress.c

Error #13: UNINITIALIZED READ: reading 4 byte(s)
%if WINDOWS
system call NtQueryVirtualMemory parameter value #1
# omitting since case varies: kernel32.dll!VirtualQuery
suppress!syscall_test
suppress.c:220
%endif
%if UNIX
system call write parameter #1
suppress!syscall_test
suppress.c:215
%endif
suppress!test
suppress.c
suppress!main
suppress.c

Error #14: UNINITIALIZED READ: reading register
<not in a module>
suppress!test
suppress.c
suppress!main
suppress.c

Error #15: UNINITIALIZED READ: reading register
suppress!do_uninit_read
suppress.c:59
suppress!do_uninit_cb
suppress.c:263
# Drop the dll module name as it's different on Linux, and the source file name
# tells us which module it was.
!callback_with_n_frames
suppress-mod-bar.c
!callback_with_n_frames
suppress-mod-bar.c
!callback_with_n_frames
suppress-mod-bar.c
!callback_with_n_frames
suppress-mod-bar.c
suppress!call_into_bar
suppress.c
!callback_with_n_frames
suppress-mod-foo.c
!callback_with_n_frames
suppress-mod-foo.c
!callback_with_n_frames
suppress-mod-foo.c
!callback_with_n_frames
suppress-mod-foo.c
suppress!mod_ellipsis_test
suppress.c

Error #16: UNINITIALIZED READ: reading register
suppress!do_uninit_read
suppress.c:59
suppress!do_uninit_cb
suppress.c:263
# Drop the dll module name as it's different on Linux, and the source file name
# tells us which module it was.
!callback_with_n_frames
suppress-mod-foo.c
!callback_with_n_frames
suppress-mod-foo.c
!callback_with_n_frames
suppress-mod-foo.c
!callback_with_n_frames
suppress-mod-foo.c
suppress!call_into_foo
suppress.c
!callback_with_n_frames
suppress-mod-foo.c
!callback_with_n_frames
suppress-mod-foo.c
!callback_with_n_frames
suppress-mod-foo.c
!callback_with_n_frames
suppress-mod-foo.c
suppress!mod_ellipsis_test
suppress.c

Error #17: UNADDRESSABLE ACCESS: reading 4 byte(s)
# non-det so disabling: Note: next higher malloc:
suppress!invalid_free_test1
suppress.c:198
suppress!test
suppress.c
suppress!main
suppress.c

Error #18: UNADDRESSABLE ACCESS: reading 4 byte(s)
# non-det so disabling: Note: next higher malloc:
suppress!invalid_free_test1
suppress.c:200
suppress!test
suppress.c
suppress!main
suppress.c

Error #19: UNADDRESSABLE ACCESS: reading 4 byte(s)
# non-det so disabling: Note: next higher malloc:
suppress!invalid_free_test1
suppress.c:200
suppress!test
suppress.c
suppress!main
suppress.c

Error #20: INVALID HEAP ARGUMENT
suppress!invalid_free_test1
suppress.c:206
suppress!test
suppress.c
suppress!main
suppress.c

# these are sometimes out of order
%OUT_OF_ORDER

: LEAK 4 direct bytes + 0 indirect bytes
suppress!leak_test1
suppress.c:137
suppress!test
suppress.c
suppress!main
suppress.c

: LEAK 4 direct bytes + 0 indirect bytes
suppress!leak_test2
suppress.c:143
suppress!test
suppress.c
suppress!main
suppress.c

: LEAK 4 direct bytes + 0 indirect bytes
suppress!leak_test3
suppress.c:149
suppress!test
suppress.c
suppress!main
suppress.c

: LEAK 4 direct bytes + 0 indirect bytes
suppress!leak_test4
suppress.c:155
suppress!test
suppress.c
suppress!main
suppress.c

: POSSIBLE LEAK 16 direct bytes + 0 indirect bytes
suppress!possible_leak_test1
suppress.c:163
suppress!test
suppress.c
suppress!main
suppress.c

: POSSIBLE LEAK 16 direct bytes + 0 indirect bytes
suppress!possible_leak_test2
suppress.c:171
suppress!test
suppress.c
suppress!main
suppress.c

# i#292: We can only find this leak on Vista+ if we have ntdll.pdb and drsyms.
# Until we add support to fetch ntdll.pdb, we allow this leak to be missed.
#%if DRSYMS
#: LEAK 32 direct bytes + 0 indirect bytes
#suppress!invalid_free_test1
#suppress.c:188
#suppress!test
#suppress.c
#suppress!main
#suppress.c
#%endif

%if CYGWIN_PREVISTA
: LEAK 32 direct bytes + 0 indirect bytes
suppress!invalid_free_test1
suppress.c:188
suppress!test
suppress.c
suppress!main
suppress.c
%endif

%if UNIX
: LEAK 32 direct bytes + 0 indirect bytes
suppress!invalid_free_test1
suppress.c:188
suppress!test
suppress.c
suppress!main
suppress.c
%endif
