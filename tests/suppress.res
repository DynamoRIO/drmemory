# **********************************************************
# Copyright (c) 2011-2015 Google, Inc.  All rights reserved.
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

UNINITIALIZED READ
suppress!do_uninit_read
suppress.c:63
suppress!do_uninit_cb
suppress.c:261
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
