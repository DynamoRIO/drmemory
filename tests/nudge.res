# **********************************************************
# Copyright (c) 2011 Google, Inc.  All rights reserved.
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
%if WINDOWS
# XXX: extra leak due to encoded pointer (PR 482555) is no longer happening on
# my machine!  not sure what's going on
#Error #1: LEAK 128 direct bytes + 0 indirect bytes
#crtheap.c:61
#Error #2: LEAK 160 direct bytes + 0 indirect bytes
#infloop.c:91
#Error #3: LEAK 42 direct bytes + 17 indirect bytes
#infloop.c:80
Error #1: LEAK 160 direct bytes + 0 indirect bytes
infloop.c:92
Error #2: LEAK 42 direct bytes + 17 indirect bytes
infloop.c:81
%endif
%OUT_OF_ORDER
%if UNIX
LEAK 160 direct bytes + 0 indirect bytes
infloop.c:92
LEAK 42 direct bytes + 17 indirect bytes
infloop.c:81
%endif
