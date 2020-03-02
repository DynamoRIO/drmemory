# **********************************************************
# Copyright (c) 2015-2020 Google, Inc.  All rights reserved.
# **********************************************************

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

if ("${CMAKE_VERSION}" VERSION_EQUAL "3.0" OR
    "${CMAKE_VERSION}" VERSION_GREATER "3.0")
  # TODO i#1652: switch to ctest --build_and_test.
  # (Unfortunately this is printed for multiple subdirectories: passing
  # "-Wno-deprecated" to cmake will silence it.)
  cmake_policy(SET CMP0024 OLD)
endif ()

# i#1418: We are updated to the new scheme.
cmake_policy(SET CMP0022 NEW)
