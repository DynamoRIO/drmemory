# **********************************************************
# Copyright (c) 2015-2017 Google, Inc.  All rights reserved.
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

if ("${CMAKE_VERSION}" VERSION_EQUAL "3.1" OR
    "${CMAKE_VERSION}" VERSION_GREATER "3.1")
  cmake_policy(SET CMP0053 OLD)
  cmake_policy(SET CMP0054 OLD)
endif ()

if ("${CMAKE_VERSION}" VERSION_EQUAL "3.0" OR
    "${CMAKE_VERSION}" VERSION_GREATER "3.0")
  # XXX i#1651: put in actual changes to support CMake 3.x
  cmake_policy(SET CMP0026 OLD)
  # XXX i#1652: update to cmake 2.8.12's better handling of interface exports
  cmake_policy(SET CMP0024 OLD)
endif ()

if ("${CMAKE_VERSION}" VERSION_EQUAL "2.8.12" OR
    "${CMAKE_VERSION}" VERSION_GREATER "2.8.12")
  # XXX i#1481: update to cmake 2.8.12's better handling of interface imports
  cmake_policy(SET CMP0022 OLD)
endif ()

if ("${CMAKE_VERSION}" VERSION_EQUAL "2.8.11" OR
    "${CMAKE_VERSION}" VERSION_GREATER "2.8.11")
  # XXX DRi#1418: update to cmake 2.8.12's better handling of interface imports
  cmake_policy(SET CMP0020 OLD)
endif ()
