# **********************************************************
# Copyright (c) 2014 Google, Inc.  All rights reserved.
# Copyright (c) 2013 Branden Clark  All rights reserved.
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

# CMakeLists.txt
#
# Configures dhvis build
#

cmake_minimum_required(VERSION 2.8.10)

if ("${CMAKE_VERSION}" VERSION_EQUAL "2.8.11" OR
    "${CMAKE_VERSION}" VERSION_GREATER "2.8.11")
  # XXX DRi#1418: update to cmake 2.8.12's better handling of interface imports
  cmake_policy(SET CMP0020 OLD)
endif ()

# Embedded DynamoRIO
if (NOT USER_SPECIFIED_DynamoRIO_DIR)
  set(dhvis_interface_PATH
    ${CMAKE_CURRENT_SOURCE_DIR}/../../dynamorio/ext/drgui)
  include_directories(${dhvis_interface_PATH})
else () # Pre-built DynamoRIO
  set(dhvis_interface_PATH
    ${DynamoRIO_DIR}/../ext/include)
endif (NOT USER_SPECIFIED_DynamoRIO_DIR)

# Sources and MOC
set(dhvis_MOC_HEADERS
  ${CMAKE_CURRENT_SOURCE_DIR}/dhvis_options_page.h
  ${CMAKE_CURRENT_SOURCE_DIR}/dhvis_graph.h
  ${CMAKE_CURRENT_SOURCE_DIR}/dhvis_snapshot_graph.h
  ${CMAKE_CURRENT_SOURCE_DIR}/dhvis_stale_graph.h
  ${CMAKE_CURRENT_SOURCE_DIR}/dhvis_tool.h
  ${CMAKE_CURRENT_SOURCE_DIR}/dhvis_factory.h)

set(dhvis_MOC_HEADERS
  ${dhvis_MOC_HEADERS}
  ${dhvis_interface_PATH}/drgui_tool_interface.h
  ${dhvis_interface_PATH}/drgui_options_interface.h)

qt5_wrap_cpp(dhvis_MOC_OUTFILES ${dhvis_MOC_HEADERS})

set(dhvis_SOURCES
  ${CMAKE_CURRENT_SOURCE_DIR}/dhvis_structures.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/dhvis_options_page.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/dhvis_graph.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/dhvis_snapshot_graph.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/dhvis_stale_graph.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/dhvis_tool.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/dhvis_factory.cpp)

# Build
# Ignore windows specific Qt warnings
if (WIN32)
  set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -wd4127 -wd4512 -wd4189 -wd4481")
endif (WIN32)
# Set QT_NO_DEBUG to avoid errors mixing debug and release libs (i#1345)
add_definitions(-DQT_NO_DEBUG)
add_definitions(-DQT_PLUGIN)
add_library(dhvis SHARED ${dhvis_SOURCES} ${dhvis_MOC_OUTFILES})
qt5_use_modules(dhvis Widgets)
use_DynamoRIO_extension(dhvis drgui)
